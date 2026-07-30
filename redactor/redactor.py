import re
import discord
import logging
import io
import os
import asyncio
import secrets
import time
from dataclasses import dataclass, field
from redbot.core import commands, app_commands

# Global error and start messages
START_MESSAGE = "The following was shared by {mention} and was automatically redacted by {bot_name} as it may have contained sensitive information."
REDACTION_REVIEW_TTL_SECONDS = 15 * 60
REDACTOR_BUILD_ID = "review-flow-2026-07-29-1"
# List of role IDs that bypass redaction entirely.
REDACTION_BYPASS_ROLE_IDS = [
    # 823677075751043102,
    # 1187017579013873665,
    # 929756550380286153,
    # 929900016531828797,
]

# List of staff role IDs that can use another user's redaction review buttons.
STAFF_REVIEW_ROLE_IDS = [
    # 823677075751043102,
    # 1187017579013873665,
    # 929756550380286153,
    # 929900016531828797,
]

# Create logger
mylogger = logging.getLogger('redactor')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG


@dataclass
class StoredAttachment:
    filename: str
    data: bytes
    content_type: str = ""

    def to_file(self):
        return discord.File(io.BytesIO(self.data), filename=self.filename)


@dataclass
class PendingRedaction:
    author_id: int
    channel_id: int
    created_at: float
    content: str
    attachments: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    redacted_message_ids: list = field(default_factory=list)
    notice_message_id: int = None

    def is_expired(self):
        return time.time() - self.created_at > REDACTION_REVIEW_TTL_SECONDS


class RedactionConfirmRestoreView(discord.ui.View):
    def __init__(self, cog: "RedBotCog", review_id: str, author_id: int):
        super().__init__(timeout=60)
        self.cog = cog
        self.review_id = review_id
        self.author_id = author_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if await self.cog.can_manage_redaction_review(interaction, self.author_id):
            return True
        await interaction.response.send_message("Only the original author or staff can use this review.", ephemeral=True)
        return False

    @discord.ui.button(label="Confirm Restore", style=discord.ButtonStyle.danger)
    async def confirm_restore(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.cog.restore_redaction_review(interaction, self.review_id)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel_restore(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content="Restore cancelled. The redacted copy remains posted.", view=None)


class RedactionReviewView(discord.ui.View):
    def __init__(self, cog: "RedBotCog", review_id: str, author_id: int):
        super().__init__(timeout=REDACTION_REVIEW_TTL_SECONDS)
        self.cog = cog
        self.review_id = review_id
        self.author_id = author_id
        self.message = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if await self.cog.can_manage_redaction_review(interaction, self.author_id):
            return True
        await interaction.response.send_message("Only the original author or staff can use this review.", ephemeral=True)
        return False

    async def on_timeout(self):
        await self.cog.expire_redaction_review(self.review_id)
        for child in self.children:
            child.disabled = True

        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.HTTPException:
                pass

    @discord.ui.button(label="Show Findings", style=discord.ButtonStyle.secondary)
    async def show_findings(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.cog.show_redaction_findings(interaction, self.review_id)

    @discord.ui.button(label="Keep Redacted", style=discord.ButtonStyle.success)
    async def keep_redacted(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.cog.keep_redaction_review(interaction, self.review_id)

    @discord.ui.button(label="Restore Original", style=discord.ButtonStyle.danger)
    async def restore_original(self, interaction: discord.Interaction, button: discord.ui.Button):
        view = RedactionConfirmRestoreView(self.cog, self.review_id, self.author_id)
        await interaction.response.send_message(
            "This will repost the original unredacted content and attachments to the thread. Confirm only if you are sure no secrets will be exposed.",
            ephemeral=True,
            view=view,
        )


class RedBotCog(commands.Cog):
    processed_message_ids = set()

    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id
        self.regex_pattern = r"(token|client.*|(?<!\w)url:|url: (?:http|https)|api_*key|(?<!\w)secret:|run_start|run_end|changes|username|password|localhost_url|\"tvdbapi\"|\"tmdbtoken\"|\"plextoken\"|\"fanarttvapikey\"): .+"
        self.processed_message_ids = set()
        self.pending_redactions = {}
        mylogger.info(f"Loaded redactor cog build {REDACTOR_BUILD_ID} from {__file__}")

    @commands.command(name="redactorversion")
    @commands.is_owner()
    async def redactor_version(self, ctx):
        await ctx.send(f"Redactor build `{REDACTOR_BUILD_ID}` loaded from `{__file__}`")

    @commands.Cog.listener()
    async def on_message(self, message):
        try:
            # Check if the message is from a direct message (DM) with the bot
            if isinstance(message.channel, discord.DMChannel):
                mylogger.info(f"Message {message.id} in DMChannel, skipping.")
                # If the message is from a DM, just return without further processing
                return


            # Skip processing if the message has already been processed
            if message.id in RedBotCog.processed_message_ids:
                mylogger.info(f"Message {message.id} already processed, skipping.")
                return

            if message.author != self.bot.user:
                # Mark the message as processed
                self.processed_message_ids.add(message.id)

                # Add a unique log message to identify when the event is triggered
                mylogger.info(f"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                # Log command invocation details
                author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
                guild_name = message.guild.name if message.guild else "Direct Message"
                channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"

                mylogger.info(f"Redactor invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")

                # mylogger.info(f"Received message (ID: {message.id}) from {message.author.name} in #{message.channel.name}")

                if any(role.id in REDACTION_BYPASS_ROLE_IDS for role in message.author.roles):
                    mylogger.info(f"Skipping redaction for {message.author.name} due to redaction bypass role.")
                    return

                # Check if the message is in a thread (is a thread or a reply in a thread)
                if isinstance(message.channel, discord.Thread):
                    parent_channel_id = None

                    # Determine the appropriate parent channel ID based on bot user ID
                    if self.bot_uid == 1138446898487894206:  # Botmoose20
                        parent_channel_id = 1138466814519693412   # #bot-forums
                    elif self.bot_uid == 1422494031388344340:  # Luma
                        parent_channel_id = 1006644783743258635  # #kometa-help

                    # Check if the parent channel ID matches
                    if parent_channel_id and message.channel.parent.id == parent_channel_id:
                        mylogger.info("Parent channel ID matches. Adding a 5-second delay.")
                        await asyncio.sleep(5)  # Add a 5-second delay
                        mylogger.info("5-second delay completed.")

                message_type = self.check_message_type(message)
                # mylogger.info(f"message_type: {message_type}")
                is_sensitive_text = self.is_sensitive(message.content)
                has_sensitive_attachments = await self.contains_sensitive_attachments(message.attachments)

                if message_type == "Text Only" and is_sensitive_text:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_only_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text}")
                    await self.process_text_only_sensitive(message)

                elif message_type == "Text Only" and not is_sensitive_text:
                    mylogger.info(f"do nothing - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text}")

                elif message_type == "Attachments Only" and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_attachments_only_sensitive - message_type:{message_type} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_attachments_only_sensitive(message)

                elif message_type == "Attachments Only" and not has_sensitive_attachments:
                    mylogger.info(f"do nothing - message_type:{message_type} and not has_sensitive_attachments:{has_sensitive_attachments}")

                elif message_type == "Text and Attachments" and is_sensitive_text and not has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_text_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text} and not has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_text_sensitive(message)

                elif message_type == "Text and Attachments" and is_sensitive_text and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_both_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_both_sensitive(message)

                elif message_type == "Text and Attachments" and not is_sensitive_text and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_attachments_sensitive - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_attachments_sensitive(message)

                elif message_type == "Text and Attachments" and not is_sensitive_text and not has_sensitive_attachments:
                    mylogger.info(f"do nothing - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text} and not has_sensitive_attachments:{has_sensitive_attachments}")

        except Exception as e:
            mylogger.exception('An error occurred during message processing:', exc_info=e)

    def check_message_type(self, message):
        has_text = bool(message.content)
        has_attachments = bool(message.attachments)

        if has_text and has_attachments:
            return "Text and Attachments"
        elif has_text:
            return "Text Only"
        elif has_attachments:
            return "Attachments Only"
        else:
            return "No Text or Attachments"

    async def send_replacement_message(self, channel, content=None, files=None):
        files = files or []
        normalized_content = content if content else None
        sent_messages = []

        if not files:
            if normalized_content is not None:
                sent_messages.append(
                    await channel.send(normalized_content, allowed_mentions=discord.AllowedMentions.none())
                )
            return sent_messages

        for index in range(0, len(files), 10):
            batch = files[index:index + 10]
            batch_content = normalized_content if index == 0 else None
            sent_messages.append(
                await channel.send(
                    content=batch_content,
                    files=batch,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            )

        return sent_messages

    def is_text_like_attachment(self, attachment):
        content_type = (attachment.content_type or "").lower()
        if content_type:
            return (
                content_type.startswith('text') or
                content_type == 'application/octet-stream' or
                content_type.startswith('application/json') or
                content_type.startswith('application/xml')
            )

        extension = attachment.filename.rsplit('.', 1)[-1].lower() if '.' in attachment.filename else ''
        return extension in {'txt', 'log', 'yml', 'yaml', 'json', 'xml', 'csv'}

    async def snapshot_attachments(self, attachments):
        snapshots = []
        for attachment in attachments:
            snapshots.append(
                StoredAttachment(
                    filename=attachment.filename,
                    data=await attachment.read(),
                    content_type=attachment.content_type or "",
                )
            )
        return snapshots

    def build_replacement_attachment(self, attachment):
        if not self.is_text_like_attachment(attachment):
            return attachment.to_file()

        try:
            text_data = attachment.data.decode('utf-8')
        except UnicodeDecodeError:
            mylogger.warning(f"Failed to decode attachment {attachment.filename} as UTF-8; reposting unchanged.")
            return attachment.to_file()

        redacted_text = self.redact_sensitive_info(text_data, self.bot_name)
        if redacted_text != text_data:
            return discord.File(io.BytesIO(redacted_text.encode('utf-8')), filename=attachment.filename)

        return attachment.to_file()

    def build_replacement_attachments(self, attachments):
        replacement_attachments = []
        for attachment in attachments:
            replacement_attachments.append(self.build_replacement_attachment(attachment))
        return replacement_attachments

    async def replace_redacted_message(self, message, content=None, files=None, original_attachments=None, findings=None):
        self.cleanup_expired_redactions()
        await message.delete()
        sent_messages = await self.send_replacement_message(message.channel, content=content, files=files)

        review_id = secrets.token_urlsafe(16)
        pending = PendingRedaction(
            author_id=message.author.id,
            channel_id=message.channel.id,
            created_at=time.time(),
            content=message.content,
            attachments=original_attachments or [],
            findings=findings or [],
            redacted_message_ids=[sent_message.id for sent_message in sent_messages],
        )
        self.pending_redactions[review_id] = pending

        view = RedactionReviewView(self, review_id, message.author.id)
        notice = await message.channel.send(
            content=message.author.mention,
            embed=self.build_redaction_review_embed(pending),
            view=view,
            allowed_mentions=discord.AllowedMentions(users=True),
        )
        view.message = notice
        pending.notice_message_id = notice.id
        await self.try_send_redaction_dm(message.author, pending)

    def cleanup_expired_redactions(self):
        expired_review_ids = [
            review_id
            for review_id, pending in self.pending_redactions.items()
            if pending.is_expired()
        ]
        for review_id in expired_review_ids:
            self.pending_redactions.pop(review_id, None)

    async def can_manage_redaction_review(self, interaction, author_id):
        if interaction.user.id == author_id:
            return True

        member = interaction.guild.get_member(interaction.user.id) if interaction.guild else None
        return bool(member and any(role.id in STAFF_REVIEW_ROLE_IDS for role in member.roles))

    def get_pending_redaction(self, review_id):
        pending = self.pending_redactions.get(review_id)
        if not pending:
            return None

        if pending.is_expired():
            self.pending_redactions.pop(review_id, None)
            return None

        return pending

    def format_redaction_findings(self, pending, limit=20):
        if not pending.findings:
            return "No line-level details were available. The message still matched the redaction rules."

        visible_findings = pending.findings[:limit]
        lines = [f"- {finding}" for finding in visible_findings]
        remaining = len(pending.findings) - len(visible_findings)
        if remaining:
            lines.append(f"- {remaining} additional finding(s) hidden for length.")
        return "\n".join(lines)

    def build_redaction_review_embed(self, pending):
        embed = discord.Embed(
            title="Redaction Review",
            description=(
                "I removed the original message because it matched the secret redaction rules and posted a redacted copy.\n\n"
                f"The original content is held in memory for {REDACTION_REVIEW_TTL_SECONDS // 60} minutes. "
                "Use the buttons below to inspect the sanitized findings, keep the redacted copy, or restore the original."
            ),
            color=discord.Color.orange(),
        )
        embed.add_field(name="Findings", value=self.format_redaction_findings(pending, limit=5)[:1024], inline=False)
        return embed

    async def try_send_redaction_dm(self, author, pending):
        try:
            embed = discord.Embed(
                title="Redaction Review",
                description=(
                    "Your message was redacted in the server because it matched the secret redaction rules. "
                    "Use the review buttons in the thread to keep the redacted copy or restore the original."
                ),
                color=discord.Color.orange(),
            )
            embed.add_field(name="Findings", value=self.format_redaction_findings(pending, limit=10)[:1024], inline=False)
            await author.send(embed=embed)
        except discord.Forbidden:
            mylogger.info(f"Could not DM redaction review to {author}.")
        except discord.HTTPException as e:
            mylogger.warning(f"Failed to DM redaction review to {author}: {e}")

    async def show_redaction_findings(self, interaction, review_id):
        pending = self.get_pending_redaction(review_id)
        if not pending:
            await interaction.response.send_message("This redaction review has expired.", ephemeral=True)
            return

        await interaction.response.send_message(self.format_redaction_findings(pending), ephemeral=True)

    async def keep_redaction_review(self, interaction, review_id):
        pending = self.get_pending_redaction(review_id)
        if not pending:
            await interaction.response.send_message("This redaction review has already expired or closed.", ephemeral=True)
            return

        self.pending_redactions.pop(review_id, None)
        embed = discord.Embed(
            title="Redaction Review Closed",
            description="The redacted copy was kept and the temporary original was discarded.",
            color=discord.Color.green(),
        )
        await interaction.response.edit_message(content=None, embed=embed, view=None)

    async def expire_redaction_review(self, review_id):
        self.pending_redactions.pop(review_id, None)

    async def delete_redacted_messages(self, pending, channel):
        for message_id in pending.redacted_message_ids:
            try:
                redacted_message = await channel.fetch_message(message_id)
                await redacted_message.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass

    async def update_redaction_notice(self, pending, channel, embed):
        if not pending.notice_message_id:
            return

        try:
            notice = await channel.fetch_message(pending.notice_message_id)
            await notice.edit(content=None, embed=embed, view=None)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

    async def restore_redaction_review(self, interaction, review_id):
        pending = self.get_pending_redaction(review_id)
        if not pending:
            await interaction.response.send_message("This redaction review has expired.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        channel = self.bot.get_channel(pending.channel_id) or interaction.channel
        restored_files = [attachment.to_file() for attachment in pending.attachments]
        await self.send_replacement_message(channel, content=pending.content, files=restored_files)
        await self.delete_redacted_messages(pending, channel)
        self.pending_redactions.pop(review_id, None)

        embed = discord.Embed(
            title="Original Restored",
            description="The original content was reposted by request and the temporary copy was discarded.",
            color=discord.Color.red(),
        )
        await self.update_redaction_notice(pending, channel, embed)
        await interaction.followup.send("Original restored. The temporary stored copy has been discarded.", ephemeral=True)

    async def process_text_only_sensitive(self, message):
        try:
            redacted_content = self.redact_sensitive_info(message.content, self.bot_name)
            start_message = START_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name)
            findings = self.build_redaction_findings(message.content, [])

            # Check if the redacted content exceeds Discord's character limit
            if len(redacted_content) > 1000:
                redacted_file = discord.File(
                    io.BytesIO(redacted_content.encode("utf-8")),
                    filename=f"redacted_message_{message.author.name}.txt",
                )
                await self.replace_redacted_message(
                    message,
                    content=f"{start_message} See attached file for redacted content.",
                    files=[redacted_file],
                    findings=findings,
                )
            else:
                # If the redacted content is within Discord's character limit, send it as a regular message
                await self.replace_redacted_message(
                    message,
                    content=f"{start_message}\n\n{redacted_content}",
                    findings=findings,
                )

        except Exception as e:
            # Log the exception (you can customize this part based on your logging setup)
            mylogger.exception('An error occurred in process_text_only_sensitive:', exc_info=e)

    async def process_attachments_only_sensitive(self, message):
        original_attachments = await self.snapshot_attachments(message.attachments)
        replacement_attachments = self.build_replacement_attachments(original_attachments)
        findings = self.build_redaction_findings(message.content, original_attachments)
        await self.replace_redacted_message(
            message,
            files=replacement_attachments,
            original_attachments=original_attachments,
            findings=findings,
        )

    async def process_text_and_attachments_text_sensitive(self, message):
        redacted_content = self.redact_sensitive_info(message.content, self.bot_name)
        original_attachments = await self.snapshot_attachments(message.attachments)
        replacement_attachments = self.build_replacement_attachments(original_attachments)
        findings = self.build_redaction_findings(message.content, original_attachments)
        await self.replace_redacted_message(
            message,
            content=redacted_content,
            files=replacement_attachments,
            original_attachments=original_attachments,
            findings=findings,
        )

    async def process_text_and_attachments_both_sensitive(self, message):
        redacted_content = self.redact_sensitive_info(message.content, self.bot_name)
        original_attachments = await self.snapshot_attachments(message.attachments)
        replacement_attachments = self.build_replacement_attachments(original_attachments)
        findings = self.build_redaction_findings(message.content, original_attachments)
        await self.replace_redacted_message(
            message,
            content=redacted_content,
            files=replacement_attachments,
            original_attachments=original_attachments,
            findings=findings,
        )

    async def process_text_and_attachments_attachments_sensitive(self, message):
        original_attachments = await self.snapshot_attachments(message.attachments)
        replacement_attachments = self.build_replacement_attachments(original_attachments)
        findings = self.build_redaction_findings(message.content, original_attachments)
        await self.replace_redacted_message(
            message,
            content=message.content,
            files=replacement_attachments,
            original_attachments=original_attachments,
            findings=findings,
        )

    def build_redaction_findings(self, message_content, attachments):
        findings = []
        findings.extend(self.find_sensitive_lines(message_content, "message content"))

        for attachment in attachments:
            if not self.is_text_like_attachment(attachment):
                continue

            try:
                attachment_text = attachment.data.decode("utf-8")
            except UnicodeDecodeError:
                continue

            findings.extend(self.find_sensitive_lines(attachment_text, f"attachment {attachment.filename}"))

        return findings

    def find_sensitive_lines(self, text, source):
        findings = []
        for line_number, line in enumerate((text or "").split("\n"), start=1):
            if self.should_skip_sensitive_line(line):
                continue

            if self.redact_sensitive_info(line, self.bot_name) == line:
                continue

            field_name = line.split(":", 1)[0].strip() or "sensitive value"
            findings.append(f"{source}, line {line_number}: `{field_name[:80]}`")

        return findings

    def should_skip_sensitive_line(self, line):
        keywords_to_skip = [
            "redacted",
            "invalid_token",
            "is blank",
            "is invalid",
            "doesn't match",
            "were found in",
            "mapping values",
            "{e}",
            "not found",
            "failed to parse",
        ]
        return line.isspace() or any(keyword in line.lower() for keyword in keywords_to_skip)

    def redact_sensitive_info(self, text, bot_name):
        # Use regex to find and replace sensitive information, but skip lines containing certain keywords
        lines = text.split('\n')
        redacted_lines = []

        for line in lines:
            # Check if the line consists of only whitespace characters
            if self.should_skip_sensitive_line(line):
                # Skip lines that are empty or contain any of the specified keywords (case-insensitive)
                redacted_lines.append(line)
            else:
                # Check if the line contains sensitive information
                if re.search(self.regex_pattern, line, flags=re.IGNORECASE):
                    # Check if all characters between ":" and the end of the line are spaces
                    line_to_redact = line.split(": ", 1)
                    if len(line_to_redact) == 2:
                        key, value = line_to_redact
                        if not any(char.isalnum() for char in value.strip()):
                            # If all characters are spaces, skip redaction
                            redacted_lines.append(line)
                            continue

                    # Check if the last character is "|" and all characters between ":" and "|" are spaces
                    if "|" in line:
                        line_split = line.rsplit("|", 1)
                        if len(line_split) == 2:
                            key_part, value_part = line_split
                            if not any(char.isalnum() for char in value_part.strip()) and all(
                                    char.isspace() for char in key_part.strip()):
                                # If last character is "|" and all characters between ":" and "|" are spaces, skip redaction
                                redacted_lines.append(line)
                                continue

                    # Redact sensitive information in the line
                    redacted_line = re.sub(self.regex_pattern, f"\\1: (redacted by {bot_name})", line, flags=re.IGNORECASE)
                    redacted_lines.append(redacted_line)
                else:
                    # If the line doesn't contain sensitive information, keep it as-is
                    redacted_lines.append(line)

        return '\n'.join(redacted_lines)

    def is_sensitive(self, text):
        """
        Determines if the given text contains sensitive information based on predefined conditions.
        """
        for line in text.split('\n'):
            if self.should_skip_sensitive_line(line):
                continue

            if self.redact_sensitive_info(line, self.bot_name) != line:
                return True

        return False

    async def contains_sensitive_attachments(self, attachments):
        """
        Checks if any of the attachments have sensitive information.
        """
        for att in attachments:
            try:
                if att.content_type:
                    mylogger.debug(f"Attachment Content Type: {att.content_type}")  # Log content type for debugging
                else:
                    mylogger.debug(f"Attachment has no content type: {att.filename}")

                if self.is_text_like_attachment(att):
                    att_content = await att.read()
                    try:
                        text_data = att_content.decode('utf-8')  # Decode the bytes to text
                    except UnicodeDecodeError:
                        mylogger.warning(f"Failed to decode attachment {att.filename} as UTF-8; skipping redaction scan.")
                        continue

                    if self.is_sensitive(text_data):
                        return True

            except Exception as e:
                mylogger.error(f"Error processing attachment {att.filename}: {e}")

        return False
