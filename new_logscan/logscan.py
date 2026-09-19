from __future__ import annotations

import io
import re
import zipfile
from urllib.parse import quote

import aiohttp
import discord
from redbot.core import Config, commands

MAX_BYTES = 500 * 1024 * 1024
MAX_BATCH_BYTES = 500 * 1024 * 1024
ALLOWED_SUFFIXES = (".log", ".txt", ".yml", ".yaml", ".zip", ".tar", ".tgz", ".gz") + tuple(f".{n}" for n in range(1, 10))
DEFAULT_PRODUCTION_CHANNEL_IDS = (1539665929330499664,)
MISSING_PEOPLE_CHANNEL_ID = 1539665929330499664
ENVIRONMENTS = ("production", "test")


class ScanPrompt(discord.ui.View):
    def __init__(
        self,
        cog: "LogScan",
        author_id: int,
        attachments: list[discord.Attachment],
        uploaded_by: str,
        uploaded_by_id: int,
        source_url: str | None = None,
    ):
        super().__init__(timeout=120)
        self.cog = cog
        self.author_id = author_id
        self.attachments = attachments
        self.uploaded_by = uploaded_by
        self.uploaded_by_id = uploaded_by_id
        self.source_url = source_url

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.author_id or await self.cog.user_has_privileged_role(interaction.user):
            return True
        await interaction.response.send_message(
            "Only the person who posted the log or a configured support role can choose.",
            ephemeral=True,
        )
        return False

    @discord.ui.button(label="Scan log", style=discord.ButtonStyle.primary, emoji="🔎")
    async def scan(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        self.remove_item(self.cancel)
        button.label = "Scanning…"
        button.emoji = "⏳"
        total_logs = sum(self.cog.valid_log_count(attachment) for attachment in self.attachments)
        await interaction.response.edit_message(content=f"Scanning {total_logs} log(s)…", view=self)
        results = []
        failures = []
        batch_result_url = None
        batch_admin_url = None
        try:
            results, batch_result_url, batch_admin_url = await self.cog.scan_attachments(
                self.attachments, self.source_url, self.uploaded_by, self.uploaded_by_id
            )
        except (aiohttp.ClientError, ValueError) as exc:
            error = str(exc)
            if "Unexpected files:" in error:
                prefix, _, names = error.partition("Unexpected files:")
                unexpected = ", ".join(f"`{name.strip()}`" for name in names.split(",") if name.strip())
                error = f"{prefix}Unexpected files: {unexpected}"
            failures.append(error)
        if not results:
            button.label = "Scan failed"
            button.emoji = "❌"
            await interaction.edit_original_response(content="The log scans failed.", view=self)
            await interaction.followup.send("\n".join(failures), ephemeral=True)
            return
        button.label = "Scan complete"
        button.emoji = "✅"
        await interaction.edit_original_response(content=f"Scan of {len(results)} log(s) complete", view=self)
        is_single_scan = len(results) == 1 and not batch_result_url
        public_results = (
            f"**Batch Results:** [Click Here]({batch_result_url})"
            if batch_result_url else (
                f"**Results:** [Click Here]({results[0][1]})" if is_single_scan
                else "\n".join(f"- `{filename}`: [Click Here]({view_url})" for filename, view_url, *_ in results)
            )
        )
        private_results = (
            f"**Private batch link:** [Click Here]({batch_admin_url})\n\n"
            if batch_admin_url else ""
        )
        if is_single_scan:
            filename, view_url, delete_url, expires_at, missing_people = results[0]
            await interaction.followup.send(
                f"**Scanned File:** `{filename}`\n**Uploaded By:** `{self.uploaded_by}`\n"
                f"**Results:** [Click Here]({view_url})\n**Auto-Delete:** <t:{expires_at}:R>",
                suppress_embeds=True,
            )
            await interaction.followup.send(
                f"Your deletion link: [Click Here]({delete_url})\n"
                "**Keep this link private. Anyone with it can permanently delete the log.**",
                ephemeral=True,
                suppress_embeds=True,
            )
            return
        await interaction.followup.send(
            "**Scanned Files**\n"
            f"**Uploaded By:** `{self.uploaded_by}`\n"
            f"**Auto-Delete:** <t:{results[0][3]}:R>\n\n"
            + public_results,
            suppress_embeds=True,
        )
        await interaction.followup.send(
            "**Private deletion links — keep these secret**\n\n"
            + private_results
            + ("" if batch_admin_url else "\n".join(f"- `{filename}`: [Click Here]({delete_url})" for filename, _view_url, delete_url, *_ in results))
            + "\nAnyone with one of these links can permanently delete its corresponding scan.",
            ephemeral=True,
            suppress_embeds=True,
        )
        if failures:
            await interaction.followup.send("Some files could not be scanned:\n" + "\n".join(failures), ephemeral=True)

    @discord.ui.button(label="No thanks", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(content="Log scan skipped.", view=self)


class LogScan(commands.Cog):
    """Detect and submit Kometa log attachments."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4C4F475343414E, force_registration=True)
        self.config.register_global(
            url="https://logscan.kometa.team",
            api_key="",
            environment="production",
            production_channel_ids=list(DEFAULT_PRODUCTION_CHANNEL_IDS),
            test_channel_ids=[],
            privileged_role_ids=[],
        )
        self.validated_log_counts: dict[int, int] = {}

    async def active_channel_ids(self) -> set[int]:
        """Return the permitted parent-channel IDs for the active environment."""
        environment = await self.config.environment()
        key = f"{environment}_channel_ids" if environment in ENVIRONMENTS else "production_channel_ids"
        return {int(channel_id) for channel_id in await getattr(self.config, key)()}

    async def is_allowed_scan_location(self, channel: discord.abc.GuildChannel) -> bool:
        """Threads are allowed; parent channels must be configured for the active environment."""
        return isinstance(channel, discord.Thread) or channel.id in await self.active_channel_ids()

    async def user_has_privileged_role(self, user: discord.abc.User) -> bool:
        """Whether a guild member may act on another user's scan prompt."""
        role_ids = {int(role_id) for role_id in await self.config.privileged_role_ids()}
        return bool(role_ids and any(role.id in role_ids for role in getattr(user, "roles", ())))

    async def disallowed_channel_message(self) -> str:
        channels = sorted(await self.active_channel_ids())
        destinations = ", ".join(f"<#{channel_id}>" for channel_id in channels)
        if destinations:
            return f"Log scanning is allowed in {destinations} or in a thread created there."
        return "Log scanning is not configured for this environment yet. Ask a bot owner to configure allowed channels."

    def valid_log_count(self, attachment: discord.Attachment) -> int:
        return self.validated_log_counts.get(attachment.id, 1)

    @staticmethod
    def log_attachments(message: discord.Message) -> list[discord.Attachment]:
        return [item for item in message.attachments if item.filename.lower().endswith(ALLOWED_SUFFIXES)]

    async def usable_log_attachments(self, message: discord.Message) -> list[discord.Attachment] | None:
        """Return supported attachments accepted by LogScan's parser within the batch limit."""
        usable = []
        total_size = 0
        for attachment in self.log_attachments(message):
            if attachment.size > MAX_BYTES:
                continue
            validation = await self.validate_attachment(attachment)
            if validation is None:
                continue
            content_size, log_count = validation
            total_size += content_size
            if total_size > MAX_BATCH_BYTES:
                raise ValueError("The files are too large after extraction. Please upload smaller batches of up to 500 MiB each.")
            usable.append(attachment)
            self.validated_log_counts[attachment.id] = log_count
        return usable or None

    async def prompt_for_scan(
        self,
        destination: discord.abc.Messageable,
        author_id: int,
        attachments: list[discord.Attachment],
        uploaded_by: str,
        source_url: str | None = None,
    ) -> None:
        await destination.send(
            f"Would you like me to scan {sum(self.valid_log_count(attachment) for attachment in attachments)} Kometa log(s) to identify issues and suggest improvements?",
            view=ScanPrompt(self, author_id, attachments, uploaded_by, author_id, source_url),
        )

    @commands.Cog.listener()
    async def on_message_without_command(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        attachments = self.log_attachments(message)
        if not attachments:
            return
        if not await self.is_allowed_scan_location(message.channel):
            await message.reply(await self.disallowed_channel_message(), mention_author=False, delete_after=20)
            return
        prompt_message = await message.reply("⏳ *Checking for valid Kometa log files, please wait...*", mention_author=False)
        try:
            usable_attachments = await self.usable_log_attachments(message)
        except ValueError as exc:
            await prompt_message.edit(content=str(exc), view=None)
            return
        if usable_attachments is None:
            if any(item.size > MAX_BYTES for item in attachments):
                await prompt_message.edit(content="That log is larger than the 500 MiB scanner limit.", view=None)
            else:
                await prompt_message.delete()
            return
        await prompt_message.edit(
            content=f"Would you like me to scan {sum(self.valid_log_count(attachment) for attachment in usable_attachments)} Kometa log(s) to identify issues and suggest improvements?",
            view=ScanPrompt(self, message.author.id, usable_attachments, message.author.name, message.author.id, message.jump_url),
        )

    async def _resolve_message(self, ctx: commands.Context, reference: str) -> discord.Message | None:
        match = re.fullmatch(r"https?://(?:canary\.|ptb\.)?discord\.com/channels/\d+/(\d+)/(\d+)", reference)
        channel = ctx.channel
        message_id = reference
        if match:
            channel_id, message_id = map(int, match.groups())
            channel = self.bot.get_channel(channel_id)
            if channel is None:
                try:
                    channel = await self.bot.fetch_channel(channel_id)
                except discord.HTTPException:
                    await ctx.send("I couldn't retrieve the channel from that message link.")
                    return None
        try:
            return await channel.fetch_message(int(message_id))
        except ValueError:
            await ctx.send("Provide a Discord message ID or message link.")
        except discord.NotFound:
            await ctx.send("I couldn't find that message.")
        except discord.HTTPException:
            await ctx.send("I couldn't retrieve that message. Please try again.")
        return None

    async def _offer_scan_for_message(self, ctx: commands.Context, message: discord.Message) -> None:
        attachments = self.log_attachments(message)
        if not attachments:
            await ctx.send("That message doesn't have a supported log attachment.")
            return
        prompt_message = await ctx.send("⏳ *Scanning attachments for valid Kometa log files...*")
        try:
            usable_attachments = await self.usable_log_attachments(message)
        except ValueError as exc:
            await prompt_message.edit(content=str(exc), view=None)
            return
        if usable_attachments is None:
            if any(item.size > MAX_BYTES for item in attachments):
                await prompt_message.edit(content="That log is larger than the 500 MiB scanner limit.", view=None)
            else:
                await prompt_message.edit(content="That message doesn't have a usable Kometa log attachment.", view=None)
            return
        await prompt_message.edit(content=f"Would you like me to scan {sum(self.valid_log_count(attachment) for attachment in usable_attachments)} Kometa log(s) to identify issues and suggest improvements?", view=ScanPrompt(self, ctx.author.id, usable_attachments, message.author.name, message.author.id, message.jump_url))

    @commands.command(name="logscan")
    @commands.guild_only()
    async def scan_log_message(self, ctx: commands.Context, reference: str):
        """Offer to scan a supported attachment from a message in this channel."""
        if not await self.is_allowed_scan_location(ctx.channel):
            await ctx.send(await self.disallowed_channel_message(), delete_after=20)
            return
        message = await self._resolve_message(ctx, reference)
        if message is not None:
            await self._offer_scan_for_message(ctx, message)

    async def validate_attachment(self, attachment: discord.Attachment) -> tuple[int, int] | None:
        """Ask the scanner to validate an attachment before offering a scan."""
        base_url = (await self.config.url()).rstrip("/")
        api_key = await self.config.api_key()
        if not api_key:
            return None
        content = await attachment.read()
        if len(content) > MAX_BYTES:
            return None
        form = aiohttp.FormData()
        form.add_field(
            "log",
            io.BytesIO(content),
            filename=attachment.filename,
            content_type=attachment.content_type or "text/plain",
        )
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = aiohttp.ClientTimeout(total=300)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(f"{base_url}/api/bot/validate", data=form, headers=headers) as response:
                    if response.status != 200:
                        return None
                    files = (await response.json(content_type=None))["files"]
                    return sum(int(file["content_size"]) for file in files), len(files)
        except (aiohttp.ClientError, KeyError, TypeError, ValueError):
            return None

    async def scan_attachments(
        self,
        attachments: list[discord.Attachment],
        source_url: str | None = None,
        uploaded_by: str | None = None,
        uploaded_by_id: int | None = None,
    ) -> tuple[list[tuple[str, str, str, int, list[dict]]], str | None, str | None]:
        """Scan attachments together so multi-log Discord uploads create one batch."""
        if not attachments:
            raise ValueError("no attachments were provided")
        files = [(attachment.filename, await attachment.read(), attachment.content_type) for attachment in attachments]
        if any(len(content) > MAX_BYTES for _filename, content, _content_type in files):
            raise ValueError("the attachment exceeds 500 MiB")
        if sum(len(content) for _filename, content, _content_type in files) > MAX_BATCH_BYTES:
            raise ValueError("the files are too large after extraction. Please upload smaller batches of up to 500 MiB each.")
        if len(files) == 1:
            filename, content, content_type = files[0]
        else:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for filename, content, _content_type in files:
                    bundle.writestr(filename, content)
            filename, content, content_type = "discord-log-batch.zip", archive.getvalue(), "application/zip"
        return await self._submit_scan(filename, content, content_type, source_url, uploaded_by, uploaded_by_id)

    async def _submit_scan(
        self,
        filename: str,
        content: bytes,
        content_type: str | None = None,
        source_url: str | None = None,
        uploaded_by: str | None = None,
        uploaded_by_id: int | None = None,
    ) -> tuple[list[tuple[str, str, str, int, list[dict]]], str | None, str | None]:
        base_url = (await self.config.url()).rstrip("/")
        api_key = await self.config.api_key()
        if not api_key:
            raise ValueError("the cog API key has not been configured")
        if len(content) > MAX_BYTES and not filename.lower().endswith(".zip"):
            raise ValueError("the attachment exceeds 500 MiB")
        form = aiohttp.FormData()
        form.add_field(
            "log",
            io.BytesIO(content),
            filename=filename,
            content_type=content_type or "text/plain",
        )
        if source_url:
            form.add_field("source_url", source_url)
        if uploaded_by:
            form.add_field("uploaded_by", uploaded_by)
        if uploaded_by_id is not None:
            form.add_field("uploaded_by_id", str(uploaded_by_id))
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = aiohttp.ClientTimeout(total=300)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{base_url}/api/bot/scan", data=form, headers=headers) as response:
                payload = await response.json(content_type=None)
                if response.status != 200:
                    raise ValueError(payload.get("error", f"server returned HTTP {response.status}"))
        results = []
        for scan in payload["scans"]:
            view_url = scan["result_url"]
            delete_url = f"{view_url}#delete={quote(scan['delete_token'], safe='')}"
            results.append((scan["filename"], view_url, delete_url, int(scan["expires_at"]), scan.get("missing_people", [])))
        return results, payload.get("batch_result_url"), payload.get("batch_admin_url")

    async def notify_missing_people(
        self,
        *,
        filename: str,
        log_url: str,
        source_url: str | None,
        people: list[dict],
    ) -> None:
        """Post one concise, non-embedding notice for every detected missing person."""
        if not people:
            return
        channel = self.bot.get_channel(MISSING_PEOPLE_CHANNEL_ID)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(MISSING_PEOPLE_CHANNEL_ID)
            except discord.HTTPException:
                return
        for person in people:
            source = f"[Click Here]({source_url})" if source_url else "Not available"
            message = (
                f"Log Name: `{filename}`\n"
                f"Log Url: [Click Here]({log_url})\n"
                f"Log Source: {source}\n"
                f"Person Found: {person.get('name', 'Unknown')}\n"
                f"TMDb Image Found: {'Yes' if person.get('tmdb_image_found') else 'No'}\n"
                f"Link: [Click Here]({person.get('people_url', log_url)})"
            )
            try:
                await channel.send(message, suppress_embeds=True)
            except discord.HTTPException:
                return

    @commands.group(name="logscanset")
    @commands.is_owner()
    async def logscan_settings(self, ctx: commands.Context):
        """Configure the LogScan service."""

    @logscan_settings.command(name="url")
    async def set_url(self, ctx: commands.Context, url: str):
        await self.config.url.set(url.rstrip("/"))
        await ctx.send("LogScan URL updated.")

    @logscan_settings.command(name="apikey")
    async def set_api_key(self, ctx: commands.Context, api_key: str):
        await self.config.api_key.set(api_key)
        try:
            await ctx.message.delete()
        except discord.HTTPException:
            pass
        await ctx.send("LogScan API key updated.", delete_after=10)

    @logscan_settings.command(name="environment")
    async def set_environment(self, ctx: commands.Context, environment: str):
        """Select the production or test channel set."""
        environment = environment.lower()
        if environment not in ENVIRONMENTS:
            await ctx.send("Environment must be `production` or `test`.")
            return
        await self.config.environment.set(environment)
        await ctx.send(f"LogScan environment set to `{environment}`.")

    @logscan_settings.command(name="channels")
    async def set_channels(self, ctx: commands.Context, environment: str, *channel_ids: int):
        """Set allowed parent-channel IDs for production or test."""
        environment = environment.lower()
        if environment not in ENVIRONMENTS:
            await ctx.send("Environment must be `production` or `test`.")
            return
        if not channel_ids:
            await ctx.send("Provide at least one channel ID.")
            return
        await getattr(self.config, f"{environment}_channel_ids").set(list(dict.fromkeys(channel_ids)))
        await ctx.send(f"{environment.title()} scan channels updated: " + ", ".join(f"<#{channel_id}>" for channel_id in channel_ids))

    @logscan_settings.command(name="roles")
    async def set_privileged_roles(self, ctx: commands.Context, *role_ids: int):
        """Set role IDs allowed to act on another user's scan prompt."""
        await self.config.privileged_role_ids.set(list(dict.fromkeys(role_ids)))
        if role_ids:
            await ctx.send("Privileged scan roles updated: " + ", ".join(f"<@&{role_id}>" for role_id in role_ids))
        else:
            await ctx.send("Privileged scan roles cleared.")
