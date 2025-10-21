from __future__ import annotations

import asyncio
import re
import logging
from typing import Optional

import discord
from redbot.core import commands, app_commands

# 862041125706268702  Sponsor
# 938443185347244033  Support
# 1097919568334311495 Priority Support
# 822460010649878531  #general-chat
# 1006644783743258635 #kometa-help

# 1232124371901087764 Test Sponsor
# 1232122972521762836 Test Support
# 1232121280971407362 Test Priority Support
# 1138466667165405244 #bot-chat
# 1138466814519693412 #bot-forums

# 938492411649339462 - Docker
# 938490334286082068 - Linux
# 938490571637555220 - Mac
# 938490657717252148 - NAS
# 938490888437502053 - Windows
# 938490820129079296 - Unraid
# 938492563596406876 - Master Build
# 938492604989968454 - Develop Build
# 952912471226716192 - Nightly Build

# Create logger
mylogger = logging.getLogger("threads")
mylogger.setLevel(logging.DEBUG)


class Buttons(discord.ui.View):
    def __init__(self, cog: "Threads", bot_role: discord.Role, user_id: int, *, timeout: Optional[float] = None):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.bot_role = bot_role
        self.user_id = user_id

    @discord.ui.button(label="Close Post", style=discord.ButtonStyle.red, emoji="🔒", custom_id="Close Post")
    async def gray_button(self, interaction: discord.Interaction, button: discord.ui.Button, **kwargs):
        thread = interaction.channel
        if thread and isinstance(thread, discord.Thread):
            member = interaction.guild.get_member(interaction.user.id)
            mylogger.info(f"User roles: {[role.id for role in member.roles] if member else 'unknown'}")
            mylogger.info(f"Bot role: {self.bot_role.id if self.bot_role else 'missing'}")
            if interaction.user.id == self.user_id or (member and self.bot_role in member.roles):
                await self.cog._close(interaction)
            else:
                await interaction.response.send_message("You don't have permission to use this button.", ephemeral=True)


class Threads(commands.Cog):
    """Creates support thread greetings and integrates with SponsorCheck to validate sponsors automatically."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id
        self.setup_role_logic()

    # ---------- Role/Channel wiring ----------
    def setup_role_logic(self):
        self.role1 = None            # Priority Support
        self.role2 = None            # Support
        self.sponsor = None          # Sponsor role
        self.general_chat = None     # general/bot chat channel (for close notes)
        self.parent_channel_id = None  # Forums/Help parent id

        # Match the two bot identities you use today
        if self.bot.user.id == 1138446898487894206:  # Botmoose20 (test)
            self.role1 = 1232121280971407362  # Test Priority Support
            self.role2 = 1232122972521762836  # Test Support
            self.sponsor = 1232124371901087764  # Test Sponsor
            self.general_chat = 1138466667165405244  # #bot-chat
            self.parent_channel_id = 1138466814519693412  # #bot-forums
        elif self.bot.user.id == 1422494031388344340:  # Luma (prod)
            self.role1 = 1097919568334311495  # Priority Support
            self.role2 = 938443185347244033  # Support
            self.sponsor = 862041125706268702  # Sponsor
            self.general_chat = 822460010649878531  # #general-chat
            self.parent_channel_id = 1006644783743258635  # #kometa-help

    # ---------- Helper: ask SponsorCheck for current/past/private ----------
    async def _eval_sponsor_status(
        self, guild: discord.Guild, member: discord.Member
    ) -> Optional[object]:
        """
        Calls SponsorCheck.check_discord_member(guild, member) if available.
        Returns SponsorEval or None on failure/missing cog.
        """
        cog = self.bot.get_cog("SponsorCheck")
        if not cog:
            mylogger.warning("SponsorCheck cog not loaded; skipping sponsor auto-eval.")
            return None
        try:
            return await cog.check_discord_member(guild, member)  # type: ignore[attr-defined]
        except Exception as e:
            mylogger.exception("SponsorCheck.check_discord_member failed: %s", e)
            return None

    # ---------- Thread create listener ----------
    @commands.Cog.listener()
    async def on_thread_create(self, thread: discord.Thread):
        # Log invocation details
        author = f"{thread.owner.name}#{thread.owner.discriminator}" if thread.owner else "Unknown"
        gname = thread.guild.name if thread.guild else "Direct Message"
        parent_name = thread.parent.name if isinstance(thread.parent, discord.TextChannel) else "Direct Message"
        mylogger.info(
            f"Threads invoked by {author} in {gname}/{parent_name} "
            f"(ID: {thread.guild.id if thread.guild else 'N/A'}/{thread.parent.id if thread.parent else 'N/A'})"
        )

        # Only handle threads under the designated help/forums channel
        if not thread.parent or thread.parent.id != self.parent_channel_id:
            return

        # Resolve roles
        role1 = thread.guild.get_role(self.role1) if self.role1 else None
        role2 = thread.guild.get_role(self.role2) if self.role2 else None
        if not role1:
            mylogger.error(
                f"role1: {self.role1} is missing. Someone may have removed the Priority Support role. Aborting now..."
            )
            return
        if not role2:
            mylogger.error(
                f"role2: {self.role2} is missing. Someone may have removed the Support role. Aborting now..."
            )
            return

        # Give Discord time to attach initial content
        await asyncio.sleep(2)

        # Try to extract the username from the auto-created thread name/first line
        # (e.g., "Underskore needs assistance. Invoked by ...")
        initial_message_content = str(thread)
        match = re.search(r"(\w+) needs assistance\. Invoked by", initial_message_content)
        username = match.group(1) if match else None

        # Resolve target user (member we should greet)
        user: Optional[discord.Member] = None
        if username:
            user = discord.utils.get(thread.guild.members, name=username)
        if not user:
            user = thread.owner  # fallback
        if not isinstance(user, discord.Member):
            mylogger.warning("Could not resolve thread user; aborting greeting.")
            return

        # Build initial mention and pull roles
        initial_mention = f"Welcome {user.mention}!\n\n"
        user_id = user.id
        user_roles = user.roles

        # Apply the "Open" tag if present
        tags = []
        for tag in thread.parent.available_tags:
            if tag.name.lower() == "open":
                tags.append(tag)
        try:
            if tags:
                await thread.edit(applied_tags=tags)
        except Exception as e:
            mylogger.warning(f"Failed to set 'Open' tag on thread: {e}")

        # Evaluate sponsor status using SponsorCheck (auto-grants sponsor role if current & possible)
        eval = await self._eval_sponsor_status(thread.guild, user)

        # Helper: allowed mentions and Buttons view
        allowed = discord.AllowedMentions(roles=[r for r in [role1, role2] if r])
        bot_role_for_button = role2

        # Sponsor/current: preferred priority path
        if any(role.id == self.sponsor for role in user_roles) or (eval and eval.is_current):
            msg = (
                f"{initial_mention}"
                "Thanks for being a Kometa Sponsor, we greatly appreciate it! "
                f"Your ticket will now be diverted to <@&{self.role1}> and <@&{self.role2}>.\n\n"
                "Including `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\n"
                "After attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n"
            )
            if eval and getattr(eval, "grant_role_msg", None):
                msg += f"_(Role update: {eval.grant_role_msg})_\n"
            await thread.send(msg, allowed_mentions=allowed, view=Buttons(self, bot_role_for_button, user_id))

        # Known tech/build roles (your existing middle path)
        elif any(
            role.id
            in [
                952912471226716192,  # Nightly Build
                938492604989968454,  # Develop Build
                938492563596406876,  # Master Build
                938490820129079296,  # Unraid
                938490888437502053,  # Windows
                938490657717252148,  # NAS
                938490571637555220,  # Mac
                938490334286082068,  # Linux
                938492411649339462,  # Docker
            ]
            for role in user_roles
        ):
            await thread.send(
                f"{initial_mention}"
                "Someone from <@&{self.role2}> will assist when they're available.\n\n"
                "Including `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\n"
                "After attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                allowed_mentions=discord.AllowedMentions(roles=[role1, role2]),
                view=Buttons(self, bot_role_for_button, user_id),
            )

        # Past sponsor acknowledgement (optional, comes before the default path)
        elif eval and getattr(eval, "is_past", False):
            await thread.send(
                f"{initial_mention}"
                "Thanks for having supported Kometa previously ❤️. "
                f"Someone from <@&{self.role2}> will assist when they're available.\n\n"
                "Including `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\n"
                "After attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                allowed_mentions=discord.AllowedMentions(roles=[role1, role2]),
                view=Buttons(self, bot_role_for_button, user_id),
            )

        # Default path
        else:
            await thread.send(
                f"{initial_mention}"
                "It looks like you have not yet completed the <id:customize> section of our Discord server, "
                "this will allow us to help you quicker.\n\n"
                f"Someone from <@&{self.role2}> will assist when they're available.\n\n"
                "Including `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\n"
                "After attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                allowed_mentions=discord.AllowedMentions(roles=[role1, role2]),
                view=Buttons(self, bot_role_for_button, user_id),
            )

        # Pin the close instructions
        message = await thread.send(
            'You can press the "Close Post" button above or type `/close` at any time to close this post.'
        )
        try:
            await message.pin(reason="Makes it easier to close the post.")
        except Exception as e:
            mylogger.warning(f"Failed to pin close instructions: {e}")

    # ---------- Slash close command ----------
    @app_commands.command()
    async def close(self, interaction: discord.Interaction):
        await self._close(interaction)

    # ---------- Close helper ----------
    async def _close(self, interaction: discord.Interaction):
        if not isinstance(interaction.channel, discord.Thread):
            await interaction.response.send_message("This command can only be used in a thread.", ephemeral=True)
            return

        channel: discord.Thread = interaction.channel
        channel_owner = channel.owner

        initial_message_content = str(channel)
        mylogger.info(f"initial_message_content: {initial_message_content}")

        # Try to recover "who needed help" from the thread name/body
        match = re.search(r"(.*?) needs assistance\. Invoked by ", initial_message_content)
        user_that_needed_help = match.group(1) if match else None

        user_that_needed_help_id = None
        if user_that_needed_help and user_that_needed_help != "U_n_k_n_o_w_n":
            user_obj = discord.utils.get(channel.guild.members, name=user_that_needed_help)
            if user_obj:
                user_that_needed_help_id = user_obj.id

        mylogger.info(f"channel: {channel}")
        mylogger.info(f"channel_owner: {channel_owner}")
        mylogger.info(f"channel.parent: {channel.parent}")
        mylogger.info(f"channel.parent.id: {getattr(channel.parent, 'id', None)}")
        mylogger.info(f"self.parent_channel_id: {self.parent_channel_id}")
        mylogger.info(f"user_that_needed_help: {user_that_needed_help}")
        mylogger.info(f"user_that_needed_help_id: {user_that_needed_help_id}")
        mylogger.info(f"channel.owner_id: {channel.owner_id}")

        if not channel.parent or channel.parent.id != self.parent_channel_id:
            await interaction.response.send_message("This command can only be used in the help forum.", ephemeral=True)
            return

        member = interaction.guild.get_member(interaction.user.id)
        mylogger.info(f"member.id: {member.id if member else 'unknown'}")
        mylogger.info(f"member.guild_permissions.manage_threads: {member.guild_permissions.manage_threads if member else 'unknown'}")
        if member is None:
            await interaction.response.send_message(
                "Sorry, I couldn't find your member information. Please try again later.", ephemeral=True
            )
            return

        # Permissions: thread owner, staff with manage_threads, or the member who asked for help
        if member.id == channel.owner_id or member.guild_permissions.manage_threads or user_that_needed_help_id == member.id:
            try:
                await interaction.response.send_message(
                    "This post has been marked as Resolved and has now been closed."
                    f"\n\nYou cannot reopen this thread - you must create a new one or ask a member of staff to reopen it in <#{self.general_chat}>."
                    "\n\nThanks for using Kometa.",
                    ephemeral=False,
                )
                tags = []
                for tag in channel.parent.available_tags:
                    if tag.name.lower() == "closed":
                        tags.append(tag)
                    # remove review tags if present
                    if tag.name.lower() == "sohjiro to review" and tag in tags:
                        tags.remove(tag)
                    if tag.name.lower() == "staff to review" and tag in tags:
                        tags.remove(tag)
                await channel.edit(locked=True, archived=True, applied_tags=tags)
            except discord.Forbidden:
                await interaction.response.send_message(
                    "I don't have the necessary permissions to close and lock the thread.", ephemeral=True
                )
            except discord.HTTPException as e:
                await interaction.response.send_message(
                    f"An error occurred while attempting to close and lock the thread. {e}", ephemeral=True
                )
            except Exception as e:
                await interaction.response.send_message(
                    f"An unexpected error occurred. Please try again later. {e}", ephemeral=True
                )
        else:
            await interaction.response.send_message(
                f"Hello {channel_owner.mention if channel_owner else 'there'}, a user has suggested that this thread has been "
                "resolved and can be closed.\n\nPlease confirm that you are happy to close this thread by typing `/close` "
                "or by pressing the Close Post button which is pinned to this thread."
            )


async def setup(bot: commands.Bot):
    await bot.add_cog(Threads(bot))