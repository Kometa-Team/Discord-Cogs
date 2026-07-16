import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import discord
from discord.ext import tasks
from redbot.core import Config, commands

log = logging.getLogger("red.honeypot")

DELETE_MESSAGE_SECONDS = 3 * 24 * 60 * 60
DEFAULT_BAN_DAYS = 7


class HoneypotPanel(discord.ui.View):
    """Display-only controls shown beneath the honeypot notice."""

    def __init__(self, action_count: int):
        super().__init__(timeout=None)

        self.add_item(
            discord.ui.Button(
                label=f"Bans: {action_count}",
                emoji="🔒",
                style=discord.ButtonStyle.secondary,
                disabled=True,
            )
        )


class Honeypot(commands.Cog):
    """Temporarily ban accounts that post in a protected channel."""

    __author__ = "Kevin Smart"
    __version__ = "1.1.0"

    def __init__(self, bot):
        self.bot = bot

        self.config = Config.get_conf(
            self,
            identifier=784215963147,
            force_registration=True,
        )

        default_guild = {
            "monitored_channel_id": None,
            "bypass_role_id": None,
            "report_channel_id": None,
            "panel_message_id": None,
            "panel_image_url": None,
            "ban_duration_days": DEFAULT_BAN_DAYS,
            "action_count": 0,
            "temporary_bans": {},
        }

        self.config.register_guild(**default_guild)

        # Prevent the same account being handled more than once when several
        # messages arrive before the first ban operation finishes.
        self._processing: set[tuple[int, int]] = set()
        self._processing_lock = asyncio.Lock()

    async def cog_load(self):
        if not self.expired_ban_loop.is_running():
            self.expired_ban_loop.start()

    def cog_unload(self):
        self.expired_ban_loop.cancel()

    # -------------------------------------------------------------------------
    # Configuration commands
    # -------------------------------------------------------------------------

    @commands.group(name="honeypot")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def honeypot(self, ctx: commands.Context):
        """
        Configure the protected channel.

        Run `[p]help honeypot` to view the available commands.
        """

        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @honeypot.command(name="channel")
    async def set_monitored_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ):
        """
        Set the channel monitored by the honeypot.

        You may provide a channel mention, name or ID.
        """

        guild_config = self.config.guild(ctx.guild)
        previous_channel_id = await guild_config.monitored_channel_id()
        previous_message_id = await guild_config.panel_message_id()

        # Delete the old panel when changing to a different channel.
        if (
            previous_channel_id
            and previous_message_id
            and previous_channel_id != channel.id
        ):
            previous_channel = ctx.guild.get_channel(previous_channel_id)

            if isinstance(previous_channel, discord.TextChannel):
                try:
                    previous_message = await previous_channel.fetch_message(
                        previous_message_id
                    )
                    await previous_message.delete()
                except (
                    discord.NotFound,
                    discord.Forbidden,
                    discord.HTTPException,
                ):
                    pass

        await guild_config.monitored_channel_id.set(channel.id)
        await guild_config.panel_message_id.set(None)

        await ctx.send(
            f"The monitored channel has been set to {channel.mention}."
        )

    @honeypot.command(name="bypassrole")
    async def set_bypass_role(
        self,
        ctx: commands.Context,
        role: discord.Role,
    ):
        """
        Set the role allowed to test the honeypot.

        You may provide a role mention, name or ID.
        """

        await self.config.guild(ctx.guild).bypass_role_id.set(role.id)

        await ctx.send(
            f"The bypass role has been set to {role.mention} "
            f"(`{role.id}`)."
        )

    @honeypot.command(name="reportchannel")
    async def set_report_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ):
        """
        Set the channel that receives honeypot reports.

        You may provide a channel mention, name or ID.
        """

        await self.config.guild(ctx.guild).report_channel_id.set(channel.id)

        await ctx.send(
            f"Honeypot reports will be sent to {channel.mention}."
        )

    @honeypot.command(name="image")
    async def set_panel_image(
        self,
        ctx: commands.Context,
        image_url: str,
    ):
        """
        Set the thumbnail image shown on the honeypot notice.

        The image must use a direct HTTP or HTTPS URL.
        """

        if not self._is_valid_url(image_url):
            await ctx.send(
                "Please provide a valid direct image URL beginning with "
                "`http://` or `https://`."
            )
            return

        await self.config.guild(ctx.guild).panel_image_url.set(image_url)

        updated = await self.update_panel(ctx.guild)

        if updated:
            await ctx.send(
                "The image has been saved and the existing honeypot notice "
                "has been updated."
            )
        else:
            await ctx.send(
                "The image has been saved. Run "
                f"`{ctx.clean_prefix}honeypot post` to post the notice."
            )

    @honeypot.command(name="clearimage")
    async def clear_panel_image(self, ctx: commands.Context):
        """Remove the thumbnail image from the honeypot notice."""

        await self.config.guild(ctx.guild).panel_image_url.set(None)

        updated = await self.update_panel(ctx.guild)

        if updated:
            await ctx.send(
                "The image has been removed from the honeypot notice."
            )
        else:
            await ctx.send("The saved honeypot image has been removed.")

    @honeypot.command(name="duration")
    async def set_duration(
        self,
        ctx: commands.Context,
        days: int,
    ):
        """Set the temporary-ban duration, from 1 to 28 days."""

        if days < 1 or days > 28:
            await ctx.send(
                "The ban duration must be between **1 and 28 days**."
            )
            return

        await self.config.guild(ctx.guild).ban_duration_days.set(days)

        await ctx.send(
            f"Honeypot bans will now last for **{days} "
            f"day{'s' if days != 1 else ''}**."
        )

    @honeypot.command(name="post")
    @commands.bot_has_permissions(
        view_channel=True,
        send_messages=True,
        embed_links=True,
    )
    async def post_panel(self, ctx: commands.Context):
        """Post or replace the notice in the monitored channel."""

        settings = await self.config.guild(ctx.guild).all()
        channel_id = settings["monitored_channel_id"]

        if channel_id is None:
            await ctx.send(
                "Set the monitored channel first using:\n"
                f"`{ctx.clean_prefix}honeypot channel CHANNEL_ID`"
            )
            return

        channel = ctx.guild.get_channel(channel_id)

        if not isinstance(channel, discord.TextChannel):
            await ctx.send(
                "The configured monitored channel could not be found. "
                "Please configure it again."
            )
            return

        permissions = channel.permissions_for(ctx.guild.me)
        missing_permissions = []

        if not permissions.view_channel:
            missing_permissions.append("View Channel")

        if not permissions.send_messages:
            missing_permissions.append("Send Messages")

        if not permissions.embed_links:
            missing_permissions.append("Embed Links")

        if missing_permissions:
            await ctx.send(
                f"I am missing the following permissions in "
                f"{channel.mention}: "
                f"**{', '.join(missing_permissions)}**."
            )
            return

        old_message_id = settings["panel_message_id"]

        if old_message_id:
            try:
                old_message = await channel.fetch_message(old_message_id)
                await old_message.delete()
            except (
                discord.NotFound,
                discord.Forbidden,
                discord.HTTPException,
            ):
                pass

        embed = self.build_panel_embed(settings["panel_image_url"])
        view = HoneypotPanel(settings["action_count"])

        try:
            message = await channel.send(
                embed=embed,
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException as exc:
            await ctx.send(
                f"I could not post the honeypot notice: `{str(exc)[:1000]}`"
            )
            return

        await self.config.guild(ctx.guild).panel_message_id.set(message.id)

        await ctx.send(
            f"The honeypot notice was posted in {channel.mention}."
        )

    @honeypot.command(name="status")
    async def show_status(self, ctx: commands.Context):
        """Show the current honeypot configuration."""

        settings = await self.config.guild(ctx.guild).all()

        monitored = self._channel_text(
            ctx.guild,
            settings["monitored_channel_id"],
        )

        report = self._channel_text(
            ctx.guild,
            settings["report_channel_id"],
        )

        bypass = self._role_text(
            ctx.guild,
            settings["bypass_role_id"],
        )

        image_url = settings["panel_image_url"]
        temporary_bans = settings["temporary_bans"]

        embed = discord.Embed(
            title="Honeypot Configuration",
            colour=discord.Colour.orange(),
            timestamp=discord.utils.utcnow(),
        )

        embed.add_field(
            name="Monitored channel",
            value=monitored,
            inline=False,
        )

        embed.add_field(
            name="Bypass role",
            value=bypass,
            inline=False,
        )

        embed.add_field(
            name="Report channel",
            value=report,
            inline=False,
        )

        embed.add_field(
            name="Ban duration",
            value=(
                f"{settings['ban_duration_days']} "
                f"day{'s' if settings['ban_duration_days'] != 1 else ''}"
            ),
            inline=True,
        )

        embed.add_field(
            name="Messages deleted",
            value="Previous 3 days",
            inline=True,
        )

        embed.add_field(
            name="Recorded bans",
            value=str(settings["action_count"]),
            inline=True,
        )

        embed.add_field(
            name="Pending automatic unbans",
            value=str(len(temporary_bans)),
            inline=True,
        )

        embed.add_field(
            name="Panel posted",
            value="Yes" if settings["panel_message_id"] else "No",
            inline=True,
        )

        embed.add_field(
            name="Custom image",
            value=image_url or "Not configured",
            inline=False,
        )

        if image_url:
            embed.set_thumbnail(url=image_url)

        await ctx.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @honeypot.command(name="reset")
    async def reset_configuration(self, ctx: commands.Context):
        """
        Reset the honeypot configuration.

        Existing temporary-ban records are retained so users can still be
        automatically unbanned.
        """

        guild_config = self.config.guild(ctx.guild)
        settings = await guild_config.all()

        temporary_bans = settings["temporary_bans"]
        panel_message_id = settings["panel_message_id"]
        monitored_channel_id = settings["monitored_channel_id"]

        if panel_message_id and monitored_channel_id:
            channel = ctx.guild.get_channel(monitored_channel_id)

            if isinstance(channel, discord.TextChannel):
                try:
                    message = await channel.fetch_message(panel_message_id)
                    await message.delete()
                except (
                    discord.NotFound,
                    discord.Forbidden,
                    discord.HTTPException,
                ):
                    pass

        await guild_config.clear()
        await guild_config.temporary_bans.set(temporary_bans)

        await ctx.send(
            "The honeypot configuration has been reset. Existing temporary "
            "ban records were retained so their automatic unbans still occur."
        )

    # -------------------------------------------------------------------------
    # Message listener
    # -------------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.guild is None:
            return

        if not isinstance(message.author, discord.Member):
            return

        # Do not act on messages from Discord bots or webhooks. This prevents
        # another integration from accidentally being banned.
        if message.author.bot or message.webhook_id is not None:
            return

        settings = await self.config.guild(message.guild).all()
        monitored_channel_id = settings["monitored_channel_id"]

        if monitored_channel_id is None:
            return

        if message.channel.id != monitored_channel_id:
            return

        key = (message.guild.id, message.author.id)

        async with self._processing_lock:
            if key in self._processing:
                return

            self._processing.add(key)

        try:
            await self._handle_protected_message(message, settings)
        finally:
            async with self._processing_lock:
                self._processing.discard(key)

    async def _handle_protected_message(
        self,
        message: discord.Message,
        settings: dict,
    ):
        guild = message.guild
        member = message.author

        bypass_role_id = settings["bypass_role_id"]

        has_bypass_role = (
            bypass_role_id is not None
            and any(role.id == bypass_role_id for role in member.roles)
        )

        is_server_owner = member.id == guild.owner_id
        is_bot_owner = await self.bot.is_owner(member)

        if has_bypass_role or is_server_owner or is_bot_owner:
            if has_bypass_role:
                bypass_type = "Configured bypass role"
            elif is_server_owner:
                bypass_type = "Server owner protection"
            else:
                bypass_type = "Red bot owner protection"

            await self._handle_bypass_message(
                message=message,
                settings=settings,
                bypass_type=bypass_type,
            )
            return

        await self._temporarily_ban_member(
            message=message,
            settings=settings,
        )

    async def _handle_bypass_message(
        self,
        message: discord.Message,
        settings: dict,
        bypass_type: str,
    ):
        message_deleted = False

        try:
            await message.delete()
            message_deleted = True
        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException,
        ):
            pass

        embed = self.build_report_embed(
            message=message,
            title="Honeypot Test Triggered",
            colour=discord.Colour.gold(),
        )

        embed.description = (
            f"{message.author.mention} posted in the monitored channel, "
            "but no moderation action was taken."
        )

        embed.add_field(
            name="Test result",
            value=(
                "This account would normally have been temporarily banned "
                f"for **{settings['ban_duration_days']} days**."
            ),
            inline=False,
        )

        embed.add_field(
            name="Bypass reason",
            value=bypass_type,
            inline=False,
        )

        embed.add_field(
            name="Test message deleted",
            value="Yes" if message_deleted else "No",
            inline=True,
        )

        await self.send_report(
            guild=message.guild,
            report_channel_id=settings["report_channel_id"],
            embed=embed,
        )

    async def _temporarily_ban_member(
        self,
        message: discord.Message,
        settings: dict,
    ):
        guild = message.guild
        member = message.author

        duration_days = settings["ban_duration_days"]
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=duration_days
        )

        reason = (
            f"Posted in monitored channel #{message.channel.name}. "
            f"Temporary honeypot ban for {duration_days} days."
        )

        report_embed = self.build_report_embed(
            message=message,
            title="Honeypot Ban",
            colour=discord.Colour.red(),
        )

        report_embed.description = (
            f"{member.mention} posted in the monitored channel and was "
            f"temporarily banned for **{duration_days} days**."
        )

        report_embed.add_field(
            name="Ban expires",
            value=(
                f"{discord.utils.format_dt(expires_at, style='F')}\n"
                f"({discord.utils.format_dt(expires_at, style='R')})"
            ),
            inline=False,
        )

        report_embed.add_field(
            name="Message deletion",
            value=(
                "Discord was instructed to delete the account's messages "
                "from the previous **3 days** across the server."
            ),
            inline=False,
        )

        try:
            await guild.ban(
                member,
                reason=reason,
                delete_message_seconds=DELETE_MESSAGE_SECONDS,
            )

        except discord.Forbidden:
            report_embed.title = "Honeypot Ban Failed"
            report_embed.colour = discord.Colour.dark_red()

            report_embed.add_field(
                name="Error",
                value=(
                    "Discord refused the ban. Check that the bot has the "
                    "**Ban Members** permission and that its highest role is "
                    "above the member's highest role."
                ),
                inline=False,
            )

            await self.send_report(
                guild=guild,
                report_channel_id=settings["report_channel_id"],
                embed=report_embed,
            )
            return

        except discord.HTTPException as exc:
            log.exception(
                "Discord rejected a honeypot ban in guild %s",
                guild.id,
            )

            report_embed.title = "Honeypot Ban Failed"
            report_embed.colour = discord.Colour.dark_red()

            report_embed.add_field(
                name="Discord error",
                value=f"`{str(exc)[:900]}`",
                inline=False,
            )

            await self.send_report(
                guild=guild,
                report_channel_id=settings["report_channel_id"],
                embed=report_embed,
            )
            return

        async with self.config.guild(guild).temporary_bans() as bans:
            bans[str(member.id)] = {
                "expires_at": expires_at.isoformat(),
                "reason": reason,
                "username": str(member),
            }

        action_count = await self.config.guild(guild).action_count()
        action_count += 1

        await self.config.guild(guild).action_count.set(action_count)

        await self.send_report(
            guild=guild,
            report_channel_id=settings["report_channel_id"],
            embed=report_embed,
        )

        await self.update_panel(guild, action_count=action_count)

    # -------------------------------------------------------------------------
    # Automatic unbanning
    # -------------------------------------------------------------------------

    @tasks.loop(minutes=1)
    async def expired_ban_loop(self):
        now = datetime.now(timezone.utc)

        for guild in list(self.bot.guilds):
            bans = await self.config.guild(guild).temporary_bans()

            if not bans:
                continue

            completed_user_ids = []

            for user_id_text, ban_data in bans.items():
                try:
                    user_id = int(user_id_text)
                    expires_at = datetime.fromisoformat(
                        ban_data["expires_at"]
                    )

                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(
                            tzinfo=timezone.utc
                        )

                except (KeyError, TypeError, ValueError):
                    log.warning(
                        "Removing invalid honeypot ban record for guild %s: %r",
                        guild.id,
                        user_id_text,
                    )

                    completed_user_ids.append(user_id_text)
                    continue

                if expires_at > now:
                    continue

                try:
                    await guild.unban(
                        discord.Object(id=user_id),
                        reason="Honeypot temporary ban expired.",
                    )

                except discord.NotFound:
                    # A moderator has already removed the ban.
                    pass

                except discord.Forbidden:
                    log.warning(
                        "Missing permission to unban user %s in guild %s",
                        user_id,
                        guild.id,
                    )
                    continue

                except discord.HTTPException:
                    log.exception(
                        "Failed to unban user %s in guild %s",
                        user_id,
                        guild.id,
                    )
                    continue

                completed_user_ids.append(user_id_text)

                settings = await self.config.guild(guild).all()
                stored_username = ban_data.get("username", "Unknown")

                embed = discord.Embed(
                    title="Honeypot Ban Expired",
                    description=(
                        f"The temporary honeypot ban for <@{user_id}> "
                        "has expired and the account has been unbanned."
                    ),
                    colour=discord.Colour.green(),
                    timestamp=discord.utils.utcnow(),
                )

                embed.add_field(
                    name="Username when banned",
                    value=discord.utils.escape_markdown(stored_username),
                    inline=False,
                )

                embed.add_field(
                    name="User ID",
                    value=f"`{user_id}`",
                    inline=False,
                )

                await self.send_report(
                    guild=guild,
                    report_channel_id=settings["report_channel_id"],
                    embed=embed,
                )

            if completed_user_ids:
                async with self.config.guild(guild).temporary_bans() as stored:
                    for user_id_text in completed_user_ids:
                        stored.pop(user_id_text, None)

    @expired_ban_loop.before_loop
    async def before_expired_ban_loop(self):
        await self.bot.wait_until_red_ready()

    # -------------------------------------------------------------------------
    # Embeds and reports
    # -------------------------------------------------------------------------

    @staticmethod
    def build_panel_embed(
        image_url: Optional[str] = None,
    ) -> discord.Embed:
        embed = discord.Embed(
            title="DO NOT SEND MESSAGES IN THIS CHANNEL",
            description=(
                "This channel is reserved for automated system processing "
                "and should never receive user messages.\n\n"
                "Messages posted here are handled automatically and will "
                "result in your access to this server being removed."
            ),
            colour=discord.Colour.orange(),
        )

        if image_url:
            embed.set_thumbnail(url=image_url)

        return embed

    @staticmethod
    def build_report_embed(
        message: discord.Message,
        title: str,
        colour: discord.Colour,
    ) -> discord.Embed:
        member = message.author

        embed = discord.Embed(
            title=title,
            colour=colour,
            timestamp=discord.utils.utcnow(),
        )

        embed.set_author(
            name=str(member),
            icon_url=member.display_avatar.url,
        )

        embed.set_thumbnail(url=member.display_avatar.url)

        embed.add_field(
            name="Account",
            value=(
                f"**Username:** "
                f"{discord.utils.escape_markdown(str(member))}\n"
                f"**Display name:** "
                f"{discord.utils.escape_markdown(member.display_name)}\n"
                f"**Mention:** {member.mention}\n"
                f"**User ID:** `{member.id}`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Account created",
            value=(
                f"{discord.utils.format_dt(member.created_at, style='F')}\n"
                f"({discord.utils.format_dt(member.created_at, style='R')})"
            ),
            inline=True,
        )

        if member.joined_at:
            joined_value = (
                f"{discord.utils.format_dt(member.joined_at, style='F')}\n"
                f"({discord.utils.format_dt(member.joined_at, style='R')})"
            )
        else:
            joined_value = "Unknown"

        embed.add_field(
            name="Joined server",
            value=joined_value,
            inline=True,
        )

        role_mentions = [
            role.mention
            for role in reversed(member.roles)
            if role != message.guild.default_role
        ]

        embed.add_field(
            name="Roles",
            value=", ".join(role_mentions)[:1024] or "No roles",
            inline=False,
        )

        content = message.content.strip()

        if not content:
            content = "*No text content*"
        else:
            content = discord.utils.escape_markdown(content)

        if len(content) > 1000:
            content = content[:997] + "..."

        embed.add_field(
            name="Triggering message",
            value=content,
            inline=False,
        )

        embed.add_field(
            name="Channel",
            value=message.channel.mention,
            inline=True,
        )

        embed.add_field(
            name="Message ID",
            value=f"`{message.id}`",
            inline=True,
        )

        embed.add_field(
            name="Attachments",
            value=str(len(message.attachments)),
            inline=True,
        )

        if message.attachments:
            attachment_lines = []

            for attachment in message.attachments[:10]:
                attachment_lines.append(
                    f"• [{attachment.filename}]({attachment.url})"
                )

            embed.add_field(
                name="Attachment details",
                value="\n".join(attachment_lines)[:1024],
                inline=False,
            )

        return embed

    async def send_report(
        self,
        guild: discord.Guild,
        report_channel_id: Optional[int],
        embed: discord.Embed,
    ):
        if report_channel_id is None:
            log.warning(
                "No honeypot report channel configured for guild %s",
                guild.id,
            )
            return

        channel = guild.get_channel(report_channel_id)

        if not isinstance(channel, discord.TextChannel):
            log.warning(
                "Honeypot report channel %s was not found in guild %s",
                report_channel_id,
                guild.id,
            )
            return

        try:
            await channel.send(
                embed=embed,
                allowed_mentions=discord.AllowedMentions.none(),
            )

        except discord.HTTPException:
            log.exception(
                "Failed to send a honeypot report in guild %s",
                guild.id,
            )

    async def update_panel(
        self,
        guild: discord.Guild,
        action_count: Optional[int] = None,
    ) -> bool:
        settings = await self.config.guild(guild).all()

        channel_id = settings["monitored_channel_id"]
        message_id = settings["panel_message_id"]

        if channel_id is None or message_id is None:
            return False

        channel = guild.get_channel(channel_id)

        if not isinstance(channel, discord.TextChannel):
            return False

        if action_count is None:
            action_count = settings["action_count"]

        try:
            message = await channel.fetch_message(message_id)

            await message.edit(
                embed=self.build_panel_embed(
                    settings["panel_image_url"]
                ),
                view=HoneypotPanel(action_count),
            )

            return True

        except discord.NotFound:
            await self.config.guild(guild).panel_message_id.set(None)
            return False

        except (discord.Forbidden, discord.HTTPException):
            log.exception(
                "Could not update the honeypot panel in guild %s",
                guild.id,
            )
            return False

    @staticmethod
    def _is_valid_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
        except ValueError:
            return False

        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
        )

    @staticmethod
    def _channel_text(
        guild: discord.Guild,
        channel_id: Optional[int],
    ) -> str:
        if channel_id is None:
            return "Not configured"

        channel = guild.get_channel(channel_id)

        if channel is None:
            return f"Missing channel (`{channel_id}`)"

        return channel.mention

    @staticmethod
    def _role_text(
        guild: discord.Guild,
        role_id: Optional[int],
    ) -> str:
        if role_id is None:
            return "Not configured"

        role = guild.get_role(role_id)

        if role is None:
            return f"Missing role (`{role_id}`)"

        return role.mention