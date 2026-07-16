import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import discord
from discord.ext import tasks
from redbot.core import Config, commands

log = logging.getLogger("red.honeypot")

DELETE_MESSAGE_SECONDS = 3 * 24 * 60 * 60
DEFAULT_BAN_DAYS = 7


class HoneypotPanel(discord.ui.View):
    """Display-only components for the warning panel."""

    def __init__(self, action_count: int):
        super().__init__(timeout=None)

        self.add_item(
            discord.ui.Button(
                label=f"Actions: {action_count}",
                emoji="🔒",
                style=discord.ButtonStyle.secondary,
                disabled=True,
            )
        )


class Honeypot(commands.Cog):
    """Temporarily ban accounts that post in a protected channel."""

    __author__ = "Kevin Smart"
    __version__ = "1.0.0"

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
            "ban_duration_days": DEFAULT_BAN_DAYS,
            "action_count": 0,
            # Stored as:
            # {
            #     "user_id": {
            #         "expires_at": ISO timestamp,
            #         "reason": str
            #     }
            # }
            "temporary_bans": {},
        }

        self.config.register_guild(**default_guild)

        # Prevent the same account being processed twice if Discord dispatches
        # multiple messages in quick succession.
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

        Use `[p]help honeypot` to see the available commands.
        """

        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @honeypot.command(name="channel")
    async def set_monitored_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ):
        """Set the channel that must not receive user messages."""

        await self.config.guild(ctx.guild).monitored_channel_id.set(channel.id)

        # A newly selected channel will need a new panel.
        await self.config.guild(ctx.guild).panel_message_id.set(None)

        await ctx.send(
            f"The monitored channel has been set to {channel.mention}."
        )

    @honeypot.command(name="bypassrole")
    async def set_bypass_role(
        self,
        ctx: commands.Context,
        role: discord.Role,
    ):
        """Set the role permitted to test the protected channel."""

        await self.config.guild(ctx.guild).bypass_role_id.set(role.id)

        await ctx.send(
            f"The bypass role has been set to {role.mention}."
        )

    @honeypot.command(name="reportchannel")
    async def set_report_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ):
        """Set the channel where enforcement reports are sent."""

        await self.config.guild(ctx.guild).report_channel_id.set(channel.id)

        await ctx.send(
            f"Enforcement reports will be sent to {channel.mention}."
        )

    @honeypot.command(name="duration")
    async def set_duration(
        self,
        ctx: commands.Context,
        days: commands.Range[int, 1, 28],
    ):
        """Set the temporary-ban duration, between 1 and 28 days."""

        await self.config.guild(ctx.guild).ban_duration_days.set(days)

        await ctx.send(
            f"Accounts will now remain banned for **{days} day"
            f"{'s' if days != 1 else ''}**."
        )

    @honeypot.command(name="post")
    @commands.bot_has_permissions(
        send_messages=True,
        embed_links=True,
    )
    async def post_panel(self, ctx: commands.Context):
        """Post or replace the warning panel in the monitored channel."""

        settings = await self.config.guild(ctx.guild).all()
        channel_id = settings["monitored_channel_id"]

        if channel_id is None:
            await ctx.send(
                f"Set the monitored channel first with "
                f"`{ctx.clean_prefix}honeypot channel #channel`."
            )
            return

        channel = ctx.guild.get_channel(channel_id)

        if not isinstance(channel, discord.TextChannel):
            await ctx.send(
                "The configured monitored channel no longer exists."
            )
            return

        permissions = channel.permissions_for(ctx.guild.me)

        missing = []

        if not permissions.view_channel:
            missing.append("View Channel")

        if not permissions.send_messages:
            missing.append("Send Messages")

        if not permissions.embed_links:
            missing.append("Embed Links")

        if missing:
            await ctx.send(
                f"I am missing these permissions in {channel.mention}: "
                f"**{', '.join(missing)}**."
            )
            return

        old_message_id = settings["panel_message_id"]

        if old_message_id:
            try:
                old_message = await channel.fetch_message(old_message_id)
                await old_message.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass

        embed = self.build_panel_embed()
        view = HoneypotPanel(settings["action_count"])

        message = await channel.send(embed=embed, view=view)

        await self.config.guild(ctx.guild).panel_message_id.set(message.id)

        await ctx.send(
            f"The protected-channel notice was posted in {channel.mention}."
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

        temporary_bans = settings["temporary_bans"]

        embed = discord.Embed(
            title="Protected-channel status",
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
            value=f"{settings['ban_duration_days']} days",
        )
        embed.add_field(
            name="Recorded actions",
            value=str(settings["action_count"]),
        )
        embed.add_field(
            name="Pending unbans",
            value=str(len(temporary_bans)),
        )

        await ctx.send(embed=embed)

    @honeypot.command(name="reset")
    async def reset_configuration(self, ctx: commands.Context):
        """Reset this server's honeypot configuration."""

        await self.config.guild(ctx.guild).clear()

        await ctx.send(
            "The protected-channel configuration has been reset."
        )

    # -------------------------------------------------------------------------
    # Message listener
    # -------------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.guild is None:
            return

        if message.author.id == self.bot.user.id:
            return

        # Webhook messages have no normal guild-member account to punish.
        if message.webhook_id is not None:
            return

        if not isinstance(message.author, discord.Member):
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

        # The server owner cannot be banned by a bot. Bot owners are also
        # protected to avoid an accidental lockout during testing.
        is_server_owner = member.id == guild.owner_id
        is_bot_owner = await self.bot.is_owner(member)

        if has_bypass_role or is_server_owner or is_bot_owner:
            await self._handle_bypass_message(
                message=message,
                settings=settings,
                bypass_type=(
                    "Configured bypass role"
                    if has_bypass_role
                    else "Protected owner account"
                ),
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
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

        embed = self.build_report_embed(
            message=message,
            title="Protected-channel test triggered",
            colour=discord.Colour.gold(),
        )

        embed.description = (
            f"{message.author.mention} posted in the protected channel, "
            "but no action was taken."
        )

        embed.add_field(
            name="Result",
            value="The account would normally have been temporarily banned.",
            inline=False,
        )
        embed.add_field(
            name="Bypass",
            value=bypass_type,
            inline=False,
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
        expires_at = datetime.now(timezone.utc) + timedelta(days=duration_days)

        reason = (
            f"Posted in protected channel #{message.channel.name}. "
            f"Temporary ban for {duration_days} days."
        )

        report_embed = self.build_report_embed(
            message=message,
            title="Protected-channel ban",
            colour=discord.Colour.red(),
        )

        report_embed.description = (
            f"{member.mention} posted in the protected channel and was "
            f"temporarily banned for **{duration_days} days**."
        )

        report_embed.add_field(
            name="Ban expires",
            value=discord.utils.format_dt(expires_at, style="F"),
            inline=False,
        )
        report_embed.add_field(
            name="Message deletion",
            value="Messages from the previous three days were requested for deletion.",
            inline=False,
        )

        try:
            await guild.ban(
                member,
                reason=reason,
                delete_message_seconds=DELETE_MESSAGE_SECONDS,
            )

        except discord.Forbidden:
            report_embed.title = "Protected-channel ban failed"
            report_embed.colour = discord.Colour.dark_red()

            report_embed.add_field(
                name="Error",
                value=(
                    "Discord refused the ban. Check that the bot has "
                    "**Ban Members** and that its highest role is above the "
                    "member's highest role."
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

            report_embed.title = "Protected-channel ban failed"
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
            }

        action_count = await self.config.guild(guild).action_count()
        action_count += 1
        await self.config.guild(guild).action_count.set(action_count)

        await self.send_report(
            guild=guild,
            report_channel_id=settings["report_channel_id"],
            embed=report_embed,
        )

        await self.update_panel(guild, action_count)

    # -------------------------------------------------------------------------
    # Temporary-ban expiry
    # -------------------------------------------------------------------------

    @tasks.loop(minutes=1)
    async def expired_ban_loop(self):
        now = datetime.now(timezone.utc)

        for guild in list(self.bot.guilds):
            bans = await self.config.guild(guild).temporary_bans()

            if not bans:
                continue

            expired_user_ids = []

            for user_id_text, ban_data in bans.items():
                try:
                    user_id = int(user_id_text)
                    expires_at = datetime.fromisoformat(
                        ban_data["expires_at"]
                    )

                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)

                except (KeyError, TypeError, ValueError):
                    log.warning(
                        "Removing invalid temporary-ban record for guild %s: %r",
                        guild.id,
                        user_id_text,
                    )
                    expired_user_ids.append(user_id_text)
                    continue

                if expires_at > now:
                    continue

                try:
                    await guild.unban(
                        discord.Object(id=user_id),
                        reason="Protected-channel temporary ban expired.",
                    )

                except discord.NotFound:
                    # Someone already removed the ban manually.
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

                expired_user_ids.append(user_id_text)

                settings = await self.config.guild(guild).all()

                embed = discord.Embed(
                    title="Temporary ban expired",
                    description=(
                        f"<@{user_id}>'s protected-channel ban has expired."
                    ),
                    colour=discord.Colour.green(),
                    timestamp=discord.utils.utcnow(),
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

            if expired_user_ids:
                async with self.config.guild(guild).temporary_bans() as stored:
                    for user_id_text in expired_user_ids:
                        stored.pop(user_id_text, None)

    @expired_ban_loop.before_loop
    async def before_expired_ban_loop(self):
        await self.bot.wait_until_red_ready()

    # -------------------------------------------------------------------------
    # Embeds and reports
    # -------------------------------------------------------------------------

    @staticmethod
    def build_panel_embed() -> discord.Embed:
        embed = discord.Embed(
            title="READ-ONLY SYSTEM CHANNEL",
            description=(
                "This channel is reserved for automated server processing.\n\n"
                "Please do not send messages here. Posting may cause your "
                "server access to be restricted automatically."
            ),
            colour=discord.Colour.from_rgb(232, 143, 39),
        )

        embed.add_field(
            name="Need assistance?",
            value="Use one of the server's normal support or general channels.",
            inline=False,
        )

        embed.set_footer(
            text="Automated access protection"
        )

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

        embed.add_field(
            name="Account",
            value=(
                f"**Username:** {discord.utils.escape_markdown(str(member))}\n"
                f"**Mention:** {member.mention}\n"
                f"**User ID:** `{member.id}`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Account created",
            value=discord.utils.format_dt(
                member.created_at,
                style="F",
            ),
            inline=True,
        )

        if member.joined_at:
            joined_value = discord.utils.format_dt(
                member.joined_at,
                style="F",
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
            for role in member.roles
            if role != message.guild.default_role
        ]

        embed.add_field(
            name="Roles",
            value=", ".join(role_mentions)[0:1024] or "No roles",
            inline=False,
        )

        content = message.content.strip()

        if not content:
            content = "*No text content*"

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
            name="Attachments",
            value=str(len(message.attachments)),
            inline=True,
        )

        if message.attachments:
            attachment_names = "\n".join(
                f"• {attachment.filename}"
                for attachment in message.attachments[:10]
            )

            embed.add_field(
                name="Attachment names",
                value=attachment_names[:1024],
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
                "Failed to send honeypot report in guild %s",
                guild.id,
            )

    async def update_panel(
        self,
        guild: discord.Guild,
        action_count: int,
    ):
        settings = await self.config.guild(guild).all()

        channel_id = settings["monitored_channel_id"]
        message_id = settings["panel_message_id"]

        if channel_id is None or message_id is None:
            return

        channel = guild.get_channel(channel_id)

        if not isinstance(channel, discord.TextChannel):
            return

        try:
            message = await channel.fetch_message(message_id)

            await message.edit(
                embed=self.build_panel_embed(),
                view=HoneypotPanel(action_count),
            )

        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException,
        ):
            log.warning(
                "Could not update the honeypot panel in guild %s",
                guild.id,
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