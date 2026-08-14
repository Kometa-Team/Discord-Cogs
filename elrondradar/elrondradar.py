import asyncio
import json
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Optional, Tuple

import aiohttp
import discord
from redbot.core import Config, app_commands, commands


log = logging.getLogger("red.elrondradar")

DEFAULT_ALLOWED_USER_IDS = [396052375409917952]
DEFAULT_ALLOWED_ROLE_IDS = [
    1198381095553617922,
    1252252269790105721,
    1247172016490938472,
]
DEFAULT_TENANT_ROLE_IDS = [1391914584440311840]
DEFAULT_LINK_INSTRUCTIONS_CHANNEL_ID = 1392004498611900476
SUPPORTED_EMOJIS = {"🚨", "🐧", "🏎️", "🏎", "👀", "🛠️", "🛠", "⏳", "⌛", "✅", "📦", "🔁", "🔄"}
DEFAULT_TICKET_CATEGORY_ID = 1281426693906759730
DEFAULT_ADDITIONAL_TICKET_CATEGORY_IDS = [1310419382169501767]
LEGACY_BACKEND_CHANNEL_ID = 1480735317089587251
DEFAULT_BACKEND_CHANNEL_ID = 1532180274119573617
DEFAULT_INTAKE_TEMPLATE = """🧾 **Ticket Intake**

🎫 **Ticket**
{ticket_channel}
{source_url}

👤 **Tenant**
- Account: `{account}`
- Discord: {tenant_discord}

📝 **Report**
{excerpt_block}

{support_context_block}

{staff_notes_block}

🧠 **Next step**
Use the button to ask Elrond to diagnose this ticket."""
USERNAME_RE = re.compile(r"(?:aa-)?[a-z0-9][a-z0-9-]{1,60}", re.IGNORECASE)
USERNAME_STOPWORDS = {"account", "elfhosted", "username", "user", "none", "unknown", "not", "sure", "unsure", "na", "n/a"}


class DiagnosisRequestModal(discord.ui.Modal):
    """Collect staff context before asking Elrond to spend diagnosis tokens."""

    def __init__(self, cog, ticket_channel_id: int, ticket_channel_name: str, ticket_url: str, backend_thread_id: int, source_message_id: int, tenant_username: str = ""):
        super().__init__(title="Elrond diagnosis")
        self.cog = cog
        self.ticket_channel_id = ticket_channel_id
        self.ticket_channel_name = ticket_channel_name
        self.ticket_url = ticket_url
        self.backend_thread_id = backend_thread_id
        self.source_message_id = source_message_id
        self.tenant_username = tenant_username
        self.context = discord.ui.TextInput(
            label="What should Elrond focus on?",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=800,
            placeholder="Optional. Add symptoms, suspicion, or what has already been checked.",
        )
        self.add_item(self.context)

    async def on_submit(self, interaction: discord.Interaction):
        guild_id = interaction.guild.id if interaction.guild else await self.cog.config.guild_id()
        data = {
            "action": "diagnosis_requested",
            "guild_id": str(guild_id),
            "channel_id": str(self.ticket_channel_id),
            "channel_name": self.ticket_channel_name,
            "message_id": str(self.source_message_id),
            "message_url": self.ticket_url,
            "tenant_username": self.tenant_username,
            "message_content": str(self.context.value or "").strip(),
            "backend_thread_id": str(self.backend_thread_id),
            "backend_thread_url": getattr(interaction.channel, "jump_url", ""),
            "staff_discord_id": str(interaction.user.id),
            "staff_display_name": getattr(interaction.user, "display_name", str(interaction.user)),
        }
        await self.cog._post_legacy_diagnosis_request_notice(data)
        await interaction.response.send_message(
            "Posted an Elrond diagnosis request into the backend thread.",
            ephemeral=True,
        )


class DiagnosisRequestView(discord.ui.View):
    """Button wrapper that opens the diagnosis modal on demand."""

    def __init__(self, cog, ticket_channel_id: int, ticket_channel_name: str, ticket_url: str, backend_thread_id: int, source_message_id: int, tenant_username: str = ""):
        super().__init__(timeout=None)
        self.tenant_username = tenant_username
        button = discord.ui.Button(
            label="Activate Elrond diagnosis",
            style=discord.ButtonStyle.primary,
            custom_id=f"elrondradar:diagnose:{ticket_channel_id}",
        )

        async def callback(interaction: discord.Interaction):
            if interaction.guild is None:
                await interaction.response.send_message("Run this from the ElfHosted guild.", ephemeral=True)
                return
            member = interaction.user if isinstance(interaction.user, discord.Member) else None
            if not await cog._is_allowed_staff(interaction.guild, interaction.user.id, member):
                await interaction.response.send_message("Only authorised staff can activate Elrond diagnosis.", ephemeral=True)
                return
            await interaction.response.send_modal(
                DiagnosisRequestModal(cog, ticket_channel_id, ticket_channel_name, ticket_url, backend_thread_id, source_message_id, self.tenant_username)
            )

        button.callback = callback
        self.add_item(button)


class ElrondRadar(commands.Cog):
    """Bridge staff reactions to Elrond support radar."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=2026051701, force_registration=True)
        self.config.register_global(
            enabled=False,
            endpoint_url="",
            gateway_token="",
            guild_id=396055506072109067,
            allowed_user_ids=DEFAULT_ALLOWED_USER_IDS,
            allowed_role_ids=DEFAULT_ALLOWED_ROLE_IDS,
            tenant_role_ids=DEFAULT_TENANT_ROLE_IDS,
            link_instructions_channel_id=DEFAULT_LINK_INSTRUCTIONS_CHANNEL_ID,
            ticket_category_id=DEFAULT_TICKET_CATEGORY_ID,
            ticket_category_ids=DEFAULT_ADDITIONAL_TICKET_CATEGORY_IDS,
            backend_channel_id=DEFAULT_BACKEND_CHANNEL_ID,
            announce_ticket_link=True,
            tracked_ticket_channel_ids=[],
            tracked_ticket_backend_notice_ids=[],
            tracked_ticket_backend_link_notice_ids=[],
            tracked_ticket_link_notice_ids=[],
            tracked_ticket_identity_resolved={},
            tracked_ticket_backend_thread_ids={},
            tracked_ticket_user_history={},
            user_notes={},
            intake_template=DEFAULT_INTAKE_TEMPLATE,
        )
        self._pending_ticket_intake_tasks = {}

    async def cog_load(self):
        # Migrate existing installs from the old text backchannel to the new staff-only forum.
        try:
            if await self.config.backend_channel_id() == LEGACY_BACKEND_CHANNEL_ID:
                await self.config.backend_channel_id.set(DEFAULT_BACKEND_CHANNEL_ID)
                log.info("Elrond radar backend channel migrated to forum channel %s", DEFAULT_BACKEND_CHANNEL_ID)
        except Exception:
            log.exception("Elrond radar could not migrate backend forum channel")

    def cog_unload(self):
        for task in self._pending_ticket_intake_tasks.values():
            task.cancel()
        self._pending_ticket_intake_tasks.clear()

    def _reactions_intent_state(self) -> str:
        intents = getattr(self.bot, "intents", None)
        if intents is None:
            return "unknown"
        if hasattr(intents, "reactions"):
            return str(getattr(intents, "reactions"))
        return str(getattr(intents, "guild_reactions", "unknown"))

    def _normalized_emoji(self, emoji) -> str:
        return str(emoji or "").strip().replace("\ufe0f", "")

    def _is_supported_emoji(self, emoji) -> bool:
        text = str(emoji or "").strip()
        return text in SUPPORTED_EMOJIS or self._normalized_emoji(text) in SUPPORTED_EMOJIS

    async def _ticket_category_ids(self):
        category_ids = []
        primary = await self.config.ticket_category_id()
        if primary:
            category_ids.append(primary)
        for category_id in await self.config.ticket_category_ids() or []:
            if category_id:
                category_ids.append(category_id)
        return list(dict.fromkeys(category_ids))

    async def _is_ticket_category(self, channel) -> bool:
        return getattr(channel, "category_id", None) in set(await self._ticket_category_ids())

    @commands.group(name="elrondradar")
    @commands.admin_or_permissions(manage_guild=True)
    async def elrondradar(self, ctx):
        """Configure the Elrond support radar bridge."""

    @elrondradar.command(name="enable")
    async def enable(self, ctx):
        """Enable reaction forwarding."""
        await self.config.enabled.set(True)
        await ctx.send("Elrond radar bridge enabled.")

    @elrondradar.command(name="disable")
    async def disable(self, ctx):
        """Disable reaction forwarding."""
        await self.config.enabled.set(False)
        await ctx.send("Elrond radar bridge disabled.")

    @elrondradar.command(name="setendpoint")
    async def setendpoint(self, ctx, endpoint_url: str):
        """Set the Elrond/OpenClaw webhook endpoint URL."""
        await self.config.endpoint_url.set(endpoint_url.strip())
        await ctx.send("Elrond radar endpoint updated.")

    @elrondradar.command(name="settoken")
    async def settoken(self, ctx, gateway_token: str):
        """Set the OpenClaw gateway token used for webhook auth."""
        await self.config.gateway_token.set(gateway_token.strip())
        await ctx.send("Elrond radar gateway token updated.")

    @elrondradar.command(name="status")
    async def status(self, ctx):
        """Show bridge status without revealing the token."""
        cfg = await self.config.all()
        token_state = "set" if cfg.get("gateway_token") else "missing"
        await ctx.send(
            "Elrond radar bridge:\n"
            f"- enabled: {cfg.get('enabled')}\n"
            f"- endpoint: {cfg.get('endpoint_url')}\n"
            f"- guild_id: {cfg.get('guild_id')}\n"
            f"- token: {token_state}\n"
            f"- reactions intent: {self._reactions_intent_state()}\n"
            f"- ticket category: {cfg.get('ticket_category_id')}\n"
            f"- extra ticket categories: {', '.join(str(item) for item in cfg.get('ticket_category_ids') or []) or 'none'}\n"
            f"- backend channel: {cfg.get('backend_channel_id')}\n"
            f"- announce ticket link: {cfg.get('announce_ticket_link')}\n"
            f"- pending ticket intake retries: {len(self._pending_ticket_intake_tasks)}\n"
            f"- allowed users: {len(cfg.get('allowed_user_ids') or [])}\n"
            f"- allowed roles: {len(cfg.get('allowed_role_ids') or [])}\n"
            f"- tenant roles: {len(cfg.get('tenant_role_ids') or [])}\n"
            f"- link instructions channel: {cfg.get('link_instructions_channel_id')}\n"
            f"- intake template: {len(cfg.get('intake_template') or '')} chars"
        )

    @elrondradar.command(name="showintaketemplate")
    async def showintaketemplate(self, ctx):
        """Show the current backend intake template."""
        template = await self.config.intake_template() or DEFAULT_INTAKE_TEMPLATE
        await ctx.send(("Current Elrond intake template:\n```text\n" + template.replace("```", "`\u200b``") + "\n```")[:1900], allowed_mentions=discord.AllowedMentions.none())

    @elrondradar.command(name="setintaketemplate")
    async def setintaketemplate(self, ctx, *, template: str):
        """Set the backend intake template. Use resetintaketemplate to restore default."""
        if not template.strip():
            await ctx.send("Template cannot be empty.")
            return
        await self.config.intake_template.set(template.strip())
        await ctx.send("Elrond radar intake template updated.")

    @elrondradar.command(name="resetintaketemplate")
    async def resetintaketemplate(self, ctx):
        """Reset the backend intake template to the default."""
        await self.config.intake_template.set(DEFAULT_INTAKE_TEMPLATE)
        await ctx.send("Elrond radar intake template reset to default.")

    @elrondradar.command(name="setticketcategory")
    async def setticketcategory(self, ctx, category_id: int):
        """Set the Discord category ID watched for fresh support tickets."""
        await self.config.ticket_category_id.set(category_id)
        await ctx.send("Elrond radar ticket category updated.")

    @elrondradar.command(name="addticketcategory")
    async def addticketcategory(self, ctx, category_id: int):
        """Add a Discord category ID watched for fresh support tickets."""
        category_ids = await self._ticket_category_ids()
        category_ids.append(category_id)
        category_ids = list(dict.fromkeys(category_ids))
        primary = await self.config.ticket_category_id()
        extra_ids = [item for item in category_ids if item != primary]
        await self.config.ticket_category_ids.set(extra_ids)
        await ctx.send(f"Elrond radar ticket categories updated: {', '.join(str(item) for item in category_ids)}")

    @elrondradar.command(name="removeticketcategory")
    async def removeticketcategory(self, ctx, category_id: int):
        """Remove an extra Discord category ID watched for fresh support tickets."""
        primary = await self.config.ticket_category_id()
        if category_id == primary:
            await ctx.send("Use setticketcategory to change the primary ticket category.")
            return
        category_ids = [item for item in await self._ticket_category_ids() if item != category_id]
        await self.config.ticket_category_ids.set([item for item in category_ids if item != primary])
        await ctx.send(f"Elrond radar ticket categories updated: {', '.join(str(item) for item in category_ids) or 'none'}")

    @elrondradar.command(name="setbackendchannel")
    async def setbackendchannel(self, ctx, channel_id: int):
        """Set the staff backend channel where intake threads are created."""
        await self.config.backend_channel_id.set(channel_id)
        await ctx.send("Elrond radar backend channel updated.")

    @elrondradar.command(name="settenantrole")
    async def settenantrole(self, ctx, role_id: int):
        """Set the Discord role used to identify tenant members in ticket channels."""
        await self.config.tenant_role_ids.set([role_id])
        await ctx.send("Elrond radar tenant role updated.")

    @elrondradar.command(name="setlinkchannel")
    async def setlinkchannel(self, ctx, channel_id: int):
        """Set the channel users should visit to link their Discord account."""
        await self.config.link_instructions_channel_id.set(channel_id)
        await ctx.send("Elrond radar link instructions channel updated.")

    @elrondradar.command(name="cleartickets")
    async def cleartickets(self, ctx):
        """Clear tracked ticket IDs so category scan/create can retry intake."""
        await self.config.tracked_ticket_channel_ids.set([])
        await self.config.tracked_ticket_backend_notice_ids.set([])
        await self.config.tracked_ticket_backend_link_notice_ids.set([])
        await self.config.tracked_ticket_link_notice_ids.set([])
        await self.config.tracked_ticket_identity_resolved.set({})
        await self.config.tracked_ticket_backend_thread_ids.set({})
        await self.config.tracked_ticket_user_history.set({})
        await ctx.send("Elrond radar tracked ticket cache cleared.")

    @elrondradar.command(name="scantickets")
    async def scantickets(self, ctx, limit: int = 25, force: bool = False):
        """Scan configured ticket category and create missing backend intake threads."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return

        category_ids = set(await self._ticket_category_ids())
        candidates = [
            channel for channel in getattr(ctx.guild, "text_channels", [])
            if getattr(channel, "category_id", None) in category_ids
        ]
        candidates = sorted(candidates, key=lambda channel: getattr(channel, "created_at", None) or discord.utils.utcnow(), reverse=True)
        processed = 0
        attempted = 0
        async with ctx.typing():
            for channel in candidates[: max(1, min(limit, 100))]:
                attempted += 1
                if await self._handle_ticket_channel_create(channel, force=force):
                    processed += 1
        await ctx.send(f"Elrond radar ticket scan complete: processed {processed}/{attempted} visible channel(s) in categories {', '.join(str(item) for item in category_ids)}. force={force}")

    @elrondradar.command(name="rerunintake", aliases=["rerunticket"])
    async def rerunintake(self, ctx, channel_id: int):
        """Force a fresh backend intake for one support ticket channel."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return

        channel = self.bot.get_channel(channel_id)
        if channel is None:
            try:
                channel = await ctx.guild.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
                await ctx.send(f"Could not fetch ticket channel {channel_id}: {exc}")
                return

        requested_channel = channel
        category_ids = set(await self._ticket_category_ids())
        if getattr(channel, "category_id", None) not in category_ids:
            source_channel = await self._source_ticket_channel_from_intake(ctx.guild, channel)
            if source_channel is not None:
                channel = source_channel

        async with ctx.typing():
            try:
                processed = await self._handle_ticket_channel_create(channel, force=True)
            except Exception as exc:
                log.exception("Elrond radar forced intake failed for channel %s", channel_id)
                await ctx.send(f"Elrond radar forced intake failed for {channel_id}: {exc}")
                return

        if processed:
            if requested_channel.id == channel.id:
                await ctx.send(f"Elrond radar forced intake posted for <#{channel.id}>.")
            else:
                await ctx.send(f"Elrond radar forced intake posted for <#{channel.id}> from backend thread <#{requested_channel.id}>.")
        else:
            await ctx.send(f"Elrond radar did not post an intake for <#{channel.id}>. Run inspectticket {channel.id} for details.")

    @elrondradar.command(name="inspectticket")
    async def inspectticket(self, ctx, channel_id: int):
        """Show what Redbot can mechanically extract from a support ticket channel."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return

        channel = self.bot.get_channel(channel_id)
        if channel is None:
            try:
                channel = await ctx.guild.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
                await ctx.send(f"Could not fetch ticket channel {channel_id}: {exc}")
                return

        if not hasattr(channel, "history"):
            await ctx.send(f"Channel {channel_id} is not a readable text channel.")
            return

        tenant_member = await self._ticket_tenant_member(channel)
        visible_members = await self._ticket_visible_members(channel)
        unlinked_members = [member for member in visible_members if tenant_member is None or member.id != tenant_member.id]
        first_message = await self._first_useful_channel_message(channel, tenant_member.id if tenant_member is not None else None)
        ticket_username = self._ticket_username(first_message)
        excerpt = self._message_excerpt(first_message, limit=900)
        source_url = first_message.jump_url if first_message is not None else f"https://discord.com/channels/{ctx.guild.id}/{channel.id}"
        category_id = getattr(channel, "category_id", None)
        expected_categories = set(await self._ticket_category_ids())
        tracked = set(await self.config.tracked_ticket_channel_ids() or [])
        tracked_notices = set(await self.config.tracked_ticket_backend_notice_ids() or [])
        tracked_backend_links = set(await self.config.tracked_ticket_backend_link_notice_ids() or [])
        tracked_link_notices = set(await self.config.tracked_ticket_link_notice_ids() or [])
        tracked_identity = await self.config.tracked_ticket_identity_resolved() or {}
        if not isinstance(tracked_identity, dict):
            tracked_identity = {}
        tracked_key = str(channel.id)
        is_tracked = channel.id in tracked
        tracked_identity_resolved = tracked_identity.get(tracked_key, True) if is_tracked else None
        if category_id not in expected_categories:
            automatic_state = "skipped: wrong category"
        elif is_tracked and tracked_identity_resolved:
            automatic_state = "skipped: already tracked with resolved identity"
        elif is_tracked and not tracked_identity_resolved and not (tenant_member is not None or ticket_username):
            automatic_state = "skipped: tracked sparse intake still lacks identity"
        else:
            automatic_state = "eligible for automatic intake scan"

        backend_thread = None
        thread_username = self._thread_username(channel, ticket_username, tenant_member)
        channel_thread_name = self._thread_username(channel, "", None)
        backend_channel = await self._backend_channel(channel)
        if backend_channel is not None:
            for lookup_name in (thread_username, channel_thread_name):
                backend_thread = await self._find_backend_thread(backend_channel, lookup_name)
                if backend_thread is not None:
                    break
        backend_thread_line = "- backend thread: not found"
        if backend_thread is not None:
            backend_thread_url = getattr(backend_thread, "jump_url", "")
            backend_thread_line = f"- backend thread: #{getattr(backend_thread, 'name', backend_thread.id)} ({backend_thread.id})"
            if backend_thread_url:
                backend_thread_line += f" {backend_thread_url}"

        lines = [
            "Elrond radar ticket inspection:",
            f"- channel: #{getattr(channel, 'name', channel.id)} ({channel.id})",
            f"- category: {category_id} ({'ok' if category_id in expected_categories else 'expected one of ' + ', '.join(str(item) for item in expected_categories)})",
            f"- tracked intake: {'yes' if is_tracked else 'no'}",
            f"- backend notice posted: {'yes' if channel.id in tracked_notices else 'no'}",
            f"- backend link posted in ticket: {'yes' if channel.id in tracked_backend_links else 'no'}",
            f"- link-required notice posted: {'yes' if channel.id in tracked_link_notices else 'no'}",
            backend_thread_line,
            f"- tracked identity resolved: {tracked_identity_resolved if tracked_identity_resolved is not None else 'n/a'}",
            f"- automatic scan state: {automatic_state}",
            f"- linked discord member: {tenant_member} ({tenant_member.id})" if tenant_member is not None else "- linked discord member: not found",
            f"- modal account username: {ticket_username}" if ticket_username else "- modal account username: not found",
            "- unlinked visible members: " + (", ".join(f"{member} ({member.id})" for member in unlinked_members[:5]) if unlinked_members else "none"),
            f"- first useful message: {first_message.id} by {first_message.author}" if first_message is not None else "- first useful message: not found",
            f"- source: {source_url}",
            "- excerpt: " + (excerpt or "not provided"),
        ]
        await ctx.send("\n".join(lines)[:1900], allowed_mentions=discord.AllowedMentions.none())

    @elrondradar.command(name="previewintake", aliases=["previewticket"])
    async def previewintake(self, ctx, channel_id: int):
        """Render the LLM-free backend intake text without posting or calling Elrond."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return

        channel = self.bot.get_channel(channel_id)
        if channel is None:
            try:
                channel = await ctx.guild.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
                await ctx.send(f"Could not fetch ticket channel {channel_id}: {exc}")
                return
        if not hasattr(channel, "history"):
            await ctx.send(f"Channel {channel_id} is not a readable text channel.")
            return

        tenant_member = await self._ticket_tenant_member(channel)
        visible_members = await self._ticket_visible_members(channel)
        first_message = await self._first_useful_channel_message(channel, tenant_member.id if tenant_member is not None else None)
        ticket_username = self._ticket_username(first_message)
        message_excerpt = self._message_excerpt(first_message)
        intake_member = tenant_member or (visible_members[0] if visible_members else None)
        thread_username = self._thread_username(channel, ticket_username, tenant_member)
        source_message_id = first_message.id if first_message is not None else channel.id
        ticket_url = first_message.jump_url if first_message is not None else f"https://discord.com/channels/{ctx.guild.id}/{channel.id}"
        user_notes = await self._format_user_notes_for_intake(
            str(intake_member.id) if intake_member is not None else (str(first_message.author.id) if first_message is not None else ""),
            ticket_username or thread_username,
        )

        support_context = await self._build_support_context(
            username=ticket_username or thread_username,
            discord_id=str(intake_member.id) if intake_member is not None else "",
            include_kubernetes=False,
        )
        previous_intakes = await self._format_previous_intakes(ticket_username or thread_username, exclude_ticket_id=channel.id)
        if previous_intakes:
            support_context = support_context.rstrip() + "\n\n" + previous_intakes
        preview = await self._render_intake(
            ticket_channel=channel,
            source_url=ticket_url,
            author=str(first_message.author) if first_message is not None else "unknown",
            tenant_member=tenant_member,
            account=ticket_username or thread_username,
            excerpt=message_excerpt,
            user_notes=user_notes,
            support_context=support_context,
        )
        preview = preview.replace(
            "Use the button to post a Hermes Elrond diagnosis request into this backchannel topic. Mention Elrond here if it does not auto-start.",
            "Preview only: the real forum topic will include an Activate Elrond diagnosis button/modal. Mention Elrond in the topic if the button does not auto-start diagnosis.",
        )
        metadata = [
            "Preview only; no thread created and no webhook called.",
            "Interactive buttons appear only in the real forum topic.",
            f"Would use backend topic name: 🟡 {thread_username}",
            f"Source message id: {source_message_id}",
        ]
        preview_text = "\n".join(metadata) + "\n\n" + preview
        chunks = self._split_discord(preview_text)
        for index, chunk in enumerate(chunks):
            prefix = "" if index == 0 else f"Intake preview continued ({index + 1}/{len(chunks)}):\n\n"
            await ctx.send(prefix + chunk, allowed_mentions=discord.AllowedMentions.none())

    @elrondradar.command(name="test")
    async def test(self, ctx, channel_id: int, message_id: int, emoji: str = "👀"):
        """Send a synthetic radar event for a specific Discord message."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return
        if not self._is_supported_emoji(emoji):
            await ctx.send(f"Unsupported radar emoji: {emoji}")
            return

        channel = self.bot.get_channel(channel_id)
        if channel is None:
            try:
                channel = await ctx.guild.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
                await ctx.send(f"Could not fetch channel {channel_id}: {type(exc).__name__}")
                return
        if not hasattr(channel, "fetch_message"):
            await ctx.send(f"Channel {channel_id} cannot fetch messages.")
            return

        try:
            message = await channel.fetch_message(message_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
            await ctx.send(f"Could not fetch message {message_id}: {type(exc).__name__}")
            return

        data = self._build_payload(
            action="added",
            guild_id=ctx.guild.id,
            channel_id=channel_id,
            message_id=message_id,
            emoji=emoji,
            staff_id=ctx.author.id,
            staff_display_name=getattr(ctx.author, "display_name", str(ctx.author)),
            message=message,
        )
        status, body = await self._post_to_elrond(data)
        if status is None:
            await ctx.send("Elrond radar test failed: endpoint or token is not configured.")
        elif status >= 300:
            await ctx.send(f"Elrond radar test failed: HTTP {status} {body[:300]}")
        else:
            await ctx.send(f"Elrond radar test accepted: HTTP {status}")

    @elrondradar.command(name="findtest")
    async def findtest(self, ctx, message_id: int, emoji: str = "👀"):
        """Find a message by ID across visible guild channels, then send a synthetic radar event."""
        if ctx.guild is None:
            await ctx.send("Run this in the configured guild.")
            return
        if ctx.guild.id != await self.config.guild_id():
            await ctx.send("This server is not the configured Elrond radar guild.")
            return
        if not self._is_supported_emoji(emoji):
            await ctx.send(f"Unsupported radar emoji: {emoji}")
            return

        async with ctx.typing():
            message = await self._find_message_in_guild(ctx.guild, message_id)
        if message is None:
            await ctx.send(f"Could not find message {message_id} in channels Redbot can read.")
            return

        data = self._build_payload(
            action="added",
            guild_id=ctx.guild.id,
            channel_id=message.channel.id,
            message_id=message_id,
            emoji=emoji,
            staff_id=ctx.author.id,
            staff_display_name=getattr(ctx.author, "display_name", str(ctx.author)),
            message=message,
        )
        status, body = await self._post_to_elrond(data)
        if status is None:
            await ctx.send("Elrond radar findtest failed: endpoint or token is not configured.")
        elif status >= 300:
            await ctx.send(f"Elrond radar findtest failed: HTTP {status} {body[:300]}")
        else:
            await ctx.send(f"Elrond radar findtest accepted: HTTP {status} in <#{message.channel.id}>")

    @commands.command(name="usernote-prefix-add")
    async def usernote_add(self, ctx: commands.Context, target: str, note: str):
        """Add a staff note for a Discord user or ElfHosted username."""
        if await self._block_prefix_usernote_in_ticket(ctx):
            return
        if not await self._ctx_is_allowed_staff(ctx):
            await self._send_private(ctx, "Only authorised staff can manage user notes.")
            return
        if not " ".join(str(note or "").split()):
            await self._send_private(ctx, "Note text is required.")
            return
        key, label = await self._note_key_from_target(ctx.guild, target)
        if not key:
            await self._send_private(ctx, "I couldn't resolve that target. Use a Discord mention/ID or ElfHosted username.")
            return
        saved = await self._add_user_note(key, label, note, ctx.author, ctx.channel)
        await self._send_private(ctx, f"Saved note for {saved['label']}.")

    @commands.command(name="usernote-prefix")
    async def usernote(self, ctx: commands.Context, note: str):
        """Add a staff note for the user inferred from the current ticket/intake context."""
        if await self._block_prefix_usernote_in_ticket(ctx):
            return
        if not await self._ctx_is_allowed_staff(ctx):
            await self._send_private(ctx, "Only authorised staff can manage user notes.")
            return
        if not " ".join(str(note or "").split()):
            await self._send_private(ctx, "Note text is required.")
            return
        key, label = await self._infer_note_target(ctx)
        if not key:
            await self._send_private(ctx, "I couldn't infer a user here. Use /usernote-add with a Discord user, ID, or ElfHosted username.")
            return
        saved = await self._add_user_note(key, label, note, ctx.author, ctx.channel)
        await self._send_private(ctx, f"Saved note for {saved['label']}.")

    @commands.command(name="usernote-prefix-list")
    async def usernote_list(self, ctx: commands.Context, target: Optional[str] = None):
        """List staff notes for a Discord user or ElfHosted username."""
        if await self._block_prefix_usernote_in_ticket(ctx):
            return
        if not await self._ctx_is_allowed_staff(ctx):
            await self._send_private(ctx, "Only authorised staff can view user notes.")
            return
        if target:
            key, label = await self._note_key_from_target(ctx.guild, target)
        else:
            key, label = await self._infer_note_target(ctx)
        if not key:
            await self._send_private(ctx, "I couldn't infer a user here. Provide a Discord user, ID, or ElfHosted username.")
            return
        block = await self._format_user_notes_for_keys([key], heading=f"Notes for {label}")
        await self._send_private(ctx, block or f"No notes for {label}.")

    @commands.command(name="usernote-prefix-delete")
    async def usernote_delete(self, ctx: commands.Context, number: int, target: Optional[str] = None):
        """Delete a staff note by number from /usernote-list."""
        if await self._block_prefix_usernote_in_ticket(ctx):
            return
        if not await self._ctx_is_allowed_staff(ctx):
            await self._send_private(ctx, "Only authorised staff can delete user notes.")
            return
        if target:
            key, label = await self._note_key_from_target(ctx.guild, target)
        else:
            key, label = await self._infer_note_target(ctx)
        if not key:
            await self._send_private(ctx, "I couldn't infer a user here. Provide a Discord user, ID, or ElfHosted username.")
            return
        deleted = await self._delete_user_note_by_number(key, number)
        if deleted is None:
            await self._send_private(ctx, f"No note #{number} for {label}. Run /usernote-list first.")
            return
        await self._send_private(ctx, f"Deleted note #{number} for {label}: {deleted.get('text', '')[:120]}")

    @app_commands.command(name="usernote", description="Add a staff note for the user inferred from this ticket or intake thread.")
    @app_commands.guilds(discord.Object(id=396055506072109067))
    @app_commands.guild_only()
    @app_commands.describe(note="Staff-only note for the user inferred from this ticket or intake thread")
    async def usernote_slash(self, interaction: discord.Interaction, note: str):
        if not await self._interaction_is_allowed_staff(interaction):
            await interaction.response.send_message("Only authorised staff can manage user notes.", ephemeral=True)
            return
        if not " ".join(str(note or "").split()):
            await interaction.response.send_message("Note text is required.", ephemeral=True)
            return
        key, label = await self._infer_note_target_from_channel(interaction.guild, interaction.channel)
        if not key:
            await interaction.response.send_message("I couldn't infer a user here. Use /usernote-add with a Discord user, ID, or ElfHosted username.", ephemeral=True)
            return
        saved = await self._add_user_note(key, label, note, interaction.user, interaction.channel)
        await interaction.response.send_message(f"Saved note for {saved['label']}.", ephemeral=True)

    @app_commands.command(name="usernote-add", description="Add a staff note for a Discord user or ElfHosted username.")
    @app_commands.guilds(discord.Object(id=396055506072109067))
    @app_commands.guild_only()
    @app_commands.describe(target="Discord mention/ID or ElfHosted username", note="Staff-only note to attach to future intakes")
    async def usernote_add_slash(self, interaction: discord.Interaction, target: str, note: str):
        if not await self._interaction_is_allowed_staff(interaction):
            await interaction.response.send_message("Only authorised staff can manage user notes.", ephemeral=True)
            return
        if not " ".join(str(note or "").split()):
            await interaction.response.send_message("Note text is required.", ephemeral=True)
            return
        key, label = await self._note_key_from_target(interaction.guild, target)
        if not key:
            await interaction.response.send_message("I couldn't resolve that target. Use a Discord mention/ID or ElfHosted username.", ephemeral=True)
            return
        saved = await self._add_user_note(key, label, note, interaction.user, interaction.channel)
        await interaction.response.send_message(f"Saved note for {saved['label']}.", ephemeral=True)

    @app_commands.command(name="usernote-list", description="List staff notes for a Discord user or ElfHosted username.")
    @app_commands.guilds(discord.Object(id=396055506072109067))
    @app_commands.guild_only()
    @app_commands.describe(target="Optional Discord mention/ID or ElfHosted username; omit in ticket/intake context")
    async def usernote_list_slash(self, interaction: discord.Interaction, target: Optional[str] = None):
        if not await self._interaction_is_allowed_staff(interaction):
            await interaction.response.send_message("Only authorised staff can view user notes.", ephemeral=True)
            return
        if target:
            key, label = await self._note_key_from_target(interaction.guild, target)
        else:
            key, label = await self._infer_note_target_from_channel(interaction.guild, interaction.channel)
        if not key:
            await interaction.response.send_message("I couldn't infer a user here. Provide a Discord user, ID, or ElfHosted username.", ephemeral=True)
            return
        block = await self._format_user_notes_for_keys([key], heading=f"Notes for {label}")
        await interaction.response.send_message(block or f"No notes for {label}.", ephemeral=True, allowed_mentions=discord.AllowedMentions.none())

    @app_commands.command(name="usernote-delete", description="Delete a staff note by number from /usernote-list.")
    @app_commands.guilds(discord.Object(id=396055506072109067))
    @app_commands.guild_only()
    @app_commands.describe(number="Note number from /usernote-list", target="Optional Discord mention/ID or ElfHosted username; omit in ticket/intake context")
    async def usernote_delete_slash(self, interaction: discord.Interaction, number: int, target: Optional[str] = None):
        if not await self._interaction_is_allowed_staff(interaction):
            await interaction.response.send_message("Only authorised staff can delete user notes.", ephemeral=True)
            return
        if target:
            key, label = await self._note_key_from_target(interaction.guild, target)
        else:
            key, label = await self._infer_note_target_from_channel(interaction.guild, interaction.channel)
        if not key:
            await interaction.response.send_message("I couldn't infer a user here. Provide a Discord user, ID, or ElfHosted username.", ephemeral=True)
            return
        deleted = await self._delete_user_note_by_number(key, number)
        if deleted is None:
            await interaction.response.send_message(f"No note #{number} for {label}. Run /usernote-list first.", ephemeral=True)
            return
        await interaction.response.send_message(f"Deleted note #{number} for {label}: {deleted.get('text', '')[:120]}", ephemeral=True, allowed_mentions=discord.AllowedMentions.none())

    async def _is_allowed_staff(self, guild: discord.Guild, user_id: int, member: Optional[discord.Member]) -> bool:
        allowed_user_ids = set(await self.config.allowed_user_ids())
        if user_id in allowed_user_ids:
            return True

        if member is None:
            try:
                member = await guild.fetch_member(user_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                return False

        allowed_role_ids = set(await self.config.allowed_role_ids())
        return any(role.id in allowed_role_ids for role in getattr(member, "roles", []))

    async def _ctx_is_allowed_staff(self, ctx: commands.Context) -> bool:
        if ctx.guild is None or ctx.author is None:
            return False
        member = ctx.author if isinstance(ctx.author, discord.Member) else None
        return await self._is_allowed_staff(ctx.guild, ctx.author.id, member)

    async def _interaction_is_allowed_staff(self, interaction: discord.Interaction) -> bool:
        if interaction.guild is None or interaction.user is None:
            return False
        member = interaction.user if isinstance(interaction.user, discord.Member) else None
        return await self._is_allowed_staff(interaction.guild, interaction.user.id, member)

    async def _send_private(self, ctx: commands.Context, message: str):
        kwargs = {"allowed_mentions": discord.AllowedMentions.none()}
        if getattr(ctx, "interaction", None) is not None:
            kwargs["ephemeral"] = True
        await ctx.send(message, **kwargs)

    async def _block_prefix_usernote_in_ticket(self, ctx: commands.Context) -> bool:
        if getattr(ctx, "interaction", None) is not None:
            return False
        if not await self._is_ticket_category(ctx.channel):
            return False
        try:
            await ctx.message.delete()
        except (discord.Forbidden, discord.HTTPException, AttributeError):
            pass
        try:
            await ctx.author.send("Use the slash command `/usernote`, `/usernote-add`, `/usernote-list`, or `/usernote-delete` in ticket channels so the response is only visible to you.")
        except (discord.Forbidden, discord.HTTPException, AttributeError):
            try:
                await ctx.send("Use the slash command for user notes in ticket channels.", delete_after=10)
            except (discord.Forbidden, discord.HTTPException):
                pass
        return True

    async def _note_key_from_target(self, guild: Optional[discord.Guild], target: str) -> Tuple[str, str]:
        value = str(target or "").strip()
        if not value:
            return "", ""
        user_id = self._extract_discord_id(value)
        if user_id:
            member = None
            if guild is not None:
                member = guild.get_member(user_id)
                if member is None:
                    try:
                        member = await guild.fetch_member(user_id)
                    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                        member = None
            label = str(member) if member is not None else f"Discord {user_id}"
            return f"discord:{user_id}", label
        username = self._normalize_username(value)
        if not username:
            return "", ""
        return f"username:{username}", username

    def _extract_discord_id(self, value: str) -> Optional[int]:
        clean = str(value or "").strip()
        if clean.startswith("<@") and clean.endswith(">"):
            clean = clean.strip("<@!>")
        if clean.isdigit():
            return int(clean)
        return None

    def _normalize_username(self, value: str) -> str:
        clean = str(value or "").strip().lower()
        clean = clean.replace("`", " ").replace("\u200b", "")
        for match in USERNAME_RE.findall(clean):
            username = match.lower().replace("aa-", "", 1).strip("*_~<>:;,. ")
            if username and username not in USERNAME_STOPWORDS:
                return username
        return ""

    async def _infer_note_target(self, ctx: commands.Context) -> Tuple[str, str]:
        return await self._infer_note_target_from_channel(ctx.guild, ctx.channel)

    async def _infer_note_target_from_channel(self, guild: Optional[discord.Guild], channel) -> Tuple[str, str]:
        if channel is None:
            return "", ""

        if await self._is_ticket_category(channel):
            tenant_member = await self._ticket_tenant_member(channel)
            if tenant_member is not None:
                return f"discord:{tenant_member.id}", str(tenant_member)
            first_message = await self._first_useful_channel_message(channel)
            username = self._ticket_username(first_message)
            if username:
                normalized = self._normalize_username(username)
                return f"username:{normalized}", normalized

        backend_channel_id = await self.config.backend_channel_id()
        parent_id = getattr(channel, "parent_id", None)
        if parent_id == backend_channel_id or getattr(channel, "id", None) == backend_channel_id:
            username = self._normal_thread_name(getattr(channel, "name", ""))
            if " · " in username:
                username = username.split(" · ", 1)[0].strip()
            if username:
                normalized = self._normalize_username(username)
                return f"username:{normalized}", normalized

        return "", ""

    async def _add_user_note(self, key: str, label: str, note: str, author, channel) -> dict:
        text = " ".join(str(note or "").split()).strip()
        if len(text) > 600:
            text = text[:599].rstrip() + "…"
        entry = {
            "text": text,
            "label": label,
            "created_by_id": str(getattr(author, "id", "")),
            "created_by_name": getattr(author, "display_name", str(author)),
            "created_at": discord.utils.utcnow().isoformat(),
            "source_channel_id": str(getattr(channel, "id", "")),
            "source_channel_name": getattr(channel, "name", ""),
        }
        async with self.config.user_notes() as notes:
            items = list(notes.get(key, []))
            items.append(entry)
            notes[key] = items[-50:]
        return entry

    async def _format_user_notes_for_keys(self, keys, heading: str = "Staff notes") -> str:
        all_notes = await self.config.user_notes()
        seen = set()
        entries = []
        for key in keys:
            if not key or key in seen:
                continue
            seen.add(key)
            entries.extend(all_notes.get(key, []))
        if not entries:
            return ""
        entries = sorted(entries, key=lambda item: item.get("created_at", ""), reverse=True)[:8]
        lines = [f"🗒️ **{heading}**"]
        for index, entry in enumerate(entries, start=1):
            created = str(entry.get("created_at", ""))[:10] or "unknown date"
            by = entry.get("created_by_name") or entry.get("created_by_id") or "unknown staff"
            text = entry.get("text") or ""
            lines.append(f"{index}. {created} · {by}: {text}")
        return "\n".join(lines)

    async def _delete_user_note_by_number(self, key: str, number: int) -> Optional[dict]:
        if number < 1:
            return None
        async with self.config.user_notes() as notes:
            items = list(notes.get(key, []))
            sorted_pairs = sorted(enumerate(items), key=lambda pair: pair[1].get("created_at", ""), reverse=True)
            if number > len(sorted_pairs):
                return None
            original_index, deleted = sorted_pairs[number - 1]
            del items[original_index]
            if items:
                notes[key] = items
            else:
                notes.pop(key, None)
            return deleted

    async def _format_user_notes_for_intake(self, discord_id: str = "", username: str = "") -> str:
        keys = []
        clean_discord = str(discord_id or "").strip()
        clean_username = self._normalize_username(username)
        if clean_discord:
            keys.append(f"discord:{clean_discord}")
        if clean_username:
            keys.append(f"username:{clean_username}")
        return await self._format_user_notes_for_keys(keys)

    def _format_excerpt_block(self, excerpt: str) -> str:
        text = str(excerpt or "").strip()
        if not text:
            return "> not provided"
        return "\n".join("> " + line for line in text.splitlines())

    def _md_value(self, value: Any, fallback: str = "unknown") -> str:
        text = str(value or "").strip()
        return text if text else fallback

    def _truncate_inline(self, value: Any, limit: int = 700) -> str:
        text = " ".join(str(value or "").split())
        return text[: limit - 1].rstrip() + "…" if len(text) > limit else text

    def _strip_code_fences(self, value: str) -> str:
        text = str(value or "").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return text

    def _table_lines_from_output(self, value: str, required: tuple[str, ...]) -> list[str]:
        text = self._strip_code_fences(value)
        lines = [line.rstrip() for line in text.splitlines() if line.strip()]
        for idx, line in enumerate(lines):
            header = re.split(r"\s{2,}", line.strip())
            if all(name in header for name in required):
                return lines[idx:]
        return lines

    def _compact_k8s_workload_name(self, value: Any, username: str = "") -> str:
        text = str(value or "").strip()
        prefix = (self._normalize_username(username) + "-") if username else ""
        if prefix and text.startswith(prefix):
            text = text[len(prefix):]
        parts = text.rsplit("-", 2)
        if (
            len(parts) == 3
            and re.fullmatch(r"[a-z0-9]{8,10}", parts[1] or "")
            and re.fullmatch(r"[a-z0-9]{5}", parts[2] or "")
            and any(char.isdigit() for char in parts[1] + parts[2])
        ):
            text = parts[0]
        return text

    def _code_block(self, value: str, limit: int = 1400, language: str = "text") -> list[str]:
        text = self._strip_code_fences(value).replace("```", "`\u200b``")
        if len(text) > limit:
            text = text[: limit - 1].rstrip() + "…"
        return ["```" + language, text or "(no output)", "```"]

    def _code_blocks(self, value: str, limit: int = 1050, language: str = "text") -> list[str]:
        text = self._strip_code_fences(value).replace("```", "`\u200b``")
        lines = text.splitlines() or ["(no output)"]
        blocks = []
        current = []

        def flush():
            if current:
                blocks.extend(["```" + language, "\n".join(current), "```", ""])
                current.clear()

        for line in lines:
            remaining = line
            while len(remaining) > limit:
                flush()
                blocks.extend(["```" + language, remaining[:limit], "```"])
                remaining = remaining[limit:]
            candidate = "\n".join([*current, remaining]) if current else remaining
            if current and len(candidate) > limit:
                flush()
            current.append(remaining)
        flush()
        if blocks and blocks[-1] == "":
            blocks.pop()
        return blocks

    def _tenant_node_from_pods(self, pods_output: str) -> str:
        lines = self._table_lines_from_output(pods_output, ("NODE",))
        if len(lines) < 2:
            return ""
        header = re.split(r"\s{2,}", lines[0].strip())
        try:
            node_index = header.index("NODE")
        except ValueError:
            return ""
        nodes = []
        for line in lines[1:]:
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) > node_index and cols[node_index] and cols[node_index] not in nodes:
                nodes.append(cols[node_index])
        return ", ".join(nodes[:3])

    def _compact_pods_table(self, pods_output: str) -> str:
        text = self._strip_code_fences(pods_output)
        lines = self._table_lines_from_output(pods_output, ("APP", "POD", "READY", "STATUS"))
        if len(lines) < 2:
            return text
        header = re.split(r"\s{2,}", lines[0].strip())
        wanted = ["APP", "POD", "READY", "STATUS", "RESTARTS", "AGE"]
        indexes = []
        for name in wanted:
            try:
                indexes.append(header.index(name))
            except ValueError:
                return text
        rows = []
        for line in lines[1:]:
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) <= max(indexes):
                continue
            row = [cols[i] for i in indexes]
            try:
                pod_col = wanted.index("POD")
                row[pod_col] = self._compact_k8s_workload_name(row[pod_col])
            except ValueError:
                pass
            rows.append(row)
        if not rows:
            return text
        widths = [len(name) for name in wanted]
        for row in rows:
            for idx, value in enumerate(row):
                widths[idx] = min(max(widths[idx], len(value)), 32)
        def trim(value, width):
            value = str(value)
            return value if len(value) <= width else value[: max(1, width - 1)] + "…"
        formatted = ["  ".join(name.ljust(widths[idx]) for idx, name in enumerate(wanted))]
        for row in rows:
            formatted.append("  ".join(trim(value, widths[idx]).ljust(widths[idx]) for idx, value in enumerate(row)))
        return "\n".join(formatted)

    def _compact_pod_usage_table(self, usage_output: str, username: str = "") -> str:
        text = self._strip_code_fences(usage_output)
        lines = self._table_lines_from_output(usage_output, ("CPU(cores)", "MEMORY(bytes)"))
        if len(lines) < 2:
            return text
        header = re.split(r"\s{2,}", lines[0].strip())
        pod_header = "POD" if "POD" in header else "NAME"
        wanted = [(pod_header, "APP")]
        if "CONTAINER" in header:
            wanted.append(("CONTAINER", "CONTAINER"))
        wanted.extend([("CPU(cores)", "CPU"), ("MEMORY(bytes)", "MEM")])
        indexes = []
        for source, _label in wanted:
            try:
                indexes.append(header.index(source))
            except ValueError:
                return text
        rows = []
        seen = set()
        for line in lines[1:]:
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) <= max(indexes):
                continue
            values = [cols[i] for i in indexes]
            values[0] = self._compact_k8s_workload_name(values[0], username)
            row = values
            key = tuple(row)
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
        if not rows:
            return text
        labels = [label for _source, label in wanted]
        widths = [len(label) for label in labels]
        for row in rows:
            for idx, value in enumerate(row):
                widths[idx] = min(max(widths[idx], len(value)), 28)
        def trim(value, width):
            value = str(value)
            return value if len(value) <= width else value[: max(1, width - 1)] + "…"
        formatted = ["  ".join(label.ljust(widths[idx]) for idx, label in enumerate(labels))]
        for row in rows:
            formatted.append("  ".join(trim(value, widths[idx]).ljust(widths[idx]) for idx, value in enumerate(row)))
        return "\n".join(formatted)

    def _store_links(self, user_id: Any) -> str:
        clean = str(user_id or "").strip()
        if not clean:
            return "`unknown`"
        enc = urllib.parse.quote(clean)
        return (
            f"[user](<https://store.elfhosted.com/wp-admin/user-edit.php?user_id={enc}>) / "
            f"[subscriptions](<https://store.elfhosted.com/wp-admin/admin.php?page=wc-orders--shop_subscription&_customer_user={enc}&status=all>) / "
            f"[orders](<https://store.elfhosted.com/wp-admin/admin.php?page=wc-orders&_customer_user={enc}&status=all>)"
        )

    def _admin_post_link(self, kind: str, item_id: Any, label: str) -> str:
        clean = str(item_id or "").strip()
        safe = str(label or "").replace("[", "").replace("]", "").strip() or (kind + " #" + clean if clean else kind)
        if not clean:
            return safe
        return "[" + safe + "](<https://store.elfhosted.com/wp-admin/post.php?post=" + urllib.parse.quote(clean) + "&action=edit>)"

    def _subscription_items(self, sub: dict[str, Any]) -> str:
        items = sub.get("items") if isinstance(sub, dict) else []
        if not isinstance(items, list):
            return "`no items`"
        names = [str(item.get("name") or item.get("sku") or "").strip() for item in items if isinstance(item, dict)]
        names = [name for name in names if name]
        return ", ".join("`" + name.replace("`", "'") + "`" for name in names) or "`no items`"

    def _format_subscriptions(self, subs: Any) -> list[str]:
        visible = []
        if isinstance(subs, list):
            visible = [sub for sub in subs if isinstance(sub, dict) and str(sub.get("status") or "").lower() in {"active", "pending-cancel"}]
        if not visible:
            return ["- No active or pending-cancel subscriptions found"]
        lines = []
        for sub in visible[:8]:
            status = str(sub.get("status") or "unknown").replace("-", " ")
            raw_date = sub.get("endDate") if status == "pending cancel" else sub.get("nextPayment")
            date = str(raw_date or sub.get("nextPayment") or sub.get("endDate") or "")[:10]
            date_part = (", ends `" + date + "`") if status == "pending cancel" and date else ((", renews `" + date + "`") if date else "")
            first_item = "Subscription #" + str(sub.get("id"))
            if isinstance(sub.get("items"), list) and sub["items"]:
                first_item = str(sub["items"][0].get("name") or sub["items"][0].get("sku") or first_item)
            lines.append("- " + self._admin_post_link("Subscription", sub.get("id"), first_item) + f" — `{status}`" + date_part + " — " + self._subscription_items(sub))
        return lines

    def _format_orders(self, orders: Any) -> list[str]:
        visible = orders if isinstance(orders, list) else []
        if not visible:
            return ["- No recent orders found"]
        lines = []
        for order in visible[:5]:
            if not isinstance(order, dict):
                continue
            order_id = order.get("id") or order.get("orderId")
            status = str(order.get("status") or "unknown").replace("-", " ")
            date = str(order.get("dateCreated") or order.get("date") or "")[:10]
            total = str(order.get("total") or order.get("orderTotal") or "").strip()
            label = "Order #" + str(order_id or "?")
            tail = ""
            if date:
                tail += " — `" + date + "`"
            if total:
                tail += " — " + total
            lines.append("- " + self._admin_post_link("Order", order_id, label) + " — `" + status + "`" + tail)
        return lines or ["- No recent orders found"]

    def _extract_helm_metadata(self, output: str) -> tuple[list[str], int | None]:
        text = str(output or "")
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return [], None
        try:
            import json
            values = json.loads(text[start : end + 1])
        except Exception:
            return [], None
        skip = {"global", "storageclass", "volsync", "traefikforwardauth", "dns_domain", "userid"}
        apps = []
        if isinstance(values, dict):
            for key, val in values.items():
                if str(key).lower() in skip:
                    continue
                if isinstance(val, dict) and val.get("enabled") is True:
                    apps.append(str(key))
        user_id = None
        try:
            parsed = int(values.get("userId")) if isinstance(values, dict) and values.get("userId") else 0
            user_id = parsed if parsed > 0 else None
        except Exception:
            user_id = None
        return sorted(apps), user_id

    async def _support_http_json(self, base_url: str, path: str, secret: str, params: dict[str, str] | None = None, *, timeout: int = 15) -> dict[str, Any]:
        query = "?" + urllib.parse.urlencode(params) if params else ""
        url = base_url.rstrip("/") + path + query
        headers = {"Accept": "application/json", "Authorization": "Bearer " + secret}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                text = await response.text()
                if response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status} from {path}: {text[:200]}")
                return await response.json(content_type=None) if text.strip() else {}

    async def _support_jsonrpc_text(self, base_url: str, secret: str, tool_name: str, args: dict[str, str], *, timeout: int = 10) -> str:
        headers = {"Accept": "application/json", "Authorization": "Bearer " + secret, "Content-Type": "application/json"}
        payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": "tools/call", "params": {"name": tool_name, "arguments": args}}
        async with aiohttp.ClientSession() as session:
            async with session.post(base_url.rstrip("/"), json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                text = await response.text()
                if response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status} from {tool_name}: {text[:200]}")
                data = json.loads(text) if text.strip() else {}
        if isinstance(data, dict) and data.get("error"):
            error = data.get("error")
            raise RuntimeError(str(error.get("message") if isinstance(error, dict) else error))
        content = data.get("result", {}).get("content") if isinstance(data, dict) else None
        if isinstance(content, list):
            return "".join(str(item.get("text") or "") for item in content if isinstance(item, dict)).strip()
        result = data.get("result") if isinstance(data, dict) else data
        return str(result or "").strip()

    async def _discord_linked_user_id(self, discord_id: str) -> Optional[int]:
        clean_discord = str(discord_id or "").strip()
        if not clean_discord:
            return None
        base_url = os.getenv("ELROND_DISCORD_BOT_MCP_URL") or os.getenv("DISCORD_BOT_MCP_URL") or "http://discord-auth.discord-auth:3000/mcp"
        secret = os.getenv("ELROND_DISCORD_BOT_MCP_SECRET") or os.getenv("DISCORDBOT_SECRET") or os.getenv("DISCORD_BOT_MCP_SECRET") or ""
        if not secret:
            return None
        result = await self._support_jsonrpc_text(base_url, secret, "get_userid_from_discordid", {"discord_id": clean_discord})
        text = str(result or "").strip()
        if not re.fullmatch(r"[1-9]\d*", text):
            return None
        return int(text)

    def _elrond_base_url(self, cluster: str) -> str:
        suffix = str(cluster or "").upper().replace(".", "_").replace("-", "_")
        defaults = {
            "elfhosted.com": "http://elrond.elrond.svc.cluster.local:8080",
            "elfhosted.cafe": "http://elrond-elfhosted-cafe.elrond.svc.cluster.local:8080",
            "elfhosted.cc": "http://elrond-elfhosted-cc.elrond.svc.cluster.local:8080",
            "elfhosted.coffee": "http://elrond-elfhosted-coffee.elrond.svc.cluster.local:8080",
            "elfhosted.party": "http://elrond-elfhosted-party.elrond.svc.cluster.local:8080",
            "elfhosted.surf": "http://elrond-elfhosted-surf.elrond.svc.cluster.local:8080",
            "elfhosted.wine": "http://elrond-elfhosted-wine.elrond.svc.cluster.local:8080",
        }
        return (os.getenv("ELROND_MCP_URL_" + suffix) or os.getenv("ELROND_BASE_URL_" + suffix) or defaults.get(cluster) or os.getenv("ELROND_BASE_URL") or defaults["elfhosted.com"]).rstrip("/")

    async def _run_read(self, cluster: str, operation: str, namespace: str, params: dict[str, Any] | None = None) -> str:
        base_url = self._elrond_base_url(cluster)
        secret = os.getenv("ELROND_MCP_SECRET_" + str(cluster or "").upper().replace(".", "_").replace("-", "_")) or os.getenv("ELROND_SECRET") or os.getenv("ELROND_MCP_SECRET") or ""
        if not secret:
            raise RuntimeError("ELROND_SECRET is not configured")
        payload = {"operation": operation, "namespace": namespace, "params": params or {}, "requested_by": "redbot:elrondradar", "reason": "LLM-free support ticket intake"}
        headers = {"Accept": "application/json", "Authorization": "Bearer " + secret}
        async with aiohttp.ClientSession() as session:
            async with session.post(base_url.rstrip("/") + "/run", json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as response:
                text = await response.text()
                if response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status} from Elrond {operation}: {text[:200]}")
                data = await response.json(content_type=None) if text.strip() else {}
        if not isinstance(data, dict):
            return str(data or "")
        result = data.get("data")
        if result is None and "output" in data:
            return str(data.get("output") or "")
        if isinstance(result, dict):
            return str(result.get("output") or result.get("message") or result.get("error") or result)
        return str(result or "")

    async def _build_support_context(self, *, username: str, discord_id: str = "", include_billing: bool = True, include_kubernetes: bool = True, context_title: str = "📦 **Support Context**") -> str:
        warnings = []
        resolved_username = self._normalize_username(username)
        user_id = None
        profile = None
        tenant = None
        gitops_url = os.getenv("ELROND_GITOPS_URL", "http://elrond-gitops.openclaw:8080")
        woo_url = os.getenv("ELROND_WOO_URL", "http://elrond-woo.openclaw:8080")
        woo_secret = os.getenv("ELROND_WOO_SECRET") or os.getenv("WOO_SECRET") or ""
        gitops_secret = os.getenv("ELROND_GITOPS_SECRET") or os.getenv("GITOPS_SECRET") or ""

        discord_lookup_secret = os.getenv("ELROND_DISCORD_BOT_MCP_SECRET") or os.getenv("DISCORDBOT_SECRET") or os.getenv("DISCORD_BOT_MCP_SECRET") or ""
        if discord_id and woo_secret and discord_lookup_secret:
            try:
                linked_user_id = await self._discord_linked_user_id(discord_id)
                if linked_user_id:
                    linked_profile = await self._support_http_json(woo_url, "/customer/profile", woo_secret, {"customer_id": str(linked_user_id)})
                    profile_username = self._normalize_username(linked_profile.get("username")) if isinstance(linked_profile, dict) else ""
                    if profile_username:
                        user_id = linked_user_id
                        profile = linked_profile
                        if resolved_username and profile_username != resolved_username:
                            warnings.append("Discord-linked billing profile username `" + profile_username + "` differs from supplied ticket username `" + resolved_username + "`; using verified Discord-linked billing username for GitOps lookup.")
                        resolved_username = profile_username
                    else:
                        warnings.append("Discord-linked billing profile did not include a username; using supplied ticket username lookup")
            except Exception as exc:
                warnings.append("Discord-linked billing lookup failed: " + str(exc))
        elif discord_id and woo_secret:
            warnings.append("Discord link lookup secret is not configured")

        if resolved_username and woo_secret and not user_id:
            try:
                search = await self._support_http_json(woo_url, "/customer/search", woo_secret, {"query": resolved_username})
                customers = search.get("customers") if isinstance(search, dict) else []
                customers = customers if isinstance(customers, list) else []
                exact = next((c for c in customers if self._normalize_username(c.get("username")) == resolved_username), None)
                match = exact or (customers[0] if len(customers) == 1 else None)
                if isinstance(match, dict) and match.get("id"):
                    user_id = int(match.get("id"))
                    resolved_username = self._normalize_username(match.get("username")) or resolved_username
                elif not customers:
                    warnings.append("Woo customer search found no user for `" + resolved_username + "`")
                else:
                    warnings.append("Woo customer search returned multiple non-exact users for `" + resolved_username + "`; user details skipped")
            except Exception as exc:
                warnings.append("Woo customer search failed: " + str(exc))
        elif not woo_secret:
            warnings.append("Woo lookup secret is not configured")

        if user_id and woo_secret and profile is None:
            try:
                profile = await self._support_http_json(woo_url, "/customer/profile", woo_secret, {"customer_id": str(user_id)})
                resolved_username = self._normalize_username(profile.get("username")) or resolved_username
            except Exception as exc:
                warnings.append("Woo profile lookup failed: " + str(exc))

        if resolved_username and gitops_secret:
            try:
                tenant = await self._support_http_json(gitops_url, "/tenant/lookup", gitops_secret, {"username": resolved_username})
                if isinstance(tenant, dict) and tenant.get("userId") and not user_id:
                    user_id = int(tenant.get("userId"))
            except Exception as exc:
                warnings.append("GitOps lookup failed: " + str(exc))
        elif not gitops_secret:
            warnings.append("GitOps lookup secret is not configured")

        cluster_name = tenant.get("cluster") if isinstance(tenant, dict) else ""
        namespace = "aa-" + resolved_username if resolved_username else ""
        apps = tenant.get("apps") if isinstance(tenant, dict) and isinstance(tenant.get("apps"), list) else []
        pods = ""
        top_pods = ""
        if include_kubernetes:
            if cluster_name and namespace:
                try:
                    hr_values = await self._run_read(cluster_name, "get_helmrelease_values", namespace, {"name": resolved_username})
                    metadata_apps, metadata_user_id = self._extract_helm_metadata(hr_values)
                    if not apps and metadata_apps:
                        apps = metadata_apps
                    if not user_id and metadata_user_id:
                        user_id = metadata_user_id
                except Exception as exc:
                    warnings.append("HelmRelease values lookup failed: " + str(exc))
                try:
                    pods = await self._run_read(cluster_name, "list_pods", namespace, {})
                except Exception as exc:
                    warnings.append("Pod snapshot failed: " + str(exc))
                try:
                    top_pods = await self._run_read(cluster_name, "top_pods", namespace, {"containers": True})
                except Exception as exc:
                    warnings.append("Pod usage lookup failed: " + str(exc))
            elif namespace:
                warnings.append("Cluster lookup did not resolve for `" + namespace + "`; skipped Kubernetes snapshots")
            else:
                warnings.append("Tenant identity did not resolve; skipped GitOps, billing, and Kubernetes snapshots")
        elif cluster_name and namespace:
            warnings.append("Kubernetes snapshot is being collected asynchronously")
        elif namespace:
            warnings.append("Cluster lookup did not resolve for `" + namespace + "`; skipped Kubernetes snapshots")
        else:
            warnings.append("Tenant identity did not resolve; skipped GitOps, billing, and Kubernetes snapshots")

        subscriptions = []
        orders = []
        if include_billing and user_id and woo_secret:
            try:
                sub_data = await self._support_http_json(woo_url, "/customer/subscriptions", woo_secret, {"customer_id": str(user_id), "active_only": "true"})
                subscriptions = sub_data.get("subscriptions") if isinstance(sub_data, dict) and isinstance(sub_data.get("subscriptions"), list) else []
            except Exception as exc:
                warnings.append("Subscription lookup failed: " + str(exc))
            try:
                order_data = await self._support_http_json(woo_url, "/customer/orders", woo_secret, {"customer_id": str(user_id), "limit": "5"})
                orders = order_data.get("orders") if isinstance(order_data, dict) and isinstance(order_data.get("orders"), list) else []
            except Exception as exc:
                warnings.append("Order lookup failed: " + str(exc))

        tenant_node = self._tenant_node_from_pods(pods)
        lines = [
            context_title,
            "Generated: " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "",
            "👤 **Tenant Details**",
            "- ElfHosted username: `" + self._md_value(resolved_username) + "`",
            "- Discord: " + ("<@" + discord_id + ">" if discord_id else "`unknown`"),
            "- Datacenter: `" + self._md_value(cluster_name) + "`",
            "- Node: `" + self._md_value(tenant_node) + "`",
            "- Store: " + self._store_links(user_id or (tenant.get("userId") if isinstance(tenant, dict) else None)),
            "",
            "📦 **Apps Detected**",
            ", ".join("`" + str(app).lower().replace("`", "'") + "`" for app in apps) if apps else "`unknown`",
        ]
        if include_billing:
            lines.extend([
                "",
                "💳 **Subscriptions**",
                *self._format_subscriptions(subscriptions),
                "",
                "🧾 **Recent Orders**",
                *self._format_orders(orders),
            ])
        if include_billing and profile:
            lines.extend(["", "👥 **User Details**"])
            for label, key in (("Email", "email"), ("Registered", "dateCreated"), ("Orders", "ordersCount"), ("Total spent", "totalSpent")):
                if profile.get(key) is not None:
                    lines.append("- " + label + ": `" + str(profile.get(key)) + "`")
        if top_pods:
            lines.extend(["", "📊 **Pod Usage**", *self._code_blocks(self._compact_pod_usage_table(top_pods, resolved_username), 1050)])
        if pods:
            lines.extend(["", "📋 **Pods**", *self._code_blocks(self._compact_pods_table(pods), 1050)])
        usage_block, usage_warning = await self._palantir_usage_block(resolved_username)
        if usage_warning:
            warnings.append(usage_warning)
        if usage_block:
            lines.append(usage_block)
        if warnings:
            lines.extend(["", "⚠️ **Lookup Warnings**", *("- " + self._truncate_inline(warning, 220) for warning in warnings)])
        return "\n".join(lines)


    async def _palantir_usage_block(self, username: str) -> tuple[str, str]:
        """Neutral usage facts for a tenant, but only when something is anomalous.

        Returns (block, warning). Both may be empty.

        Shown only when palantir has flagged the tenant. A usage block on every
        routine ticket would prime a support agent to suspect a customer who has
        done nothing, and most tickets have nothing to do with sharing.

        Deliberately states what was MEASURED and not what it means. The verdict
        ("resale", "credential sharing") lives in elrond, where someone has
        asked for it — every strong signal in this system has had at least one
        confident-and-wrong case behind it: 135 apparent clients that were 6, a
        resale ring that turned out to be our own nodes, and the fleet's highest
        address count belonging to a family.
        """
        url = os.getenv("ELROND_PALANTIR_URL", "")
        secret = os.getenv("ELROND_PALANTIR_SECRET") or os.getenv("PALANTIR_API_TOKEN") or ""
        if not username or not url or not secret:
            return "", ""
        try:
            data = await self._support_http_json(url, "/tenant/" + urllib.parse.quote(username), secret)
        except Exception as exc:
            return "", "Palantir usage lookup failed: " + str(exc)
        if not isinstance(data, dict) or not data.get("flagged"):
            return "", ""

        apps = data.get("apps") or []
        lines = ["", "🔍 **Usage (flagged by palantir)**"]
        for app in apps[:5]:
            if not isinstance(app, dict):
                continue
            parts = [str(app.get("clients", 0)) + " clients"]
            peak = app.get("peak_concurrent") or 0
            if peak:
                parts.append(str(peak) + " at once")
            countries = app.get("countries") or 0
            if countries:
                parts.append(str(countries) + (" country" if countries == 1 else " countries"))
            requests = app.get("requests") or 0
            if requests:
                parts.append(f"{requests:,} requests")
            mark = "• " if app.get("flagged") else "· "
            lines.append(mark + "`" + str(app.get("app", "?")) + "` — " + ", ".join(parts))
        if len(apps) > 5:
            lines.append("· …and " + str(len(apps) - 5) + " more")
        lines.append("- Ask Elrond `why was " + username + " flagged` for the assessment.")
        return "\n".join(lines), ""

    async def _render_intake(self, *, ticket_channel, source_url: str, author: str, tenant_member, account: str, excerpt: str, user_notes: str, support_context: str = "") -> str:
        template = await self.config.intake_template() or DEFAULT_INTAKE_TEMPLATE
        # Ticket messages are often authored by ElfHelpBot, not the tenant. Prefer the
        # Discord ID resolved from Woo/support context when the member cannot be seen
        # in the ticket channel, and suppress the low-signal Author field in default
        # and older persisted templates.
        template = template.replace("\n- Author: `{author}`", "").replace("\n- Author: {author}", "")
        support_discord_match = re.search(r"- Discord:\s*<@!?(\d+)>", support_context or "")
        if tenant_member is not None:
            tenant_discord = tenant_member.mention
        elif support_discord_match:
            tenant_discord = "<@" + support_discord_match.group(1) + ">"
        else:
            tenant_discord = "`unknown`"
        staff_notes_block = user_notes or "🗒️ **Staff Notes**\nNo stored staff notes found."
        support_context_block = support_context.strip() or "📦 **Support Context**\n- Not resolved yet."
        values = {
            "ticket_channel": getattr(ticket_channel, "mention", f"<#{getattr(ticket_channel, 'id', '')}>"),
            "ticket_channel_name": getattr(ticket_channel, "name", str(getattr(ticket_channel, "id", "unknown"))),
            "ticket_channel_id": str(getattr(ticket_channel, "id", "")),
            "source_url": source_url or "not provided",
            "author": author or "unknown",
            "tenant_discord": tenant_discord,
            "account": account or "unknown",
            "excerpt": excerpt or "not provided",
            "excerpt_block": self._format_excerpt_block(excerpt),
            "staff_notes": user_notes or "",
            "staff_notes_block": staff_notes_block,
            "support_context": support_context or "",
            "support_context_block": support_context_block,
        }
        if "support_context" not in template and "support_context_block" not in template:
            marker = "\n\n{staff_notes_block}"
            if marker in template:
                template = template.replace(marker, "\n\n{support_context_block}" + marker, 1)
        try:
            return template.format(**values)
        except Exception as exc:
            log.warning("Elrond radar intake template render failed: %s", exc)
            return DEFAULT_INTAKE_TEMPLATE.format(**values)

    def _split_discord(self, content: str, max_len: int = 1800):
        text = str(content or "").strip()
        if not text:
            return []
        chunks = []
        current = ""
        for section in re.split(r"\n\n+", text):
            candidate = current + "\n\n" + section if current else section
            if len(candidate) <= max_len:
                current = candidate
                continue
            if current:
                chunks.append(current)
                current = ""
            while len(section) > max_len:
                chunks.append(section[:max_len])
                section = section[max_len:]
            current = section
        if current:
            chunks.append(current)
        return chunks

    async def _send_backend_intake_notice(self, backend_thread, intake_text: str, view=None):
        chunks = self._split_discord(intake_text)
        for index, chunk in enumerate(chunks):
            await backend_thread.send(
                chunk,
                view=view if index == 0 else None,
                allowed_mentions=discord.AllowedMentions.none(),
            )

    async def _fetch_message(self, payload: discord.RawReactionActionEvent) -> Optional[discord.Message]:
        channel = self.bot.get_channel(payload.channel_id)
        if channel is None:
            guild = self.bot.get_guild(payload.guild_id) if payload.guild_id else None
            if guild is not None:
                try:
                    channel = await guild.fetch_channel(payload.channel_id)
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    return None
        if channel is None or not hasattr(channel, "fetch_message"):
            return None
        try:
            return await channel.fetch_message(payload.message_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return None

    async def _find_message_in_guild(self, guild: discord.Guild, message_id: int) -> Optional[discord.Message]:
        seen_channel_ids = set()
        channels = []
        for channel in list(getattr(guild, "text_channels", [])) + list(getattr(guild, "threads", [])):
            channel_id = getattr(channel, "id", None)
            if channel_id in seen_channel_ids:
                continue
            seen_channel_ids.add(channel_id)
            if hasattr(channel, "fetch_message"):
                channels.append(channel)

        for channel in channels:
            try:
                return await channel.fetch_message(message_id)
            except discord.NotFound:
                continue
            except (discord.Forbidden, discord.HTTPException):
                continue
        return None


    async def _post_legacy_diagnosis_request_notice(self, data: dict) -> None:
        """Bridge the old Redbot diagnosis button to the Hermes-era workflow.

        The original button POSTed to the OpenClaw service endpoint. That central
        bot is intentionally scaled down during the Hermes Elrond cutover, so the
        old HTTP endpoint now refuses connections. Keep the button safe by posting
        deterministic context into the staff backend thread instead of calling the
        retired service.
        """
        backend_thread_id = int(str(data.get("backend_thread_id") or "0") or 0)
        if not backend_thread_id:
            return
        channel = self.bot.get_channel(backend_thread_id)
        if channel is None:
            guild_id = int(str(data.get("guild_id") or await self.config.guild_id() or 0) or 0)
            guild = self.bot.get_guild(guild_id) if guild_id else None
            if guild is not None:
                try:
                    channel = await guild.fetch_channel(backend_thread_id)
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    channel = None
        if channel is None or not hasattr(channel, "send"):
            log.warning("Elrond radar could not post Hermes diagnosis request notice: backend_thread=%s", backend_thread_id)
            return

        tenant = str(data.get("tenant_username") or "").strip()
        focus = str(data.get("message_content") or "").strip()
        ticket_url = str(data.get("message_url") or "").strip()
        staff = str(data.get("staff_display_name") or data.get("staff_discord_id") or "staff").strip()
        elrond_user_id = "1480732802541424922"
        lines = [
            "<@" + elrond_user_id + "> diagnose this intake ticket.",
            "🧠 Hermes Elrond diagnosis requested by " + staff + ".",
        ]
        if tenant:
            lines.append("Account: `" + tenant + "`")
        if ticket_url:
            lines.append("Ticket: " + ticket_url)
        if focus:
            lines.append("Focus:\n" + "\n".join("> " + line for line in focus.splitlines()))
        lines.append("Elrond should start from this mention; if not, staff can mention him again in this topic.")
        await channel.send(
            "\n\n".join(lines),
            allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
        )

    async def _post_to_elrond(self, data: dict) -> Tuple[Optional[int], str]:
        endpoint_url = (await self.config.endpoint_url()).strip()
        gateway_token = (await self.config.gateway_token()).strip()
        if not endpoint_url or not gateway_token:
            log.warning("Elrond radar endpoint or token is not configured")
            return None, "endpoint or token is not configured"

        headers = {
            "Authorization": f"Bearer {gateway_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(endpoint_url, json=data, headers=headers, timeout=10) as response:
                    text = await response.text()
                    if response.status >= 300:
                        log.warning("Elrond radar webhook failed: HTTP %s %s", response.status, text[:500])
                    else:
                        log.info("Elrond radar webhook accepted: %s", text[:500])
                    return response.status, text
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                log.warning("Elrond radar webhook request failed: %s", exc)
                return 599, str(exc)

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        await self._handle_reaction(payload, action="added")

    @commands.Cog.listener()
    async def on_raw_reaction_remove(self, payload: discord.RawReactionActionEvent):
        await self._handle_reaction(payload, action="removed")

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        log.info(
            "Elrond radar saw channel create: channel=%s category=%s",
            getattr(channel, "id", "unknown"),
            getattr(channel, "category_id", None),
        )
        self._schedule_ticket_channel_intake(getattr(channel, "id", 0))

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        try:
            if await self._was_tracked_ticket_channel(channel):
                await self._close_backend_thread_for_ticket(channel, reason="Original ticket channel was deleted")
        except Exception:
            log.exception("Elrond radar could not close backend topic for deleted ticket %s", getattr(channel, "id", "unknown"))

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
        try:
            ticket_category_ids = set(await self._ticket_category_ids())
        except Exception:
            log.exception("Elrond radar could not read ticket category for channel update")
            return
        before_is_ticket = getattr(before, "category_id", None) in ticket_category_ids
        after_is_ticket = getattr(after, "category_id", None) in ticket_category_ids
        if after_is_ticket and not before_is_ticket:
            log.info(
                "Elrond radar saw channel move into ticket category: channel=%s category=%s",
                getattr(after, "id", "unknown"),
                getattr(after, "category_id", None),
            )
            self._schedule_ticket_channel_intake(getattr(after, "id", 0))
        elif before_is_ticket and not after_is_ticket and await self._was_tracked_ticket_channel(before):
            await self._close_backend_thread_for_ticket(before, reason="Original ticket channel left the ticket category")

    @commands.Cog.listener()
    async def on_member_update(self, before, after):
        tenant_roles = set(await self.config.tenant_role_ids())
        if not tenant_roles:
            return
        before_roles = {role.id for role in getattr(before, "roles", [])}
        after_roles = {role.id for role in getattr(after, "roles", [])}
        if not tenant_roles.intersection(after_roles - before_roles):
            return

        guild = getattr(after, "guild", None)
        if guild is None or guild.id != await self.config.guild_id():
            return

        category_ids = set(await self._ticket_category_ids())
        channels = [
            channel for channel in getattr(guild, "text_channels", [])
            if getattr(channel, "category_id", None) in category_ids
        ]
        for channel in channels:
            visible_members = await self._ticket_visible_members(channel)
            if any(member.id == after.id for member in visible_members):
                if await self._handle_ticket_channel_create(channel):
                    log.info("Elrond radar refreshed ticket intake after Discord link: channel=%s user=%s", channel.id, after.id)

    async def _handle_reaction(self, payload: discord.RawReactionActionEvent, action: str):
        if not await self.config.enabled():
            return
        if payload.guild_id is None:
            return
        if payload.guild_id != await self.config.guild_id():
            return

        emoji = str(payload.emoji)
        if not self._is_supported_emoji(emoji):
            log.debug(
                "Elrond radar ignored unsupported reaction: emoji=%s channel=%s message=%s user=%s",
                emoji,
                payload.channel_id,
                payload.message_id,
                payload.user_id,
            )
            return

        guild = self.bot.get_guild(payload.guild_id)
        if guild is None:
            return

        member = payload.member if isinstance(payload.member, discord.Member) else None
        if not await self._is_allowed_staff(guild, payload.user_id, member):
            return

        message = await self._fetch_message(payload)
        data = self._build_payload(
            action=action,
            guild_id=payload.guild_id,
            channel_id=payload.channel_id,
            message_id=payload.message_id,
            emoji=emoji,
            staff_id=payload.user_id,
            staff_display_name=member.display_name if member is not None else str(payload.user_id),
            message=message,
        )
        log.info(
            "Elrond radar reaction accepted locally: action=%s emoji=%s channel=%s message=%s user=%s",
            action,
            emoji,
            payload.channel_id,
            payload.message_id,
            payload.user_id,
        )
        await self._post_to_elrond(data)

    def _schedule_ticket_channel_intake(self, channel_id: int):
        if not channel_id:
            return
        existing = self._pending_ticket_intake_tasks.get(channel_id)
        if existing is not None and not existing.done():
            log.info("Elrond radar ticket intake retry already pending: channel=%s", channel_id)
            return

        log.info("Elrond radar scheduled ticket intake retry: channel=%s", channel_id)
        task = asyncio.create_task(self._retry_ticket_channel_intake(channel_id))
        self._pending_ticket_intake_tasks[channel_id] = task
        task.add_done_callback(lambda _: self._pending_ticket_intake_tasks.pop(channel_id, None))

    async def _retry_ticket_channel_intake(self, channel_id: int):
        for delay in (0, 10, 30, 90):
            if delay:
                await asyncio.sleep(delay)
            try:
                guild = self.bot.get_guild(await self.config.guild_id())
                channel = self.bot.get_channel(channel_id)
                if channel is None and guild is not None:
                    try:
                        channel = await guild.fetch_channel(channel_id)
                    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                        channel = None
                if channel is None:
                    log.info("Elrond radar ticket intake retry skipped: channel=%s reason=not-found delay=%s", channel_id, delay)
                    continue
                precheck = await self._ticket_intake_precheck_skip_reason(channel)
                if precheck:
                    log.info(
                        "Elrond radar ticket intake retry skipped: channel=%s category=%s reason=%s delay=%s",
                        channel_id,
                        getattr(channel, "category_id", None),
                        precheck,
                        delay,
                    )
                    continue
                log.info(
                    "Elrond radar ticket intake retry attempting: channel=%s category=%s delay=%s",
                    channel_id,
                    getattr(channel, "category_id", None),
                    delay,
                )
                if await self._handle_ticket_channel_create(channel):
                    log.info("Elrond radar ticket intake retry succeeded: channel=%s", channel_id)
                    return
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Elrond radar delayed ticket intake failed for channel %s", channel_id)
        log.info("Elrond radar ticket intake retry exhausted: channel=%s", channel_id)

    async def _ticket_intake_precheck_skip_reason(self, channel: discord.abc.GuildChannel, force: bool = False) -> str:
        if not await self.config.enabled():
            return "disabled"
        guild = getattr(channel, "guild", None)
        if guild is None:
            return "missing-guild"
        configured_guild_id = await self.config.guild_id()
        if guild.id != configured_guild_id:
            return f"wrong-guild:{guild.id}!={configured_guild_id}"
        ticket_category_ids = set(await self._ticket_category_ids())
        category_id = getattr(channel, "category_id", None)
        if category_id not in ticket_category_ids:
            return f"wrong-category:{category_id}!={','.join(str(item) for item in ticket_category_ids)}"
        if not hasattr(channel, "send") or not hasattr(channel, "history"):
            return "not-readable-text-channel"
        tracked = set(await self.config.tracked_ticket_channel_ids() or [])
        tracked_identity = await self.config.tracked_ticket_identity_resolved() or {}
        if not isinstance(tracked_identity, dict):
            tracked_identity = {}
        tracked_key = str(channel.id)
        if channel.id in tracked and tracked_identity.get(tracked_key, True) and not force:
            return "tracked-resolved"
        return ""

    async def _handle_ticket_channel_create(self, channel: discord.abc.GuildChannel, force: bool = False) -> bool:
        if not await self.config.enabled():
            return False
        guild = getattr(channel, "guild", None)
        if guild is None or guild.id != await self.config.guild_id():
            return False
        if not await self._is_ticket_category(channel):
            return False
        if not hasattr(channel, "send") or not hasattr(channel, "history"):
            return False

        tracked = set(await self.config.tracked_ticket_channel_ids() or [])
        tracked_notices = set(await self.config.tracked_ticket_backend_notice_ids() or [])
        tracked_backend_links = set(await self.config.tracked_ticket_backend_link_notice_ids() or [])
        tracked_link_notices = set(await self.config.tracked_ticket_link_notice_ids() or [])
        tracked_identity = await self.config.tracked_ticket_identity_resolved() or {}
        if not isinstance(tracked_identity, dict):
            tracked_identity = {}
        tracked_key = str(channel.id)
        if channel.id in tracked and tracked_identity.get(tracked_key, True) and not force:
            return False

        await asyncio.sleep(5)
        tenant_member = await self._ticket_tenant_member(channel)
        first_message = await self._first_useful_channel_message(channel, tenant_member.id if tenant_member is not None else None)
        for _ in range(5):
            if tenant_member is not None or first_message is not None:
                break
            await asyncio.sleep(3)
            tenant_member = await self._ticket_tenant_member(channel)
            first_message = await self._first_useful_channel_message(channel, tenant_member.id if tenant_member is not None else None)
        message_excerpt = self._message_excerpt(first_message)
        ticket_username = self._ticket_username(first_message)
        identity_resolved = tenant_member is not None or bool(ticket_username)
        if channel.id in tracked and not identity_resolved and not force:
            return False

        visible_members = await self._ticket_visible_members(channel)
        if tenant_member is None and visible_members and not ticket_username:
            if channel.id not in tracked_link_notices:
                if await self._announce_link_required(channel, visible_members[0]):
                    await self._append_tracked_ticket_id(self.config.tracked_ticket_link_notice_ids, channel.id)
                    tracked_link_notices.add(channel.id)
            log.info("Elrond radar ticket intake is sparse pending Discord link: channel=%s user=%s", channel.id, visible_members[0].id)
        intake_member = tenant_member or (visible_members[0] if visible_members else None)
        thread_username = self._thread_username(channel, ticket_username, tenant_member)
        channel_thread_name = self._thread_username(channel, "", None)
        source_message_id = first_message.id if first_message is not None else channel.id
        ticket_url = first_message.jump_url if first_message is not None else f"https://discord.com/channels/{guild.id}/{channel.id}"
        user_notes = await self._format_user_notes_for_intake(
            str(intake_member.id) if intake_member is not None else (str(first_message.author.id) if first_message is not None else ""),
            ticket_username or thread_username,
        )
        support_context = await self._build_support_context(
            username=ticket_username or thread_username,
            discord_id=str(intake_member.id) if intake_member is not None else "",
            include_kubernetes=False,
        )
        previous_intakes = await self._format_previous_intakes(ticket_username or thread_username, exclude_ticket_id=channel.id)
        if previous_intakes:
            support_context = support_context.rstrip() + "\n\n" + previous_intakes
        intake_text = await self._render_intake(
            ticket_channel=channel,
            source_url=ticket_url,
            author=str(first_message.author) if first_message is not None else "unknown",
            tenant_member=tenant_member,
            account=ticket_username or thread_username,
            excerpt=message_excerpt,
            user_notes=user_notes,
            support_context=support_context,
        )
        intake_view = DiagnosisRequestView(self, channel.id, getattr(channel, "name", str(channel.id)), ticket_url, 0, source_message_id, ticket_username)
        backend_thread, backend_thread_created, initial_notice_posted = await self._create_backend_thread(
            channel,
            thread_username,
            aliases=[channel_thread_name],
            initial_content=intake_text,
            initial_view=intake_view,
        )
        if backend_thread is None:
            log.warning("Elrond radar could not create backend topic/thread for ticket channel %s", channel.id)
            return False
        if ticket_username or thread_username:
            asyncio.create_task(self._post_backend_kubernetes_update(
                backend_thread,
                ticket_username or thread_username,
                str(intake_member.id) if intake_member is not None else "",
            ))
        intake_view = DiagnosisRequestView(self, channel.id, getattr(channel, "name", str(channel.id)), ticket_url, backend_thread.id, source_message_id, ticket_username)
        if backend_thread_created and initial_notice_posted:
            await backend_thread.send(
                "🧠 Hermes Elrond diagnosis/action is available from this topic when staff are ready.",
                view=intake_view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            await self._append_tracked_ticket_id(self.config.tracked_ticket_backend_notice_ids, channel.id)
            tracked_notices.add(channel.id)
        else:
            should_post_backend_notice = force or channel.id not in tracked_notices or (backend_thread_created and not initial_notice_posted)
            if should_post_backend_notice:
                await self._send_backend_intake_notice(backend_thread, intake_text, intake_view)
                await self._append_tracked_ticket_id(self.config.tracked_ticket_backend_notice_ids, channel.id)
                tracked_notices.add(channel.id)
                log.info("Elrond radar posted backend ticket notice: channel=%s backend_thread=%s reused=%s", channel.id, backend_thread.id, not backend_thread_created)
        if await self.config.announce_ticket_link() and channel.id not in tracked_backend_links:
            try:
                await channel.send(
                    "Staff backend thread: " + backend_thread.jump_url,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                await self._append_tracked_ticket_id(self.config.tracked_ticket_backend_link_notice_ids, channel.id)
                tracked_backend_links.add(channel.id)
            except (discord.Forbidden, discord.HTTPException) as exc:
                log.warning("Elrond radar could not announce backend thread in ticket %s: %s", channel.id, exc)

        # Record the Discord-side mapping before the legacy webhook. Hermes/OpenClaw webhook
        # delivery may be intentionally disabled, but forum lifecycle tracking still needs to work.
        await self._record_backend_thread(channel, ticket_username or thread_username, backend_thread)

        status, body = await self._post_to_elrond({
            "action": "ticket_created",
            "guild_id": str(guild.id),
            "channel_id": str(channel.id),
            "channel_name": getattr(channel, "name", str(channel.id)),
            "message_id": str(source_message_id),
            "message_url": ticket_url,
            "message_author_id": str(intake_member.id) if intake_member is not None else (str(first_message.author.id) if first_message is not None else ""),
            "message_author_name": str(intake_member) if intake_member is not None else (str(first_message.author) if first_message is not None else ""),
            "tenant_username": ticket_username,
            "message_content": message_excerpt,
            "user_notes": user_notes,
            "backend_thread_id": str(backend_thread.id),
            "backend_thread_url": backend_thread.jump_url,
            "staff_discord_id": str(self.bot.user.id if self.bot.user else 0),
            "staff_display_name": "Elrond Radar",
        })
        if status is not None and status < 300:
            tracked_ids = await self.config.tracked_ticket_channel_ids() or []
            tracked_ids = [item for item in tracked_ids if item != channel.id]
            tracked_ids.append(channel.id)
            tracked_ids = tracked_ids[-500:]
            await self.config.tracked_ticket_channel_ids.set(tracked_ids)
            tracked_identity[tracked_key] = identity_resolved
            tracked_identity = {str(item): tracked_identity.get(str(item), True) for item in tracked_ids}
            await self.config.tracked_ticket_identity_resolved.set(tracked_identity)
            log.info("Elrond radar ticket intake completed: channel=%s backend_thread=%s", channel.id, backend_thread.id)
            return True
        log.warning("Elrond radar ticket intake webhook failed after creating backend thread: channel=%s status=%s body=%s", channel.id, status, body[:300])
        # The Redbot-created backend forum topic is now the authoritative intake
        # artifact. Do not keep retrying for minutes just because the legacy
        # Hermes/OpenClaw webhook is disabled or unavailable after the topic exists.
        tracked_ids = await self.config.tracked_ticket_channel_ids() or []
        tracked_ids = [item for item in tracked_ids if item != channel.id]
        tracked_ids.append(channel.id)
        tracked_ids = tracked_ids[-500:]
        await self.config.tracked_ticket_channel_ids.set(tracked_ids)
        tracked_identity[tracked_key] = identity_resolved
        tracked_identity = {str(item): tracked_identity.get(str(item), True) for item in tracked_ids}
        await self.config.tracked_ticket_identity_resolved.set(tracked_identity)
        log.info("Elrond radar ticket intake completed with backend topic only: channel=%s backend_thread=%s", channel.id, backend_thread.id)
        return True

    async def _was_tracked_ticket_channel(self, channel) -> bool:
        if channel is None:
            return False
        tracked = set(await self.config.tracked_ticket_channel_ids() or [])
        mapping = await self.config.tracked_ticket_backend_thread_ids() or {}
        return getattr(channel, "id", None) in tracked or str(getattr(channel, "id", "")) in mapping

    def _history_key(self, username: str) -> str:
        return self._normalize_username(username) or str(username or "").strip().lower()

    async def _format_previous_intakes(self, username: str, exclude_ticket_id: int = 0) -> str:
        key = self._history_key(username)
        if not key:
            return ""
        history = await self.config.tracked_ticket_user_history() or {}
        entries = [item for item in history.get(key, []) if str(item.get("ticket_channel_id")) != str(exclude_ticket_id)]
        entries = entries[-5:]
        if not entries:
            return ""
        lines = ["🧵 **Previous Intakes**"]
        for item in reversed(entries):
            title = str(item.get("ticket_name") or item.get("ticket_channel_id") or "ticket")
            created = str(item.get("created_at") or "unknown")[:16].replace("T", " ")
            url = item.get("backend_thread_url") or item.get("ticket_url") or ""
            status = "closed" if item.get("closed_at") else "open"
            if url:
                lines.append(f"- {created} — `{title}` — {url} — `{status}`")
            else:
                lines.append(f"- {created} — `{title}` — `{status}`")
        return "\n".join(lines)

    async def _record_backend_thread(self, ticket_channel, username: str, backend_thread):
        ticket_id = str(getattr(ticket_channel, "id", ""))
        if not ticket_id or backend_thread is None:
            return
        key = self._history_key(username) or self._thread_username(ticket_channel, "", None)
        now = discord.utils.utcnow().isoformat()
        entry = {
            "ticket_channel_id": ticket_id,
            "ticket_name": getattr(ticket_channel, "name", ticket_id),
            "ticket_url": f"https://discord.com/channels/{getattr(getattr(ticket_channel, 'guild', None), 'id', '')}/{ticket_id}",
            "backend_thread_id": str(getattr(backend_thread, "id", "")),
            "backend_thread_name": getattr(backend_thread, "name", ""),
            "backend_thread_url": getattr(backend_thread, "jump_url", ""),
            "username": key,
            "created_at": now,
        }
        mapping = await self.config.tracked_ticket_backend_thread_ids() or {}
        mapping[ticket_id] = entry
        await self.config.tracked_ticket_backend_thread_ids.set(mapping)
        history = await self.config.tracked_ticket_user_history() or {}
        items = [item for item in history.get(key, []) if str(item.get("ticket_channel_id")) != ticket_id and str(item.get("backend_thread_id")) != entry["backend_thread_id"]]
        items.append(entry)
        history[key] = items[-20:]
        await self.config.tracked_ticket_user_history.set(history)

    async def _close_backend_thread_for_ticket(self, ticket_channel, reason: str):
        ticket_id = str(getattr(ticket_channel, "id", ""))
        if not ticket_id:
            return False
        mapping = await self.config.tracked_ticket_backend_thread_ids() or {}
        entry = mapping.get(ticket_id)
        if not entry:
            return False
        backend_thread_id = int(str(entry.get("backend_thread_id") or "0") or 0)
        if not backend_thread_id:
            return False
        thread = self.bot.get_channel(backend_thread_id)
        guild = getattr(ticket_channel, "guild", None)
        if thread is None and guild is not None:
            try:
                thread = await guild.fetch_channel(backend_thread_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                thread = None
        if thread is None:
            return False
        closed_at = discord.utils.utcnow().isoformat()
        try:
            await thread.send(f"✅ Original ticket `{getattr(ticket_channel, 'name', ticket_id)}` closed/removed. Archiving this intake topic.\nReason: {reason}", allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            pass
        try:
            name = getattr(thread, "name", "") or ""
            new_name = ("✅ " + name.lstrip("🟡✅🟠🔴 "))[:90] if name else None
            kwargs = {"archived": True, "locked": True, "reason": "Original support ticket closed"}
            if new_name:
                kwargs["name"] = new_name
            await thread.edit(**kwargs)
        except (discord.Forbidden, discord.HTTPException, TypeError):
            try:
                await thread.edit(archived=True, reason="Original support ticket closed")
            except (discord.Forbidden, discord.HTTPException, TypeError):
                pass
        entry["closed_at"] = closed_at
        entry["close_reason"] = reason
        mapping[ticket_id] = entry
        await self.config.tracked_ticket_backend_thread_ids.set(mapping)
        key = entry.get("username") or self._history_key(getattr(ticket_channel, "name", ""))
        history = await self.config.tracked_ticket_user_history() or {}
        if key in history:
            for item in history[key]:
                if str(item.get("ticket_channel_id")) == ticket_id:
                    item["closed_at"] = closed_at
                    item["close_reason"] = reason
            await self.config.tracked_ticket_user_history.set(history)
        log.info("Elrond radar archived backend topic %s for closed ticket %s", backend_thread_id, ticket_id)
        return True


    async def _announce_link_required(self, channel, member):
        link_channel_id = await self.config.link_instructions_channel_id()
        link_target = f"<#{link_channel_id}>" if link_channel_id else "the Discord linking instructions channel"
        try:
            await channel.send(
                f"{member.mention}, I can't prepare your ElfHosted account intake yet because this Discord account is not linked. "
                f"Please follow the instructions in {link_target}, then staff can retry intake.",
                allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
            )
            return True
        except (discord.Forbidden, discord.HTTPException) as exc:
            log.warning("Elrond radar could not announce Discord linking instructions in ticket %s: %s", channel.id, exc)
            return False

    async def _append_tracked_ticket_id(self, config_value, channel_id: int):
        tracked_ids = await config_value() or []
        tracked_ids = [item for item in tracked_ids if item != channel_id]
        tracked_ids.append(channel_id)
        tracked_ids = tracked_ids[-500:]
        await config_value.set(tracked_ids)

    async def _ticket_tenant_member(self, channel):
        tenant_roles = set(await self.config.tenant_role_ids())
        for member in await self._ticket_visible_members(channel):
            if tenant_roles and any(role.id in tenant_roles for role in getattr(member, "roles", [])):
                return member
        return None

    async def _ticket_visible_members(self, channel):
        allowed_users = set(await self.config.allowed_user_ids())
        allowed_roles = set(await self.config.allowed_role_ids())
        overwrites = getattr(channel, "overwrites", {}) or {}
        members = []
        for target, overwrite in overwrites.items():
            if not isinstance(target, discord.Member):
                continue
            if target.bot or target.id in allowed_users:
                continue
            if any(role.id in allowed_roles for role in getattr(target, "roles", [])):
                continue
            view_channel = getattr(overwrite, "view_channel", None)
            read_messages = getattr(overwrite, "read_messages", None)
            if view_channel is False or read_messages is False:
                continue
            if view_channel is True or read_messages is True:
                members.append(target)
        return members

    async def _first_useful_channel_message(self, channel, preferred_author_id: Optional[int] = None) -> Optional[discord.Message]:
        fallback = None
        preferred_fallback = None
        try:
            async for message in channel.history(limit=50, oldest_first=True):
                excerpt = self._message_excerpt(message)
                if excerpt and fallback is None:
                    fallback = message
                if self._has_ticket_request_fields(message):
                    return message
                author = getattr(message, "author", None)
                if excerpt and preferred_author_id is not None and getattr(author, "id", None) == preferred_author_id:
                    return message
                if excerpt and preferred_fallback is None and not getattr(author, "bot", False):
                    preferred_fallback = message
        except (discord.Forbidden, discord.HTTPException):
            return None
        return preferred_fallback or fallback

    async def _post_backend_kubernetes_update(self, backend_thread, username: str, discord_id: str = ""):
        try:
            context = await self._build_support_context(
                username=username,
                discord_id=discord_id,
                include_billing=False,
                include_kubernetes=True,
                context_title="🔁 **Kubernetes Snapshot Update**",
            )
            for chunk in self._split_discord(context):
                await backend_thread.send(chunk, allowed_mentions=discord.AllowedMentions.none())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Elrond radar Kubernetes snapshot update failed for backend thread %s", getattr(backend_thread, "id", None))

    async def _source_ticket_channel_from_intake(self, guild: Optional[discord.Guild], channel) -> Optional[discord.abc.GuildChannel]:
        if guild is None or not hasattr(channel, "history"):
            return None
        try:
            async for message in channel.history(limit=10, oldest_first=True):
                content = str(getattr(message, "content", "") or "")
                match = re.search(r"Ticket intake for\s+<#(\d+)>", content) or re.search(r"<#(\d+)>", content)
                if not match:
                    continue
                source_channel_id = int(match.group(1))
                source_channel = self.bot.get_channel(source_channel_id)
                if source_channel is None:
                    try:
                        source_channel = await guild.fetch_channel(source_channel_id)
                    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                        return None
                return source_channel
        except (discord.Forbidden, discord.HTTPException):
            return None
        return None

    def _message_excerpt(self, message: Optional[discord.Message], limit: int = 500) -> str:
        if message is None:
            return ""

        priority_parts = []
        parts = []
        content = str(getattr(message, "content", "") or "").strip()
        if content:
            parts.append(content)

        for embed in getattr(message, "embeds", []) or []:
            title = str(getattr(embed, "title", "") or "").strip()
            description = str(getattr(embed, "description", "") or "").strip()
            if title:
                parts.append(title)
            if description:
                parts.append(description)
            for field in getattr(embed, "fields", []) or []:
                name = str(getattr(field, "name", "") or "").strip()
                value = str(getattr(field, "value", "") or "").strip()
                if name and value:
                    formatted = f"{name}: {value}"
                    if self._is_ticket_request_field(name):
                        priority_parts.append(value)
                    else:
                        parts.append(formatted)
                elif value:
                    parts.append(value)

        attachments = getattr(message, "attachments", []) or []
        if attachments:
            parts.append("Attachments: " + ", ".join(getattr(item, "filename", "attachment") for item in attachments[:5]))

        excerpt = " ".join(" ".join(part.split()) for part in [*priority_parts, *parts] if part).strip()
        if len(excerpt) > limit:
            return excerpt[: limit - 1].rstrip() + "…"
        return excerpt

    def _is_ticket_request_field(self, name: str) -> bool:
        normalized = " ".join(str(name or "").lower().replace("/", " ").replace("-", " ").split())
        return (
            "account username" in normalized
            or "account issue" in normalized
            or "issue error" in normalized
            or "support request" in normalized
            or "problem" in normalized
        )

    def _has_ticket_request_fields(self, message: Optional[discord.Message]) -> bool:
        if message is None:
            return False
        for embed in getattr(message, "embeds", []) or []:
            for field in getattr(embed, "fields", []) or []:
                name = str(getattr(field, "name", "") or "").strip()
                value = str(getattr(field, "value", "") or "").strip()
                if value and self._is_ticket_request_field(name):
                    return True
        return False

    def _ticket_username(self, message: Optional[discord.Message]) -> str:
        if message is None:
            return ""
        for embed in getattr(message, "embeds", []) or []:
            for field in getattr(embed, "fields", []) or []:
                name = str(getattr(field, "name", "") or "").strip()
                value = str(getattr(field, "value", "") or "").strip()
                if self._is_ticket_username_field(name) and value:
                    return self._normalize_username(value)
        return ""

    def _is_ticket_username_field(self, name: str) -> bool:
        normalized = " ".join(str(name or "").lower().replace("/", " ").replace("-", " ").split())
        return "account username" in normalized or "elfhosted username" in normalized or normalized == "username"

    async def _backend_channel(self, ticket_channel):
        backend_channel = self.bot.get_channel(await self.config.backend_channel_id())
        if backend_channel is None and ticket_channel.guild is not None:
            try:
                backend_channel = await ticket_channel.guild.fetch_channel(await self.config.backend_channel_id())
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                return None
        return backend_channel

    async def _create_backend_thread(self, ticket_channel, username: str, aliases=None, initial_content: str = "", initial_view=None):
        backend_channel = await self._backend_channel(ticket_channel)
        if backend_channel is None or not hasattr(backend_channel, "create_thread"):
            return None, False, False

        raw_name = username or getattr(ticket_channel, "name", str(ticket_channel.id))
        ticket_label = str(getattr(ticket_channel, "name", ticket_channel.id) or ticket_channel.id)
        unique_name = f"{raw_name} · {ticket_label} · {getattr(ticket_channel, 'id', '')}"
        thread_name = ("🟡 " + unique_name)[:90]
        lookup_names = [unique_name, thread_name, *(aliases or [])]
        existing = None
        for lookup_name in lookup_names:
            existing = await self._find_backend_thread(backend_channel, lookup_name)
            if existing is not None:
                break
        if existing is not None:
            try:
                await existing.edit(archived=False, locked=False, reason="Elrond support ticket intake reopened")
            except (discord.Forbidden, discord.HTTPException):
                try:
                    await existing.edit(reason="Elrond support ticket intake reopened")
                except (discord.Forbidden, discord.HTTPException):
                    pass
            return existing, False, False

        is_forum = getattr(backend_channel, "type", None) == discord.ChannelType.forum or backend_channel.__class__.__name__.lower().endswith("forumchannel")
        if is_forum:
            chunks = self._split_discord(initial_content or "Ticket intake pending.")
            try:
                created = await backend_channel.create_thread(
                    name=thread_name,
                    content=chunks[0] if chunks else "Ticket intake pending.",
                    allowed_mentions=discord.AllowedMentions.none(),
                    reason="Elrond support ticket intake",
                )
                thread = getattr(created, "thread", created)
                for chunk in chunks[1:]:
                    await thread.send(chunk, allowed_mentions=discord.AllowedMentions.none())
                return thread, True, True
            except TypeError:
                pass
            except (discord.Forbidden, discord.HTTPException):
                return None, False, False

        try:
            thread = await backend_channel.create_thread(
                name=thread_name,
                type=discord.ChannelType.public_thread,
                reason="Elrond support ticket intake",
            )
            return thread, True, False
        except (discord.Forbidden, discord.HTTPException, TypeError):
            try:
                thread = await backend_channel.create_thread(
                    name=thread_name,
                    type=discord.ChannelType.private_thread,
                    reason="Elrond support ticket intake",
                )
                return thread, True, False
            except (discord.Forbidden, discord.HTTPException, TypeError):
                return None, False, False

    async def _find_backend_thread(self, backend_channel, username: str):
        wanted = self._normal_thread_name(username)
        for thread in getattr(backend_channel, "threads", []) or []:
            if self._normal_thread_name(getattr(thread, "name", "")) == wanted:
                return thread
        if hasattr(backend_channel, "archived_threads"):
            for private in (False, True):
                try:
                    async for thread in backend_channel.archived_threads(private=private, limit=100):
                        if self._normal_thread_name(getattr(thread, "name", "")) == wanted:
                            return thread
                except (discord.Forbidden, discord.HTTPException, TypeError):
                    continue
        return None

    def _thread_username(self, ticket_channel, ticket_username: str, tenant_member) -> str:
        if ticket_username:
            return ticket_username.lower()
        channel_name = str(getattr(ticket_channel, "name", "") or "").strip().lower()
        if "-" in channel_name:
            prefix, suffix = channel_name.rsplit("-", 1)
            if suffix.isdigit():
                return prefix
        if tenant_member is not None:
            return str(getattr(tenant_member, "name", "") or getattr(tenant_member, "display_name", "") or "").lower()
        return channel_name

    def _normal_thread_name(self, value: str) -> str:
        name = str(value or "").strip().lower()
        for prefix in ("🟡", "🟢", "🔴", "🟠", "intake-"):
            if name.startswith(prefix):
                name = name[len(prefix):].strip()
        return name

    def _build_payload(
        self,
        action: str,
        guild_id: int,
        channel_id: int,
        message_id: int,
        emoji: str,
        staff_id: int,
        staff_display_name: str,
        message: Optional[discord.Message],
    ) -> dict:
        channel = message.channel if message is not None else self.bot.get_channel(channel_id)
        channel_name = getattr(channel, "name", str(channel_id))
        message_author = message.author if message is not None else None
        jump_url = (
            message.jump_url
            if message is not None
            else f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"
        )
        return {
            "action": action,
            "guild_id": str(guild_id),
            "channel_id": str(channel_id),
            "channel_name": channel_name,
            "message_id": str(message_id),
            "message_url": jump_url,
            "message_author_id": str(message_author.id) if message_author else "",
            "message_author_name": str(message_author) if message_author else "",
            "message_content": message.content if message is not None else "",
            "emoji": emoji,
            "staff_discord_id": str(staff_id),
            "staff_display_name": staff_display_name,
        }
