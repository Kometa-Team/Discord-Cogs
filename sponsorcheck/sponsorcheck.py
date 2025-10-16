from __future__ import annotations

import logging
import re
import aiohttp
from redbot.core import commands

# ---------------- Logging (mimics your validate cog pattern) ----------------
mylogger = logging.getLogger("sponsorcheck")
mylogger.setLevel(logging.DEBUG)

# ---------------- Config: Allowed roles (by ID) ----------------
ALLOWED_ROLE_IDS = {
    929756550380286153,  # Moderator
    929900016531828797,  # Kometa Masters
    981499667722424390,  # Kometa Apprentices
}

# ---------------- Target GitHub (sponsorable) ----------------
SPONSORABLE = "meisnate12"
SPONSORS_URL_FMT = "https://github.com/sponsors/{sponsorable}"

# Extract usernames from avatar img tags: alt="@username"
ALT_USER_RE = re.compile(r'alt="@([A-Za-z0-9-]{1,39})"')
# Conservative fallback for anchors like href="/username"
HREF_USER_RE = re.compile(r'href="/([A-Za-z0-9-]{1,39})"')


class SponsorCheck(commands.Cog):
    """Check if a GitHub user is a current or past *public* sponsor of the target account."""

    def __init__(self, bot):
        self.bot = bot

    # Gate ALL commands in this cog by allowed roles (guild only)
    async def cog_check(self, ctx: commands.Context) -> bool:
        if not ctx.guild:
            mylogger.info("Blocked: command used in DM.")
            return False

        author_name = f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author else "Unknown"
        guild_name = ctx.guild.name if ctx.guild else "Direct Message"
        channel_name = getattr(ctx.channel, "name", "Direct Message")
        mylogger.info(
            f"SponsorCheck invoked by {author_name} in {guild_name}/{channel_name} "
            f"(IDs: {ctx.guild.id if ctx.guild else 'N/A'}/{ctx.channel.id if ctx.guild else 'N/A'})"
        )

        user_role_ids = {r.id for r in ctx.author.roles}
        has_allowed = bool(ALLOWED_ROLE_IDS & user_role_ids)
        has_manage_guild = ctx.author.guild_permissions.manage_guild

        if has_allowed or has_manage_guild:
            mylogger.debug(
                f"Access granted: has_allowed={has_allowed}, manage_guild={has_manage_guild}, "
                f"user_roles={list(user_role_ids)}"
            )
            return True

        mylogger.info(
            f"Access denied for {author_name}. Required any of {list(ALLOWED_ROLE_IDS)}, "
            f"user_roles={list(user_role_ids)}"
        )
        return False

    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """
        Check if <username> is a public sponsor of the target (default: meisnate12).

        Usage: [p]sponsor <github-username>
        """
        target = username.lstrip("@").strip()
        if not target:
            mylogger.info("No username provided to sponsor command.")
            return await ctx.send("Please provide a GitHub username, e.g. `[p]sponsor bullmoose20`.")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)

        # Typing indicator (works across discord.py/Red variants)
        try:
            if hasattr(ctx.channel, "trigger_typing"):
                await ctx.channel.trigger_typing()
            else:
                # Fallback to context manager if available
                typing_cm = getattr(ctx, "typing", None)
                if callable(typing_cm):
                    async with ctx.typing():
                        pass
        except Exception as e:
            mylogger.debug(f"Typing indicator failed (non-fatal): {e}")

        mylogger.debug(f"Fetching sponsors page: {url}")

        try:
            html = await self._fetch(url)
            mylogger.debug(f"Fetched sponsors page OK (len={len(html)})")
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        # Locate section markers (best effort)
        idx_current = self._find_any(html, ["Current sponsors", "Current Sponsors"])
        idx_past = self._find_any(html, ["Past sponsors", "Past Sponsors"])
        mylogger.debug(f"Section indices: current={idx_current}, past={idx_past}")

        # Slice sections
        if idx_current != -1 and idx_past != -1:
            if idx_current < idx_past:
                html_current = html[idx_current:idx_past]
                html_past = html[idx_past:]
            else:
                html_current = html[:idx_current]
                html_past = html[idx_past:]
        elif idx_current != -1:
            html_current = html[idx_current:]
            html_past = ""
        elif idx_past != -1:
            html_current = ""
            html_past = html[idx_past:]
        else:
            html_current = html
            html_past = ""

        current_users = {u.lower() for u in self._extract_usernames(html_current)}
        past_users = {u.lower() for u in self._extract_usernames(html_past)}
        mylogger.debug(
            f"Extracted users: current={len(current_users)} past={len(past_users)} "
            f"(sample current: {list(current_users)[:5]}) (sample past: {list(past_users)[:5]})"
        )

        t_low = target.lower()
        if t_low in current_users:
            mylogger.info(f"Result: {target} is a CURRENT public sponsor of {SPONSORABLE}.")
            return await ctx.send(
                f"✅ **{target}** is a **current** public sponsor of **{SPONSORABLE}**.\n<{url}>"
            )
        if t_low in past_users:
            mylogger.info(f"Result: {target} is a PAST public sponsor of {SPONSORABLE}.")
            return await ctx.send(
                f"ℹ️ **{target}** is a **past** public sponsor of **{SPONSORABLE}**.\n<{url}>"
            )

        mylogger.info(f"Result: {target} not found as PUBLIC sponsor (private sponsors not visible).")
        return await ctx.send(
            f"❌ **{target}** is not listed as a **public** sponsor of **{SPONSORABLE}**.\n"
            f"(Private sponsors won’t appear on the public page.)\n<{url}>"
        )

    # ---------------- Helpers ----------------

    async def _fetch(self, url: str) -> str:
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {
            "User-Agent": "Red-SponsorCheck/1.0 (+https://github.com/Kometa-Team)",
            "Accept": "text/html,application/xhtml+xml",
        }
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                return await resp.text()

    def _extract_usernames(self, html: str) -> set[str]:
        users = set(ALT_USER_RE.findall(html))

        # Fallback via href="/username" (filter out non-user paths)
        link_users = set(HREF_USER_RE.findall(html))
        banned = {
            "sponsors", "orgs", "login", "notifications", "settings",
            "enterprise", "topics", "about", "pricing", "apps", "marketplace"
        }
        link_users = {u for u in link_users if u not in banned and not u.startswith("#")}
        users |= link_users

        return users

    @staticmethod
    def _find_any(haystack: str, needles: list[str]) -> int:
        for n in needles:
            i = haystack.find(n)
            if i != -1:
                return i
        return -1
