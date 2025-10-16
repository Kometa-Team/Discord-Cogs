from __future__ import annotations

from redbot.core import commands
import aiohttp
import re

# ===== Configure allowed roles (by ID) =====
ALLOWED_ROLE_IDS = {
    929756550380286153,  # Moderator
    929900016531828797,  # Kometa Masters
    981499667722424390,  # Kometa Apprentices
}

# ===== Target GitHub account (sponsorable) =====
SPONSORABLE = "meisnate12"
SPONSORS_URL_FMT = "https://github.com/sponsors/{sponsorable}"

# Precompiled regex to extract usernames from alt="@username"
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
            return False  # disallow in DMs
        user_role_ids = {r.id for r in ctx.author.roles}
        # allow if user has any allowed role OR has Manage Guild (fallback)
        return bool(ALLOWED_ROLE_IDS & user_role_ids) or ctx.author.guild_permissions.manage_guild

    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """
        Check if <username> is a public sponsor of the target (default: meisnate12).

        Usage: [p]sponsor <github-username>
        """
        target = username.lstrip("@").strip()
        if not target:
            return await ctx.send("Please provide a GitHub username, e.g. `[p]sponsor bullmoose20`.")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        await ctx.trigger_typing()

        try:
            html = await self._fetch(url)
        except Exception as e:
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        # Find section markers (best effort; headings can vary slightly)
        idx_current = self._find_any(html, ["Current sponsors", "Current Sponsors"])
        idx_past = self._find_any(html, ["Past sponsors", "Past Sponsors"])

        # Split into current and past segments if markers exist
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
            # Fallback: treat entire page as "unknown/current"
            html_current = html
            html_past = ""

        current_users = self._extract_usernames(html_current)
        past_users = self._extract_usernames(html_past)

        t_low = target.lower()
        current_users = {u.lower() for u in current_users}
        past_users = {u.lower() for u in past_users}

        if t_low in current_users:
            return await ctx.send(
                f"✅ **{target}** is a **current** public sponsor of **{SPONSORABLE}**.\n<{url}>"
            )
        if t_low in past_users:
            return await ctx.send(
                f"ℹ️ **{target}** is a **past** public sponsor of **{SPONSORABLE}**.\n<{url}>"
            )
        return await ctx.send(
            f"❌ **{target}** is not listed as a **public** sponsor of **{SPONSORABLE}**.\n"
            f"(Private sponsors won’t appear on the public page.)\n<{url}>"
        )

    # ---------- helpers ----------

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

        # Fallback: anchors like href="/username" (filter obvious non-user paths)
        link_users = set(HREF_USER_RE.findall(html))
        banned = {
            "sponsors", "orgs", "login", "notifications", "settings",
            "enterprise", "topics", "about", "pricing"
        }
        link_users = {u for u in link_users if u not in banned}

        return users.union(link_users)

    @staticmethod
    def _find_any(haystack: str, needles: list[str]) -> int:
        for n in needles:
            i = haystack.find(n)
            if i != -1:
                return i
        return -1
