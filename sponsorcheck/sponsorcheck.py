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
# Headings with counts e.g., "Current sponsors 66" / "Past sponsors 206"
CURRENT_COUNT_RE = re.compile(r"Current\s+sponsors\s+(\d+)", re.IGNORECASE)
PAST_COUNT_RE = re.compile(r"Past\s+sponsors\s+(\d+)", re.IGNORECASE)


class SponsorCheck(commands.Cog):
    """Check if a GitHub user is a current or past *public* sponsor and list/inspect public sponsors."""

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

    # ---------- Primary: single-user check ----------
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
        self._typing_safely(ctx)

        mylogger.debug(f"Fetching sponsors page: {url}")
        try:
            html = await self._fetch(url)
            mylogger.debug(f"Fetched sponsors page OK (len={len(html)})")
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        html_current, html_past = self._split_sections(html)

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

    # ---------- Counts ----------
    @commands.command(name="sponsorcount")
    @commands.guild_only()
    async def sponsorcount(self, ctx: commands.Context):
        """Show the public counts of current and past sponsors."""
        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        current_count = self._extract_count(html, CURRENT_COUNT_RE)
        past_count = self._extract_count(html, PAST_COUNT_RE)

        mylogger.info(f"Counts: current={current_count} past={past_count}")
        await ctx.send(
            f"**{SPONSORABLE}** sponsors (public page):\n"
            f"- Current: **{current_count}**\n"
            f"- Past: **{past_count}**\n<{url}>"
        )

    # ---------- List ----------
    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context, which: str = "both", limit: int = 30):
        """
        List public sponsors (names only) from the visible page.

        Usage:
          [p]sponsorlist                -> both (up to 30 each)
          [p]sponsorlist current 50     -> current only (50 max to avoid spam)
          [p]sponsorlist past 20        -> past only (20)
          [p]sponsorlist both 15        -> both, 15 each

        Note: Only the sponsors visible on the public page HTML are listed.
        (The page's "Show more" button uses JS; dates are not publicly shown.)
        """
        which = which.lower()
        limit = max(1, min(100, limit))  # clamp

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        html_current, html_past = self._split_sections(html)
        current_users = sorted(self._extract_usernames(html_current))
        past_users = sorted(self._extract_usernames(html_past))

        lines = []
        if which in ("current", "both"):
            chunk = ", ".join(current_users[:limit]) if current_users else "—"
            lines.append(f"**Current** ({len(current_users)} shown): {chunk}")
        if which in ("past", "both"):
            chunk = ", ".join(past_users[:limit]) if past_users else "—"
            lines.append(f"**Past** ({len(past_users)} shown): {chunk}")
        if which not in ("current", "past", "both"):
            return await ctx.send("Please use `current`, `past`, or `both`.")

        mylogger.info(f"sponsorlist {which} limit={limit} -> currents={len(current_users)} pasts={len(past_users)}")
        await ctx.send(
            f"Public sponsors for **{SPONSORABLE}** (from visible page):\n" + "\n".join(lines) + f"\n<{url}>")

    # ---------------- Helpers ----------------

    def _typing_safely(self, ctx: commands.Context) -> None:
        try:
            if hasattr(ctx.channel, "trigger_typing"):
                # discord.py 1.x
                self.bot.loop.create_task(ctx.channel.trigger_typing())
            else:
                # fallback to context manager if available
                typing_cm = getattr(ctx, "typing", None)
                if callable(typing_cm):
                    self.bot.loop.create_task(self._typing_cm(ctx))
        except Exception as e:
            mylogger.debug(f"Typing indicator failed (non-fatal): {e}")

    async def _typing_cm(self, ctx: commands.Context):
        try:
            async with ctx.typing():
                pass
        except Exception:
            pass

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

    def _split_sections(self, html: str) -> tuple[str, str]:
        idx_current = self._find_any(html, ["Current sponsors", "Current Sponsors"])
        idx_past = self._find_any(html, ["Past sponsors", "Past Sponsors"])
        mylogger.debug(f"Section indices: current={idx_current}, past={idx_past}")

        if idx_current != -1 and idx_past != -1:
            if idx_current < idx_past:
                return html[idx_current:idx_past], html[idx_past:]
            else:
                return html[:idx_current], html[idx_past:]
        elif idx_current != -1:
            return html[idx_current:], ""
        elif idx_past != -1:
            return "", html[idx_past:]
        else:
            return html, ""

    def _extract_usernames(self, html: str) -> list[str]:
        users = set(ALT_USER_RE.findall(html))
        # Fallback via href="/username" (filter out non-user paths)
        link_users = set(HREF_USER_RE.findall(html))
        banned = {
            "sponsors", "orgs", "login", "notifications", "settings",
            "enterprise", "topics", "about", "pricing", "apps", "marketplace"
        }
        link_users = {u for u in link_users if u not in banned and not u.startswith("#")}
        users |= link_users
        return sorted(users, key=str.lower)

    @staticmethod
    def _find_any(haystack: str, needles: list[str]) -> int:
        for n in needles:
            i = haystack.find(n)
            if i != -1:
                return i
        return -1

    @staticmethod
    def _extract_count(html: str, regex: re.Pattern) -> int:
        m = regex.search(html)
        try:
            return int(m.group(1)) if m else 0
        except Exception:
            return 0
