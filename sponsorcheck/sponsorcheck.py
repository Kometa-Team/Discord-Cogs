from __future__ import annotations

import logging
import re
from io import BytesIO

import aiohttp
import discord
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

# ---------------- Your Sponsor role (guild role for supporters) ------------
SPONSOR_ROLE_ID = 862041125706268702  # "Sponsor" role in your server

# Optional: map Discord user IDs -> GitHub usernames if names don't match
# e.g., GH_USERNAME_MAP = { 123456789012345678: "octocat", ... }
GH_USERNAME_MAP: dict[int, str] = {}

# ---------------- Target GitHub (sponsorable) ----------------
SPONSORABLE = "meisnate12"
SPONSORS_URL_FMT = "https://github.com/sponsors/{sponsorable}"

# Extract usernames from avatar img tags: alt="@username"
ALT_USER_RE = re.compile(r'alt="@([A-Za-z0-9-]{1,39})"')
# Conservative fallback for anchors like href="/username"
HREF_USER_RE = re.compile(r'href="/([A-Za-z0-9-]{1,39})"')

# Badge counts like "Current sponsors 66" / "Past sponsors 206" (mobile/desktop)
CURRENT_COUNT_RE = re.compile(r"Current\s*sponsors[^\d]*([0-9,]+)", re.IGNORECASE)
PAST_COUNT_RE = re.compile(r"Past\s*sponsors[^\d]*([0-9,]+)", re.IGNORECASE)

# Separators we treat as "Name SEP ghuser" → take last segment as candidate
SEP_CHARS = ("|", "·", "-", "—", ":", "/")


class SponsorCheck(commands.Cog):
    """GitHub sponsors tools: check/list public sponsors and verify against a server Sponsor role."""

    def __init__(self, bot):
        self.bot = bot

    # ---------------- Gate ALL commands in this cog by allowed roles ---------------
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
            f"Access denied. Needs any of {list(ALLOWED_ROLE_IDS)}; user_roles={list(user_role_ids)}"
        )
        return False

    # ---------------- Commands ----------------

    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """
        Check if <username> appears as a **public** sponsor of the target (current or past).
        If not found, tries to resolve by matching a Sponsor-role member's Kometa Server Name (display name)
        to the provided string, then uses that member's Discord username (and variants).
        Usage: [p]sponsor <github-username or Kometa server name>
        """
        target = username.lstrip("@").strip()
        if not target:
            mylogger.info("No username provided to sponsor command.")
            return await ctx.send("Please provide a GitHub username, e.g. `[p]sponsor bullmoose20`.")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        # Build union sets
        curr_html, past_html = self._split_sections(html)
        current_set = {u.lower() for u in self._extract_usernames(curr_html)}
        past_set = {u.lower() for u in self._extract_usernames(past_html)}
        union_set = current_set | past_set

        # 1) direct GH username match
        t = target.lower()
        if t in union_set:
            status = "current" if t in current_set else "past"
            return await self._send_report(ctx, [
                f"✅ **{target}** is a **{status}** public sponsor of **{SPONSORABLE}**.",
                "(Note: private sponsors are not shown on the public page.)",
                f"<{url}>",
            ])

        # 2) KSN→DSN resolution via Sponsor role (covers bullmoose → bullmoose20)
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if role:
            m = next((mem for mem in role.members if (mem.display_name or "").strip().lower() == t), None)
            if m:
                ksn = (m.display_name or "").strip()
                dsn = (m.name or "").strip()
                override = GH_USERNAME_MAP.get(m.id)
                candidates = self._gh_candidates_from_names(ksn, dsn, override)
                hit = next((c for c in candidates if c in union_set), None)
                if hit:
                    status = "current" if hit in current_set else "past"
                    return await self._send_report(ctx, [
                        f"✅ **{ksn}** resolved via Discord → GH as **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**.",
                        "(Resolved from Kometa server name; note: private sponsors are not shown on the public page.)",
                        f"<{url}>",
                    ])

        # Not found
        return await self._send_report(ctx, [
            f"❌ **{target}** is not listed as a **public** sponsor of **{SPONSORABLE}** (current or past).",
            "Only the sponsorable can verify private sponsors.",
            f"<{url}>",
        ])

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """
        List **all visible** public sponsors from the page (current & past), and show private counts.
        Usage: [p]sponsorlist
        """
        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        curr_html, past_html = self._split_sections(html)
        current_public = self._extract_usernames(curr_html)
        past_public = self._extract_usernames(past_html)

        current_total = self._extract_total(html, CURRENT_COUNT_RE) or len(current_public)
        past_total = self._extract_total(html, PAST_COUNT_RE) or len(past_public)

        current_private = max(0, current_total - len(current_public))
        past_private = max(0, past_total - len(past_public))

        lines = [
            f"**Public sponsors for {SPONSORABLE}** (from visible page):",
            f"- Current sponsors: **{current_total}**  (public: **{len(current_public)}**, private: **{current_private}**)",
            f"- Past sponsors: **{past_total}**  (public: **{len(past_public)}**, private: **{past_private}**)",
            "",
            "**Current (public usernames):**",
        ]
        lines += [", ".join(current_public)] if current_public else ["—"]
        lines += ["", "**Past (public usernames):**"]
        lines += [", ".join(past_public)] if past_public else ["—"]
        lines += ["", "Only the sponsorable can verify private sponsors.", f"<{url}>"]

        await self._send_report(ctx, lines)

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, limit: int = 2000):
        """
        Cross-check guild members with the 'Sponsor' role against **public** sponsors (current ∪ past).
        Includes public/private counts derived from the page and matched/unmatched lists.
        Usage: [p]sponsorreport [limit-to-print]
        """
        limit = max(1, min(5000, limit))  # print limiter only

        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            mylogger.error(f"Sponsor role id {SPONSOR_ROLE_ID} not found in guild.")
            return await ctx.send(f"⚠️ Sponsor role not found (ID `{SPONSOR_ROLE_ID}`).")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        # Current/past public names
        curr_html, past_html = self._split_sections(html)
        current_public = self._extract_usernames(curr_html)
        past_public = self._extract_usernames(past_html)
        current_set = {u.lower() for u in current_public}
        past_set = {u.lower() for u in past_public}
        union_set = current_set | past_set

        # Totals from badges (fallback to len(public) if not found)
        current_total = self._extract_total(html, CURRENT_COUNT_RE) or len(current_public)
        past_total = self._extract_total(html, PAST_COUNT_RE) or len(past_public)
        current_public_n = len(current_public)
        past_public_n = len(past_public)

        current_private = max(0, current_total - current_public_n)
        past_private = max(0, past_total - past_public_n)

        public_union_n = len(union_set)
        private_union_n = current_private + past_private  # sections are disjoint on GH page

        members = list(role.members)
        matched_lines: list[str] = []
        unmatched_lines: list[str] = []
        matched_count = 0

        # Match ALL members; limit only affects printing
        for m in members:
            ksn = (m.display_name or "").strip()
            dsn = (m.name or "").strip()  # Discord username
            override = GH_USERNAME_MAP.get(m.id)
            candidates = self._gh_candidates_from_names(ksn, dsn, override)
            hit = next((c for c in candidates if c in union_set), None)

            if hit:
                matched_count += 1
                matched_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}**")
            else:
                unmatched_lines.append(f"- {ksn or '—'} (`{m.id}`)")

        # Unmatched vs GH totals (public + private)
        unmatched_union = max(0, (public_union_n + private_union_n) - matched_count)

        header = [
            f"**Current GH sponsors:** total **{current_total}**  (public **{current_public_n}**, private **{current_private}**)",
            f"**Past GH sponsors:** total **{past_total}**  (public **{past_public_n}**, private **{past_private}**)",
            f"**Public union (current ∪ past):** {public_union_n}",
            f"**Private union (current ∪ past):** {private_union_n}",
            f"**Discord users with Sponsor role:** {len(members)}",
            f"**Matched (server ↔ public):** {matched_count}",
            f"**Unmatched (server ↔ public or private):** {unmatched_union}",
            "",
            "_Notes: Public counts are exact. Private counts are derived as `total − public` per section. "
            "The 'Unmatched' value compares GitHub totals (public+private) to matched server members; "
            "it can exceed the number of Discord members due to private sponsors and/or name mismatches._",
            ""
        ]

        body: list[str] = []
        body.append("**Matched (server ↔ public):**")
        body.extend(matched_lines[:limit])
        if len(matched_lines) > limit:
            body.append(f"…and {len(matched_lines) - limit} more")
        body.append("")

        body.append("**Unmatched in public list (likely private or name mismatch):**")
        body.extend(unmatched_lines[:limit])
        if len(unmatched_lines) > limit:
            body.append(f"…and {len(unmatched_lines) - limit} more")
        body.append("")
        body.append("Only the sponsorable can verify private sponsors.")
        body.append(f"<{url}>")

        await self._send_report(ctx, header + body)

    # ---------------- Helpers ----------------

    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: str | None) -> list[str]:
        """
        Build GH username candidates from:
          - override (if provided)
          - DSN (Discord username) raw/normalized + digits-stripped + segment-tail
          - KSN (server display name) raw/normalized + digits-stripped + segment-tail
        Minimal variants to reflect ksn/dsn approach.
        """
        raw_pairs = [("override", override or ""), ("dsn", dsn or ""), ("ksn", ksn or "")]
        cands: list[str] = []

        for _, raw in raw_pairs:
            if not raw:
                continue
            base = self._norm(raw)
            if base:
                cands.append(base)
                # digits-stripped (e.g., bullmoose20 -> bullmoose)
                base_no_digits = re.sub(r"\d+$", "", base)
                if base_no_digits and base_no_digits != base:
                    cands.append(base_no_digits)

            # segment tail after separators (e.g., "Name | bullmoose20")
            for sep in SEP_CHARS:
                if sep in raw:
                    tail = raw.split(sep)[-1]
                    tailn = self._norm(tail)
                    if tailn:
                        cands.append(tailn)
                        tailn_no_digits = re.sub(r"\d+$", "", tailn)
                        if tailn_no_digits and tailn_no_digits != tailn:
                            cands.append(tailn_no_digits)

        # Deduplicate preserving order
        out: list[str] = []
        seen: set[str] = set()
        for c in cands:
            if c and c not in seen:
                out.append(c)
                seen.add(c)
        return out

    @staticmethod
    def _norm(s: str | None) -> str:
        if not s:
            return ""
        s = s.strip().lstrip("@").lower()
        # keep alnum and dash only (GH allows hyphen). Remove spaces, underscores, dots.
        s = s.replace(" ", "").replace("_", "").replace(".", "")
        return "".join(ch for ch in s if ch.isalnum() or ch == "-")

    def _typing_safely(self, ctx: commands.Context) -> None:
        try:
            if hasattr(ctx.channel, "trigger_typing"):
                self.bot.loop.create_task(ctx.channel.trigger_typing())
            else:
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
        """
        Try headings; otherwise treat whole page as "current" (union logic still catches all).
        """
        idx_current = self._find_any(html, ["Current sponsors", "Current Sponsors"])
        idx_past = self._find_any(html, ["Past sponsors", "Past Sponsors"])

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
            # Fallback: treat whole page as "current", past empty
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
    def _extract_total(html: str, regex: re.Pattern) -> int | None:
        m = regex.search(html or "")
        if not m:
            return None
        try:
            # strip commas just in case “1,234”
            return int(m.group(1).replace(",", ""))
        except Exception:
            return None

    @staticmethod
    def _find_any(haystack: str, needles: list[str]) -> int:
        for n in needles:
            i = haystack.find(n)
            if i != -1:
                return i
        return -1

    # ---------------- Output protection helpers ----------------

    def _chunk_lines(self, lines: list[str], max_len: int = 1800):
        """Split text into safe message chunks (aim < 2000 to leave buffer)."""
        buf = []
        size = 0
        for line in lines:
            if not line.endswith("\n"):
                line = line + "\n"
            if size + len(line) > max_len and buf:
                yield "".join(buf)
                buf, size = [line], len(line)
            else:
                buf.append(line)
                size += len(line)
        if buf:
            yield "".join(buf)

    async def _send_report(self, ctx: commands.Context, lines: list[str], header: str | None = None):
        """Safely send a possibly-large report: paginate or attach as .txt."""
        out_lines = []
        if header:
            out_lines.append(header)
            out_lines.append("")
        out_lines.extend(lines)

        chunks = list(self._chunk_lines(out_lines, max_len=1800))
        total_len = sum(len(c) for c in chunks)

        # If modest size, send as multiple messages
        if chunks and total_len <= 3800 and len(chunks) <= 2:
            for c in chunks:
                await ctx.send(c)
            return

        # For larger reports, either send multiple chunks or attach
        if len(chunks) > 5 or total_len > 6000:
            text = "".join(chunks)
            bio = BytesIO(text.encode("utf-8"))
            filename = f"sponsorreport_{ctx.guild.id}.txt"
            await ctx.send(
                "Report was large; attached as a file:",
                file=discord.File(bio, filename=filename),
            )
            return

        for c in chunks:
            await ctx.send(c)
