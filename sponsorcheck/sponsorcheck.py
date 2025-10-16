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
# Headings with counts e.g., "Current sponsors 66" / "Past sponsors 206"
CURRENT_COUNT_RE = re.compile(r"Current\s+sponsors\s+(\d+)", re.IGNORECASE)
PAST_COUNT_RE = re.compile(r"Past\s+sponsors\s+(\d+)", re.IGNORECASE)

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
            return await self._send_report(ctx, [
                f"✅ **{target}** is a **current** public sponsor of **{SPONSORABLE}**.",
                f"<{url}>",
            ])
        if t_low in past_users:
            mylogger.info(f"Result: {target} is a PAST public sponsor of {SPONSORABLE}.")
            return await self._send_report(ctx, [
                f"ℹ️ **{target}** is a **past** public sponsor of **{SPONSORABLE}**.",
                f"<{url}>",
            ])

        mylogger.info(f"Result: {target} not found as PUBLIC sponsor (private sponsors not visible).")
        return await self._send_report(ctx, [
            f"❌ **{target}** is not listed as a **public** sponsor of **{SPONSORABLE}**.",
            "(Private sponsors won’t appear on the public page.)",
            f"<{url}>",
        ])

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
        await self._send_report(ctx, [
            f"**{SPONSORABLE}** sponsors (public page):",
            f"- Current: **{current_count}**",
            f"- Past: **{past_count}**",
            f"<{url}>",
        ])

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context, which: str = "both", limit: int = 30):
        """
        List public sponsors (usernames) from the visible page.

        Usage:
          [p]sponsorlist                -> both (up to 30 each)
          [p]sponsorlist current 50     -> current only (50)
          [p]sponsorlist past 20        -> past only (20)
          [p]sponsorlist both 15        -> both, 15 each
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

        lines = [f"Public sponsors for **{SPONSORABLE}** (from visible page):"]
        if which in ("current", "both"):
            chunk = ", ".join(current_users[:limit]) if current_users else "—"
            lines.append(f"**Current** ({len(current_users)} shown): {chunk}")
        if which in ("past", "both"):
            chunk = ", ".join(past_users[:limit]) if past_users else "—"
            lines.append(f"**Past** ({len(past_users)} shown): {chunk}")
        if which not in ("current", "past", "both"):
            return await ctx.send("Please use `current`, `past`, or `both`.")
        lines.append(f"<{url}>")

        mylogger.info(f"sponsorlist {which} limit={limit} -> currents={len(current_users)} pasts={len(past_users)}")
        await self._send_report(ctx, lines)

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, which: str = "current", limit: int = 100):
        """
        Cross-check guild members with the 'Sponsor' role against the public sponsor list.

        Prints one line per member as:
          - ksn=<Kometa server name>  dsn=<Discord username>  ghn=<GitHub username|—>  status=<current|past|not found>

        Usage:
          [p]sponsorreport              -> compare 'current' (default)
          [p]sponsorreport past         -> compare against public past sponsors
          [p]sponsorreport both         -> compare against current+past (union)
          [p]sponsorreport current 200  -> raise display cap (1..500)

        Notes:
        - Only *public* sponsors appear on the page (private sponsors won't).
        - We check both KSN (server display name) and DSN (Discord username),
          plus minimal variants (digits-stripped and segment-tail).
          You can override per member via GH_USERNAME_MAP.
        """
        which = which.lower()
        limit = max(1, min(500, limit))

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

        # Build current/past sets and a case map for nice display of GHN
        html_current, html_past = self._split_sections(html)
        current_list = self._extract_usernames(html_current)
        past_list = self._extract_usernames(html_past)
        current_set = {u.lower() for u in current_list}
        past_set = {u.lower() for u in past_list}
        case_map = {u.lower(): u for u in (current_list + past_list)}

        if which == "current":
            ref_set = current_set
        elif which == "past":
            ref_set = past_set
        elif which == "both":
            ref_set = current_set | past_set
        else:
            return await ctx.send("Please use `current`, `past`, or `both`.")

        members = list(role.members)
        mylogger.info(f"sponsorreport {which}: role='{role.name}' members={len(members)} ref={len(ref_set)}")

        lines: list[str] = []
        matched = 0
        matched_current = 0
        matched_past = 0

        for m in members[:limit]:
            ksn_raw = (m.display_name or "").strip()
            dsn_raw = (m.name or "").strip()
            override = GH_USERNAME_MAP.get(m.id)

            candidates = self._gh_candidates_from_names(ksn_raw, dsn_raw, override)
            mylogger.debug(f"KSN/DSN candidates for {m.id} -> {candidates}")

            hit = next((c for c in candidates if c in ref_set), None)

            if hit:
                matched += 1
                is_current = hit in current_set
                is_past = hit in past_set
                if is_current:
                    matched_current += 1
                if is_past:
                    matched_past += 1

                ghn_display = case_map.get(hit, hit)
                status = "current" if is_current else ("past" if is_past else "found")
                lines.append(
                    f"- ksn={ksn_raw or '—'}  dsn={dsn_raw or '—'}  ghn={ghn_display}  status={status}"
                )
            else:
                lines.append(
                    f"- ksn={ksn_raw or '—'}  dsn={dsn_raw or '—'}  ghn=—  status=not found (maybe private or mismatch)"
                )

        header = [
            f"**Sponsor role:** {role.mention}  —  **Members scanned:** {min(len(members), limit)} / {len(members)}",
            (f"**Public sponsors (union current/past):** {len(ref_set)}"
             if which == "both" else
             f"**Public {which} sponsors:** {len(ref_set)}"),
            f"**Matches:** total={matched}  current={matched_current}  past={matched_past}",
            f"<{url}>",
            ""
        ]

        await self._send_report(ctx, header + lines)

    # ---------------- Helpers ----------------

    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: str | None) -> list[str]:
        """
        Build GH username candidates from:
          - override (if provided)
          - DSN (Discord username) raw/normalized + digits-stripped + segment-tail
          - KSN (server display name) raw/normalized + digits-stripped + segment-tail
        Only minimal, targeted variants to reflect your ksn/dsn idea.
        """
        raw_pairs = [("override", override or ""), ("dsn", dsn or ""), ("ksn", ksn or "")]
        cands: list[str] = []

        for label, raw in raw_pairs:
            if not raw:
                continue
            base = self._norm(raw)
            if base:
                cands.append(base)
                # digits-stripped tail (e.g., bullmoose20 -> bullmoose)
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
                # discord.py 1.x/2.x channel method
                self.bot.loop.create_task(ctx.channel.trigger_typing())
            else:
                # fallback context manager
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
