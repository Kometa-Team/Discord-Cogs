from __future__ import annotations

import logging
import os
import re
from io import BytesIO
from datetime import datetime, timezone

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

# ---------------- Sponsor role (guild role for supporters) ------------------
SPONSOR_ROLE_ID = 862041125706268702  # "Sponsor" role in your server

# ---------------- Optional overrides & verified-private list ----------------
# If a member's Discord identity differs from their GitHub username (public sponsor),
# you can override here: { discord_id: "github-username" }
GH_USERNAME_MAP: dict[int, str] = {}

# If you have off-platform confirmation that a Discord user is a *private* sponsor,
# list them here by Discord ID and/or Discord username (member.name). Case-insensitive for usernames.
# (Useful especially for "past private", which API may not expose.)
VERIFIED_PRIVATE_IDS: set[int] = set()
VERIFIED_PRIVATE_USERNAMES: set[str] = set()

# ---------------- GitHub Sponsor target & secrets ----------------
SPONSORABLE = "meisnate12"
SPONSORS_URL_FMT = "https://github.com/sponsors/{sponsorable}"

# Personal Access Token (PAT) file path; can also be provided via env var GITHUB_PAT
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"

# ---------------- HTML scraping helpers ----------------
ALT_USER_RE = re.compile(r'alt="@([A-Za-z0-9-]{1,39})"')
HREF_USER_RE = re.compile(r'href="/([A-Za-z0-9-]{1,39})"')
CURRENT_COUNT_RE = re.compile(r"Current\s*sponsors[^\d]*([0-9,]+)", re.IGNORECASE)
PAST_COUNT_RE = re.compile(r"Past\s*sponsors[^\d]*([0-9,]+)", re.IGNORECASE)

# Separators we treat as "Name SEP ghuser" → take last segment as candidate
SEP_CHARS = ("|", "·", "-", "—", ":", "/")

GRAPHQL_API = "https://api.github.com/graphql"


class SponsorCheck(commands.Cog):
    """GitHub sponsors tools: check/list public sponsors, and verify against a server Sponsor role."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: str | None = self._load_pat()

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
        Check if <username> appears as a sponsor of the target (current or past) on the public page.
        If not found, tries to resolve by matching a Sponsor-role member's Kometa Server Name (display name)
        to the provided string, then uses that member's Discord username (and variants).
        Usage: [p]sponsor <github-username or Kometa server name>
        """
        target = username.lstrip("@").strip()
        if not target:
            return await ctx.send("Please provide a GitHub username, e.g. `[p]sponsor bullmoose20`.")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        # Build union sets from public page (current & past)
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

        # 2) KSN→DSN resolution via Sponsor role (covers e.g., bullmoose → bullmoose20)
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
        return await ctx.send(
            f"❌ **{target}** is not listed as a **public** sponsor of **{SPONSORABLE}** (current or past).\n"
            "Only the sponsorable can verify private sponsors.\n"
            f"<{url}>"
        )

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """
        List **all visible** public sponsors from the page (current & past), and show private counts.
        If a PAT is configured, we still only *print names* for public sponsors, but counts are exact.
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
        Cross-check guild members with the 'Sponsor' role against **public** sponsors (current ∪ past)
        and, when configured, API-confirmed **current private** sponsors (via PAT).
        Also supports a manual allow-list for verified private (IDs/usernames).
        Usage: [p]sponsorreport [limit-to-print]
        """
        limit = max(1, min(5000, limit))  # print limiter only

        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            mylogger.error(f"Sponsor role id {SPONSOR_ROLE_ID} not found in guild.")
            return await ctx.send(f"⚠️ Sponsor role not found (ID `{SPONSOR_ROLE_ID}`).")

        url = SPONSORS_URL_FMT.format(sponsorable=SPONSORABLE)
        self._typing_safely(ctx)

        # ---- Fetch HTML for reliable *totals* & *past public* names
        try:
            html = await self._fetch(url)
        except Exception as e:
            mylogger.error(f"Error fetching sponsors page: {e}")
            return await ctx.send(f"⚠️ Could not reach GitHub Sponsors page: `{e}`")

        curr_html, past_html = self._split_sections(html)
        current_public = self._extract_usernames(curr_html)
        past_public = self._extract_usernames(past_html)
        current_public_set = {u.lower() for u in current_public}
        past_public_set = {u.lower() for u in past_public}

        current_total = self._extract_total(html, CURRENT_COUNT_RE) or len(current_public)
        past_total = self._extract_total(html, PAST_COUNT_RE) or len(past_public)

        # ---- If PAT, fetch CURRENT sponsors (active), including private identities
        api_current_public: set[str] = set()
        api_current_private: set[str] = set()
        if self._pat:
            try:
                api_current_public, api_current_private = await self._fetch_current_sponsors_via_api()
                mylogger.info(
                    f"API current sponsors -> public={len(api_current_public)} private={len(api_current_private)}"
                )
            except Exception as e:
                mylogger.error(f"GraphQL fetch failed (falling back to page only): {e}")

        # Build union for *public* usernames (current∪past) from page
        public_union_set = current_public_set | past_public_set
        public_union_n = len(public_union_set)

        # Private counts (from badges) are exact per section; identities for current private may be known via API
        current_private_count = max(0, current_total - len(current_public))
        past_private_count = max(0, past_total - len(past_public))
        private_union_n = current_private_count + past_private_count  # sections disjoint on GH page

        members = list(role.members)
        matched_public_lines: list[str] = []
        matched_private_lines: list[str] = []  # API-confirmed private + manual allow-list
        unmatched_lines: list[str] = []
        matched_public_count = 0
        matched_private_count = 0

        # Manual verified-private lookups
        verified_usernames = {u.lower() for u in VERIFIED_PRIVATE_USERNAMES}
        # Also resolve any verified usernames to IDs (best effort)
        verified_expected_ids = set(VERIFIED_PRIVATE_IDS)
        for gm in ctx.guild.members:
            if gm.name.lower() in verified_usernames:
                verified_expected_ids.add(gm.id)

        # Build set of API-confirmed current private GH logins (lowercase)
        api_private_logins = {u.lower() for u in api_current_private}
        api_public_logins = {u.lower() for u in api_current_public}

        # Match ALL members; limit only affects printing
        for m in members:
            ksn = (m.display_name or "").strip()
            dsn = (m.name or "").strip()
            override = GH_USERNAME_MAP.get(m.id)
            candidates = self._gh_candidates_from_names(ksn, dsn, override)

            # First try public union (page)
            hit_public = next((c for c in candidates if c in public_union_set), None)
            if hit_public:
                matched_public_count += 1
                matched_public_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}**")
                continue

            # Then try API-confirmed current private (if available)
            hit_private_api = next((c for c in candidates if c in api_private_logins),
                                   None) if api_private_logins else None
            if hit_private_api:
                matched_private_count += 1
                matched_private_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}** (verified private via API)")
                continue

            # Then manual allow-list (IDs/usernames)
            if (m.id in VERIFIED_PRIVATE_IDS) or (dsn.lower() in verified_usernames):
                matched_private_count += 1
                matched_private_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}** (verified private)")
            else:
                unmatched_lines.append(f"- {ksn or '—'} (`{m.id}`)")

        # Verified-private who **don’t** currently have the Sponsor role (helpful for role hygiene)
        role_member_ids = {m.id for m in members}
        missing_role_verified: list[str] = []
        for vid in verified_expected_ids:
            if vid not in role_member_ids:
                user = ctx.guild.get_member(vid)
                if user is not None:
                    missing_role_verified.append(f"- {user.display_name or user.name} (`{user.id}`)")
                else:
                    missing_role_verified.append(f"- <Unknown user id `{vid}`>")

        # “Matched (server ↔ public)” = matched_public_count
        # “Unmatched (server ↔ public or private)” per your union math (GitHub totals vs matched public):
        unmatched_union = max(0, (public_union_n + private_union_n) - matched_public_count)

        header = [
            f"**Current GH sponsors:** total **{current_total}**  (public **{len(current_public)}**, private **{current_private_count}**)",
            f"**Past GH sponsors:** total **{past_total}**  (public **{len(past_public)}**, private **{past_private_count}**)",
            f"**Public union (current ∪ past):** {public_union_n}",
            f"**Private union (current ∪ past):** {private_union_n}",
            f"**Discord users with Sponsor role:** {len(members)}",
            f"**Matched (server ↔ public):** {matched_public_count}",
            f"**Matched (server ↔ verified private):** {matched_private_count}",
            f"**Unmatched (server ↔ public or private):** {unmatched_union}",
            "",
            "_Notes: Public counts are exact. Private counts are derived as `total − public` per section. "
            "“Matched verified private” includes API-confirmed current private sponsors (via PAT) and any entries "
            "in your manual allow-list. “Unmatched” compares GitHub totals (public+private) to matched server members; "
            "it can exceed the number of Discord members due to private sponsors and/or name mismatches._",
            ""
        ]

        body: list[str] = []
        body.append("**Matched (server ↔ public):**")
        body.extend(matched_public_lines[:limit])
        if len(matched_public_lines) > limit:
            body.append(f"…and {len(matched_public_lines) - limit} more")
        body.append("")

        body.append("**Matched (server ↔ verified private):**")
        body.extend(matched_private_lines[:limit])
        if len(matched_private_lines) > limit:
            body.append(f"…and {len(matched_private_lines) - limit} more")
        body.append("")

        body.append("**Unmatched in public list (likely private or name mismatch, and not in verified list):**")
        body.extend(unmatched_lines[:limit])
        if len(unmatched_lines) > limit:
            body.append(f"…and {len(unmatched_lines) - limit} more")
        body.append("")

        if missing_role_verified:
            body.append("**Verified-private list but missing the Sponsor role:**")
            body.extend(missing_role_verified[:limit])
            if len(missing_role_verified) > limit:
                body.append(f"…and {len(missing_role_verified) - limit} more")
            body.append("")

        body.append("Only the sponsorable can verify private sponsors.")
        body.append(f"<{url}>")

        await self._send_report(ctx, header + body)

    # ---------------- Helpers: PAT, API, HTML, matching ----------------

    def _load_pat(self) -> str | None:
        """Load PAT from file or env. Never log the token value."""
        # Env wins if present
        pat = os.environ.get("GITHUB_PAT")
        if pat:
            mylogger.info("Loaded GitHub PAT from environment.")
            return pat.strip()

        try:
            with open(PAT_FILE, "r", encoding="utf-8") as f:
                pat = f.read().strip()
            if pat:
                mylogger.info(f"Loaded GitHub PAT from file: {PAT_FILE}")
                return pat
        except FileNotFoundError:
            mylogger.info(f"No PAT file found at {PAT_FILE}; API features disabled.")
        except Exception as e:
            mylogger.error(f"Failed to read PAT file ({PAT_FILE}): {e}")
        return None

    async def _fetch_current_sponsors_via_api(self) -> tuple[set[str], set[str]]:
        """
        Returns (public_logins, private_logins) for *current (active)* sponsorships
        of SPONSORABLE. Requires PAT with 'read:org'/'sponsors' access (GitHub Apps or classic).
        """
        if not self._pat:
            raise RuntimeError("PAT not configured")

        # GraphQL query for active sponsorships (as maintainer)
        query = """
        query($login:String!, $first:Int!, $after:String) {
          user(login: $login) {
            sponsorshipsAsMaintainer(includePrivate: true, activeOnly: true, first: $first, after: $after) {
              pageInfo { hasNextPage endCursor }
              nodes {
                privacyLevel
                sponsorEntity {
                  ... on User { login }
                  ... on Organization { login }
                }
              }
            }
          }
        }
        """

        variables = {"login": SPONSORABLE, "first": 100, "after": None}
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Content-Type": "application/json",
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa-Team)",
        }

        public_logins: set[str] = set()
        private_logins: set[str] = set()

        async with aiohttp.ClientSession(headers=headers) as session:
            while True:
                async with session.post(GRAPHQL_API, json={"query": query, "variables": variables}) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(f"GraphQL HTTP {resp.status}: {text}")
                    data = await resp.json()

                try:
                    sp = data["data"]["user"]["sponsorshipsAsMaintainer"]
                except Exception:
                    raise RuntimeError(f"Unexpected GraphQL response: {data}")

                for n in sp.get("nodes", []):
                    sponsor = (n.get("sponsorEntity") or {}).get("login")
                    privacy = (n.get("privacyLevel") or "").upper()
                    if not sponsor:
                        continue
                    if privacy == "PRIVATE":
                        private_logins.add(sponsor)
                    else:
                        public_logins.add(sponsor)

                page = sp.get("pageInfo", {})
                if page.get("hasNextPage"):
                    variables["after"] = page.get("endCursor")
                else:
                    break

        return public_logins, private_logins

    async def _fetch(self, url: str) -> str:
        timeout = aiohttp.ClientTimeout(total=20)
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

    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: str | None) -> list[str]:
        """
        Build GH username candidates from:
          - override (if provided)
          - DSN (Discord username) raw/normalized + digits-stripped + segment-tail
          - KSN (server display name) raw/normalized + digits-stripped + segment-tail
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
        """Safely send a possibly-large report: paginate or attach as a timestamped .txt."""
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
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"sponsorreport_{ctx.guild.id}_{ts}.txt"
            await ctx.send(
                "Report was large; attached as a file:",
                file=discord.File(bio, filename=filename),
            )
            return

        for c in chunks:
            await ctx.send(c)
