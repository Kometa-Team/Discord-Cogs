from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional, Set, Tuple, Dict, List

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

# ---------------- Optional overrides ----------------
# If a member's Discord identity differs from their public GitHub username,
# you can override here: { discord_id: "github-username" } (used for public matching only)
GH_USERNAME_MAP: Dict[int, str] = {}

# Optional manual allow-list for private sponsors (as an extra backstop).
VERIFIED_PRIVATE_IDS: Set[int] = set()
VERIFIED_PRIVATE_USERNAMES: Set[str] = set()  # member.name, lowercase compared

# ---------------- GitHub GraphQL ----------------
SPONSORABLE = "meisnate12"
GRAPHQL_API = "https://api.github.com/graphql"
# Read PAT from env or file. Env has priority.
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"


class SponsorCheck(commands.Cog):
    """GitHub sponsors tools via the GraphQL API (no scraping)."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: Optional[str] = self._load_pat()

    # ---------------- Role gate for all commands ----------------
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
        Check if <username> appears as a sponsor (current or past).
        If not found, try resolving a Sponsor-role member's display name -> Discord username -> GH candidates.
        For privacy: if the hit is PRIVATE, we confirm sponsorship without revealing private info.
        Usage: [p]sponsor <github-username or Kometa server name>
        """
        if not self._pat:
            return await self._send_pat_error(ctx)

        target = (username or "").lstrip("@").strip()
        if not target:
            return await ctx.send("Please provide a username, e.g. `[p]sponsor bullmoose20`.")

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            mylogger.error(f"PAT auth error: {e.code} {e.detail}")
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("Unexpected GitHub API error in sponsor()")
            return await ctx.send(f"⚠️ GitHub API error: `{e}`")

        # union for public; we will *check* private but avoid printing names if it's a private hit
        public_union = {u.lower() for u in (curr_pub | past_pub)}
        private_union = {u.lower() for u in (curr_priv | past_priv)}
        t = target.lower()

        # direct GH username check
        if t in public_union:
            status = "current" if t in {x.lower() for x in curr_pub} else "past"
            return await ctx.send(f"✅ **{target}** is a **{status}** public sponsor of **{SPONSORABLE}**.")

        if t in private_union:
            status = "current" if t in {x.lower() for x in curr_priv} else "past"
            return await ctx.send(
                f"✅ **{target}** is a **{status}** sponsor of **{SPONSORABLE}** (marked **private** on GitHub)."
            )

        # KSN→DSN via Sponsor role → GH candidates
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if role:
            m = next((mem for mem in role.members if (mem.display_name or "").strip().lower() == t), None)
            if m:
                ksn = (m.display_name or "").strip()
                dsn = (m.name or "").strip()
                candidates = self._gh_candidates_from_names(ksn, dsn, GH_USERNAME_MAP.get(m.id))

                # public first
                hit_public = next((c for c in candidates if c.lower() in public_union), None)
                if hit_public:
                    status = "current" if hit_public.lower() in {x.lower() for x in curr_pub} else "past"
                    return await ctx.send(
                        f"✅ **{ksn}** → **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**.")

                # then private (confirm without leaking anything extra)
                hit_private = next((c for c in candidates if c.lower() in private_union), None)
                if hit_private:
                    status = "current" if hit_private.lower() in {x.lower() for x in curr_priv} else "past"
                    return await ctx.send(
                        f"✅ **{ksn}** → **{dsn}** → **{status}** sponsor of **{SPONSORABLE}** (marked **private**)."
                    )

        return await ctx.send(
            f"❌ **{target}** does not appear as a sponsor of **{SPONSORABLE}** (current or past)."
        )

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """
        List all *public* sponsors (current & past) from the API,
        and show private counts (we never list private usernames).
        Usage: [p]sponsorlist
        """
        if not self._pat:
            return await self._send_pat_error(ctx)

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            mylogger.error(f"PAT auth error: {e.code} {e.detail}")
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("Unexpected GitHub API error in sponsorlist()")
            return await ctx.send(f"⚠️ GitHub API error: `{e}`")

        lines: List[str] = []
        lines.append(f"**Public sponsors for {SPONSORABLE}** (from GitHub API):")
        lines.append(
            f"- Current sponsors: **{len(curr_pub) + len(curr_priv)}**  (public: **{len(curr_pub)}**, private: **{len(curr_priv)}**)")
        lines.append(
            f"- Past sponsors: **{len(past_pub) + len(past_priv)}**  (public: **{len(past_pub)}**, private: **{len(past_priv)}**)")
        lines.append("")
        lines.append("**Current (public usernames):**")
        lines.append(", ".join(sorted(curr_pub, key=str.lower)) if curr_pub else "—")
        lines.append("")
        lines.append("**Past (public usernames):**")
        lines.append(", ".join(sorted(past_pub, key=str.lower)) if past_pub else "—")
        lines.append("")
        lines.append("Private sponsors are intentionally not listed by name.")

        await self._send_report(ctx, lines)

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, limit: int = 2000):
        """
        Cross-check guild members with the 'Sponsor' role against:
          - API public sponsors (current ∪ past)
          - API private sponsors (current ∪ past) — counted, used for matching, not printed
          - Manual verified-private allow-list (IDs/usernames) as backstop
        Usage: [p]sponsorreport [limit-to-print]
        """
        if not self._pat:
            return await self._send_pat_error(ctx)

        limit = max(1, min(5000, limit))

        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            mylogger.error(f"Sponsor role id {SPONSOR_ROLE_ID} not found in guild.")
            return await ctx.send(f"⚠️ Sponsor role not found (ID `{SPONSOR_ROLE_ID}`).")

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            mylogger.error(f"PAT auth error: {e.code} {e.detail}")
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("Unexpected GitHub API error in sponsorreport()")
            return await ctx.send(f"⚠️ GitHub API error: `{e}`")

        # Unions and counts
        public_union = {u.lower() for u in (curr_pub | past_pub)}
        private_union = {u.lower() for u in (curr_priv | past_priv)}
        public_union_n = len(public_union)
        private_union_n = len(private_union)

        # Counts per section
        current_total = len(curr_pub) + len(curr_priv)
        past_total = len(past_pub) + len(past_priv)

        members = list(role.members)
        matched_public_lines: List[str] = []
        matched_private_lines: List[str] = []
        unmatched_lines: List[str] = []
        matched_public_count = 0
        matched_private_count = 0

        verified_usernames = {u.lower() for u in VERIFIED_PRIVATE_USERNAMES}
        # Add any verified usernames we can resolve to IDs:
        verified_expected_ids = set(VERIFIED_PRIVATE_IDS)
        for gm in ctx.guild.members:
            if gm.name.lower() in verified_usernames:
                verified_expected_ids.add(gm.id)

        for m in members:
            ksn = (m.display_name or "").strip()
            dsn = (m.name or "").strip()
            override = GH_USERNAME_MAP.get(m.id)

            for cand in self._gh_candidates_from_names(ksn, dsn, override):
                lc = cand.lower()
                if lc in public_union:
                    matched_public_count += 1
                    matched_public_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}**")
                    break
                if lc in private_union or (m.id in VERIFIED_PRIVATE_IDS) or (dsn.lower() in verified_usernames):
                    matched_private_count += 1
                    reason = "API" if lc in private_union else "verified"
                    matched_private_lines.append(f"- {ksn or '—'} (`{m.id}`) → **{dsn or '—'}** (private via {reason})")
                    break
            else:
                unmatched_lines.append(f"- {ksn or '—'} (`{m.id}`)")

        # Verified-private missing the Sponsor role
        role_member_ids = {m.id for m in members}
        missing_role_verified: List[str] = []
        for vid in verified_expected_ids:
            if vid not in role_member_ids:
                user = ctx.guild.get_member(vid)
                if user is not None:
                    missing_role_verified.append(f"- {user.display_name or user.name} (`{user.id}`)")
                else:
                    missing_role_verified.append(f"- <Unknown user id `{vid}`>")

        # Header math exactly per your spec:
        # Unmatched (server ↔ public or private) = (public_union + private_union) − matched_public
        unmatched_union = max(0, (public_union_n + private_union_n) - matched_public_count)

        header = [
            f"**Current GH sponsors:** total **{current_total}**  (public **{len(curr_pub)}**, private **{len(curr_priv)}**)",
            f"**Past GH sponsors:** total **{len(past_pub) + len(past_priv)}**  (public **{len(past_pub)}**, private **{len(past_priv)}**)",
            f"**Public union (current ∪ past):** {public_union_n}",
            f"**Private union (current ∪ past):** {private_union_n}",
            f"**Discord users with Sponsor role:** {len(members)}",
            f"**Matched (server ↔ public):** {matched_public_count}",
            f"**Matched (server ↔ verified private):** {matched_private_count}",
            f"**Unmatched (server ↔ public or private):** {unmatched_union}",
            "",
            "_Notes: Public counts are exact. Private sponsors are fetched with your PAT and used for matching, "
            "but their identities are not printed. The ‘Unmatched’ value compares GitHub totals (public+private) "
            "to matched server members; it can exceed the number of Discord members due to private sponsors and/or "
            "name mismatches._",
            ""
        ]

        body: List[str] = []
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

        await self._send_report(ctx, header + body)

    # ---------------- GitHub API helpers ----------------

    def _load_pat(self) -> Optional[str]:
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
            mylogger.warning("No GitHub PAT found: set GITHUB_PAT or create PAT file.")
        except Exception as e:
            mylogger.error(f"Failed to read PAT file: {e}")
        return None

    async def _fetch_all_sponsors(self) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """
        Return (current_public, current_private, past_public, past_private).
        Uses GraphQL with includePrivate:true, activeOnly:false and paginates to exhaustion.
        """
        if not self._pat:
            raise GitHubAuthError("missing_pat", "GitHub token not configured")

        query = """
        query($login:String!, $first:Int!, $after:String) {
          user(login: $login) {
            sponsorshipsAsMaintainer(includePrivate: true, activeOnly: false, first: $first, after: $after) {
              pageInfo { hasNextPage endCursor }
              nodes {
                privacyLevel
                isActive
                sponsorEntity {
                  ... on User { login }
                  ... on Organization { login }
                }
              }
            }
          }
        }
        """

        vars = {"login": SPONSORABLE, "first": 100, "after": None}
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Content-Type": "application/json",
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa-Team)",
        }

        curr_pub: Set[str] = set()
        curr_priv: Set[str] = set()
        past_pub: Set[str] = set()
        past_priv: Set[str] = set()

        async with aiohttp.ClientSession(headers=headers) as session:
            while True:
                async with session.post(GRAPHQL_API, json={"query": query, "variables": vars}) as resp:
                    status = resp.status
                    text = await resp.text()

                    # Handle coarse HTTP errors with useful messages
                    if status == 401:
                        raise GitHubAuthError("unauthorized", "Bad credentials (token invalid/expired/revoked).")
                    if status == 403:
                        raise GitHubAuthError("forbidden", "Permission denied (missing 'Sponsors' scope or access).")
                    if status >= 400:
                        raise GitHubAuthError("http_error", f"HTTP {status}: {text[:200]}")

                    data = await resp.json()

                # GraphQL-level errors (valid HTTP but auth/scopes/etc failed)
                if "errors" in data and data["errors"]:
                    msg = "; ".join(err.get("message", "unknown") for err in data["errors"])
                    # Common GraphQL auth-ish messages
                    if "Bad credentials" in msg:
                        raise GitHubAuthError("unauthorized", "Bad credentials (token invalid/expired/revoked).")
                    if "Resource not accessible by integration" in msg or "Insufficient scopes" in msg:
                        raise GitHubAuthError("forbidden", "Insufficient scopes for Sponsors API.")
                    raise GitHubAuthError("graphql_error", msg[:300])

                try:
                    conn = data["data"]["user"]["sponsorshipsAsMaintainer"]
                except Exception:
                    raise GitHubAuthError("schema_error", f"Unexpected response schema: {str(data)[:200]}")

                for n in conn.get("nodes", []):
                    sponsor = ((n.get("sponsorEntity") or {}).get("login") or "").strip()
                    if not sponsor:
                        continue
                    priv = (n.get("privacyLevel") or "").upper()
                    is_active = bool(n.get("isActive"))

                    if is_active:
                        (curr_priv if priv == "PRIVATE" else curr_pub).add(sponsor)
                    else:
                        (past_priv if priv == "PRIVATE" else past_pub).add(sponsor)

                page = conn.get("pageInfo", {})
                if page.get("hasNextPage"):
                    vars["after"] = page.get("endCursor")
                else:
                    break

        return curr_pub, curr_priv, past_pub, past_priv

    # ---------------- Local matching helpers ----------------

    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: Optional[str]) -> List[str]:
        """
        Build GH username candidates from:
          - override (if provided)
          - DSN (Discord username)
          - KSN (server display name)
        """

        def norm(s: Optional[str]) -> str:
            if not s:
                return ""
            s = s.strip().lstrip("@").lower()
            s = s.replace(" ", "").replace("_", "").replace(".", "")
            return "".join(ch for ch in s if ch.isalnum() or ch == "-")

        cands: List[str] = []
        raw = [override or "", dsn or "", ksn or ""]
        for r in raw:
            base = norm(r)
            if base and base not in cands:
                cands.append(base)
            # digits-stripped tail (e.g., "bullmoose20" -> "bullmoose")
            if base:
                stripped = base.rstrip("0123456789")
                if stripped and stripped != base and stripped not in cands:
                    cands.append(stripped)
            # tail after separators
            for sep in ("|", "·", "-", "—", ":", "/"):
                if sep in r:
                    tail = norm(r.split(sep)[-1])
                    if tail and tail not in cands:
                        cands.append(tail)
                    if tail:
                        stripped_tail = tail.rstrip("0123456789")
                        if stripped_tail and stripped_tail != tail and stripped_tail not in cands:
                            cands.append(stripped_tail)
        return cands

    # ---------------- Output helpers ----------------

    async def _send_report(self, ctx: commands.Context, lines: List[str], header: Optional[str] = None):
        """Safely send a possibly-large report: paginate or attach as a timestamped .txt."""
        out_lines: List[str] = []
        if header:
            out_lines.append(header)
            out_lines.append("")
        out_lines.extend(lines)

        # Chunk to stay well under 2000 char per message; try 1800 buffer.
        chunks: List[str] = []
        buf = ""
        for line in out_lines:
            line = (line if line.endswith("\n") else line + "\n")
            if len(buf) + len(line) > 1800:
                chunks.append(buf)
                buf = line
            else:
                buf += line
        if buf:
            chunks.append(buf)

        total_len = sum(len(c) for c in chunks)

        # Small: just send
        if total_len <= 3800 and len(chunks) <= 2:
            for c in chunks:
                await ctx.send(c)
            return

        # Large: attach as file (timestamped)
        text = "".join(chunks)
        bio = BytesIO(text.encode("utf-8"))
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"sponsorreport_{ctx.guild.id}_{ts}.txt"
        await ctx.send("Report was large; attached as a file:", file=discord.File(bio, filename=filename))

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

    async def _send_pat_error(self, ctx: commands.Context):
        return await ctx.send(
            "⚠️ GitHub token not configured. Set env `GITHUB_PAT` or create the file "
            f"`{PAT_FILE}` with a valid PAT that has access to Sponsors."
        )

    async def _send_pat_auth_message(self, ctx: commands.Context, e: "GitHubAuthError"):
        readable = {
            "missing_pat": "GitHub token not configured.",
            "unauthorized": "Bad credentials (token invalid/expired/revoked).",
            "forbidden": "Insufficient scopes or access to Sponsors API.",
            "http_error": f"HTTP error from GitHub: {e.detail}",
            "graphql_error": f"GraphQL error: {e.detail}",
            "schema_error": f"Unexpected API response.",
        }.get(e.code, f"GitHub API error: {e.detail}")
        return await ctx.send(f"⚠️ {readable}")


class GitHubAuthError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail
