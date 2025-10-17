from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional, Set, Tuple, Dict, List

import aiohttp
import discord
from redbot.core import commands

# ---------------- Logging ----------------
mylogger = logging.getLogger("sponsorcheck")
mylogger.setLevel(logging.DEBUG)

# ---------------- Access control ----------------
ALLOWED_ROLE_IDS = {
    929756550380286153,  # Moderator
    929900016531828797,  # Kometa Masters
    981499667722424390,  # Kometa Apprentices
}
SPONSOR_ROLE_ID = 862041125706268702  # Discord "Sponsor" role

# ---------------- Optional overrides / allow-lists ----------------
GH_USERNAME_MAP: Dict[int, str] = {}  # { discord_id: "github-username" } (public match helper)
VERIFIED_PRIVATE_IDS: Set[int] = set()  # Discord IDs you've verified as private sponsors
VERIFIED_PRIVATE_USERNAMES: Set[str] = set()  # Discord usernames (member.name), lowercase-checked

# ---------------- GitHub GraphQL ----------------
SPONSORABLE = "meisnate12"
GRAPHQL_API = "https://api.github.com/graphql"
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"  # fallback if env is not set


class SponsorCheck(commands.Cog):
    """GitHub Sponsors via GraphQL API (no scraping)."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: Optional[str] = None
        self._pat_source: Optional[str] = None  # "env" | "file" | None
        self._load_pat(initial=True)

    # ---------------- Gate all commands ----------------
    async def cog_check(self, ctx: commands.Context) -> bool:
        if not ctx.guild:
            mylogger.info("Blocked: command used in DM.")
            return False

        author = f"{ctx.author.name}#{ctx.author.discriminator}"
        mylogger.info(
            f"SponsorCheck invoked by {author} in {ctx.guild.name}/{getattr(ctx.channel, 'name', 'DM')} "
            f"(IDs: {ctx.guild.id}/{ctx.channel.id})"
        )

        user_role_ids = {r.id for r in ctx.author.roles}
        if (ALLOWED_ROLE_IDS & user_role_ids) or ctx.author.guild_permissions.manage_guild:
            mylogger.debug(f"Access granted. user_roles={list(user_role_ids)}")
            return True

        mylogger.info(f"Access denied. Needs one of {list(ALLOWED_ROLE_IDS)}.")
        return False

    # ---------------- Owner token tools ----------------
    @commands.group(name="sponsortoken", invoke_without_command=True)
    @commands.is_owner()
    async def sponsortoken(self, ctx: commands.Context):
        """Owner: manage/view GitHub PAT status."""
        await ctx.send("Subcommands: `check`, `reload`, `where`")

    @sponsortoken.command(name="check")
    @commands.is_owner()
    async def sponsortoken_check(self, ctx: commands.Context):
        self._ensure_pat()
        if not self._pat:
            await ctx.send(
                "❌ No GitHub PAT loaded. Set env `GITHUB_PAT` or create the file at the path in `[p]sponsortoken where`.")
            return
        masked = self._mask(self._pat)
        await ctx.send(f"✅ PAT is loaded from **{self._pat_source}**. Token (masked): `{masked}`")

    @sponsortoken.command(name="reload")
    @commands.is_owner()
    async def sponsortoken_reload(self, ctx: commands.Context):
        self._load_pat(initial=False, force=True)
        if self._pat:
            await ctx.send(f"🔁 Reloaded PAT from **{self._pat_source}**. (Use `[p]sponsortoken check` to verify.)")
        else:
            await ctx.send(
                "❌ Reload attempted but no PAT found. If you set an env var, you must restart the bot process.")

    @sponsortoken.command(name="where")
    @commands.is_owner()
    async def sponsortoken_where(self, ctx: commands.Context):
        await ctx.send(f"Looking for PAT in env `GITHUB_PAT` **or** the file: `{PAT_FILE}`")

    # ---------------- Commands ----------------
    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """
        Check a username (GitHub or Kometa display name) for sponsorship (current or past).
        If matched via private sponsorship, we confirm without revealing private info.
        """
        self._ensure_pat()
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

        # Build sets
        current_public = {u.lower() for u in curr_pub}
        past_public = {u.lower() for u in past_pub}
        current_private = {u.lower() for u in curr_priv}
        past_private = {u.lower() for u in past_priv}

        union_public = current_public | past_public
        union_private = current_private | past_private
        t = target.lower()

        # Direct GH login match
        if t in union_public:
            status = "current" if t in current_public else "past"
            return await ctx.send(f"✅ **{target}** is a **{status}** public sponsor of **{SPONSORABLE}**.")
        if t in union_private:
            status = "current" if t in current_private else "past"
            return await ctx.send(
                f"✅ **{target}** is a **{status}** sponsor of **{SPONSORABLE}** (marked **private**).")

        # KSN→DSN via Sponsor role
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if role:
            # try to resolve Kometa Server Name (display_name)
            m = next((mem for mem in role.members if (mem.display_name or "").strip().lower() == t), None)
            if m:
                ksn = (m.display_name or "").strip()
                dsn = (m.name or "").strip()
                override = GH_USERNAME_MAP.get(m.id)
                candidates = self._gh_candidates_from_names(ksn, dsn, override)

                # public first
                for cand in candidates:
                    lc = cand.lower()
                    if lc in union_public:
                        status = "current" if lc in current_public else "past"
                        return await ctx.send(
                            f"✅ **{ksn}** → **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**."
                        )
                # private next (consistent ending)
                for cand in candidates:
                    lc = cand.lower()
                    if lc in union_private:
                        status = "current" if lc in current_private else "past"
                        return await ctx.send(
                            f"✅ **{ksn}** → **{dsn}** → **{status}** sponsor of **{SPONSORABLE}** (marked **private**)."
                        )

        return await ctx.send(f"❌ **{target}** does not appear as a sponsor of **{SPONSORABLE}** (current or past).")

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """
        List all *public* sponsors (current & past) and show private counts (no private names printed).
        Large outputs attach as 'sponsorlist_<guild>_<timestamp>.txt'.
        """
        self._ensure_pat()
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

        lines = [
            f"**Public sponsors for {SPONSORABLE}** (GitHub API):",
            f"- Current sponsors: **{len(curr_pub) + len(curr_priv)}**  (public: **{len(curr_pub)}**, private: **{len(curr_priv)}**)",
            f"- Past sponsors: **{len(past_pub) + len(past_priv)}**  (public: **{len(past_pub)}**, private: **{len(past_priv)}**)",
            "",
            "**Current (public usernames):**",
            ", ".join(sorted(curr_pub, key=str.lower)) if curr_pub else "—",
            "",
            "**Past (public usernames):**",
            ", ".join(sorted(past_pub, key=str.lower)) if past_pub else "—",
            "",
            "Private sponsors are intentionally not listed by name.",
        ]
        await self._send_report(ctx, lines, base_name="sponsorlist")

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, limit: int = 2000):
        """
        Actionable reconciliation using PAT (API-only):
          • Grant Sponsor role: current sponsors in the server without the Sponsor role
          • OK (has role & is current sponsor)
          • Has role but lapsed (past-only)
          • Has role but never sponsored (or needs mapping)
          • Current sponsors not in server (GitHub usernames)
        Large outputs attach as 'sponsorreport_<guild>_<timestamp>.txt'.
        """
        self._ensure_pat()
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

        # Build sets (lowercased)
        current_all = {u.lower() for u in (curr_pub | curr_priv)}
        past_all = {u.lower() for u in (past_pub | past_priv)}
        public_union_n = len({u.lower() for u in (curr_pub | past_pub)})
        private_union_n = len({u.lower() for u in (curr_priv | past_priv)})
        current_total = len(curr_pub) + len(curr_priv)
        past_total = len(past_pub) + len(past_priv)

        members = list(ctx.guild.members)  # check everyone
        role_member_ids = {m.id for m in role.members}

        gh_to_member: dict[str, discord.Member] = {}
        member_to_hit: dict[int, str] = {}

        verified_usernames = {u.lower() for u in VERIFIED_PRIVATE_USERNAMES}

        for m in members:
            ksn = (m.display_name or "").strip()
            dsn = (m.name or "").strip()
            override = GH_USERNAME_MAP.get(m.id)
            hit: str | None = None

            for cand in self._gh_candidates_from_names(ksn, dsn, override):
                lc = cand.lower()
                if lc in current_all:
                    hit = "current"
                    gh_to_member.setdefault(lc, m)
                    break
                if lc in past_all:
                    hit = "past"
                    gh_to_member.setdefault(lc, m)
                    break

            # Manual verified-private fallback → treat as current
            if not hit and (m.id in VERIFIED_PRIVATE_IDS or dsn.lower() in verified_usernames):
                hit = "current"

            if hit:
                member_to_hit[m.id] = hit

        # Buckets
        grant_role: List[str] = []  # current sponsors in server, missing role
        ok_role: List[str] = []  # has role & current sponsor
        lapsed_role: List[str] = []  # has role & past-only sponsor
        never_role: List[str] = []  # has role & never sponsored (or needs mapping)

        for m in members:
            disp = (m.display_name or m.name or "—")
            line = f"- {disp} (`{m.id}`)"
            hit = member_to_hit.get(m.id)

            if hit == "current":
                if m.id in role_member_ids:
                    ok_role.append(line)
                else:
                    grant_role.append(line)
            elif hit == "past":
                if m.id in role_member_ids:
                    lapsed_role.append(line)
            else:
                if m.id in role_member_ids:
                    never_role.append(line)

        # Current sponsors not in server (GitHub usernames)
        current_not_in_server = []
        for gh_login in current_all:
            if gh_login not in gh_to_member:
                current_not_in_server.append(f"- {gh_login}")

        # Header summary
        header = [
            f"**Current GH sponsors:** total **{current_total}**  (public **{len(curr_pub)}**, private **{len(curr_priv)}**)",
            f"**Past GH sponsors:** total **{past_total}**  (public **{len(past_pub)}**, private **{len(past_priv)}**)",
            f"**Public union (current ∪ past):** {public_union_n}",
            f"**Private union (current ∪ past):** {private_union_n}",
            f"**Discord users with Sponsor role:** {len(role_member_ids)}",
            "",
            f"**Grant Sponsor role (current sponsors in server, no role):** {len(grant_role)}",
            f"**OK (has role & is current sponsor):** {len(ok_role)}",
            f"**Has role but lapsed (past-only):** {len(lapsed_role)}",
            f"**Has role but never sponsored (or needs mapping):** {len(never_role)}",
            f"**Current sponsors not in server (GitHub usernames):** {len(current_not_in_server)}",
            ""
        ]

        # Body sections — counts reflected in each title
        body: List[str] = []

        def section(title: str, items: List[str]):
            body.append(f"**{title} ({len(items)}):**")
            if items:
                body.extend(items[:limit])
                extra = len(items) - min(len(items), limit)
                if extra > 0:
                    body.append(f"…and {extra} more")
            else:
                body.append("—")
            body.append("")

        section("Grant Sponsor role: current sponsors in the server without the Sponsor role", grant_role)
        section("OK (has role & is current sponsor)", ok_role)
        section("Has role but lapsed (past-only)", lapsed_role)
        section("Has role but never sponsored (or needs mapping)", never_role)
        section("Current sponsors not in server (GitHub usernames)", current_not_in_server)

        body.append("_Notes: Public and private sponsors are from the GitHub API via your PAT. "
                    "Private identities are matched for reconciliation but are not printed._")

        await self._send_report(ctx, header + body, base_name="sponsorreport")

    # ---------------- GitHub API helpers ----------------
    def _load_pat(self, initial: bool = False, force: bool = False) -> None:
        """Load PAT from env or file. Env wins. If force=True, always re-read."""
        if self._pat and not force:
            return

        pat_env = os.environ.get("GITHUB_PAT")
        if pat_env:
            self._pat = pat_env.strip()
            self._pat_source = "env"
            mylogger.info("Loaded GitHub PAT from environment.")
            return

        try:
            with open(PAT_FILE, "r", encoding="utf-8") as f:
                token = f.read().strip()
            if token:
                self._pat = token
                self._pat_source = "file"
                mylogger.info(f"Loaded GitHub PAT from file: {PAT_FILE}")
                return
        except FileNotFoundError:
            msg = "No GitHub PAT file found; API needs env GITHUB_PAT or the PAT file."
            if initial:
                mylogger.info(msg)
            else:
                mylogger.warning(msg)
        except Exception as e:
            mylogger.error(f"Failed to read PAT file: {e}")

        self._pat = None
        self._pat_source = None

    def _ensure_pat(self) -> None:
        """Try to (re)load the PAT before each command."""
        if not self._pat:
            self._load_pat(initial=False, force=True)

    async def _fetch_all_sponsors(self) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """
        Return (current_public, current_private, past_public, past_private) via GraphQL,
        includePrivate:true, activeOnly:false; paginated to exhaustion.
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

                    if status == 401:
                        raise GitHubAuthError("unauthorized", "Bad credentials (token invalid/expired/revoked).")
                    if status == 403:
                        raise GitHubAuthError("forbidden",
                                              "Permission denied (insufficient scopes/access to Sponsors API).")
                    if status >= 400:
                        raise GitHubAuthError("http_error", f"HTTP {status}: {text[:200]}")

                    data = await resp.json()

                if "errors" in data and data["errors"]:
                    msg = "; ".join(err.get("message", "unknown") for err in data["errors"])
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

    # ---------------- Utilities ----------------
    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: Optional[str]) -> List[str]:
        def norm(s: Optional[str]) -> str:
            if not s:
                return ""
            s = s.strip().lstrip("@").lower()
            s = s.replace(" ", "").replace("_", "").replace(".", "")
            return "".join(ch for ch in s if ch.isalnum() or ch == "-")

        cands: List[str] = []
        for raw in (override or "", dsn or "", ksn or ""):
            base = norm(raw)
            if base and base not in cands:
                cands.append(base)
            if base:
                stripped = base.rstrip("0123456789")
                if stripped and stripped != base and stripped not in cands:
                    cands.append(stripped)
            for sep in ("|", "·", "-", "—", ":", "/"):
                if sep in raw:
                    tail = norm(raw.split(sep)[-1])
                    if tail and tail not in cands:
                        cands.append(tail)
                    if tail:
                        stripped_tail = tail.rstrip("0123456789")
                        if stripped_tail and stripped_tail != tail and stripped_tail not in cands:
                            cands.append(stripped_tail)
        return cands

    async def _send_report(self, ctx: commands.Context, lines: List[str], header: Optional[str] = None, *,
                           base_name: str = "sponsorreport"):
        """
        Safely send a possibly-large report: paginate or attach as a timestamped .txt.
        base_name: "sponsorreport" (default) or "sponsorlist" etc. Used for the attachment filename.
        """
        out_lines: List[str] = []
        if header:
            out_lines.append(header)
            out_lines.append("")
        out_lines.extend(lines)

        # Chunk to stay under Discord 2000-char cap (use 1800 buffer per chunk)
        chunks: List[str] = []
        buf = ""
        for line in out_lines:
            line = line if line.endswith("\n") else line + "\n"
            if len(buf) + len(line) > 1800:
                chunks.append(buf)
                buf = line
            else:
                buf += line
        if buf:
            chunks.append(buf)

        total_len = sum(len(c) for c in chunks)
        if total_len <= 3800 and len(chunks) <= 2:
            for c in chunks:
                await ctx.send(c)
            return

        # Large: attach as file with requested base name
        text = "".join(chunks)
        bio = BytesIO(text.encode("utf-8"))
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{base_name}_{ctx.guild.id}_{ts}.txt"
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
            "⚠️ GitHub token not configured. Set env `GITHUB_PAT` **or** create the file "
            f"`{PAT_FILE}` with a valid PAT (with Sponsors access). Then run `[p]sponsortoken reload` "
            "or restart the bot process if you used the environment variable."
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

    @staticmethod
    def _mask(token: str, keep: int = 4) -> str:
        if not token:
            return ""
        if len(token) <= keep:
            return "*" * len(token)
        return token[:keep] + "*" * (len(token) - keep)


class GitHubAuthError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail
