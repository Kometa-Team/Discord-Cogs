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
GH_USERNAME_MAP: Dict[int, str] = {}
VERIFIED_PRIVATE_IDS: Set[int] = set()
VERIFIED_PRIVATE_USERNAMES: Set[str] = set()

# ---------------- GitHub GraphQL ----------------
SPONSORABLE = "meisnate12"
GRAPHQL_API = "https://api.github.com/graphql"
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"

# ---------------- Easter Egg ----------------
EASTER_EGG_NAMES = {"sohjiro", "meisnate12"}  # lowercase
EASTER_EGG_TITLE = "You found the hidden egg! 🥚"
EASTER_EGG_DESC = (
    "You're checking **{who}** — the developer/sponsorable behind this project.\n\n"
    "If you're feeling generous, consider supporting the work directly ❤️\n"
    "→ https://github.com/sponsors/meisnate12"
)
EASTER_EGG_FOOTER = "Thanks for supporting open source ✨"


class GitHubAuthError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class SponsorCheck(commands.Cog):
    """GitHub Sponsors via GraphQL API (no scraping). All replies use embeds."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: Optional[str] = None
        self._pat_source: Optional[str] = None  # "env" | "file" | None
        self._load_pat(initial=True)

    # ---------------- Role gate ----------------
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
        allowed = (ALLOWED_ROLE_IDS & user_role_ids) or ctx.author.guild_permissions.manage_guild
        if allowed:
            mylogger.debug(f"Access granted. user_roles={list(user_role_ids)}")
            return True
        mylogger.info(f"Access denied. Needs one of {list(ALLOWED_ROLE_IDS)}.")
        return False

    # ---------------- Owner token tools ----------------
    @commands.group(name="sponsortoken", invoke_without_command=True)
    @commands.is_owner()
    async def sponsortoken(self, ctx: commands.Context):
        await ctx.send(embed=self._embed_info(
            "SponsorCheck • Token",
            "Subcommands: `check`, `reload`, `where`"
        ))

    @sponsortoken.command(name="check")
    @commands.is_owner()
    async def sponsortoken_check(self, ctx: commands.Context):
        self._ensure_pat()
        if not self._pat:
            return await ctx.send(embed=self._embed_error(
                "GitHub PAT",
                "No token loaded. Set env `GITHUB_PAT` or create the file shown by `sponsortoken where`."
            ))
        masked = self._mask(self._pat)
        await ctx.send(embed=self._embed_ok(
            "GitHub PAT",
            f"Loaded from **{self._pat_source}**.\n`{masked}`"
        ))

    @sponsortoken.command(name="reload")
    @commands.is_owner()
    async def sponsortoken_reload(self, ctx: commands.Context):
        self._load_pat(initial=False, force=True)
        if self._pat:
            await ctx.send(embed=self._embed_ok("GitHub PAT", f"Reloaded from **{self._pat_source}**."))
        else:
            await ctx.send(embed=self._embed_error(
                "GitHub PAT",
                "Reload attempted but no PAT found. If you set an env var, restart the bot process."
            ))

    @sponsortoken.command(name="where")
    @commands.is_owner()
    async def sponsortoken_where(self, ctx: commands.Context):
        await ctx.send(embed=self._embed_info("GitHub PAT location", f"Env: `GITHUB_PAT`\nFile: `{PAT_FILE}`"))

    # ---------------- Easter egg helpers ----------------
    def _is_easter_egg(self, s: str) -> bool:
        return (s or "").strip().lstrip("@").lower() in EASTER_EGG_NAMES

    async def _send_easter_egg(self, ctx: commands.Context, who: str) -> None:
        embed = discord.Embed(
            title=EASTER_EGG_TITLE,
            description=EASTER_EGG_DESC.format(who=who),
            color=discord.Color.gold(),
        )
        embed.set_author(name="SponsorCheck")
        embed.set_footer(text=EASTER_EGG_FOOTER)
        await ctx.send(embed=embed)

    # ---------------- Commands ----------------
    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """Check a username (GitHub or Kometa display name) for sponsorship (current or past)."""
        self._ensure_pat()
        if not self._pat:
            return await self._send_pat_error(ctx)

        target = (username or "").lstrip("@").strip()
        if not target:
            return await ctx.send(
                embed=self._embed_info("Usage", "Please provide a username, e.g. `[p]sponsor bullmoose20`."))

        # 🥚 Easter egg
        if self._is_easter_egg(target):
            return await self._send_easter_egg(ctx, target)

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            mylogger.error(f"PAT auth error: {e.code} {e.detail}")
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("Unexpected GitHub API error in sponsor()")
            return await ctx.send(embed=self._embed_error("GitHub API error", f"`{e}`"))

        current_public = {u.lower() for u in curr_pub}
        past_public = {u.lower() for u in past_pub}
        current_private = {u.lower() for u in curr_priv}
        past_private = {u.lower() for u in past_priv}

        union_public = current_public | past_public
        union_private = current_private | past_private
        t = target.lower()

        if t in union_public:
            status = "current" if t in current_public else "past"
            return await ctx.send(embed=self._embed_ok(
                "Sponsor check",
                f"**{target}** is a **{status}** public sponsor of **{SPONSORABLE}**."
            ))

        if t in union_private:
            status = "current" if t in current_private else "past"
            return await ctx.send(embed=self._embed_warn(
                "Sponsor check",
                f"**{target}** is a **{status}** sponsor of **{SPONSORABLE}** *(marked private)*."
            ))

        # KSN→DSN via Sponsor role
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if role:
            m = next((mem for mem in role.members if (mem.display_name or '').strip().lower() == t), None)
            if m:
                ksn = (m.display_name or "").strip()
                dsn = (m.name or "").strip()
                if self._is_easter_egg(dsn) or self._is_easter_egg(ksn):
                    return await self._send_easter_egg(ctx, dsn or ksn or target)

                override = GH_USERNAME_MAP.get(m.id)
                candidates = self._gh_candidates_from_names(ksn, dsn, override)

                for cand in candidates:
                    lc = cand.lower()
                    if lc in union_public:
                        status = "current" if lc in current_public else "past"
                        return await ctx.send(embed=self._embed_ok(
                            "Sponsor check",
                            f"**{ksn}** → **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**."
                        ))
                for cand in candidates:
                    lc = cand.lower()
                    if lc in union_private:
                        status = "current" if lc in current_private else "past"
                        return await ctx.send(embed=self._embed_warn(
                            "Sponsor check",
                            f"**{ksn}** → **{dsn}** → **{status}** sponsor of **{SPONSORABLE}** *(marked private)*."
                        ))

        return await ctx.send(embed=self._embed_error(
            "Sponsor check",
            f"**{target}** does not appear as a sponsor of **{SPONSORABLE}** (current or past)."
        ))

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """List all *public* sponsors (current & past) and show private counts. Large outputs attach as a file."""
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
            return await ctx.send(embed=self._embed_error("GitHub API error", f"`{e}`"))

        counts = (
            f"**Current sponsors:** **{len(curr_pub) + len(curr_priv)}** "
            f"(public **{len(curr_pub)}**, private **{len(curr_priv)}**)\n"
            f"**Past sponsors:** **{len(past_pub) + len(past_priv)}** "
            f"(public **{len(past_pub)}**, private **{len(past_priv)}**)"
        )

        # Build text body (public names only)
        lines = [
            f"Public sponsors for {SPONSORABLE} (GitHub API)\n",
            f"Current: {len(curr_pub) + len(curr_priv)}  (public: {len(curr_pub)}, private: {len(curr_priv)})\n",
            "Current (public): " + (", ".join(sorted(curr_pub, key=str.lower)) if curr_pub else "—") + "\n\n",
            f"Past: {len(past_pub) + len(past_priv)}  (public: {len(past_pub)}, private: {len(past_priv)})\n",
            "Past (public): " + (", ".join(sorted(past_pub, key=str.lower)) if past_pub else "—") + "\n",
        ]

        # Always send an embed summary; attach if large
        await self._send_report(ctx, lines, base_name="sponsorlist",
                                embed=self._embed_info("Sponsor list • Summary", counts,
                                                       footer="Private sponsors are not listed by name."))

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, limit: int = 2000):
        """
        Actionable reconciliation:
          • Grant Sponsor role: current sponsors in the server without the Sponsor role
          • OK (has role & is current sponsor)
          • Has role but lapsed (past-only)
          • Has role but never sponsored (or needs mapping)
          • Current sponsors not in server (GitHub usernames)
        """
        self._ensure_pat()
        if not self._pat:
            return await self._send_pat_error(ctx)

        limit = max(1, min(5000, limit))
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            mylogger.error(f"Sponsor role id {SPONSOR_ROLE_ID} not found in guild.")
            return await ctx.send(embed=self._embed_error("Sponsor role not found", f"ID `{SPONSOR_ROLE_ID}`"))

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            mylogger.error(f"PAT auth error: {e.code} {e.detail}")
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("Unexpected GitHub API error in sponsorreport()")
            return await ctx.send(embed=self._embed_error("GitHub API error", f"`{e}`"))

        # Sets
        current_all = {u.lower() for u in (curr_pub | curr_priv)}
        past_all = {u.lower() for u in (past_pub | past_priv)}
        public_union_n = len({u.lower() for u in (curr_pub | past_pub)})
        private_union_n = len({u.lower() for u in (curr_priv | past_priv)})
        current_total = len(curr_pub) + len(curr_priv)
        past_total = len(past_pub) + len(past_priv)

        members = list(ctx.guild.members)
        role_member_ids = {m.id for m in role.members}

        gh_to_member: Dict[str, discord.Member] = {}
        member_to_hit: Dict[int, str] = {}

        verified_usernames = {u.lower() for u in VERIFIED_PRIVATE_USERNAMES}

        for m in members:
            ksn = (m.display_name or "").strip()
            dsn = (m.name or "").strip()
            override = GH_USERNAME_MAP.get(m.id)
            hit: Optional[str] = None

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

            if not hit and (m.id in VERIFIED_PRIVATE_IDS or dsn.lower() in verified_usernames):
                hit = "current"

            if hit:
                member_to_hit[m.id] = hit

        # Buckets
        grant_role: List[str] = []
        ok_role: List[str] = []
        lapsed_role: List[str] = []
        never_role: List[str] = []

        for m in members:
            disp = (m.display_name or m.name or "—")
            line = f"- {disp} (`{m.id}`)"
            hit = member_to_hit.get(m.id)

            if hit == "current":
                (ok_role if m.id in role_member_ids else grant_role).append(line)
            elif hit == "past":
                if m.id in role_member_ids:
                    lapsed_role.append(line)
            else:
                if m.id in role_member_ids:
                    never_role.append(line)

        current_not_in_server = [f"- {gh}" for gh in sorted(current_all) if gh not in gh_to_member]

        # Header summary (for embed)
        summary = (
            f"**Current GH sponsors:** **{current_total}** (public **{len(curr_pub)}**, private **{len(curr_priv)}**)\n"
            f"**Past GH sponsors:** **{past_total}** (public **{len(past_pub)}**, private **{len(past_priv)}**)\n"
            f"**Public union:** {public_union_n} • **Private union:** {private_union_n}\n"
            f"**Discord members with Sponsor role:** {len(role_member_ids)}\n\n"
            f"**Grant Sponsor role:** {len(grant_role)}\n"
            f"**OK (current + role):** {len(ok_role)}\n"
            f"**Has role but lapsed (past-only):** {len(lapsed_role)}\n"
            f"**Has role but never sponsored:** {len(never_role)}\n"
            f"**Current sponsors not in server (GitHub):** {len(current_not_in_server)}"
        )

        # Build full text body for attachment
        def section_block(title: str, items: List[str]) -> List[str]:
            out = [f"{title} ({len(items)}):\n"]
            if items:
                out.extend([*items[:limit], "\n" if len(items) <= limit else f"…and {len(items) - limit} more\n\n"])
            else:
                out.append("—\n\n")
            return out

        lines: List[str] = []
        lines.append(f"Summary for {SPONSORABLE}\n\n")
        lines.append(summary + "\n\n")
        lines += section_block("Grant Sponsor role: current sponsors in the server without the Sponsor role",
                               grant_role)
        lines += section_block("OK (has role & is current sponsor)", ok_role)
        lines += section_block("Has role but lapsed (past-only)", lapsed_role)
        lines += section_block("Has role but never sponsored (or needs mapping)", never_role)
        lines += section_block("Current sponsors not in server (GitHub usernames)", current_not_in_server)
        lines.append(
            "Notes: Public and private sponsors are from the GitHub API via your PAT. Private identities are matched for reconciliation but are not printed.\n")

        # Send embed summary + attach text if large
        await self._send_report(
            ctx,
            lines,
            base_name="sponsorreport",
            embed=self._embed_info("Sponsor report • Summary", summary)
        )

    # ---------------- GitHub API helpers ----------------
    def _load_pat(self, initial: bool = False, force: bool = False) -> None:
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
            (mylogger.info if initial else mylogger.warning)(
                "No GitHub PAT file found; API needs env GITHUB_PAT or the PAT file."
            )
        except Exception as e:
            mylogger.error(f"Failed to read PAT file: {e}")
        self._pat = None
        self._pat_source = None

    def _ensure_pat(self) -> None:
        if not self._pat:
            self._load_pat(initial=False, force=True)

    async def _fetch_all_sponsors(self) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """Return (current_public, current_private, past_public, past_private) via GraphQL, paginated."""
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
                        raise GitHubAuthError("forbidden", "Insufficient scopes/access to Sponsors API.")
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

    def _embed(self, title: str, desc: str, *, color: discord.Color, footer: Optional[str] = None) -> discord.Embed:
        e = discord.Embed(title=title, description=desc, color=color)
        e.set_author(name="SponsorCheck")
        if footer:
            e.set_footer(text=footer)
        return e

    def _embed_ok(self, title: str, desc: str, footer: Optional[str] = None) -> discord.Embed:
        return self._embed(title, desc, color=discord.Color.green(), footer=footer)

    def _embed_warn(self, title: str, desc: str, footer: Optional[str] = None) -> discord.Embed:
        return self._embed(title, desc, color=discord.Color.gold(), footer=footer)

    def _embed_error(self, title: str, desc: str, footer: Optional[str] = None) -> discord.Embed:
        return self._embed(title, desc, color=discord.Color.red(), footer=footer)

    def _embed_info(self, title: str, desc: str, footer: Optional[str] = None) -> discord.Embed:
        return self._embed(title, desc, color=discord.Color.blurple(), footer=footer)

    async def _send_report(self, ctx: commands.Context, lines: List[str], *, base_name: str, embed: discord.Embed):
        """
        Send an embed summary, and:
          - if text is short (<~3800 across 2 chunks), also send text as messages
          - else attach a timestamped .txt with base_name
        """
        # Always send the summary embed first
        await ctx.send(embed=embed)

        # Build text
        chunks: List[str] = []
        buf = ""
        for line in lines:
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
                await ctx.send(f"```\n{c}```")
            return

        # Large: attach as file with requested base name
        text = "".join(chunks)
        bio = BytesIO(text.encode("utf-8"))
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{base_name}_{ctx.guild.id}_{ts}.txt"
        await ctx.send("Full report attached:", file=discord.File(bio, filename=filename))

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
        return await ctx.send(embed=self._embed_error(
            "GitHub token not configured",
            f"Set env `GITHUB_PAT` **or** create `{PAT_FILE}` with a valid PAT, then run `[p]sponsortoken reload`.\n"
            "If you used the environment variable, restart the bot process."
        ))

    async def _send_pat_auth_message(self, ctx: commands.Context, e: "GitHubAuthError"):
        readable = {
            "missing_pat": "GitHub token not configured.",
            "unauthorized": "Bad credentials (token invalid/expired/revoked).",
            "forbidden": "Insufficient scopes or access to Sponsors API.",
            "http_error": f"HTTP error from GitHub: {e.detail}",
            "graphql_error": f"GraphQL error: {e.detail}",
            "schema_error": f"Unexpected API response.",
        }.get(e.code, f"GitHub API error: {e.detail}")
        return await ctx.send(embed=self._embed_error("GitHub API", readable))

    @staticmethod
    def _mask(token: str, keep: int = 4) -> str:
        if not token:
            return ""
        if len(token) <= keep:
            return "*" * len(token)
        return token[:keep] + "*" * (len(token) - keep)
