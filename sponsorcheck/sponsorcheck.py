from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional, Set, Tuple, Dict, List

import aiohttp
import discord
from redbot.core import commands

# ---------- logging ----------
mylogger = logging.getLogger("sponsorcheck")
mylogger.setLevel(logging.DEBUG)

# ---------- access control ----------
ALLOWED_ROLE_IDS = {
    929756550380286153,  # Moderator
    929900016531828797,  # Kometa Masters
    981499667722424390,  # Kometa Apprentices
}
SPONSOR_ROLE_ID = 862041125706268702  # "Sponsor" role id in your server

# ---------- optional mappings ----------
GH_USERNAME_MAP: Dict[int, str] = {}  # { discord_user_id: "github-login" }
VERIFIED_PRIVATE_IDS: Set[int] = set()  # discord ids known as private sponsors (treat as current)
VERIFIED_PRIVATE_USERNAMES: Set[str] = set()  # member.name strings (case-insensitive)

# ---------- GitHub API ----------
SPONSORABLE = "meisnate12"
GRAPHQL_API = "https://api.github.com/graphql"
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"

# ---------- easter egg ----------
EASTER_EGG_NAMES = {"sohjiro", "meisnate12"}
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
    """GitHub Sponsors via GraphQL (no scraping). Embeds everywhere; auto-grant Sponsor role on hit."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: Optional[str] = None
        self._pat_source: Optional[str] = None  # env|file
        self._load_pat(initial=True)

    # ---------- role gate ----------
    async def cog_check(self, ctx: commands.Context) -> bool:
        if not ctx.guild:
            return False
        user_role_ids = {r.id for r in ctx.author.roles}
        return bool((ALLOWED_ROLE_IDS & user_role_ids) or ctx.author.guild_permissions.manage_guild)

    # ---------- token helpers ----------
    def _load_pat(self, initial: bool = False, force: bool = False) -> None:
        if self._pat and not force:
            return
        env = os.environ.get("GITHUB_PAT")
        if env:
            self._pat, self._pat_source = env.strip(), "env"
            return
        try:
            with open(PAT_FILE, "r", encoding="utf-8") as f:
                tok = f.read().strip()
            if tok:
                self._pat, self._pat_source = tok, "file"
                return
        except FileNotFoundError:
            pass
        except Exception as e:
            mylogger.error(f"PAT read error: {e}")
        self._pat, self._pat_source = None, None

    def _ensure_pat(self) -> None:
        if not self._pat:
            self._load_pat(force=True)

    # ---------- embed helpers ----------
    def _safe_desc(self, text: str) -> str:
        return (text or "") + "\u200b"  # avoid iOS clipping

    def _embed(self, title: str, desc: str, *, color: discord.Color, guild: Optional[discord.Guild] = None,
               footer: Optional[str] = None) -> discord.Embed:
        e = discord.Embed(title=title, description=self._safe_desc(desc), color=color)
        e.set_author(name="SponsorCheck")
        if guild and guild.icon:
            try:
                e.set_thumbnail(url=guild.icon.url)  # used on list/report; for !sponsor we override thumbnail later
            except Exception:
                pass
        if footer:
            e.set_footer(text=footer)
        return e

    def _embed_ok(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.green(), **kw)

    def _embed_warn(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.gold(), **kw)

    def _embed_err(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.red(), **kw)

    def _embed_info(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.blurple(), **kw)

    # ---------- avatars & member lookup ----------
    async def _github_avatar(self, login: str) -> Optional[str]:
        if not login:
            return None
        url = f"https://api.github.com/users/{login}"
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa)"
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return data.get("avatar_url")
        except Exception:
            return None

    def _best_member_match(self, guild: discord.Guild, *names: str) -> Optional[discord.Member]:
        lowers = {n.strip().lower() for n in names if n}
        for m in guild.members:
            if (m.display_name or "").strip().lower() in lowers or (m.name or "").strip().lower() in lowers:
                return m
        return None

    def _attach_person_avatars(self, embed: discord.Embed, member: Optional[discord.Member],
                               gh_avatar: Optional[str]) -> None:
        # Member avatar as thumbnail
        try:
            if member:
                embed.set_thumbnail(url=member.display_avatar.url)
        except Exception:
            pass
        # GH avatar (public only) as big image
        try:
            if gh_avatar:
                embed.set_image(url=gh_avatar)
        except Exception:
            pass

    # ---------- role ops ----------
    async def _try_grant_role(self, guild: discord.Guild, member: discord.Member) -> Tuple[bool, str]:
        """Attempt to add the Sponsor role. Return (ok, message)."""
        role = guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            return False, f"Role id `{SPONSOR_ROLE_ID}` not found."
        if role in member.roles:
            return True, f"Already has `{role.name}`."
        me = guild.me
        if not me:
            return False, "Bot member not resolved."
        if not guild.me.guild_permissions.manage_roles:
            return False, "Bot lacks `Manage Roles` permission."
        # role hierarchy: bot's top role must be above the target role AND above member's top role
        if role >= me.top_role:
            return False, f"Bot's top role is not above `{role.name}`."
        if member.top_role >= me.top_role and member != me:
            return False, "Target member has a role equal/higher than the bot."
        try:
            await member.add_roles(role, reason="SponsorCheck: auto-grant on sponsor hit")
            return True, f"Granted `{role.name}`."
        except discord.Forbidden:
            return False, "Discord forbids adding this role (hierarchy/permissions)."
        except discord.HTTPException as e:
            return False, f"HTTP error: {e}"

    # ---------- GraphQL ----------
    async def _fetch_all_sponsors(self) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """(current_pub, current_priv, past_pub, past_priv) — logins only, includePrivate, all pages."""
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
                sponsorEntity { ... on User { login } ... on Organization { login } }
              }
            }
          }
        }"""
        vars = {"login": SPONSORABLE, "first": 100, "after": None}
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Content-Type": "application/json",
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa)"
        }
        cp: Set[str] = set();
        cpr: Set[str] = set();
        pp: Set[str] = set();
        ppr: Set[str] = set()
        async with aiohttp.ClientSession(headers=headers) as session:
            while True:
                async with session.post(GRAPHQL_API, json={"query": query, "variables": vars}) as r:
                    status = r.status
                    text = await r.text()
                    if status == 401:
                        raise GitHubAuthError("unauthorized", "Bad credentials (invalid/expired/revoked).")
                    if status == 403:
                        raise GitHubAuthError("forbidden", "Insufficient scopes/access to Sponsors API.")
                    if status >= 400:
                        raise GitHubAuthError("http_error", f"HTTP {status}: {text[:200]}")
                    data = await r.json()
                if data.get("errors"):
                    msg = "; ".join(e.get("message", "error") for e in data["errors"])
                    if "Bad credentials" in msg:
                        raise GitHubAuthError("unauthorized", "Bad credentials (invalid/expired/revoked).")
                    if "Resource not accessible" in msg or "Insufficient scopes" in msg:
                        raise GitHubAuthError("forbidden", "Insufficient scopes/access to Sponsors API.")
                    raise GitHubAuthError("graphql_error", msg[:300])
                try:
                    conn = data["data"]["user"]["sponsorshipsAsMaintainer"]
                except Exception:
                    raise GitHubAuthError("schema_error", f"Unexpected response: {str(data)[:200]}")
                for n in conn.get("nodes", []):
                    login = ((n.get("sponsorEntity") or {}).get("login") or "").strip()
                    if not login:
                        continue
                    priv = str(n.get("privacyLevel") or "").upper() == "PRIVATE"
                    active = bool(n.get("isActive"))
                    if active:
                        (cpr if priv else cp).add(login)
                    else:
                        (ppr if priv else pp).add(login)
                if conn["pageInfo"]["hasNextPage"]:
                    vars["after"] = conn["pageInfo"]["endCursor"]
                else:
                    break
        return cp, cpr, pp, ppr

    # ---------- utils ----------
    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: Optional[str]) -> List[str]:
        def norm(s: Optional[str]) -> str:
            if not s:
                return ""
            s = s.strip().lstrip("@").lower().replace(" ", "").replace("_", "").replace(".", "")
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

    async def _send_report(self, ctx: commands.Context, lines: List[str], *, base_name: str, embed: discord.Embed):
        await ctx.send(embed=embed)
        # try inline; else attach
        chunks: List[str] = []
        buf = ""
        for line in lines:
            line = line if line.endswith("\n") else line + "\n"
            if len(buf) + len(line) > 1800:
                chunks.append(buf);
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
        text = "".join(chunks)
        bio = BytesIO(text.encode("utf-8"))
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{base_name}_{ctx.guild.id}_{ts}.txt"
        await ctx.send("Full report attached:", file=discord.File(bio, filename=filename))

    async def _send_pat_error(self, ctx: commands.Context):
        return await ctx.send(embed=self._embed_err(
            "GitHub token not configured",
            f"Set env `GITHUB_PAT` **or** create `{PAT_FILE}` with a valid PAT, then restart or `[p]sponsortoken reload`.",
            guild=ctx.guild
        ))

    async def _send_pat_auth_message(self, ctx: commands.Context, e: "GitHubAuthError"):
        readable = {
            "missing_pat": "GitHub token not configured.",
            "unauthorized": "Bad credentials (token invalid/expired/revoked).",
            "forbidden": "Insufficient scopes or access to Sponsors API.",
            "http_error": f"HTTP error: {e.detail}",
            "graphql_error": f"GraphQL error: {e.detail}",
            "schema_error": f"Unexpected API response.",
        }.get(e.code, f"GitHub API error: {e.detail}")
        return await ctx.send(embed=self._embed_err("GitHub API", readable, guild=ctx.guild))

    # ---------- commands ----------
    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor(self, ctx: commands.Context, username: str):
        """
        Check a username (GitHub login or Kometa display name).
        If they are a sponsor (public/private, current/past) and we can resolve a guild member without the role,
        we will attempt to GRANT the Sponsor role automatically and report the result.
        """
        self._ensure_pat()
        if not self._pat:
            return await self._send_pat_error(ctx)

        target = (username or "").lstrip("@").strip()
        if not target:
            return await ctx.send(embed=self._embed_info("Usage", "Try `[p]sponsor bullmoose20`.", guild=ctx.guild))

        # easter egg
        if (target or "").lower() in EASTER_EGG_NAMES:
            egg = discord.Embed(
                title=EASTER_EGG_TITLE,
                description=EASTER_EGG_DESC.format(who=target),
                color=discord.Color.gold(),
            )
            egg.set_author(name="SponsorCheck")
            return await ctx.send(embed=egg)

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("sponsor(): API failure")
            return await ctx.send(embed=self._embed_err("GitHub API error", f"`{e}`", guild=ctx.guild))

        current_public = {u.lower() for u in curr_pub}
        past_public = {u.lower() for u in past_pub}
        current_private = {u.lower() for u in curr_priv}
        past_private = {u.lower() for u in past_priv}
        union_public = current_public | past_public
        union_private = current_private | past_private
        t = target.lower()

        possible_member = self._best_member_match(ctx.guild, target)
        role_action_note = None  # we'll fill if we attempt a grant

        # ---- Direct GH login: PUBLIC
        if t in union_public:
            status = "current" if t in current_public else "past"
            gh_avatar = await self._github_avatar(target)
            em = self._embed_ok("Sponsor check", f"**{target}** is a **{status}** public sponsor of **{SPONSORABLE}**.")
            self._attach_person_avatars(em, possible_member, gh_avatar)
            # auto-grant if member found and lacks role (you asked: present OR past)
            if possible_member:
                ok, msg = await self._try_grant_role(ctx.guild, possible_member)
                role_action_note = msg
                em.add_field(name="Role action", value=msg, inline=False)
            return await ctx.send(embed=em)

        # ---- Direct GH login: PRIVATE (no GH avatar shown)
        if t in union_private:
            status = "current" if t in current_private else "past"
            em = self._embed_warn("Sponsor check", f"**{target}** is a **{status}** sponsor of **{SPONSORABLE}**.")
            em.add_field(name="Privacy", value="Private", inline=True)
            self._attach_person_avatars(em, possible_member, None)
            if possible_member:
                ok, msg = await self._try_grant_role(ctx.guild, possible_member)
                role_action_note = msg
                em.add_field(name="Role action", value=msg, inline=False)
            return await ctx.send(embed=em)

        # ---- KSN -> DSN from members with Sponsor role or same display name
        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        candidate_member = None
        if role:
            candidate_member = next((m for m in ctx.guild.members if (m.display_name or "").strip().lower() == t or (
                        m.name or "").strip().lower() == t), None)

        if candidate_member:
            ksn = (candidate_member.display_name or "").strip()
            dsn = (candidate_member.name or "").strip()
            override = GH_USERNAME_MAP.get(candidate_member.id)
            candidates = self._gh_candidates_from_names(ksn, dsn, override)

            # public first
            for cand in candidates:
                lc = cand.lower()
                if lc in union_public:
                    status = "current" if lc in current_public else "past"
                    gh_avatar = await self._github_avatar(cand)
                    em = self._embed_ok("Sponsor check",
                                        f"**{ksn}** → **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**.")
                    self._attach_person_avatars(em, candidate_member, gh_avatar)
                    ok, msg = await self._try_grant_role(ctx.guild, candidate_member)
                    role_action_note = msg
                    em.add_field(name="Role action", value=msg, inline=False)
                    return await ctx.send(embed=em)

            # private next
            for cand in candidates:
                lc = cand.lower()
                if lc in union_private:
                    status = "current" if lc in current_private else "past"
                    em = self._embed_warn("Sponsor check",
                                          f"**{ksn}** → **{dsn}** → **{status}** sponsor of **{SPONSORABLE}**.")
                    em.add_field(name="Privacy", value="Private", inline=True)
                    self._attach_person_avatars(em, candidate_member, None)
                    ok, msg = await self._try_grant_role(ctx.guild, candidate_member)
                    role_action_note = msg
                    em.add_field(name="Role action", value=msg, inline=False)
                    return await ctx.send(embed=em)

        # ---- Not found
        em = self._embed_err("Sponsor check",
                             f"**{target}** does not appear as a sponsor of **{SPONSORABLE}** (current or past).",
                             guild=ctx.guild)
        if possible_member:
            self._attach_person_avatars(em, possible_member, None)
        return await ctx.send(embed=em)

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist(self, ctx: commands.Context):
        """All public sponsors (current & past) + private counts. Guild icon in embed. Large outputs -> file."""
        self._ensure_pat()
        if not self._pat:
            return await self._send_pat_error(ctx)
        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("sponsorlist(): API failure")
            return await ctx.send(embed=self._embed_err("GitHub API error", f"`{e}`", guild=ctx.guild))

        counts = (
            f"**Current sponsors:** **{len(curr_pub) + len(curr_priv)}** (public **{len(curr_pub)}**, private **{len(curr_priv)}**)\n"
            f"**Past sponsors:** **{len(past_pub) + len(past_priv)}** (public **{len(past_pub)}**, private **{len(past_priv)}**)"
        )

        lines = [
            f"Public sponsors for {SPONSORABLE} (GitHub API)\n",
            f"Current: {len(curr_pub) + len(curr_priv)}  (public: {len(curr_pub)}, private: {len(curr_priv)})\n",
            "Current (public): " + (", ".join(sorted(curr_pub, key=str.lower)) if curr_pub else "—") + "\n\n",
            f"Past: {len(past_pub) + len(past_priv)}  (public: {len(past_pub)}, private: {len(past_priv)})\n",
            "Past (public): " + (", ".join(sorted(past_pub, key=str.lower)) if past_pub else "—") + "\n",
        ]

        await self._send_report(ctx, lines, base_name="sponsorlist",
                                embed=self._embed_info("Sponsor list • Summary", counts, guild=ctx.guild,
                                                       footer="Private sponsors are not listed by name."))

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport(self, ctx: commands.Context, limit: int = 2000):
        """Actionable reconciliation. Guild icon in embed. Large outputs -> file."""
        self._ensure_pat()
        if not self._pat:
            return await self._send_pat_error(ctx)

        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            return await ctx.send(
                embed=self._embed_err("Sponsor role not found", f"ID `{SPONSOR_ROLE_ID}`", guild=ctx.guild))

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await self._send_pat_auth_message(ctx, e)
        except Exception as e:
            mylogger.exception("sponsorreport(): API failure")
            return await ctx.send(embed=self._embed_err("GitHub API error", f"`{e}`", guild=ctx.guild))

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
            ksn = (m.display_name or "")
            dsn = (m.name or "")
            override = GH_USERNAME_MAP.get(m.id)
            hit = None
            for cand in self._gh_candidates_from_names(ksn, dsn, override):
                lc = cand.lower()
                if lc in current_all:
                    hit = "current";
                    gh_to_member.setdefault(lc, m);
                    break
                if lc in past_all:
                    hit = "past";
                    gh_to_member.setdefault(lc, m);
                    break
            if not hit and (m.id in VERIFIED_PRIVATE_IDS or dsn.lower() in verified_usernames):
                hit = "current"
            if hit:
                member_to_hit[m.id] = hit

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

        def section_block(title: str, items: List[str]) -> List[str]:
            out = [f"{title} ({len(items)}):\n"]
            if items:
                out.extend(items[:limit])
                if len(items) > limit:
                    out.append(f"…and {len(items) - limit} more")
            else:
                out.append("—")
            out.append("\n")
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
            "Notes: Public and private sponsors come from the GitHub API via your PAT. Private identities are matched for reconciliation but not printed.\n")

        await self._send_report(ctx, lines, base_name="sponsorreport",
                                embed=self._embed_info("Sponsor report • Summary", summary, guild=ctx.guild))

    # ---------- misc ----------
    @staticmethod
    def _mask(token: str, keep: int = 4) -> str:
        if not token:
            return ""
        return token[:keep] + "*" * (len(token) - keep) if len(token) > keep else "*" * len(token)
