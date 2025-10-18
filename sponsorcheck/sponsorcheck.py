from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional, Set, Tuple, Dict, List

import aiohttp
import discord
from redbot.core import commands, app_commands

# ---------- Logging ----------
mylogger = logging.getLogger("sponsorcheck")
mylogger.setLevel(logging.DEBUG)

# ---------- Who can run the commands ----------
ALLOWED_ROLE_IDS = {
    929756550380286153,  # Moderator
    929900016531828797,  # Kometa Masters
    981499667722424390,  # Kometa Apprentices
}
SPONSOR_ROLE_ID = 862041125706268702  # Discord "Sponsor" role id

# ---------- Optional mappings / allow-lists ----------
GH_USERNAME_MAP: Dict[int, str] = {}  # { discord_user_id: "github-login" }
VERIFIED_PRIVATE_IDS: Set[int] = set()  # discord IDs verified as private sponsors (treated as current)
VERIFIED_PRIVATE_USERNAMES: Set[str] = set()  # member.name strings (case-insensitive)

# ---------- GitHub API ----------
SPONSORABLE = "meisnate12"
GRAPHQL_API = "https://api.github.com/graphql"
PAT_FILE = "/opt/red-botmoose/secrets/github_pat.txt"

# ---------- Easter Egg ----------
EASTER_EGG_NAMES = {"sohjiro", "meisnate12"}
EASTER_EGG_DESC = (
    "You're checking **{who}** — the developer/sponsorable behind this project.\n\n"
    "If you're feeling generous, consider supporting the work directly ❤️\n"
    "→ https://github.com/sponsors/meisnate12"
)

# ---------- Pager constants ----------
MAX_EMBED_CHARS = 3500
PAGE_SIZE = 30
VIEW_TIMEOUT_SECONDS = 180
BULLET = "• "


# ===== UI components (colors per section + search shows location) =====

class SectionSelect(discord.ui.Select):
    def __init__(self, view: "MasterPager", sections: List[str], current: int):
        opts = [discord.SelectOption(label=t, value=str(i), default=(i == current))
                for i, t in enumerate(sections)]
        super().__init__(placeholder="Jump to section…", min_values=1, max_values=1, options=opts, row=0)
        self.master: "MasterPager" = view

    async def callback(self, interaction: discord.Interaction):
        self.master.section_index = int(self.values[0])
        self.master.page_index = 0
        await self.master.render(interaction)


class GoToPageModal(discord.ui.Modal, title="Jump to page"):
    page_number = discord.ui.TextInput(
        label="Enter page number (1..N)",
        style=discord.TextStyle.short,
        required=True,
        max_length=6,
        placeholder="e.g. 3",
    )

    def __init__(self, master: "MasterPager"):
        super().__init__()
        self.master = master

    async def on_submit(self, interaction: discord.Interaction):
        try:
            n = int(str(self.page_number).strip())
            max_n = len(self.master.pages[self.master.section_index])
            if 1 <= n <= max_n:
                self.master.page_index = n - 1
        except Exception:
            pass
        await self.master.render(interaction)


class SearchModal(discord.ui.Modal, title="Search list"):
    query = discord.ui.TextInput(
        label="Find (case-insensitive substring)",
        style=discord.TextStyle.short,
        required=True,
        max_length=50,
        placeholder="e.g. moose, darth, 1337…",
    )

    def __init__(self, master: "MasterPager"):
        super().__init__()
        self.master = master

    async def on_submit(self, interaction: discord.Interaction):
        q = str(self.query).strip().lower()
        if not q:
            return await self.master.render(interaction)

        # Build results with section/page location hints
        results = self.master.build_search_results(q)
        if not results:
            results = ["— no matches —"]

        self.master.activate_search(q, results)
        await self.master.render(interaction)


class MasterPager(discord.ui.View):
    """Dropdown + real buttons; safe defer→edit; color per section; search shows section/page."""

    def __init__(
            self,
            owner_id: int,
            *,
            title_prefix: str,
            sections: List[Tuple[str, List[str]]],  # [(title, items)]
            icon_url: Optional[str],
            color: discord.Color,  # default/fallback color
            section_colors: Optional[List[discord.Color]] = None,  # optional color per section
    ):
        super().__init__(timeout=VIEW_TIMEOUT_SECONDS)
        self.owner_id = owner_id
        self.title_prefix = title_prefix
        self.icon_url = icon_url
        self.color = color
        self.section_colors = section_colors or []

        # originals + paginated text chunks
        self.section_titles: List[str] = [t for t, _ in sections]
        self.orig_items: List[List[str]] = [lst[:] for _, lst in sections]
        self.pages: List[List[str]] = [self._chunk_to_pages(items) for _, items in sections]

        self.section_index = 0
        self.page_index = 0
        self.search_active = False
        self.search_label: Optional[str] = None

        # Dropdown (recreated on render so selected option highlights)
        self.section_select = SectionSelect(self, self.section_titles, self.section_index)
        self.add_item(self.section_select)

        # Buttons — create ONCE and add_item ONCE
        self.btn_first = discord.ui.Button(emoji="⏮", style=discord.ButtonStyle.secondary, row=1)
        self.btn_prev = discord.ui.Button(emoji="◀", style=discord.ButtonStyle.secondary, row=1)
        self.btn_next = discord.ui.Button(emoji="▶", style=discord.ButtonStyle.secondary, row=1)
        self.btn_last = discord.ui.Button(emoji="⏭", style=discord.ButtonStyle.secondary, row=1)
        self.btn_goto = discord.ui.Button(emoji="🔢", style=discord.ButtonStyle.secondary, row=2)
        self.btn_search = discord.ui.Button(emoji="🔎", style=discord.ButtonStyle.secondary, row=2)
        self.btn_clear = discord.ui.Button(emoji="🧹", style=discord.ButtonStyle.secondary, row=2)
        self.btn_close = discord.ui.Button(emoji="🗑", style=discord.ButtonStyle.danger, row=2)

        # Bind callbacks
        self.btn_first.callback = self._on_first
        self.btn_prev.callback = self._on_prev
        self.btn_next.callback = self._on_next
        self.btn_last.callback = self._on_last
        self.btn_goto.callback = self._on_goto
        self.btn_search.callback = self._on_search
        self.btn_clear.callback = self._on_clear
        self.btn_close.callback = self._on_close

        for b in (self.btn_first, self.btn_prev, self.btn_next, self.btn_last,
                  self.btn_goto, self.btn_search, self.btn_clear, self.btn_close):
            self.add_item(b)

    # Only the invoker can operate the controls
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.owner_id

    async def on_timeout(self):
        for c in self.children:
            if isinstance(c, (discord.ui.Button, discord.ui.Select)):
                c.disabled = True

    # Nav callbacks
    async def _on_first(self, interaction: discord.Interaction):
        self.page_index = 0
        await self.render(interaction)

    async def _on_prev(self, interaction: discord.Interaction):
        self.page_index = (self.page_index - 1) % len(self.pages[self.section_index])
        await self.render(interaction)

    async def _on_next(self, interaction: discord.Interaction):
        self.page_index = (self.page_index + 1) % len(self.pages[self.section_index])
        await self.render(interaction)

    async def _on_last(self, interaction: discord.Interaction):
        self.page_index = len(self.pages[self.section_index]) - 1
        await self.render(interaction)

    async def _on_goto(self, interaction: discord.Interaction):
        await interaction.response.send_modal(GoToPageModal(self))

    async def _on_search(self, interaction: discord.Interaction):
        await interaction.response.send_modal(SearchModal(self))

    async def _on_clear(self, interaction: discord.Interaction):
        self.clear_search()
        await self.render(interaction)

    async def _on_close(self, interaction: discord.Interaction):
        # Prefer deletion; fall back to disabling controls
        for c in self.children:
            if isinstance(c, (discord.ui.Button, discord.ui.Select)):
                c.disabled = True
        try:
            if not interaction.response.is_done():
                await interaction.response.defer()
            await interaction.message.delete()
        except Exception:
            try:
                await interaction.message.edit(view=self)
            except Exception as e:
                logging.getLogger("sponsorcheck").exception("Pager close failed: %s", e)

    # Render/update (Logscan-style: defer then edit)
    async def render(self, interaction: discord.Interaction):
        # Rebuild Select with current default highlighted
        try:
            self.remove_item(self.section_select)
        except Exception:
            pass
        self.section_select = SectionSelect(self, self.section_titles, self.section_index)
        self.add_item(self.section_select)

        embed = self._make_embed()

        try:
            if not interaction.response.is_done():
                await interaction.response.defer()
        except Exception:
            pass
        try:
            await interaction.message.edit(embed=embed, view=self)
        except Exception as e:
            logging.getLogger("sponsorcheck").exception("Pager render failed: %s", e)
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("Sorry, that update failed.", ephemeral=True)
            except Exception:
                pass

    # ---------- Search helpers with location ----------
    def compute_page_number(self, section_idx: int, item_idx: int) -> int:
        """Given a section and the index of an item in orig_items, return 1-based page number."""
        items = self.orig_items[section_idx]
        page = 1
        count = 0
        buf_len = 0
        for i, s in enumerate(items):
            line_len = len(f"{BULLET}{s}\n")
            if count >= PAGE_SIZE or buf_len + line_len > MAX_EMBED_CHARS:
                page += 1
                count = 1
                buf_len = line_len
            else:
                count += 1
                buf_len += line_len
            if i == item_idx:
                return page
        return 1

    def build_search_results(self, q: str) -> List[str]:
        """Return lines annotated with section and page (e.g., 'name — in OK (current + role), page 2')."""
        out: List[str] = []
        for sec_i, items in enumerate(self.orig_items):
            if sec_i == 0:  # skip Summary
                continue
            title = self.section_titles[sec_i]
            for idx, s in enumerate(items):
                if q in s.lower():
                    page = self.compute_page_number(sec_i, idx)
                    out.append(f"{s}  — _in {title}, page {page}_")
        return out

    # ---------- Embed building ----------
    def _chunk_to_pages(self, items: List[str]) -> List[str]:
        if not items:
            return ["—"]
        pages, buf, count = [], "", 0
        for it in items:
            line = f"{BULLET}{it}\n"
            if count >= PAGE_SIZE or len(buf) + len(line) > MAX_EMBED_CHARS:
                pages.append(buf.rstrip());
                buf = line;
                count = 1
            else:
                buf += line;
                count += 1
        if buf:
            pages.append(buf.rstrip())
        return pages

    def _current_title(self) -> str:
        base = f"{self.title_prefix} • {self.section_titles[self.section_index]}"
        if self.search_active and self.search_label:
            base += f" (search: {self.search_label})"
        return base

    def _resolve_color(self) -> discord.Color:
        # Only use gray when actually on search results section
        if self.search_active and self.section_index == len(self.orig_items):
            return discord.Color.light_grey()
        if 0 <= self.section_index < len(self.section_colors):
            return self.section_colors[self.section_index]
        return self.color

    def _make_embed(self) -> discord.Embed:
        body = self.pages[self.section_index][self.page_index]
        e = discord.Embed(title=self._current_title(), description=body, color=self._resolve_color())
        e.set_author(name="SponsorCheck")
        if self.icon_url:
            try:
                e.set_thumbnail(url=self.icon_url)
            except Exception:
                pass
        e.set_footer(
            text=f"Page {self.page_index + 1}/{len(self.pages[self.section_index])} • Buttons disable after {VIEW_TIMEOUT_SECONDS // 60}m")
        return e

    # search mode becomes a temporary extra section at the end
    def activate_search(self, query: str, results: List[str]):
        self.search_active = True
        self.search_label = query
        title = "Search results"
        if len(self.pages) == len(self.orig_items):
            self.section_titles.append(title)
            self.pages.append(self._chunk_to_pages(results))
            if self.section_colors:
                self.section_colors.append(discord.Color.light_grey())
        else:
            self.section_titles[-1] = title
            self.pages[-1] = self._chunk_to_pages(results)
        self.section_index = len(self.pages) - 1
        self.page_index = 0

    def clear_search(self):
        if not self.search_active:
            return
        self.search_active = False
        self.search_label = None
        if len(self.pages) > len(self.orig_items):
            self.pages.pop()
            self.section_titles.pop()
            if self.section_colors and len(self.section_colors) > len(self.orig_items):
                self.section_colors.pop()
        self.section_index = 0
        self.page_index = 0


# ===== Cog =====

class GitHubAuthError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class SponsorCheck(commands.Cog):
    """GitHub Sponsors via GraphQL (no scraping). Master-embed pagination with search + file attachments."""

    def __init__(self, bot):
        self.bot = bot
        self._pat: Optional[str] = None
        self._pat_source: Optional[str] = None
        self._load_pat(initial=True)

    # ---------- Role gate for prefix commands ----------
    async def cog_check(self, ctx: commands.Context) -> bool:
        if not ctx.guild:
            return False
        user_role_ids = {r.id for r in ctx.author.roles}
        allowed = (ALLOWED_ROLE_IDS & user_role_ids) or ctx.author.guild_permissions.manage_guild
        return bool(allowed)

    # ---------- Token helpers ----------
    def _load_pat(self, initial: bool = False, force: bool = False) -> None:
        if self._pat and not force:
            return
        pat_env = os.environ.get("GITHUB_PAT")
        if pat_env:
            self._pat = pat_env.strip()
            self._pat_source = "env"
            return
        try:
            with open(PAT_FILE, "r", encoding="utf-8") as f:
                tok = f.read().strip()
            if tok:
                self._pat = tok
                self._pat_source = "file"
                return
        except FileNotFoundError:
            pass
        except Exception as e:
            mylogger.error(f"PAT read error: {e}")
        self._pat, self._pat_source = None, None

    def _ensure_pat(self) -> None:
        if not self._pat:
            self._load_pat(force=True)

    # ---------- Embeds ----------
    def _safe_desc(self, text: str) -> str:
        return (text or "") + "\u200b"

    def _embed(self, title: str, desc: str, *, color: discord.Color,
               guild: Optional[discord.Guild] = None) -> discord.Embed:
        e = discord.Embed(title=title, description=self._safe_desc(desc), color=color)
        e.set_author(name="SponsorCheck")
        if guild and guild.icon:
            try:
                e.set_thumbnail(url=guild.icon.url)
            except Exception:
                pass
        return e

    def _embed_ok(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.green(), **kw)

    def _embed_warn(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.gold(), **kw)

    def _embed_err(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.red(), **kw)

    def _embed_info(self, t, d, **kw):
        return self._embed(t, d, color=discord.Color.blurple(), **kw)

    # ---------- Member / avatar utils ----------
    async def _github_avatar(self, login: str) -> Optional[str]:
        if not login:
            return None
        url = f"https://api.github.com/users/{login}"
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa)",
        }
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
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
        try:
            if member:
                embed.set_thumbnail(url=member.display_avatar.url)
        except Exception:
            pass
        try:
            if gh_avatar:
                embed.set_image(url=gh_avatar)
        except Exception:
            pass

    # ---------- Role helpers ----------
    def _has_sponsor_role(self, guild: discord.Guild, member: Optional[discord.Member]) -> bool:
        if not (guild and member):
            return False
        role = guild.get_role(SPONSOR_ROLE_ID)
        return bool(role and role in member.roles)

    async def _try_grant_role(self, guild: discord.Guild, member: discord.Member) -> Tuple[bool, str]:
        role = guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            return False, f"Role id `{SPONSOR_ROLE_ID}` not found."
        if role in member.roles:
            return True, f"Already has `{role.name}`."

        me = guild.me
        if not me:
            return False, "Bot member not resolved."
        if not me.guild_permissions.manage_roles:
            return False, "Bot lacks `Manage Roles` permission."
        if guild.owner_id == member.id:
            return False, "Target is the server owner (bots cannot modify owners)."

        role_pos = getattr(role, "position", -1)
        me_pos = getattr(me.top_role, "position", -1)
        user_pos = getattr(member.top_role, "position", -1)
        if role_pos >= me_pos:
            return False, f"Bot’s top role is not above `{role.name}`."
        if user_pos >= me_pos and member != me:
            return False, "Target member has a role equal/higher than the bot."

        try:
            await member.add_roles(role, reason="SponsorCheck: auto-grant on sponsor hit")
            return True, f"Granted `{role.name}`."
        except discord.Forbidden:
            return False, "Discord forbids adding this role (permissions/hierarchy)."
        except discord.HTTPException as e:
            return False, f"HTTP error: {e}"

    # ---------- GitHub GraphQL ----------
    async def _fetch_all_sponsors(self) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """Return (current_public, current_private, past_public, past_private)."""
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
            "User-Agent": "Red-SponsorCheck/1.0 (+Kometa)",
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
                    priv = (n.get("privacyLevel") or "").upper() == "PRIVATE"
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

    # ---------- Common helpers ----------
    async def _send_file_always(self, ctx: commands.Context, lines: List[str], base_name: str):
        text = "".join((ln if ln.endswith("\n") else ln + "\n") for ln in lines)
        bio = BytesIO(text.encode("utf-8"))
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{base_name}_{ctx.guild.id}_{ts}.txt"
        await ctx.send(file=discord.File(bio, filename=filename))

    def _gh_candidates_from_names(self, ksn: str, dsn: str, override: Optional[str]) -> List[str]:
        def norm(s: Optional[str]) -> str:
            if not s:
                return ""
            s = s.strip().lstrip("@").lower().replace(" ", "").replace("_", "").replace(".", "")
            return "".join(ch for ch in s if alnum(ch) or ch == "-")

        def alnum(ch: str) -> bool:
            return ("a" <= ch <= "z") or ("0" <= ch <= "9")

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
                if sep and sep in raw:
                    tail = norm(raw.split(sep)[-1])
                    if tail and tail not in cands:
                        cands.append(tail)
                    if tail:
                        stripped_tail = tail.rstrip("0123456789")
                        if stripped_tail and stripped_tail != tail and stripped_tail not in cands:
                            cands.append(stripped_tail)
        return cands

    # =====================================================================
    # Core logic shared by prefix and slash
    # =====================================================================

    async def _sponsor_core(self, ctx: commands.Context, username: str):
        self._ensure_pat()
        if not self._pat:
            return await ctx.send(embed=self._embed_err("GitHub token", "Not configured.", guild=ctx.guild))

        target = (username or "").lstrip("@").strip()
        if not target:
            return await ctx.send(embed=self._embed_info("Usage", "Try `/sponsor bullmoose20`.", guild=ctx.guild))

        # Easter egg
        if target.lower() in EASTER_EGG_NAMES:
            egg = discord.Embed(
                title="You found the hidden egg! 🥚",
                description=EASTER_EGG_DESC.format(who=target),
                color=discord.Color.gold(),
            )
            egg.set_author(name="SponsorCheck")
            return await ctx.send(embed=egg)

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await ctx.send(embed=self._embed_err("GitHub API", e.detail, guild=ctx.guild))
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

        # Direct public
        if t in union_public:
            status = "current" if t in current_public else "past"
            gh_avatar = await self._github_avatar(target)
            em = self._embed_ok("Sponsor check", f"**{target}** is a **{status}** public sponsor of **{SPONSORABLE}**.",
                                guild=ctx.guild)
            self._attach_person_avatars(em, possible_member, gh_avatar)
            if possible_member:
                ok, msg = await self._try_grant_role(ctx.guild, possible_member)
                em.add_field(name="Role action", value=msg, inline=False)
            return await ctx.send(embed=em)

        # Direct private
        if t in union_private:
            status = "current" if t in current_private else "past"
            em = self._embed_warn("Sponsor check", f"**{target}** is a **{status}** sponsor of **{SPONSORABLE}**.",
                                  guild=ctx.guild)
            em.add_field(name="Privacy", value="Private", inline=True)
            self._attach_person_avatars(em, possible_member, None)
            if possible_member:
                ok, msg = await self._try_grant_role(ctx.guild, possible_member)
                em.add_field(name="Role action", value=msg, inline=False)
            return await ctx.send(embed=em)

        # KSN/DSN → GH candidates
        candidate_member = self._best_member_match(ctx.guild, target)
        if candidate_member:
            ksn = (candidate_member.display_name or "").strip()
            dsn = (candidate_member.name or "").strip()
            override = GH_USERNAME_MAP.get(candidate_member.id)
            candidates = self._gh_candidates_from_names(ksn, dsn, override)

            for cand in candidates:
                lc = cand.lower()
                if lc in union_public:
                    status = "current" if lc in current_public else "past"
                    gh_avatar = await self._github_avatar(cand)
                    em = self._embed_ok("Sponsor check",
                                        f"**{ksn}** → **{dsn}** → **{status}** public sponsor of **{SPONSORABLE}**.",
                                        guild=ctx.guild)
                    self._attach_person_avatars(em, candidate_member, gh_avatar)
                    ok, msg = await self._try_grant_role(ctx.guild, candidate_member)
                    em.add_field(name="Role action", value=msg, inline=False)
                    return await ctx.send(embed=em)

            for cand in candidates:
                lc = cand.lower()
                if lc in union_private:
                    status = "current" if lc in current_private else "past"
                    em = self._embed_warn("Sponsor check",
                                          f"**{ksn}** → **{dsn}** → **{status}** sponsor of **{SPONSORABLE}**.",
                                          guild=ctx.guild)
                    em.add_field(name="Privacy", value="Private", inline=True)
                    self._attach_person_avatars(em, candidate_member, None)
                    ok, msg = await self._try_grant_role(ctx.guild, candidate_member)
                    em.add_field(name="Role action", value=msg, inline=False)
                    return await ctx.send(embed=em)

        # Not found → if user already has the role, warn about mismatch
        if self._has_sponsor_role(ctx.guild, possible_member):
            ksn = (possible_member.display_name or "").strip() if possible_member else ""
            dsn = (possible_member.name or "").strip() if possible_member else ""
            override = GH_USERNAME_MAP.get(possible_member.id) if possible_member else None
            candidates = self._gh_candidates_from_names(ksn, dsn, override) if possible_member else []
            cand_text = ", ".join(candidates[:6]) if candidates else "—"

            em = self._embed_warn(
                "Sponsor check",
                f"**{target}** is **not on record** as a GitHub sponsor of **{SPONSORABLE}**, "
                f"**but already has** the `{ctx.guild.get_role(SPONSOR_ROLE_ID).name}` role.",
                guild=ctx.guild,
            )
            em.add_field(
                name="What this likely means",
                value=("• GitHub login differs → add mapping in `GH_USERNAME_MAP`\n"
                       "• Private sponsor → add to `VERIFIED_PRIVATE_IDS`/`VERIFIED_PRIVATE_USERNAMES`\n"
                       "• Or the role was granted by mistake"),
                inline=False,
            )
            em.add_field(name="Candidate GH usernames (heuristic)", value=cand_text, inline=False)
            if possible_member:
                try:
                    em.set_thumbnail(url=possible_member.display_avatar.url)
                except Exception:
                    pass
            return await ctx.send(embed=em)

        # Hard not-found
        em = self._embed_err("Sponsor check",
                             f"**{target}** does not appear as a sponsor of **{SPONSORABLE}** (current or past).",
                             guild=ctx.guild)
        if possible_member:
            try:
                em.set_thumbnail(url=possible_member.display_avatar.url)
            except Exception:
                pass
        return await ctx.send(embed=em)

    async def _sponsorlist_core(self, ctx: commands.Context):
        self._ensure_pat()
        if not self._pat:
            return await ctx.send(embed=self._embed_err("GitHub token", "Not configured.", guild=ctx.guild))
        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await ctx.send(embed=self._embed_err("GitHub API", e.detail, guild=ctx.guild))
        except Exception as e:
            mylogger.exception("sponsorlist(): API failure")
            return await ctx.send(embed=self._embed_err("GitHub API error", f"`{e}`", guild=ctx.guild))

        counts = (
            f"**Current sponsors:** **{len(curr_pub) + len(curr_priv)}** "
            f"(public **{len(curr_pub)}**, private **{len(curr_priv)}**)\n"
            f"**Past sponsors:** **{len(past_pub) + len(past_priv)}** "
            f"(public **{len(past_pub)}**, private **{len(past_priv)}**)"
        )

        # Always attach the full text file
        lines = [
            f"Public sponsors for {SPONSORABLE} (GitHub API)\n",
            f"Current: {len(curr_pub) + len(curr_priv)}  (public: {len(curr_pub)}, private: {len(curr_priv)})\n",
            "Current (public): " + (", ".join(sorted(curr_pub, key=str.lower)) if curr_pub else "—") + "\n\n",
            f"Past: {len(past_pub) + len(past_priv)}  (public: {len(past_pub)}, private: {len(past_priv)})\n",
            "Past (public): " + (", ".join(sorted(past_pub, key=str.lower)) if past_pub else "—") + "\n",
        ]
        await self._send_file_always(ctx, lines, "sponsorlist")

        # Master embed pager (Summary + Current public + Past public)
        summary_items = [counts.replace("**", "")]
        current_items = sorted(curr_pub, key=str.lower)
        past_items = sorted(past_pub, key=str.lower)

        sections: List[Tuple[str, List[str]]] = [
            ("Summary", summary_items),
            (f"Current (public) — {SPONSORABLE}", current_items),
            (f"Past (public) — {SPONSORABLE}", past_items),
        ]

        icon_url = None
        if ctx.guild and ctx.guild.icon:
            try:
                icon_url = ctx.guild.icon.url
            except Exception:
                pass

        # Color-coding for sponsorlist (simple & intuitive)
        section_colors = [
            discord.Color.blurple(),  # Summary
            discord.Color.green(),  # Current public
            discord.Color.orange(),  # Past public
        ]

        view = MasterPager(
            owner_id=ctx.author.id,
            title_prefix="Sponsor list",
            sections=sections,
            icon_url=icon_url,
            color=discord.Color.blurple(),  # fallback
            section_colors=section_colors,
        )
        await ctx.send(embed=view._make_embed(), view=view)

    async def _sponsorreport_core(self, ctx: commands.Context, limit: int):
        self._ensure_pat()
        if not self._pat:
            return await ctx.send(embed=self._embed_err("GitHub token", "Not configured.", guild=ctx.guild))

        role = ctx.guild.get_role(SPONSOR_ROLE_ID)
        if not role:
            return await ctx.send(
                embed=self._embed_err("Sponsor role not found", f"ID `{SPONSOR_ROLE_ID}`", guild=ctx.guild))

        try:
            curr_pub, curr_priv, past_pub, past_priv = await self._fetch_all_sponsors()
        except GitHubAuthError as e:
            return await ctx.send(embed=self._embed_err("GitHub API", e.detail, guild=ctx.guild))
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
            line = f"{disp} (`{m.id}`)"
            hit = member_to_hit.get(m.id)
            if hit == "current":
                (ok_role if m.id in role_member_ids else grant_role).append(line)
            elif hit == "past":
                if m.id in role_member_ids:
                    lapsed_role.append(line)
            else:
                if m.id in role_member_ids:
                    never_role.append(line)

        current_not_in_server = [gh for gh in sorted(current_all) if gh not in gh_to_member]

        summary = (
            f"Current GH sponsors: {current_total} (public {len(curr_pub)}, private {len(curr_priv)})\n"
            f"Past GH sponsors: {past_total} (public {len(past_pub)}, private {len(past_priv)})\n"
            f"Public union: {public_union_n} • Private union: {private_union_n}\n"
            f"Discord members with Sponsor role: {len(role_member_ids)}\n\n"
            f"Grant Sponsor role: {len(grant_role)}\n"
            f"OK (current + role): {len(ok_role)}\n"
            f"OK (past + role): {len(lapsed_role)}\n"
            f"Has role but never sponsored (or needs mapping): {len(never_role)}\n"
            f"Current sponsors not in server (GitHub usernames): {len(current_not_in_server)}"
        )

        # Always attach the full text file
        def section_block(title: str, items: List[str]) -> List[str]:
            out = [f"{title} ({len(items)}):\n"]
            if items:
                out.extend([f"- {i}" for i in items[:limit]])
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
        lines += section_block("OK (past & has role)", lapsed_role)
        lines += section_block("Has role but never sponsored (or needs mapping)", never_role)
        lines += section_block("Current sponsors not in server (GitHub usernames)", current_not_in_server)
        lines.append(
            "Notes: Private identities come from the GitHub API via PAT; they’re matched for reconciliation but not printed.\n")
        await self._send_file_always(ctx, lines, "sponsorreport")

        # Build master pager sections
        icon_url = None
        if ctx.guild and ctx.guild.icon:
            try:
                icon_url = ctx.guild.icon.url
            except Exception:
                pass

        sections: List[Tuple[str, List[str]]] = [
            ("Summary", [summary.replace("**", "")]),
            ("Grant Sponsor role (current in server without role)", grant_role),
            ("OK (current + role)", ok_role),
            ("OK (past + role)", lapsed_role),
            ("Has role but never sponsored (or needs mapping)", never_role),
            ("Current sponsors not in server (GitHub usernames)", current_not_in_server),
        ]

        # Your requested colors (in this exact order)
        section_colors = [
            discord.Color.blurple(),  # Summary
            discord.Color.orange(),  # Grant Sponsor role
            discord.Color.green(),  # OK (current + role)
            discord.Color.green(),  # OK (past + role)
            discord.Color.red(),  # Has role but never sponsored
            discord.Color.yellow(),  # Current sponsors not in server
        ]

        view = MasterPager(
            owner_id=ctx.author.id,
            title_prefix="Sponsor report",
            sections=sections,
            icon_url=icon_url,
            color=discord.Color.blurple(),  # fallback
            section_colors=section_colors,
        )
        await ctx.send(embed=view._make_embed(), view=view)

    # =====================================================================
    # Prefix commands
    # =====================================================================

    @commands.command(name="sponsor")
    @commands.guild_only()
    async def sponsor_prefix(self, ctx: commands.Context, username: str):
        await self._sponsor_core(ctx, username)

    @commands.command(name="sponsorlist")
    @commands.guild_only()
    async def sponsorlist_prefix(self, ctx: commands.Context):
        await self._sponsorlist_core(ctx)

    @commands.command(name="sponsorreport")
    @commands.guild_only()
    async def sponsorreport_prefix(self, ctx: commands.Context, limit: int = 2000):
        await self._sponsorreport_core(ctx, limit)

    # =====================================================================
    # Slash commands (explicit, like threads.py)
    # =====================================================================

    @app_commands.command(name="sponsor", description="Check a user’s GitHub sponsor status.")
    @app_commands.describe(username="GitHub or Discord name to check")
    async def sponsor_slash(self, interaction: discord.Interaction, username: str):
        ctx = await commands.Context.from_interaction(interaction)
        await self._sponsor_core(ctx, username)

    @app_commands.command(name="sponsorlist", description="List public sponsors (master embed + file).")
    async def sponsorlist_slash(self, interaction: discord.Interaction):
        ctx = await commands.Context.from_interaction(interaction)
        await self._sponsorlist_core(ctx)

    @app_commands.command(name="sponsorreport",
                          description="Reconciliation report (summary + sections; master embed + file).")
    @app_commands.describe(limit="Max lines per section written into the attached text file (default 2000)")
    async def sponsorreport_slash(self, interaction: discord.Interaction, limit: int = 2000):
        ctx = await commands.Context.from_interaction(interaction)
        await self._sponsorreport_core(ctx, limit)


# Red entrypoint
async def setup(bot):
    await bot.add_cog(SponsorCheck(bot))
