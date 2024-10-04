import os
import discord
import requests
import logging
import time  # To add throttling
from discord.ext import commands
from redbot.core import commands, app_commands
from dotenv import load_dotenv
import asyncio  # To handle the timeout

# Load environment variables from .env file
load_dotenv()

# Get the GitHub token from the environment variable
GITHUB_API_TOKEN = os.getenv("GITHUB_API_TOKEN")

# Create logger
mylogger = logging.getLogger('version')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG

# Headers for authenticated API requests
headers = {
    "Authorization": f"token {GITHUB_API_TOKEN}" if GITHUB_API_TOKEN else None
}

class MyVersion(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def get_commit_info_from_github_api(self, owner, repo, branch, path):
        """Fetches the latest commit info from the GitHub API for a file in a specific branch."""
        url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        params = {
            "path": path,  # File path
            "sha": branch  # Branch name
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            # Extract the latest commit date and message
            latest_commit = data[0]
            commit_date = latest_commit['commit']['committer']['date']
            commit_message = latest_commit['commit']['message']
            return commit_date, commit_message

        except requests.RequestException as e:
            mylogger.error(f"Error fetching commit info from {url}: {e}")
            return "Unknown", "Unknown"

    @commands.command(name="version")
    @app_commands.describe(message_link="Fetch the current release versions of Kometa, ImageMaid, and Kometa Overlay Reset")
    @commands.cooldown(1, 60, commands.BucketType.user)  # 1 command per 60 seconds per user
    async def version(self, ctx: commands.Context):
        owner = "Kometa-Team"
        repos = {
            "Kometa": {"repo": "Kometa", "branches": ["master", "develop", "nightly"], "path": "VERSION"},
            "ImageMaid": {"repo": "ImageMaid", "branches": ["master", "develop", "nightly"], "path": "VERSION"},
            "Overlay Reset": {"repo": "Overlay-Reset", "branches": ["master", "develop", "nightly"], "path": "VERSION"}
        }

        def get_versions_for_project(project_name, project_data):
            """Fetches versions and commit dates for the project."""
            versions = {}
            repo_name = project_data['repo']
            branches = project_data['branches']
            path = project_data['path']

            for branch in branches:
                commit_date, commit_message = self.get_commit_info_from_github_api(owner, repo_name, branch, path)
                versions[branch] = (commit_message, commit_date)

                # Throttle requests to avoid hitting API rate limits
                time.sleep(2)

            return versions

        async def build_version_embed(project_name, versions, user):
            embed = discord.Embed(color=discord.Color.random())

            version_text = ""
            for name, (version, date) in versions.items():
                if version != "Unknown":
                    version_text += f"{name.capitalize()}: {version} (Updated: {date})\n"

            if version_text:
                embed.add_field(name=f"{project_name} Versions", value=version_text.strip(), inline=False)

            embed.set_footer(text="Click the button below to see update instructions.")
            return embed

        async def build_update_instructions_embed(user):
            embed = discord.Embed(title="Update Instructions", description=f"Here are the commands to use:", color=discord.Color.random())
            update_text = "`!updategit` if you are running kometateam apps locally\n`!updatedocker` if using kometateam apps in Docker\n`!updateunraid` for kometateam apps in Unraid"
            embed.add_field(name="Commands", value=update_text, inline=False)
            return embed

        class UpdateInstructionsButton(discord.ui.Button):
            def __init__(self, user):
                super().__init__(label="Update Instructions", style=discord.ButtonStyle.primary)
                self.user = user

            async def callback(self, interaction: discord.Interaction):
                try:
                    embed = await build_update_instructions_embed(self.user)
                    
                    # Ensure interaction has not been acknowledged
                    if not interaction.response.is_done():
                        await interaction.response.edit_message(embed=embed, view=None)
                    else:
                        await interaction.followup.send(embed=embed, ephemeral=True)
                except discord.errors.NotFound:
                    mylogger.error("Interaction not found or expired")
                    await interaction.followup.send("This interaction has expired. Please use `!version` again.", ephemeral=True)

        class VersionSelect(discord.ui.Select):
            def __init__(self):
                options = [
                    discord.SelectOption(label="Kometa", description="View Kometa versions"),
                    discord.SelectOption(label="ImageMaid", description="View ImageMaid versions"),
                    discord.SelectOption(label="Overlay Reset", description="View Kometa Overlay Reset versions")
                ]
                super().__init__(placeholder="Choose a project...", options=options)

            async def callback(self, interaction: discord.Interaction):
                project_name = self.values[0]
                user = interaction.user
                project_versions = get_versions_for_project(project_name, repos[project_name])

                try:
                    embed = await build_version_embed(project_name, project_versions, user)

                    # Log the response status
                    mylogger.info(f"Response is_done: {interaction.response.is_done()}")

                    # Ensure interaction is acknowledged once
                    if not interaction.response.is_done():
                        await interaction.response.edit_message(embed=embed, view=None)
                    else:
                        await interaction.followup.send(embed=embed, ephemeral=True)

                except discord.errors.NotFound:
                    mylogger.error("Interaction not found or expired")
                    await interaction.followup.send("This interaction has expired. Please use `!version` again.", ephemeral=True)

        class VersionView(discord.ui.View):
            def __init__(self, user):
                super().__init__()
                self.add_item(VersionSelect())
                self.add_item(UpdateInstructionsButton(user))

        view = VersionView(ctx.author)
        message = await ctx.send(f"Hey {ctx.author.mention}, select a project to view its current releases:", view=view)

        await asyncio.sleep(180)  # 3 minutes timeout

        for item in view.children:
            item.disabled = True

        try:
            if message.embeds:
                expired_embed = message.embeds[0]
            else:
                expired_embed = discord.Embed(title="Interaction Expired", color=discord.Color.red())

            expired_embed.set_footer(text="This interaction has expired. Please type `!version` to use it again.")
            await message.edit(embed=expired_embed, view=view)

        except discord.errors.NotFound:
            mylogger.error("Message not found or interaction expired. Couldn't edit the original message.")
