import os
import discord
import requests
import logging
import time  # To add throttling
from discord.ext import commands
from redbot.core import commands, app_commands
from dotenv import load_dotenv
import asyncio  # To handle the timeout
from datetime import datetime

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

# Define the timeout duration
TIMEOUT_SECONDS = 180  # 3 minutes
API_THROTTLE_SECONDS = 0  # Throttle between API requests

class MyVersion(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def get_version_from_url(self, raw_url):
        """Fetches the version content from the raw GitHub file URL."""
        try:
            response = requests.get(raw_url)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException as e:
            mylogger.error(f"Error fetching version from {raw_url}: {e}")
            return "Unknown"

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

            # Format the commit date into a more human-readable form
            commit_date = self.format_date(commit_date)
            return commit_date

        except requests.RequestException as e:
            mylogger.error(f"Error fetching commit info from {url}: {e}")
            return "Unknown"

    def format_date(self, iso_date):
        """Converts an ISO 8601 date into a readable format."""
        try:
            # Convert the ISO 8601 string to a datetime object
            dt_obj = datetime.strptime(iso_date, '%Y-%m-%dT%H:%M:%SZ')

            # Format it into a more readable form, e.g., 'September 30, 2024 at 4:42 PM UTC'
            formatted_date = dt_obj.strftime('%Y-%m-%d at %I:%M%p UTC')
            return formatted_date
        except ValueError:
            return iso_date  # In case of formatting errors, return the original string

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

        # Log the user invoking the command
        mylogger.info(f"Version command invoked by {ctx.author} (ID: {ctx.author.id}) in {ctx.guild}/{ctx.channel}")

        # Fetch version and commit date for each project
        def get_versions_for_project(project_name, project_data):
            """Fetches versions and commit dates for the project."""
            versions = {}
            repo_name = project_data['repo']
            branches = project_data['branches']
            path = project_data['path']

            for branch in branches:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{path}"
                version = self.get_version_from_url(raw_url)
                commit_date = self.get_commit_info_from_github_api(owner, repo_name, branch, path)

                # Store the version and commit date
                versions[branch] = (version, commit_date)

                # Throttle requests to avoid hitting API rate limits
                time.sleep(API_THROTTLE_SECONDS)

            return versions

        # Build the version information embed
        async def build_version_embed(project_name, versions, user):
            embed = discord.Embed(color=discord.Color.random())

            version_text = ""
            for branch, (version, date) in versions.items():
                if version != "Unknown":
                    # Simpler format as requested
                    version_text += f"{branch.capitalize()}: {version} (Released: {date})\n"

            # Only add the field if version_text is not empty
            if version_text:
                embed.add_field(name=f"{project_name} Versions", value=version_text.strip(), inline=False)

            # Mention the user that the update instructions are on a separate page
            embed.set_footer(text="Click the button below to see update instructions.")
            return embed

        # Build the update instructions embed
        async def build_update_instructions_embed(user):
            embed = discord.Embed(title="Update Instructions", description=f"Here are the commands to use:", color=discord.Color.random())
            update_text = "`!updategit` if you are running kometateam apps locally\n`!updatedocker` if using kometateam apps in Docker\n`!updateunraid` for kometateam apps in Unraid"
            embed.add_field(name="Commands", value=update_text, inline=False)
            return embed

        # Buttons for navigation
        class UpdateInstructionsButton(discord.ui.Button):
            def __init__(self, user):
                super().__init__(label="Update Instructions", style=discord.ButtonStyle.primary)
                self.user = user

            async def callback(self, interaction: discord.Interaction):
                # Build and send the update instructions embed when button is clicked
                embed = await build_update_instructions_embed(self.user)
                await interaction.response.edit_message(embed=embed, view=self.view)  # Keep the dropdown and button view active

        # Dropdown menu interaction
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
                user = interaction.user  # Get the user who made the interaction

                # Defer the response to give the bot more time to process the data
                await interaction.response.defer()

                # Fetch versions for the selected project
                project_versions = await asyncio.to_thread(get_versions_for_project, project_name, repos[project_name])

                # Build the embed with the fetched version info
                embed = await build_version_embed(project_name, project_versions, user)

                # After fetching the data, edit the original deferred message with the new embed
                await interaction.followup.edit_message(interaction.message.id, embed=embed, view=self.view)

        # View to handle the dropdown menu and button
        class VersionView(discord.ui.View):
            def __init__(self, user):
                super().__init__()
                self.add_item(VersionSelect())
                self.add_item(UpdateInstructionsButton(user))  # Add the update instructions button

        # Send the initial message with the dropdown and button
        view = VersionView(ctx.author)  # Create the view to keep track of it
        message = await ctx.send(f"Hey {ctx.author.mention}, select a project to view its current releases. This interaction will expire in {TIMEOUT_SECONDS} seconds.", view=view)

        # Wait for the defined timeout duration, then disable the buttons and dropdown
        await asyncio.sleep(TIMEOUT_SECONDS)
        
        # Disable all components (buttons and dropdowns)
        for item in view.children:
            item.disabled = True

        # Check if the message contains embeds before accessing it
        if message.embeds:
            expired_embed = message.embeds[0]
        else:
            # Fallback if no embed is present
            expired_embed = discord.Embed(title="Interaction Expired", color=discord.Color.red())

        # Set the footer to notify the user that the interaction has expired
        expired_embed.set_footer(text=f"This interaction has expired. Please type `!version` to use it again.")

        # Edit the message to disable the components and show the expired message
        await message.edit(embed=expired_embed, view=view)  # Use the original view with disabled components