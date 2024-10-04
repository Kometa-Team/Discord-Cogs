import discord
import requests
import logging
import time  # To add throttling
from discord.ext import commands
from redbot.core import commands, app_commands
from bs4 import BeautifulSoup
import asyncio  # To handle the timeout

# Create logger
mylogger = logging.getLogger('version')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG

class MyVersion(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def get_version_from_url(self, url):
        # Transform GitHub URL to raw content URL
        raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('blob/', '')

        try:
            response = requests.get(raw_url)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException as e:
            mylogger.error(f"Error fetching version from {url}: {e}")
            return "Unknown"

    def get_commit_date_from_commit_page(self, url):
        """Scrapes the latest commit date from the commit history page on GitHub."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for the first commit in the list (most recent)
            commit_info = soup.find("relative-time")
            mylogger.info(f"commit_info: {commit_info}")
            if commit_info:
                commit_date = commit_info.get("datetime")
                return commit_date

            # If not found, log and return unknown
            mylogger.warning(f"Commit date not found on page: {url}")
            return "Unknown date"
        except requests.RequestException as e:
            mylogger.error(f"Error fetching commit date from {url}: {e}")
            return "Unknown date"

    @commands.command(name="version")
    @app_commands.describe(message_link="Fetch the current release versions of Kometa, ImageMaid, and Kometa Overlay Reset")
    @commands.cooldown(1, 60, commands.BucketType.user)  # 1 command per 60 seconds per user
    async def version(self, ctx: commands.Context):
        # Define the GitHub page URLs for commits (not the raw URLs)
        kometa_commit_urls = {
            "Master": "https://github.com/Kometa-Team/Kometa/commits/master/VERSION",
            # "Develop": "https://github.com/Kometa-Team/Kometa/commits/develop/VERSION",
            # "Nightly": "https://github.com/Kometa-Team/Kometa/commits/nightly/VERSION"
        }
        
        imagemaid_commit_urls = {
            # "Master": "https://github.com/Kometa-Team/ImageMaid/commits/master/VERSION",
            # "Develop": "https://github.com/Kometa-Team/ImageMaid/commits/develop/VERSION",
            # "Nightly": "https://github.com/Kometa-Team/ImageMaid/commits/nightly/VERSION"
        }
        
        overlay_reset_commit_urls = {
            # "Master": "https://github.com/Kometa-Team/Overlay-Reset/commits/master/VERSION",
            # "Develop": "https://github.com/Kometa-Team/Overlay-Reset/commits/develop/VERSION",
            # "Nightly": "https://github.com/Kometa-Team/Overlay-Reset/commits/nightly/VERSION"
        }
        mylogger.info(f"commit_info")

        # Fetch version and commit date for each project
        def get_versions_with_commit_dates(version_urls, commit_urls):
            versions = {}
            for name in version_urls.keys():
                version = self.get_version_from_url(version_urls[name])  # Fetch the version content
                commit_date = self.get_commit_date_from_commit_page(commit_urls[name])  # Fetch the latest commit date
                versions[name] = (version, commit_date)

                # Add a delay between requests to avoid hitting rate limits
                time.sleep(2)  # Sleep for 2 seconds between requests

            return versions

        # Define raw URLs for fetching the version content
        kometa_version_urls = {
            "Master": "https://github.com/Kometa-Team/Kometa/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/Kometa/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/Kometa/blob/nightly/VERSION"
        }
        
        imagemaid_version_urls = {
            "Master": "https://github.com/Kometa-Team/ImageMaid/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/ImageMaid/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/ImageMaid/blob/nightly/VERSION"
        }
        
        overlay_reset_version_urls = {
            "Master": "https://github.com/Kometa-Team/Overlay-Reset/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/Overlay-Reset/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/Overlay-Reset/blob/nightly/VERSION"
        }

        # Fetch versions and commit dates for all projects
        kometa_versions = get_versions_with_commit_dates(kometa_version_urls, kometa_commit_urls)
        imagemaid_versions = get_versions_with_commit_dates(imagemaid_version_urls, imagemaid_commit_urls)
        overlay_reset_versions = get_versions_with_commit_dates(overlay_reset_version_urls, overlay_reset_commit_urls)

        # Build the version information embed
        async def build_version_embed(project_name, versions, user):
            embed = discord.Embed(
                color=discord.Color.random()  # Random color
            )

            version_text = ""
            for name, (version, date) in versions.items():
                if version != "Unknown":
                    version_text += f"{name}: {version} (Updated: {date})\n"
            
            # Only add the field if version_text is not empty
            if version_text:
                embed.add_field(name=f"{project_name} Versions", value=version_text.strip(), inline=False)

            # Mention the user that the update instructions are on a separate page
            embed.set_footer(text="Click the button below to see update instructions.")
            return embed

        # Build the update instructions embed
        async def build_update_instructions_embed(user):
            embed = discord.Embed(
                title="Update Instructions",
                description=f"Here are the commands to use in our Discord server to get instructions:",
                color=discord.Color.random()  # Random color
            )

            update_text = (
                "`!updategit` if you are running Kometa locally (i.e. you cloned the repository using Git)\n\n"
                "`!updatedocker` if you are running Kometa within Docker\n\n"
                "`!updateunraid` if you are running Docker on Unraid"
            )
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
                await interaction.response.edit_message(embed=embed, view=self.view)  # Keep the button view active

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
                if project_name == "Kometa":
                    embed = await build_version_embed("Kometa", kometa_versions, user)
                elif project_name == "ImageMaid":
                    embed = await build_version_embed("ImageMaid", imagemaid_versions, user)
                else:
                    embed = await build_version_embed("Kometa Overlay Reset", overlay_reset_versions, user)

                # Show the version info with a button to view update instructions
                await interaction.response.edit_message(embed=embed, view=self.view)  # Keep dropdown and button view active

        # View to handle the dropdown menu and button
        class VersionView(discord.ui.View):
            def __init__(self, user):
                super().__init__()
                self.add_item(VersionSelect())
                self.add_item(UpdateInstructionsButton(user))  # Add the update instructions button

        # Send the initial message with the dropdown and button
        view = VersionView(ctx.author)  # Create the view to keep track of it
        message = await ctx.send(f"Hey {ctx.author.mention}, select a project to view its current releases:", view=view)

        # Wait for 3 minutes (180 seconds), then disable the buttons and dropdown
        await asyncio.sleep(180)  # 3 minutes
        
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
        expired_embed.set_footer(text="This interaction has expired. Please type `!version` to use it again.")

        # Edit the message to disable the components and show the expired message
        await message.edit(embed=expired_embed, view=view)  # Use the original view with disabled components
