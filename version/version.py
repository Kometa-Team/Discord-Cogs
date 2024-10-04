import discord
import requests
import logging
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

    def get_commit_date_from_url(self, url):
        """Scrapes the last commit date for the VERSION file from the GitHub HTML page."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find the commit timestamp from the page
            commit_time_tag = soup.find("relative-time")
            if commit_time_tag:
                commit_date = commit_time_tag['datetime']
                return commit_date
            return "Unknown date"
        except requests.RequestException as e:
            mylogger.error(f"Error fetching commit date from {url}: {e}")
            return "Unknown date"

    @commands.command(name="version")
    @app_commands.describe(message_link="Fetch the current release versions of Kometa, ImageMaid, and Kometa Overlay Reset")
    @commands.cooldown(1, 60, commands.BucketType.user)  # 1 command per 60 seconds per user
    async def version(self, ctx: commands.Context):
        # URLs for each project
        kometa_urls = {
            "Master": "https://github.com/Kometa-Team/Kometa/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/Kometa/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/Kometa/blob/nightly/VERSION"
        }
        
        imagemaid_urls = {
            "Master": "https://github.com/Kometa-Team/ImageMaid/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/ImageMaid/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/ImageMaid/blob/nightly/VERSION"
        }
        
        overlay_reset_urls = {
            "Master": "https://github.com/Kometa-Team/Overlay-Reset/blob/master/VERSION",
            "Develop": "https://github.com/Kometa-Team/Overlay-Reset/blob/develop/VERSION",
            "Nightly": "https://github.com/Kometa-Team/Overlay-Reset/blob/nightly/VERSION"
        }

        # Function to get versions for each project along with their commit date
        def get_versions_with_dates(urls):
            versions = {}
            for name, url in urls.items():
                version = self.get_version_from_url(url)
                commit_date = self.get_commit_date_from_url(url)
                versions[name] = (version, commit_date)
            return versions

        # Fetch versions and commit dates
        kometa_versions = get_versions_with_dates(kometa_urls)
        imagemaid_versions = get_versions_with_dates(imagemaid_urls)
        overlay_reset_versions = get_versions_with_dates(overlay_reset_urls)

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

        # Wait for 10 minutes (600 seconds), then disable the buttons and dropdown
        await asyncio.sleep(600)  # 10 minutes
        
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