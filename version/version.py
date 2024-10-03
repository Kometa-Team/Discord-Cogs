import discord
import requests
import logging
from discord.ext import commands
from redbot.core import commands, app_commands

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

        # Function to get versions for each project
        def get_versions(urls):
            return {name: self.get_version_from_url(url) for name, url in urls.items()}

        kometa_versions = get_versions(kometa_urls)
        imagemaid_versions = get_versions(imagemaid_urls)
        overlay_reset_versions = get_versions(overlay_reset_urls)

        # Build the embed based on the selected project
        async def build_embed(project_name, versions, user):
            embed = discord.Embed(
                # title=f"Current Releases for {project_name}",
                # description=f"Here are the current versions for {project_name}.",
                color=discord.Color.blue()
            )

            version_text = ""
            if versions["Master"] != "Unknown":
                version_text += f"Master: {versions['Master']}\n"
            if versions["Develop"] != "Unknown":
                version_text += f"Develop: {versions['Develop']}\n"
            if versions["Nightly"] != "Unknown":
                version_text += f"Nightly: {versions['Nightly']}\n"
            
            # Only add the field if version_text is not empty
            if version_text:
                embed.add_field(name=f"{project_name} Versions", value=version_text.strip()+"\n", inline=False)

            # Add a new line before the "Update Instructions" header
            update_text = (
                f"Hey {user.mention}, if you are looking for guidance on how to update, "
                "type one of the following commands:\n\n"
                "`!updategit` if you are running Kometa locally (i.e. you cloned the repository using Git)\n\n"
                "`!updatedocker` if you are running Kometa within Docker\n\n"
                "`!updateunraid` if you are running Docker on Unraid"
            )
            embed.add_field(name="Update Instructions", value=update_text, inline=False)

            return embed

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
                    embed = await build_embed("Kometa", kometa_versions, user)
                elif project_name == "ImageMaid":
                    embed = await build_embed("ImageMaid", imagemaid_versions, user)
                else:
                    embed = await build_embed("Kometa Overlay Reset", overlay_reset_versions, user)

                await interaction.response.edit_message(embed=embed)

        # View to handle the dropdown menu
        class VersionView(discord.ui.View):
            def __init__(self):
                super().__init__()
                self.add_item(VersionSelect())

        # Initial message with the dropdown
        await ctx.send("Select a project to view its current releases:", view=VersionView())
