import discord
import requests
import logging
from discord.ext import commands
from redbot.core import commands, app_commands

# Create logger
mylogger = logging.getLogger('version_fetcher')
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
    @app_commands.describe(message_link="Fetch the current release versions of Kometa")
    @commands.cooldown(1, 60, commands.BucketType.user)  # 1 command per 60 seconds per user
    async def version(self, ctx: commands.Context):
        try:
            # URLs to fetch versions from
            urls = {
                "Master": "https://github.com/Kometa-Team/Kometa/blob/master/VERSION",
                "Develop": "https://github.com/Kometa-Team/Kometa/blob/develop/VERSION",
                "Nightly": "https://github.com/Kometa-Team/Kometa/blob/nightly/VERSION"
            }

            # Fetch version content from each URL
            versions = {name: self.get_version_from_url(url) for name, url in urls.items()}

            # Create the embedded message
            embed = discord.Embed(
                title="Current Kometa Releases",
                description="Here are the current versions of Kometa across different branches.",
                color=discord.Color.blue()
            )

            # Add version information to the embed
            for name, version in versions.items():
                embed.add_field(name=f"{name}:", value=version, inline=False)

            # Add the extra guidance text
            update_text = (
                "If you are looking for guidance on how to update Kometa, please type one of the following commands\n\n"
                "`!updategit` if you are running Kometa locally (i.e. you cloned the repository using Git)\n\n"
                "`!updatedocker` if you are running Kometa within docker\n\n"
                "`!updateunraid` if you are running docker on Unraid"
            )
            embed.add_field(name="Update Instructions", value=update_text, inline=False)

            # embed.set_footer(text="Please refer to the official documentation for more details.")

            # Send the embed message
            await ctx.send(embed=embed)

        except Exception as e:
            mylogger.error(f"Error fetching versions: {e}")
            await ctx.send(f"An error occurred while fetching the versions: {e}")
