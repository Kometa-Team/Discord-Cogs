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
        # Extract necessary information for logging
        author_name = f"{ctx.author.name}#{ctx.author.discriminator}"
        guild_name = ctx.guild.name if ctx.guild else "Direct Message"
        channel_name = ctx.channel.name if isinstance(ctx.channel, discord.TextChannel) else "Direct Message"
        
        # Log the invocation details
        mylogger.info(f"version invoked by {author_name} in {guild_name}/{channel_name} (ID: {ctx.guild.id if ctx.guild else 'N/A'}/{ctx.channel.id if ctx.channel else 'N/A'})")
        
        try:
            # URLs for Kometa
            kometa_urls = {
                "Master": "https://github.com/Kometa-Team/Kometa/blob/master/VERSION",
                "Develop": "https://github.com/Kometa-Team/Kometa/blob/develop/VERSION",
                "Nightly": "https://github.com/Kometa-Team/Kometa/blob/nightly/VERSION"
            }
            
            # URLs for ImageMaid
            imagemaid_urls = {
                "Master": "https://github.com/Kometa-Team/ImageMaid/blob/master/VERSION",
                "Develop": "https://github.com/Kometa-Team/ImageMaid/blob/develop/VERSION",
                "Nightly": "https://github.com/Kometa-Team/ImageMaid/blob/nightly/VERSION"
            }
            
            # URLs for Kometa Overlay Reset
            overlay_reset_urls = {
                "Master": "https://github.com/Kometa-Team/Overlay-Reset/blob/master/VERSION",
                "Develop": "https://github.com/Kometa-Team/Overlay-Reset/blob/develop/VERSION",
                "Nightly": "https://github.com/Kometa-Team/Overlay-Reset/blob/nightly/VERSION"
            }

            # Fetch version content from each URL group
            kometa_versions = {name: self.get_version_from_url(url) for name, url in kometa_urls.items()}
            imagemaid_versions = {name: self.get_version_from_url(url) for name, url in imagemaid_urls.items()}
            overlay_reset_versions = {name: self.get_version_from_url(url) for name, url in overlay_reset_urls.items()}

            # Create the embedded message
            embed = discord.Embed(
                title="Current Releases for Kometa, ImageMaid, and Kometa Overlay Reset",
                description="Here are the current versions across different branches.",
                color=discord.Color.blue()
            )

            # Add Kometa versions to the embed with inline fields
            embed.add_field(name="**Kometa Master**", value=kometa_versions["Master"], inline=True)
            embed.add_field(name="**Kometa Develop**", value=kometa_versions["Develop"], inline=True)
            embed.add_field(name="**Kometa Nightly**", value=kometa_versions["Nightly"], inline=True)

            # Add ImageMaid versions to the embed with inline fields
            embed.add_field(name="**ImageMaid Master**", value=imagemaid_versions["Master"], inline=True)
            embed.add_field(name="**ImageMaid Develop**", value=imagemaid_versions["Develop"], inline=True)
            embed.add_field(name="**ImageMaid Nightly**", value=imagemaid_versions["Nightly"], inline=True)

            # Add Overlay Reset versions to the embed with inline fields
            embed.add_field(name="**Overlay Reset Master**", value=overlay_reset_versions["Master"], inline=True)
            embed.add_field(name="**Overlay Reset Develop**", value=overlay_reset_versions["Develop"], inline=True)
            embed.add_field(name="**Overlay Reset Nightly**", value=overlay_reset_versions["Nightly"], inline=True)

            # Add the extra guidance text
            update_text = (
                "If you are looking for guidance on how to update, please type one of the following commands:\n\n"
                "`!updategit` if you are running Kometa locally (i.e. you cloned the repository using Git)\n\n"
                "`!updatedocker` if you are running Kometa within Docker\n\n"
                "`!updateunraid` if you are running Docker on Unraid"
            )
            embed.add_field(name="Update Instructions", value=update_text, inline=False)

            # Send the embed message
            await ctx.send(embed=embed)

        except Exception as e:
            mylogger.error(f"Error fetching versions: {e}")
            await ctx.send(f"An error occurred while fetching the versions: {e}")
