from redbot.core import commands
import discord

class ChannelMonitor(commands.Cog):
    """Monitor a specific channel and prompt users to use the designated community showcase channel for new posts."""

    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        # Ignore messages from bots or DMs
        if message.author.bot or not message.guild:
            return

        # Only act on messages in the monitored channels
        if message.channel.id not in {921844476283064381, 927936511238869042}:
            return

        # Delete the posted message
        try:
            await message.delete()
        except discord.errors.Forbidden:
            # Bot might not have permission to delete messages
            return

        # Send a reminder message that auto-deletes after 30 seconds
        try:
            reminder = await message.channel.send(
                f"{message.author.mention} This channel is now locked for new posts.\n- All new creations should be posted in <#1349035437846695966>.\n- You may still chat in existing threads within this channel if needed."
            )
            await reminder.delete(delay=30)
        except discord.errors.Forbidden:
            # Bot might not have permissions to send messages or delete the reminder
            pass

def setup(bot):
    bot.add_cog(ChannelMonitor(bot))
