import discord
import logging
from redbot.core import commands, app_commands

ALLOWED_ROLE_IDS = [938443185347244033, 929756550380286153]

# Create logger
mylogger = logging.getLogger('test_support')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG


class RedBotCogSupport(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id

    @commands.hybrid_command(name="kometa-help")
    @app_commands.describe(message_link="The discord message link you want to create a new kometa-help forum post.")
    async def support(self, ctx, message_link: discord.Message):
        try:
            # Check if the linked message is associated with a guild
            if not message_link.guild:
                return await ctx.send("The specified message is not associated with a guild. Aborting...")

            # Attempt to fetch the member corresponding to the author of the linked message
            message_author = message_link.author
            if not isinstance(message_author, discord.Member):
                # The author is not a guild member (likely a bot or user outside the guild)
                return await ctx.send("The author of the linked message is not a member of the guild. Aborting...")

            # Log command invocation details
            author_name = f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author else "Unknown"
            guild_name = ctx.guild.name if ctx.guild else "Direct Message"
            channel_name = ctx.channel.name if isinstance(ctx.channel, discord.TextChannel) else "Direct Message"
        
            mylogger.info(f"Support invoked by {author_name} in {guild_name}/{channel_name} (ID: {ctx.guild.id if ctx.guild else 'N/A'}/{ctx.channel.id if ctx.guild else 'N/A'})")
            # mylogger.info(f"Processing message: {message_link.id}")
            
            # Log the invoker and their roles for troubleshooting
            invoker_display_name = ctx.author.display_name
            invoker_username = ctx.author.name
            mylogger.info(f"Invoker: {invoker_display_name} ({invoker_username}), Roles: {ctx.author.roles}")
            mylogger.info(f"message_link.author: {message_link.author}")
            mylogger.info(f"self.bot.user: {self.bot.user}")

            # Check if the author has the "Support" role or any other allowed roles
            invoker_has_allowed_role = any(role.id in ALLOWED_ROLE_IDS for role in ctx.author.roles)

            # Log the result of the role check for troubleshooting
            mylogger.info(f"Has allowed role: {invoker_has_allowed_role}")

            if invoker_has_allowed_role or message_link.author == ctx.author:
                # Allow the command since the invoker has an allowed role or is the author of the linked message
                pass
            else:
                await ctx.send("You don't have permission to use this command or the specified message is not yours.")
                return

            if isinstance(message_link.author, discord.Member) and message_link.guild:
                # Retrieve the display name (nickname) of the message author within the guild
                author_display_name = message_link.author.display_name
                
                # Send an acknowledgment message
                await ctx.send("Processing your request...")

                # Determine the appropriate forum channel ID based on bot user ID
                forum_channel_id = None
                if self.bot_uid == 1138446898487894206:  # Botmoose20
                    forum_channel_id = 1138466814519693412  # #bot-forums
                elif self.bot_uid == 1422494031388344340:  # Luma
                    forum_channel_id = 1006644783743258635  # #kometa-help

                # Get the forum channel
                forum_channel = self.bot.get_channel(forum_channel_id)
                if not forum_channel:
                    return await ctx.send(f'Could not find a channel with ID {forum_channel_id}.')

                # Construct subject and description with author's display name (nickname)
                subject = f"{author_display_name} ({message_link.author.name}) needs assistance. Invoked by {invoker_display_name}"

                description = f"**{author_display_name}**, please continue the conversation here.\n\n**Content:** {message_link.content}\n\n**Attachments:**(if any)"

                # Create a thread in the forum channel
                thread, message = await forum_channel.create_thread(name=f"{subject}", content=f"{description}", files=[await a.to_file() for a in message_link.attachments])

                # Delete the original message and leave a trace
                await message_link.delete()
                trace_message = await ctx.send(f"A message by {author_display_name} ({message_link.author.name}) was moved to {message.jump_url} by {invoker_display_name}")
            else:
                await ctx.send("The specified message is not associated with a guild member. Aborting...")

        except Exception as e:
            mylogger.exception('An error occurred during message processing:', exc_info=e)
            await ctx.send("An error occurred while processing your request.")
