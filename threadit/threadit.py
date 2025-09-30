import discord
import logging
from redbot.core import commands, app_commands
from datetime import datetime
from typing import Optional

# Create logger
mylogger = logging.getLogger('threadit')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG


class RedBotCogThreadit(commands.Cog):
    processed_message_ids = set()

    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id
        self.processed_messages = set()  # Keep track of processed messages

    async def move_to_channel(self, message: discord.Message, target_channel_id: Optional[int] = None):
        """
        Move the message to the specified channel by sending a new message and deleting the original one.
        """
        # Check if the message has already been processed
        if message.id in self.processed_messages:
            return

        # Get the target channel
        target_channel = self.bot.get_channel(target_channel_id)

        if target_channel:
            # Collect attachment files
            files = [await attachment.to_file() for attachment in message.attachments]

            # Inform the user about the move and provide a clickable link to the new channel
            move_message = await target_channel.send(
                f"{message.author.mention}, your message has been moved here for reference:\n\n{message.content}\n\n[Original Message]({message.jump_url})",
                files=files  # Include attachments
            )

            # Delete the original message
            await message.delete()

            # Mark the message as processed
            self.processed_messages.add(message.id)
        else:
            # Log a warning if the target channel is not found
            mylogger.warning(f'Could not find a channel with ID {target_channel_id}.')

    @commands.Cog.listener()
    async def on_message(self, message):
        # Check if the message is from a direct message (DM) with the bot
        if isinstance(message.channel, discord.DMChannel):
            mylogger.info(f"Message {message.id} in DMChannel, skipping.")
            # If the message is from a DM, just return without further processing
            return
        # Log command invocation details
        author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
        guild_name = message.guild.name if message.guild else "Direct Message"
        channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"
        
        mylogger.info(f"Threadit invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")
        # mylogger.info(f"Processing message: {message.id}")

        # Check if the message has already been processed
        if message.id in self.processed_messages:
            return

        # Check if you *want* to create a thread first
        image_showcase_id = None
        config_showcase_id = None
        # Determine the appropriate target channel ID based on bot user ID
        if self.bot_uid == 1138446898487894206:  # Botmoose20
            image_showcase_id = 1186898546520236052  # #test-image-showcase
            config_showcase_id = 1186897793198071859  # #test-config-showcase
            moved_to_channel_id = 1138466667165405244  # #bot-chat
        elif self.bot_uid == 1422494031388344340:  # Luma
            image_showcase_id = 927936511238869042  # #image-showcase
            config_showcase_id = 921844476283064381  # #config-showcase
            moved_to_channel_id = 1100494390071410798  # #bot-spam

        # Example checks - don't make threads from bot messages or wrong channels
        if message.author.bot or (message.channel.id != image_showcase_id and message.channel.id != config_showcase_id):
            return
        # Now specific channel checks
        is_image_channel = message.channel.id == image_showcase_id
        is_config_channel = message.channel.id == config_showcase_id
        allowed_types = ('image/', 'application/zip', 'application/x-rar-compressed', 'application/x-tar', 'application/gzip', 'application/x-7z-compressed')
        contains_allowed_attachment = any(
            attachment and attachment.content_type and attachment.content_type.startswith(allowed_types)
            for attachment in message.attachments or []
        )

        # Log information about attachments
        for attachment in message.attachments:
            mylogger.debug(
                f"Attachment: {attachment.filename}, Content Type: {attachment.content_type}, URL: {attachment.url}")

        contains_url = any(url in message.content.lower() for url in ('http://', 'https://'))
        contains_yaml_code = any(code_block in message.content.lower() for code_block in ('```yml', '```yaml'))

        # Check conditions for image channel
        if is_image_channel:
            if not contains_allowed_attachment and not contains_url:
                # Send ephemeral message about posting images and move the message
                try:
                    await message.reply(
                        "You cannot post new messages in this channel without images. "
                        f"Your message has been moved to <#{moved_to_channel_id}>.",
                        delete_after=30  # Delete the message after 30 seconds
                    )
                except discord.errors.HTTPException:
                    mylogger.warning("Failed to send ephemeral reply. User may have DMs disabled or the bot lacks permissions.")

                mylogger.info("Message will be moved to bot-spam channel.")
                return await self.move_to_channel(message, target_channel_id=moved_to_channel_id)

        # Check conditions for config channel
        elif is_config_channel:
            if not contains_allowed_attachment and not contains_yaml_code and not contains_url:
                # Send ephemeral message about posting YAML code or images of code and move the message
                try:
                    await message.reply(
                        "You cannot post new messages in this channel without a YAML code block. "
                        f"Your message has been moved to <#{moved_to_channel_id}>.",
                        delete_after=30  # Delete the message after 30 seconds
                    )
                except discord.errors.HTTPException:
                    mylogger.warning("Failed to send ephemeral reply. User may have DMs disabled or the bot lacks permissions.")
                return await self.move_to_channel(message, target_channel_id=moved_to_channel_id)

        # Format the current date in yyyy-mm-dd
        current_date = datetime.now().strftime("%Y-%m-%d")

        # Include the formatted date in the subject
        subject = f"{message.author} started a new thread on {current_date}."
        await message.create_thread(name=f"{subject}" or f"{subject}")
