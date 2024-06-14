import discord
import logging
import asyncio
import yaml
import re
from redbot.core import commands

YAML_REGEX = r'```(yaml|yml)(.*?)```'

# Create logger
mylogger = logging.getLogger('validate')
mylogger.setLevel(logging.DEBUG)


class RedBotCogValidate(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message):
        # Log command invocation details
        author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
        guild_name = message.guild.name if message.guild else "Direct Message"
        channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"
        
        mylogger.info(f"Validate invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")
        # mylogger.info(f"Received message (ID: {message.id}) from {message.author.name} in #{message.channel.name}")

        if message.author.bot:
            return

        # Process message content for inline YAML code blocks
        content = message.content
        yaml_code_blocks = re.findall(YAML_REGEX, content, re.DOTALL)

        for _, code_block in yaml_code_blocks:
            await self.validate_yaml(message.channel, code_block)

        # Process message attachments for YAML files
        for attachment in message.attachments:
            if attachment.filename.lower().endswith(('.yml', '.yaml')):
                try:
                    attachment_data = await attachment.read()
                    attachment_text = attachment_data.decode('utf-8')
                    await self.validate_yaml(message.channel, attachment_text)
                except Exception as e:
                    mylogger.error(f"Error processing YAML attachment: {e}")

    async def validate_yaml(self, channel, code_block):
        try:
            yaml.safe_load(code_block)
            mylogger.info("YAML is valid")
            await self.send_validation_message(channel, code_block, is_valid=True)
        except yaml.YAMLError as exc:
            mylogger.info("YAML is NOT valid")
            error_message = f"Error message:\n\n{str(exc)}"
            await self.send_validation_message(channel, code_block, is_valid=False, error_message=error_message)

    async def send_validation_message(self, channel, code_block, is_valid, error_message=None):
        # Determine the appropriate emoji and status message based on YAML validity
        emoji = '✅' if is_valid else '❌'
        status_message = 'passed! YAML checked and **IS** valid.\n\n**Note:** Although YAML is valid, it may not be written as Kometa expects' if is_valid else 'failed! YAML checked and is **NOT** valid.'

        # Format the validation message with emoji and status
        formatted_message = f"{emoji} YAML validation {status_message}\n"
        if error_message:
            formatted_message += f"```Markdown\n{error_message}\n```"

        # Send the validation message with emoji to the channel
        message = await channel.send(formatted_message)

        # Add reaction emoji to the message based on validation result
        if is_valid:
            await message.add_reaction('🇾')  # Letter Y
            await message.add_reaction('🇦')  # Letter A
            await message.add_reaction('🇲')  # Letter M
            await message.add_reaction('🇱')  # Letter L
            await message.add_reaction('🆗')  # "YAML OK" emoji
        else:
            await message.add_reaction('🇾')  # Letter Y
            await message.add_reaction('🇦')  # Letter A
            await message.add_reaction('🇲')  # Letter M
            await message.add_reaction('🇱')  # Letter L
            await message.add_reaction('🚫')  # Prohibited emoji
