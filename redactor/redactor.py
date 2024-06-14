import re
import discord
import logging
import io
import os
import asyncio
from redbot.core import commands, app_commands

# Global error and start messages
START_MESSAGE = "The following was shared by {mention} and was automatically redacted by {bot_name} as it may have contained sensitive information.\n\nIf you feel this message should not have been redacted, resend it with `!bypass` in your message to avoid redaction."
FORBIDDEN_MESSAGE = "The following was shared by {mention} and was automatically redacted by {bot_name} as it may have contained sensitive information."
NO_REDACT_COMMAND = "!bypass"

# Create logger
mylogger = logging.getLogger('redactor')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG


class RedBotCog(commands.Cog):
    processed_message_ids = set()

    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id
        self.regex_pattern = r"(token|client.*|(?<!\w)url:|url: (?:http|https)|api_*key|(?<!\w)secret:|(?<!\w)error:|run_start|run_end|changes|username|password|localhost_url|\"tvdbapi\"|\"tmdbtoken\"|\"plextoken\"|\"fanarttvapikey\"): .+"
        self.processed_message_ids = set()

    @commands.Cog.listener()
    async def on_message(self, message):
        try:
            # Check if the message is from a direct message (DM) with the bot
            if isinstance(message.channel, discord.DMChannel):
                mylogger.info(f"Message {message.id} in DMChannel, skipping.")
                # If the message is from a DM, just return without further processing
                return
                
            # Skip processing if the message has already been processed
            if message.id in RedBotCog.processed_message_ids:
                mylogger.info(f"Message {message.id} already processed, skipping.")
                return

            if message.author != self.bot.user:
                # Mark the message as processed
                self.processed_message_ids.add(message.id)

                # Add a unique log message to identify when the event is triggered
                mylogger.info(f"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                # Log command invocation details
                author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
                guild_name = message.guild.name if message.guild else "Direct Message"
                channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"
        
                mylogger.info(f"Redactor invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")
        
                # mylogger.info(f"Received message (ID: {message.id}) from {message.author.name} in #{message.channel.name}")

                if message.content.strip() == NO_REDACT_COMMAND:
                    return

                if NO_REDACT_COMMAND in message.content:
                    mylogger.info(f"!bypass detected by {message.author.name}")
                    embed = discord.Embed(
                        title="💥BYPASS Override Detected!💥",
                        description=(
                            f"**💥Redaction Override Detected!💥** ↑↑↑ {message.author.mention}, I hope you know what you are doing?!?\n\n"
                            f"*This message will self-destruct in 30 seconds...*"
                        ),
                        color=discord.Color.blurple()
                    )
                    await message.channel.send(embed=embed, delete_after=30)  # Set delete_after as needed
                    return

                # Check if the message is in a thread (is a thread or a reply in a thread)
                if isinstance(message.channel, discord.Thread):
                    parent_channel_id = None

                    # Determine the appropriate parent channel ID based on bot user ID
                    if self.bot_uid == 1138446898487894206:  # Botmoose20
                        parent_channel_id = 1138466814519693412   # #bot-forums
                    elif self.bot_uid == 1132406656785973418:  # Luma
                        parent_channel_id = 1006644783743258635  # #kometa-help

                    # Check if the parent channel ID matches
                    if parent_channel_id and message.channel.parent.id == parent_channel_id:
                        mylogger.info("Parent channel ID matches. Adding a 5-second delay.")
                        await asyncio.sleep(5)  # Add a 5-second delay
                        mylogger.info("5-second delay completed.")

                message_type = self.check_message_type(message)
                # mylogger.info(f"message_type: {message_type}")
                is_sensitive_text = self.is_sensitive(message.content)
                has_sensitive_attachments = await self.contains_sensitive_attachments(message.attachments)

                if message_type == "Text Only" and is_sensitive_text:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_only_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text}")
                    await self.process_text_only_sensitive(message)

                elif message_type == "Text Only" and not is_sensitive_text:
                    mylogger.info(f"do nothing - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text}")

                elif message_type == "Attachments Only" and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_attachments_only_sensitive - message_type:{message_type} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_attachments_only_sensitive(message)

                elif message_type == "Attachments Only" and not has_sensitive_attachments:
                    mylogger.info(f"do nothing - message_type:{message_type} and not has_sensitive_attachments:{has_sensitive_attachments}")

                elif message_type == "Text and Attachments" and is_sensitive_text and not has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_text_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text} and not has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_text_sensitive(message)

                elif message_type == "Text and Attachments" and is_sensitive_text and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_both_sensitive - message_type:{message_type} and is_sensitive_text:{is_sensitive_text} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_both_sensitive(message)

                elif message_type == "Text and Attachments" and not is_sensitive_text and has_sensitive_attachments:
                    mylogger.info(f"*************REDACTED MESSAGE*************")
                    mylogger.info(f"process_text_and_attachments_attachments_sensitive - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text} and has_sensitive_attachments:{has_sensitive_attachments}")
                    await self.process_text_and_attachments_attachments_sensitive(message)

                elif message_type == "Text and Attachments" and not is_sensitive_text and not has_sensitive_attachments:
                    mylogger.info(f"do nothing - message_type:{message_type} and not is_sensitive_text:{is_sensitive_text} and not has_sensitive_attachments:{has_sensitive_attachments}")

        except Exception as e:
            mylogger.exception('An error occurred during message processing:', exc_info=e)

    def check_message_type(self, message):
        has_text = bool(message.content)
        has_attachments = bool(message.attachments)

        if has_text and has_attachments:
            return "Text and Attachments"
        elif has_text:
            return "Text Only"
        elif has_attachments:
            return "Attachments Only"
        else:
            return "No Text or Attachments"

    async def process_text_only_sensitive(self, message):
        try:
            redacted_content = self.redact_sensitive_info(message.content, self.bot_name)

            # Check if the redacted content exceeds Discord's character limit
            if len(redacted_content) > 1000:
                # Create a text file with the redacted content
                redacted_filename = f"redacted_message_{message.author.name}.txt"
                with open(redacted_filename, "w", encoding="utf-8") as file:
                    file.write(redacted_content)

                # Send a message notifying the user and attach the redacted text file
                await message.channel.send(
                    f"{START_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name)} "
                    f"See attached file for redacted content.",
                    file=discord.File(redacted_filename)
                )

                try:
                    # Send a direct message to the user with a link to the redacted message
                    error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
                    await message.author.send(error_message)

                except discord.errors.Forbidden:
                    # If sending a direct message is forbidden, inform the user in the server channel
                    await message.channel.send(
                        FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

                finally:
                    # Remove the temporary redacted text file
                    os.remove(redacted_filename)
            else:
                # If the redacted content is within Discord's character limit, send it as a regular message
                await message.channel.send(START_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))
                await message.channel.send(redacted_content)

                try:
                    # Send a direct message to the user with a link to the redacted message
                    error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
                    await message.author.send(error_message)

                except discord.errors.Forbidden:
                    # If sending a direct message is forbidden, inform the user in the server channel
                    await message.channel.send(
                        FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

        except Exception as e:
            # Log the exception (you can customize this part based on your logging setup)
            mylogger.exception('An error occurred in process_text_only_sensitive:', exc_info=e)

        finally:
            # Delete the original message (outside the try-except block)
            await message.delete()

    async def process_attachments_only_sensitive(self, message):
        # Redact sensitive attachments, send private message to user, and send redacted attachments
        redacted_attachments = []

        for att in message.attachments:
            if att.content_type:
                if (att.content_type.startswith('text') or
                        att.content_type == 'application/octet-stream' or
                        att.content_type.startswith('application/json') or
                        att.content_type.startswith('application/xml')):

                    att_content = await att.read()
                    try:
                        text_data = att_content.decode('utf-8')  # Decode the bytes to text
                    except UnicodeDecodeError:
                        # Handle the case where the attachment is not text
                        await message.delete()
                        await message.channel.send(
                            f"Sorry {message.author.mention}, for your own safety, please attach a file with a proper extension.")
                        continue

                    redacted_text = self.redact_sensitive_info(text_data, self.bot_name)

                    if redacted_text != text_data:
                        # Create a new attachment with the redacted content
                        redacted_attachment = discord.File(io.BytesIO(redacted_text.encode('utf-8')),
                                                           filename=att.filename)
                        redacted_attachments.append(redacted_attachment)
                    else:
                        # Send the original attachment if no redaction needed
                        att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                        await message.channel.send(file=att_file)
                else:
                    # Handle unsupported content types
                    att_file = discord.File(io.BytesIO(await att.read()), filename=att.filename)
                    await message.channel.send(file=att_file)
            else:
                # Treat attachment with content_type=None as text
                att_content = await att.read()
                try:
                    text_data = att_content.decode('utf-8')  # Decode the bytes to text
                except UnicodeDecodeError:
                    # If decoding fails, delete the message and inform the user
                    await message.delete()
                    await message.channel.send(
                        f"Sorry {message.author.mention}, for your own safety, please attach a file with a proper extension.")
                    continue

                redacted_text = self.redact_sensitive_info(text_data, self.bot_name)

                if redacted_text != text_data:
                    redacted_attachment = discord.File(io.BytesIO(redacted_text.encode('utf-8')),
                                                       filename=att.filename)
                    redacted_attachments.append(redacted_attachment)
                else:
                    att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                    await message.channel.send(file=att_file)

        try:
            # Send the redacted attachments back to the channel
            for redacted_attachment in redacted_attachments:
                await message.channel.send(file=redacted_attachment)

            # Send a private message to the user with a link to the redacted message
            error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
            await message.author.send(error_message)

        except discord.errors.Forbidden:
            # Inform the server channel if sending a direct message is forbidden
            await message.channel.send(FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

        # Delete the original message containing sensitive attachments (if not already deleted)
        await message.delete()

    async def process_text_and_attachments_text_sensitive(self, message):
        # Redact sensitive text, delete original, send private message to user, and send redacted text and attachments
        redacted_content = self.redact_sensitive_info(message.content, self.bot_name)

        try:
            # Send a private message to the user with a link to the redacted message
            error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
            await message.author.send(error_message)

        except discord.errors.Forbidden:
            # If sending a direct message is forbidden, inform the user in the server channel
            await message.channel.send(FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

        # Send the redacted text in the same channel
        await message.channel.send(redacted_content)

        for att in message.attachments:
            # Read the attachment's binary data
            att_content = await att.read()

            # Create a discord.File object with the attachment's data
            att_file = discord.File(io.BytesIO(att_content), filename=att.filename)

            # Send the attachment as a file
            await message.channel.send(file=att_file)

        # Delete the original message
        await message.delete()

    async def process_text_and_attachments_both_sensitive(self, message):
        # Redact both sensitive text and sensitive attachments, delete original, send private message to user,
        # and send redacted text and redacted attachments

        # Redact the sensitive text in the message content
        redacted_content = self.redact_sensitive_info(message.content, self.bot_name)

        # Redact sensitive attachments
        redacted_attachments = []

        for att in message.attachments:
            if att.content_type.startswith('text') or att.content_type == 'application/octet-stream'  or att.content_type.startswith('application/json') or att.content_type.startswith('application/xml'):
                att_content = await att.read()
                text_data = att_content.decode('utf-8')  # Decode the bytes to text
                redacted_text = self.redact_sensitive_info(text_data, self.bot_name)

                # If sensitive information was found and redacted in the text attachment, create a new attachment
                if redacted_text != text_data:
                    redacted_attachment = discord.File(io.BytesIO(redacted_text.encode('utf-8')), filename=att.filename)
                    redacted_attachments.append(redacted_attachment)
                else:
                    att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                    await message.channel.send(file=att_file)
            else:
                att_content = await att.read()
                att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                await message.channel.send(file=att_file)

        try:
            # Send a private message to the user with a link to the redacted message
            error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
            await message.author.send(error_message)

        except discord.errors.Forbidden:
            # If sending a direct message is forbidden, inform the user in the server channel
            await message.channel.send(FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

        # Send the redacted text in the same channel
        await message.channel.send(redacted_content)

        # Send the redacted attachments in the same channel
        for redacted_attachment in redacted_attachments:
            await message.channel.send(file=redacted_attachment)

        # Delete the original message
        await message.delete()

    async def process_text_and_attachments_attachments_sensitive(self, message):
        # Redact sensitive attachments, delete original, send private message to user, and send redacted attachments

        # Redact sensitive attachments
        redacted_attachments = []

        for att in message.attachments:
            if att.content_type.startswith('text') or att.content_type == 'application/octet-stream' or att.content_type.startswith('application/json') or att.content_type.startswith('application/xml'):
                att_content = await att.read()
                text_data = att_content.decode('utf-8')  # Decode the bytes to text
                redacted_text = self.redact_sensitive_info(text_data, self.bot_name)

                # If sensitive information was found and redacted in the text attachment, create a new attachment
                if redacted_text != text_data:
                    redacted_attachment = discord.File(io.BytesIO(redacted_text.encode('utf-8')), filename=att.filename)
                    redacted_attachments.append(redacted_attachment)
                else:
                    att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                    await message.channel.send(file=att_file)
            else:
                att_content = await att.read()
                att_file = discord.File(io.BytesIO(att_content), filename=att.filename)
                await message.channel.send(file=att_file)

        try:
            # Send a private message to the user with a link to the redacted message
            error_message = self.generate_error_message(message.author.name, self.bot_name, message.jump_url)
            await message.author.send(error_message)

        except discord.errors.Forbidden:
            # If sending a direct message is forbidden, inform the user in the server channel
            await message.channel.send(FORBIDDEN_MESSAGE.format(mention=message.author.mention, bot_name=self.bot_name))

        # Send the redacted attachments in the same channel
        for redacted_attachment in redacted_attachments:
            await message.channel.send(file=redacted_attachment)

        # Recreate the message.content as it was non-sensitive
        await message.channel.send(message.content)

        # Delete the original message
        await message.delete()

    def generate_error_message(self, author, bot_name, message_url):
        error_message = f"💥***{author}, you may have shared sensitive information***💥\n"
        error_message += f"{bot_name} has taken some precautions to redact information for you.\n"
        error_message += f"You can view the redacted message here: <{message_url}>."
        return error_message

    def redact_sensitive_info(self, text, bot_name):
        # Use regex to find and replace sensitive information, but skip lines containing certain keywords
        keywords_to_skip = ["redacted", "invalid_token", "is blank", "is invalid", "doesn't match", "were found in", "mapping values", "{e}", "not found", "failed to parse"]
        lines = text.split('\n')
        redacted_lines = []

        for line in lines:
            # Check if the line consists of only whitespace characters
            if line.isspace() or any(keyword in line.lower() for keyword in keywords_to_skip):
                # Skip lines that are empty or contain any of the specified keywords (case-insensitive)
                redacted_lines.append(line)
            else:
                # Check if the line contains sensitive information
                if re.search(self.regex_pattern, line, flags=re.IGNORECASE):
                    # Check if all characters between ":" and the end of the line are spaces
                    line_to_redact = line.split(": ", 1)
                    if len(line_to_redact) == 2:
                        key, value = line_to_redact
                        if not any(char.isalnum() for char in value.strip()):
                            # If all characters are spaces, skip redaction
                            redacted_lines.append(line)
                            continue

                    # Check if the last character is "|" and all characters between ":" and "|" are spaces
                    if "|" in line:
                        line_split = line.rsplit("|", 1)
                        if len(line_split) == 2:
                            key_part, value_part = line_split
                            if not any(char.isalnum() for char in value_part.strip()) and all(
                                    char.isspace() for char in key_part.strip()):
                                # If last character is "|" and all characters between ":" and "|" are spaces, skip redaction
                                redacted_lines.append(line)
                                continue

                    # Redact sensitive information in the line
                    redacted_line = re.sub(self.regex_pattern, f"\\1: (redacted by {bot_name})", line, flags=re.IGNORECASE)
                    redacted_lines.append(redacted_line)
                else:
                    # If the line doesn't contain sensitive information, keep it as-is
                    redacted_lines.append(line)

        return '\n'.join(redacted_lines)

    def is_sensitive(self, text):
        """
        Determines if the given text contains sensitive information based on predefined conditions.
        """
        keywords_to_skip = ["redacted", "invalid_token", "is blank", "is invalid", "doesn't match", "were found in", "mapping values", "{e}", "not found", "failed to parse"]

        # Check if the line consists of only whitespace characters or contains certain keywords
        if any(keyword in text.lower() for keyword in keywords_to_skip) or text.isspace():
            return False

        # Check if the line contains sensitive information using regex pattern
        if re.search(self.regex_pattern, text, flags=re.IGNORECASE):
            line_to_redact = text.split(": ", 1)
            if len(line_to_redact) == 2:
                key, value = line_to_redact
                if not any(char.isalnum() for char in value.strip()):
                    # If all characters are spaces, skip redaction
                    return False

            if "|" in text:
                line_split = text.rsplit("|", 1)
                if len(line_split) == 2:
                    key_part, value_part = line_split
                    if not any(char.isalnum() for char in value_part.strip()) and all(
                            char.isspace() for char in key_part.strip()):
                        # If last character is "|" and all characters between ":" and "|" are spaces, skip redaction
                        return False

            # Line contains sensitive information
            return True

        # Line doesn't contain sensitive information
        return False

    async def contains_sensitive_attachments(self, attachments):
        """
        Checks if any of the attachments have sensitive information.
        """
        for att in attachments:
            try:
                if att.content_type:
                    mylogger.debug(f"Attachment Content Type: {att.content_type}")  # Log content type for debugging
                else:
                    # Handle case where content_type is None (unrecognized type)
                    # Optionally, inspect file extension to determine file type
                    file_extension = att.filename.split('.')[-1].lower()  # Get file extension
                    if file_extension == 'txt':
                        # Treat as text file
                        content_type = 'text/plain'
                    elif file_extension == 'pdf':
                        # Treat as PDF file
                        content_type = 'application/pdf'
                    else:
                        # Default to generic binary data (handle based on file content)
                        content_type = 'application/octet-stream'
                    mylogger.debug(f"Attachment File Extension: {file_extension}")

                if (not att.content_type or
                        att.content_type.startswith('text') or
                        att.content_type == 'application/octet-stream' or
                        att.content_type.startswith('application/json') or
                        att.content_type.startswith('application/xml')):
                    att_content = await att.read()
                    try:
                        text_data = att_content.decode('utf-8')  # Decode the bytes to text
                    except UnicodeDecodeError:
                        # Handle the case where decoding as UTF-8 fails (treat as binary)
                        mylogger.warning(f"Failed to decode attachment {att.filename} as UTF-8")
                        # continue  # Skip to the next attachment
                        return True

                    if self.is_sensitive(text_data):
                        return True

            except Exception as e:
                mylogger.error(f"Error processing attachment {att.filename}: {e}")

        return False
