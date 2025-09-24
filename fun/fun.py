import os
import random
import discord
import logging
from redbot.core import commands

# Create logger
mylogger = logging.getLogger('fun')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG

class RedBotCogFun(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        # exact, startswith, contains are the options
        self.reaction_triggers = {
            'omg': 'exact',
            'wtf': 'exact',
            'wth': 'exact',
            'lol': 'exact',
            'wow': 'exact',
            'yay': 'exact',
            'fml': 'exact',
            'smh': 'exact',
            'brb': 'exact',
            'ban': 'exact',
            'yolo': 'exact',
            'lmao': 'exact',
            'ha': 'exact',
            'haha': 'exact',
            'hahaha': 'exact',
            'pmm': 'exact'
        }

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author == self.bot.user:
            return

        # Log command invocation details
        author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
        guild_name = message.guild.name if message.guild else "Direct Message"
        channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"
        
        mylogger.info(f"Fun invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")

        content_lower = message.content.strip().lower()

        # Check if the message matches any trigger based on the specified matching type
        for trigger, match_type in self.reaction_triggers.items():
            if match_type == 'exact' and content_lower == trigger:
                await self.react_with_image(message, trigger)
            elif match_type == 'startswith' and content_lower.startswith(trigger):
                await self.react_with_image(message, trigger)
            elif match_type == 'contains' and trigger in content_lower:
                await self.react_with_image(message, trigger)

    async def react_with_image(self, message, reaction_trigger):
        mylogger.info(f"Fun Message matches '{reaction_trigger}'")

        # Get the directory path of the current cog
        cog_directory = os.path.dirname(__file__)
        mylogger.info(f"cog_directory: {cog_directory}")

        # Specify the directory containing the images based on the reaction trigger
        reaction_images_dir = os.path.join(cog_directory, reaction_trigger)

        if os.path.exists(reaction_images_dir) and os.path.isdir(reaction_images_dir):
            mylogger.info(f"Directory {reaction_images_dir} exists and is accessible.")

            # List all files in the directory
            directory_contents = os.listdir(reaction_images_dir)

            # Filter out image files (ending with .jpg, .jpeg, .png, .gif)
            images = [f for f in directory_contents if f.endswith(('.jpg', '.jpeg', '.png', '.gif'))]

            if images:
                # Select a random image from the list
                random_image = random.choice(images)
                image_path = os.path.join(reaction_images_dir, random_image)
                mylogger.info(f"Selected image: {image_path}")

                # Determine appropriate reaction title
                reaction_title = self.get_reaction_title(reaction_trigger)

                # Create and send an embed with a random color and the selected image
                embed = discord.Embed(title=reaction_title, color=random.randint(0, 0xFFFFFF))
                embed.set_image(url=f"attachment://{random_image}")

                # Add user on the left side of the embed
                embed.set_author(name=message.author.display_name, icon_url=message.author.avatar.url)

                # Set footer with bot information
                embed.set_footer(text=f"Brought to you by {self.bot_name}", icon_url=self.bot.user.avatar.url or discord.Embed.Empty)
                try:
                    await message.channel.send(embed=embed, file=discord.File(image_path))
                    mylogger.info(f"Sent {reaction_trigger.upper()} embed with image")
                except Exception as e:
                    mylogger.exception(f"Error occurred while sending {reaction_trigger.upper()} embed: {e}")
            else:
                mylogger.warning(f"No valid image files found in directory {reaction_images_dir}.")
        else:
            mylogger.error(f"Directory {reaction_images_dir} not found or is not accessible.")

    def get_reaction_title(self, reaction_trigger):
        if reaction_trigger == 'omg':
            return "OMG!!!!"
        elif reaction_trigger == 'wtf':
            return "What the f#ck!!?"
        elif reaction_trigger == 'wth':
            return "What the heck!?!"
        elif reaction_trigger == 'ban':
            return "Ban Hammer in Action!"
        elif reaction_trigger == 'lol':
            return ":rofl: lol!!!"
        elif reaction_trigger == 'wow':
            return "Wow!!!"
        elif reaction_trigger == 'yay':
            return "Yay!!!"
        elif reaction_trigger == 'fml':
            return "It's your life!!!"
        elif reaction_trigger == 'smh':
            return "Really!?! Keep shakin' it..."
        elif reaction_trigger == 'brb':
            return "Why you gone so long? Please come back!"
        elif reaction_trigger == 'yolo':
            return "No regrets, right?"
        elif reaction_trigger == 'lmao':
            return ":rofl: lmao!!!"
        elif reaction_trigger == 'ha' or reaction_trigger == 'haha' or reaction_trigger == 'hahaha':
            return ":rofl: What's so funny?!?"
        elif reaction_trigger == 'pmm':
            return "Was that a slip? Did you know?\n\nhttps://discord.com/channels/822460010649878528/1230493777001582643/1230916021456474213\n\n"
        else:
            return ""
