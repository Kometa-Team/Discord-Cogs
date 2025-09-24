import os
import random
import discord
import logging
from redbot.core import commands

mylogger = logging.getLogger('fun')
mylogger.setLevel(logging.DEBUG)

# 🔒 Only fire in these channels (IDs). Per-guild is fine; just add more IDs.
ALLOWED_CHANNEL_IDS = {
    1141467136158613544,  # #botmoose-tests
    1141467174570049696,  # #luma-tests-1038
    1100494390071410798,  # #bot-spam
}


class RedBotCogFun(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.reaction_triggers = {
            'omg': 'exact', 'wtf': 'exact', 'wth': 'exact', 'lol': 'exact', 'wow': 'exact',
            'yay': 'exact', 'fml': 'exact', 'smh': 'exact', 'brb': 'exact', 'ban': 'exact',
            'yolo': 'exact', 'lmao': 'exact', 'ha': 'exact', 'haha': 'exact', 'hahaha': 'exact', 'pmm': 'exact'
        }

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        # ignore bot messages
        if message.author.bot:
            return
        # ignore DMs
        if not message.guild:
            return

        # ✅ Allow only specific channels. Handle threads by mapping to their parent channel.
        channel_id = message.channel.id
        if isinstance(message.channel, (discord.Thread,)):
            channel_id = message.channel.parent_id or message.channel.id

        if ALLOWED_CHANNEL_IDS and channel_id not in ALLOWED_CHANNEL_IDS:
            return

        author_name = f"{message.author}";
        guild_name = message.guild.name
        channel_name = getattr(message.channel, "name", "Direct Message")
        mylogger.info(f"Fun invoked by {author_name} in {guild_name}/{channel_name} "
                      f"(ID: {message.guild.id}/{channel_id})")

        content_lower = message.content.strip().lower()
        for trigger, match_type in self.reaction_triggers.items():
            if (match_type == 'exact' and content_lower == trigger) or \
                    (match_type == 'startswith' and content_lower.startswith(trigger)) or \
                    (match_type == 'contains' and trigger in content_lower):
                await self.react_with_image(message, trigger)
                break  # prevent multiple fires on same message

    async def react_with_image(self, message, reaction_trigger):
        mylogger.info(f"Fun Message matches '{reaction_trigger}'")
        cog_directory = os.path.dirname(__file__)
        reaction_images_dir = os.path.join(cog_directory, reaction_trigger)
        if os.path.isdir(reaction_images_dir):
            images = [f for f in os.listdir(reaction_images_dir)
                      if f.lower().endswith(('.jpg', '.jpeg', '.png', '.gif'))]
            if images:
                import random as _r
                random_image = _r.choice(images)
                image_path = os.path.join(reaction_images_dir, random_image)
                embed = discord.Embed(title=self.get_reaction_title(reaction_trigger),
                                      color=_r.randint(0, 0xFFFFFF))
                embed.set_image(url=f"attachment://{random_image}")
                embed.set_author(name=message.author.display_name,
                                 icon_url=getattr(message.author.avatar, "url", discord.Embed.Empty))
                embed.set_footer(text=f"Brought to you by {self.bot_name}",
                                 icon_url=getattr(self.bot.user.avatar, "url", discord.Embed.Empty))
                await message.channel.send(embed=embed, file=discord.File(image_path))
            else:
                mylogger.warning(f"No images in {reaction_images_dir}")
        else:
            mylogger.error(f"Directory {reaction_images_dir} not found")

    def get_reaction_title(self, reaction_trigger):
        return {
            'omg': "OMG!!!!", 'wtf': "What the f#ck!!?", 'wth': "What the heck!?!", 'ban': "Ban Hammer in Action!",
            'lol': ":rofl: lol!!!", 'wow': "Wow!!!", 'yay': "Yay!!!", 'fml': "It's your life!!!",
            'smh': "Really!?! Keep shakin' it...", 'brb': "Why you gone so long? Please come back!",
            'yolo': "No regrets, right?", 'lmao': ":rofl: lmao!!!", 'ha': ":rofl: What's so funny?!?",
            'haha': ":rofl: What's so funny?!?", 'hahaha': ":rofl: What's so funny?!?",
            'pmm': "Was that a slip? Did you know?\n\nhttps://discord.com/channels/822460010649878528/1230493777001582643/1230916021456474213\n\n"
        }.get(reaction_trigger, "")
