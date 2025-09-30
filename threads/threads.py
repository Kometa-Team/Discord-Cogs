import discord
import asyncio
import re
import logging
from redbot.core import commands, app_commands

# 862041125706268702  Sponsor
# 938443185347244033  Support
# 1097919568334311495 Priority Support
# 822460010649878531 #general-chat
# 1006644783743258635 #kometa-help

# 1232124371901087764 Test Sponsor
# 1232122972521762836 Test Support
# 1232121280971407362 Test Priority Support
# 1138466667165405244 #bot-chat
# 1138466814519693412 #bot-forums

# 938492411649339462 - Docker
# 938490334286082068 - Linux
# 938490571637555220 - Mac
# 938490657717252148 - NAS
# 938490888437502053 - Windows
# 938490820129079296 - Unraid
# 938492563596406876 - Master Build
# 938492604989968454 - Develop Build
# 952912471226716192 - Nightly Build

# Create logger
mylogger = logging.getLogger('threads')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG


class Buttons(discord.ui.View):
    def __init__(self, cog, bot_role, user_id, *, timeout=None):
        self.cog = cog
        self.bot_role = bot_role
        self.user_id = user_id
        self.counter = 0
        super().__init__(timeout=timeout)

    @discord.ui.button(label="Close Post", style=discord.ButtonStyle.red, emoji="🔒", custom_id="Close Post")
    async def gray_button(self, interaction: discord.Interaction, button: discord.ui.Button, **kwargs):
        thread = interaction.channel
        if thread and isinstance(thread, discord.Thread):
            # Check if the interaction user is the thread owner or has the appropriate bot role
            member = interaction.guild.get_member(interaction.user.id)
            mylogger.info(f"User roles: {[role.id for role in member.roles]}")
            mylogger.info(f"Bot role: {self.bot_role.id}")
            if interaction.user.id == self.user_id or self.bot_role in member.roles:
                await self.cog._close(interaction)
            else:
                await interaction.response.send_message("You don't have permission to use this button.", ephemeral=True)


class Threads(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.bot_name = bot.user.name
        self.bot_uid = bot.user.id
        self.setup_role_logic()

    def setup_role_logic(self):
        self.role1 = None
        self.role2 = None
        self.sponsor = None
        self.general_chat = None
        self.parent_channel_id = None

        if self.bot.user.id == 1138446898487894206:  # Botmoose20
            self.role1 = 1232121280971407362  # Test Priority Support
            self.role2 = 1232122972521762836  # Test Support
            self.sponsor = 1232124371901087764  # Test Sponsor
            self.general_chat = 1138466667165405244  # #bot-chat
            self.parent_channel_id = 1138466814519693412  # #bot-forums
        elif self.bot.user.id == 1422494031388344340:  # Luma
            self.role1 = 1097919568334311495  # Priority Support
            self.role2 = 938443185347244033  # Support
            self.sponsor = 862041125706268702  # Sponsor
            self.general_chat = 822460010649878531  # #general-chat
            self.parent_channel_id = 1006644783743258635  # #kometa-help

    @commands.Cog.listener()
    async def on_thread_create(self, thread):
        # Log command invocation details
        author_name = f"{thread.owner.name}#{thread.owner.discriminator}" if thread.owner else "Unknown"
        guild_name = thread.guild.name if thread.guild else "Direct Message"
        channel_name = thread.parent.name if isinstance(thread.parent, discord.TextChannel) else "Direct Message"
        
        mylogger.info(f"Threads invoked by {author_name} in {guild_name}/{channel_name} (ID: {thread.guild.id if thread.guild else 'N/A'}/{thread.parent.id if thread.parent else 'N/A'})")
        # mylogger.info(f"Processing message: {thread.id}")
        role1 = thread.guild.get_role(self.role1)
        role2 = thread.guild.get_role(self.role2)

        if not (role1):
            mylogger.error(f"role1: {self.role1} is missing. Someone may have removed the Test Priority Support role. Aborting now...")
            return

        if not (role2):
            mylogger.error(f"role2: {self.role2} is missing. Someone may have removed the Test Support role. Aborting now...")
            return
        
        # Determine the appropriate bot role based on the bot running
        bot_role = role2

        if thread.parent_id == self.parent_channel_id:
            await asyncio.sleep(2)
            thread_owner = thread.owner
            tags = []

            # Check if the string is in the initial message content
            initial_message_content = str(thread)
            # Use regex to extract the username
            match = re.search(r'(\w+) needs assistance\. Invoked by', initial_message_content)
            username = match.group(1) if match else "U_n_k_n_o_w_n"

            # Retrieve the Discord user object
            user = discord.utils.get(thread.guild.members, name=username)

            initial_mention = None
            if username != "U_n_k_n_o_w_n":
                initial_mention = f"Welcome {user.mention}!\n\n"
                user_id = user.id
                user_roles = user.roles
            else:
                initial_mention = f"Welcome {thread_owner.mention}!\n\n"
                user_id = thread_owner.id
                user_roles = thread_owner.roles

            for tag in thread.parent.available_tags:
                if tag.name.lower() == "open":
                    tags.append(tag)
                    await thread.edit(applied_tags=tags)

            if any(role.id == self.sponsor for role in user_roles):
                await thread.send(
                    f"{initial_mention}Thanks for being a Kometa Sponsor, we greatly appreciate it! Your ticket will now be diverted to <@&{self.role1}> and <@&{self.role2}>.\n\nIncluding `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\nAfter attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                    allowed_mentions=discord.AllowedMentions(roles=[role for role in [role1, role2] if role]),
                    view=Buttons(self, bot_role, user_id))
            # See top for roles
            elif any(role.id in [952912471226716192, 938492604989968454, 938492563596406876, 938490820129079296,
                                 938490888437502053, 938490657717252148, 938490571637555220, 938490334286082068,
                                 938492411649339462] for role in user_roles):
                await thread.send(
                    f"{initial_mention}Someone from <@&{self.role2}> will assist when they're available.\n\nIncluding `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\nAfter attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                    allowed_mentions=discord.AllowedMentions(roles=[role1, role2]), view=Buttons(self, bot_role, user_id))
            else:
                await thread.send(
                    f"{initial_mention}It looks like you have not yet completed the <id:customize> section of our Discord server, this will allow us to help you quicker.\n\nSomeone from <@&{self.role2}> will assist when they're available.\n\nIncluding `meta.log` from the beginning is a huge help. Type `!logs` for more information.\n\nAfter attaching your log, do not forget to hit the green check boxes when prompted by our bot.\n\n",
                    allowed_mentions=discord.AllowedMentions(roles=[role1, role2]), view=Buttons(self, bot_role, user_id))
            message = await thread.send(
                "You can press the \"Close Post\" button above or type `/close` at any time to close this post.")
            await message.pin(reason="Makes it easier to close the post.")

    @app_commands.command()
    async def close(self, interaction: discord.Interaction):
        await self._close(interaction)

    async def _close(self, interaction):
        if isinstance(interaction.channel, discord.Thread):
            channel = interaction.channel
            channel_owner = channel.owner
            initial_message_content = str(channel)

            mylogger.info(f"initial_message_content: {initial_message_content}")

            # Use regex to search for the line and extract the text before the comma
            match = re.search(r'(.*?) needs assistance\. Invoked by ', initial_message_content)
            if match:
                user_that_needed_help = match.group(1)
            else:
                user_that_needed_help = None  # Set it to None if the line isn't found

            user_that_needed_help_id = None  # Initialize the user ID as None

            # Retrieve the Discord user object by name
            if user_that_needed_help and user_that_needed_help != "U_n_k_n_o_w_n":
                user_obj = discord.utils.get(channel.guild.members, name=user_that_needed_help)
                if user_obj:
                    user_that_needed_help_id = user_obj.id

            mylogger.info(f"channel: {channel}")
            mylogger.info(f"channel_owner: {channel_owner}")
            mylogger.info(f"channel.parent: {channel.parent}")
            mylogger.info(f"channel.parent.id: {channel.parent.id}")
            mylogger.info(f"self.parent_channel_id: {self.parent_channel_id}")
            mylogger.info(f"user_that_needed_help: {user_that_needed_help}")
            mylogger.info(f"user_that_needed_help_id: {user_that_needed_help_id}")
            mylogger.info(f"channel.owner_id: {channel.owner_id}")
            if channel.parent and channel.parent.id == self.parent_channel_id:
                member = interaction.guild.get_member(interaction.user.id)
                mylogger.info(f"member.id: {member.id}")
                mylogger.info(f"member.guild_permissions.manage_threads: {member.guild_permissions.manage_threads}")
                if member is None:
                    await interaction.response.send_message(
                        f"Sorry, I couldn't find your member information. Please try again later.", ephemeral=True)
                    return

                if member.id == channel.owner_id or member.guild_permissions.manage_threads or user_that_needed_help_id == member.id:
                    try:
                        await interaction.response.send_message(
                            f"This post has been marked as Resolved and has now been closed."
                            f"\n\nYou cannot reopen this thread - you must create a new one or ask a member of staff to reopen it in <#{self.general_chat}>."
                            f"\n\nThanks for using Kometa.",
                            ephemeral=False)
                        tags = []
                        for tag in channel.parent.available_tags:
                            if tag.name.lower() == "closed":
                                tags.append(tag)
                            if tag.name.lower() == "sohjiro to review" and tag in tags:
                                tags.remove(tag)
                            if tag.name.lower() == "staff to review" and tag in tags:
                                tags.remove(tag)
                        await channel.edit(
                            locked=True,
                            archived=True,
                            applied_tags=tags
                        )
                    except Exception as e:
                        await interaction.response.send_message(
                            f"An unexpected error occurred. Please try again later. {e}", ephemeral=True)
                    except discord.Forbidden:
                        await interaction.response.send_message(
                            f"I don't have the necessary permissions to close and lock the thread.", ephemeral=True)
                    except discord.HTTPException:
                        await interaction.response.send_message(
                            f"An error occurred while attempting to close and lock the thread.", ephemeral=True)
                else:
                    await interaction.response.send_message(
                        f"Hello {channel_owner.mention}, a user has suggested that this thread has been resolved and can be closed."
                        f"\n\nPlease confirm that you are happy to close this thread by typing `/close` or by pressing the Close Post button which is pinned to this thread.")
            else:
                await interaction.response.send_message(f"This command can only be used in a thread.", ephemeral=True)
