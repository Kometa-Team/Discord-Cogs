import subprocess
import io
import re
from discord import File
from redbot.core import commands
from discord.ext.commands import has_any_role

# Kometa-Masters 929900016531828797
# Moderators 929756550380286153
# Kometa-Apprentices 981499667722424390

class BotLogs(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    # @has_any_role(929900016531828797, 981499667722424390)  # Uncomment to use decorator
    async def botlogs(self, ctx, num_lines: int = 50):
        # Role IDs to check
        allowed_roles = [929900016531828797, 981499667722424390, 929756550380286153]
        
        # Print out all the user's roles
        user_roles = [role.id for role in ctx.author.roles]
        print(f"User {ctx.author} (ID: {ctx.author.id}) has roles: {user_roles}")
        
        # Check if user has one of the allowed roles
        has_role = any(role.id in allowed_roles for role in ctx.author.roles)
        if not has_role:
            await ctx.send("You do not have the required role to use this command.")
            print(f"User {ctx.author} (ID: {ctx.author.id}) does NOT have the required role.")
            return
        else:
            print(f"User {ctx.author} (ID: {ctx.author.id}) has the required role.")
        
        # Constrain the number of lines between 1 and 10000
        num_lines = max(1, min(num_lines, 10000))

        # Determine the appropriate target channel ID based on bot user ID
        bot_uid = self.bot.user.id
        if bot_uid == 1138446898487894206:  # Botmoose20
            service_name = 'botmoose@botmoose'
        elif bot_uid == 1422494031388344340:  # Luma
            service_name = 'luma@luma'
        else:
            await ctx.send("Unknown bot UID.")
            return

        command = f'sudo journalctl -eu {service_name} --no-pager --no-hostname | uniq'
        output = subprocess.run(command, stdout=subprocess.PIPE, text=True, shell=True).stdout

        # Filter out lines that contain "python" but do not have a timestamp between square brackets
        filtered_output_lines = [line for line in output.split('\n') if 'python' not in line or re.search(r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]', line)]

        # Take the last num_lines from the list to get the most recent entries
        filtered_output_lines = filtered_output_lines[-num_lines:]

        # Join the lines into a single string
        filtered_output = "\n".join(filtered_output_lines)

        # Save the filtered output as a text file
        output_file = io.StringIO(filtered_output)
        file = File(fp=io.BytesIO(output_file.getvalue().encode()), filename="bot_logs.txt")
        
        # Send the message with the attachment
        await ctx.send(f"Ran: {command}\nHere are the last {num_lines} lines of the bot's log files (filtered):", file=file)
