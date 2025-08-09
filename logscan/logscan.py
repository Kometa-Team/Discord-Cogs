import re
import discord
import io
import asyncio
import requests
import yaml
import os
import zipfile
import tarfile
import gzip
import rarfile
import py7zr
import tempfile
import string
import random
import jsonschema
import json
import logging

from urllib.parse import unquote
from datetime import datetime, timedelta

from redbot.core import app_commands, commands
from redbot.core.utils.views import SimpleMenu


# Create logger
mylogger = logging.getLogger('logscan')
mylogger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG

# Define constants
SUPPORTED_FILE_EXTENSIONS = ('.txt', '.log', '.yml', '.1', '.2', '.3', '.4', '.5', '.6', '.7', '.8', '.9')
SUPPORTED_COMPRESSED_FORMATS = ['.zip', '.tar', '.tar.gz', '.gz', '.rar', '.7z']
ALLOWED_ROLES = ["Support", "Moderator"]
# 929756550380286153 Moderator
# 938443185347244033 Support
ALLOWED_ROLE_IDS = [938443185347244033, 929756550380286153]
GLOBAL_TIMEOUT = 180
MENU_TIMEOUT = 3600
CONFIG_MENU_TIMEOUT = 30
NOPARSE_COMMAND = "!noparse"
# 1006644783743258635 #kometa-help
# 1141467174570049696 #luma-tests-103
# 1100494390071410798 #bot-spam
# 929901956271570945 #masters-chat

# 1138466814519693412 #bot-forums
# 1141467136158613544 #botmoose-tests
# 1138466667165405244 #bot-chat
# 1193948895496118303 #bot-masters-chat
# 796565792492617728 @bullmoose
# 206797306173849600 @sohjiro
# 1110266071849652335 #Missing People
# 1193970055508148326 #bot-Missing People

ALLOWED_HELP = 1138466814519693412
ALLOWED_TEST = 1141467136158613544
ALLOWED_CHAT = 1138466667165405244

global_divider = "="

# --- PMS security vulnerability helpers (non-invasive; keep existing checks as-is) ---

def _parse_pms_version_tuple(ver: str):
    """Return a 4-int tuple for PMS versions like '1.41.7.9100' (trims any '-xyz')."""
    ver = ver.split("-", 1)[0].strip()  # drop any '-whatever' suffix if present
    parts = ver.split(".")
    nums = []
    for i in range(4):
        try:
            nums.append(int(parts[i]))
        except Exception:
            nums.append(0)
    return tuple(nums[:4])

def _version_in_inclusive_range(ver: str, low: tuple, high: tuple) -> bool:
    v = _parse_pms_version_tuple(ver)
    return low <= v <= high

# Vulnerable range you want to flag (adjust as needed)
_PMS_VULN_LOW  = (1, 41, 7, 0)      # 1.41.7.x
_PMS_VULN_HIGH = (1, 42, 0, 99999)  # through 1.42.0.x

def initialize_variables():
    global script_name, script_env, target_thread_id, target_masters_thread_id, specific_user_id, sohjiro_id, support_role_id, ALLOWED_HELP, ALLOWED_TEST, ALLOWED_CHAT
    script_name = os.path.basename(__file__)
    script_env = "prod" if script_name == "logscan.py" else "test"
    target_thread_id = (1193970055508148326 if script_env == "test" else 1110266071849652335)
    target_masters_thread_id = (1193948895496118303 if script_env == "test" else 929901956271570945)
    ALLOWED_HELP = (1138466814519693412 if script_env == "test" else 1006644783743258635)
    ALLOWED_TEST = (1141467136158613544 if script_env == "test" else 1141467174570049696)
    ALLOWED_CHAT = (1138466667165405244 if script_env == "test" else 1100494390071410798)
    specific_user_id = (796565792492617728 if script_env == "test" else 796565792492617728)
    sohjiro_id = (796565792492617728 if script_env == "test" else 206797306173849600)
    support_role_id = 55559384431853472440335555


class MyMenu(SimpleMenu):
    def __init__(self, *args, invoker=None, **kwargs):
        self.invoker = invoker
        super().__init__(*args, **kwargs)

    async def interaction_check(self, interaction: discord.Interaction):
        # Check if the interaction user is the invoker or has the allowed role
        is_invoker = interaction.user.id == self.invoker.id
        author_has_allowed_role = any(role.id in ALLOWED_ROLE_IDS for role in interaction.user.roles)

        # Logging the invoker's ID and name
        mylogger.info(f"Invoker ID: {interaction.user.id}, Invoker Name: {interaction.user.name}")

        if is_invoker or author_has_allowed_role:
            return True  # Allow the interaction
        else:
            return False  # Prevent the interaction


class RedBotCogLogscan(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.current_plexapi_version = None
        self.current_kometa_version = None
        self.kometa_newest_version = None
        self.version_master = None
        self.version_develop = None
        self.version_nightly = None
        self.run_time = None
        self.plex_timeout = None
        self.checkfiles_flg = None
        self.server_versions = []
        self.schema_url = "https://raw.githubusercontent.com/kometa-team/kometa/nightly/json-schema/config-schema.json"

        initialize_variables()  # Call the method to initialize variables

    def reset_server_versions(self):
        """Reset the server_versions list to an empty list."""
        self.server_versions = []

    def add_fields_with_limit(self, embed, name, value):
        MAX_FIELD_LENGTH = 1024  # Discord's character limit for field values
        remaining_value = value

        while remaining_value:
            field_value = remaining_value[:MAX_FIELD_LENGTH]

            # Check if the message was truncated
            truncated_indicator = " (Truncated)" if len(remaining_value) > MAX_FIELD_LENGTH else ""

            # Add field with the truncated indicator
            embed.add_field(
                name=name,
                value=f"{field_value}{truncated_indicator}",
                inline=False
            )

            remaining_value = remaining_value[MAX_FIELD_LENGTH:]

        return embed  # Return the modified embed

    def remove_repeated_dividers(self, line):
        global global_divider  # Reference the global divider variable

        # Ensure that line is a string
        line = str(line)

        # Use regular expression to find and replace repeated dividers
        line = re.sub(f'({re.escape(global_divider)}){{10,}}', '', line)

        return line

    async def parse_attachment_content(self, content_bytes):
        """
        Parse the attachment content and clean it up.
        """
        try:
            content = content_bytes.decode('utf-8')
        except Exception as e:
            mylogger.error(f"Error decoding attachment content: {str(e)}")
            content = content_bytes.decode("utf-8", errors="replace")

        # Search for the divider string and set the global divider
        self.set_global_divider(content)

        # Clean up the content
        cleaned_content = self.cleanup_content(content)
        # mylogger.info(f"cleaned_content:{cleaned_content}")

        return cleaned_content

    def set_global_divider(self, content):
        """
        Search for the divider string in the content and set the global divider.
        """
        global global_divider  # Reference the global divider variable

        # Define the patterns to search for
        patterns = [
            r'--divider \(KOMETA_DIVIDER\): ?["\']?([^"\']{1})["\']?',  # KOMETA_DIVIDER pattern
            r'--divider \(PMM_DIVIDER\): ?["\']?([^"\']{1})["\']?'  # PMM_DIVIDER pattern
        ]

        # Try each pattern and set global_divider if a match is found
        for pattern in patterns:
            divider_match = re.search(pattern, content)
            if divider_match:
                divider = divider_match.group(1)
                global_divider = divider
                mylogger.info(f"Divider found and set to: {divider}")
                return  # Exit the function once a divider is found

        # If no match is found for any pattern, use default divider
        global_divider = "="
        mylogger.info(f"Divider not found, using default divider: {global_divider}")
    def set_global_divider1(self, content):
        """
        Search for the divider string in the content and set the global divider.
        """
        global global_divider  # Reference the global divider variable

        divider_match = re.search(r'--divider \(KOMETA_DIVIDER\): ?["\']?([^"\']{1})["\']?', content)

        if divider_match:
            divider = divider_match.group(1)
            global_divider = divider
            mylogger.info(f"Divider found and set to: {divider}")
        else:
            global_divider = "="
            mylogger.info(f"Divider not found, using default divider: {global_divider}")

    def extract_memory_value(self, content):
        """
        Extract the memory value from the given content.
        """
        # Regular expression to match the memory value
        memory_match = re.search(r'Memory:\s*([\d.]+)\s*(\w+)', content)

        if memory_match:
            value = float(memory_match.group(1))
            unit = memory_match.group(2).lower()

            # Convert value to gigabytes (GB)
            if unit == 'gb':
                return value
            elif unit == 'mb':
                return value / 1024  # Convert MB to GB
            elif unit == 'tb':
                return value * 1024  # Convert TB to GB

        return None  # Return None if no valid memory value is found

    def extract_db_cache_value(self, content):
        """
        Extract the db_cache value from the given content.
        """
        # Regular expression to match the memory value
        memory_match = re.search(r'Plex DB cache setting:\s*([\d.]+)\s*(\w+)', content)

        if memory_match:
            value = float(memory_match.group(1))
            unit = memory_match.group(2).lower()

            # Convert value to gigabytes (GB)
            if unit == 'gb':
                return value
            elif unit == 'mb':
                return value / 1024  # Convert MB to GB
            elif unit == 'tb':
                return value * 1024  # Convert TB to GB

        return None  # Return None if no valid memory value is found

    def extract_scheduled_run_time(self, content):
        """
        Extract the scheduled run time from the content.
        """
        # Define the patterns to search for
        patterns = [
            r'--times? \((KOMETA_TIMES?)\): ?["\']?(\d{1,2}:\d{2})["\']?',  # KOMETA_TIMES pattern
            r'--times? \((PMM_TIMES?)\): ?["\']?(\d{1,2}:\d{2})["\']?'  # PMM_TIMES pattern
        ]

        # Try each pattern and return the first match found
        for pattern in patterns:
            scheduled_run_time_match = re.search(pattern, content)
            if scheduled_run_time_match:
                scheduled_run_time = scheduled_run_time_match.group(2)
                mylogger.info(f"Scheduled run time found: {scheduled_run_time}")
                return scheduled_run_time

        # If no match is found
        mylogger.info("Scheduled run time not found in content.")
        return None

    def extract_maintenance_times(self, content):
        """
        Extract the start and end times of the maintenance from the content.
        """
        maintenance_times_match = re.search(r'Scheduled maintenance running between (\d+:\d+) and (\d+:\d+)', content)

        if maintenance_times_match:
            start_time = maintenance_times_match.group(1)
            end_time = maintenance_times_match.group(2)
            mylogger.info(f"Scheduled maintenance times found: Start time: {start_time}, End time: {end_time}")
            return start_time, end_time
        else:
            mylogger.info("Scheduled maintenance times not found in content.")
            return None, None

    def contains_overlay_path(self, content):
        # Regular expression to search for overlay_path
        return bool(re.search(r'\boverlay_path:\s*', content, re.IGNORECASE))

    def contains_overlay_files(self, content):
        # Regular expression to search for overlay_files
        return bool(re.search(r'\boverlay_files:\s*', content, re.IGNORECASE))

    def detect_wsl_and_recommendation(self, content):
        # Regular expression to check if the content contains information about WSL platform
        wsl_pattern = r"Platform: .*-WSL"

        if re.search(wsl_pattern, content):
            recommendation = (
                "💬🪟🐧 **WSL MEMORY RECOMMENDATION**\n"
                "According to Microsoft’s documentation, the amount of system memory (RAM) that gets allocated to WSL is limited to "
                "either 50% of your total memory or 8GB, whichever happens to be smaller.\n\n"
                "It is possible to override the maximum RAM allocation, we suggest googling 'WSL memory limit' to learn more otherwise the following may work for you:"
                "To override the maximum RAM allocation when running Windows Subsystem for Linux (WSL), you need to modify the configuration settings. Here are the steps to do this:\n"
                "1. Open a PowerShell window as an administrator.\n"
                "2. Run the command: `wsl --set-default-version 2` to set WSL version to 2 (WSL 2).\n"
                "3. Run the command: `wsl --set-memory <your_memory_limit>` to set the maximum memory limit for WSL (replace `<your_memory_limit>` with the desired memory limit, e.g., `4GB`).\n"
                "4. Restart WSL by running the command: `wsl --shutdown`.\n\n"
                "It is important to note that modifying these settings may require a reboot of your system."
            )
            return recommendation

        return None  # Return None if WSL is not detected in the content

    def make_db_cache_recommendations(self, parsed_content):
        disclaimer = "**NOTE**:The number you choose can vary wildly based on a number of factors " \
                     "(such as the size and number of libraries, and the amount of files/operations/overlays that are being utilized)."
        url_info = "https://kometa.wiki/en/latest/config/plex#plex-attributes"

        # Extract db_cache value and total memory value
        db_cache_value = self.extract_db_cache_value(parsed_content)
        total_memory_value = self.extract_memory_value(parsed_content)

        if db_cache_value is None or total_memory_value is None:
            return None  # Unable to determine recommendations due to missing data

        if db_cache_value >= total_memory_value:
            # db_cache should not be greater than or equal to total memory
            return f"❌ **PLEX DB CACHE ISSUE**\n" \
                   f"The Plex DB cache setting (**{db_cache_value:.2f} GB**) is equal to or greater than the total memory " \
                   f"(**{total_memory_value:.2f} GB**). Consider adjusting the Plex DB cache setting to a value **below** the total memory.\n" \
                   f"For more info on this setting: {url_info}\n" \
                   f"{disclaimer}"

        elif db_cache_value < 1:
            # db_cache is less than 1 GB, recommend updating based on total memory
            return f"💬💡️ **PLEX DB CACHE ADVICE**\n" \
                   f"Consider updating the Plex DB cache setting from **{db_cache_value:.2f} GB**, to a value **greater** than **1 GB** based on the total memory of **{total_memory_value:.2f} GB**.\nSetting `db_cache: 1024` within the plex settings in your config.yml is effectively 1024MB which is 1GB. " \
                   f"For more info on this setting: {url_info}\n" \
                   f"{disclaimer}"

        return None  # No issues or recommendations

    def calculate_memory_recommendation(self, content):
        disclaimer = "These numbers are purely estimates and can vary wildly based on a number of factors " \
                     "(such as the size and number of libraries, and the amount of files/operations/overlays that are being utilized)."

        # Extract memory value from the content
        memory_value = self.extract_memory_value(content)
        overlay_value = self.contains_overlay_path(content)

        # Check if overlay_value is still empty before updating it the second time
        if not overlay_value:
            overlay_value = self.contains_overlay_files(content)

        if memory_value is None:
            return "Error: Memory value not found in content."

        if memory_value < 4:
            if overlay_value:
                return f"⚠️ **MEMORY RECOMMENDATION**\n" \
                       f"The memory value is {memory_value:.2f} GB, which is less than 4 GB. " \
                       f"We advise having at least 8GB of RAM when running Kometa with overlays (we have detected overlays) to avoid potential out-of-memory issues.\n\n" \
                       f"{disclaimer}"
            else:
                return f"⚠️ **MEMORY RECOMMENDATION**\n" \
                       f"The memory value is {memory_value:.2f} GB, which is less than 4 GB. " \
                       f"We advise having at least 4GB of RAM when running Kometa without overlays (we have NOT detected overlays) to avoid potential out-of-memory issues.\n\n" \
                       f"{disclaimer}"

        elif memory_value < 8:
            if overlay_value:
                return f"⚠️ **MEMORY RECOMMENDATION**\n" \
                       f"The memory value is {memory_value:.2f} GB, which is less than 8 GB. " \
                       f"We advise having at least 8GB of RAM when running Kometa with overlays (we have detected overlays) for optimal performance.\n\n" \
                       f"{disclaimer}"
            else:
                return None  # No specific recommendation for memory < 8GB without overlays

        return None  # No specific recommendation for memory >= 8GB

    def calculate_recommendation(self, kometa_scheduled_time, maintenance_start_time=None, maintenance_end_time=None):
        if not kometa_scheduled_time:
            return "Error: Plex scheduled time is missing."

        kometa_scheduled_time = datetime.strptime(kometa_scheduled_time, '%H:%M').time()

        # Check if maintenance times are provided
        if maintenance_start_time is None or maintenance_end_time is None:
            return None  # Cannot provide recommendations without maintenance times

        maintenance_start_time = datetime.strptime(maintenance_start_time, '%H:%M').time()
        maintenance_end_time = datetime.strptime(maintenance_end_time, '%H:%M').time()

        plex_scheduled_datetime = datetime.combine(datetime.today(), kometa_scheduled_time)
        maintenance_start_datetime = datetime.combine(datetime.today(), maintenance_start_time)
        maintenance_end_datetime = datetime.combine(datetime.today(), maintenance_end_time)

        if maintenance_start_datetime > plex_scheduled_datetime:
            # Plex maintenance period starts on the next day
            time_before_plex_maintenance = (
                    (maintenance_start_datetime - plex_scheduled_datetime).seconds // 60
            )
        else:
            # Plex maintenance period starts on the same day
            time_before_plex_maintenance = (
                    (maintenance_start_datetime - plex_scheduled_datetime).seconds // 60
            )
        # Calculate the buffer until the next plex maintenance in minutes
        buffer_until_next_plex_maintenance = (
                                                     (24 + maintenance_start_time.hour - maintenance_end_time.hour) * 60
                                             ) % 1440  # 1440 minutes in a day

        run_time_in_minutes = self.run_time.total_seconds() / 60
        time_buffer = timedelta(minutes=buffer_until_next_plex_maintenance)
        mylogger.info(f"time_before_plex_maintenance: {time_before_plex_maintenance}")
        mylogger.info(f"buffer_until_next_plex_maintenance: {buffer_until_next_plex_maintenance}")
        mylogger.info(f"time_buffer until next Plex maintenance: {time_buffer}")
        mylogger.info(f"run_time_in_minutes: {run_time_in_minutes}")
        plex_maint_url = "https://support.plex.tv/articles/202197488-scheduled-server-maintenance/"

        if run_time_in_minutes > 1440:
            return f"❌⏰ **KOMETA RUN TIME > 24 HOURS**\nThis Run took: `{self.run_time}`\nTime between Kometa scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nIf your Kometa runs typically take this long [this run took `{self.run_time}`], your Kometa run time will coincide with the next Plex maintenance period as this run is greater than 24 hours.\n\nThe suggestion we can make at this point is to find ways to break down your run into smaller chunks and schedule them on different days.\nFor more information on Plex Maintenance, see {plex_maint_url}"

        if run_time_in_minutes > buffer_until_next_plex_maintenance:
            return f"❌⏰ **KOMETA RUN TIME > BUFFER BEFORE MAINTENANCE**\nThis Run took: `{self.run_time}`\nTime between Kometa Scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nIf your Kometa runs typically take this long [this run took `{self.run_time}`], your Kometa run time will coincide with the next Plex maintenance period. Adjust the Kometa Scheduled start time to `{maintenance_end_time.strftime('%-H:%M')}` (if needed) AND adjust the Plex Scheduled Maintenance start time to be later.\nFor more information on Plex Maintenance, see {plex_maint_url}"

        if maintenance_start_datetime <= plex_scheduled_datetime < maintenance_end_datetime:
            # Provide a message for the case when kometa_scheduled_time is between maintenance start and end times
            return f"❌⏰ **KOMETA SCHEDULED TIME CONFLICT**\nThis Run took: `{self.run_time}`\nTime between Kometa Scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nYou are within the maintenance window between Plex maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}` and end time: `{maintenance_end_time.strftime('%-H:%M')}`. Adjust the Kometa Scheduled start time to `{maintenance_end_time.strftime('%-H:%M')}` or adjust the Plex Scheduled Maintenance times to end prior to the Kometa Scheduled run time.\nFor more information on Plex Maintenance, see {plex_maint_url}"

        if run_time_in_minutes > time_before_plex_maintenance:
            return f"❌⏰ **KOMETA RUN TIME > TIME BEFORE MAINTENANCE**\nThis Run took: `{self.run_time}`\nTime between Kometa Scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nIf your Kometa runs typically take this long [this run took `{self.run_time}`], your Kometa run time will coincide with the next Plex maintenance period. Consider moving the Kometa scheduled start time to `{maintenance_end_time.strftime('%-H:%M')}` or adjust the Plex Scheduled Maintenance times to end prior to the Kometa Scheduled run time.\nFor more information on Plex Maintenance, see {plex_maint_url}"

        return None

    def cleanup_content(self, content):
        """
        Clean up the content by removing unnecessary lines and trailing characters.
        """
        cleanup_regex = r"\[(202[0-9])-\d+-\d+ \d+:\d+:\d+,\d+\] \[.*\.py:\d+\] +\[[INFODEBUGWARCTL]*\] +\||^[ ]{65}\|"
        cleaned_content = re.sub(cleanup_regex, "", content)

        # mylogger.info(f"content:\n{content}")
        # mylogger.info(f"cleaned_content:\n{cleaned_content}")

        # Second pass to remove trailing '|'
        lines = cleaned_content.splitlines()
        cleaned_lines = [line.rstrip('|') if line.rstrip().endswith('|') else line for line in lines]
        cleaned_content = "\n".join(cleaned_lines)

        # Third pass to remove trailing spaces
        cleaned_lines = [line.rstrip() for line in cleaned_content.splitlines()]
        cleaned_content = "\n".join(cleaned_lines)
        # mylogger.info(f"cleaned_content3rdpass:\n{cleaned_content}")

        return cleaned_content

    def extract_filename_from_url(self, url):
        return unquote(os.path.splitext(os.path.basename(url))[0])

    def scan_file_for_people_posters(self, content):
        # Split content into lines using splitlines()
        content_lines = content.splitlines()

        unique_names = {}  # Use a dictionary to store names as keys and URLs as values

        # String replacements to eliminate extra words
        words_to_eliminate = [' (Director)', ' (Producer)', ' (Writer)']

        # Join lines for regex
        content_text = '\n'.join(content_lines)

        # Regular expression to find name, URL, and extension using groups
        url_name_pattern = r'\[\d\d\d\d-\d\d-\d\d .*\[.*\] *\| Detail: tmdb_person updated poster to \[URL\] (https.*)(\..*g) *\|\n.*\n.*\n.*Finished (.*) Collection'
        url_name_matches = re.findall(url_name_pattern, content_text)

        # Process the matches
        for url, ext, name in url_name_matches:
            # Apply string replacements to the name
            for word in words_to_eliminate:
                name = name.replace(word, '')

            if name not in unique_names:  # Check if name is already in unique_names
                unique_names[name] = (url, ext)

        mylogger.info("1-Unique Names (URLs and Extensions): %s", unique_names)

        # Regular expression to find lines with "Collection Warning: No Poster Found at"
        warning_regex = r'Collection Warning: No Poster Found at https://raw\.githubusercontent\.com/Kometa-Team/People-Images(.+?)\s+'
        warning_matches = re.findall(warning_regex, '\n'.join(content_lines))  # Join lines for regex
        if warning_matches:
            for match in warning_matches:
                decoded_filename = self.extract_filename_from_url(match)
                if decoded_filename not in unique_names:  # Check if filename is already in unique_names
                    unique_names[decoded_filename] = None  # No URL available for now

        mylogger.info("2-Unique Names after Warning Matches: %s", unique_names)

        # Fetch the online content once
        online_content = requests.get(
            'https://raw.githubusercontent.com/Kometa-Team/People-Images-rainier/master/README.md').text

        online_names = set()
        for line in online_content.splitlines():
            if '](https://raw.githubusercontent.com/Kometa-Team/People-Images' in line:
                # Extract the name from the URL and add it to the set
                name = line.split('](')[0].split('[')[1]
                online_names.add(name.strip())

        # mylogger.info("3-Online Names: %s",, online_names)

        found_items = [name for name in unique_names.keys() if name in online_names]
        not_found_names = [name for name in unique_names.keys() if name not in online_names]
        not_found_names_with_url = {name: url for name, url in unique_names.items() if name not in online_names and url}

        mylogger.info("4-Found Items: %s", found_items)
        mylogger.info("5-Not Found Names: %s", not_found_names)
        mylogger.info("6-Not Found Names with URL: %s", not_found_names_with_url)

        # Remove names from not_found_names_with_url if they are in found_items
        for name in found_items:
            not_found_names_with_url.pop(name, None)
            if name in not_found_names:
                not_found_names.remove(name)

        # Remove names from not_found_names if they are in not_found_names_with_url
        for name in not_found_names_with_url.keys():
            if name in not_found_names:
                not_found_names.remove(name)

        # Add a prefix to each name in the not_found_names list
        prefix = "- "
        not_found_names = [f"{prefix}{name}" for name in not_found_names]

        # Add a prefix to each name in the found_items list
        found_items = [f"{prefix}{name}" for name in found_items]

        # Construct the desired output format for not_found_names_with_url
        not_found_names_with_url_formatted = {}
        for name, (url, ext) in not_found_names_with_url.items():
            if url and ext:
                not_found_names_with_url_formatted[name] = f"{prefix}{name}"

        mylogger.info("7-Not Found Names after Deduplication: %s", not_found_names)
        mylogger.info("8-Not Found Names with URL after Deduplication: %s", not_found_names_with_url)
        mylogger.info("9-Found Items after Deduplication: %s", found_items)
        mylogger.info("10-Not Found Names with URL formatted after Deduplication: %s", not_found_names_with_url_formatted)

        return found_items, not_found_names, list(not_found_names_with_url_formatted.values())

    def extract_finished_runs(self, content):
        lines = content.splitlines()
        finished_runs = []

        # Iterate through lines to find pairs
        for i in range(len(lines) - 1):
            line = lines[i]
            next_line = lines[i + 1]

            if "Finished " in line and " Run Time: " in next_line:
                # mylogger.info(f"Pair Found L1: {line}")
                # mylogger.info(f"Pair Found L2: {next_line}")
                finished_match = re.search(r'.*Finished\s+(.*?)\s*$', line)
                run_time_match = re.search(r'.*Run Time:(.*?)\s*$', next_line)

                finished_text = finished_match.group(1).strip() if finished_match else "N/A"
                run_time_text = run_time_match.group(1).strip() if run_time_match else "N/A"
                # mylogger.info(f"finished_text L1: {finished_text}")
                # mylogger.info(f"run_time_text L2: {run_time_text}")

                # Join the pair into one line
                combined_line = f"{finished_text} - {run_time_text}"
                # mylogger.info(f"combined_line: {combined_line}")
                finished_runs.append(combined_line)

        # Check if there's a line with "Finished:" and "Run Time:" at the end
            if "Finished: " in line and " Run Time: " in line:
                finished_match = re.search(r'.*Finished:\s+(.*?)\s*$', line)
                run_time_match = re.search(r'.*Run Time:(.*?)\s*$', line)

                finished_text = finished_match.group(1).strip() if finished_match else "N/A"
                run_time_text = run_time_match.group(1).strip() if run_time_match else "N/A"
                # Join the pair into one line
                combined_line = f"Finished at:{finished_text} - {run_time_text}"
                # mylogger.info(f"FINAL:combined_line: {combined_line}")
                # Add the line to the result
                finished_runs.append(combined_line)

        return finished_runs

    def extract_last_lines(self, content):
        lines = content.splitlines()

        # Find the index of the last line containing "Finished: "
        finished_run_index = next((i for i, line in enumerate(reversed(lines)) if "Finished: " in line and "Run Time: " in line), None)

        if finished_run_index is not None:
            # Calculate the starting index of the finished run lines
            start_index = len(lines) - finished_run_index - 5  # Go back by 5 lines
            extracted_lines = [line.lstrip() for line in lines[start_index:]]
            # Extract run time from the line that contains "Run Time: "
            run_time_line = next((line for line in extracted_lines if "Run Time: " in line), None)

            if run_time_line:
                # Extract the run time value
                run_time_str = run_time_line.split("Run Time: ")[1].strip()
                mylogger.info(f"run_time_str: {run_time_str}")
                self.run_time = timedelta(hours=int(run_time_str.split(":")[0]), minutes=int(run_time_str.split(":")[1]), seconds=int(run_time_str.split(":")[2]))
                mylogger.info(f"self.run_time: {self.run_time}")
                return "\n".join(extracted_lines)
            else:
                # If "Run Time: " is not found, return None for run time
                return "\n".join(extracted_lines)
        else:
            return None

    def format_contiguous_lines(self, line_numbers):
        formatted_ranges = []
        start_range = line_numbers[0]
        end_range = line_numbers[0]

        for i in range(1, len(line_numbers)):
            if line_numbers[i] == line_numbers[i - 1] + 1:
                end_range = line_numbers[i]
            else:
                if start_range == end_range:
                    formatted_ranges.append(str(start_range))
                else:
                    formatted_ranges.append(f"{start_range}-{end_range}")
                start_range = end_range = line_numbers[i]

        if start_range == end_range:
            formatted_ranges.append(str(start_range))
        else:
            formatted_ranges.append(f"{start_range}-{end_range}")

        return ", ".join(formatted_ranges)

    def make_recommendations(self, content, incomplete_message):
        self.checkfiles_flg = None
        lines = content.splitlines()
        special_check_lines = []
        anidb69_errors = []
        anidb_auth_errors = []
        api_blank_errors = []
        bad_version_found_errors = []
        cache_false = []
        checkFiles = []
        current_year = []
        other_award = []
        convert_errors = []
        corrupt_image_errors = []
        critical_errors = []
        error_errors = []
        warning_errors = []
        delete_unmanaged_collections_errors = []
        flixpatrol_errors = []
        flixpatrol_paywall = []
        git_kometa_errors = []
        pmm_legacy_errors = []
        image_size = []
        incomplete_errors = []
        internal_server_errors = []
        lsio_errors = []
        mal_connection_errors = []
        mass_update_errors = []
        mdblist_attr_errors = []
        mdblist_errors = []
        mdblist_api_limit_errors = []
        metadata_attribute_errors = []
        metadata_load_errors = []
        missing_path_errors = []
        new_version_found_errors = []
        new_plexapi_version_found_errors = []
        no_items_found_errors = []
        omdb_errors = []
        omdb_api_limit_errors = []
        overlays_bloat = []
        overlay_font_missing = []
        overlay_apply_errors = []
        overlay_image_missing = []
        overlay_level_errors = []
        overlay_load_errors = []
        playlist_load_errors = []
        playlist_errors = []
        plex_lib_errors = []
        plex_regex_errors = []
        plex_url_errors = []
        rounding_errors = []
        ruamel_errors = []
        run_order_errors = []
        security_vuln_hits = []
        tautulli_url_errors = []
        tautulli_apikey_errors = []
        timeout_errors = []
        to_be_configured_errors = []
        tmdb_api_errors = []
        tmdb_fail_errors = []
        trakt_connection_errors = []

        for idx, line in enumerate(lines, start=1):
            if "run_order:" in line:
                next_line = lines[idx] if idx < len(lines) else None
                if next_line and "- operations" not in next_line:
                    run_order_errors.append(idx)
            if "No Anime Found for AniDB ID: 69" in line:
                anidb69_errors.append(idx)
            if re.search(r'\bcache: false\b', line):
                cache_false.append(idx)
            if self.server_versions and (
                    "mass_user_rating_update" in line or "mass_episode_user_ratings_update" in line):

                # Set to keep track of unique (server_name, server_version, idx) combinations
                unique_entries = set()

                # Iterate through each (server_name, server_version) tuple in self.server_versions
                for server_name, server_version in self.server_versions:

                    # Create a unique identifier for the tuple
                    identifier = (server_name, server_version, idx)

                    # Check if the identifier is not in unique_entries (i.e., it's a new entry)
                    if identifier not in unique_entries:
                        # Append server info to rounding_errors
                        rounding_errors.append((server_name, server_version, idx))
                        # Add the identifier to unique_entries set to mark it as processed
                        unique_entries.add(identifier)

            # Detect PMS versions in "Connected to server ..." lines and flag the vulnerable range
            m = re.search(
                r"Connected to server\s+(.+?)\s+(?:\(?\s*(?:version|Version:)\s+)(\d+\.\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)",
                line
            )
            if m:
                sn = m.group(1).strip()
                ver = m.group(2).strip()
                if _version_in_inclusive_range(ver, _PMS_VULN_LOW, _PMS_VULN_HIGH):
                    security_vuln_hits.append((sn, ver, idx))
        
            if "Config Error: anidb sub-attribute" in line:
                anidb_auth_errors.append(idx)
            elif "apikey is blank" in line:
                api_blank_errors.append(idx)
            elif "1.32.7" in line and "Connected to server " in line:
                bad_version_found_errors.append(idx)
            elif "Convert Warning: No " in line and "ID Found for" in line:
                convert_errors.append(idx)
            elif "PIL.UnidentifiedImageError: cannot" in line:
                corrupt_image_errors.append(idx)
            elif "checkFiles=1" in line:
                checkFiles.append(idx)
            elif "current_year" in line:
                current_year.append(idx)
            elif "other_award" in line:
                other_award.append(idx)
            elif "delete_unmanaged_collections" in line:
                delete_unmanaged_collections_errors.append(idx)
            elif "internal_server_error" in line:
                internal_server_errors.append(idx)
            elif "FlixPatrol Error: " in line and "failed to parse" in line:
                flixpatrol_errors.append(idx)
            elif "flixpatrol" in line and "- pmm:" in line:
                flixpatrol_paywall.append(idx)
            elif "- git: PMM" in line:
                git_kometa_errors.append(idx)
            elif "- pmm: " in line:
                pmm_legacy_errors.append(idx)
            elif ", in _upload_image" in line:
                image_size.append(idx)
            elif "(Linuxserver" in line and "Version:" in line:
                lsio_errors.append(idx)
            elif "My Anime List Connection Failed" in line:
                mal_connection_errors.append(idx)
            elif "Config Error: Operation mass_" in line and "without a successful" in line:
                mass_update_errors.append(idx)
            elif "mdblist_list attribute not allowed with Collection Level: Season" in line:
                mdblist_attr_errors.append(idx)
            elif "MdbList Error: Invalid API key" in line:
                mdblist_errors.append(idx)
            elif "MDBList Error: API Limit Reached" in line or "MDBList Error: API Rate Limit Reached" in line:
                mdblist_api_limit_errors.append(idx)
            elif "metadata attribute is required" in line:
                metadata_attribute_errors.append(idx)
            elif "Metadata File Failed To Load" in line:
                metadata_load_errors.append(idx)
            elif "Overlay File Failed To Load" in line:
                overlay_load_errors.append(idx)
            elif "Playlist File Failed To Load" in line:
                playlist_load_errors.append(idx)
            elif "missing_path" in line or "save_missing" in line:
                missing_path_errors.append(idx)
            elif "Newest Version: " in line:
                new_version_found_errors.append(idx)
            elif "requires an update to:" in line:
                new_plexapi_version_found_errors.append(idx)
            elif "OMDb Error: Invalid API key" in line:
                omdb_errors.append(idx)
            elif "OMDb Error: Request limit reached" in line:
                omdb_api_limit_errors.append(idx)
            elif "Overlay Error: Poster already has an Overlay" in line:
                overlay_apply_errors.append(idx)
            elif "| Overlay Error: Overlay Image not found" in line:
                overlay_image_missing.append(idx)
            elif "overlay_level:" in line:
                overlay_level_errors.append(idx)
            elif "Plex Error: No Items found in Plex" in line:
                no_items_found_errors.append(idx)
            elif "Overlay Error: font:" in line:
                overlay_font_missing.append(idx)
            elif "Reapply Overlays: True" in line or "Reset Overlays: [" in line:
                overlays_bloat.append(idx)
            elif "Playlist Error: Library: " in line and "not defined" in line:
                playlist_errors.append(idx)
            elif "Plex Error: Plex Library " in line and "not found" in line:
                plex_lib_errors.append(idx)
            elif "Plex Error: " in line and "No matches found with regex pattern" in line:
                plex_regex_errors.append(idx)
            elif "Plex Error: Plex url is invalid" in line:
                plex_url_errors.append(idx)
            elif "ruamel.yaml." in line:
                ruamel_errors.append(idx)
            elif "TMDb Error: Invalid API key" in line:
                tmdb_api_errors.append(idx)
            elif "Tautulli Error: Invalid apikey" in line:
                tautulli_apikey_errors.append(idx)
            elif "Tautulli Error: Invalid URL" in line:
                tautulli_url_errors.append(idx)
            elif "timed out." in line:
                timeout_errors.append(idx)
            elif "Failed to Connect to https://api.themoviedb.org/3" in line:
                tmdb_fail_errors.append(idx)
            elif "Error: " in line and " requires " in line and " to be configured" in line:
                to_be_configured_errors.append(idx)
            elif "Trakt Connection Failed" in line:
                trakt_connection_errors.append(idx)
            elif "[CRITICAL]" in line:
                critical_errors.append(idx)
            elif "[ERROR]" in line:
                error_errors.append(idx)
            elif "[WARNING]" in line:
                warning_errors.append(idx)

        if anidb69_errors:
            url_line = "[https://kometa.wiki/en/latest/config/anidb]"
            formatted_errors = self.format_contiguous_lines(anidb69_errors)
            anidb69_error_message = (
                    "❌ **ANIDB69 ERROR**\n"
                    "Kometa uses AniDB ID 69 to test that it can connect to AniDB.\n"
                    "This error indicates that the test request sent to AniDB failed and AniDB could not be reached.\n"
                    f"For more information on configuring AniDB, {url_line}\n"
                    f"{len(anidb69_errors)} line(s) with ANIDB69 errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(anidb69_error_message)

        if anidb_auth_errors:
            url_line = "[https://kometa.wiki/en/latest/config/anidb]"
            formatted_errors = self.format_contiguous_lines(anidb_auth_errors)
            anidb_auth_errors_message = (
                    "❌ **ANIDB AUTH ERRORS**\n"
                    "Kometa uses AniDB settings to connect to AniDB.\n"
                    "This error indicates that the setting is not correctly setup in config.yml.\n"
                    f"For more information on configuring AniDB, {url_line}\n"
                    f"{len(anidb_auth_errors)} line(s) with ANIDB AUTH errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(anidb_auth_errors_message)

        if api_blank_errors:
            url_line = "[https://kometa.wiki/en/latest/config/trakt/?q=api]"
            formatted_errors = self.format_contiguous_lines(api_blank_errors)
            api_blank_error_message = (
                    "❌🔒 **BLANK API KEY ERROR**\n"
                    "An API key is required for certain services, and it appears to be blank in your configuration.\n"
                    "Make sure to provide the required API key to enable proper functionality.\n"
                    f"For more information on configuring API keys, {url_line}\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search for the service with the missing apikey \n"
                    f"{len(api_blank_errors)} line(s) with BLANK API KEY errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(api_blank_error_message)

        if bad_version_found_errors:
            url_line = "[https://forums.plex.tv/t/refresh-endpoint-put-post-requests-started-throwing-404s-in-version-1-32-7-7484/853588]"
            formatted_errors = self.format_contiguous_lines(bad_version_found_errors)
            bad_version_found_errors_message = (
                    "💥 **BAD PLEX VERSION ERROR**\n"
                    "You are running a version of Plex that is known to have issues with Kometa.\n"
                    "You should downgrade/upgrade to a version that is not `1.32.7.*`.\n"
                    f"For more information on this issue, {url_line}\n"
                    f"{len(bad_version_found_errors)} line(s) with Plex Version 1.32.7.*. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(bad_version_found_errors_message)

        if cache_false:
            url_line = "[https://kometa.wiki/en/latest/config/settings#cache]"
            formatted_errors = self.format_contiguous_lines(cache_false)
            cache_false_message = (
                    "💬 **Kometa CACHE**\n"
                    "Kometa cache setting is set to false(`cache: false`). Normally, you would want this set to true to improve performance.\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(cache_false)} line(s) with `cache: false`. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(cache_false_message)

        if checkFiles:
            formatted_errors = self.format_contiguous_lines(checkFiles)
            checkFiles_message = (
                    "⚠️ **CHECKFILES=1 DETECTED**\n"
                    "`checkFiles=1` detected. Notifying Kometa staff.\n"
                    f"{len(checkFiles)} line(s) with `checkFiles=1` messages. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(checkFiles_message)

        # if current_year:
        #     url_line = "[https://kometa.wiki/en/latest/files/dynamic_types/?h=latest#imdb-awards]"
        #     formatted_errors = self.format_contiguous_lines(current_year)
        #     current_year_message = (
        #             "⚠️ **LEGACY SCHEMA DETECTED**\n"
        #             "As of 1.20 `current_year` is no longer used and should be replaced with `latest`.\n"
        #             f"For more information on handling these, {url_line}\n"
        #             f"{len(current_year)} line(s) with `current_year` issues. Line number(s): {formatted_errors}"
        #     )
        #     special_check_lines.append(current_year_message)

        if other_award:
            url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=other_award#pmm-120-release-changes]"
            formatted_errors = self.format_contiguous_lines(other_award)
            other_award_message = (
                    "⚠️ **LEGACY SCHEMA DETECTED**\n"
                    "As of 1.20 `other_award` is no longer used and should be removed. All of those awards now have their own individual files.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(other_award)} line(s) with `other_award` issues. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(other_award_message)

        if critical_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Bcritical%5D#critical]"
            formatted_errors = self.format_contiguous_lines(critical_errors)
            critical_error_message = (
                    "💥 **[CRITICAL]**\n"
                    f"Critical messages found in your attached log.\n"
                    f"There is a very strong likelihood that Kometa aborted the run or part of the run early thus not all of what you wanted was applied.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(critical_errors)} line(s) with [CRITICAL] messages. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(critical_error_message)

        if error_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
            formatted_errors = self.format_contiguous_lines(error_errors)
            error_error_message = (
                    "❌ **[ERROR]**\n"
                    f"Error messages found in your attached log.\n"
                    f"There is a very strong likelihood that Kometa did not complete all of what you wanted. Some [ERROR] lines can be ignored.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(error_errors)} line(s) with [ERROR] messages. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(error_error_message)

        if warning_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Bwarning%5D#warning]"
            formatted_errors = self.format_contiguous_lines(warning_errors)
            warning_error_message = (
                    f"⚠️ **[WARNING]**\n"
                    f"Warning messages found in your attached log.\n"
                    f"This is a Kometa warning and usually does not require any immediate action. Most [WARNING] lines can be ignored.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(warning_errors)} line(s) with [WARNING] messages. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(warning_error_message)

        if convert_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/#warning]"
            formatted_errors = self.format_contiguous_lines(convert_errors)
            convert_error_message = (
                    "💬 **CONVERT WARNING**\n"
                    "Convert Warning: No * ID Found for * ID.\n"
                    "These sorts of errors indicate that the thing can't be cross-referenced between sites.  For example:\n\n"
                    "Convert Warning: No TVDb ID Found for TMDb ID: 15733\n\n"
                    "In the above scenario, the TMDB record for `The Two Mrs. Grenvilles` `ID 15733` didn't contain a TVDB ID. This could be because the record just hasn't been updated, or because `The Two Mrs. Grenvilles` isn't listed on TVDB.\n\n"
                    "The fix is for someone `like you, perhaps` to go to the relevant site and fill in the missing data.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(convert_errors)} line(s) with Convert Warnings. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(convert_error_message)

        if corrupt_image_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/#error]"
            formatted_errors = self.format_contiguous_lines(corrupt_image_errors)
            corrupt_image_message = (
                    "❌ **CORRUPT FILE ERROR**\n"
                    "Likely, when processing overlays, Kometa encountered a file that it could not process because it was corrupt.\n"
                    "Review the lines in your log file and based on the lines shown here and determine if those files are ok or not with your favorite image editor.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(corrupt_image_errors)} line(s) with `PIL.UnidentifiedImageError` reported. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(corrupt_image_message)

        if delete_unmanaged_collections_errors:
            url_line = "[https://kometa.wiki/en/latest/config/operations/#delete-collections]"
            formatted_errors = self.format_contiguous_lines(delete_unmanaged_collections_errors)
            delete_unmanaged_collections_errors_message = (
                    "⚠️ **LEGACY SCHEMA DETECTED**\n"
                    "`delete_unmanaged_collections` is a Library operation and should be adjusted in your config file accordingly.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(delete_unmanaged_collections_errors)} line(s) with `delete_unmanaged_collections` errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(delete_unmanaged_collections_errors_message)

        if flixpatrol_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=flixpatrol#flixpatrol]"
            formatted_errors = self.format_contiguous_lines(flixpatrol_errors)
            flixpatrol_error_message = (
                    "❌ **FLIXPATROL ERROR**\n"
                    "There was an issue with FlixPatrol data.\n"
                    "This is a known issue with Kometa 1.19.0 (master/latest branch).\n"
                    "Switch to the 1.19.1 nightly21 or greater Kometa release for a fix.\n"
                    "In the Kometa discord thread, for more information on how to switch branches, type `!branch`.\n"
                    f"For more information on handling FlixPatrol errors, {url_line}\n"
                    "If the problem persists, your IP address might be banned by FlixPatrol. Contact their support to have it unbanned.\n"
                    f"{len(flixpatrol_errors)} line(s) with FlixPatrol errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(flixpatrol_error_message)

        if flixpatrol_paywall:
            url_line = "[https://flixpatrol.com/about/premium/]"
            url_line2 = "[https://discord.com/channels/822460010649878528/1099773891733377065/1214929432754651176]"
            formatted_errors = self.format_contiguous_lines(flixpatrol_paywall)
            flixpatrol_paywall_message = (
                    "❌💰 **FLIXPATROL PAYWALL ERROR**\n"
                    "FlixPatrol decided to implement a Paywall which causes Kometa to no longer gather data from them.\n"
                    "Even if you pay, this will not work with Kometa.\n"
                    f"For more information on the FlixPatrol paywall, {url_line}\n"
                    f"As of Kometa 1.20.0-nightly34 (you are on {self.current_kometa_version}), we have eliminated FlixPatrol. See this announcement: {url_line2}\n"
                    f"{len(flixpatrol_paywall)} line(s) with `- pmm: flixpatrol` detected. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(flixpatrol_paywall_message)

        if git_kometa_errors:
            url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
            formatted_errors = self.format_contiguous_lines(git_kometa_errors)
            git_kometa_error_message = (
                    "💬 **OLD Kometa YAML**\n"
                    "You are using an old config.yml with references to metadata files that date to a version of Kometa that is pre 1.18\n"
                    "In the Kometa discord thread, type `!118` for more information.\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(git_kometa_errors)} line(s) with OLD Kometa YAML. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(git_kometa_error_message)

        if pmm_legacy_errors:
            url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
            formatted_errors = self.format_contiguous_lines(pmm_legacy_errors)
            pmm_legacy_error_message = (
                    "💬 **PRE KOMETA YAML**\n"
                    "You are using an old config.yml with references to metadata files that date to a version of this script that is pre Kometa\n"
                    "In your config.yml, search for `- pmm: ` and replace with `- default: ` .\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(pmm_legacy_errors)} line(s) with PRE Kometa YAML. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(pmm_legacy_error_message)

        if image_size:
            url_line = "[https://www.google.com]"
            formatted_errors = self.format_contiguous_lines(image_size)
            image_size_message = (
                    "❌ **IMAGE SIZE ERRORS**\n"
                    "It seems that you are attempting to upload or apply artwork and it's greater than the maximum `10MB`.\n"
                    f"This usually means that you have internal server errors (500) as well in this log. Change the image to one that is less than 10MB. For more information on handling this, {url_line}\n"
                    f"{len(image_size)} line(s) with IMAGE SIZE errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(image_size_message)

        if incomplete_message:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/#providing-log-files-on-discord]"
            incomplete_errors_message = (
                    "❌🛠️ **INCOMPLETE LOGS**\n"
                    f"{incomplete_message}\n"
                    "**The attached file seems incomplete. Without a complete log file troubleshooting is limited as we might be missing valuable information!**\n"
                    "Type `!logs` for more information about providing logs."
                    f"For more information on providing logs, {url_line}\n"
            )
            special_check_lines.append(incomplete_errors_message)

        if internal_server_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=errors+issues#errors-issues]"
            formatted_errors = self.format_contiguous_lines(internal_server_errors)
            internal_server_error_message = (
                    "💥 **INTERNAL SERVER ERROR**\n"
                    "An internal server error has occurred. This could be due to an issue with the service's server.\n"
                    "In the Kometa discord thread, type `!500` for more information.\n"
                    f"For more information on handling internal server errors, {url_line}\n"
                    f"{len(internal_server_errors)} line(s) with INTERNAL SERVER errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(internal_server_error_message)

        if lsio_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/install/images/?h=linuxserver#linuxserver]"
            formatted_errors = self.format_contiguous_lines(lsio_errors)
            lsio_error_message = (
                    "⚠️🖥️ **LINUXSERVER IMAGE DETECTED**\n"
                    "You are not using the official Kometa container image.\n"
                    "In the Kometa discord thread, type `!lsio` for more information.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(lsio_errors)} line(s) with LINUXSERVER IMAGE issues. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(lsio_error_message)

        if mal_connection_errors:
            url_line = "[https://kometa.wiki/en/latest/config/myanimelist]"
            formatted_errors = self.format_contiguous_lines(mal_connection_errors)
            mal_connection_error_message = (
                    "❌ **MY ANIME LIST CONNECTION ERROR**\n"
                    "There was an issue connecting to My Anime List (MAL) service.\n"
                    "This will affect any functionality that relies on MAL data.\n"
                    "In the Kometa discord thread, type `!mal` for more information\n"
                    f"For more information on configuring the My Anime List (MAL) service, {url_line}\n"
                    f"{len(mal_connection_errors)} line(s) with MY ANIME LIST CONNECTION errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(mal_connection_error_message)

        if mass_update_errors:
            url_line = "[https://kometa.wiki/en/latest/config/operations]"
            formatted_errors = self.format_contiguous_lines(mass_update_errors)
            mass_update_errors_message = (
                    "❌ **MASS_*_UPDATE ERROR**\n"
                    "You have specified a `mass_*_update` operation in your config file however you have not configured the corresponding service so this will never work.\n"
                    "Review each of the lines mentioned in this message to understand what all the config issues are.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on `mass_*_update` operations, {url_line}\n"
                    f"{len(mass_update_errors)} line(s) with `mass_*_update` config errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(mass_update_errors_message)

        if mdblist_attr_errors:
            url_line = "[https://kometa.wiki/en/latest/files/builders/mdblist/?h=mdblist+builders]"
            formatted_errors = self.format_contiguous_lines(mdblist_attr_errors)
            mdblist_attr_error_message = (
                    f"❌ **MDBLIST ATTRIBUTE ERROR**\n"
                    f"MDBList functionality does not currently support season-level collections.\n"
                    f"In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on MDBList configuration, {url_line}\n"
                    f"{len(mdblist_attr_errors)} line(s) with MDBList attribute errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(mdblist_attr_error_message)

        if mdblist_errors:
            url_line = "[https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes]"
            formatted_errors = self.format_contiguous_lines(mdblist_errors)
            mdblist_error_message = (
                    f"❌ **MDBLIST ERROR**\n"
                    f"Your configuration contains an invalid API key for MdbList.\n"
                    f"This will cause any services that rely on MdbList to fail.\n"
                    f"In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring MdbList, {url_line}\n"
                    f"{len(mdblist_errors)} line(s) with MDBLIST errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(mdblist_error_message)

        if mdblist_api_limit_errors:
            url_line = "[https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes]"
            formatted_errors = self.format_contiguous_lines(mdblist_api_limit_errors)
            mdblist_api_limit_error_message = (
                    f"❌ **MDBLIST API LIMIT ERROR**\n"
                    f"You have hit the MDBLIST API LIMIT. The free apikey is limited to 1000 requests per day so if you hit your limit Kometa should be able to pick up where it left off the next day as long as the Kometa cache setting is enabled in yur config.yml file.\n"
                    f"This will cause any metadata updates that rely on MdbList to fail until the limit is reset (usually daily).\n"
                    f"For more information on configuring MdbList, {url_line}\n"
                    f"{len(mdblist_api_limit_errors)} line(s) with MDBLIST API Limit errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(mdblist_api_limit_error_message)

        if metadata_attribute_errors:
            url_line = "[https://kometa.wiki/en/latest/config/files/#example]"
            formatted_errors = self.format_contiguous_lines(metadata_attribute_errors)
            metadata_attribute_errors_message = (
                    f"❌ **METADATA ATTRIBUTE ERRORS**\n"
                    f"If you are using Kometa nightly48 or newer, this is expected behaviour.\n"
                    f"`metadata_path` and `overlay_path` are now legacy attributes, and using them will cause the `YAML Error: metadata attribute is required` error.\n"
                    f"The error can be ignored as it won't cause any issues, or you can update your config.yml to use the new `collection_files`, `overlay_files` and `metadata_files` attributes.\n\n"
                    f"The steps to take are:\n"
                    f":one: - Look at every file referred to within your config.yml and see what the first level indentation yaml file attributes are. They should be one of these(`collections:, dynamic_collections:, overlays:, metadata:, playlists:, templates:, external_templates:`) and can contain more than 1. For now, ignore the `templates:` and `external_templates:` attributes.\n"
                    f":two: - if it's `metadata:`, file it under the `metadata_file:` section of your config.yml\n"
                    f":three: - if it's `collections:` or `dynamic_collections:`, file it under the `collection_files:` section of your config.yml\n"
                    f":four: - if it's `playlists:`,  file it under the `playlist_files:` section of your config.yml\n"
                    f":five: - if it's `overlays:`,  file it under the `overlay_files:` section of your config.yml\n\n"
                    f"`*NOTE:` If you only see `templates:` or `external_templates:`, this is a special case and you typically would not be referring to it directly in your config.yml file.\n\n"
                    f"Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(metadata_attribute_errors)} line(s) with METADATA ATTRIBUTE errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(metadata_attribute_errors_message)

        if metadata_load_errors:
            url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
            formatted_errors = self.format_contiguous_lines(metadata_load_errors)
            metadata_load_errors_message = (
                    f"❌ **METADATA LOAD ERRORS**\n"
                    f"Kometa is trying to load a file from your config file.\n"
                    f"This error indicates that the setting is not correctly setup in config.yml. Usually wrong path to the file, or a badly formatted yml file.\n"
                    f"Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(metadata_load_errors)} line(s) with METADATA LOAD errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(metadata_load_errors_message)

        if overlay_load_errors:
            url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
            formatted_errors = self.format_contiguous_lines(overlay_load_errors)
            overlay_load_errors_message = (
                    "❌ **OVERLAY LOAD ERRORS**\n"
                    "Kometa is trying to load a file from your config file.\n"
                    "This error indicates that the setting is not correctly setup in config.yml. Usually wrong path to the file, or a badly formatted yml file.\n"
                    "Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(overlay_load_errors)} line(s) with OVERLAY LOAD errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlay_load_errors_message)
            
        if playlist_load_errors:
            url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
            formatted_errors = self.format_contiguous_lines(playlist_load_errors)
            playlist_load_errors_message = (
                    "❌ **PLAYLIST LOAD ERRORS**\n"
                    "Kometa is trying to load a file from your config file.\n"
                    "This error indicates that the setting is not correctly setup in config.yml. Usually wrong path to the file, or a badly formatted yml file.\n"
                    "Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(playlist_load_errors)} line(s) with PLAYLIST LOAD errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(playlist_load_errors_message)

        if missing_path_errors:
            url_line = "[https://kometa.wiki/en/latest/config/libraries/?h=report_path#attributes]"
            formatted_errors = self.format_contiguous_lines(missing_path_errors)
            missing_path_errors_message = (
                    "⚠️ **LEGACY SCHEMA DETECTED**\n"
                    "`missing_path` or `save_missing` is no longer used and should be replaced/removed. Use `report_path` instead.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(missing_path_errors)} line(s) with `missing_path` or `save_missing` errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(missing_path_errors_message)

        if new_plexapi_version_found_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version]"
            formatted_errors = self.format_contiguous_lines(new_plexapi_version_found_errors)
            note = f"**(as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})**"
            new_plexapi_version_found_errors_message = (
                    "🚀 **PYTHON MODULE UPDATE NEEDED**\n"
                    # f"PlexAPI: {self.current_plexapi_version}\n\n"
                    "In the Kometa discord thread, type `!update` for instructions on how to update your requirements.\n"
                    f"For more information on updating, {url_line}\n"
                    f"{len(new_plexapi_version_found_errors)} line(s) with New Python Module Updates. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(new_plexapi_version_found_errors_message)

        if new_version_found_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version]"
            formatted_errors = self.format_contiguous_lines(new_version_found_errors)
            note = f"**(as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})**"
            new_version_found_errors_message = (
                    "🚀 **VERSION UPDATE AVAILABLE**\n"
                    f"**Current Version:** {self.current_kometa_version}\n"
                    f"**Newest Version (at the time of this log):** {self.kometa_newest_version}\n\n"
                    f"**Latest Kometa Versions** {note}\n"
                    f"Master branch: {self.version_master}\n"
                    f"Develop branch: {self.version_develop}\n"
                    f"Nightly branch: {self.version_nightly}\n\n"
                    "In the Kometa discord thread, type `!update` for instructions on how to update.\n"
                    f"For more information on updating, {url_line}\n"
                    f"{len(new_version_found_errors)} line(s) with New Version errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(new_version_found_errors_message)

        if no_items_found_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
            formatted_errors = self.format_contiguous_lines(no_items_found_errors)
            no_items_error_message = (
                    "⚠️ **NO ITEMS FOUND IN PLEX**\n"
                    "The criteria defined by a search/filter returned 0 results.\n"
                    "This is often expected - for example, if you try to apply a 1080P overlay to a 4K library then no items will get the overlay since no items have a 1080P resolution.\n"
                    "It is worth noting that search and filters are case-sensitive, so `1080P` and `1080p` are treated as two separate things.\n"
                    f"For more information on this error, {url_line}\n"
                    f"{len(no_items_found_errors)} line(s) with 'No Items found in Plex' errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(no_items_error_message)

        if omdb_errors:
            url_line = "[https://kometa.wiki/en/latest/config/omdb/#omdb-attributes]"
            formatted_errors = self.format_contiguous_lines(omdb_errors)
            omdb_error_message = (
                    "❌ **OMDB ERROR**\n"
                    "Your configuration contains an invalid API key for OMDb.\n"
                    "This will cause any services that rely on OMDb to fail.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring OMDb, {url_line}\n"
                    f"{len(omdb_errors)} line(s) with OMDb errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(omdb_error_message)

        if omdb_api_limit_errors:
            url_line = "[https://kometa.wiki/en/latest/config/omdb/?h=omdb#omdb-attributes]"
            formatted_errors = self.format_contiguous_lines(omdb_api_limit_errors)
            omdb_api_limit_error_message = (
                    f"❌ **OMDB API LIMIT ERROR**\n"
                    f"You have hit the OMDB API LIMIT. The free apikey is limited to 1000 requests per day so if you hit your limit Kometa should be able to pick up where it left off the next day as long as the Kometa cache setting is enabled in yur config.yml file.\n"
                    f"This will cause any metadata updates that rely on OMDB to fail until the limit is reset (usually daily).\n"
                    f"For more information on configuring OMDB, {url_line}\n"
                    f"{len(omdb_api_limit_errors)} line(s) with OMDB API Limit errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(omdb_api_limit_error_message)

        if overlay_font_missing:
            url_line = "[https://kometa.wiki/en/latest/showcase/overlays/?h=font#example-2]"
            formatted_errors = self.format_contiguous_lines(overlay_font_missing)
            overlay_font_missing_message = (
                    "❌ **OVERLAY FONT MISSING**\n"
                    "We detected that you are referencing a font that Kometa cannot find.\n"
                    "This can lead to overlays not being applied when a font is required.\n"
                    f"In the Kometa discord thread, type `!wiki` for more information or follow this link: {url_line}\n"
                    f"{len(overlay_font_missing)} line(s) with `Overlay Error: font:` errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlay_font_missing_message)

        if overlays_bloat:
            url_line = "[https://kometa.wiki/en/latest/kometa/scripts/imagemaid]"
            formatted_errors = self.format_contiguous_lines(overlays_bloat)
            overlays_bloat_message = (
                    "⚠️ **REAPPLY / RESET OVERLAYS**\n\n"
                    "We detected that you are using either reapply_overlays OR reset_overlays within your config.\n\n"
                    "**You should NOT be using reapply_overlays unless you have a specific reason to. If you are not sure do NOT enable it.**\n\n"
                    "This can lead to your system creating additional posters within Plex causing bloat\n\n"
                    "Typically these config lines are only used for very specific cases so if this is your case, then you can ignore this recommendation\n\n"
                    f"In the Kometa discord thread, type `!bloat` for more information or follow this link: {url_line}\n\n"
                    f"{len(overlays_bloat)} line(s) with reapply_overlays or reset_overlays. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlays_bloat_message)

        if overlay_apply_errors:
            url_line = "[https://kometa.wiki/en/latest/defaults/overlays]"
            url_line2 = "[https://kometa.wiki/en/latest/kometa/guides/assets]"
            formatted_errors = self.format_contiguous_lines(overlay_apply_errors)
            overlay_apply_errors_message = (
                    "⚠️ **OVERLAY APPLY ERROR**\n"
                    "Kometa attempts to apply an overlay to things, but finds that the art on the item is already an overlaid poster from Kometa with an EXIF tag:\n"
                    "```Abraham Season 1\n  Overlay Error: Poster already has an Overlay\nArchie Bunker''s Place S03E14\n  Overlay Error: Poster already has an Overlay\nAs Time Goes By Season 10\n  Overlay Error: Poster already has an Overlay\nCHiPs Season 3\n  Overlay Error: Poster already has an Overlay```\n\n"
                    "For `Season` posters, this is often because Plex has assigned higher-level art [like the show poster to a season that has no art of its own].\n"
                    "For `Movies`, `Show`, and `Episode` posters, this is often because an art item was selected or part of the assets pipeline that already had an overlay image on it.\n\n"
                    "You can fix this by going to each item in Plex, hitting the pencil icon, selecting Poster, and choosing art that does not have an overlay.\n"
                    "Alternatively if you are using the asset pipeline in Kometa, updating your asset pipeline with the art that does not have an overlay.\n"
                    "In the Kometa discord thread, type `!overlaylabel` for more information.\n\n"
                    f"For more information on overlays, {url_line}\n"
                    f"For more information on the asset pipeline, {url_line2}\n"
                    f"{len(overlay_apply_errors)} line(s) with OVERLAY APPLY errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlay_apply_errors_message)

        if overlay_image_missing:
            url_line = "[https://kometa.wiki/en/latest/defaults/overlays]"
            formatted_errors = self.format_contiguous_lines(overlay_image_missing)
            overlay_image_missing_message = (
                    "❌ **OVERLAY IMAGE MISSING ERROR**\n"
                    "Kometa attempts to apply an overlay to things, but finds that the overlay itself is not found and thus cannot be applied to the art.\n"
                    "Validate the path and also ensure that the case of the file(i.e. `4K.png` is NOT the same as `4k.png`) is the same as found in the line within the log.\n"
                    f"For more information on overlays, {url_line}\n"
                    f"{len(overlay_image_missing)} line(s) with OVERLAY IMAGE MISSING errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlay_image_missing_message)

        if overlay_level_errors:
            url_line = "[https://kometa.wiki/en/latest/files/settings/?h=builder_level]"
            formatted_errors = self.format_contiguous_lines(overlay_level_errors)
            overlay_level_errors_message = (
                    "⚠️ **LEGACY SCHEMA DETECTED**\n"
                    "`overlay_level:` is no longer used and should be replaced by `builder_level:`.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(overlay_level_errors)} line(s) with `overlay_level` errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(overlay_level_errors_message)

        if playlist_errors:
            url_line = "[https://kometa.wiki/en/latest/defaults/playlist/?h=playlist]"
            formatted_errors = self.format_contiguous_lines(playlist_errors)
            playlist_error_message = (
                    "❌ **PLAYLIST ERROR**\n"
                    "A playlist is trying to use a library that does not exist in Plex.\n"
                    "Ensure that all libraries being defined actually exist.\n"
                    "The Kometa Defaults `playlist` file expects libraries called `Movies` and `TV Shows`, template variables can be used to change this.\n"
                    f"For more information: {url_line}\n"
                    f"{len(playlist_errors)} line(s) with playlist errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(playlist_error_message)

        # Extract scheduled run time
        if self.run_time is None or not isinstance(self.run_time, timedelta):
            self.run_time = timedelta(hours=0, minutes=0, seconds=0)
        kometa_scheduled_time = self.extract_scheduled_run_time(content)
        maintenance_start_time, maintenance_end_time = self.extract_maintenance_times(content)
        kometa_time_recommendation = self.calculate_recommendation(kometa_scheduled_time, maintenance_start_time, maintenance_end_time)
        if kometa_time_recommendation:
            special_check_lines.append(kometa_time_recommendation)

        # Extract Memory value:
        kometa_mem_recommendation = self.calculate_memory_recommendation(content)
        if kometa_mem_recommendation:
            special_check_lines.append(kometa_mem_recommendation)

        # Extract DB Cache value:
        kometa_db_cache_recommendation = self.make_db_cache_recommendations(content)
        if kometa_db_cache_recommendation:
            special_check_lines.append(kometa_db_cache_recommendation)

        # Extract WSL information
        wsl_recommendation = self.detect_wsl_and_recommendation(content)
        if wsl_recommendation:
            special_check_lines.append(wsl_recommendation)

        if plex_regex_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
            formatted_errors = self.format_contiguous_lines(plex_regex_errors)
            plex_regex_error_message = (
                    "⚠️ **PLEX REGEX ERROR**\n"
                    "Kometa is trying to perform a regex search, and 0 items match the regex pattern.\n"
                    "This is often an expected error and can be ignored in most cases.\n"
                    "If you need assistance with this error, raise a support thread in `#kometa-help`.\n"
                    f"For more information on handling regex issues, {url_line}\n"
                    f"{len(plex_regex_errors)} line(s) with Plex regex errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(plex_regex_error_message)

        if plex_lib_errors:
            url_line = "[https://kometa.wiki/en/latest/config/settings/?h=show_options#show-options]"
            formatted_errors = self.format_contiguous_lines(plex_lib_errors)
            plex_lib_error_message = (
                    "❌ **PLEX LIBRARY ERROR**\n"
                    "Your configuration contains an invalid Plex Library Name.\n"
                    "Kometa will not be able to update a library that does not exist.\n"
                    "Check for spelling `case sensitive` and ensure that you have `show_options: true` within your settings within config.yml\n"
                    f"For more information on configuring the show_options, {url_line}\n"
                    f"{len(plex_lib_errors)} line(s) with PLEX LIBRARY errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(plex_lib_error_message)

        if plex_url_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-plex-url-and-token]"
            formatted_errors = self.format_contiguous_lines(plex_url_errors)
            plex_url_error_message = (
                    "❌ **PLEX URL ERROR**\n"
                    "Your configuration contains an invalid Plex URL.\n"
                    "This will cause any services that rely on this URL to fail.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring the Plex URL, {url_line}\n"
                    f"{len(plex_url_errors)} line(s) with PLEX URL errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(plex_url_error_message)

        if rounding_errors:
            url_line = "[https://forums.plex.tv/t/plex-rounding-down-user-ratings-when-set-via-api/875806/8]"

            # Construct the message with server names and versions
            rounding_errors_message = (
                "⚠️ **USER RATINGS ROUNDING ISSUE**\n"
                "We have detected that you are running `mass_user_rating_update` or `mass_episode_user_ratings_update` with Plex versions that will cause rounding issues with user ratings. To avoid this, downgrade your Plex Media server to `1.40.0.7998` or upgrade it to `1.40.3.8555` or later.\n"
                f"For more information on this issue, {url_line}\n"
                f"Detected issues on the following servers:\n"
            )
            # Append server names, versions, and line numbers to the message
            for server_name, server_version, line_num in rounding_errors:
                rounding_errors_message += f"- Server: {server_name}, Version: {server_version}, Line: {line_num}\n"

            special_check_lines.append(rounding_errors_message)

        if ruamel_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/yaml/]"
            formatted_errors = self.format_contiguous_lines(ruamel_errors)
            ruamel_error_message = (
                    "💥 **YAML ERROR**\n"
                    "YAML is very sensitive with regards to spaces and indentation.\n"
                    "Search for `ruamel.yaml.` in your log file to get hints as to where the problem lies.\n"
                    "In the Kometa discord thread, type `!yaml` and `!editors` for more information.\n"
                    f"For more information on handling YAML issues, {url_line}\n"
                    f"{len(ruamel_errors)} line(s) with YAML errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(ruamel_error_message)

        if run_order_errors:
            url_line = "[https://kometa.wiki/en/latest/config/settings/?h=run_order#run-order]"
            formatted_errors = self.format_contiguous_lines(run_order_errors)
            run_order_error_message = (
                    "⚠️ **RUN_ORDER WARNING**\n"
                    f"Typically, and in almost EVERY situation, you want ` - operations` to precede both metadata and overlays processing. To fix this, place `- operations` first in the `run_order` section of the config.yml file\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(run_order_errors)} line(s) with RUN_ORDER warnings. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(run_order_error_message)

        if security_vuln_hits:
            seen = set()
            items = []
            for sn, ver, ln in security_vuln_hits:
                key = (sn, ver, ln)
                if key not in seen:
                    seen.add(key)
                    items.append((sn, ver, ln))

            vuln_low_str  = ".".join(map(str, _PMS_VULN_LOW))
            vuln_high_str = ".".join(map(str, _PMS_VULN_HIGH))
            url_line = "[https://forums.plex.tv/t/plex-media-server-security-update/928341]"

            msg = (
                "🚀 **PMS SECURITY ALERT**\n"
                "A Plex Media Server version in a **known vulnerable range** was detected.\n"
                f"**Affected range:** `{vuln_low_str}` **through** `{vuln_high_str}`\n"
                "Please **upgrade Plex Media Server** to a safe release as soon as possible.\n"
                f"For more information on this see url: {url_line}\n"
                f"{len(security_vuln_hits)} line(s) with these errors."
                "Detected on:\n"
            )
            for sn, ver, ln in items:
                msg += f"- Server: {sn}, Version: `{ver}`, Line: {ln}\n"

            special_check_lines.append(msg)
    
        if tautulli_apikey_errors:
            url_line = "[https://kometa.wiki/en/latest/config/tautulli]"
            formatted_errors = self.format_contiguous_lines(tautulli_apikey_errors)
            tautulli_apikey_errors_message = (
                    "❌ **TAUTULLI API ERROR**\n"
                    "Your configuration contains an invalid API key for Tautulli.\n"
                    "This will cause any services that rely on Tautulli to fail.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring Tautulli, {url_line}\n"
                    f"{len(tautulli_apikey_errors)} line(s) with Tautulli errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(tautulli_apikey_errors_message)

        if tautulli_url_errors:
            url_line = "[https://kometa.wiki/en/latest/config/tautulli#tautulli-attributes]"
            formatted_errors = self.format_contiguous_lines(tautulli_url_errors)
            tautulli_url_error_message = (
                    "❌ **TAUTULLI URL ERROR**\n"
                    "Your configuration contains an invalid Tautulli URL.\n"
                    "This will cause any services that rely on this URL to fail.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring the Tautulli URL, {url_line}\n"
                    f"{len(tautulli_url_errors)} line(s) with TAUTULLI URL errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(tautulli_url_error_message)

        if tmdb_api_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-tmdb-api-key]"
            formatted_errors = self.format_contiguous_lines(tmdb_api_errors)
            tmdb_api_errors_message = (
                    "❌ **TMDB API ERROR**\n"
                    "Your configuration contains an invalid API key for TMDb.\n"
                    "This will cause any services that rely on TMDb to fail.\n"
                    "In the Kometa discord thread, type `!wiki` for more information and search.\n"
                    f"For more information on configuring TMDb, {url_line}\n"
                    f"{len(tmdb_api_errors)} line(s) with TMDb errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(tmdb_api_errors_message)

        if timeout_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/install/overview/]"
            formatted_errors = self.format_contiguous_lines(timeout_errors)
            timeout_error_message = (
                    "❌⏱️ **TIMEOUT ERROR**\n"
                    "There were timeout issues while trying to connect to different services.\n"
                    "Ensure that your network configuration allows Kometa to make internet calls.\n"
                    f"Typically this is your Plex server timing out when Kometa tries to connect to it. There's nothing Kometa can do about this directly. Currently your timeout for plex is set to: `{self.plex_timeout}` seconds. You can try increasing the connection timeout in `config.yml`:\n"
                    "```plex:\n  url: http://bing.bang.boing\n  token: REDACTED\n  timeout: 360   <<< right here```\n"
                    "But that's not a guarantee.\n\nEffectively what's happening here is that you're ringing the doorbell and no one's answering. You can't do anything about that aside from waiting longer. You can't ring the doorbell differently.\n\n"
                    "This seems to happen most often in an Appbox context, so perhaps contact your appbox provider to discuss it.\n\n"
                    "In the Kometa discord thread, type `!timeout` for more information.\n"
                    f"For more information on network configuration, {url_line}\n"
                    f"{len(timeout_errors)} line(s) with timeout errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(timeout_error_message)

        if tmdb_fail_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/]"
            formatted_errors = self.format_contiguous_lines(tmdb_fail_errors)
            tmdb_fail_error_message = (
                    "❌ **TMDB ERROR**\n"
                    "This error appears when your host machine is unable to connect to TMDb.\n"
                    "Ensure that your networking (particularly docker container) is configured to allow Kometa to make internet calls.\n"
                    f"For more information on network configuration, {url_line}\n"
                    f"{len(tmdb_fail_errors)} line(s) with TMDB errors. Line number location. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(tmdb_fail_error_message)

        if to_be_configured_errors:
            url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
            formatted_errors = self.format_contiguous_lines(to_be_configured_errors)
            to_be_configured_errors_message = (
                    "❌ **TO BE CONFIGURED ERROR**\n"
                    "You are using a builder that has not been configured yet.\n"
                    "This will affect any functionality that relies on these connections. Review all lines below and resolve.\n"
                    "In the Kometa discord thread, type `!wiki` and search for more information\n"
                    f"For more information on configuring services, {url_line}\n"
                    f"{len(to_be_configured_errors)} line(s) with `to be configured` errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(to_be_configured_errors_message)

        if trakt_connection_errors:
            url_line = "[https://kometa.wiki/en/latest/config/trakt/#trakt-attributes]"
            formatted_errors = self.format_contiguous_lines(trakt_connection_errors)
            trakt_connection_error_message = (
                    "❌ **TRAKT CONNECTION ERROR**\n"
                    "There was an issue connecting to the Trakt service.\n"
                    "This will affect any functionality that relies on Trakt data.\n"
                    "In the Kometa discord thread, type `!trakt` for more information\n"
                    f"For more information on configuring the Trakt service, {url_line}\n"
                    f"{len(trakt_connection_errors)} line(s) with TRAKT CONNECTION errors. Line number(s): {formatted_errors}"
            )
            special_check_lines.append(trakt_connection_error_message)

        if checkFiles:
            self.checkfiles_flg = 1

        # Initialize a list to store both the first line and full recommendation message
        recommendation_messages = []

        for idx, message in enumerate(special_check_lines, start=1):
            # Split the message into lines and log the first line with a label
            lines = message.split('\n')
            first_line = lines[0] if lines else ""
            mylogger.info(f"Kometa Recommendation {idx}: {first_line}")

            # Append both the first line and the full recommendation message to the list
            recommendation_messages.append({"first_line": first_line, "message": message})

        return recommendation_messages

    def reorder_recommendations(self, recommendations):
        # Define the priority order of symbols
        priority_order = {'🚀': 1, '💥': 2, '❌': 3, '⚠': 4, '💬': 5}

        def sort_key(recommendation):
            # Get the first symbol in the message
            first_symbol = recommendation.get('first_line', 'No first line available')[0]

            # Remove variation selector if present
            first_symbol = first_symbol.rstrip('\uFE0F')

            # Check if the first symbol is in the priority_order dictionary
            if first_symbol in priority_order:
                priority = priority_order[first_symbol]
                # mylogger.info(f"Original Message: {recommendation.get('first_line', 'No first line available')}")
                # mylogger.info(f"First Symbol: {first_symbol}")
                # mylogger.info(f"Priority: {priority}")
                return priority
            else:
                # mylogger.info(f"Priority not found for symbol {first_symbol}, using default priority")
                return float('inf')

        # Sort recommendations based on the custom key
        sorted_recommendations = sorted(recommendations, key=sort_key)

        # Print or log the sorted recommendations for debugging
        # mylogger.info("Sorted Recommendations:")
        for rec in sorted_recommendations:
            mylogger.info(rec.get('first_line', 'No first line available'))

        return sorted_recommendations

    def extract_plex_config(self, content):
        """
        Extract Plex configuration sections from the content.
        """
        lines = content.splitlines()
        plex_config_content = []

        start_marker = "Plex Configuration"
        # end_markers = [" Scanning Metadata and", "Library Connection Failed"]
        end_markers = [" Scanning ", "Library Connection Failed"]
        mylogger.info(f"extract_plex_config")

        i = 0
        while i < len(lines):
            line = lines[i]
            if start_marker in line:
                config_section = self.extract_plex_config_section(lines, i + 1, end_markers)
                if config_section:
                    # Call parse_server_info
                    server_info, all_lines = self.parse_server_info(config_section)
                    plex_config_content.append(config_section)

                    # Store the extracted server info in a variable
                    if server_info:
                        my_server_name = server_info['server_name']
                        my_server_version = server_info['version']

                        stable_version = "1.40.0.7998-c29d4c0c8"
                        good_version = "1.40.3.8555-fef15d30c"

                        if stable_version < my_server_version < good_version:
                            mylogger.info(
                                f"Server Name: {my_server_name} has Version: {my_server_version}. Potential Rounding Issue because > {stable_version} and < {good_version}")
                            # Store the server version globally in a list
                            self.server_versions.append((my_server_name, my_server_version))
                        elif my_server_version >= good_version:
                            mylogger.info(f"Server Name: {my_server_name} has Version: {my_server_version}. ALL GOOD")
                        else:
                            mylogger.info(f"Server Name: {my_server_name} has Version: {my_server_version}. ALL GOOD")

            i += 1

        if plex_config_content:
            return plex_config_content  # Return the list of extracted server info
        else:
            return None

    def extract_plex_config_section(self, lines, start_index, end_markers):
        """
        Extract a Plex configuration section starting from a specific index.
        """
        config_section = []

        for i in range(start_index, len(lines)):
            line = lines[i].strip()
            if any(marker in line for marker in end_markers):
                break
            if line:
                config_section.append(line)

        # Find the index of "Traceback (most recent call last):"
        traceback_marker = "Traceback (most recent call last):"
        traceback_line_number = -1
        for i, line in enumerate(config_section):
            if traceback_marker in line:
                traceback_line_number = i
                break

        # Remove lines after traceback_marker + 1 and before (total_lines - 2)
        if traceback_line_number >= 0:
            total_lines = len(config_section)
            start_remove = traceback_line_number + 1
            end_remove = total_lines - 2
            config_section = config_section[:start_remove] + config_section[end_remove + 1:]

        return "\n".join(config_section) if config_section else None

    def parse_server_info(self, config_section):
        """
        Parse the server name and version from the Plex configuration section.
        """
        server_info = {}

        # Initialize a list to keep all lines, including the ones not matched
        all_lines = []

        # Iterate through each line in the config_section
        for line in config_section.splitlines():
            # Add each line to the all_lines list
            all_lines.append(line)

            # Attempt to match the regex pattern in the current line
            match = re.search(r"Connected to server\s+([\w\s]+)\s+version\s+(\d+\.\d+\.\d+\.\d+-[\w\d]+)", line)
            if match:
                # Extract server name and version from the regex match
                server_name = match.group(1).strip()
                version = match.group(2).strip()

                # Store server name and version in dictionary
                server_info['server_name'] = server_name
                server_info['version'] = version

        # Log if server info extraction failed for all lines
        if not server_info:
            mylogger.info("Failed to extract server info from config_section")

        return server_info, all_lines

    def extract_config(self, content):
        extracted_lines = self.extract_config_lines(content)
        extracted_content = "\n".join(extracted_lines)

        if extracted_content:
            cleaned_content = self.clean_extracted_content(extracted_content)
            return self.parse_yaml_from_content(cleaned_content)
        else:
            return None, None, None

    def extract_config_schema(self, content):
        extracted_lines = self.extract_config_lines(content)
        extracted_content = "\n".join(extracted_lines)

        if extracted_content:
            cleaned_content = self.clean_extracted_content(extracted_content)
            return self.parse_yaml_schema_from_content(cleaned_content)
        else:
            return None, None, None

    def extract_config_lines(self, content):
        extraction_started = False
        extracted_lines = []

        for line in content.splitlines():
            if "Redacted Config" in line:
                extraction_started = True
                continue
            if extraction_started:
                # Config Warning at the start of the line means we're done
                if "Config Warning: " in line:
                    # mylogger.info(f"****break on config warning")
                    break
                # Check for the global divider condition
                if line.count(global_divider) >= 10:
                    # mylogger.info(f"****break on global divider")
                    break
                # Check for "Initializing cache database at" condition
                if "Initializing cache database at" in line:
                    # mylogger.info(f"****break on cache database")
                    break

                extracted_lines.append(line)

                # Check for "timeout: " in the line and extract the value
                if "timeout: " in line:
                    timeout_value = line.split("timeout: ")[1].strip()
                    self.plex_timeout = int(timeout_value)
                    # mylogger.info(f"plex_timeout:{self.plex_timeout}")

        total_lines = len(extracted_lines)
        if total_lines > 1:  # Ensure there are at least 2 lines to process
            extracted_lines = extracted_lines[:-1]

        # mylogger.info(f"*******extracted_lines**********: {extracted_lines}")
        return extracted_lines

    def clean_extracted_content(self, content):
        # Remove one leading space from each line
        cleaned_lines = [line[1:] if line.startswith(" ") else line for line in content.splitlines()]
        return "\n".join(cleaned_lines)

    def validate_against_schema(self, yaml_content, schema):
        try:
            # Validate YAML data against the JSON schema
            jsonschema.validate(instance=yaml_content, schema=schema)

            # Validation successful if no exceptions are raised
            return True

        except jsonschema.ValidationError as e:
            # Extract details about the validation error
            error_details = {
                "message": str(e),
                "path": list(e.path),
                "validator": e.validator
            }
            return False, error_details  # Return both the error flag and error details

    def parse_yaml_schema_from_content(self, content):
        try:
            parsed_yaml = yaml.safe_load(content)
            schema_response = requests.get(self.schema_url)

            if schema_response.status_code != 200:
                return None, "❌ Unable to fetch schema.", None

            schema = schema_response.json()  # schema is already a dictionary

            # Validate parsed_yaml against the schema
            validation_result, error_details = self.validate_against_schema(parsed_yaml, schema)

            if validation_result:
                valid_yaml_message = "✅ **PASSED SCHEMA VALIDATION**\nValidated against the Kometa schema."
                file_content = io.BytesIO(content.encode("utf-8"))
                return parsed_yaml, valid_yaml_message, file_content
            else:
                # Find the index of the first line break
                line_break_index = error_details['message'].find('\n')

                # If a line break exists, truncate the message at that point
                if line_break_index != -1:
                    error_message = error_details['message'][:line_break_index]
                else:
                    error_message = error_details['message']
                # Create a more informative error message
                invalid_yaml_message = f"❌ **FAILED SCHEMA VALIDATION** \nValidation against the Kometa schema[# yaml-language-server: $schema={self.schema_url}] failed due to: {error_message}\n" \
                                       # f"Path: {error_details['path']}\nValidator: {error_details['validator']}"
                file_content = io.BytesIO(content.encode("utf-8"))
                return None, invalid_yaml_message, file_content

        except yaml.YAMLError as e:
            error_message = f"❌ **INVALID YAML** content\nCannot validate against the Kometa schema until proper YAML is used.\n{e}"
            invalid_yaml_message = f"❌ **INVALID YAML** detected\n\n{error_message}"
            file_content = io.BytesIO(content.encode("utf-8"))
            return None, invalid_yaml_message, file_content

    def parse_yaml_from_content(self, content):
        try:
            parsed_yaml = yaml.safe_load(content)
            valid_yaml_message = "✅ **VALID YAML** content detected.\nWhile this is a good sign, this does NOT mean that the yml is valid from a Kometa perspective.\nUsing incorrect terms that are not found in the `!wiki` would validate properly here and surely fail to run."
            file_content = io.BytesIO(content.encode("utf-8"))
            return parsed_yaml, valid_yaml_message, file_content
        except yaml.YAMLError as e:
            error_message = f"❌ **INVALID YAML** content\n\n{e}"
            invalid_yaml_message = f"❌ **INVALID YAML** detected\n\n{error_message}"
            file_content = io.BytesIO(content.encode("utf-8"))
            return None, invalid_yaml_message, file_content

    def extract_header_lines(self, content):
        start_marker_current = "Version: "
        start_marker_newest = "Newest Version: "
        end_marker = "Run Command: "

        lines = content.splitlines()
        header_lines = []

        for i, line in enumerate(lines):
            if start_marker_current in line:
                version_value = line.split(start_marker_current)[1].strip()  # Extract version value
                self.current_kometa_version = version_value  # Store the version as a class variable
                while line and end_marker not in line:
                    header_lines.append(line.strip())  # Trim leading and trailing spaces
                    i += 1
                    line = lines[i] if i < len(lines) else ""
                    if start_marker_newest in line:
                        newest_version_value = line.split(start_marker_newest)[1].strip()  # Extract newest version value
                        self.kometa_newest_version = newest_version_value  # Store the newest version as a class variable
                header_lines.append(line.strip())  # Append the "Run Command" line
                # mylogger.info(f"header_lines bef replacement: {header_lines}")
                break  # Stop after the first occurrence

        # Perform the replacement after all lines have been added to header_lines
        header_lines = [line.replace("(redacted)", "") for line in header_lines]
        header_lines = [line.replace("(redacted)", "") for line in header_lines]
        # mylogger.info(f"header_lines aft replacement: {header_lines}")

        return "\n".join(header_lines)

    async def send_start_message(self, ctx, attachment):
        # Implementation of send_start_message
        start_message = f"🌟 **Starting to review the attached file: {attachment.filename}** 🌟"
        mylogger.info(f"STANDARD: Starting to review the attached file: {attachment.filename}")
        await ctx.send(start_message)

    async def send_completion_message(self, ctx, attachment):
        end_message = (
            f"🌟 **Parsing completed for the attached file: {attachment.filename}** 🌟\n\n"
            f"📝 If you want to review this again, use the command: `/logscan message_link` or `!logscan message_link` 📝"
        )
        mylogger.info(f"STANDARD: Sending End message")
        await ctx.send(end_message)

    def create_summary_info_embed(self, summary_lines, message):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        # Rest of the method remains the same  (Run Time: Sorted by duration)
        summary_info_embed = discord.Embed(title="**Kometa Summary Info**", color=discord.Color.green())

        if server_icon_url:
            summary_info_embed.set_thumbnail(url=server_icon_url)

        if summary_lines:
            # Sort the summary lines based on time in descending order
            def time_to_seconds(time_str):
                try:
                    # Split the line by the last occurrence of " - " to handle additional dashes in the main text
                    main_text, time_text = time_str.rsplit(" - ", 1)

                    # Extract the time components
                    hours, minutes, seconds = map(int, time_text.split(':'))

                    # If hours, minutes, and seconds are all 0, return None
                    if hours == 0 and minutes == 0 and seconds == 0:
                        return None

                    # If hours are greater than 9, adjust the format
                    if hours > 9:
                        return main_text.strip(), hours * 3600 + minutes * 60 + seconds
                    else:
                        # If hours are single-digit, add a leading zero for consistency
                        hours_str = f'0{hours}' if hours > 0 else '00'
                        return main_text.strip(), f'{hours_str}:{minutes:02d}:{seconds:02d}'
                except (ValueError, IndexError):
                    # Log the line that caused the issue
                    # mylogger.error(f"Invalid time format in line: {time_str}")
                    return time_str, 0  # Return the original line and a default value (zero seconds)

            # Filter out lines with 0 seconds before sorting
            filtered_summary_lines = filter(lambda x: time_to_seconds(x.split(" - ")[-1]) is not None, summary_lines)

            # Filter out lines with a run time of "0:00:00"
            filtered_summary_lines = filter(lambda x: not x.endswith(" - 0:00:00"), filtered_summary_lines)

            sorted_summary_lines = sorted(
                filtered_summary_lines,
                key=lambda x: time_to_seconds(x.split(" - ")[-1]),
                reverse=True
            )

            header_text = "**Kometa Section Run Times:** Top 10 sections sorted by duration (excluding run times of 0 seconds)."
            # Take the top 10 lines
            top_10_lines = sorted_summary_lines[:10]
            combined_text = "\n".join(top_10_lines)
            text_length = len(f"{header_text}\n\n{combined_text}")
            # mylogger.info(f"combined_text_length: {len(combined_text)}")  # 8446
            # mylogger.info(f"header_text_length: {len(header_text)}")  # 83
            # mylogger.info(f"text_length: {text_length}")  # 8531

            # Check if the combined text and header text exceed the character limit
            if text_length > 4096:
                # Calculate the remaining space for the combined text after considering the header
                remaining_space = 4096 - len(header_text) - 5  # Subtracting 5 for "..." and "\n\n"

                # Truncate at the calculated length and add "..."
                combined_text = combined_text[:remaining_space] + "..."
                # mylogger.info(f"combined_text_length_trunc: {len(combined_text)}")  # 4012
                summary_info_embed.description = f"{header_text}\n\n{combined_text}"
            else:
                # Set the combined text and header text as the description
                summary_info_embed.description = f"{header_text}\n\n{combined_text}"

        return summary_info_embed

    def create_user_info_embed(self, user, invoker, filename):
        # Create an embed for the "User Info" page
        user_info_embed = discord.Embed(
            title="**User Info**",
            description=f"**Author of Linked Message:** {user.display_name}\n**Person who Invoked the Command:** {invoker.display_name}\n**File Name:** {filename}",
            color=discord.Color.blurple(),
        )

        # Set the thumbnail to the author's avatar if available
        user_avatar_url = user.avatar.url if user.avatar else user.default_avatar.url
        user_info_embed.set_thumbnail(url=user_avatar_url)

        return user_info_embed

    def create_kometa_info_embed(self, header_lines, finished_lines, message, attachment):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        # Initialize incomplete_message as an empty string
        incomplete_message = ""

        # Rest of the method remains the same
        kometa_info_embed = discord.Embed(title="**Kometa Info**", color=discord.Color.green(), )

        if server_icon_url:
            kometa_info_embed.set_thumbnail(url=server_icon_url)

        if header_lines:
            mylogger.info(f"Header found")
            self.add_fields_with_limit(kometa_info_embed, "Kometa Header", self.remove_repeated_dividers(header_lines))

        else:
            incomplete_message += "Incomplete logs attached - Kometa Header missing or incomplete\n"
            self.add_fields_with_limit(kometa_info_embed, "Kometa Header",
                                       f"The header was empty/not found in {attachment.filename}.")

        if finished_lines:
            mylogger.info(f"Footer found")
            self.add_fields_with_limit(kometa_info_embed, "Kometa Footer", self.remove_repeated_dividers(finished_lines))

        else:
            incomplete_message += "Incomplete logs attached - Kometa Footer missing or incomplete\n"
            self.add_fields_with_limit(kometa_info_embed, "Kometa Footer",
                                       f"The footer was empty/not found in {attachment.filename}. Go see recommendations pages.")

        # Read version information from the URLs
        try:
            self.version_master = requests.get(
                "https://raw.githubusercontent.com/kometa-team/Kometa/master/VERSION").text.strip()
            self.version_develop = requests.get(
                "https://raw.githubusercontent.com/kometa-team/Kometa/develop/VERSION").text.strip().replace("master", "develop")
            self.version_nightly = requests.get(
                "https://raw.githubusercontent.com/kometa-team/Kometa/nightly/VERSION").text.strip().replace("develop", "nightly")
        except requests.RequestException as e:
            mylogger.error(f"Error while fetching version information: {str(e)}")

        # Add version information to the embed
        note = f"as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        kometa_info_embed.add_field(name="Available Kometa Versions", value=note)

        if self.version_master:
            self.add_fields_with_limit(kometa_info_embed, "Kometa Version (Master branch)", f"{self.version_master}")

        if self.version_develop:
            self.add_fields_with_limit(kometa_info_embed, "Kometa Version (Develop branch)", f"{self.version_develop}")

        if self.version_nightly:
            self.add_fields_with_limit(kometa_info_embed, "Kometa Version (Nightly branch)", f"{self.version_nightly}")

        # Assuming kometa_info_embed is the Discord embed
        # embed_content = kometa_info_embed.to_dict()

        # Calculate the character length
        # total_length = sum(len(str(value)) for key, value in embed_content.items())

        # Convert the embed content to a string
        # embed_string = str(embed_content)

        # Print or use the total_length as needed
        # mylogger.info(f"Character length of kometa_info_embed:{total_length}")
        # mylogger.info(f"kometa_info_embed:{embed_content}")

        return kometa_info_embed, incomplete_message

    def create_kometa_config_schema_embed(self, schema_message, message, incomplete_message):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        if schema_message is not None:
            if schema_message[0].startswith("❌"):  # Check if it's an invalid message
                title = "**WIP - Kometa Config.yml Schema Validation** ❌"
                color = discord.Color.red()
            else:
                title = "**WIP - Kometa Config.yml Schema Validation** ✅"
                color = discord.Color.green()
        else:
            title = "**WIP - Kometa Config.yml Schema Validation** ❌"
            color = discord.Color.red()
            incomplete_message += "Incomplete logs attached - Kometa config.yml missing or incomplete\n"

        kometa_config_schema_embed = discord.Embed(title=title, color=color)

        if server_icon_url:
            kometa_config_schema_embed.set_thumbnail(url=server_icon_url)

        if schema_message:
            # If yaml_message exceeds 4096 characters, truncate it
            if len(schema_message) > 4096:
                yaml_message = schema_message[:4093] + "..."
            kometa_config_schema_embed.description = f"**WIP - Schema Validation Results**:\n\nNote: This is currently a work in progress so some of this may not be totally accurate for the time being. If you chose to extract your config.yml, open it up in an editor like Visual Studio Code where the yaml-language-server is supported and you can see where the issues might be.\n\n{schema_message}"

        return kometa_config_schema_embed, incomplete_message  # Return both the Embed object and the incomplete_message

    def create_kometa_config_embed(self, yaml_message, message, incomplete_message):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        if yaml_message is not None:
            if yaml_message.startswith("❌"):  # Check if it's an invalid message
                title = "**Kometa Config.yml YAML Validation** ❌"
                color = discord.Color.red()
            else:
                title = "**Kometa Config.yml YAML Validation** ✅"
                color = discord.Color.green()
        else:
            title = "**Kometa Config.yml YAML Validation** ❌"
            color = discord.Color.red()
            incomplete_message += "Incomplete logs attached - Kometa config.yml missing or incomplete\n"

        kometa_config_embed = discord.Embed(title=title, color=color)

        if server_icon_url:
            kometa_config_embed.set_thumbnail(url=server_icon_url)

        if yaml_message:
            kometa_config_embed.add_field(
                name="YAML Validation Results",
                value=yaml_message,
                inline=False
            )
        else:
            kometa_config_embed.description = "The config.yml was not detected within your log file. Is it a complete log file?"

        return kometa_config_embed, incomplete_message

    async def send_config_content(self, ctx, linked_message_author, config_content, attachment):
        if config_content:
            # Convert BytesIO to string for manipulation
            config_content_str = config_content.getvalue().decode('utf-8')

            # Define the schema URL line
            schema_url_line = f"# yaml-language-server: $schema={self.schema_url}"

            # Define the bot-related information line
            added_by_bot_line = f"# ^^^ Added by bot: {self.bot.user} ^^^. Here is your extracted config. Note that line numbers will have changed if we added the header."

            # Split the content into lines
            lines = config_content_str.split("\n")

            # Check if the first line contains the string "yaml-language-server"
            if "yaml-language-server" not in lines[0]:
                # Prepend the line with schema URL and bot-related information
                config_content_str = schema_url_line + "\n" + added_by_bot_line + "\n" + config_content_str

            # Send the updated content as a file
            await ctx.send(file=discord.File(io.BytesIO(config_content_str.encode("utf-8")),
                                             filename=f"parsed_{attachment.filename}_config_{linked_message_author.display_name}.yml"))
        else:
            mylogger.info("Config content is empty or invalid.")
            await ctx.response.send_message(
                "💥An error occurred while processing the attachment. Config content is empty or invalid.💥",
                ephemeral=True)

    def create_plex_config_pages(self, plex_config_sections, incomplete_message, message):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        """
        Create Plex config pages based on Plex config sections and server icon URL.
        """
        plex_config_pages = []

        if plex_config_sections:
            mylogger.info(f"Plex config found")
            # Loop through each Plex config section and create an embed for it
            for section_index, section_content in enumerate(plex_config_sections):
                # Create an embed for the current Plex config section
                plex_config_embed = discord.Embed(
                    title=f"**Plex Configuration** - Section {section_index + 1}",
                    # Title indicating the section number
                    description=section_content[:4093] + "..." if len(section_content) > 4096 else section_content,
                    color=discord.Color.green(),
                )

                if server_icon_url:
                    plex_config_embed.set_thumbnail(url=server_icon_url)  # Set the server icon as the thumbnail

                # Create a page dictionary containing the content and embed for this section
                page = {"content": "", "embed": plex_config_embed}

                # Add the page to the list of pages
                plex_config_pages.append(page)
        else:
            incomplete_message += "Incomplete logs attached - Plex Config section missing or incomplete\n"

        return plex_config_pages, incomplete_message

    def get_server_icon_url(self, message):
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(message, "guild") and message.guild:
            server_icon_url = message.guild.icon.url

        return server_icon_url

    def generate_toc_entries_and_string(self, pages, recommendations):
        # Create an empty list to store TOC entries
        toc_entries = []

        # Generate the Table of Contents text
        toc_text = "Table of Contents:\n"
        for i, page in enumerate(pages):
            page_title = page["embed"].title
            # Include the first line of the recommendation for each page in the TOC text
            first_line = recommendations[i]["first_line"] if i < len(recommendations) else ""
            toc_text += f"Page {str(i + 1).zfill(2)}: {page_title} - {first_line}\n"

        # Add entries for each page to the TOC list
        for i, page in enumerate(pages):
            page_name = page["embed"].title  # Use the embed's title as the TOC entry name
            toc_entries.append({"name": page_name, "page": i + 1})  # Page numbers are 1-based

        # Define the total number of pages (including the TOC)
        total_pages = len(pages)

        # Iterate through each page and add a footer with page number and total pages
        for i, page in enumerate(pages):
            # Calculate the current page number (1-based)
            current_page_number = i + 1
            # Create an embed for the current page
            current_page_embed = page["embed"]

            # Add a footer to the current page embed
            current_page_embed.set_footer(
                text=f"Page {current_page_number}/{total_pages}"
            )

        # Return the TOC entries and the TOC text
        return toc_entries, toc_text

    def create_people_posters_embed(self, ctx, found_items, not_found_names, not_found_names_with_url):
        target_thread = self.bot.get_channel(target_thread_id)
        # Initialize server_icon_url to None
        server_icon_url = None

        if hasattr(ctx, "guild") and ctx.guild:
            server_icon_url = ctx.guild.icon.url

        # Create an embed to display the people posters scan results
        embed = discord.Embed(
            title="👥 **People Poster Scan Results**",
            description="",  # Initialize an empty description
            color=discord.Color.green()
        )

        if server_icon_url:
            embed.set_thumbnail(url=server_icon_url)

        # Helper function to truncate text to fit the character limit
        def truncate_text(text, limit):
            if len(text) > limit:
                return text[:limit - 3] + "..."
            else:
                return text

        if found_items:
            found_items_text = "\n".join(found_items)
            found_items_text_truncated = truncate_text(found_items_text, 4096)
            embed.description += f"✅ **Found People** ✅\n\nThese are people found in the attached log that we have a pre-made poster for. If you do not see posters for these people, we recommend you delete the collection and re-run Kometa:\n\n{found_items_text_truncated}\n\n Feel free to review all of the people posters we have here: https://github.com/kometa-team/Kometa-People-rainier/blob/master/README.md\n\n"

        if not_found_names:
            not_found_names_text = "\n".join(not_found_names)
            not_found_names_text_truncated = truncate_text(not_found_names_text, 4096 - len(embed.description))
            embed.description += f"❌ **Missing People (No TMDB Image)** ❌\n\nThese are people found in the attached log we do not have a pre-made poster for and we cannot detect a TMDB image to use as a source for creating a poster. If you could go and add proper images to TMDb for these people, we can then proceed to create the styled posters:\n\n{not_found_names_text_truncated}\n✉️ **People Poster request sent on your behalf to: <#{target_thread.id}>** ✉️\n\n"

        if not_found_names_with_url:
            not_found_names_with_url_text = "\n".join(not_found_names_with_url)
            not_found_names_with_url_text_truncated = truncate_text(not_found_names_with_url_text, 4096 - len(embed.description))
            embed.description += f"❌ **Missing People (With TMDB Image)** ❌\n\nThese are people found in the attached log that we do not yet have a pre-made poster for, but we were able to detect a source image on TMDb to use for creating a poster:\n\n{not_found_names_with_url_text_truncated}\n✉️ **People Poster request sent on your behalf to: <#{target_thread.id}>** ✉️\n\n"

        # Truncate the final description to fit the character limit
        embed.description = truncate_text(embed.description, 4096)

        return embed

    async def send_to_masters(self, ctx, target_masters_thread_id, sohjiro_id, msg_txt):
        target_channel = self.bot.get_channel(target_masters_thread_id)
        specific_user = ctx.author  # Use ctx.author as the specific user
        mylogger.info(f"target_channel: {target_channel}")

        if isinstance(target_channel, discord.abc.GuildChannel) and specific_user:
            mylogger.info(f"target_channel if is true: {target_channel}")
            sender_mention = f"Sender: {ctx.author.mention}\nKometa-Masters, bot is notifying you.."
            sent_message = await target_channel.send(f"{sender_mention}\n\n")

            user_mention = f"<@{sohjiro_id}>"

            await target_channel.send(f"{user_mention} {msg_txt}<{ctx.author.name}>. Log file found here: {ctx.message.jump_url}")
        else:
            mylogger.info(f"target_channel if is FALSE: {target_channel}")
            response = []

            if not isinstance(target_channel, discord.abc.GuildChannel):
                response.append("The provided channel ID is invalid or does not represent a channel.")

            if not specific_user:
                response.append("The provided specific user ID is invalid.")

            if response:
                await ctx.send("\n".join(response))
                await ctx.send(f"❌ **Failure to send to: <#{target_channel.id}> contact `@Support` directly about this failure** ❌")

    async def send_people_poster_request(self, ctx, target_thread_id, specific_user_id):
        target_thread = self.bot.get_channel(target_thread_id)
        specific_user = ctx.author  # Use ctx.author as the specific user

        if isinstance(target_thread, discord.Thread) and specific_user:
            sender_mention = f"Sender: {ctx.author.mention}\nA request for a people poster was made."
            sent_message = await target_thread.send(f"{sender_mention}\n\n")

            user_mention = f"<@{specific_user_id}>"

            await target_thread.send(f"{user_mention} New people poster request from {ctx.author.name}: {ctx.message.jump_url}")
        else:
            response = []

            if not isinstance(target_thread, discord.Thread):
                response.append("The provided thread ID is invalid or does not represent a thread.")

            if not specific_user:
                response.append("The provided specific user ID is invalid.")

            if response:
                await ctx.send("\n".join(response))
                await ctx.send(f"❌ **Failure to send to: <#{target_thread.id}> contact `@Support` directly about this failure** ❌")

    def generate_random_string(self, length):
        """
        Generates a random string of the specified length.
        """
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    def create_unique_temp_dir(self, message_id):
        """
        Creates a unique temporary directory based on the message ID.
        """
        random_suffix = self.generate_random_string(6)  # Generate a random suffix
        temp_dir_name = f"{message_id}_{random_suffix}"  # Use message ID and random suffix
        temp_dir_path = os.path.join(tempfile.gettempdir(), temp_dir_name)
        mylogger.info(f"temp_dir_name: {temp_dir_name}")
        mylogger.info(f"temp_dir_path: {temp_dir_path}")

        os.makedirs(temp_dir_path)  # Create the temporary directory
        return temp_dir_path

    def cleanup_temp_dir(self, temp_dir_path):
        """
        Cleans up the specified temporary directory by deleting its contents and the directory itself.
        """
        try:
            for root, dirs, files in os.walk(temp_dir_path):
                for file in files:
                    os.remove(os.path.join(root, file))
                for dir in dirs:
                    os.rmdir(os.path.join(root, dir))

            # Finally, delete the temporary directory itself
            os.rmdir(temp_dir_path)
        except Exception as e:
            mylogger.error(f"Error while cleaning up temp dir: {str(e)}")

    async def handle_compressed_file(self, ctx, attachment):
        filename, extension = os.path.splitext(attachment.filename.lower())
        message_id = ctx.message.id

        extracted_files = []

        if extension in SUPPORTED_COMPRESSED_FORMATS:
            temp_dir = self.create_unique_temp_dir(message_id)
            os.makedirs(temp_dir, exist_ok=True)

            compressed_path = os.path.join(temp_dir, attachment.filename)

            try:
                await attachment.save(compressed_path)

                if extension == '.zip':
                    with zipfile.ZipFile(compressed_path, 'r') as zip_ref:
                        for file_info in zip_ref.infolist():
                            if '__MACOSX' in file_info.filename:
                                continue  # Ignore entries under __MACOSX folder
                            with zip_ref.open(file_info) as file:
                                content_bytes = file.read()
                                try:
                                    content = content_bytes.decode("utf-8")
                                except UnicodeDecodeError as e:
                                    mylogger.error(f"UnicodeDecodeError: {e}")
                                    content = content_bytes.decode("utf-8", errors="replace")

                                extracted_files.append((file_info.filename, content, content_bytes))

                elif extension == '.tar':
                    with tarfile.open(compressed_path, 'r') as tar_ref:
                        for file_info in tar_ref.getmembers():
                            if '__MACOSX' in file_info.name:
                                continue  # Ignore entries under __MACOSX folder
                            if file_info.isfile():
                                with tar_ref.extractfile(file_info) as file:
                                    content_bytes = file.read()
                                    try:
                                        content = content_bytes.decode("utf-8")
                                    except UnicodeDecodeError as e:
                                        mylogger.error(f"UnicodeDecodeError: {e}")
                                        content = content_bytes.decode("utf-8", errors="replace")

                                    extracted_files.append((file_info.name, content, content_bytes))

                elif extension == '.gz':
                    with gzip.open(compressed_path, 'rt', encoding='utf-8') as gz_ref:
                        content = gz_ref.read()
                        extracted_files.append((attachment.filename, content, content.encode("utf-8")))

                elif extension == '.rar':
                    with rarfile.RarFile(compressed_path) as rar_ref:
                        for file_info in rar_ref.infolist():
                            if '__MACOSX' in file_info.filename:
                                continue  # Ignore entries under __MACOSX folder
                            content_bytes = rar_ref.read(file_info)
                            try:
                                content = content_bytes.decode("utf-8")
                            except UnicodeDecodeError as e:
                                mylogger.info(f"UnicodeDecodeError: {e}")
                                content = content_bytes.decode("utf-8", errors="replace")

                            extracted_files.append((file_info.filename, content, content_bytes))

                elif extension == '.7z':
                    with py7zr.SevenZipFile(compressed_path, 'r') as seven_zip_ref:
                        for file_info in seven_zip_ref.getnames():
                            if '__MACOSX' in file_info:
                                continue  # Ignore entries under __MACOSX folder
                            content_bytes = seven_zip_ref.read(file_info)
                            try:
                                content = content_bytes.decode("utf-8")
                            except UnicodeDecodeError as e:
                                mylogger.error(f"UnicodeDecodeError: {e}")
                                content = content_bytes.decode("utf-8", errors="replace")

                            extracted_files.append((file_info, content, content_bytes))

            finally:
                self.cleanup_temp_dir(temp_dir)

        else:
            mylogger.error("Unsupported compressed format")

        return extracted_files

    async def prompt_user_and_get_decision(self, ctx, file_info):
        user_name = ctx.author.name  # Get the user's name

        response_embed = discord.Embed(
            title=f"📁 Attachment Detected: {file_info.filename} 📁",
            description=(
                f"**{user_name}**, I see you attached a file 📁 **{file_info.filename}** 📁, **{user_name}**. "
                f"Would you like to process this file and make some recommendations? "
                f"Default value of **No/Red X** will be selected after {GLOBAL_TIMEOUT} seconds."
            ),
            color=discord.Color.blurple()
        )

        # Send the response embed and reactions
        sent_msg = await ctx.send(embed=response_embed)
        await sent_msg.add_reaction("✅")  # Tick
        await sent_msg.add_reaction("❌")  # Cross

        try:
            reaction, user = await ctx.bot.wait_for(
                "reaction_add",
                timeout=GLOBAL_TIMEOUT,
                check=lambda r, u: (u == ctx.author or u.guild_permissions.manage_messages) and str(
                    r.emoji) in ["✅", "❌"]
            )

            if str(reaction.emoji) == "✅":
                try:
                    await sent_msg.clear_reactions()  # Clear reactions
                except discord.Forbidden:
                    pass  # If the bot doesn't have permission to manage messages
                return "✅", user  # Return the decision and the user
            elif str(reaction.emoji) == "❌":
                try:
                    await sent_msg.clear_reactions()  # Clear reactions
                except discord.Forbidden:
                    pass  # If the bot doesn't have permission to manage messages
                return "❌", user  # Return the decision and the user
        except asyncio.TimeoutError:
            try:
                await sent_msg.clear_reactions()  # Clear reactions
            except discord.Forbidden:
                pass  # If the bot doesn't have permission to manage messages
            return "❌", None  # Return "❌" and None if timeout occurs
        finally:
            # Edit the original message with the byebye_message
            await sent_msg.edit(
                embed=discord.Embed(description=f"📝 If you want to review this again, **{user_name}**:\n"
                                                f":one: Right-click (or long press with phone) on the message that contains the log\n"
                                                f":two: Select: `Copy Message Link`\n"
                                                f":three: Use the command: `/logscan <message_link>` or `!logscan <message_link>` "
                                                f"and paste the value copied from the previous step where you see `<message_link>` 📝",
                                    color=discord.Color.blurple()))

    async def process_attachment(self, ctx, linked_message_author, invoker, attachment, content, content_bytes):
        # Your processing code when "✅" is clicked
        mylogger.info(f"process_attachment is starting")
        incomplete_message = ""
        special_message = None
        parsed_content = await self.parse_attachment_content(content_bytes)
        # mylogger.info(f"parsed_content:{parsed_content}")
        header_lines = self.extract_header_lines(parsed_content)
        finished_lines = self.extract_last_lines(parsed_content)
        summary_lines = self.extract_finished_runs(parsed_content)
        plex_config_sections = self.extract_plex_config(parsed_content)
        parsed_yaml, yaml_message, config_content = self.extract_config(parsed_content)
        parsed_yaml, schema_message, config_content = self.extract_config_schema(parsed_content)
        server_icon_url = self.get_server_icon_url(ctx)
        self.checkfiles_flg = None

        # Call send_start_message to send the start message
        # await self.send_start_message(ctx, attachment)

        # mylogger.info(f"Summary Lines: {summary_lines}")

        # Call the create_user_info_embed method
        user_info_embed = self.create_user_info_embed(linked_message_author, invoker, attachment.filename)
        # mylogger.info("user_info_embed:")
        # mylogger.info(f"Title: {user_info_embed.title}")
        # mylogger.info(f"Description: {user_info_embed.description}")
        # mylogger.info(f"Color: {user_info_embed.color}")

        # Call the create_kometa_info_embed method
        kometa_info_embed, incomplete_message = self.create_kometa_info_embed(header_lines, finished_lines, ctx, attachment)

        # Call the create_summary_info_embed method
        summary_info_embed = self.create_summary_info_embed(summary_lines, ctx)

        # Create the Kometa config embed
        # mylogger.info(f"yaml_message: {yaml_message}")
        kometa_config_embed, incomplete_message = self.create_kometa_config_embed(yaml_message, ctx, incomplete_message)
        # mylogger.info(f"schema_message: {schema_message}")
        # kometa_config_schema_embed, incomplete_message = self.create_kometa_config_schema_embed(schema_message, ctx, incomplete_message)

        # Create the Plex Config Pages embed
        plex_config_pages, incomplete_message = self.create_plex_config_pages(plex_config_sections, incomplete_message, ctx)

        # Call the make_recommendations method
        recommendations_embed = None
        recommendations = self.make_recommendations(content, incomplete_message)

        # Call the make_recommendations method
        recommendations_embeds = []

        # Assuming recommendations_embeds is a list where you store your embeds
        if recommendations:
            # Sort the recommendations based on the specified symbols and priority
            recommendations = self.reorder_recommendations(recommendations)

            for index, recommendation_message in enumerate(recommendations, start=1):
                # Truncate the recommendation message if it exceeds the limit
                truncated_recommendation_message = recommendation_message.get('message', '')[:4093] + "..." if len(
                    recommendation_message.get('message', '')) > 4096 else recommendation_message.get('message', '')

                # Generate the padded index string
                padded_index = str(index).zfill(2)

                # Create an embed for each recommendation message
                recommendations_embed = discord.Embed(
                    title=f"**Rec {padded_index}** - {recommendation_message.get('first_line', 'No first line available')}",
                    color=discord.Color.green()
                )
                recommendations_embed.description = truncated_recommendation_message  # Assign the formatted message as description

                # Set the server icon URL for each recommendation embed
                if server_icon_url:
                    recommendations_embed.set_thumbnail(url=server_icon_url)

                recommendations_embeds.append(recommendations_embed)
        else:
            # Add a "No Recommendations" message as a separate page
            no_recommendations_embed = discord.Embed(title="**No Recommendations**", color=discord.Color.green(), )
            no_recommendations_embed.description = "😔 There are no recommendations at the moment. 😔"
            # Set the server icon URL for each recommendation embed
            if server_icon_url:
                no_recommendations_embed.set_thumbnail(url=server_icon_url)
            recommendations_embeds.append(no_recommendations_embed)

        # Call the scan_text_files function on the content of the attached file to deal with People Posters
        found_items, not_found_names, not_found_names_with_url = self.scan_file_for_people_posters(content)

        # Check if any of the lists is empty or None
        people_posters_embed = None
        if not found_items and not not_found_names and not not_found_names_with_url:
            # None of the lists have data, so no embed is created
            pass
        else:
            # Send the people posters as an embed
            people_posters_embed = self.create_people_posters_embed(ctx, found_items, not_found_names,
                                                                    not_found_names_with_url)
        # After sending people posters as an embed
        if not_found_names or not_found_names_with_url:
            await self.send_people_poster_request(ctx, target_thread_id, specific_user_id)

        if self.checkfiles_flg == 1:
            await self.send_to_masters(ctx, target_masters_thread_id, sohjiro_id, "**checkFiles=1** detected in a user uploaded log file by:")

        # Initialize an empty list for pages
        pages = []

        # Add other pages if available
        if user_info_embed:
            pages.append({"content": "", "embed": user_info_embed})

        if kometa_info_embed:
            pages.append({"content": "", "embed": kometa_info_embed})

        if summary_info_embed:
            pages.append({"content": "", "embed": summary_info_embed})

        if kometa_config_embed:
            pages.append({"content": "", "embed": kometa_config_embed})

        # if kometa_config_schema_embed:
        #     pages.append({"content": "", "embed": kometa_config_schema_embed})

        # Check if people_posters_embed is not None (no people found), add it to pages
        if people_posters_embed:
            pages.append({"content": "", "embed": people_posters_embed})

        # Add plex_config_pages if available
        pages += plex_config_pages

        # Append each recommendation embed separately to the pages list
        for recommendation_embed in recommendations_embeds:
            pages.append({"content": "", "embed": recommendation_embed})

        # Add TOC for the "User Info" page
        toc_entries, toc_text = self.generate_toc_entries_and_string(pages, recommendations)

        # Generate the TOC string
        toc_string = "\n".join([f"`Page {str(entry['page']).zfill(2)}:` {entry['name']}" for entry in toc_entries])
        # mylogger.info(f"toc_string: {toc_string}")

        # Combine TOC header and string
        toc_header = f"{user_info_embed.description}\n\nTable of Contents:"
        full_toc_string = f"{toc_header}\n{toc_string}"

        # Check if the combined TOC string exceeds the character limit
        if len(full_toc_string) > 4096:
            # Truncate at 4093 characters and add "..."
            truncated_toc_string = full_toc_string[:4093] + "..."
            user_info_embed.description = truncated_toc_string
        else:
            # Set the full TOC string as the description
            user_info_embed.description = full_toc_string

        menu = MyMenu(
            pages,
            invoker=ctx.author,
            timeout=MENU_TIMEOUT,
            page_start=0,
            delete_after_timeout=False,
            disable_after_timeout=True,
            use_select_menu=True,
            use_select_only=False,
        )

        menu.embed = recommendations_embed  # Set the menu's embed to the recommendations_embed

        try:
            # Check the type of ctx and use the appropriate method to start the menu
            mylogger.info(f"STANDARD: Starting menu.")
            await menu.start(ctx)  # Start the menu for regular messages

        except AttributeError as e:
            # Handle the AttributeError if needed
            mylogger.error(f"STANDARD: An error occurred while starting the menu. {e}")
            await ctx.send(f"An error occurred while starting the menu.")

        # Call the send_config_content function to extract extracted config.yml file
        # Prompt the user for whether they want the .yml file attached
        if config_content:
            # There is extracted content for config.yml
            prompt_embed = discord.Embed(
                title="Extract File?",
                description="Do you want to see the extracted config.yml file?",
                color=discord.Color.blurple()
            )
            prompt_embed.add_field(name="Yes", value="Extract the file", inline=True)
            prompt_embed.add_field(name=f"No (**Default after {CONFIG_MENU_TIMEOUT} seconds**)",
                                   value=f"Don't extract file", inline=True)

            prompt_message = await ctx.send(embed=prompt_embed)

            # Add reactions for Yes and No
            await prompt_message.add_reaction("✅")  # Yes
            await prompt_message.add_reaction("❌")  # No

            def check(reaction, user):
                return (user == ctx.author or any(role.id in ALLOWED_ROLE_IDS for role in user.roles)) and \
                    reaction.message == prompt_message and str(reaction.emoji) in ["✅", "❌"]

            try:
                reaction, _ = await self.bot.wait_for("reaction_add", timeout=CONFIG_MENU_TIMEOUT, check=check)

                if str(reaction.emoji) == "✅":
                    # User wants to extract the .yml file
                    await self.send_config_content(ctx, linked_message_author, config_content, attachment)
                    await prompt_message.delete()
                else:
                    # User doesn't want to extract the .yml file
                    await prompt_message.delete()

            except asyncio.TimeoutError:
                # User didn't respond within 30 seconds, delete the prompt message
                await prompt_message.delete()

        # Call the send_completion_message function
        # await self.send_completion_message(ctx, attachment)

    @commands.hybrid_command(name="logscan")
    @app_commands.describe(message_link="The discord message link you want to scan.")
    async def kometa_logscan(self, ctx: commands.Context, message_link: commands.MessageConverter):
        # Check if the message is from a DM (Direct Message)
        if not ctx.guild:
            # Message is from a DM or outside a guild
            # Handle User object without guild-related attributes
            mylogger.info("SLASH-Logscan is not currently supported in DM Channel with bot. Aborting...")
            # Check if the message author is the bot itself to avoid responding to its own messages
            if ctx.author == self.bot.user:
                return
            # Send a message to the user explaining that log scanning is not supported in DMs with the bot
            # await message.channel.send("Logscan is not currently supported in DM Channel with bot. Aborting...")
            return

        # Log command invocation details
        author_name = f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author else "Unknown"
        guild_name = ctx.guild.name if ctx.guild else "Direct Message"
        channel_name = ctx.channel.name if isinstance(ctx.channel, discord.TextChannel) else "Direct Message"
       
        mylogger.info(f"SLASH-Logscan invoked by {author_name} in {guild_name}/{channel_name} (ID: {ctx.guild.id if ctx.guild else 'N/A'}/{ctx.channel.id if ctx.guild else 'N/A'})")

        try:
            self.reset_server_versions()
            # Add a unique log message to identify when the event is triggered
            mylogger.info(f"SLASH-Received message (ID: {message_link.id}) from {message_link.author.name} in #{message_link.channel.name}")
            mylogger.info(f"script_env: {script_env}")
            mylogger.info(f"ALLOWED_HELP: {ALLOWED_HELP}")
            mylogger.info(f"ALLOWED_TEST: {ALLOWED_TEST}")
            mylogger.info(f"ALLOWED_CHAT: {ALLOWED_CHAT}")
            bad_channel = False
            friendly_ALLOWED_HELP = self.bot.get_channel(ALLOWED_HELP).jump_url
            friendly_ALLOWED_TEST = self.bot.get_channel(ALLOWED_TEST).jump_url
            friendly_ALLOWED_CHAT = self.bot.get_channel(ALLOWED_CHAT).jump_url
            bad_channel_msg = f"💡 Parsing logs in this channel is not permitted. Use {friendly_ALLOWED_HELP}, {friendly_ALLOWED_CHAT}, or create a thread and post log in that newly created thread.💡"

            if isinstance(ctx.channel, discord.Thread):
                # This message is in a thread
                thread_id = ctx.channel.id
                mylogger.info(f"The message is in the thread with ID: {thread_id}")
            else:
                # This message is not in a thread
                mylogger.info("The message is not in a thread")
                # Check if the current channel is allowed
                allowed_channels = [ALLOWED_TEST, ALLOWED_CHAT]
                mylogger.info(f"message.channel.id: {ctx.channel.id}")
                if ctx.channel.id not in allowed_channels:
                    bad_channel = True
                    mylogger.info("Message received in a channel that is not allowed.")
            if message_link is not None:
                try:
                    linked_message = message_link
                    attachment = linked_message.attachments[0]
                    filename, extension = os.path.splitext(attachment.filename.lower())

                    if extension in SUPPORTED_COMPRESSED_FORMATS:
                        mylogger.info(
                            f"SLASH-Compressed file detected. Sending {attachment.filename} to handle_compressed_file")
                        extracted_files = await self.handle_compressed_file(ctx, attachment)

                        # Process each extracted file
                        for extracted_file in extracted_files:
                            file_name, content, content_bytes = extracted_file
                            # Check if the extracted file has a supported extension
                            if any(file_name.lower().endswith(ext) for ext in SUPPORTED_FILE_EXTENSIONS):
                                if ("[kometa.py:" in content  or "plex_meta_manager.py:" in content) and not bad_channel:
                                    mylogger.info(
                                        f"SLASH-kometa.py/plex_meta_manager.py: detected in content. Sending to prompt_user_and_get_decision")
                                    decision, invoker = await self.prompt_user_and_get_decision(ctx, attachment)

                                    if decision == "✅":
                                        # Rest of the processing code when "✅" is clicked
                                        await self.process_attachment(ctx, linked_message.author, ctx.author,
                                                                      attachment, content,
                                                                      content_bytes)
                                else:
                                    if bad_channel:
                                        await ctx.reply(bad_channel_msg, delete_after=20, suppress_embeds=True)
                                    else:
                                        mylogger.info(f"SLASH-💥File {file_name} extracted from the compressed file {attachment.filename} does not seem to be a complete or valid Kometa log file.💥")
                                        return
                            else:
                                mylogger.info(
                                    f"SLASH-💥File {file_name} extracted from the compressed file {attachment.filename} is not a supported format.💥")
                    else:
                        content_bytes = await attachment.read()
                        try:
                            content = content_bytes.decode("utf-8")
                        except UnicodeDecodeError as e:
                            mylogger.error(f"UnicodeDecodeError: {e}")
                            content = content_bytes.decode("utf-8", errors="replace")

                        if ("[kometa.py:" in content  or "plex_meta_manager.py:" in content) and not bad_channel:
                            mylogger.info(
                                f"SLASH-kometa.py/plex_meta_manager.py: detected in content. Sending to prompt_user_and_get_decision")
                            decision, invoker = await self.prompt_user_and_get_decision(ctx, attachment)

                            if decision == "✅":
                                await self.process_attachment(ctx, linked_message.author, ctx.author, attachment,
                                                              content,
                                                              content_bytes)
                        else:
                            if bad_channel:
                                await ctx.reply(bad_channel_msg, delete_after=20, suppress_embeds=True)
                                return
                            else:
                                mylogger.info(f"SLASH-💥Attachment {attachment.filename} does not seem to be a complete or valid Kometa log file.")
                                await ctx.send(
                                    f"💥Attachment {attachment.filename} does not seem to be a complete or valid Kometa log file.💥", ephemeral=True)
                except IndexError:
                    mylogger.info("SLASH-💥The specified message has no attachments.")
                    await ctx.send("💥The specified message has no attachments.💥", ephemeral=True)
                except Exception as e:
                    mylogger.error(f"SLASH-💥Error while processing attachment: {str(e)}")
                    await ctx.send("💥An error occurred while processing the attachment.💥", ephemeral=True)
            else:
                mylogger.info(
                    f"SLASH-💥Please specify a valid Message Link (r-click on Discord message and `Copy Message Link`)💥")
                await ctx.send(
                    f"💥Please specify a valid Message Link (r-click on Discord message and `Copy Message Link`)💥")
        except Exception as e:
            mylogger.error(f"SLASH-💥An unexpected error occurred: {str(e)}")
            await ctx.send("💥An unexpected error occurred.💥", ephemeral=True)

    @commands.Cog.listener()
    async def on_message(self, message):
        # Check if the message is from a DM (Direct Message)
        if not message.guild:
            # Message is from a DM or outside a guild
            # Handle User object without guild-related attributes
            mylogger.info("Logscan is not currently supported in DM Channel with bot. Aborting...")
            # Check if the message author is the bot itself to avoid responding to its own messages
            if message.author == self.bot.user:
                return
            # Send a message to the user explaining that log scanning is not supported in DMs with the bot
            # await message.channel.send("Logscan is not currently supported in DM Channel with bot. Aborting...")
            return

        # Initialize ctx outside the loop
        ctx = await self.bot.get_context(message)
        # Log command invocation details
        author_name = f"{message.author.name}#{message.author.discriminator}" if message.author else "Unknown"
        guild_name = message.guild.name if message.guild else "Direct Message"
        channel_name = message.channel.name if isinstance(message.channel, discord.TextChannel) else "Direct Message"
   
        mylogger.info(f"Logscan invoked by {author_name} in {guild_name}/{channel_name} (ID: {message.guild.id if message.guild else 'N/A'}/{message.channel.id if message.guild else 'N/A'})")

        self.reset_server_versions()

        if message.author == self.bot.user:
            return

        mylogger.info(f"script_env: {script_env}")
        mylogger.info(f"ALLOWED_HELP: {ALLOWED_HELP}")
        mylogger.info(f"ALLOWED_TEST: {ALLOWED_TEST}")
        mylogger.info(f"ALLOWED_CHAT: {ALLOWED_CHAT}")
        bad_channel = False
        friendly_ALLOWED_HELP = self.bot.get_channel(ALLOWED_HELP).jump_url
        friendly_ALLOWED_TEST = self.bot.get_channel(ALLOWED_TEST).jump_url
        friendly_ALLOWED_CHAT = self.bot.get_channel(ALLOWED_CHAT).jump_url
        bad_channel_msg = f"💡 If you would like me to scan your log and make helpful recommendations, post your log file in {friendly_ALLOWED_HELP}, {friendly_ALLOWED_CHAT}, or create a thread and post log in that newly created thread.💡"

        content = message.content.lower()
        user = message.author

        author_has_allowed_role = any(role.id in ALLOWED_ROLE_IDS for role in message.author.roles)

        if not (author_has_allowed_role or message.author):
            return

        if message.content.strip() == NOPARSE_COMMAND and not message.attachments:
            return

        if NOPARSE_COMMAND in message.content:
            mylogger.info(f"!noparse detected by {message.author.name}")
            embed = discord.Embed(
                title="💥NOPARSE Override Detected!💥",
                description=(
                    f"↑↑↑ {message.author.mention}. Too bad 😢! As a bot, I love to parse messages!\n\n"
                    f"📝 If you change your mind, **{message.author}**:\n"
                    f":one: Right-click (or long press with phone) on the message that contains the log\n"
                    f":two: Select: `Copy Message Link`\n"
                    f":three: Use the command: `/logscan <message_link>` or `!logscan <message_link>` "
                    f"and paste the value copied from the previous step where you see `<message_link>` 📝\n\n"
                    f"*This message will self-destruct in 30 seconds...*"
                ),
                color=discord.Color.blurple()
            )
            await message.channel.send(embed=embed, delete_after=30)  # Set delete_after as needed
            return

        if isinstance(message.channel, discord.Thread):
            # This message is in a thread
            thread_id = message.channel.id
            mylogger.info(f"The message is in the thread with ID: {thread_id}")
        else:
            # This message is not in a thread
            mylogger.info("The message is not in a thread")
            # Check if the current channel is allowed
            allowed_channels = [ALLOWED_TEST, ALLOWED_CHAT]
            mylogger.info(f"message.channel.id: {message.channel.id}")
            if message.channel.id not in allowed_channels:
                bad_channel = True
                mylogger.info("Message received in a channel that is not allowed. Aborting.")

        if message.attachments:
            for attachment in message.attachments:
                filename, extension = os.path.splitext(attachment.filename.lower())

                if extension in SUPPORTED_COMPRESSED_FORMATS:
                    mylogger.info(f"Compressed file detected. Sending {attachment.filename} to handle_compressed_file")
                    extracted_files = await self.handle_compressed_file(ctx, attachment)

                    # Process each extracted file
                    for extracted_file in extracted_files:
                        file_name, content, content_bytes = extracted_file
                        # Check if the extracted file has a supported extension
                        if any(file_name.lower().endswith(ext) for ext in SUPPORTED_FILE_EXTENSIONS):
                            if ("[kometa.py:" in content or "plex_meta_manager.py:" in content) and not bad_channel:
                                mylogger.info(
                                    f"kometa.py/plex_meta_manager.py: detected in content. Sending to prompt_user_and_get_decision")
                                decision, invoker = await self.prompt_user_and_get_decision(ctx, attachment)

                                if decision == "✅":
                                    # Rest of the processing code when "✅" is clicked
                                    await self.process_attachment(ctx, user, invoker, attachment, content,
                                                                  content_bytes)
                            else:
                                if bad_channel:
                                    await message.reply(bad_channel_msg, delete_after=20, suppress_embeds=True)
                                    return
                                else:
                                    mylogger.info(f"💥File {file_name} extracted from the compressed file {attachment.filename} does not seem to be a complete or valid Kometa log file.💥")
                        else:
                            mylogger.info(f"💥File {file_name} extracted from the compressed file {attachment.filename} is not a supported format.💥")
                elif extension in SUPPORTED_FILE_EXTENSIONS:
                    mylogger.info(f"Valid extension detected for {attachment.filename}.")
                    content_bytes = await attachment.read()
                    try:
                        content = content_bytes.decode("utf-8")
                    except UnicodeDecodeError as e:
                        mylogger.error(f"UnicodeDecodeError: {e}")
                        content = content_bytes.decode("utf-8", errors="replace")

                    if ("[kometa.py:" in content or "plex_meta_manager.py:" in content) and not bad_channel:
                        mylogger.info(f"kometa.py/plex_metamanager.py: detected in content. Sending to prompt_user_and_get_decision")
                        decision, invoker = await self.prompt_user_and_get_decision(ctx, attachment)

                        if decision == "✅":
                            # Rest of the processing code when "✅" is clicked
                            await self.process_attachment(ctx, user, invoker, attachment, content, content_bytes)
                    else:
                        if bad_channel:
                            await message.reply(bad_channel_msg, delete_after=20, suppress_embeds=True)
                            return
                        else:
                            mylogger.info(f"💥Attachment {attachment.filename} does not seem to be a complete or valid Kometa log file.💥")
                else:
                    mylogger.info(f"💥Attachment {attachment.filename} is not from a supported file format.💥")
