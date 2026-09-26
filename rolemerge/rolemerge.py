from redbot.core import commands
import discord


class RoleMerge(commands.Cog):
    """Merge one Discord role into another."""

    def __init__(self, bot):
        self.bot = bot

    @commands.guild_only()
    @commands.admin_or_permissions(manage_roles=True)
    @commands.command(name="mergerole")
    async def merge_role(
        self,
        ctx: commands.Context,
        source_role_id: int,
        target_role_id: int
    ):
        """
        Merge all members from one role into another.

        Usage:
        !mergerole <source_role_id> <target_role_id>
        """

        guild = ctx.guild

        source_role = guild.get_role(source_role_id)
        target_role = guild.get_role(target_role_id)

        # Validate roles

        if source_role is None:
            await ctx.send(
                f"Could not find the source role `{source_role_id}`."
            )
            return

        if target_role is None:
            await ctx.send(
                f"Could not find the target role `{target_role_id}`."
            )
            return

        if source_role == target_role:
            await ctx.send(
                "The source and target roles cannot be the same."
            )
            return

        bot_member = guild.me

        if source_role >= bot_member.top_role:
            await ctx.send(
                f"I cannot manage **{source_role.name}** because it is "
                "higher than or equal to my highest role."
            )
            return

        if target_role >= bot_member.top_role:
            await ctx.send(
                f"I cannot manage **{target_role.name}** because it is "
                "higher than or equal to my highest role."
            )
            return

        # Snapshot members before removing the source role

        members = list(source_role.members)
        total = len(members)

        if total == 0:
            await ctx.send(
                f"**{source_role.name}** (`{source_role.id}`) "
                "does not have any members."
            )
            return

        # Start progress message

        progress_message = await ctx.send(
            f"**Role Merge**\n\n"
            f"**{source_role.name}** (`{source_role.id}`)\n"
            f"->\n"
            f"**{target_role.name}** (`{target_role.id}`)\n\n"
            f"**Progress:** 0 / {total}\n"
            f"`--------------------` **0.0%**\n\n"
            f"Updated: **0**\n"
            f"Already had target role: **0**\n"
            f"Failed: **0**"
        )

        updated = 0
        already_had = 0
        failed_members = []

        # Process members

        for index, member in enumerate(members, start=1):

            try:
                had_target = target_role in member.roles

                # Keep all existing roles except the source role
                new_roles = [
                    role
                    for role in member.roles
                    if role != source_role
                ]

                # Add target role if they do not already have it
                if not had_target:
                    new_roles.append(target_role)

                # Update the member's roles in one API request
                await member.edit(
                    roles=new_roles,
                    reason=f"Role merge initiated by {ctx.author}"
                )

                updated += 1

                if had_target:
                    already_had += 1

            except (discord.Forbidden, discord.HTTPException) as error:
                failed_members.append(
                    (member.name, str(error))
                )

            # Update progress every 10 members
            # and always update on the final member

            if index % 10 == 0 or index == total:

                percentage = (index / total) * 100

                filled = round(percentage / 5)

                bar = (
                    "#" * filled
                    + "-" * (20 - filled)
                )

                await progress_message.edit(
                    content=(
                        f"**Role Merge**\n\n"
                        f"**{source_role.name}** "
                        f"(`{source_role.id}`)\n"
                        f"->\n"
                        f"**{target_role.name}** "
                        f"(`{target_role.id}`)\n\n"
                        f"**Progress:** {index} / {total}\n"
                        f"`{bar}` **{percentage:.1f}%**\n\n"
                        f"Updated: **{updated}**\n"
                        f"Already had target role: "
                        f"**{already_had}**\n"
                        f"Failed: **{len(failed_members)}**"
                    )
                )

        # Build failure list

        failure_text = ""

        if failed_members:
            failure_list = "\n".join(
                f"- `{username}`"
                for username, error in failed_members
            )

            # Avoid Discord's message length limit
            if len(failure_list) > 1400:
                failure_list = failure_list[:1400]
                failure_list += (
                    "\n- Additional failures omitted"
                )

            failure_text = (
                f"\n\n**Failed members:**\n"
                f"{failure_list}"
            )

        # Final progress message

        await progress_message.edit(
            content=(
                f"**Role Merge Complete**\n\n"
                f"**{source_role.name}** "
                f"(`{source_role.id}`)\n"
                f"->\n"
                f"**{target_role.name}** "
                f"(`{target_role.id}`)\n\n"
                f"**Processed:** {total}\n"
                f"Successfully updated: **{updated}**\n"
                f"Already had target role: "
                f"**{already_had}**\n"
                f"Failed: **{len(failed_members)}**"
                f"{failure_text}\n\n"
                f"The source role has NOT been deleted."
            )
        )


async def setup(bot):
    await bot.add_cog(RoleMerge(bot))