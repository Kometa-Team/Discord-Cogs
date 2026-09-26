from .rolemerge import RoleMerge


async def setup(bot):
    await bot.add_cog(RoleMerge(bot))