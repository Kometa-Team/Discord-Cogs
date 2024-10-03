from .version import MyVersion


async def setup(bot):
    await bot.add_cog(MyVersion(bot))
