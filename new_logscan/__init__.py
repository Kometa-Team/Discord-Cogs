from .logscan import LogScan


async def setup(bot):
    await bot.add_cog(LogScan(bot))
