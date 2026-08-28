from .logscan import RedBotCogLogscan


async def setup(bot):
    await bot.add_cog(RedBotCogLogscan(bot))
