from .redactor import RedBotCog


async def setup(bot):
    await bot.add_cog(RedBotCog(bot))
