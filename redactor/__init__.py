from .redactor import RedBotCogRedactor


async def setup(bot):
    await bot.add_cog(RedBotCogRedactor(bot))
