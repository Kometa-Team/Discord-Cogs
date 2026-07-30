from importlib import reload

from . import redactor

reload(redactor)


async def setup(bot):
    await bot.add_cog(redactor.RedBotCog(bot))
