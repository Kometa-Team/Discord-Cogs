from .honeypot import Honeypot


async def setup(bot):
    await bot.add_cog(Honeypot(bot))