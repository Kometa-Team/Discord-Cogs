from .sponsorcheck import SponsorCheck


async def setup(bot):
    await bot.add_cog(SponsorCheck(bot))
