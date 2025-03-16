from .showcase_lockdown import ChannelMonitor


async def setup(bot):
    await bot.add_cog(ChannelMonitor(bot))
