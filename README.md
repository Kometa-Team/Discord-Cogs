================================================
Discord Cogs for Kometa Server Bots
================================================

------------
Installation
------------

Primarily, make sure `downloader` is loaded on the Discord bot.

.. code-block:: ini

    [p]load downloader

Next, let's add the repository to the Discord bot.

.. code-block:: ini

    [p]repo add Kometa https://github.com/Kometa-Team/Discord-Cogs

To install a cog, use this command, replacing <cog> with the name of the cog you wish to install:

.. code-block:: ini

    [p]cog install Kometa <cog>

Then you can use commands like:

.. code-block:: ini

    [p]cog update
    [p]unload <cog>
    [p]load <cog>
    [p]reload <cog>