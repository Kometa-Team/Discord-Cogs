# LogScan Red cog

`logscan` detects supported Kometa log attachments, asks before submitting
them to a LogScan service, and posts a result link. The uploader receives the
deletion link privately; anyone with that link can permanently delete the
associated scan.

## Install

Add this repository to Red's Downloader, then install and load the cog:

```text
[p]repo add logscan <repository-clone-url>
[p]cog install logscan logscan
[p]load logscan
```

The cog needs permission to read message content and attachments, send and
edit messages, and use message components. The bot must also be able to access
the configured channels and threads.

## Configuration

All `[p]logscanset` commands are restricted to the bot owner. Replace `[p]`
with your bot's command prefix.

### Service URL

```text
[p]logscanset url https://logscan.kometa.wiki
```

Sets the base URL for the LogScan web service. The cog uses the service's
`/api/bot/validate` endpoint before showing a prompt and `/api/bot/scan` after
the user chooses to scan.

### API key

```text
[p]logscanset apikey <api-key>
```

Sets the bearer token sent to both bot API endpoints. Use the same value as
`LOGSCAN_API_KEY` on the web service. The cog attempts to delete the command
message after saving the key; run it in a private channel regardless.

### Allowed channels

```text
[p]logscanset channels production <channel-id> [additional-channel-ids]
[p]logscanset channels test <channel-id> [additional-channel-ids]
```

Each command replaces that environment's full allowed-channel list. Automatic
attachment prompts and the `[p]logscan <message-link-or-id>` command work only
when invoked in a configured non-thread channel. Messages in unconfigured
channels receive a temporary direction message instead of a scan prompt.

Threads are permitted in either environment. This is intentional so users can
open a support thread and submit a log there.

### Active environment

```text
[p]logscanset environment production
[p]logscanset environment test
```

Chooses which allowed-channel list is active. The default is `production`.
Configure test channels before switching to `test`; an empty active list means
non-thread scanning is disabled until channels are configured.

### Privileged prompt roles

```text
[p]logscanset roles <role-id> [additional-role-ids]
[p]logscanset roles
```

The first command replaces the privileged role list. Members with one of these
roles may press **Scan log** or **No thanks** on another user's pending prompt.
The second form clears the list. Roles never bypass the allowed-channel policy.

## Scanning a message

When a supported attachment is posted in an allowed location, the cog validates
it and presents **Scan log** and **No thanks** buttons. Users can also request a
scan manually:

```text
[p]logscan <message-link-or-id>
```

The command must be run in an allowed channel or thread. It can resolve a
Discord message link from another channel when the bot has access to that
message.

Supported attachment names include `.log`, `.txt`, `.yml`, `.yaml` and the archive suffixes `.zip`, `.tar`, `.tgz`, and
`.gz`. The cog validates files with the web service before submitting them.

## Results and privacy

The public result link is safe to share with people who should view the scan.
The private deletion link is not: it includes a deletion token after
`#delete=`. URL fragments are not sent to the server, but anyone who receives
the complete deletion link can use it to delete the scan.
