# Command and filter syntax

## Command field

Type into the command field in the toolbar (`Alt Q`) and press `Enter`. *Help → Command
Syntax* and the command `help` show this list in the app.

| Command | Effect |
|---|---|
| `?text` | select sessions whose URL contains *text* |
| `>10k`, `<5k` | select by response size (`k`, `m`, `g` suffixes) |
| `=404`, `=POST` | select by status code or method |
| `@host` | select by host |
| `select type` | select by content type, e.g. `select image` |
| `find expr` | select sessions matching a filter expression |
| `filter expr` | hide sessions not matching *expr*; `filter` alone removes it |
| `keeponly type` | remove sessions whose content type does not match |
| `cls`, `clear` | remove all sessions |
| `tail 100` | keep the most recent 100 sessions |
| `bpu [text]` | break before requests (URL contains *text*); without text: off |
| `bpafter [text]` | break after responses (URL contains *text*); without text: off |
| `bps 500` | break on a response status; `bps` alone: off |
| `bpv POST`, `bpm POST` | break on a request method; alone: off |
| `g`, `go` | resume all paused sessions |
| `dump` | save all sessions as `.saz` |
| `start`, `stop` | start or stop capturing |
| `help` | show the syntax |

## Filter expressions

Filter expressions are used by `filter` and `find` in the command field and by
*Filters → Advanced expression*.

```text
host ~= "*.company.de" and method == POST and status >= 400
status == 4xx
size > 10k
time > 1s
not kind == tunnel
```

### Fields

| Field | Aliases | Meaning |
|---|---|---|
| `host` | | host |
| `url` | | full URL |
| `path` | | path and query |
| `method` | `verb` | HTTP method |
| `status` | `result`, `code` | response status; `4xx` style values allowed |
| `type` | `ctype`, `content-type`, `mime` | response content type |
| `process` | `proc` | client process |
| `size` | `body`, `respsize` | response body size (`k`, `m`, `g`) |
| `reqsize` | | request body size |
| `time` | `duration`, `ms` | duration (`200`, `200ms`, `1.5s`, `2m`) |
| `comment` | `comments` | comment |
| `protocol` | `proto` | protocol |
| `color` | `mark`, `marked` | mark colour (`red`, `blue`, …; `''` for none) |
| `kind` | | session kind, e.g. `tunnel` |
| `client` | `clientip` | client address |
| `custom` | | the Custom column |
| `id` | `#` | session number |
| `conn` | `connection` | client connection id (sessions of one keep-alive or HTTP/2 connection) |
| `trace` | `correlation` | trace or correlation id of the request |
| `session` | `sessioncookie` | session cookie as `NAME #hash` |

### Operators

| Operator | Meaning |
|---|---|
| `==`, `!=` | equal, not equal |
| `~=` | wildcard match (`*`, `?`) |
| `~`, `!~` | contains, does not contain |
| `=~` | regular expression |
| `<`, `<=`, `>`, `>=` | numeric comparison |
| `and` / `&&`, `or` / `||`, `not` / `!`, `( )` | combine |

A bare word matches sessions whose URL contains it (case-insensitive).

## Mock Rules patterns

The match patterns and actions of Mock Rules are listed in
[Change and replay → Mock Rules](change-replay.md#match-patterns).
