# Archives and copying

## Session archives

Quena reads and writes two archive formats:

| Format | Use |
|---|---|
| **SAZ** (`.saz`) | Session archive compatible with Fiddler Classic. Keeps marks, comments, the Custom column and process information. |
| **HAR 1.2** (`.har`) | The HTTP Archive format that browsers' developer tools import and export. Comments are kept. |

### Saving

| Command | Saves |
|---|---|
| *File → Save → All Sessions…* (`Ctrl/⌘ S`, or the disk icon in the toolbar) | all sessions as `.saz` |
| *File → Save → Selected Sessions…* | the selected sessions as `.saz` |
| *File → Export Sessions → SAZ Archive…* / *HTTP Archive (HAR)…* | the selection if more than one session is selected, else all sessions |
| `dump` in the command field | all sessions as `.saz` |

The file name defaults to `quena_<date>_<time>.saz`. Saving runs as a background job; the
status bar shows its progress.

### Loading

- *File → Load Archive…* (`Ctrl/⌘ O`), or *File → Import Sessions → SAZ Archive… / HTTP
  Archive (HAR)…*.
- **Drag and drop** `.saz` or `.har` files onto the Quena window. Other files are skipped
  with a message.
- **Double-click** a `.har` or `.saz` file, or use *Open With → Quena*, on any platform.
  (Quena registers `.saz` only as an alternative viewer on macOS and not at all on Windows,
  so it never takes over another application's file association.)

### Recovering a capture

Quena records into a capture database on disk. If Quena did not exit cleanly, it offers to
recover the previous capture at the next start (*Settings → General → Offer to recover
sessions after a crash*). You can also open unfinished captures any time with
*File → Recover Previous Capture…*. With *Keep capture data after exit*, captures are kept
after a clean exit as well.

## Saving bodies

- *File → Save → Response Body…* / *Request Body…*, the context menu (*Save*), or the
  **Save…** button in a body view write the body of the focused session to a file —
  decoded when *Decode* is on.

## Copying sessions

Right-click the selection → **Copy**, or *Edit → Copy Session*:

| Copy | Result |
|---|---|
| *Just Url* | the URLs, one per line |
| *Summary* (`Ctrl/⌘ C`) | method, URL, status and content type |
| *Headers only* | request and response heads |
| *Full Session* | request and response with bodies (text up to 1 MB, up to 20 sessions) |
| *As cURL* | a `curl` command line |
| *As fetch (JavaScript)* | a `fetch(…)` call |
| *As PowerShell* | an `Invoke-WebRequest` command |
| *As Python requests* | a `requests` call |

For the code variants, text request bodies up to 1 MB are included inline; binary or larger
bodies are referenced as a file. Up to 50 sessions are copied at once.

*File → Export Sessions → cURL Script…* writes the selected sessions (or the first 500) as a
shell script with one `curl` command per session.

## Moving sessions elsewhere in Quena

Drag selected sessions from the list:

- onto the **Composer**, to load the first one for editing;
- onto **Mock Rules**, to create rules that answer with their recorded responses.
