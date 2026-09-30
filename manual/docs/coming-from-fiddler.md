# Coming from Fiddler Classic

Quena is an independent HTTP(S) debugging proxy with its own design. If you have used
Fiddler Classic, much of your workflow carries over: the same file formats, the same filter
and command syntax and familiar keyboard shortcuts. Quena uses its own names for some
features — this page maps them. The same overview is in the app under
*Help → Coming from Fiddler Classic…*.

!!! info "Not affiliated"
    Quena is an independent project. It is not affiliated with, endorsed by, or connected
    to Progress Software Corporation or the Fiddler product family. *Fiddler* is a
    trademark of its respective owner and is mentioned here only to describe familiarity
    and compatibility.

## Your files

| You have | In Quena |
|---|---|
| Session archives (`.saz`) | *File → Import Sessions → SAZ Archive…*, or drop them onto the window; *File → Export Sessions → SAZ Archive…* to hand sessions back to colleagues |
| AutoResponder rules (`.farx`) | **Mock Rules** tab → *Import…* / *Export…* |
| HTTP archives (`.har`) | *File → Import / Export Sessions → HTTP Archive (HAR)…* |

See [Archives and copying](archives.md) and [Mock Rules](change-replay.md#mock-rules).

## Names

| Fiddler Classic | Quena |
|---|---|
| QuickExec | **Command field** in the toolbar (`Alt Q`); every menu command is also in the **command palette** (`Ctrl/⌘ K`) |
| AutoResponder | **Mock Rules** |
| Inspectors | **Inspect** |
| TextView / SyntaxView / WebForms / HexView | **Plain Text** / **Body** / **Form Data** / **Hex** |
| ImageView / WebView / Transformer | **Image** / **Preview** / **Encoding** |
| TextWizard | **Text Tools** (`Ctrl/⌘ E`) |
| FiddlerScript, *Rules → Customize Rules…* | **Rules Script** in JavaScript (*Capture → Rules Script…*, `Ctrl/⌘ R`) — see [Rules scripts](scripting.md) |
| *Rules* menu | **Capture** menu (breakpoints, mock rules, rules script, authentication); the *Hide …* items are in *View → Hide in List* |
| Reissue … | **Replay …** |
| Any Process | **Process Filter** (Filters tab, status bar) |
| Hide CONNECTs | *View → Hide in List →* **Tunnels (CONNECT)** |
| Result column | **Status** column |
| Body column | **Size** column |

## Layout

Quena starts with its own layout: the session list on the left, request and response side
by side. If you prefer a dense list with more columns and the request above the response,
choose **Classic** — on first start, in *Settings → General*, or switch only the inspector
arrangement with *View → Request Above / Beside Response*. Inspectors show as many views as
fit as tabs; the others are under **More**.

## Map Remote and Map Local

Both are Mock Rules, made with *Mock Rules → Add mapping…* and editable like any rule:

| Mapping | Rule |
|---|---|
| Map Remote: a URL prefix to another server | `prefix:https://prod.example.com/api/` → `https://staging.example.com/api/` — the rest of the path and the query are appended, `Host` follows the target |
| Map Local: a URL prefix to a folder | `prefix:https://example.com/static/` → `dir:/path/to/folder` — serves the file at the rest of the path, `index.html` for folders |

`regex:` rules with `$1` in an `https://…` action keep working as before. Details:
[Map Remote](change-replay.md#map-remote), [Map Local](change-replay.md#map-local).

## Command field

The command field in the toolbar understands the syntax you know:

```text
?text   @host   =404   =POST   >100k   <5k
bpu /api   bpafter /api   bps 500   bpm POST   g
select json   keeponly image   cls   tail 1000   dump   help
```

Full list: [Command and filter syntax](syntax.md).

## Keyboard shortcuts

| Action | Shortcut |
|---|---|
| Start / stop capturing | `F12` |
| Break before requests / after responses / off | `F11` / `Alt F11` / `Shift F11` |
| Statistics / Inspect / Composer | `F7` / `F8` / `F9` |
| Rules Script | `Ctrl/⌘ R` |
| Text Tools | `Ctrl/⌘ E` |
| Find sessions | `Ctrl/⌘ F` |
| Mark red … purple / unmark | `Ctrl/⌘ 1` … `6` / `Ctrl/⌘ 0` |
| Focus the command field | `Alt Q` |
| Command palette | `Ctrl/⌘ K` |

All shortcuts: [Keyboard shortcuts](shortcuts.md).

## Scripting

Rules scripts are JavaScript instead of JScript.NET. The hooks are similar in spirit
(`onBeforeRequest`, `onBeforeResponse`, `onSessionComplete`, `onBoot`), with
`registerMenu` and `registerColumn` for custom commands and a custom column. Scripts see
headers and metadata; bodies keep streaming. See [Rules scripts](scripting.md).
