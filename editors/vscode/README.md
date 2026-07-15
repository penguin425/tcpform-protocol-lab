# tcpform for Visual Studio Code

This extension turns `.tcpf` files into a complete tcpform workspace. It starts
`tcpform lsp` for completion, diagnostics, definition navigation, symbols,
refactoring, and formatting, and adds editor-native execution tools.

## Features

- TextMate syntax highlighting and bracket/comment configuration
- LSP completion, diagnostics, definitions, references, rename, and hover
- Formatting and format on save
- CodeLens actions above every protocol for `run`, `test`, and Visualizer
- tcpform tasks with problem matching
- Embedded Visualizer in a side-by-side webview
- Automatic generation and refresh of the tcpform DSL v2 JSON Schema

Set `tcpform.executable` when `tcpform` is not on `PATH`. Commands are available
from the Command Palette under `tcpform:`.

## Development

```sh
npm ci
npm test
npm run package
```
