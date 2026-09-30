# ClipboardProtector

English · [中文](readme.md)

Monitor clipboard access on Windows and allow, block or ask about access using process and content rules. Detect BTC, ETH and SOL address replacement, including addresses within paragraphs.

**Version: 0.1.0-alpha, development preview.** Global injection, long-running compatibility and startup after reboot have not completed validation. Use a separate Windows test environment; this is not a production security guarantee. See the [validation record](doc/validation.md) (Chinese).

## Features

- Clipboard access log, filters, details and CSV export.
- Ordered rules for process names/paths, source processes, read/write operations, formats and text patterns.
- Allow, block or ask for each access, with independent notification and log visibility settings.
- Optional BTC / ETH / SOL address replacement protection.
- Private text clipboard stored in memory, with configurable copy/paste shortcuts.
- Tray controls, persistent settings and optional Windows startup.
- Chinese and English interfaces in the same executable.

## Getting started

Requires Windows 10/11 x64. Extract the entire release package and keep the executable, DLLs and helpers together. Release builds request administrator privileges and are currently unsigned.

Download the ZIP and its SHA-256 checksum from this repository's **Releases** page. Version tags trigger automatic builds and publication; versions with an alpha, beta or rc suffix are marked as pre-releases. If no release is available yet, follow the build instructions below.

1. Start `ClipboardProtector.exe` in a test environment.
2. Choose **Options > 语言 / Language > English**. On a fresh installation, Chinese Windows defaults to Chinese; other Windows UI languages default to English. Existing configurations without a language preference retain Chinese.
3. Choose **Protection > Enable protection** to cover compatible desktop applications. Use disposable content to test access rules.
4. Enable Crypto address protection in Settings if needed. User-initiated Ctrl+C / Ctrl+Insert permits updating the protected address; ordinary access rules remain independent.
5. To stop, disable protection or choose **Window > Exit**. Closing the main window hides it to the tray.

Changing language updates the interface without restarting protection. Your rule names, clipboard text, process names and paths remain unchanged. CSV headings and status descriptions use the selected language. System-owned dialogs may follow the Windows display language.

## Private clipboard

Select text in an injected application and press **Alt+Shift+C**. Focus a target input and press **Alt+Shift+V** to paste. Both targets must have the current hook installed and confirm readiness. Configure shortcuts under **Options > Keyboard shortcuts**; clear stored text under **Options > Clear private clipboard**. Exiting also clears it.

Only text is supported, up to 65536 UTF-16 code units. Private text is not stored in the configuration or access log and does not enter the system clipboard. It does not protect against keyloggers, process memory access or the target application saving the content.

If input was sent but the operation did not complete, the target clipboard remains isolated to prevent late writes. **Restart that target application to restore normal copy/paste.** Custom asynchronous copy/paste and cross-process proxies may be incompatible.

## Coverage and privacy

Protection applies only to processes that actually load the Hook DLL. Protected processes, some UWP/AppContainer applications and access bypassing the intercepted APIs may be outside coverage. Verify the final destination address before transferring funds.

Text previews are enabled by default and may retain clipboard prefixes in memory. Exports, notifications and confirmation windows can also contain sensitive information. Image/file snapshots are off by default. Use fictional data in reports and screenshots.

Configuration: `%APPDATA%\ClipboardProtector\config.json`. Before upgrading, exit and replace the complete set of matching components. Before removing the application, disable Windows startup and exit it.

## Building

Requires Git, Visual Studio 2022 or Build Tools with C++ desktop development and a Windows SDK, and CMake 3.20+. See [build and test instructions](doc/development.md) (Chinese). Build a release package with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/package-release.ps1
```

The script requires a clean working tree by default and writes a ZIP and SHA-256 checksum to `dist/`.

Project code is licensed under [MIT](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md), [contribution instructions](CONTRIBUTING.md) and [security reporting](SECURITY.md).
