# Browser Session Transfer

Windows CLI for copying cookies from one browser to another.

Supported browsers: Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Arc.

## Install

```pwsh
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Close both browsers first.

```pwsh
# List detected browsers/profiles
python transfer.py --list

# Transfer all cookies
python transfer.py --source chrome --target brave

# Transfer selected domains
python transfer.py --source chrome --target brave --domains github.com,gitlab.com

# Use specific profiles
python transfer.py --source chrome --target brave --source-profile "Profile 1" --target-profile "Profile 2"

# Export/import JSON
python transfer.py --source chrome --export cookies.json
python transfer.py --import cookies.json --target brave

# Explicit User Data paths
python transfer.py --source-path "D:\old\User Data" --target-path "D:\new\User Data"

# Validate without writing
python transfer.py --source chrome --target brave --dry-run
```

The target `Cookies` DB is backed up as `Cookies.bak` before writing.

## Chrome 127+ / App-Bound Encryption

Chrome 127+ may store cookies with App-Bound Encryption (`v20`). For those
cookies, this tool needs `chromelevator_x64.exe` to extract the app-bound key.

`chromelevator_x64.exe` is **not bundled** here because it is a third-party
binary from another project.

Get or build it from the upstream project:
https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption

Then configure it one of these ways:

```pwsh
$env:CHROMEELEVATOR_PATH = "C:\Tools\chromelevator_x64.exe"
python transfer.py --source chrome --target brave

# or
python transfer.py --source chrome --target brave --chromelevator-path "C:\Tools\chromelevator_x64.exe"
```

If you do not want to use `chromelevator`, export cookies from a browser
extension using `chrome.cookies.getAll()` JSON and import that file:

```pwsh
python transfer.py --import chrome-cookies.json --target brave
```

## What It Transfers

- Cookies only.
- Preserves core Chromium cookie fields and upserts existing cookies.
- Does not transfer LocalStorage, IndexedDB, service workers, extensions, or
  full browser profiles.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `pywin32` import error | Run `pip install -r requirements.txt` inside the venv. |
| `Cookies DB is locked` | Fully close the source/target browser. |
| `chromelevator_x64.exe not found` | Set `CHROMEELEVATOR_PATH` or pass `--chromelevator-path`. |
| `Unknown cookie encryption prefix` | Usually Chrome ABE. Configure `chromelevator` or use JSON import. |
