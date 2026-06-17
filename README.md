# Browser Session Transfer

A small Python CLI that moves cookies (and therefore active logins) between
two Chromium-based browsers on the same Windows machine.

Supported browsers: **Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Arc**.

> Use this only on browser profiles you own or are explicitly authorized to
> administer. Cookies can grant access to signed-in accounts.

## How it works

Chromium encrypts every cookie with an AES-GCM key. The key is wrapped using
the operating system's secret store:

| OS      | Where the wrapped key lives                          | How we unwrap it                              |
|---------|------------------------------------------------------|-----------------------------------------------|
| Windows | `os_crypt.encrypted_key` in `Local State`            | DPAPI (`win32crypt.CryptUnprotectData`)       |

The tool reads the source's wrapped key, unwraps it, decrypts every cookie,
then re-encrypts each value with the target's unwrapped key and upserts it
into the target's `Cookies` SQLite DB.

## Install

```pwsh
cd C:\Users\Arman\browser-session-transfer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`pywin32` and `psutil` are required on Windows.

## chromelevator

Chrome 127+ uses App-Bound Encryption (ABE) for some cookies. This project can
call `chromelevator_x64.exe` to extract the app-bound key, but the executable
is **not bundled** in this repository because it comes from a separate project.

Recommended setup:

1. Get `chromelevator_x64.exe` from its upstream repository or build it
   yourself.
2. Verify that binary and its license before use.
3. Either place it next to `transfer.py`, set `CHROMEELEVATOR_PATH`, or pass
   `--chromelevator-path`:

   ```pwsh
   $env:CHROMEELEVATOR_PATH = "C:\Tools\chromelevator_x64.exe"
   python transfer.py --source chrome --target brave

   # or
   python transfer.py --source chrome --target brave --chromelevator-path "C:\Tools\chromelevator_x64.exe"
   ```

## Usage

> **Close both browsers before transferring.** Chromium holds an exclusive
> lock on its `Cookies` file while running.

```pwsh
# Show what's installed
python transfer.py --list

# Transfer every cookie from Chrome -> Brave
python transfer.py --source chrome --target brave

# Use a specific profile
python transfer.py --source chrome --target brave --source-profile "Profile 1" --target-profile "Profile 2"

# Only move cookies for some domains
python transfer.py --source chrome --target brave --domains github.com,gitlab.com

# Dump source cookies to a JSON file (handy for backup / inspection)
python transfer.py --source chrome --export my-cookies.json

# Restore from JSON into another browser
python transfer.py --target brave --import my-cookies.json

# Use explicit User Data paths instead of browser names
python transfer.py --source-path "D:\old-browser\User Data" --target-path "D:\new-browser\User Data"

# Skip confirmation prompts
python transfer.py --source chrome --target brave -y

# Don't actually write anything, just validate
python transfer.py --source chrome --target brave --dry-run
```

A backup of the target `Cookies` DB is written next to it as
`Cookies.bak` before any modification, so you can roll back if something
goes wrong.

## Chrome 127+ on Windows (App-Bound Encryption)

Starting with Chrome 127, Windows builds use App-Bound Encryption (ABE) for
some cookies. When ABE is detected, this tool tries to run `chromelevator` if
available. Without it, v20 cookies cannot be decrypted from the source, and v20
cookies cannot be written correctly for an ABE target.

If app-bound key extraction fails, use the JSON fallback:

1. Install a small extension (e.g. *Cookie Editor* or *EditThisCookie*) in
   Chrome and export all cookies to JSON, or dump `chrome.cookies.getAll()`
   from a custom extension.
3. Run:

   ```pwsh
   python transfer.py --import chrome-cookies.json --target brave
   ```

   The imported values are re-encrypted with Brave's key, so the resulting
   file is fully compatible with the target browser.

## Notes

- Cookies are upserted on `(host_key, top_frame_site_key, name, path,
  source_scheme, source_port)`. Existing cookies with the same identity are
  overwritten; new ones are inserted.
- The tool preserves `expires_utc`, `is_secure`, `is_httponly`, `samesite`,
  `priority`, `source_scheme`, `source_port`, `source_type`, and
  `has_cross_site_ancestor`. It also works against older Chromium schemas
  (without `top_frame_site_key`, `creation_utc`, etc.) by reading the live
  schema with `PRAGMA table_info`.
- It does not transfer `LocalStorage`, `IndexedDB`, or service-worker
  state — those use LevelDB and need a separate strategy. Cookies alone are
  enough to restore most "active sessions" on the modern web.

## Troubleshooting

| Symptom                                                  | Likely cause / fix                                                         |
|----------------------------------------------------------|----------------------------------------------------------------------------|
| `pywin32` import error on Windows                        | `pip install pywin32` inside the venv.                                     |
| `No os_crypt.encrypted_key in Local State`               | You pointed at a non-Chromium browser.                                     |
| `Cookies DB is locked`                                   | Close the source or target browser fully and retry.                        |
| `Unknown cookie encryption prefix`                       | Usually Chrome 127+ ABE. Configure `chromelevator` or use JSON import.     |
| `chromelevator_x64.exe not found`                        | Set `CHROMEELEVATOR_PATH`, pass `--chromelevator-path`, or place it next to `transfer.py`. |
