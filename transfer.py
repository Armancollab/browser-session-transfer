#!/usr/bin/env python3
"""
Browser Session Transfer
========================
Transfer cookies/sessions between Chromium-based browsers on Windows.
"""

import argparse
import platform
import sys
from pathlib import Path

from browsers import (
    BROWSER_DIRS,
    browser_arg_or_detect,
    cookies_db_path,
    detect_browsers,
    get_app_bound_key,
    get_encryption_key,
    has_app_bound_key,
    is_browser_running,
    list_profiles,
)
from cookie_store import (
    host_matches_domain,
    load_cookies_json,
    read_cookies,
    save_cookies_json,
    write_cookies,
)


def _resolve_browser_dir(name_or_path):
    """Return a User Data dir either by browser name or by explicit path."""
    p = Path(name_or_path)
    if p.exists():
        # If the user pointed at a browser binary, resolve to nearby User Data.
        if p.is_file() or p.suffix.lower() in (".exe", ""):
            sibling = p.parent / "User Data"
            if sibling.exists():
                sys.stderr.write(f"Note: resolved {p} -> {sibling}\n")
                return sibling
            parent_sibling = p.parent.parent / "User Data"
            if parent_sibling.exists():
                sys.stderr.write(f"Note: resolved {p} -> {parent_sibling}\n")
                return parent_sibling
        if p.is_dir():
            return p

    system = platform.system()
    candidate = BROWSER_DIRS.get(name_or_path, {}).get(system)
    if candidate and candidate.exists():
        return candidate
    raise FileNotFoundError(
        f"Browser '{name_or_path}' not found and path does not exist."
    )


def _print_browsers():
    found = detect_browsers()
    if not found:
        print("No Chromium-based browsers detected on this machine.")
        return
    print("Detected Chromium-based browsers:")
    for name, path in found.items():
        profiles = list_profiles(path)
        print(f"  {name:9s}  {path}")
        for prof in profiles:
            print(f"             - {prof}")


def main(argv=None):
    if platform.system() != "Windows":
        print("ERROR: This tool currently supports Windows only.", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(
        prog="transfer.py",
        description="Transfer cookies between Chromium-based browsers.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List detected browsers and profiles, then exit.",
    )
    parser.add_argument(
        "--source", help="Source browser name (chrome, edge, brave, ...)"
    )
    parser.add_argument("--source-path", help="Explicit path to source User Data dir")
    parser.add_argument("--target", help="Target browser name")
    parser.add_argument("--target-path", help="Explicit path to target User Data dir")
    parser.add_argument(
        "--source-profile",
        default="Default",
        help="Source profile name (default: Default)",
    )
    parser.add_argument(
        "--target-profile",
        default="Default",
        help="Target profile name (default: Default)",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export source cookies to a JSON file instead of writing to target.",
    )
    parser.add_argument(
        "--import",
        dest="import_file",
        metavar="FILE",
        help="Import cookies from a JSON file instead of reading source.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate everything but do not write to the target DB.",
    )
    parser.add_argument(
        "--chromelevator-path",
        help=(
            "Path to chromelevator_x64.exe. Also accepted via "
            "CHROMEELEVATOR_PATH."
        ),
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip confirmation prompts."
    )
    parser.add_argument(
        "--domains",
        help="Comma-separated list of domains to include (matches host_key).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    args = parser.parse_args(argv)

    if args.list:
        _print_browsers()
        return 0

    domain_filter = None
    if args.domains:
        domain_filter = tuple(
            d.strip().lower() for d in args.domains.split(",") if d.strip()
        )

    if args.import_file:
        cookies = load_cookies_json(args.import_file)
        print(f"Loaded {len(cookies)} cookies from {args.import_file}")
    else:
        if not (args.source or args.source_path):
            parser.error("Provide --source/--source-path or use --import.")

        src_dir = _resolve_browser_dir(args.source_path or args.source)
        src_db = cookies_db_path(src_dir, args.source_profile)
        if not src_db.exists():
            print(f"Source Cookies DB not found: {src_db}", file=sys.stderr)
            print(
                "Available profiles:",
                ", ".join(list_profiles(src_dir)) or "(none)",
                file=sys.stderr,
            )
            return 1

        source_browser_key = browser_arg_or_detect(args.source, src_dir)
        running = is_browser_running(source_browser_key)
        if running:
            print(
                f"WARNING: {source_browser_key} appears to be running. "
                "Close it for a reliable copy.",
                file=sys.stderr,
            )
            if not args.yes and not _confirm("Continue anyway?"):
                return 1

        if args.verbose:
            print(f"Source User Data: {src_dir}")
            print(f"Source Cookies DB: {src_db}")

        print("Unwrapping source encryption key...")
        src_key = get_encryption_key(src_dir)

        app_bound_key = None
        if has_app_bound_key(src_dir):
            app_bound_key = get_app_bound_key(
                source_browser_key, args.chromelevator_path
            )
            if not app_bound_key:
                print(
                    "WARNING: App-bound key extraction failed. v20 cookies "
                    "will not be decryptable. Continuing with v10 key only.",
                    file=sys.stderr,
                )

        print(f"Reading cookies from {src_db}...")
        cookies = read_cookies(src_db, src_key, app_bound_key)
        print(f"  {len(cookies)} cookies read")

    if domain_filter:
        before = len(cookies)
        cookies = [
            c
            for c in cookies
            if any(host_matches_domain(c.get("host_key"), d) for d in domain_filter)
        ]
        print(f"Filtered by domains: {before} -> {len(cookies)}")

    if args.export:
        save_cookies_json(args.export, cookies)
        print(f"Exported {len(cookies)} cookies to {args.export}")
        return 0

    if not (args.target or args.target_path):
        parser.error("Provide --target/--target-path, --export, or --import.")

    tgt_dir = _resolve_browser_dir(args.target_path or args.target)
    tgt_db = cookies_db_path(tgt_dir, args.target_profile)
    if not tgt_db.exists():
        print(f"Target Cookies DB not found: {tgt_db}", file=sys.stderr)
        print(
            "Available profiles:",
            ", ".join(list_profiles(tgt_dir)) or "(none)",
            file=sys.stderr,
        )
        return 1

    target_browser_key = browser_arg_or_detect(args.target, tgt_dir)
    running = is_browser_running(target_browser_key)
    if running:
        print(
            f"ERROR: {target_browser_key} appears to be running. Close it first.",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        print(f"Target User Data: {tgt_dir}")
        print(f"Target Cookies DB: {tgt_db}")

    print("Unwrapping target encryption key...")
    tgt_key = get_encryption_key(tgt_dir)

    tgt_app_bound_key = None
    if has_app_bound_key(tgt_dir):
        tgt_app_bound_key = get_app_bound_key(
            target_browser_key, args.chromelevator_path
        )
        if tgt_app_bound_key:
            if args.verbose:
                print("Target has App-Bound Encryption — writing v20 cookies.")
        else:
            print(
                "WARNING: Target has App-Bound Encryption but the app-bound "
                "key could not be extracted. Cookies will be written as v10 "
                "and may be dropped when the browser next starts.",
                file=sys.stderr,
            )

    src_label = args.source or args.import_file
    tgt_label = args.target or "(target)"
    print(f"\nTransfer {len(cookies)} cookies: {src_label} -> {tgt_label}")
    if not args.yes and not _confirm("Proceed?"):
        return 0

    if args.dry_run:
        print("Dry run: no changes will be written.")
    inserted, updated = write_cookies(
        tgt_db, tgt_key, cookies,
        dry_run=args.dry_run,
        target_app_bound_key=tgt_app_bound_key,
    )
    print(f"  inserted: {inserted}")
    print(f"  updated:  {updated}")
    print(f"  done.    {tgt_db}")
    return 0


def _confirm(prompt):
    try:
        resp = input(f"{prompt} [y/N] ")
    except EOFError:
        return False
    return resp.strip().lower() in ("y", "yes")


if __name__ == "__main__":
    sys.exit(main())
