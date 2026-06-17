"""Chromium cookie encryption, SQLite storage, and JSON import/export."""

import base64
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tempfile
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write(
        "ERROR: pycryptodome is required. Install with:\n    pip install pycryptodome\n"
    )
    sys.exit(2)


CHROME_EPOCH_DELTA_SECONDS = 11644473600
HOST_HASH_DB_VERSION = 24

KNOWN_COLUMNS = (
    "host_key",
    "top_frame_site_key",
    "name",
    "value",
    "encrypted_value",
    "path",
    "expires_utc",
    "is_secure",
    "is_httponly",
    "samesite",
    "last_access_utc",
    "has_expires",
    "is_persistent",
    "priority",
    "source_scheme",
    "source_port",
    "last_update_utc",
    "source_type",
    "has_cross_site_ancestor",
    "creation_utc",
)

_HELIUM_KEY_MAP = {
    "host": "host_key",
    "expires": "expires_utc",
    "domain": "host_key",
    "expirationDate": "expires_utc",
    "secure": "is_secure",
    "httpOnly": "is_httponly",
    "sameSite": "samesite",
    "storeId": "store_id",
}

_SAMESITE_MAP = {
    "unspecified": -1,
    "no_restriction": 0,
    "no_restriction_mode": 0,
    "none": 0,
    "lax": 1,
    "lax_mode": 1,
    "strict": 2,
    "strict_mode": 2,
}


def host_matches_domain(host_key, domain):
    host = (host_key or "").lower().lstrip(".")
    domain = domain.lower().lstrip(".")
    return host == domain or host.endswith("." + domain)


def decrypt_value(encrypted_value, key, app_bound_key=None, host_key=None,
                  has_host_prefix=True):
    """Decrypt a Chrome v10/v11 or v20 cookie value."""
    if not encrypted_value:
        return ""
    prefix = encrypted_value[:3]
    if prefix in (b"v10", b"v11"):
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        if has_host_prefix:
            plaintext = _strip_host_prefix(plaintext, host_key)
        return plaintext.decode("utf-8", errors="replace")
    if prefix == b"v20":
        if app_bound_key:
            iv = encrypted_value[3:15]
            ciphertext = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            cipher = AES.new(app_bound_key, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            if has_host_prefix:
                plaintext = _strip_host_prefix(plaintext, host_key)
            return plaintext.decode("utf-8", errors="replace")
        raise ValueError(
            "Cookie uses Chrome 127+ App-Bound Encryption (v20 prefix). No "
            "app-bound key available — chromelevator may not have run, or it "
            "could not extract the key."
        )

    if platform.system() == "Windows":
        try:
            import win32crypt

            out, _ = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)
            return out.decode("utf-8", errors="replace")
        except Exception:
            pass
    raise ValueError(f"Unknown cookie encryption prefix: {encrypted_value[:3]!r}")


def encrypt_value(plaintext, key, app_bound_key=None, host_key=None,
                  has_host_prefix=True):
    """Encrypt a cookie value for the target Chromium cookie DB."""
    iv = os.urandom(12)
    use_key = app_bound_key if app_bound_key else key
    prefix = b"v20" if app_bound_key else b"v10"
    if has_host_prefix:
        if not host_key:
            raise ValueError(
                "Cannot encrypt cookie for modern Chromium schema without host_key"
            )
        header = hashlib.sha256(host_key.encode("utf-8")).digest()
        payload = header + plaintext.encode("utf-8")
    else:
        if app_bound_key:
            raise ValueError("Cannot write app-bound v20 cookie without host prefix")
        payload = plaintext.encode("utf-8")
    cipher = AES.new(use_key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(payload)
    return prefix + iv + ct + tag


def read_cookies(cookies_db_path, source_key, app_bound_key=None):
    """Decrypt and return all readable cookies from the source DB."""
    uri = _sqlite_ro_uri(cookies_db_path)
    conn = sqlite3.connect(uri, uri=True)
    try:
        columns, _ = _schema(conn)
        if not columns:
            raise RuntimeError(f"No 'cookies' table in {cookies_db_path}")
        has_host_prefix = _uses_host_hash_prefix(conn)
        sel = [
            c
            for c in columns
            if c in KNOWN_COLUMNS or c in ("value", "encrypted_value")
        ]
        rows = conn.execute(f"SELECT {', '.join(sel)} FROM cookies").fetchall()
        out = []
        decrypt_errors = 0
        for row in rows:
            d = dict(zip(sel, row))
            ev = d.get("encrypted_value")
            if ev:
                try:
                    d["value"] = decrypt_value(
                        ev, source_key, app_bound_key,
                        host_key=d.get("host_key"),
                        has_host_prefix=has_host_prefix,
                    )
                except Exception as e:
                    decrypt_errors += 1
                    if decrypt_errors <= 5:
                        sys.stderr.write(
                            "WARNING: skipped cookie that could not be decrypted "
                            f"host={d.get('host_key')!r} name={d.get('name')!r}: {e}\n"
                        )
                    continue
            else:
                d["value"] = d.get("value", "")
            out.append(d)
        if decrypt_errors:
            sys.stderr.write(
                f"WARNING: skipped {decrypt_errors} cookies due to decrypt errors.\n"
            )
        return out
    finally:
        conn.close()


def write_cookies(cookies_db_path, target_key, cookies, dry_run=False,
                  target_app_bound_key=None):
    """
    Re-encrypt each cookie with the target's key and upsert it into the target DB.

    The real DB is replaced only after all writes succeed. Copies go through
    SQLite's backup API so committed WAL contents are preserved.
    """
    cookies_db_path = Path(cookies_db_path)
    if not cookies_db_path.exists():
        raise FileNotFoundError(cookies_db_path)

    backup = cookies_db_path.with_name(cookies_db_path.name + ".bak")
    if not dry_run:
        _copy_sqlite_db(cookies_db_path, backup)

    fd, tmp_name = tempfile.mkstemp(
        prefix=cookies_db_path.name + ".",
        suffix=".tmp",
        dir=str(cookies_db_path.parent),
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    _copy_sqlite_db(cookies_db_path, tmp_path)

    try:
        conn = sqlite3.connect(str(tmp_path))
        try:
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.DatabaseError:
                pass

            columns, pk = _schema(conn)
            if not columns:
                raise RuntimeError(f"Target has no 'cookies' table: {cookies_db_path}")
            has_host_prefix = _uses_host_hash_prefix(conn)

            if not pk:
                pk = [
                    c
                    for c in (
                        "host_key",
                        "top_frame_site_key",
                        "has_cross_site_ancestor",
                        "name",
                        "path",
                        "source_scheme",
                        "source_port",
                    )
                    if c in columns
                ]

            inserted, updated = 0, 0
            existing = set()
            key_cols = []
            if pk:
                key_cols = [c for c in pk if c in columns]
                if key_cols:
                    sel = ", ".join(_quote_ident(c) for c in key_cols)
                    try:
                        existing = {
                            tuple(r) for r in conn.execute(
                                f"SELECT {sel} FROM cookies"
                            ).fetchall()
                        }
                    except sqlite3.DatabaseError:
                        existing = set()

            for cookie in cookies:
                enc = encrypt_value(
                    cookie.get("value", ""), target_key, target_app_bound_key,
                    host_key=cookie.get("host_key"),
                    has_host_prefix=has_host_prefix,
                )

                row = {}
                for col in columns:
                    if col == "value":
                        row[col] = ""
                    elif col == "encrypted_value":
                        row[col] = enc
                    elif col in cookie:
                        row[col] = cookie[col]
                    else:
                        row[col] = _default_for(col, cookie)

                placeholders = ",".join("?" for _ in row)
                col_list = ",".join(_quote_ident(c) for c in row.keys())

                if pk:
                    update_cols = [c for c in row if c not in pk]
                    conflict_cols = ", ".join(_quote_ident(c) for c in pk)
                    if update_cols:
                        set_clause = ", ".join(
                            f"{_quote_ident(c)} = excluded.{_quote_ident(c)}"
                            for c in update_cols
                        )
                        on_conflict = (
                            f" ON CONFLICT({conflict_cols}) DO UPDATE SET {set_clause}"
                        )
                    else:
                        on_conflict = f" ON CONFLICT({conflict_cols}) DO NOTHING"
                    sql = (
                        f"INSERT INTO cookies ({col_list}) "
                        f"VALUES ({placeholders}){on_conflict}"
                    )

                    key_tuple = tuple(row.get(c) for c in key_cols) if key_cols else None
                    if key_tuple is not None and key_tuple in existing:
                        updated += 1
                    else:
                        inserted += 1
                        if key_tuple is not None:
                            existing.add(key_tuple)
                else:
                    sql = f"INSERT INTO cookies ({col_list}) VALUES ({placeholders})"
                    inserted += 1

                conn.execute(sql, list(row.values()))

            if not dry_run:
                conn.commit()
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.DatabaseError:
                    pass
            else:
                conn.rollback()
        finally:
            conn.close()

        if not dry_run:
            os.replace(tmp_path, cookies_db_path)
            _remove_sqlite_sidecars(cookies_db_path)
        return inserted, updated
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def save_cookies_json(path, cookies):
    serializable = []
    for c in cookies:
        out = {}
        for k, v in c.items():
            if k.startswith("_"):
                continue
            if isinstance(v, (bytes, bytearray)):
                out[k] = {"__b64__": base64.b64encode(bytes(v)).decode("ascii")}
            else:
                out[k] = v
        serializable.append(out)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)


def load_cookies_json(path):
    """Load cookies from transfer.py, Helium, or chrome.cookies JSON exports."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (UnicodeDecodeError, json.JSONDecodeError):
        with open(path, "r", encoding="latin-1") as f:
            data = json.load(f)

    out = []
    for c in data:
        out.append(_normalise_cookie_dict(c))
    return out


def _strip_host_prefix(plaintext, host_key):
    if host_key is None or len(plaintext) < 32:
        return plaintext
    expected = hashlib.sha256(host_key.encode("utf-8")).digest()
    if plaintext[:32] == expected:
        return plaintext[32:]
    sys.stderr.write(
        f"WARNING: cookie SHA-256(host_key) prefix did not match for "
        f"host={host_key!r} — returning raw plaintext.\n"
    )
    return plaintext


def _schema(conn):
    """Return (column_names, key_cols) for the cookies table."""
    cur = conn.execute("PRAGMA table_info(cookies)")
    columns = []
    pk = []
    for cid, name, ctype, notnull, dflt, pk_ord in cur.fetchall():
        columns.append(name)
        if pk_ord > 0:
            pk.append(name)

    if not pk:
        try:
            for _seq, idx_name, unique, _origin, _partial in conn.execute(
                "PRAGMA index_list('cookies')"
            ).fetchall():
                if not unique:
                    continue
                info = conn.execute(f"PRAGMA index_info('{idx_name}')").fetchall()
                cols = [r[2] for r in info]
                if cols:
                    pk = cols
                    break
        except sqlite3.DatabaseError:
            pass

    return columns, pk


def _meta_version(conn):
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'version'"
        ).fetchone()
    except sqlite3.DatabaseError:
        return 0
    if not row:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return 0


def _uses_host_hash_prefix(conn):
    return _meta_version(conn) >= HOST_HASH_DB_VERSION


def _quote_ident(name):
    return '"' + str(name).replace('"', '""') + '"'


def _sqlite_ro_uri(path):
    return Path(path).resolve().as_uri() + "?mode=ro"


def _copy_sqlite_db(src_path, dst_path):
    src = sqlite3.connect(_sqlite_ro_uri(src_path), uri=True)
    try:
        dst = sqlite3.connect(str(dst_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def _sqlite_sidecars(db_path):
    db_path = Path(db_path)
    return (db_path.with_name(db_path.name + "-wal"),
            db_path.with_name(db_path.name + "-shm"))


def _remove_sqlite_sidecars(db_path):
    for sidecar in _sqlite_sidecars(db_path):
        if sidecar.exists():
            sidecar.unlink()


def _default_for(col, cookie):
    if col == "value":
        return ""
    if col == "encrypted_value":
        return b""
    if col in ("expires_utc", "last_access_utc", "last_update_utc", "creation_utc"):
        val = cookie.get(col)
        if val is not None and val != 0:
            return int(val)
        val = cookie.get("last_access_utc")
        if val is not None and val != 0:
            return int(val)
        return 0
    if col in ("is_secure", "is_httponly", "has_cross_site_ancestor"):
        return int(cookie.get(col) or 0)
    if col == "has_expires":
        if "has_expires" in cookie:
            return int(cookie["has_expires"] or 0)
        return 1 if (cookie.get("expires_utc") or 0) != 0 else 0
    if col == "is_persistent":
        if "is_persistent" in cookie:
            return int(cookie["is_persistent"] or 0)
        return 1 if (cookie.get("expires_utc") or 0) != 0 else 0
    if col == "samesite":
        return int(cookie.get(col, -1))
    if col == "priority":
        return int(cookie.get(col, 1))
    if col == "source_scheme":
        if "source_scheme" in cookie:
            return int(cookie["source_scheme"])
        return 2 if cookie.get("is_secure") else 1
    if col == "source_port":
        if (
            "source_port" in cookie
            and cookie["source_port"] is not None
            and cookie["source_port"] >= 0
        ):
            return int(cookie["source_port"])
        return 443 if cookie.get("is_secure") else 80
    if col == "source_type":
        return int(cookie.get(col, 0))
    if col == "top_frame_site_key":
        return cookie.get(col, "") or ""
    if col == "path":
        return cookie.get(col, "/") or "/"
    if col == "host_key":
        return cookie.get(col, "") or ""
    if col == "name":
        return cookie.get(col, "") or ""
    return cookie.get(col, "")


def _unix_seconds_to_chrome_time(value):
    return int((float(value) + CHROME_EPOCH_DELTA_SECONDS) * 1000000)


def _looks_like_unix_expiry(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    return 0 < v < 100000000000


def _normalise_cookie_dict(c):
    for alt, canonical in _HELIUM_KEY_MAP.items():
        if alt in c and canonical not in c:
            c[canonical] = c.pop(alt)

    if "partitionKey" in c and "top_frame_site_key" not in c:
        partition_key = c.get("partitionKey")
        if isinstance(partition_key, dict):
            c["top_frame_site_key"] = partition_key.get("topLevelSite", "") or ""
            if "hasCrossSiteAncestor" in partition_key:
                c["has_cross_site_ancestor"] = int(
                    bool(partition_key["hasCrossSiteAncestor"])
                )
        elif isinstance(partition_key, str):
            c["top_frame_site_key"] = partition_key

    for flag in ("is_secure", "is_httponly", "has_expires",
                 "has_cross_site_ancestor", "is_persistent"):
        if flag in c and isinstance(c[flag], bool):
            c[flag] = int(c[flag])

    if "samesite" in c and isinstance(c["samesite"], str):
        c["samesite"] = _SAMESITE_MAP.get(c["samesite"].lower(), -1)
    elif "samesite" in c and c["samesite"] is None:
        del c["samesite"]

    if "expires_utc" in c and _looks_like_unix_expiry(c["expires_utc"]):
        c["expires_utc"] = _unix_seconds_to_chrome_time(c["expires_utc"])

    if c.get("session") is True:
        c["expires_utc"] = 0
        c["has_expires"] = 0
        c["is_persistent"] = 0
    elif "expires_utc" in c and c.get("expires_utc"):
        c.setdefault("has_expires", 1)
        c.setdefault("is_persistent", 1)

    for typed_col in ("is_secure", "is_httponly", "has_expires",
                      "has_cross_site_ancestor", "is_persistent",
                      "priority", "source_scheme", "source_port",
                      "source_type", "expires_utc"):
        if typed_col in c and c[typed_col] is None:
            del c[typed_col]

    ev = c.get("encrypted_value")
    if isinstance(ev, dict) and "__b64__" in ev:
        c["encrypted_value"] = base64.b64decode(ev["__b64__"])
    if isinstance(c.get("encrypted_value"), str):
        c["encrypted_value"] = c["encrypted_value"].encode("latin-1")

    if isinstance(c.get("value"), bytes):
        c["value"] = c["value"].decode("utf-8", errors="replace")

    if "host_key" in c and c["host_key"] is not None:
        c["host_key"] = str(c["host_key"])
    c.setdefault("path", "/")
    c.setdefault("name", "")
    c.setdefault("value", "")

    return c
