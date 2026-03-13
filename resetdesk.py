
"""
ResetDesk

Self-Service Password Reset Simulator (portfolio project)

This simulates a secure password reset flow without touching any real system accounts.
Everything stays local in a SQLite database.

Shows:
- identity verification (security questions)
- one-time reset code with expiration
- rate limiting and temporary lockouts
- audit logging
- simple roles (user vs tech)

Note about passwords:
Some IDE run consoles do not support hidden input (getpass) correctly.
This code uses hidden input only when it detects a real terminal.
Otherwise it falls back to normal input and tells you to press Enter.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple


APP_NAME = "ResetDesk"
DB_FILE = "resetdesk.db"

MAX_VERIFY_ATTEMPTS = 5
VERIFY_WINDOW_MIN = 10
CODE_TTL_MIN = 5
LOCKOUT_MIN = 10


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt_obj: datetime) -> str:
    return dt_obj.isoformat(timespec="seconds")


def print_line() -> None:
    print("=" * 62)


def safe_secret(prompt: str) -> str:
    """
    Uses hidden input only if stdin/stdout look like a real terminal.
    In IDE consoles, getpass can act weird, so we fall back to normal input.

    You always finish the input by pressing Enter.
    """
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            return getpass.getpass(prompt)
        except Exception:
            pass
    return input(f"{prompt} (press Enter): ")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def pbkdf2_hash(password: str, salt_hex: str, rounds: int = 120_000) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return dk.hex()


def strong_password(pw: str) -> Tuple[bool, str]:
    if len(pw) < 10:
        return False, "Password too short (min 10)"
    if not re.search(r"[A-Z]", pw):
        return False, "Missing uppercase letter"
    if not re.search(r"[a-z]", pw):
        return False, "Missing lowercase letter"
    if not re.search(r"\d", pw):
        return False, "Missing number"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return False, "Missing symbol"
    return True, "OK"


class DB:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self.conn.close()

    def exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()
        return cur

    def one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()

    def many(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()


def init_db(db: DB) -> None:
    db.exec(
        """
        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT UNIQUE NOT NULL,
            email            TEXT NOT NULL,
            role             TEXT NOT NULL,
            pw_salt          TEXT NOT NULL,
            pw_hash          TEXT NOT NULL,
            sec_q1           TEXT NOT NULL,
            sec_a1_hash      TEXT NOT NULL,
            sec_q2           TEXT NOT NULL,
            sec_a2_hash      TEXT NOT NULL,
            created_at_utc   TEXT NOT NULL
        )
        """
    )

    db.exec(
        """
        CREATE TABLE IF NOT EXISTS reset_sessions (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            username           TEXT NOT NULL,
            code_hash          TEXT NOT NULL,
            expires_at_utc     TEXT NOT NULL,
            verified           INTEGER NOT NULL DEFAULT 0,
            created_at_utc     TEXT NOT NULL
        )
        """
    )

    db.exec(
        """
        CREATE TABLE IF NOT EXISTS attempts (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            username           TEXT NOT NULL,
            action             TEXT NOT NULL,
            ok                 INTEGER NOT NULL,
            reason             TEXT,
            created_at_utc     TEXT NOT NULL
        )
        """
    )

    db.exec(
        """
        CREATE TABLE IF NOT EXISTS locks (
            username           TEXT PRIMARY KEY,
            locked_until_utc   TEXT NOT NULL
        )
        """
    )

    db.exec(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            actor             TEXT NOT NULL,
            target            TEXT NOT NULL,
            action            TEXT NOT NULL,
            details           TEXT,
            created_at_utc    TEXT NOT NULL
        )
        """
    )


def audit(db: DB, actor: str, target: str, action: str, details: str = "") -> None:
    db.exec(
        "INSERT INTO audit_log(actor,target,action,details,created_at_utc) VALUES(?,?,?,?,?)",
        (actor, target, action, details, iso(now_utc())),
    )


def log_attempt(db: DB, username: str, action: str, ok: bool, reason: str = "") -> None:
    db.exec(
        "INSERT INTO attempts(username,action,ok,reason,created_at_utc) VALUES(?,?,?,?,?)",
        (username, action, 1 if ok else 0, reason, iso(now_utc())),
    )


def is_locked(db: DB, username: str) -> Tuple[bool, Optional[str]]:
    row = db.one("SELECT locked_until_utc FROM locks WHERE username = ?", (username,))
    if not row:
        return False, None

    until = datetime.fromisoformat(row["locked_until_utc"])
    if now_utc() >= until:
        db.exec("DELETE FROM locks WHERE username = ?", (username,))
        return False, None

    return True, row["locked_until_utc"]


def count_recent_attempts(db: DB, username: str, action: str, minutes: int) -> int:
    cutoff = iso(now_utc() - timedelta(minutes=minutes))
    row = db.one(
        "SELECT COUNT(*) AS c FROM attempts WHERE username=? AND action=? AND created_at_utc >= ?",
        (username, action, cutoff),
    )
    return int(row["c"]) if row else 0


def apply_lock(db: DB, username: str, minutes: int) -> None:
    until = iso(now_utc() + timedelta(minutes=minutes))
    db.exec(
        "INSERT INTO locks(username, locked_until_utc) VALUES(?, ?) "
        "ON CONFLICT(username) DO UPDATE SET locked_until_utc=excluded.locked_until_utc",
        (username, until),
    )


@dataclass
class User:
    username: str
    email: str
    role: str
    pw_salt: str
    pw_hash: str
    sec_q1: str
    sec_a1_hash: str
    sec_q2: str
    sec_a2_hash: str


def get_user(db: DB, username: str) -> Optional[User]:
    r = db.one("SELECT * FROM users WHERE username = ?", (username,))
    if not r:
        return None
    return User(
        username=r["username"],
        email=r["email"],
        role=r["role"],
        pw_salt=r["pw_salt"],
        pw_hash=r["pw_hash"],
        sec_q1=r["sec_q1"],
        sec_a1_hash=r["sec_a1_hash"],
        sec_q2=r["sec_q2"],
        sec_a2_hash=r["sec_a2_hash"],
    )


def create_user(db: DB) -> None:
    print_line()
    print("Create a demo user (stored locally in SQLite)")
    print_line()

    username = input("Username: ").strip()
    email = input("Email: ").strip()

    role = input("Role (user/tech) [user]: ").strip().lower() or "user"
    if role not in ("user", "tech"):
        print("Role must be user or tech.")
        return

    pw1 = safe_secret("Password:")
    pw2 = safe_secret("Confirm:")

    if pw1 != pw2:
        print("Passwords do not match.")
        return

    ok, msg = strong_password(pw1)
    if not ok:
        print(f"Password rejected: {msg}")
        return

    sec_q1 = input("Security Q1 (ex: first pet?): ").strip()
    sec_a1 = safe_secret("Answer Q1:").strip().lower()

    sec_q2 = input("Security Q2 (ex: favorite teacher?): ").strip()
    sec_a2 = safe_secret("Answer Q2:").strip().lower()

    salt = secrets.token_hex(16)
    pw_hash = pbkdf2_hash(pw1, salt)

    a1_hash = sha256_hex(sec_a1)
    a2_hash = sha256_hex(sec_a2)

    try:
        db.exec(
            "INSERT INTO users(username,email,role,pw_salt,pw_hash,sec_q1,sec_a1_hash,sec_q2,sec_a2_hash,created_at_utc) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (username, email, role, salt, pw_hash, sec_q1, a1_hash, sec_q2, a2_hash, iso(now_utc())),
        )
        audit(db, actor=username, target=username, action="user_created", details=f"role={role}")
        print("\nUser created.")
    except sqlite3.IntegrityError:
        print("That username already exists.")


def start_reset(db: DB) -> None:
    print_line()
    print("Start password reset")
    print_line()

    username = input("Username: ").strip()
    u = get_user(db, username)
    if not u:
        print("User not found.")
        return

    locked, until = is_locked(db, username)
    if locked:
        print(f"Account is temporarily locked until {until}.")
        return

    recent = count_recent_attempts(db, username, "verify", VERIFY_WINDOW_MIN)
    if recent >= MAX_VERIFY_ATTEMPTS:
        apply_lock(db, username, LOCKOUT_MIN)
        audit(db, actor="system", target=username, action="lock_applied",
              details=f"too many verify attempts in {VERIFY_WINDOW_MIN} min")
        print(f"Too many verification attempts. Locked for {LOCKOUT_MIN} minutes.")
        return

    print("\nAnswer these to verify your identity.")
    print(f"Q1: {u.sec_q1}")
    a1 = safe_secret("A1:").strip().lower()

    print(f"\nQ2: {u.sec_q2}")
    a2 = safe_secret("A2:").strip().lower()

    a1_ok = hmac.compare_digest(sha256_hex(a1), u.sec_a1_hash)
    a2_ok = hmac.compare_digest(sha256_hex(a2), u.sec_a2_hash)

    if not (a1_ok and a2_ok):
        log_attempt(db, username, "verify", ok=False, reason="security answers mismatch")
        audit(db, actor=username, target=username, action="verify_failed", details="bad security answers")
        print("\nVerification failed.")
        return

    log_attempt(db, username, "verify", ok=True, reason="verified")
    audit(db, actor=username, target=username, action="verify_ok", details="security answers matched")

    code_plain = f"{secrets.randbelow(10**6):06d}"
    code_hash = sha256_hex(code_plain)
    expires = now_utc() + timedelta(minutes=CODE_TTL_MIN)

    db.exec(
        "INSERT INTO reset_sessions(username,code_hash,expires_at_utc,verified,created_at_utc) VALUES(?,?,?,?,?)",
        (username, code_hash, iso(expires), 0, iso(now_utc())),
    )
    audit(db, actor="system", target=username, action="reset_code_issued", details=f"ttl_min={CODE_TTL_MIN}")

    print("\nVerification passed.")
    print(f"Demo one-time code (normally sent via email): {code_plain}")
    print("Next: submit the code, then reset the password.")


def submit_code(db: DB) -> None:
    print_line()
    print("Submit reset code")
    print_line()

    username = input("Username: ").strip()
    u = get_user(db, username)
    if not u:
        print("User not found.")
        return

    locked, until = is_locked(db, username)
    if locked:
        print(f"Account is temporarily locked until {until}.")
        return

    sess = db.one("SELECT * FROM reset_sessions WHERE username=? ORDER BY id DESC LIMIT 1", (username,))
    if not sess:
        print("No reset session found. Start reset first.")
        return

    expires = datetime.fromisoformat(sess["expires_at_utc"])
    if now_utc() > expires:
        log_attempt(db, username, "code", ok=False, reason="code expired")
        audit(db, actor=username, target=username, action="code_failed", details="expired")
        print("Code expired. Start reset again.")
        return

    code = input("Enter 6-digit code: ").strip()
    if not re.fullmatch(r"\d{6}", code):
        print("Code format should be 6 digits.")
        return

    ok = hmac.compare_digest(sha256_hex(code), sess["code_hash"])
    if not ok:
        log_attempt(db, username, "code", ok=False, reason="code mismatch")
        audit(db, actor=username, target=username, action="code_failed", details="mismatch")
        print("Wrong code.")
        return

    db.exec("UPDATE reset_sessions SET verified=1 WHERE id=?", (sess["id"],))
    log_attempt(db, username, "code", ok=True, reason="code ok")
    audit(db, actor=username, target=username, action="code_ok", details="verified session")

    print("Code accepted. You can reset the password now.")


def reset_password(db: DB) -> None:
    print_line()
    print("Reset password")
    print_line()

    username = input("Username: ").strip()
    u = get_user(db, username)
    if not u:
        print("User not found.")
        return

    locked, until = is_locked(db, username)
    if locked:
        print(f"Account is temporarily locked until {until}.")
        return

    sess = db.one("SELECT * FROM reset_sessions WHERE username=? ORDER BY id DESC LIMIT 1", (username,))
    if not sess:
        print("No reset session found. Start reset first.")
        return

    if int(sess["verified"]) != 1:
        print("Reset session not verified yet. Submit the code first.")
        return

    expires = datetime.fromisoformat(sess["expires_at_utc"])
    if now_utc() > expires:
        print("Session expired. Start reset again.")
        return

    pw1 = safe_secret("New password:")
    pw2 = safe_secret("Confirm:")

    if pw1 != pw2:
        print("Passwords do not match.")
        return

    ok, msg = strong_password(pw1)
    if not ok:
        print(f"Password rejected: {msg}")
        return

    new_hash = pbkdf2_hash(pw1, u.pw_salt)
    db.exec("UPDATE users SET pw_hash=? WHERE username=?", (new_hash, username))
    audit(db, actor=username, target=username, action="password_reset", details="local db password updated")

    db.exec("DELETE FROM reset_sessions WHERE username=?", (username,))
    log_attempt(db, username, "reset", ok=True, reason="password updated")

    print("Password reset complete (simulated).")


def tech_unlock(db: DB) -> None:
    print_line()
    print("Support tech unlock")
    print_line()

    actor = input("Tech username: ").strip()
    tech = get_user(db, actor)
    if not tech or tech.role != "tech":
        print("That account is not a tech user.")
        return

    target = input("User to unlock: ").strip()
    u = get_user(db, target)
    if not u:
        print("Target user not found.")
        return

    db.exec("DELETE FROM locks WHERE username=?", (target,))
    audit(db, actor=actor, target=target, action="tech_unlock", details="lock cleared")
    print(f"Unlocked {target}.")


def tech_audit_report(db: DB) -> None:
    print_line()
    print("Audit log (last 30 actions)")
    print_line()

    actor = input("Tech username: ").strip()
    tech = get_user(db, actor)
    if not tech or tech.role != "tech":
        print("That account is not a tech user.")
        return

    rows = db.many("SELECT * FROM audit_log ORDER BY id DESC LIMIT 30")
    if not rows:
        print("No audit entries yet.")
        return

    for r in rows:
        print(f"{r['created_at_utc']}  actor={r['actor']}  target={r['target']}  action={r['action']}  details={r['details']}")


def main_menu() -> str:
    print_line()
    print(f"{APP_NAME}  Self-Service Password Reset Simulator")
    print_line()
    print("1) Create demo user")
    print("2) Start reset (verify + issue code)")
    print("3) Submit reset code")
    print("4) Reset password (simulated)")
    print("5) Tech: unlock user")
    print("6) Tech: view audit log")
    print("7) Exit")
    print_line()
    return input("Choose: ").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="ResetDesk: password reset simulator with lockouts + audit logging")
    parser.add_argument("--db", default=DB_FILE, help="SQLite DB filename")
    args = parser.parse_args()

    db = DB(Path(args.db))
    try:
        init_db(db)

        while True:
            choice = main_menu()

            if choice == "1":
                create_user(db)
            elif choice == "2":
                start_reset(db)
            elif choice == "3":
                submit_code(db)
            elif choice == "4":
                reset_password(db)
            elif choice == "5":
                tech_unlock(db)
            elif choice == "6":
                tech_audit_report(db)
            elif choice == "7":
                print("Bye.")
                break
            else:
                print("Pick a number from the menu.")

            print()
            time.sleep(0.25)

        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())