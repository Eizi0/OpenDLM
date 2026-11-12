"""Emergency commands, run inside the container:

    docker compose exec app python -m app.cli list-users
    docker compose exec app python -m app.cli reset-2fa USERNAME
    docker compose exec app python -m app.cli reset-password USERNAME

They work directly on the database, so they are the way back in when the only administrator lost their
authenticator and their recovery codes, or forgot their password.
"""

import argparse
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import twofa
from .db import SessionLocal
from .models import User
from .security import hash_password, password_problem


def _user(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username.strip().lower()))


def list_users(session: Session) -> list[str]:
    return [f"{u.username}\t{u.role}\t2FA {'on' if u.totp_enabled else 'off'}" for u in session.scalars(select(User).order_by(User.username))]


def reset_2fa(session: Session, username: str) -> bool:
    user = _user(session, username)
    if user is None:
        return False
    twofa.disable(session, user)
    return True


def reset_password(session: Session, username: str, password: str) -> str | None:
    """Returns None on success, otherwise a short reason."""
    user = _user(session, username)
    if user is None:
        return "unknown user"
    problem = password_problem(password)
    if problem:
        return problem
    user.password_hash = hash_password(password)  # also signs the user out everywhere
    session.commit()
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="OpenDLM emergency commands")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-users")
    sub.add_parser("reset-2fa").add_argument("username")
    sub.add_parser("reset-password").add_argument("username")
    args = parser.parse_args(argv)
    with SessionLocal() as session:
        if args.command == "list-users":
            print("\n".join(list_users(session)))
            return 0
        if args.command == "reset-2fa":
            ok = reset_2fa(session, args.username)
            print("Two-factor authentication reset. The user signs in with the password only." if ok else "Unknown user.", file=sys.stdout if ok else sys.stderr)
            return 0 if ok else 1
        password = getpass.getpass("New password (12 characters minimum): ")
        if password != getpass.getpass("Confirm: "):
            print("The two passwords do not match.", file=sys.stderr)
            return 1
        reason = reset_password(session, args.username, password)
        print("Password changed." if reason is None else f"Not changed: {reason}", file=sys.stdout if reason is None else sys.stderr)
        return 0 if reason is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
