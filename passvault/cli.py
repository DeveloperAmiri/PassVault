"""Command-line interface for PassVault.

Built with argparse + rich. Every command that touches the vault asks for the
master password via getpass (input is never echoed or stored).
"""

import argparse
import getpass
import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from . import __version__
from .crypto import VaultCrypto, VERIFIER_PLAINTEXT
from .db import VaultDB
from .generator import generate_password, strength_label

console = Console()
err_console = Console(stderr=True, style="bold red")

DEFAULT_DATA_DIR = Path.home() / ".passvault"
VERIFIER_KEY = "verifier"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _open_vault(data_dir: Path):
    """Open DB + crypto, ask for the master password and verify it."""
    if not (data_dir / "vault.db").exists():
        err_console.print(
            f"No vault found at [bold]{data_dir}[/bold]. "
            "Create one first with: [bold]python passvault.py init[/bold]"
        )
        raise SystemExit(1)

    crypto = VaultCrypto(data_dir)
    db = VaultDB(data_dir / "vault.db")

    master = getpass.getpass("Master password: ")
    fernet = crypto.fernet_for(master)
    verifier = db.get_meta(VERIFIER_KEY)
    if verifier is None:
        err_console.print("Vault is corrupted (missing verifier). Aborting.")
        db.close()
        raise SystemExit(1)
    try:
        ok = VaultCrypto.decrypt(fernet, verifier) == VERIFIER_PLAINTEXT
    except ValueError:
        ok = False
    if not ok:
        db.close()
        err_console.print("[bold red]✗ Wrong master password.[/bold red]")
        raise SystemExit(1)
    return db, fernet


def _copy_to_clipboard(text: str) -> bool:
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except Exception:
        return False


def render_entries_table(entries, title="🔐 PassVault — stored entries"):
    """Render entry metadata (never passwords) as a rich table."""
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Username")
    table.add_column("URL", style="dim")
    table.add_column("Notes", style="dim")
    table.add_column("Updated", justify="right")

    for e in entries:
        table.add_row(
            str(e["id"]),
            e["name"],
            e["username"],
            e["url"] or "—",
            e["notes"] or "—",
            (e["updated_at"] or "")[:10],
        )
    return table


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_init(args):
    data_dir = Path(args.data_dir)
    if (data_dir / "vault.db").exists():
        if not Confirm.ask(f"A vault already exists at {data_dir}. Overwrite it?", default=False):
            console.print("Aborted.")
            return
        (data_dir / "vault.db").unlink()

    console.print(f"Creating a new vault in [bold]{data_dir}[/bold] …")
    master = getpass.getpass("Choose a master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    if master != confirm:
        err_console.print("Passwords do not match. Aborting.")
        raise SystemExit(1)
    if len(master) < 8:
        err_console.print("Master password must be at least 8 characters.")
        raise SystemExit(1)

    score, label, bits = strength_label(master)
    console.print(f"Master password strength: [bold]{label}[/bold] (~{bits:.0f} bits)")

    crypto = VaultCrypto(data_dir)
    fernet = crypto.fernet_for(master)
    db = VaultDB(data_dir / "vault.db")
    db.set_meta(VERIFIER_KEY, VaultCrypto.encrypt(fernet, VERIFIER_PLAINTEXT))
    db.close()
    console.print("[bold green]✓ Vault created.[/bold green] Add your first entry:")
    console.print("  python passvault.py add github -u octocat --generate")


def cmd_add(args):
    db, fernet = _open_vault(Path(args.data_dir))

    if args.generate:
        password = generate_password(
            length=args.length,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            avoid_ambiguous=args.avoid_ambiguous,
        )
    else:
        password = getpass.getpass(f"Password for '{args.name}': ")

    entry_id = db.add_entry(
        name=args.name,
        username=args.username,
        url=args.url,
        password_enc=VaultCrypto.encrypt(fernet, password),
        notes=args.notes or "",
    )
    db.close()

    if args.generate:
        score, label, _ = strength_label(password)
        console.print(f"Generated password: [bold]{password}[/bold]  ({label})")
        if _copy_to_clipboard(password):
            console.print("[dim]Copied to clipboard.[/dim]")
    console.print(f"[bold green]✓ Entry #{entry_id} '{args.name}' saved (encrypted).[/bold green]")


def cmd_list(args):
    db, _ = _open_vault(Path(args.data_dir))
    entries = db.list_entries(search=args.search)
    db.close()
    if not entries:
        console.print("[yellow]No entries found.[/yellow] Add one with the 'add' command.")
        return
    console.print(render_entries_table(entries))


def cmd_get(args):
    db, fernet = _open_vault(Path(args.data_dir))
    matches = db.find_by_name(args.name)
    if not matches:
        db.close()
        err_console.print(f"No entry named '{args.name}'. Use 'list' to see entries.")
        raise SystemExit(1)
    entry = matches[0]
    password = VaultCrypto.decrypt(fernet, entry["password_enc"])
    db.close()

    console.print(f"[bold]{entry['name']}[/bold] — {entry['username']}" + (f"  ({entry['url']})" if entry["url"] else ""))

    if args.show:
        console.print(f"Password: [bold]{password}[/bold]")

    copied = _copy_to_clipboard(password)
    if copied:
        console.print("[bold green]✓ Password copied to clipboard[/bold green] "
                      "[dim](clipboard clears when you copy something else — paste soon)[/dim]")
    elif not args.show:
        # No clipboard available: fall back to printing so the tool stays usable.
        console.print(f"Password (clipboard unavailable): [bold]{password}[/bold]")


def cmd_delete(args):
    db, _ = _open_vault(Path(args.data_dir))
    matches = db.find_by_name(args.name)
    if not matches:
        db.close()
        err_console.print(f"No entry named '{args.name}'.")
        raise SystemExit(1)
    if len(matches) > 1:
        console.print("Multiple matches:")
        console.print(render_entries_table(matches, title="Matches"))
        db.close()
        err_console.print("Delete by making the names unique first.")
        raise SystemExit(1)

    entry = matches[0]
    if Confirm.ask(f"Delete '{entry['name']}' ({entry['username']})?", default=False):
        db.delete_entry(entry["id"])
        db.close()
        console.print("[bold green]✓ Entry deleted.[/bold green]")
    else:
        db.close()
        console.print("Aborted.")


def cmd_generate(args):
    password = generate_password(
        length=args.length,
        upper=not args.no_upper,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
        avoid_ambiguous=args.avoid_ambiguous,
    )
    score, label, bits = strength_label(password)
    color = ["red", "red", "yellow", "green", "green"][score]
    console.print(f"[bold]{password}[/bold]")
    console.print(f"Strength: [{color}]{label}[/{color}] — ~{bits:.0f} bits of entropy")
    if args.copy and _copy_to_clipboard(password):
        console.print("[dim]Copied to clipboard.[/dim]")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------
def _add_generation_flags(p):
    p.add_argument("-n", "--length", type=int, default=20, help="password length (default: 20)")
    p.add_argument("--no-upper", action="store_true", help="exclude uppercase letters")
    p.add_argument("--no-digits", action="store_true", help="exclude digits")
    p.add_argument("--no-symbols", action="store_true", help="exclude symbols")
    p.add_argument("--avoid-ambiguous", action="store_true", help="exclude look-alike chars (Il1O0 …)")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="passvault",
        description="🔐 PassVault — an encrypted, offline password manager in your terminal.",
    )
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR), help="vault directory (default: ~/.passvault)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a new vault (set master password)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="add a new entry")
    p.add_argument("name", help="entry name, e.g. 'github'")
    p.add_argument("-u", "--username", required=True, help="username / e-mail")
    p.add_argument("--url", default="", help="site URL")
    p.add_argument("--notes", default="", help="free-text note")
    p.add_argument("--generate", action="store_true", help="generate a strong password instead of typing one")
    _add_generation_flags(p)
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("list", help="list entries (metadata only)")
    p.add_argument("-s", "--search", default=None, help="filter by name/username substring")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("get", help="retrieve a password (copies to clipboard)")
    p.add_argument("name", help="entry name")
    p.add_argument("--show", action="store_true", help="also print the password to the terminal")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("delete", help="delete an entry")
    p.add_argument("name", help="entry name")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("generate", help="generate a strong one-off password")
    _add_generation_flags(p)
    p.add_argument("--copy", action="store_true", help="copy the password to the clipboard")
    p.set_defaults(func=cmd_generate)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
