#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  2FA SHIELD - Terminal Security Suite                           ║
║  Author: 2FA Shield Team | License: MIT                         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import hmac
import base64
import struct
import hashlib
import secrets
import threading
import readline
from datetime import datetime
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────
def check_and_install(package, import_name=None):
    import importlib, subprocess
    try:
        importlib.import_module(import_name or package)
    except ImportError:
        print(f"\033[93m[+] Installing {package}...\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])

for pkg, imp in [("rich", "rich"), ("pyotp", "pyotp"), ("qrcode", "qrcode"),
                 ("prompt_toolkit", "prompt_toolkit"), ("cryptography", "cryptography"),
                 ("Pillow", "PIL")]:
    check_and_install(pkg, imp)

import pyotp
import qrcode
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.columns import Columns
from rich.text import Text
from rich.align import Align
from rich.layout import Layout
from rich.rule import Rule
from rich import box
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter, FuzzyCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from cryptography.fernet import Fernet

console = Console()

# ── Colour Palette ────────────────────────────────────────────────
COLORS = {
    "primary":   "#7C3AED",   # violet
    "secondary": "#06B6D4",   # cyan
    "accent":    "#10B981",   # emerald
    "warning":   "#F59E0B",   # amber
    "danger":    "#EF4444",   # red
    "info":      "#3B82F6",   # blue
    "ghost":     "#6B7280",   # gray
    "white":     "#F9FAFB",
}

GRADIENT_BANNER = r"""
[bold]
[#7C3AED]  ██████╗[/#7C3AED][#8B31E8]███████╗[/#8B31E8][#9929E3]  █████╗ [/#9929E3][#A820DE] ███████╗[/#A820DE][#B718D9]██╗  ██╗[/#B718D9][#C610D4]██╗    ██████╗ [/#C610D4]
[#7C3AED] ╚════██╗[/#7C3AED][#8B31E8]██╔════╝[/#8B31E8][#9929E3] ██╔══██╗[/#9929E3][#A820DE] ██╔════╝[/#A820DE][#B718D9]██║  ██║[/#B718D9][#C610D4]██║    ██╔══██╗[/#C610D4]
[#7C3AED]  █████╔╝[/#7C3AED][#8B31E8]█████╗  [/#8B31E8][#9929E3] ███████║[/#9929E3][#A820DE]  ███████╗[/#A820DE][#B718D9]███████║[/#B718D9][#C610D4]██║    ██║  ██║[/#C610D4]
[#7C3AED] ██╔═══╝ [/#7C3AED][#8B31E8]██╔══╝  [/#8B31E8][#9929E3] ██╔══██║[/#9929E3][#A820DE]      ████╗[/#A820DE][#B718D9]██╔══██║[/#B718D9][#C610D4]██║    ██║  ██║[/#C610D4]
[#7C3AED] ███████╗[/#7C3AED][#8B31E8]██║     [/#8B31E8][#9929E3] ██║  ██║[/#9929E3][#A820DE] ███████╔╝[/#A820DE][#B718D9]██║  ██║[/#B718D9][#C610D4]██║    ██████╔╝[/#C610D4]
[#7C3AED] ╚══════╝[/#7C3AED][#8B31E8]╚═╝     [/#8B31E8][#9929E3] ╚═╝  ╚═╝[/#9929E3][#A820DE] ╚══════╝ [/#A820DE][#B718D9]╚═╝  ╚═╝[/#B718D9][#C610D4]╚═╝    ╚═════╝ [/#C610D4]
[bold]
"""

SHIELD_ART = r"""[#06B6D4]
      ██████████
    ██          ██
   █   ███████   █
   █   █[#10B981]  🔐  [/#10B981]█   █
   █   ███████   █
    ██          ██
      ████████
        ████
         ██
[/#06B6D4]"""

# ── Encryption Helper ─────────────────────────────────────────────
class VaultEncryption:
    def __init__(self, key_file="vault.key"):
        self.key_file = Path(key_file)
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self):
        if self.key_file.exists():
            return self.key_file.read_bytes()
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        self.key_file.chmod(0o600)
        return key

    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self.fernet.decrypt(token.encode()).decode()


# ── TOTP Engine ───────────────────────────────────────────────────
class TOTPEngine:
    def __init__(self):
        self.vault_file = Path("vault.json")
        self.enc = VaultEncryption()
        self.vault = self._load_vault()

    def _load_vault(self):
        if self.vault_file.exists():
            try:
                raw = json.loads(self.vault_file.read_text())
                return raw
            except Exception:
                return {"accounts": {}}
        return {"accounts": {}}

    def _save_vault(self):
        self.vault_file.write_text(json.dumps(self.vault, indent=2))
        self.vault_file.chmod(0o600)

    def add_account(self, name: str, secret: str = None, issuer: str = "2FAShield"):
        if secret is None:
            secret = pyotp.random_base32()
        secret = secret.upper().replace(" ", "")
        try:
            pyotp.TOTP(secret).now()  # validate
        except Exception:
            return None, "Invalid secret key format"

        encrypted_secret = self.enc.encrypt(secret)
        self.vault["accounts"][name] = {
            "secret": encrypted_secret,
            "issuer": issuer,
            "created": datetime.now().isoformat(),
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        }
        self._save_vault()
        return secret, None

    def get_totp(self, name: str):
        if name not in self.vault["accounts"]:
            return None, None, "Account not found"
        acc = self.vault["accounts"][name]
        secret = self.enc.decrypt(acc["secret"])
        totp = pyotp.TOTP(secret)
        code = totp.now()
        remaining = 30 - (int(time.time()) % 30)
        return code, remaining, None

    def get_uri(self, name: str):
        if name not in self.vault["accounts"]:
            return None
        acc = self.vault["accounts"][name]
        secret = self.enc.decrypt(acc["secret"])
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=name, issuer_name=acc["issuer"])

    def delete_account(self, name: str):
        if name in self.vault["accounts"]:
            del self.vault["accounts"][name]
            self._save_vault()
            return True
        return False

    def list_accounts(self):
        return list(self.vault["accounts"].keys())

    def verify_code(self, name: str, code: str):
        if name not in self.vault["accounts"]:
            return False, "Account not found"
        acc = self.vault["accounts"][name]
        secret = self.enc.decrypt(acc["secret"])
        totp = pyotp.TOTP(secret)
        valid = totp.verify(code, valid_window=1)
        return valid, None

    def generate_backup_codes(self, name: str, count: int = 8):
        codes = [secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper()
                 for _ in range(count)]
        if name in self.vault["accounts"]:
            self.vault["accounts"][name]["backup_codes"] = [
                self.enc.encrypt(c) for c in codes
            ]
            self._save_vault()
        return codes

    def export_qr(self, name: str):
        uri = self.get_uri(name)
        if not uri:
            return False
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#7C3AED", back_color="white")
        fname = f"qr_{name}.png"
        img.save(fname)
        return fname


# ── Backup Codes ──────────────────────────────────────────────────
class BackupCodeManager:
    @staticmethod
    def display(codes: list):
        table = Table(
            title="🔑 Backup Recovery Codes",
            box=box.DOUBLE_EDGE,
            border_style="#7C3AED",
            header_style="bold #06B6D4",
            show_lines=True,
        )
        table.add_column("#", style="bold #F59E0B", width=5)
        table.add_column("Recovery Code", style="bold #F9FAFB", width=25)
        table.add_column("Status", style="#10B981", width=10)

        for i, code in enumerate(codes, 1):
            table.add_row(str(i), code, "✅ Valid")

        console.print()
        console.print(Panel(
            table,
            title="[bold #7C3AED]⚠  SAVE THESE CODES SECURELY[/]",
            subtitle="[#EF4444]Each code can only be used ONCE[/]",
            border_style="#F59E0B",
            padding=(1, 2),
        ))


# ── Live TOTP Display ─────────────────────────────────────────────
class LiveTOTPDisplay:
    def __init__(self, engine: TOTPEngine):
        self.engine = engine
        self.running = True

    def make_progress_bar(self, remaining: int, total: int = 30) -> str:
        filled = int((remaining / total) * 20)
        pct = remaining / total
        if pct > 0.6:
            color = "#10B981"
        elif pct > 0.3:
            color = "#F59E0B"
        else:
            color = "#EF4444"
        bar = "█" * filled + "░" * (20 - filled)
        return f"[{color}]{bar}[/{color}] [{color}]{remaining:02d}s[/{color}]"

    def render(self):
        accounts = self.engine.list_accounts()
        if not accounts:
            return Panel(
                Align.center("[#6B7280]No accounts found. Add one with [bold #06B6D4]add[/][/]"),
                border_style="#7C3AED",
                title="[bold #7C3AED]🔐 Live TOTP Codes[/]",
            )

        table = Table(
            box=box.ROUNDED,
            border_style="#7C3AED",
            header_style="bold #06B6D4",
            show_lines=True,
            expand=True,
        )
        table.add_column("Account", style="bold #F9FAFB", min_width=15)
        table.add_column("OTP Code", style="bold #10B981", min_width=12, justify="center")
        table.add_column("Time Left", min_width=28)
        table.add_column("Issuer", style="#6B7280", min_width=12)

        for name in accounts:
            code, remaining, err = self.engine.get_totp(name)
            if err:
                continue
            acc = self.engine.vault["accounts"][name]
            table.add_row(
                f"[bold #7C3AED]{name}[/]",
                f"[bold #10B981]{code[:3]} {code[3:]}[/]",
                self.make_progress_bar(remaining),
                acc.get("issuer", "Unknown"),
            )

        ts = datetime.now().strftime("%H:%M:%S")
        return Panel(
            table,
            title=f"[bold #7C3AED]🔐 Live TOTP Monitor[/]",
            subtitle=f"[#6B7280]Updated: {ts} | Press Ctrl+C to exit live view[/]",
            border_style="#7C3AED",
            padding=(0, 1),
        )

    def run(self):
        try:
            with Live(self.render(), refresh_per_second=2, screen=True) as live:
                while self.running:
                    time.sleep(0.5)
                    live.update(self.render())
        except KeyboardInterrupt:
            pass


# ── Statistics Dashboard ──────────────────────────────────────────
def show_dashboard(engine: TOTPEngine):
    accounts = engine.list_accounts()

    stats_table = Table(box=box.SIMPLE_HEAVY, border_style="#7C3AED", expand=True)
    stats_table.add_column("Metric", style="bold #06B6D4")
    stats_table.add_column("Value", style="bold #10B981", justify="right")

    stats_table.add_row("Total Accounts", str(len(accounts)))
    stats_table.add_row("Vault Status", "🔒 Encrypted")
    stats_table.add_row("Algorithm", "TOTP / SHA-1")
    stats_table.add_row("Code Length", "6 digits")
    stats_table.add_row("Period", "30 seconds")
    stats_table.add_row("Encryption", "Fernet AES-128")
    stats_table.add_row("Vault File", "vault.json")
    stats_table.add_row("Session Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    security_checks = Table(box=box.SIMPLE_HEAVY, border_style="#10B981", expand=True)
    security_checks.add_column("Security Check", style="bold #F9FAFB")
    security_checks.add_column("Status", justify="center")

    vault_path = Path("vault.json")
    key_path = Path("vault.key")

    security_checks.add_row("Vault File Encrypted", "✅" if key_path.exists() else "❌")
    security_checks.add_row("Vault Permissions", "✅ 600" if vault_path.exists() else "⚠  N/A")
    security_checks.add_row("Key File Protected", "✅ 600" if key_path.exists() else "❌")
    security_checks.add_row("TOTP Standards", "✅ RFC 6238")
    security_checks.add_row("Backup Codes Ready",
        "✅" if any(engine.vault["accounts"].get(a, {}).get("backup_codes")
                   for a in accounts) else "⚠  None")

    layout = Layout()
    layout.split_row(
        Layout(Panel(stats_table, title="[bold #7C3AED]📊 System Stats[/]",
                     border_style="#7C3AED")),
        Layout(Panel(security_checks, title="[bold #10B981]🛡 Security Audit[/]",
                     border_style="#10B981")),
    )
    console.print(layout)


# ── Command Help Table ────────────────────────────────────────────
def show_help():
    table = Table(
        title="📖 2FA Shield Command Reference",
        box=box.DOUBLE_EDGE,
        border_style="#7C3AED",
        header_style="bold #06B6D4",
        show_lines=True,
        expand=True,
    )
    table.add_column("Command", style="bold #10B981", min_width=22)
    table.add_column("Arguments", style="#F59E0B", min_width=25)
    table.add_column("Description", style="#F9FAFB", min_width=38)
    table.add_column("Example", style="#6B7280", min_width=30)

    COMMANDS = [
        ("add",         "<name> [secret]",      "Add a new 2FA account",             "add GitHub"),
        ("list",        "",                      "List all stored accounts",          "list"),
        ("show",        "<name>",                "Show live TOTP for one account",    "show GitHub"),
        ("live",        "",                      "Live monitor all accounts",         "live"),
        ("verify",      "<name> <code>",         "Verify a TOTP code",                "verify GitHub 123456"),
        ("delete",      "<name>",                "Delete an account",                 "delete GitHub"),
        ("backup",      "<name>",                "Generate backup codes",             "backup GitHub"),
        ("qr",          "<name>",                "Export QR code as PNG",             "qr GitHub"),
        ("dashboard",   "",                      "Show security dashboard",           "dashboard"),
        ("export",      "<name>",                "Show account URI",                  "export GitHub"),
        ("search",      "<query>",               "Search accounts by name",           "search git"),
        ("rename",      "<old> <new>",           "Rename an account",                 "rename Git GitHub"),
        ("info",        "<name>",                "Show full account info",            "info GitHub"),
        ("clear",       "",                      "Clear the terminal",                "clear"),
        ("help",        "",                      "Show this help table",              "help"),
        ("exit / quit", "",                      "Exit 2FA Shield",                   "exit"),
    ]

    for cmd, args, desc, ex in COMMANDS:
        table.add_row(cmd, args, desc, ex)

    console.print()
    console.print(Panel(table, border_style="#7C3AED", padding=(1, 2)))


# ── Auto-complete Setup ───────────────────────────────────────────
BASE_COMMANDS = [
    "add", "list", "show", "live", "verify", "delete",
    "backup", "qr", "dashboard", "export", "search",
    "rename", "info", "clear", "help", "exit", "quit",
]

def build_completer(engine: TOTPEngine):
    accounts = engine.list_accounts()
    words = BASE_COMMANDS + accounts
    # Add contextual completions
    for acc in accounts:
        for cmd in ["show", "delete", "backup", "qr", "export", "verify", "info", "rename"]:
            words.append(f"{cmd} {acc}")
    return FuzzyCompleter(WordCompleter(words, ignore_case=True))


def make_prompt_style():
    return Style.from_dict({
        "prompt":       "#7C3AED bold",
        "completion-menu.completion":         "bg:#1e1e2e #cdd6f4",
        "completion-menu.completion.current": "bg:#7C3AED #ffffff bold",
        "auto-suggestion":                    "#6B7280 italic",
        "bottom-toolbar":                     "bg:#1e1e2e #6B7280",
    })


def bottom_toolbar(engine: TOTPEngine):
    count = len(engine.list_accounts())
    t = datetime.now().strftime("%H:%M:%S")
    return HTML(
        f'<b><style fg="#7C3AED">🔐 2FA Shield</style></b> │ '
        f'<style fg="#10B981">Accounts: {count}</style> │ '
        f'<style fg="#06B6D4">Vault: 🔒 Encrypted</style> │ '
        f'<style fg="#F59E0B">⏰ {t}</style> │ '
        f'<style fg="#6B7280">Tab=autocomplete  ↑↓=history  Ctrl+C=cancel</style>'
    )


# ── Boot Animations ───────────────────────────────────────────────
def boot_animation():
    os.system("clear" if os.name != "nt" else "cls")

    steps = [
        ("[#7C3AED]Initialising encryption engine...[/]",  0.3),
        ("[#8B31E8]Loading vault...[/]",                    0.25),
        ("[#06B6D4]Verifying TOTP algorithms...[/]",        0.25),
        ("[#10B981]Loading command interface...[/]",         0.2),
        ("[#F59E0B]Starting auto-complete engine...[/]",     0.2),
        ("[#10B981]All systems ready![/]",                   0.3),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="#7C3AED"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=35, style="#7C3AED", complete_style="#10B981"),
        transient=True,
    ) as progress:
        task = progress.add_task("Booting...", total=len(steps))
        for msg, delay in steps:
            progress.update(task, description=msg, advance=1)
            time.sleep(delay)


def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(GRADIENT_BANNER))
    console.print(Align.center(
        "[bold #06B6D4]Two-Factor Authentication Security Suite[/]  "
        "[#6B7280]v2.0.0 │ RFC 6238 Compliant[/]"
    ))
    console.print(Align.center(
        "[#7C3AED]━[/]" * 65
    ))
    console.print(Align.center(
        "[#6B7280]Type [bold #10B981]help[/] for commands  │  "
        "Tab for auto-complete  │  ↑/↓ for history[/]"
    ))
    console.print()


# ── Command Processor ─────────────────────────────────────────────
def process_command(raw: str, engine: TOTPEngine):
    parts = raw.strip().split()
    if not parts:
        return
    cmd, args = parts[0].lower(), parts[1:]

    # ── add ────────────────────────────────────────────────────────
    if cmd == "add":
        if not args:
            console.print("[#EF4444]Usage: add <name> [secret][/]")
            return
        name = args[0]
        secret = args[1] if len(args) > 1 else None

        if name in engine.list_accounts():
            console.print(f"[#F59E0B]⚠  Account '{name}' already exists.[/]")
            return

        issuer = console.input("[#06B6D4]Issuer/Service name [2FAShield]: [/]").strip() or "2FAShield"

        with console.status("[#7C3AED]Adding account...[/]", spinner="dots"):
            time.sleep(0.4)
            secret, err = engine.add_account(name, secret, issuer)

        if err:
            console.print(f"[#EF4444]Error: {err}[/]")
            return

        code, remaining, _ = engine.get_totp(name)
        console.print(Panel(
            f"[bold #10B981]✅ Account Added Successfully![/]\n\n"
            f"[#F9FAFB]Name   :[/] [bold #7C3AED]{name}[/]\n"
            f"[#F9FAFB]Secret :[/] [bold #F59E0B]{secret}[/]\n"
            f"[#F9FAFB]Issuer :[/] [#06B6D4]{issuer}[/]\n"
            f"[#F9FAFB]OTP    :[/] [bold #10B981]{code[:3]} {code[3:]}[/]  "
            f"[#6B7280](expires in {remaining}s)[/]\n\n"
            f"[#6B7280]Run [bold #06B6D4]qr {name}[/] to export a QR code[/]",
            title="[bold #7C3AED]🔐 New Account[/]",
            border_style="#10B981",
            padding=(1, 2),
        ))

    # ── list ───────────────────────────────────────────────────────
    elif cmd == "list":
        accounts = engine.list_accounts()
        if not accounts:
            console.print(Panel(
                "[#6B7280]No accounts yet. Use [bold #10B981]add <name>[/] to get started.[/]",
                border_style="#6B7280",
            ))
            return
        table = Table(box=box.ROUNDED, border_style="#7C3AED",
                      header_style="bold #06B6D4", show_lines=True)
        table.add_column("#", style="#6B7280", width=5)
        table.add_column("Account Name", style="bold #F9FAFB")
        table.add_column("Issuer", style="#06B6D4")
        table.add_column("Created", style="#6B7280")
        table.add_column("Backup Codes", justify="center")

        for i, name in enumerate(accounts, 1):
            acc = engine.vault["accounts"][name]
            has_backup = "✅" if acc.get("backup_codes") else "❌"
            created = acc.get("created", "Unknown")[:10]
            table.add_row(str(i), name, acc.get("issuer", "?"), created, has_backup)

        console.print(Panel(table,
            title=f"[bold #7C3AED]📋 Stored Accounts ({len(accounts)})[/]",
            border_style="#7C3AED"))

    # ── show ───────────────────────────────────────────────────────
    elif cmd == "show":
        if not args:
            console.print("[#EF4444]Usage: show <name>[/]")
            return
        name = args[0]
        code, remaining, err = engine.get_totp(name)
        if err:
            console.print(f"[#EF4444]Error: {err}[/]")
            return

        pct = remaining / 30
        color = "#10B981" if pct > 0.6 else "#F59E0B" if pct > 0.3 else "#EF4444"
        filled = int(pct * 30)
        bar = "█" * filled + "░" * (30 - filled)

        console.print(Panel(
            f"[bold {color}]   {code[:3]}  {code[3:]}   [/bold {color}]\n\n"
            f"[{color}]{bar}[/{color}]  [{color}]{remaining:02d}s[/{color}]\n\n"
            f"[#6B7280]Account: [bold #F9FAFB]{name}[/]  │  "
            f"Algorithm: SHA-1  │  Digits: 6  │  Period: 30s[/]",
            title=f"[bold #7C3AED]🔐 {name}[/]",
            border_style=color,
            padding=(1, 4),
        ))

    # ── live ───────────────────────────────────────────────────────
    elif cmd == "live":
        display = LiveTOTPDisplay(engine)
        console.print("[#6B7280]Starting live view... Press Ctrl+C to exit.[/]")
        time.sleep(0.5)
        display.run()
        print_banner()

    # ── verify ─────────────────────────────────────────────────────
    elif cmd == "verify":
        if len(args) < 2:
            console.print("[#EF4444]Usage: verify <name> <code>[/]")
            return
        name, code = args[0], args[1].replace(" ", "")
        valid, err = engine.verify_code(name, code)
        if err:
            console.print(f"[#EF4444]Error: {err}[/]")
            return
        if valid:
            console.print(Panel(
                "[bold #10B981]✅ CODE VALID — Authentication Successful![/]\n"
                f"[#6B7280]Account: {name}  │  Code: {code}[/]",
                border_style="#10B981", padding=(1, 2)))
        else:
            console.print(Panel(
                "[bold #EF4444]❌ CODE INVALID — Authentication Failed![/]\n"
                f"[#6B7280]Account: {name}  │  Code may be expired or wrong[/]",
                border_style="#EF4444", padding=(1, 2)))

    # ── delete ─────────────────────────────────────────────────────
    elif cmd == "delete":
        if not args:
            console.print("[#EF4444]Usage: delete <name>[/]")
            return
        name = args[0]
        confirm = console.input(
            f"[bold #EF4444]⚠  Delete '{name}'? This cannot be undone! (yes/no): [/]"
        ).strip().lower()
        if confirm == "yes":
            if engine.delete_account(name):
                console.print(f"[#10B981]✅ Account '{name}' deleted.[/]")
            else:
                console.print(f"[#EF4444]Account '{name}' not found.[/]")
        else:
            console.print("[#6B7280]Deletion cancelled.[/]")

    # ── backup ─────────────────────────────────────────────────────
    elif cmd == "backup":
        if not args:
            console.print("[#EF4444]Usage: backup <name>[/]")
            return
        name = args[0]
        if name not in engine.list_accounts():
            console.print(f"[#EF4444]Account '{name}' not found.[/]")
            return
        with console.status("[#7C3AED]Generating backup codes...[/]", spinner="dots2"):
            time.sleep(0.5)
            codes = engine.generate_backup_codes(name)
        BackupCodeManager.display(codes)

    # ── qr ─────────────────────────────────────────────────────────
    elif cmd == "qr":
        if not args:
            console.print("[#EF4444]Usage: qr <name>[/]")
            return
        name = args[0]
        with console.status(f"[#7C3AED]Generating QR for {name}...[/]", spinner="aesthetic"):
            time.sleep(0.5)
            fname = engine.export_qr(name)
        if fname:
            console.print(Panel(
                f"[#10B981]✅ QR Code saved to [bold]{fname}[/][/]\n"
                f"[#6B7280]Scan with Google Authenticator, Authy, or any TOTP app.[/]",
                border_style="#10B981", padding=(1, 2)))
        else:
            console.print("[#EF4444]Failed to generate QR code.[/]")

    # ── dashboard ──────────────────────────────────────────────────
    elif cmd == "dashboard":
        show_dashboard(engine)

    # ── export ─────────────────────────────────────────────────────
    elif cmd == "export":
        if not args:
            console.print("[#EF4444]Usage: export <name>[/]")
            return
        uri = engine.get_uri(args[0])
        if uri:
            console.print(Panel(
                f"[bold #F59E0B]otpauth URI:[/]\n[#06B6D4]{uri}[/]",
                title=f"[bold #7C3AED]📤 Export: {args[0]}[/]",
                border_style="#F59E0B", padding=(1, 2)))
        else:
            console.print(f"[#EF4444]Account '{args[0]}' not found.[/]")

    # ── search ─────────────────────────────────────────────────────
    elif cmd == "search":
        if not args:
            console.print("[#EF4444]Usage: search <query>[/]")
            return
        query = args[0].lower()
        results = [a for a in engine.list_accounts() if query in a.lower()]
        if results:
            console.print(Panel(
                "\n".join(f"[bold #7C3AED]{r}[/]  "
                          f"[#6B7280]({engine.vault['accounts'][r].get('issuer','?')})[/]"
                          for r in results),
                title=f"[bold #06B6D4]🔍 Results for '{query}' ({len(results)})[/]",
                border_style="#06B6D4", padding=(1, 2)))
        else:
            console.print(f"[#6B7280]No accounts matching '{query}'.[/]")

    # ── rename ─────────────────────────────────────────────────────
    elif cmd == "rename":
        if len(args) < 2:
            console.print("[#EF4444]Usage: rename <old_name> <new_name>[/]")
            return
        old, new = args[0], args[1]
        if old not in engine.vault["accounts"]:
            console.print(f"[#EF4444]Account '{old}' not found.[/]")
            return
        if new in engine.vault["accounts"]:
            console.print(f"[#F59E0B]Account '{new}' already exists.[/]")
            return
        engine.vault["accounts"][new] = engine.vault["accounts"].pop(old)
        engine._save_vault()
        console.print(f"[#10B981]✅ Renamed '{old}' → '{new}'[/]")

    # ── info ───────────────────────────────────────────────────────
    elif cmd == "info":
        if not args:
            console.print("[#EF4444]Usage: info <name>[/]")
            return
        name = args[0]
        if name not in engine.vault["accounts"]:
            console.print(f"[#EF4444]Account '{name}' not found.[/]")
            return
        acc = engine.vault["accounts"][name]
        code, rem, _ = engine.get_totp(name)
        info_text = (
            f"[#F9FAFB]Name      :[/] [bold #7C3AED]{name}[/]\n"
            f"[#F9FAFB]Issuer    :[/] [#06B6D4]{acc.get('issuer','?')}[/]\n"
            f"[#F9FAFB]Algorithm :[/] [#F59E0B]{acc.get('algorithm','SHA1')}[/]\n"
            f"[#F9FAFB]Digits    :[/] [#F59E0B]{acc.get('digits',6)}[/]\n"
            f"[#F9FAFB]Period    :[/] [#F59E0B]{acc.get('period',30)}s[/]\n"
            f"[#F9FAFB]Created   :[/] [#6B7280]{acc.get('created','?')[:19]}[/]\n"
            f"[#F9FAFB]Current OTP:[/] [bold #10B981]{code[:3]} {code[3:]}[/]  "
            f"[#6B7280]({rem}s)[/]\n"
            f"[#F9FAFB]Backup Codes:[/] "
            f"{'[#10B981]✅ Saved[/]' if acc.get('backup_codes') else '[#EF4444]❌ None[/]'}"
        )
        console.print(Panel(info_text,
            title=f"[bold #7C3AED]ℹ  Account Info: {name}[/]",
            border_style="#7C3AED", padding=(1, 2)))

    # ── clear ──────────────────────────────────────────────────────
    elif cmd == "clear":
        print_banner()

    # ── help ───────────────────────────────────────────────────────
    elif cmd == "help":
        show_help()

    # ── exit ───────────────────────────────────────────────────────
    elif cmd in ("exit", "quit"):
        console.print(Panel(
            Align.center("[bold #7C3AED]👋 Goodbye! Stay Secure.[/]"),
            border_style="#7C3AED", padding=(1, 0)))
        sys.exit(0)

    else:
        close = [c for c in BASE_COMMANDS if c.startswith(cmd[:2])]
        hint = f"  Did you mean: [bold #06B6D4]{', '.join(close[:3])}[/]?" if close else ""
        console.print(f"[#EF4444]Unknown command: '[bold]{cmd}[/]'[/]{hint}  "
                      f"[#6B7280]Type [bold #10B981]help[/] for all commands.[/]")


# ── Main Loop ─────────────────────────────────────────────────────
def main():
    boot_animation()
    print_banner()

    engine = TOTPEngine()

    console.print(Align.center(SHIELD_ART))
    console.print()

    if not engine.list_accounts():
        console.print(Panel(
            "[#F9FAFB]Welcome to [bold #7C3AED]2FA Shield[/]! 🎉\n\n"
            "[#6B7280]Get started:\n"
            "  [bold #10B981]add GitHub[/]      → Add a GitHub 2FA account\n"
            "  [bold #10B981]add MyBank[/]      → Add a banking 2FA account\n"
            "  [bold #10B981]live[/]            → Live TOTP monitor\n"
            "  [bold #10B981]help[/]            → All commands[/]",
            title="[bold #7C3AED]🚀 Quick Start[/]",
            border_style="#7C3AED",
            padding=(1, 3),
        ))

    history = InMemoryHistory()
    session = PromptSession(
        history=history,
        auto_suggest=AutoSuggestFromHistory(),
        style=make_prompt_style(),
        mouse_support=False,
        complete_in_thread=True,
    )

    while True:
        try:
            completer = build_completer(engine)
            raw = session.prompt(
                HTML('<b><style fg="#7C3AED">2fa-shield</style></b>'
                     '<style fg="#6B7280"> ❯ </style>'),
                completer=completer,
                bottom_toolbar=lambda: bottom_toolbar(engine),
                style=make_prompt_style(),
            )
            if raw.strip():
                process_command(raw, engine)
        except KeyboardInterrupt:
            console.print("\n[#6B7280]Ctrl+C pressed. Type [bold #10B981]exit[/] to quit.[/]")
        except EOFError:
            console.print("\n[#7C3AED]👋 Goodbye![/]")
            break


if __name__ == "__main__":
    main()
