# 🔐 2FA Shield — Two-Factor Authentication Security Suite

<div align="center">

![2FA Shield Banner](https://img.shields.io/badge/2FA-Shield-7C3AED?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-06B6D4?style=for-the-badge&logo=python&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-Web_GUI-10B981?style=for-the-badge&logo=html5&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)
![RFC](https://img.shields.io/badge/RFC-6238_Compliant-EF4444?style=for-the-badge)

**A beautiful, beginner-friendly 2FA management suite with both a TUI and Web GUI.**

[Features](#-features) · [Install](#-installation) · [TUI Usage](#-tui-usage) · [Web GUI](#-web-gui) · [Security](#-security)

</div>

---

## ✨ Features

### 🖥️ Terminal UI (TUI)
| Feature | Description |
|---------|-------------|
| 🌈 **Gradient Banner** | Stunning blocky ASCII art with purple→cyan gradient |
| ⚡ **Auto-complete** | Fuzzy tab-completion for all commands + account names |
| 💡 **Auto-suggest** | Ghost-text command hints from history |
| 📊 **Live Monitor** | Real-time TOTP dashboard with countdown bars |
| 🔒 **Encrypted Vault** | AES-128 (Fernet) encrypted secret storage |
| 📋 **Backup Codes** | Generate and store 8 recovery codes per account |
| 📷 **QR Export** | Save QR codes as PNG files |
| 🛡️ **Security Audit** | Built-in security status dashboard |
| ✅ **Verify Codes** | Validate TOTP codes with ±1 window tolerance |
| 🔍 **Search** | Fuzzy search across all accounts |
| ✏️ **Rename** | Rename accounts without losing secrets |

### 🌐 Web GUI
| Feature | Description |
|---------|-------------|
| 🎨 **Gradient UI** | Beautiful dark UI with purple/cyan/emerald gradients |
| 🔐 **Logo** | Animated SVG shield logo with gradient |
| ✨ **Particles** | Animated particle network background |
| 📱 **Responsive** | Works on mobile, tablet, and desktop |
| ⚡ **Live Codes** | Codes update every second with progress bars |
| 📋 **Click to Copy** | Click any code to copy it instantly |
| 🔍 **QR Display** | Visual QR code in account detail view |
| 💾 **LocalStorage** | Data stored locally, never leaves your device |
| 🌙 **Dark/Light** | Toggle between dark and light modes |
| ⌨️ **Shortcuts** | Ctrl+N (add), Ctrl+V (verify), Esc (close) |

---

## 📦 Installation

### TUI

```bash
# Clone the repo
git clone https://github.com/yourusername/2fa-shield.git
cd 2fa-shield/tui

# Install dependencies
pip install -r requirements.txt

# Run!
python main.py
```

### Web GUI

```bash
cd 2fa-shield/web

# No build step needed!
# Option 1: Python server
python -m http.server 3000

# Option 2: Node serve
npx serve .

# Option 3: Just open index.html in your browser!
```

---

## 🖥️ TUI Usage

```
2fa-shield ❯ _          ← Prompt with auto-suggest
```

| Command | Example | Description |
|---------|---------|-------------|
| `add <name>` | `add GitHub` | Add a 2FA account |
| `list` | `list` | List all accounts |
| `show <name>` | `show GitHub` | Show current TOTP code |
| `live` | `live` | Live monitor all codes |
| `verify <name> <code>` | `verify GitHub 123456` | Verify a code |
| `backup <name>` | `backup GitHub` | Generate backup codes |
| `qr <name>` | `qr GitHub` | Export QR code PNG |
| `delete <name>` | `delete GitHub` | Delete an account |
| `search <query>` | `search git` | Search accounts |
| `rename <old> <new>` | `rename Git GitHub` | Rename account |
| `info <name>` | `info GitHub` | Full account details |
| `dashboard` | `dashboard` | Security overview |
| `help` | `help` | Show all commands |
| `exit` | `exit` | Quit 2FA Shield |

### Auto-complete Tips
- Press **Tab** to auto-complete commands and account names
- Press **↑ / ↓** to cycle through command history
- Ghost text suggestions appear as you type

---

## 🌐 Web GUI

Open `web/index.html` in any modern browser. No installation required.

- **Add accounts** → Click "Add Account" or press `Ctrl+N`
- **Copy codes** → Click any TOTP code card
- **View QR** → Click the QR button on a card
- **Verify** → Navigate to the Verify tab
- **Backup** → Click 🔑 on any card for recovery codes

---

## 🔐 Security

### Architecture
```
Secret Key ──► Fernet Encrypt ──► vault.json (encrypted at rest)
                    │
                 vault.key (chmod 600, never stored in vault)
```

### Standards Compliance
- **RFC 6238** — TOTP time-based OTPs
- **RFC 4226** — HOTP: HMAC-based OTPs
- **FIPS 198** — HMAC with SHA-1
- **AES-128**  — Vault encryption (Python Fernet)
- **Web Crypto API** — Browser-native crypto (no external libs)

### Best Practices
- ✅ Secrets encrypted at rest (Fernet AES-128)
- ✅ Vault key file chmod 600
- ✅ Web vault uses localStorage (data never leaves device)
- ✅ No external API calls
- ✅ ±1 window TOTP verification (handles clock drift)
- ✅ Backup codes generated with `secrets.token_hex()` / `crypto.getRandomValues()`

---

## 🎨 Colour Palette

| Name | Hex | Usage |
|------|-----|-------|
| Violet | `#7C3AED` | Primary / gradient start |
| Cyan | `#06B6D4` | Secondary / gradient mid |
| Emerald | `#10B981` | Success / gradient end |
| Amber | `#F59E0B` | Warning / timer |
| Red | `#EF4444` | Danger / expiry |
| Gray | `#6B7280` | Muted text |

---

## 📁 Project Structure

```
2fa-shield/
├── tui/
│   ├── main.py          ← Full TUI application
│   ├── requirements.txt ← Python dependencies
│   ├── vault.json       ← Encrypted vault (auto-created)
│   └── vault.key        ← Encryption key (chmod 600, auto-created)
├── web/
│   ├── index.html       ← Web GUI (single file app)
│   ├── style.css        ← Styles with gradients
│   └── app.js           ← Full TOTP engine + UI logic
└── README.md
```

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">
  Made with ❤️ and 🔐 by the 2FA Shield Team
  <br/>
  <sub>Stay secure. Enable 2FA everywhere.</sub>
</div>
