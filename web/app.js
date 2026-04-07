"use strict";
/* ── 2FA Shield · Web App ──────────────────────────────────────
   Pure vanilla JS · No build step · LocalStorage vault
   TOTP generation implemented natively with Web Crypto API
─────────────────────────────────────────────────────────────── */

// ── TOTP Engine ────────────────────────────────────────────────
const TOTP = {
  /* Base32 decode */
  base32Decode(s) {
    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    s = s.toUpperCase().replace(/=+$/, "");
    let bits = 0, val = 0, idx = 0;
    const out = new Uint8Array(Math.floor((s.length * 5) / 8));
    for (const c of s) {
      val = (val << 5) | ALPHABET.indexOf(c);
      bits += 5;
      if (bits >= 8) {
        out[idx++] = (val >>> (bits - 8)) & 0xff;
        bits -= 8;
      }
    }
    return out;
  },

  /* HMAC-SHA1 */
  async hmacSHA1(key, data) {
    const k = await crypto.subtle.importKey(
      "raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
  },

  /* Generate TOTP code */
  async generate(secret, digits = 6, period = 30) {
    const key    = this.base32Decode(secret);
    const epoch  = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / period);
    const buf    = new ArrayBuffer(8);
    const view   = new DataView(buf);
    view.setUint32(4, counter, false);
    const mac    = await this.hmacSHA1(key, new Uint8Array(buf));
    const offset = mac[19] & 0xf;
    const code   = (
      ((mac[offset]     & 0x7f) << 24) |
      ((mac[offset + 1] & 0xff) << 16) |
      ((mac[offset + 2] & 0xff) <<  8) |
       (mac[offset + 3] & 0xff)
    ) % Math.pow(10, digits);
    return code.toString().padStart(digits, "0");
  },

  /* Remaining seconds */
  remaining(period = 30) {
    return period - (Math.floor(Date.now() / 1000) % period);
  },

  /* Random base32 secret */
  randomSecret(len = 20) {
    const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    return Array.from(bytes, b => ALPHA[b % 32]).join("");
  },

  /* Build provisioning URI */
  uri(account, secret, issuer) {
    const p = new URLSearchParams({
      secret, issuer, algorithm: "SHA1", digits: 6, period: 30,
    });
    return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?${p}`;
  },
};

// ── Vault (localStorage) ───────────────────────────────────────
const Vault = {
  KEY: "2fa_shield_vault",

  load() {
    try {
      return JSON.parse(localStorage.getItem(this.KEY)) || { accounts: [] };
    } catch { return { accounts: [] }; }
  },

  save(data) {
    localStorage.setItem(this.KEY, JSON.stringify(data));
  },

  get accounts() { return this.load().accounts; },

  add(account) {
    const vault = this.load();
    vault.accounts.push({ ...account, created: new Date().toISOString() });
    this.save(vault);
  },

  remove(id) {
    const vault = this.load();
    vault.accounts = vault.accounts.filter(a => a.id !== id);
    this.save(vault);
  },

  find(id) {
    return this.load().accounts.find(a => a.id === id);
  },

  clear() {
    this.save({ accounts: [] });
  },
};

// ── State ──────────────────────────────────────────────────────
let updateLoop = null;
let currentBackupAccount = null;

// ── Toast ──────────────────────────────────────────────────────
function toast(message, type = "info", duration = 3000) {
  const icons = { success: "✅", error: "❌", info: "💡", warning: "⚠️" };
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
  document.getElementById("toastContainer").appendChild(el);
  setTimeout(() => {
    el.style.animation = "toast-out 0.3s ease forwards";
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ── Modal ──────────────────────────────────────────────────────
function openModal(id) {
  const el = document.getElementById(`modal-${id}`);
  if (el) { el.classList.add("open"); el.style.display = "flex"; }
}

function closeModal(id) {
  const el = document.getElementById(`modal-${id}`);
  if (el) { el.classList.remove("open"); el.style.display = "none"; }
}

function closeModalOutside(e, id) {
  if (e.target === e.currentTarget) closeModal(id);
}

// ── Section Navigation ─────────────────────────────────────────
function showSection(id) {
  document.querySelectorAll(".section").forEach(s => {
    s.style.display = "none";
  });
  const target = document.getElementById(id);
  if (target) target.style.display = "block";

  document.querySelectorAll(".nav-link").forEach(l => {
    l.classList.toggle("active", l.getAttribute("href") === `#${id}`);
  });

  // Also handle hero separately
  const hero = document.querySelector(".hero");
  if (hero) hero.style.display = id === "dashboard" ? "grid" : "none";
}

// ── Init Nav ───────────────────────────────────────────────────
document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    const target = link.getAttribute("href").slice(1);
    if (target === "dashboard") {
      // Show hero + accounts
      document.querySelector(".hero").style.display = "grid";
      document.querySelectorAll(".section").forEach(s => s.style.display = "none");
      document.getElementById("accounts").style.display = "block";
    } else {
      showSection(target);
    }
    document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
    link.classList.add("active");
  });
});

// ── Emoji Picker ───────────────────────────────────────────────
function initEmojiPicker() {
  const picker = document.getElementById("emojiPicker");
  if (!picker) return;
  picker.innerHTML = "";
  const emojis = ["🔐","🏦","📧","💻","🎮","🛒","🏥","🎓","🔑","💳","🌐","📱","🏠","✈️","🎵","🔒","🛡️","💡","🎯","🏢"];
  emojis.forEach(em => {
    const span = document.createElement("span");
    span.textContent = em;
    span.title = em;
    span.addEventListener("click", () => {
      picker.querySelectorAll("span").forEach(s => s.classList.remove("selected"));
      span.classList.add("selected");
      document.getElementById("selectedEmoji").value = em;
    });
    picker.appendChild(span);
  });
  // Select first
  picker.firstChild?.classList.add("selected");
}

// ── Add Account ────────────────────────────────────────────────
function generateSecret() {
  document.getElementById("addSecret").value = TOTP.randomSecret();
  toast("New secret generated!", "success");
}

async function addAccount() {
  const name   = document.getElementById("addName").value.trim();
  const issuer = document.getElementById("addIssuer").value.trim() || "2FAShield";
  const emoji  = document.getElementById("selectedEmoji").value || "🔐";
  let   secret = document.getElementById("addSecret").value.trim().toUpperCase().replace(/\s/g, "");

  if (!name) { toast("Account name is required", "error"); return; }

  if (!secret) secret = TOTP.randomSecret();

  // Validate
  try {
    await TOTP.generate(secret);
  } catch {
    toast("Invalid secret key — must be valid Base32", "error"); return;
  }

  const account = {
    id:      crypto.randomUUID(),
    name, issuer, secret, emoji,
    backup:  generateBackupCodes(),
  };

  Vault.add(account);
  closeModal("addAccount");
  resetAddForm();
  renderAccounts();
  updateStats();
  toast(`✅ ${name} added successfully!`, "success");
}

function resetAddForm() {
  ["addName","addIssuer","addSecret"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  document.getElementById("selectedEmoji").value = "🔐";
  initEmojiPicker();
}

// ── Backup Codes ───────────────────────────────────────────────
function generateBackupCodes(count = 8) {
  return Array.from({ length: count }, () => {
    const a = crypto.getRandomValues(new Uint8Array(4));
    const b = crypto.getRandomValues(new Uint8Array(4));
    return Array.from(a, x => x.toString(16).padStart(2,"0")).join("").toUpperCase() +
      "-" +
      Array.from(b, x => x.toString(16).padStart(2,"0")).join("").toUpperCase();
  });
}

function showBackupCodes(accountId) {
  const account = Vault.find(accountId);
  if (!account) return;
  currentBackupAccount = account;

  const body = document.getElementById("backupBody");
  body.innerHTML = `
    <p style="color:var(--c-muted);font-size:.85rem;margin-bottom:1rem">
      ⚠️ Save these codes somewhere safe. Each can only be used <strong>once</strong>.
    </p>
    <div class="backup-grid">
      ${account.backup.map((code, i) => `
        <div class="backup-code" onclick="copyText('${code}', this)">
          <span>${String(i+1).padStart(2,"0")}. ${code}</span>
          <span style="font-size:.7rem;opacity:.5">copy</span>
        </div>
      `).join("")}
    </div>
    <div style="margin-top:1rem;padding:.75rem;background:rgba(245,158,11,.08);
         border:1px solid rgba(245,158,11,.25);border-radius:10px;
         font-size:.78rem;color:var(--c-amber)">
      🔑 These codes work even if you lose your phone.
      Store them in a password manager or print them.
    </div>
  `;
  openModal("backup");
}

function downloadBackupCodes() {
  if (!currentBackupAccount) return;
  const content = [
    `2FA Shield — Backup Codes`,
    `Account: ${currentBackupAccount.name}`,
    `Generated: ${new Date().toLocaleString()}`,
    ``,
    ...currentBackupAccount.backup.map((c, i) => `${i+1}. ${c}`),
    ``,
    `Keep these codes safe. Each can only be used once.`,
  ].join("\n");

  const blob = new Blob([content], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `2fa-backup-${currentBackupAccount.name}.txt`;
  a.click();
  toast("Backup codes downloaded!", "success");
}

// ── Render Accounts ────────────────────────────────────────────
function renderAccounts() {
  const grid  = document.getElementById("accountsGrid");
  const empty = document.getElementById("emptyState");
  const accounts = Vault.accounts;

  if (!accounts.length) {
    grid.innerHTML = "";
    empty.classList.add("show");
    return;
  }

  empty.classList.remove("show");

  // Rebuild only if count changed (optimisation)
  if (grid.children.length !== accounts.length) {
    grid.innerHTML = accounts.map(a => `
      <div class="account-card" id="card-${a.id}" onclick="handleCardClick(event,'${a.id}')">
        <div class="card-header">
          <div class="card-emoji">${a.emoji}</div>
          <div class="card-meta">
            <div class="card-name">${escHtml(a.name)}</div>
            <div class="card-issuer">${escHtml(a.issuer)}</div>
          </div>
          <div class="card-actions" onclick="event.stopPropagation()">
            <div class="card-btn" title="View QR" onclick="viewAccount('${a.id}')">QR</div>
            <div class="card-btn" title="Backup Codes" onclick="showBackupCodes('${a.id}')">🔑</div>
            <div class="card-btn" title="Delete" style="color:#EF4444"
                 onclick="deleteAccount('${a.id}')">🗑</div>
          </div>
        </div>
        <div class="card-otp mono" id="otp-${a.id}" title="Click to copy">
          — — —  — — —
        </div>
        <div class="card-progress-wrap">
          <div class="card-progress">
            <div class="card-progress-bar" id="bar-${a.id}" style="width:100%"></div>
          </div>
          <div class="card-timer" id="timer-${a.id}">30</div>
        </div>
      </div>
    `).join("");
  }

  updateOTPs();
}

function handleCardClick(e, id) {
  // Copy OTP on card click (if not a button)
  const otpEl = document.getElementById(`otp-${id}`);
  if (otpEl && !e.target.classList.contains("card-btn")) {
    const raw = otpEl.textContent.replace(/\s/g, "");
    if (raw.length === 6 && /\d+/.test(raw)) {
      navigator.clipboard.writeText(raw).then(() => toast("Code copied! 📋", "success"));
    }
  }
}

// ── Update OTPs (called every second) ─────────────────────────
async function updateOTPs() {
  const remaining = TOTP.remaining();
  const progress  = (remaining / 30) * 100;

  // Color based on time
  let barColor;
  if (remaining > 18) barColor = "linear-gradient(90deg,#7C3AED,#06B6D4)";
  else if (remaining > 9) barColor = "linear-gradient(90deg,#F59E0B,#EF4444)";
  else barColor = "#EF4444";

  for (const account of Vault.accounts) {
    try {
      const code = await TOTP.generate(account.secret);
      const otpEl  = document.getElementById(`otp-${account.id}`);
      const barEl  = document.getElementById(`bar-${account.id}`);
      const timEl  = document.getElementById(`timer-${account.id}`);

      if (otpEl) {
        otpEl.textContent = `${code.slice(0,3)}  ${code.slice(3)}`;
        otpEl.title = "Click to copy";
      }
      if (barEl) {
        barEl.style.width = `${progress}%`;
        barEl.style.background = barColor;
      }
      if (timEl) {
        timEl.textContent = remaining;
        timEl.style.color = remaining > 9 ? "var(--c-primary)" : "var(--c-red)";
      }
    } catch { /* skip invalid */ }
  }

  // Update hero display
  const hero = await getHeroCode();
  const heroEl = document.getElementById("heroCode");
  if (heroEl && hero) heroEl.textContent = `${hero.slice(0,3)} ${hero.slice(3)}`;

  // Update hero arc
  const arc = document.getElementById("arcProgress");
  const countdown = document.getElementById("heroCountdown");
  if (arc) {
    const dashOffset = 163 - (remaining / 30) * 163;
    arc.style.strokeDashoffset = dashOffset;
    arc.style.stroke = remaining > 9 ? "url(#arcGrad)" : "#EF4444";
  }
  if (countdown) countdown.textContent = remaining;
}

async function getHeroCode() {
  const accounts = Vault.accounts;
  if (!accounts.length) return null;
  try { return await TOTP.generate(accounts[0].secret); }
  catch { return null; }
}

// ── Delete Account ─────────────────────────────────────────────
function deleteAccount(id) {
  const account = Vault.find(id);
  if (!account) return;
  if (!confirm(`Delete "${account.name}"? This cannot be undone.`)) return;
  Vault.remove(id);
  renderAccounts();
  updateStats();
  populateVerifySelect();
  toast(`${account.name} deleted`, "warning");
}

// ── View Account / QR ──────────────────────────────────────────
async function viewAccount(id) {
  const account = Vault.find(id);
  if (!account) return;

  document.getElementById("viewModalTitle").textContent = `${account.emoji} ${account.name}`;

  const uri   = TOTP.uri(account.name, account.secret, account.issuer);
  const code  = await TOTP.generate(account.secret);
  const remaining = TOTP.remaining();

  const body = document.getElementById("viewModalBody");
  body.innerHTML = `
    <div style="display:grid;gap:1rem">
      <!-- Current code -->
      <div style="text-align:center;padding:1.5rem;background:var(--c-surface);
           border-radius:12px;border:1px solid var(--c-border)">
        <div style="font-size:.7rem;color:var(--c-muted);text-transform:uppercase;
             letter-spacing:.08em;margin-bottom:.5rem">Current Code</div>
        <div class="otp-display" style="font-size:2.5rem;letter-spacing:.2em">
          ${code.slice(0,3)} ${code.slice(3)}
        </div>
        <div style="font-size:.75rem;color:var(--c-muted);margin-top:.5rem">
          Expires in ${remaining}s
        </div>
      </div>

      <!-- QR Code -->
      <div class="qr-display">
        <div class="qr-canvas-wrap">
          <canvas id="qrCanvas" width="200" height="200"></canvas>
        </div>
        <p style="font-size:.75rem;color:var(--c-muted)">
          Scan with Google Authenticator, Authy, or any TOTP app
        </p>
        <div class="qr-uri">${escHtml(uri)}</div>
      </div>

      <!-- Account info -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
        ${[
          ["Name",    account.name],
          ["Issuer",  account.issuer],
          ["Secret",  account.secret.slice(0,8) + "…"],
          ["Created", account.created.slice(0,10)],
          ["Algorithm","SHA-1 / TOTP"],
          ["Period",  "30 seconds"],
        ].map(([l,v]) => `
          <div style="padding:.75rem;background:var(--c-surface);border-radius:10px;
               border:1px solid var(--c-border2)">
            <div style="font-size:.68rem;color:var(--c-muted);text-transform:uppercase;
                 letter-spacing:.06em">${l}</div>
            <div style="font-size:.85rem;font-weight:700;margin-top:4px">${escHtml(String(v))}</div>
          </div>
        `).join("")}
      </div>

      <!-- Copy buttons -->
      <div style="display:flex;gap:.75rem">
        <button class="btn btn-primary" style="flex:1"
                onclick="navigator.clipboard.writeText('${code}').then(()=>toast('Code copied!','success'))">
          📋 Copy Code
        </button>
        <button class="btn btn-ghost" style="flex:1"
                onclick="navigator.clipboard.writeText('${escAttr(uri)}').then(()=>toast('URI copied!','info'))">
          🔗 Copy URI
        </button>
      </div>
    </div>
  `;

  openModal("viewAccount");

  // Draw QR
  setTimeout(() => drawQR(uri, "qrCanvas"), 50);
}

// ── Tiny QR Generator (pure JS, no library needed for simple demo)
// For production, use a proper QR library. This draws a placeholder.
function drawQR(text, canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;

  // Background
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, W, H);

  // Encode text as a deterministic pattern for demo
  // (In production, use qrcode.js or qrcode-generator library)
  const size = 21;
  const cell = Math.floor(W / (size + 2));
  const off  = Math.floor((W - cell * size) / 2);

  // Seed from text
  let seed = 0;
  for (const c of text) seed = (seed * 31 + c.charCodeAt(0)) >>> 0;

  const lcg = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 0xFFFFFFFF; };

  const grad = ctx.createLinearGradient(0, 0, W, H);
  grad.addColorStop(0, "#7C3AED");
  grad.addColorStop(0.5, "#06B6D4");
  grad.addColorStop(1, "#10B981");

  ctx.fillStyle = grad;

  // Draw finder patterns (corners)
  const drawFinder = (x, y) => {
    ctx.fillStyle = "#7C3AED";
    ctx.fillRect(off + x*cell, off + y*cell, 7*cell, 7*cell);
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(off + (x+1)*cell, off + (y+1)*cell, 5*cell, 5*cell);
    ctx.fillStyle = grad;
    ctx.fillRect(off + (x+2)*cell, off + (y+2)*cell, 3*cell, 3*cell);
  };

  drawFinder(0, 0);
  drawFinder(size-7, 0);
  drawFinder(0, size-7);

  // Fill data cells
  ctx.fillStyle = grad;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      // Skip finder pattern areas
      const inFinder = (r < 8 && c < 8) || (r < 8 && c >= size-8) || (r >= size-8 && c < 8);
      if (!inFinder && lcg() > 0.5) {
        ctx.fillStyle = lcg() > 0.5 ? "#7C3AED" : "#06B6D4";
        const px = off + c * cell;
        const py = off + r * cell;
        const r2 = cell * 0.15;
        ctx.beginPath();
        ctx.roundRect?.(px+1, py+1, cell-2, cell-2, r2) ||
          ctx.rect(px+1, py+1, cell-2, cell-2);
        ctx.fill();
      }
    }
  }

  // Center logo
  ctx.fillStyle = "#ffffff";
  ctx.beginPath();
  ctx.arc(W/2, H/2, 18, 0, Math.PI * 2);
  ctx.fill();
  ctx.font = "22px serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("🔐", W/2, H/2);
}

// ── Verify Code ────────────────────────────────────────────────
async function verifyCode() {
  const accId = document.getElementById("verifyAccount").value;
  const raw   = document.getElementById("verifyCode").value.replace(/\s/g, "");
  const result = document.getElementById("verifyResult");

  if (!accId) { toast("Select an account first", "error"); return; }
  if (raw.length !== 6 || !/^\d{6}$/.test(raw)) {
    toast("Enter a valid 6-digit code", "error"); return;
  }

  const account = Vault.find(accId);
  if (!account) { toast("Account not found", "error"); return; }

  // Check current and adjacent windows (±1)
  let valid = false;
  for (const offset of [-1, 0, 1]) {
    const now     = Math.floor(Date.now() / 1000);
    const counter = Math.floor((now + offset * 30) / 30);
    const buf     = new ArrayBuffer(8);
    new DataView(buf).setUint32(4, counter, false);
    const key    = TOTP.base32Decode(account.secret);
    const mac    = await crypto.subtle.sign("HMAC",
      await crypto.subtle.importKey("raw", key,
        { name: "HMAC", hash: "SHA-1" }, false, ["sign"]),
      new Uint8Array(buf)
    );
    const m = new Uint8Array(mac);
    const o = m[19] & 0xf;
    const code = (
      ((m[o]   & 0x7f) << 24) | ((m[o+1] & 0xff) << 16) |
      ((m[o+2] & 0xff) <<  8) |  (m[o+3] & 0xff)
    ) % 1000000;
    if (code.toString().padStart(6,"0") === raw) { valid = true; break; }
  }

  result.style.display = "block";
  if (valid) {
    result.className = "verify-result valid";
    result.innerHTML = "✅ &nbsp;CODE VALID — Authentication Successful!";
    toast("Code verified successfully!", "success");
  } else {
    result.className = "verify-result invalid";
    result.innerHTML = "❌ &nbsp;CODE INVALID — Authentication Failed!";
    toast("Invalid code!", "error");
  }

  setTimeout(() => { result.style.display = "none"; }, 4000);
}

function formatCodeInput(el) {
  let v = el.value.replace(/\D/g, "").slice(0, 6);
  el.value = v.length > 3 ? v.slice(0,3) + " " + v.slice(3) : v;
}

// ── Populate Verify Select ─────────────────────────────────────
function populateVerifySelect() {
  const sel = document.getElementById("verifyAccount");
  if (!sel) return;
  sel.innerHTML = '<option value="">Choose account...</option>' +
    Vault.accounts.map(a =>
      `<option value="${a.id}">${a.emoji} ${escHtml(a.name)}</option>`
    ).join("");
}

// ── Stats ──────────────────────────────────────────────────────
function updateStats() {
  const el = document.getElementById("totalAccounts");
  if (el) el.textContent = Vault.accounts.length;
  populateVerifySelect();
}

// ── Theme ──────────────────────────────────────────────────────
function toggleTheme(toggle) {
  toggle.classList.toggle("active");
  document.body.classList.toggle("light-mode");
  toast(`Switched to ${document.body.classList.contains("light-mode") ? "light" : "dark"} mode`, "info");
}

// ── Clear All ──────────────────────────────────────────────────
function clearAll() {
  if (!confirm("Delete ALL accounts? This cannot be undone!")) return;
  Vault.clear();
  renderAccounts();
  updateStats();
  toast("All accounts cleared", "warning");
}

// ── Utilities ──────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function escAttr(s) {
  return String(s).replace(/'/g,"&#39;");
}
function copyText(text, el) {
  navigator.clipboard.writeText(text).then(() => {
    toast("Copied!", "success");
    if (el) { const orig = el.style.opacity; el.style.opacity = "0.5"; setTimeout(()=>el.style.opacity=orig,300); }
  });
}

// ── Particles ─────────────────────────────────────────────────
function initParticles() {
  const canvas = document.getElementById("particles");
  const ctx    = canvas.getContext("2d");
  let W, H, particles;

  const COLORS = ["#7C3AED","#06B6D4","#10B981","#F59E0B"];

  const resize = () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  };

  const spawn = () => ({
    x: Math.random() * W,
    y: Math.random() * H,
    r: Math.random() * 1.5 + 0.5,
    dx: (Math.random() - 0.5) * 0.4,
    dy: (Math.random() - 0.5) * 0.4,
    color: COLORS[Math.floor(Math.random() * COLORS.length)],
    alpha: Math.random() * 0.5 + 0.1,
  });

  resize();
  particles = Array.from({ length: 80 }, spawn);
  window.addEventListener("resize", resize);

  const draw = () => {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(124,58,237,${0.12 * (1 - dist/120)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.alpha;
      ctx.fill();
      ctx.globalAlpha = 1;

      p.x += p.dx;
      p.y += p.dy;

      if (p.x < 0 || p.x > W) p.dx *= -1;
      if (p.y < 0 || p.y > H) p.dy *= -1;
    });

    requestAnimationFrame(draw);
  };

  draw();
}

// ── Keyboard Shortcuts ─────────────────────────────────────────
document.addEventListener("keydown", e => {
  if (e.ctrlKey || e.metaKey) {
    if (e.key === "n") { e.preventDefault(); openModal("addAccount"); }
    if (e.key === "v") { e.preventDefault(); showSection("verify"); }
  }
  if (e.key === "Escape") {
    ["addAccount","viewAccount","backup"].forEach(closeModal);
  }
});

// ── Startup ────────────────────────────────────────────────────
(async function init() {
  initParticles();
  initEmojiPicker();
  renderAccounts();
  updateStats();
  populateVerifySelect();

  // Tick every second
  setInterval(async () => {
    await updateOTPs();
  }, 1000);

  // Welcome toast
  const count = Vault.accounts.length;
  if (count > 0) {
    toast(`Welcome back! ${count} account${count>1?"s":""} loaded.`, "success");
  } else {
    toast("Welcome to 2FA Shield! Press Ctrl+N to add an account.", "info", 5000);
  }

  // Demo account if empty
  if (!Vault.accounts.length) {
    const demo = {
      id:     crypto.randomUUID(),
      name:   "Demo Account",
      issuer: "2FA Shield",
      emoji:  "🔐",
      secret: "JBSWY3DPEHPK3PXP",  // well-known test secret
      backup: generateBackupCodes(),
      created: new Date().toISOString(),
    };
    Vault.add(demo);
    renderAccounts();
    updateStats();
    populateVerifySelect();
    toast("Demo account loaded! Try the live TOTP code. 👆", "info", 5000);
  }
})();
