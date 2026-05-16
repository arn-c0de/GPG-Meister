"""Help tab view (planv2.md §14.5)."""

from __future__ import annotations

import html

from PySide6.QtCore import QEvent, QObject
from PySide6.QtWidgets import QTabWidget, QTextBrowser, QToolTip, QWidget

from gpg_meister.ui.help.glossary import TERMS

_FIRST_STEPS_HTML = """
<h2>First Steps</h2>

<h3>Generate your first key</h3>
<ol>
  <li>Go to the <b>Keys</b> tab and click <b>New Key…</b></li>
  <li>Enter your name and email address.</li>
  <li>Choose an algorithm — <b>Ed25519 + Curve25519</b> is recommended for new keys.</li>
  <li>Set an expiry date (2 years is a good default).</li>
  <li>Create a strong passphrase. GPG Meister will tell you if it is strong enough.</li>
  <li>Click <b>Create Key</b> and wait a moment for key generation.</li>
</ol>
<p>After creating a key, create a vault backup immediately (see below).</p>

<h3>Encrypt your first message</h3>
<ol>
  <li>Go to the <b>Messages</b> tab and select <b>Encrypt</b>.</li>
  <li>Type or paste the message in the text area.</li>
  <li>Click <b>Add</b> to add one or more recipient keys.</li>
  <li>Review the recipient confirmation panel — verify each fingerprint.</li>
  <li>Check <b>I have verified the recipients</b> and click <b>Encrypt</b>.</li>
  <li>Copy the armored output and send it to the recipient.</li>
</ol>

<h3>Decrypt a message</h3>
<ol>
  <li>Go to the <b>Messages</b> tab and select <b>Decrypt</b>.</li>
  <li>Paste the armored PGP message into the text area.</li>
  <li>Click <b>Decrypt</b>.</li>
  <li>If the message is encrypted for your private key, you will be prompted for your passphrase.</li>
  <li>The decrypted plaintext will appear in the output area.</li>
</ol>

<h3>Create a vault backup</h3>
<ol>
  <li>Go to the <b>Vault</b> tab and select <b>Export</b>.</li>
  <li>Select the private keys to back up.</li>
  <li>Choose a file path (e.g., on an encrypted USB drive).</li>
  <li>Set a strong vault master passphrase — different from your key passphrase.</li>
  <li>Enter your GPG key passphrase to unlock the private keys for export.</li>
  <li>Click <b>Create Vault</b> and store the .gpgm file safely.</li>
</ol>
"""

_SECURITY_HTML = """
<h2>Security Boundaries</h2>
<p>GPG Meister is designed to protect your keys and messages in common scenarios.
The following threats are <b>not</b> covered by the application itself:</p>

<ul>
  <li><b>Keyloggers and screen capture</b> — if malware runs with your user privileges,
      it can capture passphrases as you type them.</li>
  <li><b>Root / administrator access</b> — any process with root access can read your
      memory and key files regardless of encryption.</li>
  <li><b>Compromised operating system</b> — a backdoored OS or infected shared library
      can intercept operations at any level.</li>
  <li><b>Physical access without full-disk encryption</b> — if your disk is not
      encrypted, an attacker with physical access can read your keyring files directly.
      Always use full-disk encryption (e.g., LUKS, BitLocker, FileVault).</li>
  <li><b>Quantum computers</b> — current GPG key algorithms (RSA, Ed25519) are not
      quantum-resistant. Post-quantum algorithms are not yet supported.</li>
  <li><b>Passphrase brute-force with unlimited tries</b> — Argon2id slows down
      guessing significantly, but an extremely weak passphrase can still be broken.
      Use the strength meter and accept only "Strong" or better.</li>
  <li><b>Key server trust</b> — GPG Meister does not automatically fetch keys from
      key servers. You are responsible for verifying key authenticity out-of-band.</li>
</ul>
<p>For a complete threat model, see planv2.md §11.</p>
"""

_TROUBLESHOOTING_HTML = """
<h2>Troubleshooting</h2>

<h3>Vault decryption fails with "wrong passphrase"</h3>
<p>You entered the wrong vault master passphrase. Note: the vault passphrase is
separate from your GPG key passphrase. Check which one you used when creating the vault.</p>

<h3>Encryption fails with "no public key"</h3>
<p>The recipient's public key is not in your keyring. Import it first via
<b>Keys → Import Public Key…</b></p>

<h3>GnuPG not found at startup</h3>
<p>Install GnuPG from your system package manager:<br>
Linux: <code>sudo apt install gnupg</code> or <code>sudo dnf install gnupg2</code><br>
macOS: <code>brew install gnupg</code><br>
Windows: Download Gpg4win from <code>gpg4win.org</code></p>

<h3>Config file is world-readable (startup warning)</h3>
<p>Run: <code>chmod 600 ~/.config/gpg-meister/config.toml</code></p>

<h3>Signing fails with "bad passphrase"</h3>
<p>The passphrase you entered does not match the selected signing key's passphrase.
Re-enter it carefully — remember that Caps Lock affects passphrase input.</p>
"""


_CSS = (
    "<style>"
    "h2 { margin-top: 4px; margin-bottom: 4px; }"
    "h3 { margin-top: 10px; margin-bottom: 2px; }"
    "p  { margin-top: 1px; margin-bottom: 4px; }"
    "li { margin-top: 1px; margin-bottom: 1px; }"
    "ol, ul { margin-top: 2px; margin-bottom: 4px; }"
    "</style>"
)

_TOOLTIPS: dict[str, str | None] = {
    "Keys": "The Keys tab — create, import, and manage your GPG key pairs.",
    "Messages": "The Messages tab — encrypt, decrypt, sign, and verify text messages.",
    "Vault": "The Vault tab — export and import encrypted .gpgm key backup files.",
    "New Key…": "Opens the key creation wizard to generate a new GPG key pair.",
    "Ed25519 + Curve25519": "A modern elliptic-curve algorithm. Ed25519 for signing, Curve25519 for encryption. Recommended for new keys.",
    "Create Key": "Generates the new key pair and adds it to the keyring.",
    "Encrypt": "Encrypts the message so only the selected recipients can read it.",
    "Add": "Adds a recipient's public key to the encryption target list.",
    "I have verified the recipients": "Required checkbox confirming you checked each recipient's fingerprint before encrypting.",
    "Decrypt": "Decrypts a PGP-armored message using your private key and passphrase.",
    "Export": "The Export sub-tab — create a .gpgm vault backup from selected keys.",
    "Create Vault": "Generates the encrypted .gpgm vault file with the selected keys.",
    "Keys → Import Public Key…": "Go to the Keys tab and click 'Import Public Key…' to add a recipient's public key to your keyring.",
    "Keyloggers and screen capture": "Malware running under your user account can record keystrokes and screenshots, capturing passphrases as you type.",
    "Root / administrator access": "Any process with root/admin privileges can read process memory and key files regardless of encryption.",
    "Compromised operating system": "A backdoored kernel or shared library can intercept cryptographic operations at any level.",
    "Physical access without full-disk encryption": "Without full-disk encryption (e.g. LUKS), an attacker with physical access can read key files directly from disk.",
    "Quantum computers": "RSA and Ed25519 are not quantum-resistant. Post-quantum algorithms are not yet supported by GnuPG.",
    "Passphrase brute-force with unlimited tries": "Argon2id slows down guessing significantly, but an extremely weak passphrase can still be cracked offline.",
    "Key server trust": "GPG Meister never fetches keys automatically. You are responsible for verifying key authenticity out-of-band.",
}


class _CharTooltipFilter(QObject):
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.ToolTip and isinstance(watched, QTextBrowser):
            cursor = watched.cursorForPosition(event.pos())
            tip = cursor.charFormat().toolTip()
            if tip:
                QToolTip.showText(event.globalPos(), tip, watched)
            else:
                QToolTip.hideText()
            return True
        return super().eventFilter(watched, event)


def _apply_char_tooltips(browser: QTextBrowser) -> None:
    doc = browser.document()
    for term, tip in _TOOLTIPS.items():
        if tip is None:
            continue
        cursor = doc.find(term)
        while not cursor.isNull():
            fmt = cursor.charFormat()
            fmt.setToolTip(tip)
            cursor.setCharFormat(fmt)
            cursor = doc.find(term, cursor)


def _build_glossary_html() -> str:
    parts = [_CSS, "<h2>Glossary</h2>"]
    for term, definition in TERMS.items():
        parts.append(f"<h3>{html.escape(term)}</h3><p>{html.escape(definition)}</p>")
    return "\n".join(parts)


class HelpView(QTabWidget):
    """Help tab with First Steps, Glossary, Security Boundaries, Troubleshooting."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.addTab(_html_browser(_CSS + _FIRST_STEPS_HTML), "First Steps")
        self.addTab(_html_browser(_build_glossary_html()), "Glossary")
        self.addTab(_html_browser(_CSS + _SECURITY_HTML), "Security Boundaries")
        self.addTab(_html_browser(_CSS + _TROUBLESHOOTING_HTML), "Troubleshooting")


def _html_browser(content: str) -> QTextBrowser:
    browser = QTextBrowser()
    browser.setOpenExternalLinks(False)
    browser.setHtml(content)
    browser.setReadOnly(True)
    _apply_char_tooltips(browser)
    browser.installEventFilter(_CharTooltipFilter(browser))
    return browser
