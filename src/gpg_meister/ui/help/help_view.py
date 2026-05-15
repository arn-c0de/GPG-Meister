"""Help tab view (planv2.md §14.5)."""

from __future__ import annotations

import html

from PySide6.QtWidgets import QTabWidget, QTextBrowser, QWidget

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


def _build_glossary_html() -> str:
    parts = ["<h2>Glossary</h2>"]
    for term, definition in TERMS.items():
        parts.append(f"<h3>{html.escape(term)}</h3><p>{html.escape(definition)}</p>")
    return "\n".join(parts)


class HelpView(QTabWidget):
    """Help tab with First Steps, Glossary, Security Boundaries, Troubleshooting."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.addTab(_html_browser(_FIRST_STEPS_HTML), "First Steps")
        self.addTab(_html_browser(_build_glossary_html()), "Glossary")
        self.addTab(_html_browser(_SECURITY_HTML), "Security Boundaries")
        self.addTab(_html_browser(_TROUBLESHOOTING_HTML), "Troubleshooting")


def _html_browser(html: str) -> QTextBrowser:
    browser = QTextBrowser()
    browser.setOpenExternalLinks(False)
    browser.setHtml(html)
    browser.setReadOnly(True)
    return browser
