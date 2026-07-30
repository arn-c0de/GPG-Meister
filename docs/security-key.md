---
title: Security keys (FIDO2)
---

# Security keys (FIDO2)

A FIDO2 security key — a Yubico Security Key, a YubiKey 5, or any authenticator
supporting the `hmac-secret` extension — can take the place of a key passphrase.
You enter the token's PIN, touch it, and the key opens.

This is **not** the same feature as [Smartcards and YubiKeys](smartcard.md), and
the difference decides which one you can use:

| | Smartcard (OpenPGP) | Security key (FIDO2) |
| --- | --- | --- |
| Where the private key lives | On the card; it never leaves | On this computer, encrypted |
| Needs the OpenPGP applet | Yes | No |
| Works with FIDO-only tokens | No | **Yes** |
| Host packages needed | `scdaemon`, `pcscd` | none |
| What it costs an attacker with your files | The card itself | The token, plus its PIN |

If your token has the OpenPGP applet, prefer the smartcard route: a key that
never leaves the hardware is strictly stronger. This page is for the tokens that
cannot do that — which is most of the cheap ones.

---

## How it works

A GPG key has exactly one passphrase, so the token cannot simply *be* the
passphrase — enrolling a second token, or keeping an emergency way in, would
each mean rewriting the key. Instead the passphrase is a random secret, stored
once per unlock method:

```
passphrase = 32 random bytes, base64 (44 characters)

unlock slots, in metadata.sqlite3:
  fido       : AEAD(passphrase) under the 32 bytes the token derives
  passphrase : AEAD(passphrase) under Argon2id(your emergency passphrase)
```

Both slots yield the same passphrase, so adding or removing an unlock method
never touches the key itself. It is the same construction version 3 vaults use
for their file key.

The token's 32 bytes come from the WebAuthn `prf` extension (CTAP2
`hmac-secret` underneath): the same credential and the same salt return the same
bytes forever, and nothing outside the token can reproduce them.

> **`prf`, not raw `hmac-secret`.** They are one authenticator feature, but the
> `prf` layer hashes the salt before passing it down, so the two produce
> different outputs from the same token. Every enrolled credential depends on
> this choice, so it is fixed and cannot be revisited.

Once the passphrase is recovered it travels the path every other passphrase in
this application takes: a `SecureBytes` buffer, an app-owned pipe,
`--passphrase-fd`, never `argv`. No code in the encrypt, decrypt, or sign paths
changed for this feature.

---

## Setting it up

1. **Set a FIDO2 PIN on the token**, if it has none. GPG Meister requires user
   verification, so a PIN-less token is refused at enrolment rather than
   silently enrolled with a weaker guarantee.

   > A FIDO2 PIN can only be removed by resetting the token's FIDO application,
   > which erases every credential on it — including website logins.

2. **Create a key** with *Unlock this key with a security key* ticked. Enrolment
   asks for two touches: one to create the credential, one to prove it derives.

3. **Decide about the emergency passphrase.** It is on by default. Ticking *No
   emergency passphrase* produces a key only that token can ever open — the
   dialog says so in red, because it is true and irreversible.

Credentials are stored **on the token** (a discoverable credential), so the token
can find them again even if this computer's database is lost. The PRF salt still
lives in `metadata.sqlite3`, so back that file up along with your keys.

---

## Unlocking

The Decrypt tab grows a **Decrypt with security key…** button as soon as any key
in the keyring is enrolled. It asks for the PIN, waits for a touch, and decrypts.

Touching blocks for up to about thirty seconds. That work runs on a background
thread, so the window stays responsive; a token that is never touched reports
`OPERATION_DENIED`, which GPG Meister translates to "the token was not touched
in time" rather than a device error.

A wrong PIN, a blocked PIN, and a missed touch stop the attempt immediately
instead of trying the next enrolled token: each retry would spend another of the
few PIN attempts the token allows before locking itself.

---

## What this does not protect against

Stated plainly, because the comparison with a smartcard matters:

- **The private key is on disk.** It is encrypted, and the token holds the only
  copy of what decrypts it — but malware running as you can capture the
  passphrase at the moment you touch the token, and with it the key. An OpenPGP
  card would have handed out one signature instead.
- **The FIDO PIN briefly exists as a Python string.** `python-fido2` takes it as
  `str`, and Python strings cannot be wiped. Everything else in this application
  keeps secrets in `SecureBytes`; this is a documented, deliberate narrowing,
  limited to the FIDO PIN.
- **Losing the token is losing the key**, unless an emergency passphrase slot
  exists. No backup of this computer helps: the passphrase was never anywhere
  else.

---

## Requirements

Only `fido2`, which GPG Meister installs. No `scdaemon`, no `pcscd`, no card
reader.

On Linux the token is reached through `/dev/hidraw*`, which needs the FIDO udev
rules — usually shipped by the `libfido2` package. Without them the token is
present but unreadable; GPG Meister says so and names the rules, rather than
reporting "no token found".
