---
title: Smartcards and YubiKeys
---

# Smartcards and YubiKeys

GPG Meister can use a hardware token — a YubiKey, Nitrokey, or any other OpenPGP
card — in two independent ways:

1. as the holder of a **GPG key**, so decrypting and signing ask for the card PIN
   instead of a key passphrase, and
2. as an extra **unlock method for a vault backup**, alongside the master
   passphrase.

Neither adds a dependency to GPG Meister itself: GnuPG already talks to the card
through `scdaemon`, and GPG Meister drives it the same way it drives every other
GPG operation.

---

## Which tokens work, and what has to be installed

The token needs the **OpenPGP applet**, reached over the card (CCID) interface.
That rules out FIDO-only devices, whatever the packaging suggests:

| Device | Works |
| --- | --- |
| YubiKey 5 series, YubiKey NEO/4 | Yes — OpenPGP applet present |
| Nitrokey, and other OpenPGP cards | Yes |
| **Security Key Series by Yubico** ("YubiKey FIDO", blue) | **No** — FIDO2/U2F only, no OpenPGP applet, no CCID interface |

A FIDO-only key cannot be converted: the applet is absent from the hardware, not
switched off. `lsusb -v` showing a single HID interface, or `ykman info` listing
no `OpenPGP` line, means this device is not usable here.

Two things are needed on the host as well, and on Debian/Ubuntu neither ships
with `gnupg` by default:

```sh
sudo apt install scdaemon pcscd
```

Without `scdaemon` GnuPG reports `No SmartCard daemon` and every token looks
absent. The smartcard panel names the missing package rather than reporting a
bare "no card".

---

## How a card key is unlocked

Every GPG subprocess runs with `--batch --pinentry-mode loopback`, so GnuPG never
spawns an external Pinentry. With loopback pinentry, gpg-agent asks the *calling
process* for the secret it needs — and for a card operation, that secret is the
card PIN. It therefore travels the same audited path as a passphrase:

- typed into the same masked field in the UI,
- moved into a `SecureBytes` buffer on the UI thread,
- written to an app-owned `os.pipe()` and passed as `--passphrase-fd`,
- never present in `argv` (asserted by `reject_passphrase_in_argv`).

Consequence: no code in the encrypt / decrypt / sign paths needed to change for
smartcard support. What changed is that the UI now *knows* when a PIN is what is
being asked for, and says so.

> **PIN attempts are finite.** A card blocks itself after a few wrong PINs
> (typically three). That is why the vault import view sends the PIN verbatim
> instead of Unicode-normalising it the way it normalises passphrases — a
> normalisation that altered the input would burn an attempt.

---

## Which device holds a key

`gpg --list-secret-keys --with-colons` overloads field 15:

| Value | Meaning |
| --- | --- |
| `+` | the secret key is stored on this computer |
| `#` | the secret key is not available here (offline primary, unlearned stub) |
| a serial | the secret key lives on the token with that OpenPGP AID |

`services/gpg_service.py` maps those to `KeyInfo.card_serial` and
`KeyInfo.is_stub`, and `KeyInfo.storage` turns them into a `KeyStorage` value:

- `SMARTCARD` — `YubiKey 12345678` (the label the UI shows)
- `OFFLINE` — "Secret key elsewhere"
- `LOCAL` — "Local"
- `PUBLIC_ONLY` — "Public only"

The token serial only appears in the *secret* listing, so `list_keys()` performs
one cross-reference to carry it into the public listing as well. Because a
typical card layout keeps the primary key offline and only the subkeys on the
token, the parser also attributes a subkey's serial to its primary key.

The AID (`D276000124 0103 0006 12345678 0000`) is decoded in
`models/smartcard.py`: bytes 8–9 are the manufacturer (`0006` = Yubico), bytes
10–13 the printed serial number. That is where the "YubiKey" label comes from —
no device-specific code path exists.

---

## Linking a card into the app's keyring

GPG Meister runs GnuPG against its **own** `--homedir`, isolated from
`~/.gnupg`. A freshly inserted card is therefore unknown to it until GnuPG has
seen it once. The Keys tab has a **Smartcard…** panel that does this:

1. `gpg --card-status --with-colons` reports the card *and* makes GnuPG create
   the secret-key stubs for every card key whose public key is already present.
2. The panel lists the card's three slots and marks each one either "usable in
   GPG Meister" or "public key missing".
3. For a missing one, import the public key (the card usually carries a URL for
   it) and press **Link card keys** again.

`SmartcardService.detect()` deliberately returns `None` rather than raising when
no card is reachable: "no token plugged in" is a normal state for a panel that is
polled on every refresh, not an error.

---

## Managing the card

The smartcard panel also drives the operations that *write* to the card:
changing or unblocking a PIN, moving an existing key onto the card, and
generating a fresh key set on the device.

Those live behind GnuPG's interactive editors (`gpg --card-edit`,
`gpg --edit-key`), which are menu-driven programs rather than one-shot commands.
GPG Meister drives them through `--command-fd`, and the way it does so is the
safety property worth understanding:

- GnuPG announces every prompt on the status stream as
  `GET_LINE`/`GET_BOOL`/`GET_HIDDEN` followed by a **prompt keyword**. Answers are
  keyed by that keyword, never supplied as a positional list of lines.
- A positional script that drifted out of step would answer the *next* question
  with the *previous* answer — and one of the questions is "Replace existing
  keys?". Keyed answers cannot drift.
- A prompt nothing was scripted for gets **no answer at all**: the command pipe
  is closed, GnuPG aborts, and the UI reports which prompt was asked. If a GnuPG
  version words its menus differently, the operation refuses to run rather than
  guessing — run `gpg --card-edit` in a terminal in that case.
- `--batch` is dropped for these runs (GnuPG refuses its editors under it), but
  loopback pinentry is kept, so no external Pinentry is ever spawned and PINs
  still travel an app-owned pipe.

On top of that, destructive actions are gated twice: the service refuses to
touch a slot that already holds a key unless the caller passes an explicit
overwrite flag, and the dialog only passes it after the user has typed
`REPLACE`. Moving a key additionally requires typing `MOVE`, because GnuPG
replaces the on-disk secret key with a stub — after the move the token holds the
only copy.

When generating on the card, GnuPG's off-card backup of the *encryption* key is
enabled by default. Without it, a lost or broken card makes everything encrypted
to it unreadable for good.

## Vaults with a smartcard slot

A vault has always been encrypted with a key derived from the master passphrase
(format version 2). Adding a second unlock method requires the payload key to be
*shared* rather than *derived*, so vaults created with a token get format
version 3:

```
version 2                      version 3
---------                      ---------
key = Argon2id(passphrase)     key = random 32 bytes
                               key_slots:
                                 - passphrase: AEAD(key) under Argon2id(passphrase)
                                 - openpgp:    PGP message with key, addressed to the token
payload = AEAD(manifest, key, aad = header bytes)
```

Properties worth knowing:

- **The master passphrase stays valid by default.** A passphrase slot is written
  unless the user explicitly ticks *Token only*, so losing the token normally
  does not orphan a backup. A token-only vault has no fallback at all: if every
  listed token is lost, the backup is unrecoverable, and the export view says so
  before it lets the tick-box take effect.
- **Slots are tamper-evident.** The whole header — key slots included — is the
  associated data of the payload's AEAD tag, so editing, adding, or removing a
  slot breaks decryption through *any* slot.
- **Passphrase-only vaults are unchanged.** Version 3 is only written when a
  token was selected, and optional header fields are omitted rather than written
  as `null`, so a v2 header serialises to exactly the bytes it did before.
- **Reading a vault's unlock methods needs no credential.** `unlock_info()`
  parses the header alone, which is how the import wizard can offer "Smartcard
  PIN" before anything is typed.

The vault key is wrapped to the card's *public* encryption key, so creating such
a vault does not require the token to be present — only opening it does.

---

## Limits

- The card-management flows are driven by scripted answers to GnuPG's menus and
  have **not** been verified against physical hardware — the prompt keywords come
  from GnuPG's sources, and the protocol layer is covered by tests, but no
  YubiKey has run them end to end. They fail closed (see above) rather than
  guess, and `gpg --card-edit` in a terminal remains the fallback.
- Setting a card's reset code, changing its URL/login attributes, and factory
  resetting a card are not exposed.
- A key on a token cannot be exported into a vault as private key material —
  that is the point of a token. Such keys are backed up as public keys only, and
  the vault views label them accordingly.
- Deleting a card key from the Keys tab removes only the local stub. The key
  stays on the token and can be linked again.

---
[← Back to overview](overview.md)
