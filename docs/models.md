# Domain Models

The models live in `src/gpg_meister/models`.

They define the validated data shapes used across the app.

## Implementation style

`planv2.md` talks about Pydantic dataclasses, but the current code uses immutable Pydantic `BaseModel` classes with `ConfigDict(frozen=True)` in the main models.

This provides the same practical benefits:

- runtime validation
- strict structure
- safe serialization
- reduced accidental mutation

## Key models

### `key_info.py`

`KeyInfo` is the main key record used by the UI and services.

It contains:

- fingerprint
- user IDs
- algorithm
- key length
- creation and expiry time
- revoked state
- private key availability
- trust level
- user context fields: `label`, `purpose`, `platform`, `notes`

The context fields are not part of GPG itself. They come from the local SQLite metadata store.

### `message.py`

This file defines result objects for:

- encryption
- decryption
- signing
- verification

These models keep the service API simple and stable for the UI layer.

### `vault.py`

This file defines the vault structure:

- `CipherAlgorithm`
- `CipherParams`
- `KDFFields`
- `VaultHeader`
- `VaultKeyEntry`
- `VaultManifest`

The split is important:

- the header is unencrypted but authenticated
- the manifest is encrypted and contains the actual key material

The models also defend against unsafe input:

- base64 fields are validated
- nonce length is checked
- KDF values are bounded
- fingerprints are normalized and validated

### `config.py`

`AppConfig` stores non-secret application settings like:

- locale
- selected cipher
- KDF profile
- clipboard timeout
- accessibility options
- trusted GPG binary pin
- audit settings

Passphrases are not part of this model.

## Trust Boundary

The project uses the models as a trust boundary.

If raw data comes from:

- GPG output
- TOML config
- vault files
- user input

it should become a validated model before the rest of the app depends on it.
