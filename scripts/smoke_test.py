#!/usr/bin/env python3
"""End-to-end smoke test for GPG-Meister.

Exercises every public service function against a real ``gpg`` binary inside a
**fully isolated** throwaway home directory. The test never reads or writes the
real user environment: it uses its own ``GNUPGHOME``, its own audit log,
metadata DB and vault file, all under a single ``mkdtemp`` directory.

Safety (this is a test fixture, not a cleanup tool):

  * Nothing is created outside the per-run tempdir, so nothing the test does can
    surface in the user's GUI (the real ~/.gnupg, ~/.local/share/gpg-meister,
    ~/.config/gpg-meister are never targeted).
  * Before tearing down, the test snapshots those user-space directories
    *before* and *after* the run and asserts a zero diff — proof that no user
    file was added, modified or removed.
  * Cleanup deletes ONLY the run's own tempdir, and ``_safe_rmtree`` refuses to
    remove anything that is not a non-symlink directory directly under the
    system temp dir carrying this script's prefix. It can never be pointed at
    user data.

Run with:    uv run python scripts/smoke_test.py
"""
from __future__ import annotations

import contextlib
import hashlib
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams  # noqa: E402
from gpg_meister.models.key_info import KeyAlgorithm  # noqa: E402
from gpg_meister.models.message import SignatureStatus  # noqa: E402
from gpg_meister.models.vault import CipherAlgorithm  # noqa: E402
from gpg_meister.security.secure_bytes import SecureBytes  # noqa: E402
from gpg_meister.services.errors import GPGPassphraseError  # noqa: E402
from gpg_meister.services.gpg_service import (  # noqa: E402
    GPGService,
    GPGServiceConfig,
)
from gpg_meister.services.vault_service import VaultService  # noqa: E402
from gpg_meister.storage.audit_log import AuditLog  # noqa: E402
from gpg_meister.storage.metadata_store import MetadataStore  # noqa: E402

PASSPHRASE = b"smoke-test-passphrase-correct-horse"
WRONG_PASSPHRASE = b"this-is-the-wrong-passphrase"
MASTER_PASSPHRASE = b"smoke-vault-master-correct-horse"
USER_NAME = "Smoke Tester"
USER_EMAIL = "smoke@example.invalid"
TEMP_PREFIX = "gpgmeister-smoke-"

# Directories that belong to the *real* user. The test must never write here;
# we snapshot them before/after to prove it.
USER_DIRS = [
    Path.home() / ".gnupg",
    Path.home() / ".local" / "share" / "gpg-meister",
    Path.home() / ".config" / "gpg-meister",
    Path.home() / ".cache" / "gpg-meister",
]


# ----------------------------------------------------------------------- helpers


class Reporter:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def step(self, name: str) -> None:
        print(f"  → {name} ... ", end="", flush=True)

    def ok(self, detail: str = "") -> None:
        self.passed += 1
        print(f"ok {detail}".rstrip())

    def fail(self, detail: str) -> None:
        self.failed += 1
        print(f"FAIL: {detail}")


def _snapshot(paths: Iterable[Path]) -> dict[str, str]:
    """Hash every regular file under each path so we can diff after the run."""
    snap: dict[str, str] = {}
    for root in paths:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file():
                try:
                    snap[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
                except OSError:
                    snap[str(p)] = "<unreadable>"
    return snap


def _diff_snapshots(before: dict[str, str], after: dict[str, str]) -> list[str]:
    diffs: list[str] = []
    for path, digest in after.items():
        if path not in before:
            diffs.append(f"+ {path}")
        elif before[path] != digest:
            diffs.append(f"M {path}")
    for path in before:
        if path not in after:
            diffs.append(f"- {path}")
    return diffs


def _fast_kdf_params() -> KDFParams:
    """Smallest legal Argon2id params, to keep the smoke under a few seconds."""
    return KDFParams(
        algorithm=KDFAlgorithm.ARGON2ID,
        time_cost=2,
        memory_cost=19_456,
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )


def _kill_agents(gpg_bin: str, homes: Iterable[Path]) -> None:
    """Stop any gpg-agent the test started in its isolated homes.

    Operates only on the test's own temp homedirs, never the user's. Failures
    are ignored — a stray agent pointed at a soon-to-be-deleted dir is harmless.
    """
    gpgconf = shutil.which("gpgconf") or str(Path(gpg_bin).with_name("gpgconf"))
    if not Path(gpgconf).exists():
        return
    for home in homes:
        with contextlib.suppress(Exception):
            subprocess.run(  # noqa: S603 — fixed argv, resolved gpgconf, temp homedir
                [gpgconf, "--homedir", str(home), "--kill", "all"],
                capture_output=True,
                timeout=15,
            )


def _reset_agent_cache(gpg_bin: str, home: Path) -> None:
    """Drop the gpg-agent's cached secret keys for one isolated home.

    Without this, the agent caches the unlocked private key from an earlier
    correct-passphrase operation, so a subsequent decrypt never consults the
    passphrase at all — which would make the wrong-passphrase negative check
    pass vacuously. Killing the agent forces a fresh loopback unlock.
    """
    gpgconf = shutil.which("gpgconf") or str(Path(gpg_bin).with_name("gpgconf"))
    if not Path(gpgconf).exists():
        return
    with contextlib.suppress(Exception):
        subprocess.run(  # noqa: S603 — fixed argv, resolved gpgconf, temp homedir
            [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
            capture_output=True,
            timeout=15,
        )


def _safe_rmtree(root: Path) -> None:
    """Delete ONLY the run's own tempdir.

    Defense-in-depth so a future edit can never turn this into a tool that
    removes user data: refuse anything that is not a non-symlink directory
    directly beneath the system temp dir carrying our prefix.
    """
    resolved = root.resolve()
    sys_tmp = Path(tempfile.gettempdir()).resolve()
    if resolved.is_symlink():
        raise RuntimeError(f"refusing to delete symlink: {resolved}")
    if resolved.parent != sys_tmp:
        raise RuntimeError(f"refusing to delete {resolved}: not directly under {sys_tmp}")
    if not resolved.name.startswith(TEMP_PREFIX):
        raise RuntimeError(f"refusing to delete {resolved}: unexpected name")
    shutil.rmtree(resolved, ignore_errors=True)


# --------------------------------------------------------------------- the suite


def run() -> int:
    rep = Reporter()
    print("== GPG-Meister smoke test ==")

    gpg_bin = shutil.which("gpg")
    if not gpg_bin:
        print("FAIL: no `gpg` binary on PATH")
        return 2
    print(f"  gpg binary: {gpg_bin}")

    user_snapshot_before = _snapshot(USER_DIRS)
    print(f"  user-space snapshot: {len(user_snapshot_before)} files")

    root = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    print(f"  tempdir: {root}")
    gpg_home = root / "gnupg"
    gpg_home2 = root / "gnupg-import"
    try:
        gpg_home.mkdir(mode=0o700)
        vault_path = root / "smoke.gpgvault"
        audit_path = root / "audit.log"
        metadata_path = root / "metadata.sqlite"

        gpg = GPGService(GPGServiceConfig(binary_path=Path(gpg_bin), home_dir=gpg_home))

        # ---- version
        rep.step("gpg.version")
        try:
            ver = gpg.version()
            assert ver and ver[0] >= 2
            rep.ok(str(ver))
        except Exception as exc:
            rep.fail(repr(exc))
            return rep_done(rep)

        # ---- generate two keys (RSA + EdDSA) so we have multi-recipient paths
        fps: list[str] = []
        for algo, length in ((KeyAlgorithm.RSA, 2048), (KeyAlgorithm.EDDSA, 255)):
            rep.step(f"gpg.generate_key {algo.name}")
            try:
                with SecureBytes.from_bytes(PASSPHRASE) as pw:
                    fp = gpg.generate_key(
                        name=f"{USER_NAME} {algo.name}",
                        email=f"{algo.name.lower()}-{USER_EMAIL}",
                        algorithm=algo,
                        length=length,
                        expiry="1d",
                        passphrase=pw,
                    )
                assert len(fp) == 40
                fps.append(fp)
                rep.ok(fp[:16] + "…")
            except Exception as exc:
                rep.fail(repr(exc))
                return rep_done(rep)

        primary_fp = fps[0]

        # `--quick-generate-key rsa2048 default` produces only [SC] caps; add an
        # encryption subkey so encrypt() has something usable.
        rep.step("add encryption subkey to RSA primary")
        try:
            subprocess.run(  # noqa: S603 — fixed argv, gpg_bin is the resolved trusted binary
                [
                    gpg_bin,
                    "--homedir",
                    str(gpg_home),
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    PASSPHRASE.decode("utf-8"),
                    "--quick-add-key",
                    primary_fp,
                    "rsa2048",
                    "encr",
                    "1d",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            rep.ok()
        except Exception as exc:
            rep.fail(repr(exc))
            return rep_done(rep)

        # ---- list_keys
        rep.step("gpg.list_keys(secret=True)")
        try:
            keys = gpg.list_keys(secret=True)
            assert {k.fingerprint for k in keys} >= set(fps)
            rep.ok(f"{len(keys)} secret keys")
        except Exception as exc:
            rep.fail(repr(exc))

        rep.step("gpg.list_keys(secret=False)")
        try:
            pubkeys = gpg.list_keys(secret=False)
            assert {k.fingerprint for k in pubkeys} >= set(fps)
            rep.ok(f"{len(pubkeys)} public keys")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- find_key
        rep.step("gpg.find_key")
        try:
            info = gpg.find_key(primary_fp)
            assert info.fingerprint == primary_fp
            rep.ok()
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- export public + private
        pub_armor = ""
        rep.step("gpg.export_public_key")
        try:
            pub_armor = gpg.export_public_key(primary_fp)
            assert "BEGIN PGP PUBLIC KEY BLOCK" in pub_armor
            rep.ok(f"{len(pub_armor)} bytes")
        except Exception as exc:
            rep.fail(repr(exc))

        rep.step("gpg.export_private_key")
        try:
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                priv_armor = gpg.export_private_key(primary_fp, pw)
            assert "BEGIN PGP PRIVATE KEY BLOCK" in priv_armor
            rep.ok(f"{len(priv_armor)} bytes")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- scan_keys (parse an armored blob without importing)
        rep.step("gpg.scan_keys")
        try:
            scanned = gpg.scan_keys(pub_armor)
            assert any(row.get("fingerprint") == primary_fp for row in scanned)
            rep.ok(f"{len(scanned)} entries")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- import_key into a fresh keyring (public key round-trip)
        gpg_home2.mkdir(mode=0o700)
        gpg2 = GPGService(GPGServiceConfig(binary_path=Path(gpg_bin), home_dir=gpg_home2))
        rep.step("gpg.import_key (public armor → fresh keyring)")
        try:
            imported_fps = gpg2.import_key(pub_armor)
            assert primary_fp in imported_fps, f"imported={imported_fps}"
            assert {k.fingerprint for k in gpg2.list_keys(secret=False)} >= {primary_fp}
            rep.ok(f"imported {len(imported_fps)}")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- encrypt → decrypt round trip WITHOUT a signature
        rep.step("gpg.encrypt → decrypt (unsigned → SignatureStatus.NONE)")
        try:
            msg = b"the quick brown fox jumps over the lazy dog\n"
            # EdDSA keys from --quick-generate-key are sign-only, so encrypt only
            # to the RSA recipient (which now has an encryption subkey).
            ct = gpg.encrypt(msg, recipient_fingerprints=[primary_fp], always_trust=True)
            assert "BEGIN PGP MESSAGE" in ct
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                pt, signer, status, decrypted_with = gpg.decrypt(
                    ct.encode("utf-8"), passphrase=pw
                )
            assert pt == msg, "plaintext mismatch"
            assert signer is None, f"unexpected signer {signer}"
            assert status is SignatureStatus.NONE, f"expected NONE, got {status}"
            assert decrypted_with and len(decrypted_with) == 40, (
                f"unexpected decryption key {decrypted_with}"
            )
            assert not status.is_valid
            rep.ok(f"{len(ct)} → {len(pt)} bytes; status={status}")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- decrypt with the WRONG passphrase must be rejected
        rep.step("gpg.decrypt(wrong passphrase) → GPGPassphraseError")
        try:
            ct_bad = gpg.encrypt(b"secret", recipient_fingerprints=[primary_fp], always_trust=True)
            # Force a fresh unlock so the wrong passphrase is actually exercised
            # (the agent has the key cached from the round-trips above).
            _reset_agent_cache(gpg_bin, gpg_home)
            try:
                with SecureBytes.from_bytes(WRONG_PASSPHRASE) as bad:
                    gpg.decrypt(ct_bad.encode("utf-8"), passphrase=bad)
                rep.fail("decrypt accepted the wrong passphrase")
            except GPGPassphraseError:
                rep.ok("rejected as expected")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- signed encryption round trip WITH a signature
        rep.step("gpg.encrypt(sign_with=…) → decrypt verifies signer (VALID)")
        try:
            msg = b"signed-and-encrypted payload"
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                ct = gpg.encrypt(
                    msg,
                    recipient_fingerprints=[primary_fp],
                    sign_with=primary_fp,
                    passphrase=pw,
                    always_trust=True,
                )
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                pt, signer, status, decrypted_with = gpg.decrypt(
                    ct.encode("utf-8"), passphrase=pw
                )
            assert pt == msg, "plaintext mismatch"
            assert status is SignatureStatus.VALID, f"expected VALID, got {status}"
            assert status.is_valid
            assert signer == primary_fp, f"unexpected signer {signer}"
            assert decrypted_with and len(decrypted_with) == 40, (
                f"unexpected decryption key {decrypted_with}"
            )
            rep.ok(f"signer={signer[:16]}…; status={status}")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- detached sign + verify (valid, then tampered)
        rep.step("gpg.sign(detached) → verify VALID, tampered → not valid")
        try:
            payload = b"detached-signature-payload"
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                sig = gpg.sign(payload, fingerprint=primary_fp, passphrase=pw, detached=True)
            status, signer, _ = gpg.verify(payload, detached_signature=sig.encode("utf-8"))
            assert status.is_valid, f"expected VALID, got {status}"
            assert signer == primary_fp, f"unexpected signer {signer}"
            # Negative: same signature, mutated payload → must NOT be valid.
            bad_status, _, _ = gpg.verify(
                payload + b"-tampered", detached_signature=sig.encode("utf-8")
            )
            assert not bad_status.is_valid, f"tampered payload reported {bad_status}"
            rep.ok(f"valid signer={signer[:16]}…; tampered={bad_status}")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- clearsign + verify (inline, valid then tampered)
        rep.step("gpg.sign(clearsign) → verify VALID, tampered → not valid")
        try:
            payload = b"clearsigned-payload\n"
            with SecureBytes.from_bytes(PASSPHRASE) as pw:
                clear = gpg.sign(payload, fingerprint=primary_fp, passphrase=pw, detached=False)
            status, signer, _ = gpg.verify(clear.encode("utf-8"))
            assert status.is_valid, f"expected VALID, got {status}"
            assert signer == primary_fp, f"unexpected signer {signer}"
            # Negative: corrupt a byte inside the signed text region.
            tampered = clear.replace("clearsigned-payload", "clearsigned-PAYLOAD", 1)
            if tampered != clear:
                bad_status, _, _ = gpg.verify(tampered.encode("utf-8"))
                assert not bad_status.is_valid, f"tampered clearsign reported {bad_status}"
                rep.ok(f"valid signer={signer[:16]}…; tampered={bad_status}")
            else:
                rep.ok(f"valid signer={signer[:16]}… (tamper-case skipped)")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- vault: create → preview → import into a brand-new GPG home
        rep.step("VaultService.create")
        audit = AuditLog(audit_path)
        metadata = MetadataStore(metadata_path)
        vault_svc = VaultService(gpg=gpg, audit=audit, metadata=metadata)
        try:
            with SecureBytes.from_bytes(MASTER_PASSPHRASE) as master:
                gpg_pws = {fp: SecureBytes.from_bytes(PASSPHRASE) for fp in fps}
                try:
                    descriptor = vault_svc.create(
                        target_path=vault_path,
                        master_passphrase=master,
                        gpg_passphrases=gpg_pws,
                        fingerprints=fps,
                        description="smoke test vault",
                        cipher=CipherAlgorithm.CHACHA20_POLY1305,
                        kdf_params=_fast_kdf_params(),
                    )
                finally:
                    for sb in gpg_pws.values():
                        sb.close()
            assert vault_path.exists()
            rep.ok(
                f"{vault_path.stat().st_size} bytes; "
                f"keys={descriptor.key_count}; sha256={descriptor.sha256[:12]}…"
            )
        except Exception as exc:
            rep.fail(repr(exc))

        rep.step("VaultService.preview")
        try:
            with SecureBytes.from_bytes(MASTER_PASSPHRASE) as master:
                preview = vault_svc.preview(source_path=vault_path, master_passphrase=master)
            assert {e.fingerprint for e in preview.keys} == set(fps)
            rep.ok(f"{len(preview.keys)} entries; created_at={preview.created_at.isoformat()}")
        except Exception as exc:
            rep.fail(repr(exc))

        # ---- import vaulted secret keys into the second isolated GPG home
        rep.step("VaultService.import_keys into fresh keyring")
        vault_svc2 = VaultService(gpg=gpg2, audit=audit, metadata=metadata)
        try:
            with SecureBytes.from_bytes(MASTER_PASSPHRASE) as master:
                imported = vault_svc2.import_keys(source_path=vault_path, master_passphrase=master)
            assert set(imported) == set(fps), f"imported={imported}"
            after_list = {k.fingerprint for k in gpg2.list_keys(secret=True)}
            assert after_list >= set(fps)
            rep.ok(f"imported {len(imported)} keys")
        except Exception as exc:
            rep.fail(repr(exc))

        metadata.close()

        # ---- delete keys from both keyrings
        for label, svc, fingerprints in (("primary", gpg, fps), ("import", gpg2, list(fps))):
            for fp in fingerprints:
                rep.step(f"gpg.delete_key({label}, {fp[:8]}…)")
                try:
                    svc.delete_key(fp, including_secret=True)
                    rep.ok()
                except Exception as exc:
                    rep.fail(repr(exc))

        # final assertion: nothing was written outside the tempdir
        rep.step("user-space directories untouched")
        user_snapshot_after = _snapshot(USER_DIRS)
        diffs = _diff_snapshots(user_snapshot_before, user_snapshot_after)
        if diffs:
            rep.fail(f"{len(diffs)} unexpected user-space changes: {diffs[:5]}")
        else:
            rep.ok("no diffs")

    finally:
        # Stop the isolated agents, then wipe ONLY our own tempdir, even on early
        # exit. _safe_rmtree refuses to delete anything outside the system temp.
        _kill_agents(gpg_bin, [gpg_home, gpg_home2])
        try:
            _safe_rmtree(root)
        except RuntimeError as exc:
            print(f"  WARNING: cleanup refused: {exc}")
        if root.exists():
            print(f"  WARNING: tempdir still exists at {root}")
        else:
            print(f"  tempdir removed: {root}")

    return rep_done(rep)


def rep_done(rep: Reporter) -> int:
    total = rep.passed + rep.failed
    print(f"== {rep.passed}/{total} steps passed, {rep.failed} failed ==")
    return 0 if rep.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
