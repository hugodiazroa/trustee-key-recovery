#!/usr/bin/env python3
"""
Key recovery through trusted contacts (PGP-based) -- simulation.

A user protects an encrypted backup with a master key. Three trusted contacts
each receive one PGP-encrypted "package"; any two of them can help the user
rebuild the master key on a new device, no single one can.

Every cryptographic operation is done by real GnuPG (the `gpg` binary). Each
actor (the user's old device, the new device, every contact, the attacker,
and every throw-away "scratch" keyring) gets its own isolated GnuPG home
directory, so keys only exist where the protocol puts them.

Requirements: GnuPG >= 2.2.8 in PATH. Only the Python standard library.

Usage:
    python3 PGP.py                      # run everything
    python3 PGP.py --scenario recovery  # setup + normal recovery only
    python3 PGP.py --scenario adv1|adv2|adv3

Layout of the protocol (see the task statement):
    C_A = Enc_K1( Enc_{K2,K3}(mk) )      C_B = Enc_K2( Enc_K3(mk) )
    Package A -> P_A : K1, C_A, backup ID, index 1
    Package B -> P_B : K2, C_B, backup ID, index 2
    Package C -> P_C : K3,      backup ID, index 3
    Pairs:  A+B: C_A with K1 then K2 | A+C: C_A with K1 then K3 | B+C: C_B with K2 then K3
"""
from __future__ import annotations

import argparse
import atexit
import base64
import hashlib
import hmac
import itertools
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Output helpers and expectation tracking
# --------------------------------------------------------------------------- #

WIDTH = 78
BRIEF = False  # --brief: shorten long blocks (keys, ciphertexts) to a few lines


def banner(title: str) -> None:
    print("\n\n" + "#" * WIDTH)
    print(f"#  {title}")
    print("#" * WIDTH)


def step(msg: str) -> None:
    print(f"\n\n{msg}\n" + "=" * min(len(msg), WIDTH))


def substep(msg: str) -> None:
    print(f"\n  {msg}\n  " + "-" * min(len(msg), WIDTH - 2))


def info(msg: str, depth: int = 1) -> None:
    print("   " * depth + msg)


def block(label: str, text: str, depth: int = 1, note: str = "") -> None:
    """Print a multi-line value (key, ciphertext, plaintext) inside a frame."""
    pad = "   " * depth
    room = WIDTH - len(pad) - 2
    lines = [l[i:i + room] for l in text.rstrip("\n").splitlines() for i in range(0, max(len(l), 1), room)]
    lines = lines or [""]
    if BRIEF and len(lines) > 7:
        lines = lines[:4] + [f"... {len(lines) - 6} more lines (run without --brief to see all) ..."] + lines[-2:]
    width = min(max(len(l) for l in lines) + 2, WIDTH - len(pad) - 1)
    print()
    print(f"{pad}{label}" + (f"  [{note}]" if note else ""))
    print(f"{pad}+" + "-" * width)
    for l in lines:
        print(f"{pad}| {l}")
    print(f"{pad}+" + "-" * width)


def wrap(text: str, n: int = 64) -> str:
    return "\n".join(text[i:i + n] for i in range(0, len(text), n))


def show_bytes(label: str, data: bytes, depth: int = 1) -> None:
    """Binary data (OpenPGP messages, keys) shown as wrapped base64."""
    block(label, wrap(b64(data)), depth, f"{len(data)} bytes, base64")


def show_text(label: str, data: bytes | str, depth: int = 1) -> None:
    text = data.decode(errors="replace") if isinstance(data, bytes) else data
    block(label, text, depth)


def show_package(label: str, pkg: dict, depth: int = 1) -> None:
    """A plaintext recovery package, one field per line."""
    ct = pkg.get("ciphertext")
    lines = [
        f"backup_id    : {pkg.get('backup_id')}",
        f"index        : {pkg.get('index')}",
    ]
    if ct is None:
        lines.append("ciphertext   : (none)")
    else:
        lines.append(f"ciphertext   : ({len(b64d(ct))} bytes, base64)")
        lines += ["  " + l for l in wrap(ct).splitlines()]
    lines.append("recovery_key :")
    lines += ["  " + l for l in str(pkg.get("recovery_key")).splitlines()]
    block(label, "\n".join(lines), depth)


def ok(msg: str, depth: int = 1) -> None:
    info(f"[ OK ] {msg}", depth)


def bad(msg: str, depth: int = 1) -> None:
    info(f"[FAIL] {msg}", depth)


def rejected(msg: str, depth: int = 1) -> None:
    info(f"[REJECTED] {msg}", depth)


def short_fpr(fpr: str) -> str:
    return " ".join(fpr[i:i + 4] for i in range(0, len(fpr), 4))


CHECKS: list[tuple[str, bool]] = []


def expect(description: str, condition: bool) -> None:
    """Record a property the simulation is supposed to demonstrate."""
    CHECKS.append((description, bool(condition)))
    marker = "CHECK PASSED" if condition else "CHECK FAILED"
    print(f"\n   >> {marker}: {description}")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def same_fpr(a: str, b: str) -> bool:
    norm = lambda s: s.replace(" ", "").upper().encode("utf-8")
    return hmac.compare_digest(norm(a), norm(b))


# --------------------------------------------------------------------------- #
# GnuPG wrapper: one isolated keyring per actor
# --------------------------------------------------------------------------- #

class GPGError(RuntimeError):
    pass


def write_passphrase_file(home: str, secret: bytes) -> str:
    """Write `secret` to a new file only the current user can read; return its path."""
    path = os.path.join(home, f"passphrase-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as fh:
        fh.write(secret)
    return path


def remove_tree(path: str) -> None:
    """Delete a directory. On Windows a gpg-agent that was just told to stop can
    hold a file open for a moment, so retry for up to two seconds."""
    for _ in range(20):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path):
            return
        time.sleep(0.1)


class Keyring:
    """An isolated GnuPG home directory (a "device" or a scratch keyring)."""

    _live: list["Keyring"] = []

    def __init__(self, label: str):
        self.label = label
        self.home: Optional[str] = tempfile.mkdtemp(prefix="tkr-gpg-")  # mode 0700
        self.last_status: list[str] = []
        Keyring._live.append(self)

    # -- low level ---------------------------------------------------------- #
    def _gpg(self, *args: str, data: bytes = b"", pass_fds: tuple[int, ...] = ()) -> bytes:
        if self.home is None:
            raise GPGError(f"keyring '{self.label}' was destroyed")
        cmd = [
            "gpg", "--homedir", self.home, "--batch", "--yes", "--no-tty", "--quiet",
            "--pinentry-mode", "loopback", "--no-symkey-cache",
            # Fingerprints are verified out of band by the protocol itself, so we
            # tell gpg not to apply its own web-of-trust model.
            "--trust-model", "always",
            "--status-fd", "2",
            *args,
        ]
        proc = subprocess.run(cmd, input=data, capture_output=True, pass_fds=pass_fds)
        err = proc.stderr.decode(errors="replace").splitlines()
        self.last_status = [l[len("[GNUPG:] "):] for l in err if l.startswith("[GNUPG:] ")]
        if proc.returncode != 0:
            msgs = [l.removeprefix("gpg: ") for l in err if l and not l.startswith("[GNUPG:]")]
            raise GPGError("; ".join(msgs) or f"gpg exited with {proc.returncode}")
        return proc.stdout

    def _with_passphrase(self, key: bytes, *args: str, data: bytes) -> bytes:
        # Hand the secret to gpg through a pipe or a private file, never on the
        # command line.
        secret = key.hex().encode()
        if os.name == "nt":
            # Python can't pass a pipe to a child process on Windows, so the
            # passphrase goes in a file inside this keyring's private home,
            # deleted as soon as gpg has read it.
            path = write_passphrase_file(self.home, secret)
            try:
                return self._gpg("--passphrase-file", path, *args, data=data)
            finally:
                os.remove(path)
        r, w = os.pipe()
        os.write(w, secret)
        os.close(w)
        try:
            return self._gpg("--passphrase-fd", str(r), *args, data=data, pass_fds=(r,))
        finally:
            os.close(r)

    # -- key management ----------------------------------------------------- #
    def generate(self, uid: str) -> str:
        """Create an unprotected ed25519/cv25519 key pair; return its fingerprint."""
        self._gpg("--passphrase", "", "--quick-gen-key", uid, "future-default", "default", "never")
        for s in self.last_status:
            if s.startswith("KEY_CREATED"):
                return s.split()[2]
        raise GPGError("key generation did not report a fingerprint")

    def import_key(self, key: bytes | str) -> list[str]:
        data = key.encode() if isinstance(key, str) else key
        self._gpg("--import", data=data)
        return sorted({s.split()[2] for s in self.last_status if s.startswith("IMPORT_OK")})

    def fingerprint_of(self, pubkey: bytes | str) -> str:
        """Fingerprint of a public key block, without importing it."""
        data = pubkey.encode() if isinstance(pubkey, str) else pubkey
        out = self._gpg("--with-colons", "--show-keys", data=data).decode()
        for line in out.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
        raise GPGError("no key found in the given data")

    def export_public(self, fpr: str) -> bytes:
        return self._gpg("--armor", "--export", fpr)

    def export_secret(self, fpr: str) -> bytes:
        return self._gpg("--armor", "--export-secret-keys", fpr)

    def delete_key(self, fpr: str) -> None:
        self._gpg("--delete-secret-and-public-key", fpr)

    def list_secret(self) -> list[str]:
        out = self._gpg("--with-colons", "--list-secret-keys").decode()
        fprs, want = [], False
        for line in out.splitlines():
            if line.startswith("sec:"):
                want = True
            elif line.startswith("fpr:") and want:
                fprs.append(line.split(":")[9])
                want = False
        return fprs

    # -- crypto --------------------------------------------------------------- #
    def encrypt(self, data: bytes, recipients: list[str]) -> bytes:
        """Public-key encryption (SEIPD with MDC = authenticated) to all recipients."""
        args: list[str] = []
        for r in recipients:
            args += ["--recipient", r]
        return self._gpg("--encrypt", *args, data=data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt with whatever private key this keyring holds. Raises on any
        failure, including a failed integrity (MDC) check."""
        return self._gpg("--decrypt", data=data)

    def sym_encrypt(self, data: bytes, key: bytes) -> bytes:
        return self._with_passphrase(key, "--symmetric", "--cipher-algo", "AES256",
                                     "--s2k-digest-algo", "SHA512", data=data)

    def sym_decrypt(self, data: bytes, key: bytes) -> bytes:
        return self._with_passphrase(key, "--decrypt", data=data)

    # -- lifecycle ------------------------------------------------------------ #
    def destroy(self) -> None:
        """Wipe the keyring (models deleting keys / losing a device)."""
        if self.home and os.path.isdir(self.home):
            subprocess.run(["gpgconf", "--homedir", self.home, "--kill", "all"], capture_output=True)
            subprocess.run(["gpgconf", "--homedir", self.home, "--remove-socketdir"], capture_output=True)
            remove_tree(self.home)
        self.home = None
        if self in Keyring._live:
            Keyring._live.remove(self)

    @classmethod
    def destroy_all(cls) -> None:
        for kr in list(cls._live):
            kr.destroy()


atexit.register(Keyring.destroy_all)


@contextmanager
def scratch_keyring(label: str):
    kr = Keyring(label)
    try:
        yield kr
    finally:
        kr.destroy()


def peel_layer(ciphertext: bytes, secret_key: str, label: str = "peel") -> bytes:
    """Remove ONE encryption layer using ONLY the given private key, inside a
    fresh keyring that is wiped right after."""
    with scratch_keyring(label) as kr:
        kr.import_key(secret_key)
        if not kr.list_secret():
            raise GPGError("the package does not contain a usable private key")
        return kr.decrypt(ciphertext)


# --------------------------------------------------------------------------- #
# Commitment
# --------------------------------------------------------------------------- #

COMMIT_DOMAIN = b"trustee-key-recovery/master-key-commitment/v1"


def commit(backup_id: str, master_key: bytes) -> str:
    """SHA-256 commitment to the master key, bound to the backup ID.
    The master key is 256 uniformly random bits, so the hash cannot be brute-forced."""
    return hashlib.sha256(COMMIT_DOMAIN + b"\0" + backup_id.encode() + b"\0" + master_key).hexdigest()


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #

@dataclass
class BackupRecord:
    backup_id: str
    encrypted_backup: bytes
    commitment: str
    packages: dict[str, bytes] = field(default_factory=dict)  # contact name -> package for that contact


class Server:
    """Stores the encrypted backup, its ID, the commitment and the three final
    encrypted packages. Nothing else ever reaches it."""

    def __init__(self) -> None:
        self.records: dict[str, BackupRecord] = {}
        self.verbose = True  # print everything that is posted to the server

    def store_backup(self, record: BackupRecord) -> None:
        self.records[record.backup_id] = record
        if self.verbose:
            print()
            info("[SERVER] <- POST backup record")
            block("[SERVER] backup ID", record.backup_id, depth=2)
            block("[SERVER] commitment", record.commitment, depth=2, note="SHA-256, hex")
            show_bytes("[SERVER] encrypted backup", record.encrypted_backup, depth=2)

    def publish_package(self, backup_id: str, contact: str, blob: bytes) -> None:
        self.records[backup_id].packages[contact] = blob
        if self.verbose:
            print()
            info(f"[SERVER] <- POST package for {contact} (backup ID {backup_id[:8]}...)")
            show_bytes(f"[SERVER] package for {contact}, encrypted to P_{contact[0]}", blob, depth=2)

    def dump(self, backup_id: str) -> None:
        rec = self.records[backup_id]
        block("backup ID", rec.backup_id)
        block("commitment", rec.commitment, note="SHA-256, hex")
        show_bytes("encrypted backup", rec.encrypted_backup)
        for name, blob in rec.packages.items():
            show_bytes(f"package for {name}", blob)

    def get_record(self, backup_id: str) -> BackupRecord:
        return self.records[backup_id]

    def get_package(self, backup_id: str, contact: str) -> bytes:
        return self.records[backup_id].packages[contact]

    def all_blobs(self, backup_id: str) -> list[bytes]:
        rec = self.records[backup_id]
        return [rec.encrypted_backup, rec.commitment.encode(), *rec.packages.values()]


# --------------------------------------------------------------------------- #
# Trusted contact
# --------------------------------------------------------------------------- #

Tamper = Callable[["Contact", dict], dict]


class Contact:
    def __init__(self, name: str):
        self.name = name
        self.kr = Keyring(f"{name}'s keyring")
        self.fpr = self.kr.generate(f"{name} <{name.lower()}@contacts.example>")
        self.tamper: Optional[Tamper] = None  # set to make this contact malicious

    def public_key(self) -> bytes:
        return self.kr.export_public(self.fpr)

    def show_keys(self) -> None:
        substep(f"{self.name}  (P_{self.name[0]})  fingerprint {short_fpr(self.fpr)}")
        show_text(f"{self.name}'s public key", self.public_key())
        show_text(f"{self.name}'s private key", self.kr.export_secret(self.fpr))

    def read_fingerprint_aloud(self) -> str:
        """Out-of-band channel: in person, phone or video call."""
        return self.fpr

    def open_own_package(self, server: Server, backup_id: str) -> dict:
        return json.loads(self.kr.decrypt(server.get_package(backup_id, self.name)))

    def handle_recovery_request(self, server: Server, backup_id: str, offered_pub: bytes,
                                call_user: Callable[[], Optional[str]],
                                verify_identity: bool = True) -> Optional[bytes]:
        """Steps 2.2 and 2.3.

        offered_pub  -- the public key that arrived with the request (any channel).
        call_user    -- calls the user on a number / in a place the contact ALREADY
                        knows, and returns the fingerprint the real user reads out
                        (None if the user says they never asked for a recovery).
        """
        offered_fpr = self.kr.fingerprint_of(offered_pub)
        substep(f"{self.name} handles the recovery request")
        info(f"{self.name}: recovery request for key {short_fpr(offered_fpr)}")

        if verify_identity:
            spoken = call_user()
            if spoken is None:
                rejected(f"{self.name}: called the user, who says they never requested a recovery")
                return None
            if not same_fpr(spoken, offered_fpr):
                rejected(f"{self.name}: fingerprint read by the user ({short_fpr(spoken)}) "
                         f"does not match the key received -> refusing")
                return None
            ok(f"{self.name}: fingerprint confirmed out of band with the user")
        else:
            info(f"{self.name}: !! forwarding WITHOUT any out-of-band identity check")

        package = self.open_own_package(server, backup_id)  # decrypt with own private key P_x
        info(f"{self.name}: downloads their package from the server and decrypts it "
             f"with P_{self.name[0]}")
        show_package(f"{self.name}'s package, decrypted with P_{self.name[0]}", package)
        if self.tamper is not None:
            package = self.tamper(self, dict(package))
            print()
            info(f"{self.name}: !! is malicious and sends a modified package")
            show_package(f"modified package sent by {self.name}", package)

        imported = self.kr.import_key(offered_pub)
        if offered_fpr not in imported:
            raise GPGError("offered key could not be imported")
        reply = self.kr.encrypt(json.dumps(package).encode(), [offered_fpr])
        show_bytes(f"{self.name}'s reply, encrypted to the requester's key", reply)
        return reply


@contextmanager
def malicious(contact: Contact, tamper: Tamper):
    contact.tamper = tamper
    try:
        yield
    finally:
        contact.tamper = None


# --------------------------------------------------------------------------- #
# Setup (section 1)
# --------------------------------------------------------------------------- #

@dataclass
class OriginalDevice:
    keyring: Keyring
    master_key: Optional[bytes]

    def lose(self) -> None:
        self.keyring.destroy()
        self.master_key = None


@dataclass
class SetupOutcome:
    backup_id: str
    device: OriginalDevice
    # NOT part of the protocol: kept by the simulation only to assert that the
    # recovered data is correct and to model worst-case adversaries.
    sim_backup_plaintext: bytes
    sim_recovery_pubkeys: dict[int, bytes]


def setup(server: Server, contacts: list[Contact], backup_plaintext: bytes,
          verbose: bool = True) -> SetupOutcome:
    say = info if verbose else (lambda *a, **k: None)
    show = step if verbose else (lambda *a, **k: None)
    alice, bob, carol = contacts

    device = Keyring("user's original device")

    show("1.1 Backup encryption")
    master_key = secrets.token_bytes(32)
    backup_id = str(uuid.uuid4())
    envelope = json.dumps({"backup_id": backup_id, "data": b64(backup_plaintext)}).encode()
    # OpenPGP symmetric encryption, AES-256 with integrity protection (MDC).
    encrypted_backup = device.sym_encrypt(envelope, master_key)
    commitment = commit(backup_id, master_key)
    if verbose:
        say(f"backup ID : {backup_id}")
        block("master key mk", master_key.hex(), note="256 random bits, hex")
        block("commitment = SHA-256(domain || backup ID || mk)", commitment, note="hex")
        show_text("backup plaintext", backup_plaintext)
        show_text("envelope that gets encrypted with mk (JSON: backup ID + base64 data)",
                  json.dumps(json.loads(envelope), indent=2))
        print()
        say("the envelope is encrypted (OpenPGP, AES-256, key mk) and posted:")
    server.store_backup(BackupRecord(backup_id, encrypted_backup, commitment))

    show("1.2 Recovery key pairs K1, K2, K3")
    K = {i: device.generate(f"Recovery key K{i} <recovery-{i}@{backup_id[:8]}>") for i in (1, 2, 3)}
    for i, fpr in K.items():
        if verbose:
            substep(f"K{i}  fingerprint {short_fpr(fpr)}")
            show_text(f"K{i} public key", device.export_public(fpr))
            show_text(f"K{i} private key", device.export_secret(fpr))

    show("1.3 Threshold ciphertexts")
    mk_hex = master_key.hex().encode()
    inner_A = device.encrypt(mk_hex, [K[2], K[3]])
    inner_B = device.encrypt(mk_hex, [K[3]])
    C_A = device.encrypt(inner_A, [K[1]])
    C_B = device.encrypt(inner_B, [K[2]])
    if verbose:
        show_bytes("inner layer of C_A: Enc_{K2,K3}(mk)", inner_A)
        show_bytes("C_A = Enc_K1(Enc_{K2,K3}(mk))", C_A)
        show_bytes("inner layer of C_B: Enc_K3(mk)", inner_B)
        show_bytes("C_B = Enc_K2(Enc_K3(mk))", C_B)
    del inner_A, inner_B

    show("1.4 Contact public keys, fingerprints confirmed out of band")
    P: dict[str, str] = {}
    for c in contacts:
        pub = c.public_key()                 # arrives over an untrusted channel
        fpr = device.fingerprint_of(pub)
        spoken = c.read_fingerprint_aloud()  # read out in person / by phone
        if not same_fpr(fpr, spoken):
            raise SystemExit(f"fingerprint mismatch for {c.name}: aborting setup")
        device.import_key(pub)
        P[c.name] = fpr
        say(f"P_{c.name[0]} ({c.name:<5}): {short_fpr(fpr)}  [confirmed]")

    show("1.5 Packages, each encrypted to its contact")
    for contact, idx, ct in ((alice, 1, C_A), (bob, 2, C_B), (carol, 3, None)):
        package = {
            "backup_id": backup_id,
            "index": idx,
            "recovery_key": device.export_secret(K[idx]).decode(),
            "ciphertext": b64(ct) if ct is not None else None,
        }
        blob = device.encrypt(json.dumps(package).encode(), [P[contact.name]])
        what = f"K{idx}" + (f", C_{'AB'[idx - 1]}" if ct else "") + f", backup ID, index {idx}"
        if verbose:
            substep(f"package {'ABC'[idx - 1]} -> {contact.name}: {what}")
            show_package(f"package {'ABC'[idx - 1]} (plaintext, before encryption)", package)
            print()
            say(f"package {'ABC'[idx - 1]} is encrypted to P_{contact.name[0]} and posted:")
        server.publish_package(backup_id, contact.name, blob)
        del package

    show("1.6 Cleanup of the user's device")
    pubs = {i: device.export_public(K[i]) for i in K}  # simulation only (worst-case adversary)
    for fpr in K.values():
        device.delete_key(fpr)
    del C_A, C_B, mk_hex
    say("deleted K1, K2, K3, C_A, C_B and every plaintext package")
    if verbose:
        expect("no recovery private key is left on the user's device", not device.list_secret())
        leaked = [b for b in server.all_blobs(backup_id)
                  if b"PRIVATE KEY" in b or master_key.hex().encode() in b or master_key in b]
        expect("the server holds no recovery key or master key in plaintext", not leaked)

    return SetupOutcome(backup_id, OriginalDevice(device, master_key), backup_plaintext, pubs)


# --------------------------------------------------------------------------- #
# Recovery client (section 2)
# --------------------------------------------------------------------------- #

@dataclass
class Candidate:
    sender: str
    index: int
    recovery_key: str
    ciphertext: Optional[bytes]


@dataclass
class RecoveryResult:
    plaintext: Optional[bytes]
    suspects: list[str] = field(default_factory=list)


LAYERS = {
    (1, 2): "decrypt C_A with K1, then with K2",
    (1, 3): "decrypt C_A with K1, then with K3",
    (2, 3): "decrypt C_B with K2, then with K3",
}


class RecoveryClient:
    """Runs on the new device (or on the attacker's machine in adversary 3)."""

    def __init__(self, server: Server, backup_id: str, owner: str = "User"):
        self.server = server
        self.backup_id = backup_id
        self.owner = owner
        self.kr = Keyring(f"{owner}'s new device")
        self.fpr = self.kr.generate(f"{owner} (new device) <{owner.lower()}@new-device.example>")

    def public_key(self) -> bytes:
        return self.kr.export_public(self.fpr)

    def show_keys(self, name: str = "N") -> None:
        info(f"{self.owner}'s new key pair {name}: {short_fpr(self.fpr)}")
        show_text(f"{name}_pub ({self.owner}'s new device)", self.public_key())
        show_text(f"{name}_priv ({self.owner}'s new device)", self.kr.export_secret(self.fpr))

    def read_fingerprint_aloud(self) -> str:
        return self.fpr

    def destroy(self) -> None:
        self.kr.destroy()

    def _summarize(self, pkg) -> str:
        """Compact view of a decrypted reply (the full package was shown by the sender)."""
        if not isinstance(pkg, dict):
            return repr(pkg)[:200]
        try:
            key_fpr = short_fpr(self.kr.fingerprint_of(pkg["recovery_key"]))
        except (GPGError, KeyError, TypeError, AttributeError):
            key_fpr = "(no usable key)"
        ct = pkg.get("ciphertext")
        try:
            ct_desc = ("(none)" if ct is None else
                       f"{len(b64d(ct))} bytes, SHA-256 {hashlib.sha256(b64d(ct)).hexdigest()[:32]}...")
        except (ValueError, TypeError):
            ct_desc = "(not valid base64)"
        return "\n".join([
            f"backup_id    : {pkg.get('backup_id')}",
            f"index        : {pkg.get('index')}",
            f"recovery_key : fpr {key_fpr}",
            f"ciphertext   : {ct_desc}",
        ])

    # -- 2.4 validation of each reply -------------------------------------- #
    def _structural_problem(self, pkg) -> Optional[str]:
        if not isinstance(pkg, dict):
            return "not a package"
        if pkg.get("backup_id") != self.backup_id:
            return f"wrong backup ID {pkg.get('backup_id')!r} (expected {self.backup_id!r})"
        idx = pkg.get("index")
        if isinstance(idx, bool) or idx not in (1, 2, 3):
            return f"invalid index {idx!r}"
        if not isinstance(pkg.get("recovery_key"), str):
            return "no recovery key"
        has_ct = pkg.get("ciphertext") is not None
        if has_ct != (idx in (1, 2)):
            return f"index {idx} {'must not' if idx == 3 else 'must'} carry a ciphertext"
        if has_ct:
            try:
                b64d(pkg["ciphertext"])
            except (ValueError, TypeError):
                return "ciphertext is not valid base64"
        return None

    def _validate(self, replies: dict[str, Optional[bytes]]) -> list[Candidate]:
        cands: list[Candidate] = []
        for sender, blob in replies.items():
            if blob is None:
                info(f"{sender}: no reply")
                continue
            try:
                pkg = json.loads(self.kr.decrypt(blob))  # decrypt with N_priv
            except (GPGError, ValueError) as e:
                rejected(f"reply from {sender}: cannot be decrypted/parsed ({e})")
                continue
            block(f"reply from {sender}, decrypted with N_priv", self._summarize(pkg))
            problem = self._structural_problem(pkg)
            if problem:
                rejected(f"package from {sender}: {problem}")
                continue
            ct = b64d(pkg["ciphertext"]) if pkg["ciphertext"] is not None else None
            cands.append(Candidate(sender, pkg["index"], pkg["recovery_key"], ct))
            ok(f"package from {sender}: backup ID matches, index {pkg['index']}")

        # A repeated index is never accepted: two packages that claim the same
        # index are never combined with each other. (We do not simply keep the
        # first one, because a malicious contact could race the honest one.)
        for idx, n in Counter(c.index for c in cands).items():
            if n > 1:
                who = ", ".join(c.sender for c in cands if c.index == idx)
                rejected(f"index {idx} is claimed by several packages ({who}): repeated index")
        return cands

    # -- 2.4 peeling --------------------------------------------------------- #
    @staticmethod
    def _rebuild(lo: Candidate, hi: Candidate) -> bytes:
        assert lo.ciphertext is not None
        ct_name = f"C_{'AB'[lo.index - 1]}"
        show_bytes(f"{ct_name} (from {lo.sender}), the message to decrypt", lo.ciphertext, depth=2)
        middle = peel_layer(lo.ciphertext, lo.recovery_key, f"peel K{lo.index}")
        show_bytes(f"{ct_name} decrypted with K{lo.index} ({lo.sender}): inner layer", middle, depth=2)
        inner = peel_layer(middle, hi.recovery_key, f"peel K{hi.index}")
        block(f"inner layer decrypted with K{hi.index} ({hi.sender}): master key",
              inner.decode("ascii", errors="replace"), depth=2, note="hex")
        mk = bytes.fromhex(inner.decode("ascii"))
        if len(mk) != 32:
            raise ValueError("rebuilt key has the wrong length")
        return mk

    # -- 2.4 + 2.5 ----------------------------------------------------------- #
    def recover(self, replies: dict[str, Optional[bytes]]) -> RecoveryResult:
        record = self.server.get_record(self.backup_id)
        substep("2.4 Decrypt and validate the replies")
        cands = self._validate(replies)
        if len(cands) < 2:
            print()
            bad(f"only {len(cands)} valid package(s): recovery is NOT possible. Stopping.")
            return RecoveryResult(None)

        passing: list[tuple[Candidate, Candidate, bytes]] = []
        for a, b in itertools.combinations(cands, 2):
            lo, hi = sorted((a, b), key=lambda c: c.index)
            label = f"{lo.sender}(#{lo.index}) + {hi.sender}(#{hi.index})"
            substep(f"2.4 Rebuild the master key: {label}")
            if lo.index == hi.index:
                rejected(f"{label}: repeated index, pair not used")
                continue
            info(f"trying {label}: {LAYERS[(lo.index, hi.index)]}")
            try:
                mk = self._rebuild(lo, hi)
            except (GPGError, ValueError, UnicodeDecodeError) as e:
                print()
                rejected(f"{label}: layers cannot be removed ({e})", depth=2)
                continue
            block("commitment check",
                  f"stored on the server:\n  {record.commitment}\n"
                  f"computed from the rebuilt key:\n  {commit(self.backup_id, mk)}", depth=2)
            if not hmac.compare_digest(commit(self.backup_id, mk), record.commitment):
                rejected(f"{label}: rebuilt key does NOT match the stored commitment", depth=2)
                continue
            ok(f"{label}: rebuilt key matches the commitment", depth=2)
            passing.append((lo, hi, mk))

        if not passing:
            print()
            bad("no pair yields a key that passes the commitment check: "
                "recovery is NOT possible. Stopping without using any unverified key.")
            if len(cands) == 2:
                info("(with only two packages the client cannot tell which one is bad; "
                     "ask the third contact)")
            return RecoveryResult(None)

        suspects: list[str] = []
        if len(cands) > 2:
            trusted = {c.sender for lo, hi, _ in passing for c in (lo, hi)}
            suspects = [c.sender for c in cands if c.sender not in trusted]
            if suspects:
                print()
                info(f"packages that appear in no verified pair -> malicious or corrupt: "
                     f"{', '.join(suspects)}")

        lo, hi, mk = passing[0]
        substep(f"2.5 Restore the backup with the verified key from {lo.sender} + {hi.sender}")
        block("verified master key", mk.hex(), note="hex")
        show_bytes("encrypted backup from the server (message to decrypt)",
                   record.encrypted_backup)
        try:
            raw = self.kr.sym_decrypt(record.encrypted_backup, mk)
            envelope = json.loads(raw)
            show_text("decrypted envelope", json.dumps(envelope, indent=2))
            if envelope.get("backup_id") != self.backup_id:
                raise ValueError("backup ID inside the backup does not match")
            data = b64d(envelope["data"])
        except (GPGError, ValueError, KeyError) as e:
            bad(f"the backup failed to decrypt ({e}): stopping")
            return RecoveryResult(None, suspects)
        show_text("restored backup (plaintext)", data)
        print()
        ok(f"backup decrypted and integrity-verified ({len(data)} bytes)")
        return RecoveryResult(data, suspects)


def run_recovery(server: Server, outcome: SetupOutcome, ask: list[Contact],
                 title: str = "") -> RecoveryResult:
    """Honest recovery flow: steps 2.1 - 2.5."""
    if title:
        step(title)
    client = RecoveryClient(server, outcome.backup_id)
    substep("2.1 New identity N on the new device")
    client.show_keys()
    print()
    info(f"2.2/2.3 N_pub is sent directly to {', '.join(c.name for c in ask)};")
    info("        they check it out of band and forward their package")
    replies = {
        c.name: c.handle_recovery_request(server, outcome.backup_id, client.public_key(),
                                          call_user=client.read_fingerprint_aloud)
        for c in ask
    }
    try:
        return client.recover(replies)
    finally:
        client.destroy()


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def scenario_recovery(server: Server, outcome: SetupOutcome, contacts: list[Contact]) -> None:
    banner("SECTION 2 - Recovery on a new device (milestone)")
    alice, bob, carol = contacts
    for pair in ((alice, bob), (alice, carol), (bob, carol)):
        names = " + ".join(c.name for c in pair)
        res = run_recovery(server, outcome, list(pair), f"Recovery with {names}")
        expect(f"{names} restore the original backup", res.plaintext == outcome.sim_backup_plaintext)


def attacker_closure(label: str, private_keys: list[bytes], blobs: list[bytes],
                     backup_id: str, commitment: str) -> bool:
    """Give a coalition every private key it holds (in one keyring) and every
    ciphertext it has seen; peel layers until nothing new comes out. Return True
    iff some derived value is the master key (it matches the commitment)."""
    with scratch_keyring(f"coalition {label}") as kr:
        for k in private_keys:
            kr.import_key(k)
        known = list(blobs)
        seen = {hashlib.sha256(b).digest() for b in known}
        frontier = list(blobs)
        while frontier:
            new = []
            for blob in frontier:
                try:
                    out = kr.decrypt(blob)
                except GPGError:
                    continue
                h = hashlib.sha256(out).digest()
                if h not in seen:
                    seen.add(h)
                    new.append(out)
            known += new
            frontier = new
        for value in known:
            try:
                mk = bytes.fromhex(value.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                continue
            if hmac.compare_digest(commit(backup_id, mk), commitment):
                return True
    return False


def scenario_adv1(server: Server, outcome: SetupOutcome, contacts: list[Contact]) -> None:
    banner("ADVERSARY 1 - A curious server colludes with one contact")
    rec = server.get_record(outcome.backup_id)
    step("What the server holds")
    info(f"encrypted backup ({len(rec.encrypted_backup)} B), backup ID, commitment, "
         f"packages for {', '.join(rec.packages)}")
    server.dump(outcome.backup_id)
    print()
    info("the commitment is SHA-256 of a 256-bit random key: not invertible / brute-forceable")

    for colluder in contacts:
        step(f"Server + {colluder.name}")
        pkg = colluder.open_own_package(server, outcome.backup_id)
        idx = pkg["index"]
        show_package(f"{colluder.name}'s package, decrypted with P_{colluder.name[0]}", pkg)
        print()
        info(f"{colluder.name} opens their own package: K{idx}"
             + (f" and C_{'AB'[idx - 1]}" if pkg["ciphertext"] else " (no ciphertext)"))

        # What one key can do, layer by layer.
        for other in contacts:
            if other is colluder:
                continue
            try:
                colluder.kr.decrypt(server.get_package(outcome.backup_id, other.name))
                bad(f"{colluder.name} opened {other.name}'s package!")
            except GPGError:
                info(f"{other.name}'s package: encrypted to P_{other.name[0]} -> cannot open")
        if pkg["ciphertext"]:
            ct = b64d(pkg["ciphertext"])
            middle = peel_layer(ct, pkg["recovery_key"])
            info(f"outer layer of C_{'AB'[idx - 1]} removed with K{idx} -> inner ciphertext")
            show_bytes(f"C_{'AB'[idx - 1]} after decrypting with K{idx}: still encrypted", middle)
            print()
            try:
                peel_layer(middle, pkg["recovery_key"])
                bad("inner layer opened with the same key!")
            except GPGError as e:
                info(f"inner layer with K{idx} again: fails ({e})")
        else:
            info("K3 alone has no ciphertext to open")

        # Exhaustive check over everything the coalition knows.
        keys = [colluder.kr.export_secret(colluder.fpr), pkg["recovery_key"].encode()]
        blobs = server.all_blobs(outcome.backup_id)
        if pkg["ciphertext"]:
            blobs.append(b64d(pkg["ciphertext"]))
        got_it = attacker_closure(colluder.name, keys, blobs, rec.backup_id, rec.commitment)
        expect(f"server + {colluder.name} cannot recover the master key "
               f"(every ciphertext needs two different recovery keys)", not got_it)


def tamper_wrong_backup(server: Server, other_backup_id: str) -> Tamper:
    def t(contact: Contact, pkg: dict) -> dict:
        return contact.open_own_package(server, other_backup_id)
    return t


def tamper_index(new_index: int) -> Tamper:
    def t(contact: Contact, pkg: dict) -> dict:
        pkg["index"] = new_index
        return pkg
    return t


def tamper_forge_ciphertext(recovery_pubs: dict[int, bytes]) -> Tamper:
    """Worst case: the contact knows the recovery PUBLIC keys and builds a
    perfectly well-formed ciphertext for a key of their choice."""
    def t(contact: Contact, pkg: dict) -> dict:
        fake = secrets.token_bytes(32).hex().encode()
        with scratch_keyring("forgery") as kr:
            f = {i: kr.import_key(recovery_pubs[i])[0] for i in (1, 2, 3)}
            if pkg["index"] == 1:
                forged = kr.encrypt(kr.encrypt(fake, [f[2], f[3]]), [f[1]])
            else:
                forged = kr.encrypt(kr.encrypt(fake, [f[3]]), [f[2]])
        pkg["ciphertext"] = b64(forged)
        return pkg
    return t


def tamper_flip_byte(contact: Contact, pkg: dict) -> dict:
    ct = bytearray(b64d(pkg["ciphertext"]))
    ct[len(ct) // 2] ^= 0x01
    pkg["ciphertext"] = b64(bytes(ct))
    return pkg


def tamper_swap_key(contact: Contact, pkg: dict) -> dict:
    with scratch_keyring("fake recovery key") as kr:
        fpr = kr.generate("Fake recovery key <fake@example>")
        pkg["recovery_key"] = kr.export_secret(fpr).decode()
    return pkg


def scenario_adv2(server: Server, outcome: SetupOutcome, contacts: list[Contact]) -> None:
    banner("ADVERSARY 2 - A malicious contact sends a modified or foreign package")
    alice, bob, carol = contacts
    want = outcome.sim_backup_plaintext

    step("(preparation) the user also protects a second, unrelated backup with the same contacts")
    server.verbose = False
    try:
        other = setup(server, contacts, b"another backup", verbose=False)
    finally:
        server.verbose = True
    info(f"second backup ID: {other.backup_id}")

    with malicious(bob, tamper_wrong_backup(server, other.backup_id)):
        res = run_recovery(server, outcome, [alice, bob],
                           "2a. Bob forwards his package from the OTHER backup (wrong backup ID)")
    expect("package with the wrong backup ID is rejected; client stops", res.plaintext is None)

    with malicious(bob, tamper_index(1)):
        res = run_recovery(server, outcome, [alice, bob],
                           "2b. Bob relabels his package as index 1 (repeated index)")
    expect("repeated index is rejected; client stops", res.plaintext is None)

    with malicious(alice, tamper_forge_ciphertext(outcome.sim_recovery_pubkeys)):
        res = run_recovery(server, outcome, [alice, bob],
                           "2c. Alice replaces C_A with a well-formed ciphertext of a FAKE key")
    expect("modified ciphertext gives a key that fails the commitment check", res.plaintext is None)

    with malicious(bob, tamper_flip_byte):
        res = run_recovery(server, outcome, [bob, carol],
                           "2d. Bob flips one bit of C_B")
    expect("corrupted ciphertext fails to decrypt (PGP integrity/format check); client stops",
           res.plaintext is None)

    with malicious(alice, tamper_forge_ciphertext(outcome.sim_recovery_pubkeys)):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2e. All three answer; Alice's C_A is forged")
    expect("with three packages the honest pair B+C restores the backup", res.plaintext == want)
    expect("Alice is identified as the malicious contact", res.suspects == ["Alice"])

    with malicious(carol, tamper_swap_key):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2f. All three answer; Carol substitutes a fake K3")
    expect("with three packages the honest pair A+B restores the backup", res.plaintext == want)
    expect("Carol is identified as the malicious contact", res.suspects == ["Carol"])

    with malicious(bob, tamper_wrong_backup(server, other.backup_id)), malicious(carol, tamper_swap_key):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2g. Bob (wrong backup) AND Carol (fake K3) misbehave: fewer than two valid packages")
    expect("fewer than two valid packages: client reports recovery impossible", res.plaintext is None)


def scenario_adv3(server: Server, outcome: SetupOutcome, contacts: list[Contact]) -> None:
    banner("ADVERSARY 3 (optional) - A false recovery request")
    alice, bob, _ = contacts
    bid = outcome.backup_id

    def real_user_not_recovering() -> Optional[str]:
        return None  # the contact calls the user's known number: "I never asked for this"

    step("3a. Mallory poses as the user and sends her own key M_pub; contacts DO the check")
    mallory = RecoveryClient(server, bid, owner="Mallory")
    mallory.show_keys("M")
    replies = {c.name: c.handle_recovery_request(server, bid, mallory.public_key(),
                                                 call_user=real_user_not_recovering)
               for c in (alice, bob)}
    res = mallory.recover(replies)
    expect("out-of-band check stops the false request; Mallory gets nothing", res.plaintext is None)

    step("3b. The user really is recovering, but sends N_pub via the server, which swaps in M_pub")
    user = RecoveryClient(server, bid)
    info(f"user's real key N        : {short_fpr(user.fpr)}")
    info(f"key delivered by server  : {short_fpr(mallory.fpr)}  (Mallory's M)")
    replies = {c.name: c.handle_recovery_request(server, bid, mallory.public_key(),
                                                 call_user=user.read_fingerprint_aloud)
               for c in (alice, bob)}
    res = mallory.recover(replies)
    expect("the fingerprint read by the real user exposes the substituted key", res.plaintext is None)
    user.destroy()

    step("3c. Same false request, but the contacts SKIP the out-of-band check")
    replies = {c.name: c.handle_recovery_request(server, bid, mallory.public_key(),
                                                 call_user=real_user_not_recovering,
                                                 verify_identity=False)
               for c in (alice, bob)}
    res = mallory.recover(replies)
    info("the commitment check passes: it authenticates the KEY, not the person asking")
    expect("without the check Mallory rebuilds the master key and reads the victim's backup",
           res.plaintext == outcome.sim_backup_plaintext)
    mallory.destroy()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["all", "recovery", "adv1", "adv2", "adv3"], default="all")
    ap.add_argument("--brief", action="store_true",
                    help="shorten long blocks (keys, ciphertexts) to a few lines")
    args = ap.parse_args()
    global BRIEF
    BRIEF = args.brief

    if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
        print("GnuPG (gpg, gpgconf) must be installed and in PATH", file=sys.stderr)
        return 2

    banner("SECTION 1 - Setup")
    server = Server()
    step("Trusted contacts create their own PGP key pairs")
    contacts = [Contact(n) for n in ("Alice", "Bob", "Carol")]
    for c in contacts:
        c.show_keys()

    backup = ("Family photos, password vault export, 2FA backup codes...\n"
              + secrets.token_hex(64)).encode()
    outcome = setup(server, contacts, backup)

    step("The user loses the original device (master key and everything on it)")
    outcome.device.lose()
    print()
    info("original device wiped; only the server's data and the contacts remain")

    scenarios = {
        "recovery": scenario_recovery,
        "adv1": scenario_adv1,
        "adv2": scenario_adv2,
        "adv3": scenario_adv3,
    }
    for name, fn in scenarios.items():
        if args.scenario in ("all", name):
            fn(server, outcome, contacts)

    banner("SUMMARY")
    print()
    for desc, passed in CHECKS:
        print(f"  [{'PASS' if passed else 'FAIL'}] {desc}")
    failed = sum(not p for _, p in CHECKS)
    print(f"\n  {len(CHECKS) - failed}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
