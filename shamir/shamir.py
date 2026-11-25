#!/usr/bin/env python3
"""
Key recovery through trusted contacts (Shamir 2-of-3 + PGP) -- simulation.

A user protects an encrypted backup with a 256-bit master key K. K is split
with our own Shamir secret sharing over GF(p), p = 2^521 - 1, into three
shares. Each share is signed by the owner's PGP key and encrypted to one
trusted contact. Any two contacts can help the user rebuild K on a new
device; one share alone reveals nothing about K.

Every PGP operation is done by real GnuPG (the `gpg` binary). Each actor
(the owner's original device, the new device, every contact, the attacker)
gets its own isolated GnuPG home directory under <tmp>/homes/<actor>, so keys
only exist where the protocol puts them.

Requirements: GnuPG >= 2.2.8 in PATH. Only the Python standard library.

Usage:
    python3 shamir.py                      # run everything
    python3 shamir.py --scenario tests     # Shamir unit tests only
    python3 shamir.py --scenario recovery  # setup + normal recovery only
    python3 shamir.py --scenario adv1|adv2
    python3 shamir.py --brief              # shorten long blocks (keys, ciphertexts)

Package i, built in layers:
    payload_i = JSON {backup_id, index: i, share: hex(y_i)}
    S_i       = Sign_owner(payload_i)          (opaque signed message)
    E_i       = Enc_contact_i(S_i)             (delivered to contact i)
    server    : {contact_i_fpr, package_id, sha256(E_i)}
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
import uuid
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


def show_text(label: str, data: bytes | str, depth: int = 1) -> None:
    text = data.decode(errors="replace") if isinstance(data, bytes) else data
    block(label, text, depth)


def show_json(label: str, data: bytes | str, depth: int = 1) -> None:
    """A JSON document, pretty-printed (falls back to raw text)."""
    try:
        text = json.dumps(json.loads(data), indent=2)
    except (ValueError, TypeError):
        text = data.decode(errors="replace") if isinstance(data, bytes) else str(data)
    block(label, text, depth)


def show_share(label: str, share: tuple[int, int], depth: int = 1) -> None:
    x, y = share
    block(label, f"x = {x}\ny = (hex)\n" + wrap(format(y, "x")), depth, "point on f, y in GF(p)")


def ok(msg: str, depth: int = 1) -> None:
    info(f"[ OK ] {msg}", depth)


def bad(msg: str, depth: int = 1) -> None:
    info(f"[FAIL] {msg}", depth)


def rejected(msg: str, depth: int = 1) -> None:
    info(f"[REJECTED] {msg}", depth)


def short_fpr(fpr: str) -> str:
    return " ".join(fpr[i:i + 4] for i in range(0, len(fpr), 4))


def short_hex(n: int) -> str:
    h = format(n, "x")
    return h if len(h) <= 24 else f"{h[:10]}...{h[-10:]} ({n.bit_length()} bits)"


CHECKS: list[tuple[str, bool]] = []


def expect(description: str, condition: bool) -> None:
    """Record a property the simulation is supposed to demonstrate."""
    CHECKS.append((description, bool(condition)))
    marker = "CHECK PASSED" if condition else "CHECK FAILED"
    print(f"\n   >> {marker}: {description}")


def same_fpr(a: str, b: str) -> bool:
    norm = lambda s: s.replace(" ", "").upper().encode("utf-8")
    return hmac.compare_digest(norm(a), norm(b))


# --------------------------------------------------------------------------- #
# Own Shamir implementation over GF(p), p = 2^521 - 1
# --------------------------------------------------------------------------- #

P = 2 ** 521 - 1   # Mersenne prime, far larger than any 256-bit key
KEY_BYTES = 32

Share = tuple[int, int]


class ShareError(ValueError):
    pass


def _check_shares(shares: list[Share]) -> None:
    """Reject malformed points, index 0, repeated indexes and values outside [0, p)."""
    seen: set[int] = set()
    for s in shares:
        if not (isinstance(s, tuple) and len(s) == 2):
            raise ShareError(f"a share must be a pair (x, y), got {s!r}")
        x, y = s
        if any(not isinstance(v, int) or isinstance(v, bool) for v in (x, y)):
            raise ShareError("share coordinates must be integers")
        if x == 0:
            raise ShareError("index 0 is not allowed (f(0) is the secret itself)")
        if not 0 < x < P:
            raise ShareError(f"index {x} is outside [1, p)")
        if x in seen:
            raise ShareError(f"repeated index {x}")
        if not 0 <= y < P:
            raise ShareError(f"value of share {x} is outside [0, p)")
        seen.add(x)


def split(secret: int, k: int = 2, n: int = 3) -> list[Share]:
    """Random polynomial f of degree k-1 with f(0) = secret; return f(1..n)."""
    if not 0 <= secret < P:
        raise ShareError("secret is outside [0, p)")
    if not 2 <= k <= n < P:
        raise ShareError(f"need 2 <= k <= n < p, got k={k}, n={n}")
    coeffs = [secret] + [secrets.randbelow(P) for _ in range(k - 1)]

    def f(x: int) -> int:
        acc = 0
        for a in reversed(coeffs):  # Horner
            acc = (acc * x + a) % P
        return acc

    return [(x, f(x)) for x in range(1, n + 1)]


def combine(shares: list[Share], k: int = 2) -> int:
    """Lagrange interpolation of f at x = 0."""
    shares = list(shares)
    _check_shares(shares)
    if len(shares) < k:
        raise ShareError(f"need at least {k} shares (points) to interpolate, got {len(shares)}")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        term = yi
        for j, (xj, _) in enumerate(shares):
            if i != j:
                term = term * (0 - xj) * pow(xi - xj, -1, P) % P
        secret = (secret + term) % P
    return secret


def key_to_int(K: bytes) -> int:
    if len(K) != KEY_BYTES:
        raise ShareError(f"key must be {KEY_BYTES} bytes")
    return int.from_bytes(K, "big")


def int_to_key(n: int) -> bytes:
    try:
        return n.to_bytes(KEY_BYTES, "big")
    except OverflowError:
        raise ShareError(f"combined value ({n.bit_length()} bits) does not fit in "
                         f"{KEY_BYTES} bytes: it is not a valid key") from None


# --------------------------------------------------------------------------- #
# GnuPG homes: one isolated keyring per actor
# --------------------------------------------------------------------------- #

class GPGError(RuntimeError):
    pass


@dataclass
class GPGResult:
    """Outcome of one gpg call. The field names follow python-gnupg's result
    objects, so the protocol code reads like the task statement."""
    data: bytes = b""
    ok: bool = False                   # the operation itself succeeded
    valid: bool = False                # a good signature from a key in the keyring
    fingerprint: Optional[str] = None  # signing key fingerprint (from VALIDSIG)
    status: str = ""                   # short human-readable outcome
    returncode: int = 0
    statuses: list[str] = field(default_factory=list)  # raw [GNUPG:] status lines

    def has(self, keyword: str) -> bool:
        return any(s.split()[:1] == [keyword] for s in self.statuses)

    def args(self, keyword: str) -> list[str]:
        for s in self.statuses:
            parts = s.split()
            if parts[:1] == [keyword]:
                return parts[1:]
        return []

    def __str__(self) -> str:
        return self.data.decode("utf-8", errors="replace")


class GPG:
    """The gpg binary, bound to one isolated GnuPG home directory."""

    # Status keyword -> outcome, most specific first.
    _OUTCOMES = (("BADSIG", "signature bad"), ("NO_PUBKEY", "no public key"),
                 ("ERRSIG", "signature error"), ("VALIDSIG", "signature valid"),
                 ("DECRYPTION_FAILED", "decryption failed"), ("DECRYPTION_OKAY", "decryption ok"),
                 ("NODATA", "no valid OpenPGP data"))

    def __init__(self, home: str):
        self.home = home

    def _run(self, *args: str, data: bytes | str = b"",
             passphrase: Optional[str] = None) -> GPGResult:
        """Run gpg once. Never raises on a gpg failure: the caller reads the result."""
        if isinstance(data, str):
            data = data.encode()
        cmd = ["gpg", "--homedir", self.home, "--batch", "--yes", "--no-tty", "--quiet",
               "--pinentry-mode", "loopback", "--no-symkey-cache", "--status-fd", "2"]
        fds: tuple[int, ...] = ()
        r = None
        if passphrase is not None:
            # Hand the passphrase to gpg through a pipe, never on the command line.
            r, w = os.pipe()
            os.write(w, passphrase.encode())
            os.close(w)
            cmd += ["--passphrase-fd", str(r)]
            fds = (r,)
        try:
            proc = subprocess.run(cmd + list(args), input=data, capture_output=True, pass_fds=fds)
        finally:
            if r is not None:
                os.close(r)
        err = proc.stderr.decode(errors="replace").splitlines()
        res = GPGResult(data=proc.stdout, returncode=proc.returncode,
                        statuses=[l[len("[GNUPG:] "):] for l in err if l.startswith("[GNUPG:] ")])
        if res.has("GOODSIG") and res.has("VALIDSIG") and not (res.has("BADSIG") or res.has("ERRSIG")):
            res.valid = True
            res.fingerprint = res.args("VALIDSIG")[0]
        res.status = next((text for kw, text in self._OUTCOMES if res.has(kw)), "")
        if not res.status:
            msgs = [l.removeprefix("gpg: ") for l in err if l and not l.startswith("[GNUPG:]")]
            res.status = "; ".join(msgs) or (f"gpg exited with {proc.returncode}"
                                             if proc.returncode else "ok")
        return res

    # -- key management ----------------------------------------------------- #
    def gen_key(self, uid: str) -> str:
        """Unprotected ed25519 (sign) + cv25519 (encrypt) key pair; return its fingerprint."""
        res = self._run("--passphrase", "", "--quick-gen-key", uid, "future-default", "default", "never")
        created = res.args("KEY_CREATED")
        if res.returncode or len(created) < 2:
            raise GPGError(f"key generation failed: {res.status}")
        return created[1]

    def export_keys(self, fpr: str, secret: bool = False) -> str:
        res = self._run("--armor", "--export-secret-keys" if secret else "--export", fpr)
        if res.returncode or not res.data:
            raise GPGError(f"export of {fpr} failed: {res.status}")
        return str(res)

    def import_keys(self, key: str) -> list[str]:
        """Import key(s); return the fingerprints gpg reports as imported."""
        res = self._run("--import", data=key)
        return sorted({s.split()[2] for s in res.statuses if s.startswith("IMPORT_OK")})

    def show_keys(self, key: str) -> list[str]:
        """Primary key fingerprints in a key block, without importing it."""
        res = self._run("--with-colons", "--show-keys", data=key)
        fprs, want = [], False
        for line in str(res).splitlines():
            if line.startswith(("pub:", "sec:")):
                want = True
            elif line.startswith("fpr:") and want:
                fprs.append(line.split(":")[9])
                want = False
        return fprs

    def delete_keys(self, fpr: str) -> None:
        self._run("--delete-key", fpr)

    # -- crypto --------------------------------------------------------------- #
    def encrypt(self, data: bytes | str, recipients: Optional[list[str]],
                symmetric: Optional[str] = None, passphrase: Optional[str] = None,
                armor: bool = True, always_trust: bool = False) -> GPGResult:
        """Public-key encryption to `recipients`, or symmetric encryption with
        `passphrase` when `symmetric` names a cipher. Always with MDC."""
        args = ["--armor"] if armor else []
        if always_trust:  # fingerprints are checked out of band by the protocol
            args += ["--trust-model", "always"]
        if symmetric:
            args += ["--symmetric", "--cipher-algo", symmetric]
        else:
            args.append("--encrypt")
            for r in recipients or []:
                args += ["--recipient", r]
        res = self._run(*args, data=data, passphrase=passphrase)
        res.ok = res.returncode == 0 and res.has("END_ENCRYPTION")
        return res

    def sign(self, data: bytes | str, keyid: str, clearsign: bool = False,
             extra_args: tuple[str, ...] | list[str] = ()) -> GPGResult:
        """Armored signed message (opaque unless clearsign)."""
        res = self._run("--armor", "--local-user", keyid,
                        "--clearsign" if clearsign else "--sign", *extra_args, data=data)
        res.ok = res.returncode == 0 and res.has("SIG_CREATED")
        return res

    def decrypt(self, data: bytes | str, passphrase: Optional[str] = None) -> GPGResult:
        """Decrypt (and/or verify) a message. `.ok` means it was decrypted and passed
        the integrity (MDC) check; `.valid`/`.fingerprint` describe a signature.
        `.data` holds whatever gpg output, even when the signature is bad."""
        res = self._run("--decrypt", data=data, passphrase=passphrase)
        res.ok = (res.returncode == 0 and res.has("DECRYPTION_OKAY")
                  and not res.has("DECRYPTION_FAILED"))
        return res


WORKDIR: Optional[str] = None
_HOMES: list[str] = []
# Owner signatures are not compressed, so the payload bytes sit in the clear inside
# S_i: that lets adversary 2b edit them and get a clean "bad signature".
SIGN_ARGS = ["--compress-algo", "none"]


def workdir() -> str:
    global WORKDIR
    if WORKDIR is None:
        WORKDIR = tempfile.mkdtemp(prefix="tkr-shamir-")  # mode 0700
        os.makedirs(os.path.join(WORKDIR, "homes"), mode=0o700)
    return WORKDIR


def new_home(name: str) -> GPG:
    """Create <workdir>/homes/<name> and a GPG object bound to it."""
    base = os.path.join(workdir(), "homes", name)
    path, n = base, 2
    while os.path.exists(path):
        path, n = f"{base}-{n}", n + 1
    os.makedirs(path, mode=0o700)
    _HOMES.append(path)
    return GPG(path)


def wipe_home(gpg: GPG) -> None:
    """Stop the home's gpg-agent and delete the directory (models losing a device)."""
    path = gpg.home
    if path and os.path.isdir(path):
        subprocess.run(["gpgconf", "--homedir", path, "--kill", "all"], capture_output=True)
        subprocess.run(["gpgconf", "--homedir", path, "--remove-socketdir"], capture_output=True)
        shutil.rmtree(path, ignore_errors=True)
    if path in _HOMES:
        _HOMES.remove(path)


def _cleanup() -> None:
    for path in list(_HOMES):
        subprocess.run(["gpgconf", "--homedir", path, "--kill", "all"], capture_output=True)
        subprocess.run(["gpgconf", "--homedir", path, "--remove-socketdir"], capture_output=True)
    if WORKDIR:
        shutil.rmtree(WORKDIR, ignore_errors=True)


atexit.register(_cleanup)


def gen_key(gpg: GPG, name: str, email: str) -> str:
    return gpg.gen_key(f"{name} <{email}>")


def export_secret(gpg: GPG, fpr: str) -> str:
    return gpg.export_keys(fpr, secret=True)


def fingerprint_of(gpg: GPG, pubkey: str) -> str:
    """Fingerprint of a public key block, without importing it."""
    keys = gpg.show_keys(pubkey)
    if len(keys) != 1:
        raise GPGError(f"expected exactly one key, found {len(keys)}")
    return keys[0]


def import_key(gpg: GPG, key: str) -> list[str]:
    return gpg.import_keys(key)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ASCII armor, used only by the malicious contact who edits S_i bytes (2b).
def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(text: str) -> bytes:
    lines = text.strip().splitlines()
    body = lines[lines.index("") + 1:-1]  # skip header lines, drop END line
    return base64.b64decode("".join(l for l in body if not l.startswith("=")))


def enarmor(raw: bytes) -> str:
    b = base64.b64encode(raw).decode()
    crc = base64.b64encode(_crc24(raw).to_bytes(3, "big")).decode()
    return f"-----BEGIN PGP MESSAGE-----\n\n{wrap(b)}\n={crc}\n-----END PGP MESSAGE-----\n"


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #

@dataclass
class BackupRecord:
    backup_id: str
    encrypted_backup: str
    owner_public_key: str = ""
    references: list[dict] = field(default_factory=list)


class Server:
    """Stores the encrypted backup, its ID, the owner's public key (untrusted by
    itself) and one reference per package. Never a share, never a package."""

    def __init__(self) -> None:
        self.records: dict[str, BackupRecord] = {}
        self.verbose = True  # print everything that is posted to the server

    def store_backup(self, backup_id: str, encrypted_backup: str) -> None:
        self.records[backup_id] = BackupRecord(backup_id, encrypted_backup)
        if self.verbose:
            print()
            info("[SERVER] <- POST backup record")
            block("[SERVER] backup ID", backup_id, depth=2)
            show_text("[SERVER] encrypted backup (OpenPGP, AES-256, passphrase K.hex())",
                      encrypted_backup, depth=2)

    def store_owner_key(self, backup_id: str, pubkey: str) -> None:
        self.records[backup_id].owner_public_key = pubkey
        if self.verbose:
            print()
            info("[SERVER] <- POST owner public key (not trusted on its own)")
            show_text("[SERVER] owner public key", pubkey, depth=2)

    def add_reference(self, backup_id: str, ref: dict) -> None:
        self.records[backup_id].references.append(ref)
        if self.verbose:
            print()
            info(f"[SERVER] <- POST package reference (backup ID {backup_id[:8]}...)")
            show_json("[SERVER] reference", json.dumps(ref), depth=2)

    def get_record(self, backup_id: str) -> BackupRecord:
        return self.records[backup_id]

    def dump(self, backup_id: str) -> None:
        rec = self.records[backup_id]
        block("backup ID", rec.backup_id)
        show_text("encrypted backup", rec.encrypted_backup)
        show_text("owner public key", rec.owner_public_key)
        for i, ref in enumerate(rec.references, 1):
            show_json(f"reference {i}", json.dumps(ref))

    def all_blobs(self, backup_id: str) -> list[str]:
        rec = self.records[backup_id]
        return [rec.backup_id, rec.encrypted_backup, rec.owner_public_key,
                *(json.dumps(r) for r in rec.references)]


@contextmanager
def swapped_owner_key(server: Server, backup_id: str, fake_pub: str):
    rec = server.get_record(backup_id)
    real = rec.owner_public_key
    rec.owner_public_key = fake_pub
    try:
        yield
    finally:
        rec.owner_public_key = real


# --------------------------------------------------------------------------- #
# Trusted contact
# --------------------------------------------------------------------------- #

Tamper = Callable[["Contact", str, str], str]  # (contact, backup_id, S_i) -> S_i'


class Contact:
    def __init__(self, name: str):
        self.name = name
        self.gpg = new_home(name.lower())
        self.fpr = gen_key(self.gpg, name, f"{name.lower()}@contacts.example")
        self.packages: dict[str, dict] = {}  # backup_id -> {"package_id", "E"}
        self.tamper: Optional[Tamper] = None  # set to make this contact malicious

    def public_key(self) -> str:
        return self.gpg.export_keys(self.fpr)

    def show_keys(self) -> None:
        substep(f"{self.name}  fingerprint {short_fpr(self.fpr)}")
        show_text(f"{self.name}'s public key", self.public_key())
        show_text(f"{self.name}'s private key", export_secret(self.gpg, self.fpr))

    def print_fingerprint(self) -> str:
        """Out-of-band channel: the contact prints / reads out its fingerprint."""
        return self.fpr

    def receive_package(self, backup_id: str, package_id: str, E: str) -> None:
        self.packages[backup_id] = {"package_id": package_id, "E": E}

    def open_package(self, backup_id: str) -> str:
        """Decrypt E_i with the contact's own key. The result is S_i, still signed."""
        res = self.gpg.decrypt(self.packages[backup_id]["E"])
        if not res.ok:
            raise GPGError(f"{self.name} cannot decrypt their package: {res.status}")
        return res.data.decode()

    def read_payload(self, S: str) -> dict:
        """Look inside S_i (the contact has no need to verify the owner's signature)."""
        return json.loads(self.gpg.decrypt(S).data)

    def handle_recovery_request(self, backup_id: str, offered_pub: str,
                                call_user: Callable[[], Optional[str]]) -> Optional[str]:
        offered_fpr = fingerprint_of(self.gpg, offered_pub)
        substep(f"{self.name} handles the recovery request")
        info(f"{self.name}: recovery request for key {short_fpr(offered_fpr)}")
        spoken = call_user()
        if spoken is None or not same_fpr(spoken, offered_fpr):
            rejected(f"{self.name}: the fingerprint confirmed out of band does not match -> refusing")
            return None
        ok(f"{self.name}: fingerprint of N confirmed out of band with the user")

        S = self.open_package(backup_id)
        info(f"{self.name}: decrypts E_i with their own key -> S_i (signature NOT stripped)")
        show_text(f"S_i held by {self.name} (opaque message signed by the owner)", S)
        if self.tamper is not None:
            S = self.tamper(self, backup_id, S)
            print()
            info(f"{self.name}: !! is malicious and forwards a modified S_i")
            show_text(f"modified S_i sent by {self.name}", S)

        if offered_fpr not in import_key(self.gpg, offered_pub):
            raise GPGError("offered key could not be imported")
        reply = self.gpg.encrypt(S, recipients=[offered_fpr], always_trust=True)
        if not reply.ok:
            raise GPGError(f"encryption to N failed: {reply.status}")
        show_text(f"{self.name}'s reply: S_i re-encrypted unchanged to N", str(reply))
        return str(reply)


@contextmanager
def malicious(contact: Contact, tamper: Tamper):
    contact.tamper = tamper
    try:
        yield
    finally:
        contact.tamper = None


# --------------------------------------------------------------------------- #
# Setup (section 1, original device)
# --------------------------------------------------------------------------- #

@dataclass
class OriginalDevice:
    gpg: Optional[GPG]
    owner_fpr: str
    home: str
    # Everything the device must forget when it is lost:
    # backup_id -> {"K", "shares", "packages"}
    secrets: dict[str, dict] = field(default_factory=dict)

    def lose(self) -> None:
        if self.gpg is not None:
            wipe_home(self.gpg)
        self.gpg = None
        self.secrets.clear()


@dataclass
class SetupOutcome:
    backup_id: str
    device: OriginalDevice
    note_path: str
    # NOT part of the protocol: kept by the simulation only to check the
    # recovered data and to demonstrate the adversary scenarios.
    sim_backup_plaintext: bytes
    sim_master_key: bytes


def setup(server: Server, contacts: list[Contact], backup_plaintext: bytes,
          verbose: bool = True, device: Optional[OriginalDevice] = None) -> SetupOutcome:
    say = info if verbose else (lambda *a, **k: None)
    show = step if verbose else (lambda *a, **k: None)

    if device is None:
        gpg_owner = new_home("owner")
        device = OriginalDevice(gpg_owner, "", gpg_owner.home)
    gpg_owner = device.gpg
    assert gpg_owner is not None

    show("1.1 Master key and backup")
    K = secrets.token_bytes(KEY_BYTES)
    backup_id = str(uuid.uuid4())
    enc = gpg_owner.encrypt(backup_plaintext, recipients=None, symmetric="AES256",
                            passphrase=K.hex(), armor=True)
    if not enc.ok:
        raise GPGError(f"backup encryption failed: {enc.status}")
    if verbose:
        say(f"backup ID : {backup_id}")
        block("master key K", K.hex(), note="256 random bits, hex")
        show_text("backup plaintext", backup_plaintext)
        print()
        say("the backup is encrypted symmetrically by GnuPG (AES-256 + MDC, passphrase K.hex())")
        say("and posted together with its ID:")
    server.store_backup(backup_id, str(enc))

    show("1.2 Trust anchor: owner key pair and offline note")
    note_path = os.path.join(workdir(), "offline_note.txt")
    if not device.owner_fpr:
        device.owner_fpr = gen_key(gpg_owner, "Owner (original device)", "owner@device.example")
        with open(note_path, "w") as fh:
            fh.write("Trustee key recovery -- keep this sheet offline\n"
                     f"Owner signing key fingerprint: {device.owner_fpr}\n")
    owner_fpr = device.owner_fpr
    if verbose:
        substep(f"owner key  fingerprint {short_fpr(owner_fpr)}")
        show_text("owner public key", gpg_owner.export_keys(owner_fpr))
        show_text("owner private key (signing)", export_secret(gpg_owner, owner_fpr))
        with open(note_path) as fh:
            show_text("offline_note.txt (stands in for a printed sheet)", fh.read())
        print()
        say("the owner's public key is posted too; it is trustworthy only because")
        say("its fingerprint matches the offline note:")
    server.store_owner_key(backup_id, gpg_owner.export_keys(owner_fpr))

    show("1.3 Contact public keys, fingerprints confirmed out of band")
    contact_fpr: dict[str, str] = {}
    for c in contacts:
        pub = c.public_key()                  # arrives over an untrusted channel
        fpr = fingerprint_of(gpg_owner, pub)
        printed = c.print_fingerprint()       # printed / read out by the contact
        if not same_fpr(fpr, printed):
            raise SystemExit(f"fingerprint mismatch for {c.name}: aborting setup")
        import_key(gpg_owner, pub)
        contact_fpr[c.name] = fpr
        say(f"{c.name:<5}: {short_fpr(fpr)}  [matches the printed value]")

    show("1.4 Split K into 2-of-3 Shamir shares")
    secret = key_to_int(K)
    shares = split(secret, 2, 3)
    if verbose:
        block("K as an integer (int.from_bytes(K, 'big'))", wrap(format(secret, "x")), note="hex")
        say(f"f(x) = K + a1*x mod p, with a1 = secrets.randbelow(p), p = 2^521 - 1")
        for share in shares:
            show_share(f"share {share[0]} = (x{share[0]}, y{share[0]})", share)

    show("1.5 Packages: payload -> signed by the owner -> encrypted to the contact")
    packages: list[str] = []
    for contact, (x, y) in zip(contacts, shares):
        payload = json.dumps({"backup_id": backup_id, "index": x, "share": hex(y)})
        S = gpg_owner.sign(payload, keyid=owner_fpr, clearsign=False, extra_args=SIGN_ARGS)
        if not S.ok:
            raise GPGError(f"signing failed: {S.status}")
        E = gpg_owner.encrypt(str(S), recipients=[contact_fpr[contact.name]], always_trust=True)
        if not E.ok:
            raise GPGError(f"encryption to {contact.name} failed: {E.status}")
        package_id = str(uuid.uuid4())
        ref = {"contact_fpr": contact_fpr[contact.name], "package_id": package_id,
               "sha256": sha256_hex(str(E))}
        if verbose:
            substep(f"package {x} -> {contact.name}")
            show_json(f"payload {x}", payload)
            show_text(f"S{x} = owner signature over payload {x} (opaque signed message)", str(S))
            show_text(f"E{x} = S{x} encrypted to {contact.name}", str(E))
            print()
            say(f"E{x} is delivered directly to {contact.name}; the server only gets a reference:")
        contact.receive_package(backup_id, package_id, str(E))
        server.add_reference(backup_id, ref)
        packages.append(str(E))

    device.secrets[backup_id] = {"K": K, "shares": shares, "packages": packages}
    if verbose:
        blobs = server.all_blobs(backup_id)
        secrets_on_server = [b for b in blobs
                             if K.hex() in b or any(format(y, "x") in b for _, y in shares)]
        expect("the server holds neither the master key nor any share", not secrets_on_server)
    return SetupOutcome(backup_id, device, note_path, backup_plaintext, K)


# --------------------------------------------------------------------------- #
# Recovery client (section 3, new device)
# --------------------------------------------------------------------------- #

@dataclass
class RecoveryResult:
    plaintext: Optional[bytes] = None
    key: Optional[bytes] = None
    aborted: str = ""                                          # why the client stopped early
    rejected: dict[str, str] = field(default_factory=dict)     # sender -> reason code
    asked: list[str] = field(default_factory=list)
    combine_calls: int = 0
    backup_decrypt_calls: int = 0


class RecoveryClient:
    """Runs on the user's new device."""

    def __init__(self, server: Server, backup_id: str, note_path: str,
                 verify_signatures: bool = True):
        self.server = server
        self.backup_id = backup_id
        self.note_path = note_path
        self.verify_signatures = verify_signatures
        self.gpg = new_home("new-device")
        self.fpr = gen_key(self.gpg, "Owner (new device)", "owner@new-device.example")
        self.anchor = ""
        self.seen_indexes: set[int] = set()

    def public_key(self) -> str:
        return self.gpg.export_keys(self.fpr)

    def read_fingerprint_aloud(self) -> str:
        return self.fpr

    def destroy(self) -> None:
        wipe_home(self.gpg)

    # -- 3.1 ------------------------------------------------------------------ #
    def new_identity(self) -> None:
        substep("3.1 New key pair N and the offline trust anchor")
        info(f"new key pair N: {short_fpr(self.fpr)}")
        show_text("N_pub (new device)", self.public_key())
        show_text("N_priv (new device)", export_secret(self.gpg, self.fpr))
        with open(self.note_path) as fh:
            note = fh.read()
        show_text("offline_note.txt, read from the printed sheet", note)
        self.anchor = note.rsplit(":", 1)[1].strip()

    # -- 3.2 ------------------------------------------------------------------ #
    def load_verification_key(self) -> Optional[BackupRecord]:
        substep("3.2 Download the backup, the references and the owner's public key")
        rec = self.server.get_record(self.backup_id)
        show_text("encrypted backup (from the server)", rec.encrypted_backup)
        for i, ref in enumerate(rec.references, 1):
            show_json(f"reference {i} (from the server)", json.dumps(ref))
        show_text("owner public key (from the server, untrusted)", rec.owner_public_key)
        got = import_key(self.gpg, rec.owner_public_key)
        block("trust anchor check",
              f"fingerprint of the downloaded key : {', '.join(short_fpr(f) for f in got) or '(none)'}\n"
              f"fingerprint in the offline note   : {short_fpr(self.anchor)}")
        if len(got) != 1 or not same_fpr(got[0], self.anchor):
            for f in got:
                self.gpg.delete_keys(f)
            print()
            bad("the server's owner key does NOT match the offline note: the server may have "
                "swapped it. Aborting.")
            return None
        ok("the owner key from the server matches the offline note")
        return rec

    # -- 3.4 ------------------------------------------------------------------ #
    def check_reply(self, sender: str, reply: Optional[str],
                    result: RecoveryResult) -> Optional[Share]:
        substep(f"3.4 Check the reply from {sender}")

        def reject(code: str, why: str) -> None:
            result.rejected[sender] = code
            rejected(f"package from {sender}: {why}")

        if reply is None:
            reject("no-reply", "no reply")
            return None
        dec = self.gpg.decrypt(reply)
        if not dec.ok:
            reject("undecryptable", f"cannot decrypt the reply with N ({dec.status})")
            return None
        S = dec.data.decode(errors="replace")
        show_text(f"S_i from {sender}, after decrypting the reply with N_priv", S)

        v = self.gpg.decrypt(S)  # verifies the owner signature and extracts the payload
        if self.verify_signatures:
            block("signature check",
                  f"valid           : {v.valid}\n"
                  f"status          : {v.status}\n"
                  f"signer          : {short_fpr(v.fingerprint) if v.fingerprint else '(unknown)'}\n"
                  f"offline note    : {short_fpr(self.anchor)}")
            if not v.valid:
                reject("bad-signature", f"signature is not valid ({v.status})")
                return None
            if not same_fpr(v.fingerprint or "", self.anchor):
                reject("wrong-signer", "valid signature, but by a key that is NOT the owner key "
                                       "in the offline note")
                return None
            ok("signed by the owner key in the offline note")
        else:
            info("!! signature checking is OFF: the payload is used without checking who signed it")

        try:
            payload = json.loads(v.data)
        except ValueError:
            reject("bad-payload", "the payload is not JSON")
            return None
        show_json("payload", v.data)
        if not isinstance(payload, dict):
            reject("bad-payload", "the payload is not a JSON object")
            return None
        if payload.get("backup_id") != self.backup_id:
            reject("wrong-backup", f"backup_id {payload.get('backup_id')!r} does not match "
                                   f"{self.backup_id!r}")
            return None
        idx = payload.get("index")
        if isinstance(idx, bool) or idx not in (1, 2, 3):
            reject("bad-index", f"invalid index {idx!r}")
            return None
        if idx in self.seen_indexes:
            reject("repeated-index", f"index {idx} was already received")
            return None
        try:
            y = int(payload.get("share"), 16)
        except (TypeError, ValueError):
            reject("bad-share", "share is not a hex integer")
            return None
        if not 0 <= y < P:
            reject("bad-share", "share is outside [0, p)")
            return None
        self.seen_indexes.add(idx)
        ok(f"package from {sender}: backup ID matches, new index {idx}")
        return (idx, y)


def run_recovery(server: Server, outcome: SetupOutcome, ask: list[Contact],
                 title: str = "", verify_signatures: bool = True) -> RecoveryResult:
    """Honest recovery flow. N_pub goes to the first two contacts in `ask`, and
    to the next ones only while fewer than two valid shares have arrived."""
    if title:
        step(title)
    result = RecoveryResult()
    client = RecoveryClient(server, outcome.backup_id, outcome.note_path, verify_signatures)
    try:
        client.new_identity()
        rec = client.load_verification_key()
        if rec is None:
            result.aborted = "owner key mismatch"
            return result

        print()
        info(f"3.3 N_pub is sent directly to {' and '.join(c.name for c in ask[:2])}"
             + (f" ({', '.join(c.name for c in ask[2:])} only if needed)" if ask[2:] else "")
             + "; each checks it out of band")
        valid: list[Share] = []
        for c in ask:
            if len(valid) >= 2:
                break
            if len(result.asked) >= 2:
                print()
                info(f"fewer than two valid shares so far -> asking {c.name} too")
            import_key(client.gpg, c.public_key())  # the device talks to the contact
            result.asked.append(c.name)
            reply = c.handle_recovery_request(outcome.backup_id, client.public_key(),
                                              call_user=client.read_fingerprint_aloud)
            share = client.check_reply(c.name, reply, result)
            if share is not None:
                valid.append(share)

        substep("3.5 Rebuild the master key")
        if len(valid) < 2:
            bad(f"recovery impossible: not enough valid shares ({len(valid)} of 2). "
                "combine() and the backup decryption are never called.")
            result.aborted = "not enough valid shares"
            return result
        for share in valid:
            show_share(f"accepted share {share[0]}", share, depth=2)
        result.combine_calls += 1
        secret = combine(valid)
        try:
            K = int_to_key(secret)
        except ShareError as e:
            bad(f"{e}")
            result.aborted = "combined value is not a key"
            return result
        result.key = K
        block("K = combine(shares), Lagrange at x = 0, int.to_bytes(32, 'big')",
              K.hex(), note="hex")

        substep("3.6 Restore the backup")
        result.backup_decrypt_calls += 1
        dec = client.gpg.decrypt(rec.encrypted_backup, passphrase=K.hex())
        if not dec.ok:
            print()
            bad(f"the backup failed to decrypt ({dec.status}): K is wrong. Stopping.")
            return result
        show_text("restored backup (plaintext)", dec.data)
        print()
        ok(f"backup decrypted and integrity-verified (MDC), {len(dec.data)} bytes")
        result.plaintext = dec.data
        return result
    finally:
        client.destroy()


# --------------------------------------------------------------------------- #
# Section 0: Shamir unit tests
# --------------------------------------------------------------------------- #

def raises_share_error(fn: Callable[[], object]) -> tuple[bool, str]:
    try:
        fn()
    except ShareError as e:
        return True, str(e)
    return False, "accepted"


def run_unit_tests() -> None:
    banner("SECTION 0 - Shamir unit tests (GF(p), p = 2^521 - 1)")

    step("Field and encoding")
    info(f"p = 2^521 - 1, a Mersenne prime of {P.bit_length()} bits (a key has 256)")
    K = secrets.token_bytes(KEY_BYTES)
    s = key_to_int(K)
    block("test key K", K.hex(), note="hex")
    block("int.from_bytes(K, 'big')", str(s), note="decimal")
    expect("int_to_key(key_to_int(K)) == K", int_to_key(s) == K)

    shares = split(s, 2, 3)
    for share in shares:
        show_share(f"share {share[0]}", share)

    step("Every 2-of-3 combination returns the key")
    good = True
    for pair in itertools.combinations(shares, 2):
        got = int_to_key(combine(list(pair)))
        good &= got == K
        info(f"shares {pair[0][0]} + {pair[1][0]} -> {got.hex()}")
    expect("every pair of shares rebuilds K", good)
    expect("all three shares together also rebuild K", int_to_key(combine(shares)) == K)
    rounds = 200
    many = all(int_to_key(combine(list(pair))) == k
               for k in (secrets.token_bytes(KEY_BYTES) for _ in range(rounds))
               for sh in [split(key_to_int(k))]
               for pair in itertools.combinations(sh, 2))
    expect(f"every pair rebuilds K for {rounds} further random keys", many)

    step("A single share returns nothing meaningful")
    refused = True
    for share in shares:
        r, why = raises_share_error(lambda: combine([share]))
        refused &= r
        rejected(f"combine([share {share[0]}]): {why}")
    expect("combine refuses a single share", refused)
    expect("no share value equals the key", all(y != s for _, y in shares))
    info("(why one share says nothing about K: see adversary 1, every K' fits a line through it)")

    step("Changing one share gives a different key")
    differs = True
    for a, b in itertools.combinations(shares, 2):
        altered = (a[0], (a[1] + 1) % P)
        got = combine([altered, b])
        differs &= got != s
        info(f"share {a[0]} + 1, share {b[0]} unchanged -> {short_hex(got)}")
    expect("an altered share never yields K", differs)

    step("Input checks")
    (x1, y1), (x2, y2), _ = shares
    cases = [
        ("repeated index", [(x1, y1), (x1, y2)]),
        ("index 0", [(0, y1), (x2, y2)]),
        ("negative index", [(-1, y1), (x2, y2)]),
        ("value = p", [(x1, P), (x2, y2)]),
        ("negative value", [(x1, -1), (x2, y2)]),
    ]
    all_rejected = True
    for name, bad_shares in cases:
        r, why = raises_share_error(lambda: combine(bad_shares))
        all_rejected &= r
        (rejected if r else bad)(f"{name:<15}: {why}")
    expect("combine rejects repeated indexes, index 0 and values outside [0, p)", all_rejected)
    r, why = raises_share_error(lambda: int_to_key(P - 1))
    info(f"int_to_key(p - 1): {why}")
    expect("a value that does not fit in 32 bytes is not accepted as a key", r)


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def scenario_recovery(server: Server, outcome: SetupOutcome, contacts: list[Contact],
                      other: Optional[SetupOutcome]) -> None:
    banner("SECTION 3 - Recovery on a new device")
    alice, bob, carol = contacts
    for pair in ((alice, bob), (alice, carol), (bob, carol)):
        names = " + ".join(c.name for c in pair)
        res = run_recovery(server, outcome, list(pair), f"Recovery with {names}")
        expect(f"{names} restore the original backup", res.plaintext == outcome.sim_backup_plaintext)

    step("Recovery while the server swaps the owner's public key")
    mallory = new_home("mallory")
    m_fpr = gen_key(mallory, "Owner (original device)", "owner@device.example")
    info(f"the server serves Mallory's key {short_fpr(m_fpr)} under the owner's name")
    try:
        with swapped_owner_key(server, outcome.backup_id, mallory.export_keys(m_fpr)):
            res = run_recovery(server, outcome, [alice, bob])
    finally:
        wipe_home(mallory)
    expect("a swapped owner key fails the offline-note check; no contact is even asked",
           res.aborted == "owner key mismatch" and not res.asked)


def scenario_adv1(server: Server, outcome: SetupOutcome, contacts: list[Contact],
                  other: Optional[SetupOutcome]) -> None:
    banner("ADVERSARY 1 - A curious server colludes with one contact")
    bid = outcome.backup_id
    rec = server.get_record(bid)
    K_real = key_to_int(outcome.sim_master_key)

    step("What the server holds")
    info(f"backup ID, encrypted backup, owner public key, {len(rec.references)} references")
    server.dump(bid)

    step("The references are only hashes of ciphertexts")
    by_fpr = {c.fpr: c for c in contacts}
    refs_ok = True
    for i, ref in enumerate(rec.references, 1):
        c = by_fpr[ref["contact_fpr"]]
        E = c.packages[bid]["E"]
        match = sha256_hex(E) == ref["sha256"]
        refs_ok &= match and set(ref) == {"contact_fpr", "package_id", "sha256"}
        info(f"reference {i}: contact {c.name}, package_id {ref['package_id'][:8]}..., "
             f"sha256 {ref['sha256'][:16]}... = sha256(E{i}) {'yes' if match else 'NO'}")
    print()
    info("a reference holds a contact fingerprint, a random package ID and SHA-256 of a")
    info("ciphertext the server never sees: no share, no key, nothing to decrypt")
    expect("each reference is {contact_fpr, package_id, sha256(E_i)} and nothing else", refs_ok)

    for colluder in contacts:
        step(f"Server + {colluder.name}")
        S = colluder.open_package(bid)
        payload = colluder.read_payload(S)
        x, y = payload["index"], int(payload["share"], 16)
        info(f"{colluder.name} decrypts E{x} -> S{x} and reads the payload inside it")
        show_json(f"{colluder.name}'s payload", json.dumps(payload))

        print()
        refused, why = raises_share_error(lambda: combine([(x, y)]))
        rejected(f"combine([(x{x}, y{x})]): {why}")

        substep(f"every candidate key K' fits a line through (0, K') and (x{x}, y{x})")
        info("slope a = (y - K') * x^-1 mod p,  f'(x) = K' + a*x mod p")
        candidates = [("random K'", secrets.randbelow(2 ** 256)),
                      ("random K'", secrets.randbelow(2 ** 256)),
                      ("K' = 0", 0),
                      ("real K (the coalition can't tell)", K_real)]
        lines_ok = True
        other_x = 1 if x != 1 else 2
        rows = []
        for label, Kc in candidates:
            a = (y - Kc) * pow(x, -1, P) % P
            through_share = (Kc + a * x) % P == y
            # A second point on that line would make combine() return K'.
            gives_Kc = combine([(x, y), (other_x, (Kc + a * other_x) % P)]) == Kc
            lines_ok &= through_share and gives_Kc
            rows.append(f"{label}\n  K'     = {short_hex(Kc)}\n  a      = {short_hex(a)}\n"
                        f"  f'({x}) = y{x}: {'yes' if through_share else 'NO'}    "
                        f"combine with (x{other_x}, f'({other_x})) = K': {'yes' if gives_Kc else 'NO'}")
        block("candidate keys", "\n".join(rows))
        print()
        info(f"exactly one line through (x{x}, y{x}) for each of the p possible values of K',")
        info("so the share is equally consistent with every key")
        expect(f"server + {colluder.name} cannot rebuild K: combine needs two points and every "
               f"candidate K' fits the single share", refused and lines_ok)


def tamper_resign(contact: Contact, backup_id: str, S: str) -> str:
    """Change the share and sign the new payload with the contact's OWN key."""
    payload = contact.read_payload(S)
    payload["share"] = hex((int(payload["share"], 16) + 1) % P)
    S2 = contact.gpg.sign(json.dumps(payload), keyid=contact.fpr, clearsign=False,
                          extra_args=SIGN_ARGS)
    return str(S2)


def tamper_edit_bytes(contact: Contact, backup_id: str, S: str) -> str:
    """Change one hex digit of the share inside S_i, without re-signing."""
    share_hex = contact.read_payload(S)["share"].encode()
    raw = bytearray(dearmor(S))
    pos = raw.find(share_hex) + len(share_hex) - 1
    raw[pos] = ord("1") if raw[pos] != ord("1") else ord("2")
    return enarmor(bytes(raw))


def tamper_other_backup(other_backup_id: str) -> Tamper:
    def t(contact: Contact, backup_id: str, S: str) -> str:
        return contact.open_package(other_backup_id)
    return t


def scenario_adv2(server: Server, outcome: SetupOutcome, contacts: list[Contact],
                  other: Optional[SetupOutcome]) -> None:
    banner("ADVERSARY 2 - A malicious contact")
    alice, bob, carol = contacts
    want = outcome.sim_backup_plaintext
    assert other is not None

    with malicious(bob, tamper_resign):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2a. Bob changes his share and re-signs the payload with his own key")
    expect("re-signed share: valid signature but wrong signer -> rejected",
           res.rejected.get("Bob") == "wrong-signer")
    expect("Carol is asked instead and the backup is restored", res.plaintext == want)

    with malicious(bob, tamper_edit_bytes):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2b. Bob edits the share bytes inside S_i without re-signing")
    expect("edited S_i: GnuPG reports a bad signature -> rejected",
           res.rejected.get("Bob") == "bad-signature")
    expect("Carol is asked instead and the backup is restored", res.plaintext == want)

    with malicious(bob, tamper_other_backup(other.backup_id)):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2c. Bob forwards his share from ANOTHER backup of the same owner")
    expect("share from another backup: valid owner signature but wrong backup_id -> rejected",
           res.rejected.get("Bob") == "wrong-backup")
    expect("Carol is asked instead and the backup is restored", res.plaintext == want)

    with malicious(alice, tamper_resign), malicious(bob, tamper_other_backup(other.backup_id)):
        res = run_recovery(server, outcome, [alice, bob, carol],
                           "2d. Alice (re-signed share) AND Bob (other backup) are malicious")
    expect("only one valid share: the client reports recovery impossible",
           res.aborted == "not enough valid shares" and res.plaintext is None)
    expect("combine() and the backup decryption are never called",
           res.combine_calls == 0 and res.backup_decrypt_calls == 0)

    with malicious(bob, tamper_resign):
        res = run_recovery(server, outcome, [alice, bob],
                           "2e. Control: signature checking OFF, Bob changes his share",
                           verify_signatures=False)
    print()
    info("the client sees that the key is wrong, but not which of the two shares was bad:")
    info("without signatures, Alice and Bob are indistinguishable")
    expect("without signature checks the altered share yields a wrong key",
           res.key is not None and res.key != outcome.sim_master_key)
    expect("... and the symmetric decryption of the backup fails",
           res.backup_decrypt_calls == 1 and res.plaintext is None)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def summary() -> int:
    banner("SUMMARY")
    print()
    for desc, passed in CHECKS:
        print(f"  [{'PASS' if passed else 'FAIL'}] {desc}")
    failed = sum(not p for _, p in CHECKS)
    print(f"\n  {len(CHECKS) - failed}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["all", "tests", "recovery", "adv1", "adv2"], default="all")
    ap.add_argument("--brief", action="store_true",
                    help="shorten long blocks (keys, ciphertexts) to a few lines")
    args = ap.parse_args()
    global BRIEF
    BRIEF = args.brief

    if args.scenario in ("all", "tests"):
        run_unit_tests()
    if args.scenario == "tests":
        return summary()

    if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
        print("GnuPG (gpg, gpgconf) must be installed and in PATH", file=sys.stderr)
        return 2

    banner("SECTION 1 - Setup (original device)")
    server = Server()
    step("Trusted contacts create their own PGP key pairs")
    contacts = [Contact(n) for n in ("Alice", "Bob", "Carol")]
    for c in contacts:
        c.show_keys()

    backup = ("Family photos, password vault export, 2FA backup codes...\n"
              + secrets.token_hex(64)).encode()
    outcome = setup(server, contacts, backup)

    other: Optional[SetupOutcome] = None
    if args.scenario in ("all", "adv2"):
        step("(preparation for adversary 2) a second backup, same owner key and contacts")
        server.verbose = False
        try:
            other = setup(server, contacts, b"another backup", verbose=False, device=outcome.device)
        finally:
            server.verbose = True
        info(f"second backup ID: {other.backup_id}")

    banner("SECTION 2 - The user loses the original device")
    step("2.1 Delete homes/owner, K, the shares and every package")
    home = outcome.device.home
    outcome.device.lose()
    info(f"deleted {os.path.relpath(home, workdir())}/ (including the owner's signing key),")
    info("K, the shares (x, y) and every payload / S_i / E_i the device built")
    info("left: the server's data, the contacts' packages and offline_note.txt")
    expect("the original device holds nothing any more",
           not os.path.exists(home) and outcome.device.gpg is None and not outcome.device.secrets)

    scenarios = {
        "recovery": scenario_recovery,
        "adv1": scenario_adv1,
        "adv2": scenario_adv2,
    }
    for name, fn in scenarios.items():
        if args.scenario in ("all", name):
            fn(server, outcome, contacts, other)

    return summary()


if __name__ == "__main__":
    sys.exit(main())
