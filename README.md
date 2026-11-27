# Trustee key recovery

This project recovers the master key of an encrypted backup with help from trusted contacts, using only standard PGP key pairs. The user gives three contacts one package each. Any two contacts can help the user rebuild the master key on a new device, and no single contact can.

The repository has two simulations of this idea:

| Simulation | How the master key is split | Integrity of the packages |
|---|---|---|
| [`naive-approach/PGP.py`](naive-approach/PGP.py) | Nested PGP encryption with three recovery key pairs | A commitment `SHA-256(domain ‖ backup ID ‖ mk)` on the server |
| [`shamir/shamir.py`](shamir/shamir.py) | Our own 2-of-3 Shamir secret sharing over GF(2⁵²¹ − 1) | Every share is signed by the owner's PGP key, checked against an offline fingerprint |

## Requirements

Both simulations need the same things:

- Python 3.10 or later. They use only the standard library.
- GnuPG 2.2.8 or later, with `gpg` and `gpgconf` on your `PATH`.

Check both with `python3 --version` and `gpg --version`.

### Linux

On Debian or Ubuntu, install GnuPG with `sudo apt install gnupg`. Then run the commands shown under each simulation below.

### macOS

1. Install [Homebrew](https://brew.sh) if you don't have it, then install Python and GnuPG:

   ```bash
   brew install python gnupg
   ```

2. Run the scripts with `TMPDIR=/tmp` in front of the command:

   ```bash
   TMPDIR=/tmp python3 naive-approach/PGP.py
   TMPDIR=/tmp python3 shamir/shamir.py
   ```

   By default macOS puts temporary files in a long folder under `/var/folders/…`. GnuPG creates its agent sockets inside each temporary home, and macOS limits a socket path to 104 characters, so some homes go over the limit and `gpg-agent` won't start. `TMPDIR=/tmp` keeps the paths short. All the other options work the same way, for example `TMPDIR=/tmp python3 shamir/shamir.py --brief`.

### Windows

1. Install Python 3.10 or later from [python.org](https://www.python.org/downloads/windows/). In the installer, tick **Add python.exe to PATH**.
2. Install [Gpg4win](https://gpg4win.org/download.html). It includes GnuPG and adds `gpg` and `gpgconf` to your `PATH`. You only need the GnuPG part, not Kleopatra or the Outlook plugin.

   Both can also be installed from PowerShell with `winget install Python.Python.3.12 GnuPG.Gpg4win`.

3. Open a **new** PowerShell or Command Prompt window, so it picks up the new `PATH`, and check the tools:

   ```powershell
   python --version
   gpg --version
   ```

   If `gpg --version` shows a version older than 2.2.8, `where gpg` shows which `gpg` comes first on your `PATH`. Some other programs ship their own old copy.

4. Go to the project folder and run the scripts with `python` and backslashes:

   ```powershell
   python naive-approach\PGP.py
   python shamir\shamir.py --brief
   ```

   The options are the same as on Linux.

On Linux and macOS the scripts hand each passphrase to `gpg` through a pipe. Python can't pass a pipe to a child process on Windows, so there they write the passphrase to a file in the actor's temporary GnuPG home, which only you can read, and delete it as soon as `gpg` has read it.

The scripts also run in WSL (Windows Subsystem for Linux): install Ubuntu with `wsl --install`, then follow the Linux steps. Windows drives are under `/mnt`, so `C:\Users\you\trustee-key-recovery` is `/mnt/c/Users/you/trustee-key-recovery`.

Neither script touches your own `~/.gnupg`. Each actor gets its own temporary GnuPG home directory in the system temp folder: the user's old device, the new device, each contact and the attacker. Each directory is deleted, and its `gpg-agent` stopped, as soon as it's no longer needed or when the script exits.

All cryptography other than the secret sharing is done by real GnuPG. Keys are ed25519 for signing and cv25519 for encryption. Messages are encrypted with integrity protection (MDC), so gpg rejects any modified ciphertext.

## Naive approach: nested PGP encryption

### Running the simulation

```bash
python3 naive-approach/PGP.py                       # run every scenario
python3 naive-approach/PGP.py --scenario recovery   # setup + normal recovery only
python3 naive-approach/PGP.py --scenario adv1       # curious server + one contact
python3 naive-approach/PGP.py --scenario adv2       # malicious contact
python3 naive-approach/PGP.py --scenario adv3       # false recovery request
python3 naive-approach/PGP.py --brief              # same output, long keys/ciphertexts shortened
```

Setup always runs first, because every scenario depends on it. A full run takes a few seconds and prints every key (public and private), ciphertext, decryption result and everything posted to the server, so the output is long; add `--brief` to cut each long block down to a few lines. It ends with a summary of every check and exits with code `0` if all checks pass, or `1` if any fails.

Besides the per-actor homes, this script also creates a short-lived keyring for every layer it peels.

### 1. Setup

1. **Backup encryption.** The script generates a random 256-bit master key `mk` and a backup ID. It encrypts the backup as an AES-256 PGP message with integrity protection. The server stores the encrypted backup, the backup ID and the commitment `SHA-256(domain ‖ backup ID ‖ mk)`.
2. **Recovery keys.** The script generates three PGP key pairs, K₁, K₂ and K₃.
3. **Threshold ciphertexts.**
   - `C_A = Enc_K1( Enc_{K2,K3}(mk) )`
   - `C_B = Enc_K2( Enc_K3(mk) )`
4. **Contact keys.** Alice, Bob and Carol send their public keys. The user compares each fingerprint with the one the contact reads out out of band.
5. **Packages.** Each package is encrypted to its contact's key and published on the server:

   | Package | Encrypted to | Contents |
   |---|---|---|
   | A | Alice | K₁, C_A, backup ID, index 1 |
   | B | Bob   | K₂, C_B, backup ID, index 2 |
   | C | Carol | K₃, backup ID, index 3 |

6. **Cleanup.** The script deletes K₁, K₂, K₃, both ciphertexts and every plaintext package from the user's device. It then checks that no recovery private key is left on the device, and that no recovery key or master key is on the server in plaintext.

Then the original device is wiped, which models the user losing it.

### 2. Recovery (milestone)

The script runs the recovery once for each pair: A+B, A+C and B+C.

1. The new device creates a new key pair N.
2. The user sends `N_pub` directly to two contacts. Each contact checks the fingerprint with the user out of band, by calling the user on a number they already know.
3. Each contact decrypts their own package and forwards it, encrypted to `N_pub`.
4. The client decrypts the replies. It rejects any reply with the wrong backup ID, an invalid index, or a ciphertext where none belongs (or none where one belongs). It never combines two packages that claim the same index. It then peels the layers, using only one recovery key per layer:
   - **A + B:** decrypt C_A with K₁, then with K₂
   - **A + C:** decrypt C_A with K₁, then with K₃
   - **B + C:** decrypt C_B with K₂, then with K₃
5. The client compares the rebuilt key with the commitment. Only if it matches does the client decrypt the backup. The script then checks that the restored backup equals the original.

### Adversary models

**Adversary 1: a curious server colludes with one contact.** For each contact in turn, the script gives the coalition every private key the contact holds and every ciphertext the pair has seen. It then peels every layer it can until nothing new comes out. No coalition gets the master key:

- The contact can't open the other contacts' packages.
- One recovery key removes only the outer layer, and the inner layer needs a second, different key.
- Carol holds K₃ but no ciphertext to use it on.

**Adversary 2: a malicious contact.**

| Case | What the contact does | Result |
|---|---|---|
| 2a | Bob forwards his package from another backup | rejected for the wrong backup ID; recovery stops |
| 2b | Bob relabels his package as index 1 | rejected for the repeated index; recovery stops |
| 2c | Alice replaces C_A with a well-formed ciphertext of a fake key | the rebuilt key fails the commitment check |
| 2d | Bob flips one bit of C_B | gpg refuses to decrypt it |
| 2e | All three answer; Alice's C_A is forged | A+B and A+C fail, B+C passes; the backup is restored and Alice is named as malicious |
| 2f | All three answer; Carol sends a fake K₃ | A+C and B+C fail, A+B passes; the backup is restored and Carol is named as malicious |
| 2g | Bob uses the wrong backup and Carol sends a fake K₃ | fewer than two valid packages; recovery stops without using any unverified key |

In 2c and 2e, the forging contact is assumed to know the recovery *public* keys. This is the worst case: without them, the forgery becomes a decryption failure instead of a failed commitment check.

**Adversary 3: a false recovery request.**

- **3a:** Mallory sends the contacts her own public key and claims to be the user. Each contact calls the real user, who never asked for a recovery, so both contacts refuse.
- **3b:** The real user is recovering but sends `N_pub` through the server, and the server swaps in Mallory's key. The fingerprint the user reads out doesn't match the key the contacts received, so they refuse. This is why contacts must never get `N_pub`, or check it, through the server.
- **3c:** The contacts skip the identity check. Mallory rebuilds the master key and decrypts the victim's backup. The commitment check doesn't help here, because it proves the key is correct, not who is asking for it.

## Shamir approach: secret sharing + owner signatures

[`shamir/shamir.py`](shamir/shamir.py) replaces the nested encryption with Shamir secret sharing. The master key K is split into three points on a random line; any two points determine the line and so K, while one point is consistent with every possible key. Each share is signed by the owner, so the new device can tell a genuine share from a forged one and name the contact who forged it.

### Running the simulation

```bash
python3 shamir/shamir.py                        # run everything
python3 shamir/shamir.py --scenario tests       # Shamir unit tests only (no GnuPG needed)
python3 shamir/shamir.py --scenario recovery    # setup + normal recovery only
python3 shamir/shamir.py --scenario adv1        # curious server + one contact
python3 shamir/shamir.py --scenario adv2        # malicious contact
python3 shamir/shamir.py --brief                # same output, long keys/ciphertexts shortened
```

A full run takes about five seconds. The output is organised in sections:

| Section | What it shows |
|---|---|
| 0 | Unit tests of the Shamir implementation (runs with `all` and `tests`) |
| 1 | Setup on the original device: keys, the split, every package and everything posted to the server |
| 2 | The user loses the original device |
| 3 | Recovery on a new device (`recovery`) |
| Adversary 1 | A curious server colludes with one contact (`adv1`) |
| Adversary 2 | A malicious contact (`adv2`) |
| Summary | Every check, `PASS` or `FAIL` |

Every scenario except `tests` runs sections 1 and 2 first, because it depends on them. Like the naive script, it prints every key, ciphertext and server post (`--brief` shortens them), and exits with code `0` if all checks pass, `1` if any fails, or `2` if GnuPG is missing.

### The Shamir implementation

The secret sharing is our own code (`split`, `combine`, `key_to_int` and `int_to_key` in [`shamir/shamir.py`](shamir/shamir.py)), written with Python's built-in big integers. GnuPG plays no part in it.

**The field.** All arithmetic is modulo the Mersenne prime

```
p = 2^521 − 1
```

Because p is prime, the integers mod p form a field, GF(p): every non-zero value has an inverse, which Lagrange interpolation needs. p is far larger than 2²⁵⁶, so every 256-bit key is already a field element and is never reduced. Each share value y is a number in `[0, p)`, up to 521 bits long.

**Encoding the key.** The 32-byte key K is read as a big-endian integer (`key_to_int`), and turned back into 32 bytes after recovery (`int_to_key`). `int_to_key` refuses any value of 2²⁵⁶ or more, because that cannot be a key.

**Splitting (`split`).** For a k-of-n split, the script builds a random polynomial of degree k − 1 whose constant term is the secret, and evaluates it at x = 1, …, n with Horner's rule. With the defaults k = 2 and n = 3 this is a line:

```
f(x) = K + a₁·x  (mod p),   a₁ = secrets.randbelow(p)

share i = (i, f(i))   for i = 1, 2, 3
```

The coefficient a₁ is drawn uniformly from the *whole* field with the `secrets` module (a cryptographically secure generator). That is what makes a single share reveal nothing (see below). `split` refuses a secret outside `[0, p)` and parameters that don't satisfy `2 ≤ k ≤ n < p`.

**Combining (`combine`).** The secret is f(0), recovered by Lagrange interpolation at x = 0:

```
K = f(0) = Σᵢ yᵢ · Πⱼ≠ᵢ (0 − xⱼ) / (xᵢ − xⱼ)   (mod p)
```

Division is multiplication by the modular inverse, `pow(xᵢ − xⱼ, -1, p)`. For two shares the formula reduces to `K = (y₁·x₂ − y₂·x₁) / (x₂ − x₁) mod p`. Before interpolating, `combine` rejects:

- anything that isn't a pair of integers (booleans included),
- index 0, because f(0) is the secret itself,
- an index outside `[1, p)`, or the same index twice (it would make `xᵢ − xⱼ = 0`, which has no inverse),
- a value outside `[0, p)`,
- fewer than k shares.

**Why one share reveals nothing.** Take one share (x, y) and any candidate key K′. Exactly one line passes through both (0, K′) and (x, y), with slope `a = (y − K′) · x⁻¹ mod p`. Since a₁ was chosen uniformly at random, every K′ is equally likely given the share: one share carries no information about K. Adversary 1 demonstrates this with real shares.

**Why shares must be authenticated.** Shamir sharing alone does not detect a wrong share; it just returns a different number. For example, if Bob adds 1 to his share y₂ and the client combines it with Alice's share, Bob's Lagrange coefficient is (0 − 1)/(2 − 1) = −1, so the result is K − 1: a perfectly well-formed 32-byte key that is simply wrong. The client only learns this when the backup fails to decrypt, and it can't tell which contact cheated. That is why every share is signed by the owner (scenario 2e shows what happens without the signature check).

**Unit tests (section 0).** The script checks that:

- `int_to_key(key_to_int(K)) == K`;
- every pair of shares, and all three together, rebuild K, for one key and for 200 more random keys;
- `combine` refuses a single share, and no share value equals the key;
- adding 1 to any share never yields K;
- `combine` rejects repeated indexes, index 0, a negative index, a value equal to p and a negative value;
- `int_to_key(p − 1)` is refused because it doesn't fit in 32 bytes.

### 1. Setup (original device)

1. **Master key and backup.** The script generates a random 256-bit key K and a backup ID (a UUID). GnuPG encrypts the backup symmetrically with AES-256 and MDC, using `K.hex()` as the passphrase. The server stores the encrypted backup and its ID.
2. **Trust anchor.** The original device creates the owner's signing key pair and writes its fingerprint to `offline_note.txt`, which stands in for a printed sheet the user keeps at home. The owner's public key is posted to the server too, but it is trusted only if its fingerprint matches the note.
3. **Contact keys.** Alice, Bob and Carol send their public keys. The user compares each fingerprint with the one the contact reads out out of band.
4. **Split.** K is split into three 2-of-3 shares, as described above.
5. **Packages.** Package i is built in layers:

   ```
   payload_i = JSON {backup_id, index: i, share: hex(y_i)}
   S_i       = Sign_owner(payload_i)      opaque signed message
   E_i       = Enc_contact_i(S_i)         delivered directly to contact i
   server    : {contact_fpr, package_id, sha256(E_i)}
   ```

   | Package | Encrypted to | Payload |
   |---|---|---|
   | E₁ | Alice | backup ID, index 1, y₁ |
   | E₂ | Bob   | backup ID, index 2, y₂ |
   | E₃ | Carol | backup ID, index 3, y₃ |

   The server never receives a package, only a reference: the contact's fingerprint, a random package ID and the SHA-256 of E_i. The script checks that neither K nor any share value appears anywhere on the server.

   S_i is signed without compression (`--compress-algo none`), so the payload bytes sit in the clear inside the signed message. That only exists so that adversary 2b can edit them and get a clean "bad signature" result.

### 2. Losing the device

The script deletes the owner's GnuPG home (including the owner's signing key), K, the shares and every payload, S_i and E_i the device built, and checks that nothing is left. What remains is the server's data, the contacts' packages and `offline_note.txt`.

### 3. Recovery (new device)

The script runs the recovery once for each pair: Alice + Bob, Alice + Carol and Bob + Carol.

1. **New identity.** The new device creates a key pair N and reads the owner's fingerprint from the offline note.
2. **Owner key.** It downloads the encrypted backup, the references and the owner's public key. If the key's fingerprint doesn't match the offline note, it stops before contacting anyone.
3. **Request.** The user sends `N_pub` directly to two contacts. Each contact checks the fingerprint with the user out of band, decrypts E_i with their own key, and sends S_i back re-encrypted to N, *unchanged*: the owner's signature is never stripped. A third contact is asked only if fewer than two valid shares have arrived.
4. **Checks.** For each reply, the client decrypts it with N and has GnuPG verify S_i. It accepts the share only if:
   - the signature is valid (`GOODSIG` and `VALIDSIG`, no `BADSIG` or `ERRSIG`);
   - the signer is the owner key in the offline note;
   - the payload is a JSON object with this backup's ID;
   - the index is 1, 2 or 3 and hasn't been received already;
   - the share is a hex integer in `[0, p)`.
5. **Rebuild.** With two accepted shares, the client calls `combine` and `int_to_key`. With fewer, it reports that recovery is impossible and never calls `combine`.
6. **Restore.** The client decrypts the backup with `K.hex()`; GnuPG's MDC check confirms the key is right. The script then checks that the restored backup equals the original.

A last run has the server serve Mallory's key, with the owner's name on it, as the owner's public key. Its fingerprint doesn't match the offline note, so the client aborts at step 2 and no contact is ever asked.

### Adversary models

**Adversary 1: a curious server colludes with one contact.** The script prints everything the server holds and checks that each reference is only `{contact_fpr, package_id, sha256(E_i)}`: a hash of a ciphertext the server never sees. Then, for each contact in turn, the contact opens their own package and reads their share. `combine` refuses a single share. To show that the share says nothing about K, the script takes several candidate keys (two random ones, 0 and the real K), computes for each the line through (0, K′) and the share, and checks that the line passes through the share and that `combine` with a second point on it returns K′. Every candidate fits equally well, so the coalition can't tell the real key from any other.

**Adversary 2: a malicious contact.** In every case the client asks Alice and Bob first, and Carol only if needed.

| Case | What the contact does | Result |
|---|---|---|
| 2a | Bob changes his share and re-signs the payload with his own key | valid signature, but not by the owner: rejected; Carol is asked and the backup is restored |
| 2b | Bob edits the share's bytes inside S_i without re-signing | GnuPG reports a bad signature: rejected; Carol is asked and the backup is restored |
| 2c | Bob forwards his share from another backup by the same owner | valid owner signature, but the wrong backup ID: rejected; Carol is asked and the backup is restored |
| 2d | Alice re-signs a changed share and Bob forwards another backup's share | only one valid share: recovery is reported impossible; `combine` and the backup decryption are never called |
| 2e | Control: signature checking is off and Bob changes his share | the client rebuilds a wrong key and the backup fails to decrypt, but it can't tell whether Alice or Bob cheated |

For 2c and 2d the script creates a second backup during setup, with the same owner key and the same contacts.

A false recovery request (adversary 3 in the naive approach) is handled the same way here: a contact sends S_i only if the fingerprint of the offered key matches the one the user reads out. `shamir.py` doesn't simulate it again.

### Differences from the naive approach

- **Splitting.** Shamir shares replace the nested ciphertexts and the three recovery key pairs. Every contact holds the same kind of package, and the scheme generalises to any k-of-n by changing two parameters.
- **Integrity.** The owner's signature replaces the commitment on the server. A forged share is rejected on its own, before anything is combined, so the client knows which contact cheated and can ask the third one. In the naive approach, a forgery is found only when a combination fails the commitment check.
- **Server.** The server stores only a hash of each package, not the package itself.
- **New trust anchor.** The client must know the owner's fingerprint from the offline note. If the note is lost or altered, the client can't tell genuine shares from forged ones.

## Limitations

- Phone calls and in-person checks are modelled as a function that returns the fingerprint the real user reads out.
- Replies from contacts aren't signed. The client knows who sent a reply only from the channel it arrived on.
- The backup is encrypted as a PGP symmetric message, with the master key as the passphrase, instead of with AES-GCM. The task allows either.
- In the Shamir approach, the offline note must stay authentic, though not secret: it holds only a fingerprint. The owner's signing key is lost with the device, so new backups need a new key pair and a new note.
- The Shamir arithmetic uses Python's big integers, which are not constant-time. That is fine for a simulation, not for production code.
