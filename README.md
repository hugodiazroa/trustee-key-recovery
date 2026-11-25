# Trustee key recovery

This project recovers the master key of an encrypted backup with help from trusted contacts, using only standard PGP key pairs. The user gives three contacts one package each. Any two contacts can help the user rebuild the master key on a new device, and no single contact can.

## Running the simulation

The simulation is [`naive-approach/PGP.py`](naive-approach/PGP.py).

**Requirements**

- Python 3.10 or later. It uses only the standard library.
- GnuPG 2.2.8 or later, with `gpg` and `gpgconf` on your `PATH`. On Debian or Ubuntu, install it with `sudo apt install gnupg`.

**Commands**

```bash
python3 naive-approach/PGP.py                       # run every scenario
python3 naive-approach/PGP.py --scenario recovery   # setup + normal recovery only
python3 naive-approach/PGP.py --scenario adv1       # curious server + one contact
python3 naive-approach/PGP.py --scenario adv2       # malicious contact
python3 naive-approach/PGP.py --scenario adv3       # false recovery request
python3 naive-approach/PGP.py --brief              # same output, long keys/ciphertexts shortened
```

Setup always runs first, because every scenario depends on it. A full run takes a few seconds and prints every key (public and private), ciphertext, decryption result and everything posted to the server, so the output is long; add `--brief` to cut each long block down to a few lines. It ends with a summary of every check and exits with code `0` if all checks pass, or `1` if any fails.

The script never touches your own `~/.gnupg`. Each actor gets its own temporary GnuPG home directory in the system temp folder: the user's old device, the new device, each contact, the attacker, and every short-lived keyring used to peel one layer. Each directory is deleted, and its `gpg-agent` stopped, as soon as it's no longer needed or when the script exits.

## What the simulation does

All cryptography is done by real GnuPG. Keys are ed25519 for signing and cv25519 for encryption. Messages are encrypted with integrity protection (MDC), so gpg rejects any modified ciphertext.

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

## Limitations

- Phone calls and in-person checks are modelled as a function that returns the fingerprint the real user reads out.
- Replies from contacts aren't signed. The client knows who sent a reply only from the channel it arrived on.
- The backup is encrypted as a PGP symmetric message, with the master key as the passphrase, instead of with AES-GCM. The task allows either.
