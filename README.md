# wallet2hash

Turn a cryptocurrency wallet file into a password-cracking hash line, fully offline.

If you've found an old `wallet.dat`, an Electrum file, or a `keystore.json` and
forgotten the password, there are three steps between you and recovering it:
figure out what the file actually is, pull out the smallest piece of it that
proves a password, and put that piece in the exact shape your cracking tool
expects. That's all this tool does.

```text
$ wallet2hash keystore.json

Detected wallet: Ethereum UTC/JSON keystore V3
Suitable for:
  - Hashcat
  - John the Ripper

This wallet can be exported for both Hashcat and John the Ripper.
Please choose an output format:

  wallet2hash keystore.json --format hashcat
  wallet2hash keystore.json --format john
  wallet2hash keystore.json --format all
```

`wallet2hash` exports password-verification material to **Hashcat** and/or
**John the Ripper Jumbo**. It detects the wallet, picks the smallest proof of the
password, and emits the exact hash line those tools accept. No network calls, no
uploads, no telemetry, and it never prints a private key or seed.

## What this tool is not

```text
wallet2hash does not recover passwords.
wallet2hash does not crack wallets.
wallet2hash does not extract private keys or seed phrases.
wallet2hash only extracts password-verification material from encrypted wallet
files and exports it as a Hashcat-compatible or John-the-Ripper-compatible hash
line.
```

There is no wordlist, mask, rule, GPU kernel, or attack loop anywhere in this
project. The actual password search is done by Hashcat or John, using the line
this tool prints.

## Install

Python 3.8 or newer. The core has no dependencies at all:

```bash
pip install .
```

Two optional extras cover formats that need a specific library for `--verify`:

```bash
pip install ".[bdb]"      # berkeleydb  — faster Bitcoin Core wallet.dat reads
pip install ".[crypto]"   # pycryptodome + cryptography — AES-GCM / scrypt verification paths
pip install ".[dev]"      # pytest — running the test suite
```

Everything still works without the extras; the affected checks just report
`UNSUPPORTED` instead of guessing.

## Usage

```bash
wallet2hash wallet.dat                      # detect + auto-export (default)
wallet2hash wallet.dat --format hashcat     # Hashcat hash only
wallet2hash wallet.dat --format john        # John the Ripper hash only
wallet2hash wallet.dat --format all         # both, with labels
wallet2hash wallet.dat --format auto        # explicit auto behavior
wallet2hash wallet.dat --hashcat            # bare hash, for piping
wallet2hash wallet.dat --hashcat-with-mode  # "11300:$bitcoin$…"
wallet2hash wallet.dat --type electrum      # force a wallet format
wallet2hash wallet.dat --verify             # one-shot password check

wallet2hash inspect wallet.dat              # format metadata
wallet2hash list-formats                    # registered wallet formats
wallet2hash list-targets                    # hashcat / john
wallet2hash self-test                       # built-in pipeline check
```

### Auto behavior

`wallet2hash <file>` (or `--format auto`) follows these rules:

| Export targets available | Result |
| ------------------------ | ------ |
| none | prints `Suitable for: none` and stops |
| one (Hashcat *or* John) | prints that hash immediately |
| both | does **not** choose; asks you to pick `--format hashcat`, `john`, or `all` |

It never silently guesses which target you want.

## Supported formats

| Wallet | Artifact | Hashcat | John |
| ------ | -------- | ------- | ---- |
| Bitcoin / Litecoin / Dogecoin Core | `wallet.dat` (BDB + SQLite) | 11300 | `bitcoin` |
| Electrum | wallet JSON (salt 1–5) | 16600 / 21700 / 21800 | `electrum` |
| Ethereum keystore | UTC/JSON V3 (pbkdf2/scrypt) | 15600 / 15700 | `ethereum` |
| Ethereum pre-sale | pre-sale JSON | 16300 | `ethereum` |
| Trust Wallet | cloud backup JSON (incl. legacy empty-salt) | 15600 / 15700 | `ethereum` |
| Blockchain.com | `wallet.aes.json` (V0.0 raw, V1–V4) | 12700 / 15200 / 34700 | `blockchain` |
| Blockchain.com | legacy 2nd-password `dpasswordhash` (`bs:` blob) | 18800 | `blockchain` |
| MultiBit Classic | `.key` backup | 22500 | `multibit` |
| MultiBit HD | `.aes` backup | 22700 | `multibit` |
| MultiBit Classic | `.wallet` (bitcoinj protobuf) | 27700 | `multibit` |
| MetaMask | extension vault JSON | 26600 / 26610 | — |
| MetaMask Mobile | persist-root vault (`lib: original`) | 31900 | — |
| Exodus | `exodus.seco` | 28200 | — |
| Bisq | `.wallet` (bitcoinj protobuf) | 29800 | — |
| Dogechain.info | wallet JSON (CBC; GCM verify-only) | 32500 | — |
| BitShares | LevelDB `checksum` / wallet JSON | 21000 | `dynamic_84` / `BitShares` |
| Terra Station | extension `keys` JSON (localStorage export) | 29600 | — |
| Monero | `wallet.keys` | — | `monero` |
| BIP-38 key | `6P…` base58 | — | — |

Hashcat's full cryptocurrency-wallet mode list is 35 modes; every mode that
maps to a password-protected wallet artifact is either implemented above or
catalogued with an honest status in [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)
(the raw-private-key modes 28501–28506 / 30901–30906 are not password formats
and are out of scope; Stargazer 25500 is documented but **not claimed** because
its wallet source is no longer reachable, so the on-disk schema cannot be
verified). Every implemented row above is validated against both a synthetic
fixture in the test suite and — for the formats that have one — a real
encrypted wallet from a public open-source test-wallet suite.

### Format quirks worth knowing

- **Trust Wallet legacy backups (pre-2024):** some old cloud backups carry an
  *empty* salt. Hashcat's Ethereum modes (15600/15700) require a 32-byte salt,
  so for those files wallet2hash emits **no hash line** and is verify-only:
  `--verify` still tells you whether a password is correct, but the file cannot
  be cracked with Hashcat as-is. The tool says this explicitly in `--inspect`;
  it never emits a line Hashcat would silently reject.
- **Stargazer (25500):** the mode exists in Hashcat, but the wallet's source is
  gone, so the on-disk format cannot be verified — wallet2hash deliberately
  ships no extractor rather than guess.

## On not guessing

Wallet formats change between versions in ways that look identical from the
outside. A wrong hash means hours of wasted cracking. So the rule is simple:
nothing is called supported until a synthetic fixture validates it. `UNSUPPORTED`
is a feature, not a gap.

Each handler cites where its format knowledge came from — wallet source code,
Hashcat's `src/modules/module_*.c`, or a John the Ripper `*2john.py` converter —
and the CLI prints those references so the work is auditable.

## Security

Treat `--hashcat` / `--format` output like the wallet file itself. It's
everything an attacker needs to brute-force the password offline.

- No network requests, ever.
- No source wallet file is modified.
- No decrypted data is written to disk.
- No keys, seeds, or decrypted contents are printed.
- Built to run air-gapped.

`--redact` shortens hash material in human output, and `--no-color` is accepted
for automation.

## Contributing

Adding a wallet is one file under `wallet2hash/formats/` plus a registration
line. The template and the rules live in
[docs/ADDING_A_FORMAT.md](docs/ADDING_A_FORMAT.md).

## License

MIT.

---

Built by [Crypto Recovers](https://cryptorecovers.com/) — the company behind
[forgotwalletpassword.com](https://forgotwalletpassword.com/), where we write
wallet-password recovery guides and education.
