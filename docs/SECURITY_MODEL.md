# Security model

`wallet2hash` is a read-only, offline converter. Its threat model is simple and
deliberately narrow.

## What the tool does

1. Read the wallet file the user points at.
2. Identify the wallet and its encryption version.
3. Extract the *minimum* password-verification material (KDF parameters, salt,
   iteration count, IV, MAC, encrypted check material).
4. Serialize that material as a Hashcat- and/or John-the-Ripper-compatible line.

## Hard guarantees

- **No network access.** The code never opens a socket, makes an HTTP request,
  sends telemetry, or phones home. It runs air-gapped.
- **Never modifies the source file.** Every read opens the file read-only; no
  code path writes, truncates, or rewrites the input.
- **Never decrypts wallet contents.** Decryption of the private keys, seeds, or
  balances is out of scope. The only "decryption" that exists is the `--verify`
  one-shot password check, which only produces `VALID`/`INVALID` and discards the
  result.
- **Never extracts private keys or seeds.** The normalized
  `PasswordVerifier` object contains only the bytes needed to build a crackable
  hash line — never a key, mnemonic, or decrypted payload.

## What the output is

The extracted hash line is *itself* sensitive. It contains everything an attacker
needs to brute-force the password offline. Treat it exactly like the wallet file:
store it safely, and don't paste it anywhere you wouldn't paste the wallet.

`--redact` shortens hash material in human-readable output, and `--no-color` is
accepted for automation. Neither is a substitute for handling the raw hash line
carefully — it is the secret.

## Inputs

- A single wallet file path supplied by the user. The tool never scans
  directories, never follows a file the user did not name, and never reads
  hardware wallets, browser storage, or other system locations.

## Not included by design

- No cracking loop, wordlist, mask, rule, or GPU code.
- No fund movement, address derivation for theft, or transaction signing.
- No upload, cloud sync, or remote wallet service integration.

## Report generation

Human-readable output uses the `Inspection` / `PasswordVerifier` objects'
`redacted_summary()` so logs contain types and byte lengths, never the secret
material itself.
