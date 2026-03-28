# Magpie

An [Assemblyline 4](https://cybercentrecanada.github.io/assemblyline4_docs/) static analysis service that extracts high-value indicators from any file type by scanning printable strings (narrow and wide) for cryptocurrency artifacts, network IOCs, and credential patterns.

## What it detects

| Category | Detail | Heuristic | Score |
|---|---|---|---|
| Cryptocurrency wallets | Bitcoin (P2PKH, P2SH, bech32 — checksum validated), Ethereum, Monero | 1 | 500 |
| Mining pool connections | `stratum+tcp://` and `stratum+ssl://` URIs | 2 | 750 |
| Credential patterns | `password=`, `passwd=`, `pwd=`, and `user:pass@host` | 3 | 400 |
| Suspicious IPs | Public IPv4/IPv6 with known mining or C2 ports | 4 | 300 |
| Onion addresses | Tor v2 and v3 `.onion` addresses | 5 | 500 |
| Email addresses | RFC-style email addresses (informational, no score) | — | — |

## How it works

Rather than scanning raw binary bytes (which produces false positives), Magpie first extracts printable strings from the file — both narrow (ASCII) and wide (UTF-16LE) — mirroring the behaviour of the Unix `strings` command. All pattern matching is then performed against the extracted strings only.

This approach correctly handles files where strings are stored as plaintext in the binary (PE resources, ELF `.rodata`, scripts) and avoids false positives from binary data coincidentally matching IP or credential patterns.

## Tags emitted

- `network.static.ip`
- `network.port`
- `network.email.address`
- `file.string.extracted`

## Docker

```
kylemc4321/assemblyline-service-magpie:<version>
```

## License

[MIT](LICENSE)
