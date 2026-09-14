# Magpie

Docker Hub: [kylemc54321/assemblyline-service-magpie](https://hub.docker.com/r/kylemc54321/assemblyline-service-magpie)

An [Assemblyline 4](https://cybercentrecanada.github.io/assemblyline4_docs/) static analysis service that extracts high-value indicators from **any file type** by scanning printable strings (narrow and wide) — the only one of this author's AL4 services that ever sees compiled binaries (PayloadFetcher/BashSim/PhpSim are all scoped to script source), so its detection categories lean into artifacts that only show up as raw strings in a PE/ELF: debug-path leaks, dangerous API name strings, anti-VM artifacts, alongside the usual network/crypto/credential IOCs.

## What it detects

| Category | Detail | Heuristic | Score |
|---|---|---|---|
| Cryptocurrency wallets | Bitcoin (P2PKH, P2SH, bech32), Ethereum, Monero | 1 | 500 |
| Mining pool connections | `stratum+tcp://` and `stratum+ssl://` URIs | 2 | 750 |
| Credential patterns | `password=`/`passwd=`/`pwd=` (100, placeholder values suppressed) and `user:pass@host` (400) | 3 | 100 / 400 |
| Suspicious IPs | Public IPv4/IPv6 with known mining or C2 ports | 4 | 300 |
| Onion addresses | Tor v2 and v3 `.onion` addresses | 5 | 500 |
| Shell dropper commands | `wget`/`curl` + `chmod +x` on the same line | 6 | 500 |
| Cloud metadata (IMDS) access | AWS/Azure/GCP instance metadata endpoint references | 7 | 600 |
| PDB debug paths | Windows PDB paths -- leaks the build machine username/project | 8 | 100 |
| Suspicious Win32 API usage | Curated process-injection/anti-debug/credential-access/hooking API strings | 9 | 50-500 |
| Anti-VM / anti-sandbox artifacts | VMware/VBox/Sandboxie/QEMU-style strings | 10 | 150 |
| Modern C2/exfil channels | Discord webhook URLs, Telegram bot URLs/tokens, pastebin raw links | 11 | 250-450 |
| Ransom note language | Ransom-note-shaped phrases, scored higher when paired with a wallet/onion hit | 12 | 150 / 500 |
| Email addresses | RFC-style email addresses (informational, no score) | — | — |
| Suspicious staging/drop paths | `/dev/shm/`, `/var/tmp/`, `AppData\Local\Temp\`, etc. (informational, no score) | — | — |
| User-Agent strings | Hardcoded HTTP User-Agent strings (informational, no score) | — | — |

## How it works

Rather than scanning raw binary bytes (which produces false positives), Magpie first extracts printable strings from the file — both narrow (ASCII) and wide (UTF-16LE) — mirroring the behaviour of the Unix `strings` command. All pattern matching is then performed against the extracted strings only.

This approach correctly handles files where strings are stored as plaintext in the binary (PE resources, ELF `.rodata`, scripts) and avoids false positives from binary data coincidentally matching IP or credential patterns.

IPv6 detection is a two-stage design: a coarse regex locates candidate spans (deliberately over-matching), then `ipaddress.ip_address()` validates and normalizes each candidate — this avoids the truncation bugs a single monolithic "handle every compression form" regex is prone to.

## Safety

No execution risk at all — pure regex matching over `mmap`'d file bytes, no subprocess/eval/network calls anywhere in this service.

## Tags emitted

- `network.static.ip`, `network.port`, `network.email.address`, `network.static.uri`, `network.user_agent`
- `file.pe.pdb_filename`, `file.pe.api_vector`
- `file.string.extracted`

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install pytest assemblyline-v4-service assemblyline-service-utilities
.venv/bin/pytest test/
```

No test in this repo uses real/live malicious IOCs. One Magpie-specific wrinkle:
Python's `ipaddress` module classifies RFC 5737/3849 documentation-range addresses
as `is_private`, and Magpie's own filtering logic correctly excludes them — so tests
asserting "this IP is surfaced" use a well-known benign public address (e.g.
`8.8.8.8`) instead of a documentation-range placeholder, documented inline in the
test file.

## License

[MIT](LICENSE)
