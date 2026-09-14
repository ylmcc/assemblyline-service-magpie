"""Pure extraction functions for Magpie -- no AL/ServiceBase imports, no network,
no execution of any kind. Directly unit-testable. Operates on a flat bytes blob of
newline-joined printable strings (see build_string_blob) extracted from a file's
raw content, mirroring what `strings` does.
"""
from __future__ import annotations

import ipaddress
from itertools import chain

from . import patterns as p


def build_string_blob(raw: bytes) -> bytes:
    """Extract printable strings (narrow ASCII + wide UTF-16LE) and join as a flat
    byte string separated by newlines so regexes don't stitch across string
    boundaries -- mirrors what `strings` does and avoids false positives from
    binary data."""
    narrow = (m.group(0) for m in p.RE_STRINGS_NARROW.finditer(raw))
    wide = (m.group(0).replace(b'\x00', b'') for m in p.RE_STRINGS_WIDE.finditer(raw))
    return b'\n'.join(chain(narrow, wide))


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified
    except ValueError:
        return True


def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        parts = [int(x) for x in ip_str.split('.')]
        return len(parts) == 4 and all(0 <= x <= 255 for x in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Cryptocurrency / mining
# ---------------------------------------------------------------------------

def extract_wallets(data: bytes) -> list[tuple[str, str]]:
    results = []
    seen = set()
    for m in p.RE_BTC.finditer(data):
        addr = m.group(0).decode('ascii', errors='ignore')
        if addr not in seen:
            seen.add(addr)
            results.append(("BTC", addr))
    for m in p.RE_ETH.finditer(data):
        addr = m.group(0).decode('ascii', errors='ignore')
        if addr not in seen:
            seen.add(addr)
            results.append(("ETH", addr))
    for m in p.RE_XMR.finditer(data):
        addr = m.group(0).decode('ascii', errors='ignore')
        if addr not in seen:
            seen.add(addr)
            results.append(("XMR", addr))
    return results


def extract_stratum(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_STRATUM.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore').rstrip('\x00')
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


# ---------------------------------------------------------------------------
# Network indicators
# ---------------------------------------------------------------------------

def _iter_ipv6_candidates(data: bytes):
    """Yields (ip_str, port_str) for syntactically valid IPv6 candidates, WITHOUT
    applying the private/loopback/global filter -- kept separate so the regex's
    correctness (no truncation) is independently testable from the filtering
    policy applied in extract_ips()."""
    for m in p.RE_IPV6_CANDIDATE.finditer(data):
        raw = m.group(1).decode('ascii', errors='ignore')
        port_str = m.group(2).decode('ascii') if m.group(2) else ""
        bracketed = raw.startswith('[') and raw.endswith(']')
        ip_str = raw.strip('[]')
        # Reject degenerate shorthand noise (e.g. "a::") that is syntactically
        # legal per RFC 4291 but carries essentially no information content.
        if len(ip_str.replace(':', '')) < 4:
            continue
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if addr.version != 6:
            continue
        if not bracketed:
            # Unbracketed "addr:NNN" is ambiguous with address syntax; only
            # trust a port when RFC 3986 brackets disambiguate it.
            port_str = ""
        yield str(addr), port_str


def extract_ips(data: bytes) -> list[tuple[str, str, bool]]:
    """IPv4 + IPv6, with the private/loopback/global filter applied. Returns
    (ip, port, suspicious) where suspicious means a known mining port."""
    seen = set()
    results = []
    for m in p.RE_IPV4.finditer(data):
        ip_str = m.group(1).decode('ascii')
        port_str = m.group(2).decode('ascii') if m.group(2) else ""
        if not _is_valid_ipv4(ip_str) or _is_private_or_loopback(ip_str):
            continue
        if ip_str in seen:
            continue
        seen.add(ip_str)
        suspicious = bool(port_str) and int(port_str) in p.MINING_PORTS
        results.append((ip_str, port_str, suspicious))
    for ip_str, port_str in _iter_ipv6_candidates(data):
        if _is_private_or_loopback(ip_str):
            continue
        if ip_str in seen:
            continue
        seen.add(ip_str)
        suspicious = bool(port_str) and int(port_str) in p.MINING_PORTS
        results.append((ip_str, port_str, suspicious))
    return results


def extract_onions(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_ONION.finditer(data):
        val = m.group(0).decode('ascii', errors='ignore')
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


def extract_emails(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_EMAIL.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore').lower()
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


def extract_cloud_meta(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_CLOUD_META.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore').strip()
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


# ---------------------------------------------------------------------------
# Modern C2 / exfil channels
# ---------------------------------------------------------------------------

def extract_c2_channels(data: bytes) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {"discord_webhook": [], "telegram_bot": [], "pastebin_raw": []}
    seen_spans = []  # (start, end) of matches already claimed, to dedupe bare tokens inside URLs

    for m in p.RE_DISCORD_WEBHOOK.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in results["discord_webhook"]:
            results["discord_webhook"].append(val)

    for m in p.RE_TELEGRAM_BOT_URL.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in results["telegram_bot"]:
            results["telegram_bot"].append(val)
        seen_spans.append(m.span())

    for m in p.RE_TELEGRAM_BOT_TOKEN.finditer(data):
        if any(start <= m.start() and m.end() <= end for start, end in seen_spans):
            continue  # already captured as part of a full bot URL match
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in results["telegram_bot"]:
            results["telegram_bot"].append(val)

    for m in p.RE_PASTEBIN_RAW.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in results["pastebin_raw"]:
            results["pastebin_raw"].append(val)

    return {k: v for k, v in results.items() if v}


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def extract_credentials(data: bytes) -> list[tuple[str, str]]:
    results = []
    seen = set()

    for m in p.RE_CRED.finditer(data):
        val = m.group(1).decode('utf-8', errors='ignore')
        stripped = val.strip("'\"")
        if stripped.lower() in p.CRED_PLACEHOLDER_DENYLIST:
            continue
        if val not in seen:
            seen.add(val)
            results.append(("generic_password_kv", val))

    # user:pass@host -- only emit in stratum context (mining credentials)
    if p.RE_STRATUM.search(data):
        for m in p.RE_USERPASS.finditer(data):
            user = m.group(1).decode('utf-8', errors='ignore')
            password = m.group(2).decode('utf-8', errors='ignore')
            host = m.group(3).decode('utf-8', errors='ignore')
            val = f"{user}:{password}@{host}"
            if val not in seen:
                seen.add(val)
                results.append(("userpass_at_host", val))

    return results


# ---------------------------------------------------------------------------
# Shell dropper
# ---------------------------------------------------------------------------

def extract_droppers(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_DROPPER.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore').strip()
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


# ---------------------------------------------------------------------------
# PE/binary-specific artifacts
# ---------------------------------------------------------------------------

def extract_pdb_paths(data: bytes) -> list[tuple[str, str]]:
    """Returns (full_path, username_or_empty)."""
    seen = set()
    results = []
    for m in p.RE_PDB_PATH.finditer(data):
        full = m.group(0).decode('utf-8', errors='ignore')
        user = (m.group('user') or b'').decode('utf-8', errors='ignore')
        if full not in seen:
            seen.add(full)
            results.append((full, user))
    return results


def _has_suspicious_keyword(haystack: bytes) -> bool:
    """Boundary-aware substring check against SUSPICIOUS_PROJECT_KEYWORDS -- a
    keyword must be flanked by a non-alphanumeric byte or a string edge, so a
    short entry like b"c2" matches ".../eclipse-c2/..." but not "sync2.go"."""
    lowered = haystack.lower()
    for kw in p.SUSPICIOUS_PROJECT_KEYWORDS:
        start = 0
        while True:
            idx = lowered.find(kw, start)
            if idx == -1:
                break
            end = idx + len(kw)
            before_ok = idx == 0 or not lowered[idx - 1:idx].isalnum()
            after_ok = end == len(lowered) or not lowered[end:end + 1].isalnum()
            if before_ok and after_ok:
                return True
            start = idx + 1
    return False


def extract_go_build_paths(data: bytes) -> list[tuple[str, str, bool]]:
    """Returns (full_path, project_dir, suspicious) -- Go's analogue of a PDB
    leak. Filters out Go toolchain/stdlib/module-cache noise (every Go binary
    embeds hundreds of those) and caps output since a real project can have many
    source files; we only need to demonstrate the leak once the project name is
    known."""
    seen = set()
    results = []
    for m in p.RE_GO_BUILD_PATH.finditer(data):
        full = m.group(1)
        if any(marker in full for marker in p.GO_NOISE_PATH_MARKERS):
            continue
        if full in seen:
            continue
        seen.add(full)
        project = m.group('project')
        suspicious = _has_suspicious_keyword(project + b'/' + full)
        results.append((
            full.decode('utf-8', errors='ignore'),
            project.decode('utf-8', errors='ignore'),
            suspicious,
        ))
        if len(results) >= 25:
            break
    return results


def extract_win32_apis(data: bytes) -> dict[str, set[str]]:
    """category -> set of matched API names found. Scoring/combo-awareness (e.g.
    not scoring 'dynamic_resolution' alone) is an orchestration decision made by
    the caller, not this pure extraction function."""
    found: dict[str, set[str]] = {}
    for category, regex in p.RE_WIN32_API_BY_CATEGORY.items():
        names = {m.group(0).decode('ascii') for m in regex.finditer(data)}
        if names:
            found[category] = names
    return found


def extract_antivm_strings(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_ANTIVM.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


def extract_ransom_language(data: bytes) -> list[str]:
    seen = set()
    results = []
    for regex in p.RE_RANSOM:
        for m in regex.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore')
            if val.lower() not in seen:
                seen.add(val.lower())
                results.append(val)
    return results


def extract_staging_paths(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_STAGING_PATH.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore')
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results


def extract_user_agents(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in p.RE_USER_AGENT_HEADER.finditer(data):
        val = m.group(1).decode('utf-8', errors='ignore').strip()
        if val not in seen:
            seen.add(val)
            results.append(val)
    for m in p.RE_USER_AGENT_MOZILLA.finditer(data):
        val = m.group(0).decode('utf-8', errors='ignore').strip()
        if val not in seen:
            seen.add(val)
            results.append(val)
    return results
