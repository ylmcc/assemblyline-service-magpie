import ipaddress
import mmap
import re
from itertools import chain

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultTableSection, TableRow

# ---------------------------------------------------------------------------
# Mining ports — hits on these elevate IP matches to heuristic-worthy
# ---------------------------------------------------------------------------
MINING_PORTS = {
    3333, 4444, 5555, 7777, 8888, 9999,
    14444, 14433, 45700, 3032, 5683,
}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Bitcoin: P2PKH (1...), P2SH (3...), bech32 (bc1...)
RE_BTC = re.compile(
    rb'(?<![A-Za-z0-9])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})(?![A-Za-z0-9])'
)

# Ethereum: 0x + 40 hex chars
RE_ETH = re.compile(rb'(?<![A-Fa-f0-9])0x[a-fA-F0-9]{40}(?![a-fA-F0-9])')

# Monero: starts with 4, 95 chars base58
RE_XMR = re.compile(rb'(?<![A-Za-z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])')

# Stratum connection: stratum+tcp://[user]:[pass]@host:port
RE_STRATUM = re.compile(rb'stratum\+(?:tcp|ssl)://[^\s\x00"\'<>]{6,}', re.IGNORECASE)

# IPv4 with optional port
RE_IPV4 = re.compile(
    rb'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?(?!\d)'
)

# IPv6 — full, compressed, and bracketed-with-port forms
RE_IPV6 = re.compile(
    rb'\[?(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?:::\S*)?\]?(?::(\d{2,5}))?'
    rb'|::(?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{1,4}'
    rb'|(?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{1,4}::',
    re.IGNORECASE,
)

# Onion addresses (v2: 16 chars, v3: 56 chars)
RE_ONION = re.compile(rb'(?<![A-Za-z0-9])([a-z2-7]{16,56}\.onion)(?::(\d{2,5}))?', re.IGNORECASE)

# Email addresses
RE_EMAIL = re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')

# Credential patterns — password= / passwd= / pwd= followed by non-whitespace value
RE_CRED = re.compile(
    rb'(?i)(?:password|passwd|pwd)\s*[:=]\s*([^\s\x00\r\n"\']{4,})'
)

# user:pass@host style (min lengths to reduce noise)
RE_USERPASS = re.compile(
    rb'(?<![A-Za-z0-9])([A-Za-z0-9._%+\-]{3,}):([^\s\x00@:]{4,})@([A-Za-z0-9.\-]{4,})'
)

# Printable ASCII string extractor (narrow, min 6 chars)
RE_STRINGS_NARROW = re.compile(rb'[\x20-\x7e]{6,}')
# Wide (UTF-16LE) string extractor
RE_STRINGS_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified
    except ValueError:
        return True


def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        parts = [int(p) for p in ip_str.split('.')]
        return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    except ValueError:
        return False


class Magpie(ServiceBase):
    def __init__(self, config=None):
        super(Magpie, self).__init__(config)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request):
        result = Result()

        with open(request.file_path, 'rb') as f:
            try:
                raw = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            except (ValueError, mmap.error):
                raw = f.read()

        # Extract printable strings (narrow + wide) and join as a flat byte string
        # separated by newlines so regexes don't stitch across string boundaries.
        # This mirrors what `strings` does and avoids false positives from binary data.
        narrow = (m.group(0) for m in RE_STRINGS_NARROW.finditer(raw))
        wide = (m.group(0).replace(b'\x00', b'') for m in RE_STRINGS_WIDE.finditer(raw))
        data = b'\n'.join(chain(narrow, wide))

        if isinstance(raw, mmap.mmap):
            raw.close()

        wallets = self._extract_wallets(data)
        stratum = self._extract_stratum(data)
        ips = self._extract_ips(data)
        onions = self._extract_onions(data)
        emails = self._extract_emails(data)
        creds = self._extract_credentials(data, emails)

        if wallets:
            section = ResultTableSection("Cryptocurrency Wallets")
            section.set_heuristic(1)
            for coin, addr in wallets:
                section.add_row(TableRow(coin=coin, address=addr))
                section.add_tag("file.string.extracted", addr)
            result.add_section(section)

        if stratum:
            section = ResultTableSection("Mining Pool Connections")
            section.set_heuristic(2)
            for entry in stratum:
                section.add_row(TableRow(connection=entry))
                section.add_tag("file.string.extracted", entry)
            result.add_section(section)

        if ips:
            section = ResultTableSection("IP Addresses")
            has_suspicious = any(suspicious for _, _, suspicious in ips)
            if has_suspicious:
                section.set_heuristic(4)
            for ip, port, suspicious in ips:
                row = TableRow(ip=ip, port=port or "", suspicious="yes" if suspicious else "no")
                section.add_row(row)
                section.add_tag("network.static.ip", ip)
                if port:
                    section.add_tag("network.port", port)
            result.add_section(section)

        if onions:
            section = ResultTableSection("Onion Addresses")
            section.set_heuristic(5)
            for addr in onions:
                section.add_row(TableRow(address=addr))
                section.add_tag("file.string.extracted", addr)
            result.add_section(section)

        if emails:
            section = ResultTableSection("Email Addresses")
            for addr in emails:
                section.add_row(TableRow(address=addr))
                section.add_tag("network.email.address", addr)
            result.add_section(section)

        if creds:
            section = ResultTableSection("Credential Patterns")
            section.set_heuristic(3)
            for cred_type, value in creds:
                section.add_row(TableRow(type=cred_type, value=value))
                section.add_tag("file.string.extracted", value)
            result.add_section(section)

        if isinstance(data, mmap.mmap):
            data.close()

        request.result = result

    def _extract_wallets(self, data) -> list[tuple[str, str]]:
        results = []
        seen = set()
        for m in RE_BTC.finditer(data):
            addr = m.group(0).decode('ascii', errors='ignore')
            if addr not in seen:
                seen.add(addr)
                results.append(("BTC", addr))
        for m in RE_ETH.finditer(data):
            addr = m.group(0).decode('ascii', errors='ignore')
            if addr not in seen:
                seen.add(addr)
                results.append(("ETH", addr))
        for m in RE_XMR.finditer(data):
            addr = m.group(0).decode('ascii', errors='ignore')
            if addr not in seen:
                seen.add(addr)
                results.append(("XMR", addr))
        return results

    def _extract_stratum(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_STRATUM.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').rstrip('\x00')
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_ips(self, data) -> list[tuple[str, str, bool]]:
        seen = set()
        results = []
        for m in RE_IPV4.finditer(data):
            ip_str = m.group(1).decode('ascii')
            port_str = m.group(2).decode('ascii') if m.group(2) else ""
            if not _is_valid_ipv4(ip_str) or _is_private_or_loopback(ip_str):
                continue
            if ip_str in seen:
                continue
            seen.add(ip_str)
            suspicious = bool(port_str) and int(port_str) in MINING_PORTS
            results.append((ip_str, port_str, suspicious))
        for m in RE_IPV6.finditer(data):
            raw = m.group(0).decode('ascii', errors='ignore').strip('[]')
            port_str = m.group(1).decode('ascii') if m.lastindex and m.group(1) else ""
            ip_str = raw.rstrip(':').split(']')[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_loopback or addr.is_private or addr.is_unspecified:
                    continue
            except ValueError:
                continue
            if ip_str in seen:
                continue
            seen.add(ip_str)
            suspicious = bool(port_str) and int(port_str) in MINING_PORTS
            results.append((ip_str, port_str, suspicious))
        return results

    def _extract_onions(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_ONION.finditer(data):
            val = m.group(0).decode('ascii', errors='ignore')
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_emails(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_EMAIL.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').lower()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_credentials(self, data, emails: list[str]) -> list[tuple[str, str]]:
        results = []
        seen = set()

        for m in RE_CRED.finditer(data):
            val = m.group(1).decode('utf-8', errors='ignore')
            if val not in seen:
                seen.add(val)
                results.append(("password", val))

        # user:pass@host — only emit if emails were also found or stratum context nearby
        if emails or RE_STRATUM.search(data):
            for m in RE_USERPASS.finditer(data):
                user = m.group(1).decode('utf-8', errors='ignore')
                password = m.group(2).decode('utf-8', errors='ignore')
                host = m.group(3).decode('utf-8', errors='ignore')
                val = f"{user}:{password}@{host}"
                if val not in seen:
                    seen.add(val)
                    results.append(("user:pass@host", val))

        return results
