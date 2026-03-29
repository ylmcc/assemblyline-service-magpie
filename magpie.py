import hashlib
import ipaddress
import mmap
import re
import tempfile
from itertools import chain

import requests as _requests

import base58 as _base58
from bech32 import bech32_decode

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
    rb'(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?(?![.\d])'
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

# Domains — hostname with 2+ labels ending in a known TLD
# Excludes file extensions and bare two-part names to reduce noise
_TLDS = (
    rb'com|net|org|io|ru|cn|de|uk|fr|br|jp|in|au|it|nl|ca|es|'
    rb'kr|info|biz|gov|mil|edu|co|me|tv|cc|us|eu|sh|to|pw'
)
RE_DOMAIN = re.compile(
    rb'(?<![A-Za-z0-9\-\.])'
    rb'([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?'
    rb'(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?){1,}'
    rb'\.(?:' + _TLDS + rb'))'
    rb'(?![A-Za-z0-9\-\.])',
    re.IGNORECASE,
)

# File extensions to suppress from domain results
_DOMAIN_SUPPRESS_EXTS = {
    'c', 'h', 'cpp', 'cc', 'py', 'rb', 'go', 'rs', 'js', 'ts',
    'sh', 'bash', 'pl', 'php', 'java', 'kt', 'cs', 'so', 'a',
    'o', 'obj', 'inc', 'asm', 's', 'txt', 'log', 'conf', 'cfg',
    'ini', 'yml', 'yaml', 'xml', 'json', 'md', 'rst', 'html',
    'htm', 'css', 'pem', 'crt', 'key', 'csr', 'cnf', 'service',
    'local', 'arpa', 'lock', 'pid', 'tmp',
}

# Credential patterns — password= / passwd= / pwd= followed by non-whitespace value
RE_CRED = re.compile(
    rb'(?i)(?:password|passwd|pwd)\s*[:=]\s*([^\s\x00\r\n"\']{4,})'
)

# user:pass@host style — password restricted to alphanumeric + common credential chars
RE_USERPASS = re.compile(
    rb'(?<![A-Za-z0-9])([A-Za-z0-9._%+\-]{3,}):([A-Za-z0-9!#$%&*+/=^_~.\-]{4,})@([A-Za-z0-9.\-]{4,}\.[A-Za-z0-9\-]{2,})'
)

# Shell dropper: wget/curl (with or without literal URL) + chmod +x on same line
RE_DROPPER = re.compile(
    rb'(?:busybox\s+)?(?:wget|curl)\b[^\x00\n]{5,}chmod\s+\+x',
    re.IGNORECASE,
)

# Cloud instance metadata API access — credential theft from AWS/Azure/GCP IMDS
RE_CLOUD_META = re.compile(
    rb'http://169\.254\.169\.254/(?:latest/meta-data|metadata|computeMetadata)[^\s\x00]*',
    re.IGNORECASE,
)

# Cron persistence: crontab modification or raw cron expression writing
RE_CRON_PERSIST = re.compile(
    rb'(?:'
    rb'\(\s*crontab\s+-l[^\x00\n]+\|\s*crontab\s+-'
    rb"|echo\s+['\"][^'\"]*\*\s+\*\s+\*[^'\"]*['\"]\s*>>"
    rb'|\*\s+\*\s+\*\s+\*\s+\*\s+root\s+\S+'
    rb')',
    re.IGNORECASE,
)

# systemd service persistence: embedded unit file or service install commands
RE_SYSTEMD_PERSIST = re.compile(
    rb'(?:'
    rb'systemctl\s+(?:enable|start|daemon-reload)\b[^\x00\n]*\.service'
    rb'|ExecStart\s*='
    rb'|WantedBy\s*=\s*\S+'
    rb')',
    re.IGNORECASE,
)

# Backdoor account: full /etc/passwd-format entry with crypt hash embedded in binary
# Matches: user:$type$salt$hash:uid:gid:gecos:home:shell
RE_PASSWD_BACKDOOR = re.compile(
    rb'[A-Za-z0-9_\-]{2,32}:\$[0-9a-z]\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,}:\d+:\d+:[^:\x00]*:[^:\x00]+:[^\s\x00]+'
)

# su with piped password: echo 'pass' | su -c
RE_SU_PIPE = re.compile(
    rb"echo\s+['\"][^'\"]{3,}['\"]\s*\|\s*su\s+-c\b",
    re.IGNORECASE,
)

# LD_PRELOAD rootkit: writing a shared library to /etc/ld.so.preload
RE_LDPRELOAD = re.compile(rb'/etc/ld\.so\.preload', re.IGNORECASE)

# HTTP/HTTPS URLs
RE_URL = re.compile(rb"https?://[^\s\x00\"'<>{}\[\]]{8,}", re.IGNORECASE)

# RC/init script persistence: rc.local modification or SysV init registration
RE_RC_PERSIST = re.compile(
    rb'(?:/etc/rc\.local|/etc/init\.d/[A-Za-z0-9_\-]+|update-rc\.d\s+\S+|/etc/rc\d?\.d/)',
    re.IGNORECASE,
)

# Container escape: Docker socket abuse, volume mount escape, or namespace escape
RE_CONTAINER_ESCAPE = re.compile(
    rb'(?:'
    rb'docker\s+run\b[^\x00\n]*-v\s+/:/[^\x00\n]*chroot'
    rb'|nsenter\s+-t\s+1\b'
    rb'|/var/run/docker\.sock'
    rb')',
    re.IGNORECASE,
)

# Printable ASCII string extractor (narrow, min 6 chars)
RE_STRINGS_NARROW = re.compile(rb'[\x20-\x7e]{6,}')
# Wide (UTF-16LE) string extractor
RE_STRINGS_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')


def _valid_btc_legacy(addr: str) -> bool:
    try:
        decoded = _base58.b58decode(addr)
        payload, checksum = decoded[:-4], decoded[-4:]
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    except Exception:
        return False


def _valid_btc_bech32(addr: str) -> bool:
    try:
        hrp, _ = bech32_decode(addr)
        return hrp == 'bc'
    except Exception:
        return False


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
        droppers = self._extract_droppers(data)
        cloud_meta = self._extract_cloud_meta(data)
        domains = self._extract_domains(data, emails)
        cron = self._extract_cron_persist(data)
        systemd = self._extract_systemd_persist(data)
        backdoor = self._extract_passwd_backdoor(data)
        ldpreload = self._extract_ldpreload(data)
        rc_persist = self._extract_rc_persist(data)
        container_escape = self._extract_container_escape(data)
        urls = self._extract_urls(data)
        fetched = self._fetch_url_payloads(request, urls) if urls else []

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
                row = TableRow(ip=ip, port=port or "")
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

        if droppers:
            section = ResultTableSection("Shell Dropper Commands")
            section.set_heuristic(6)
            for cmd in droppers:
                section.add_row(TableRow(command=cmd))
                section.add_tag("file.string.extracted", cmd[:512])
            result.add_section(section)

        if cloud_meta:
            section = ResultTableSection("Cloud Metadata API Access")
            section.set_heuristic(7)
            for url in cloud_meta:
                section.add_row(TableRow(url=url))
                section.add_tag("file.string.extracted", url)
            result.add_section(section)

        if domains:
            section = ResultTableSection("Domains")
            for domain in domains:
                section.add_row(TableRow(domain=domain))
                section.add_tag("network.static.domain", domain)
            result.add_section(section)

        if cron:
            section = ResultTableSection("Cron Persistence")
            section.set_heuristic(8)
            for entry in cron:
                section.add_row(TableRow(command=entry))
                section.add_tag("file.string.extracted", entry[:512])
            result.add_section(section)

        if systemd:
            section = ResultTableSection("Systemd Service Persistence")
            section.set_heuristic(9)
            for entry in systemd:
                section.add_row(TableRow(entry=entry))
                section.add_tag("file.string.extracted", entry[:512])
            result.add_section(section)

        if backdoor:
            section = ResultTableSection("Backdoor Account")
            section.set_heuristic(10)
            for entry in backdoor:
                section.add_row(TableRow(entry=entry))
                section.add_tag("file.string.extracted", entry)
            result.add_section(section)

        if ldpreload:
            section = ResultTableSection("LD_PRELOAD Rootkit")
            section.set_heuristic(11)
            for entry in ldpreload:
                section.add_row(TableRow(entry=entry))
                section.add_tag("file.string.extracted", entry)
            result.add_section(section)

        if urls:
            section = ResultTableSection("URLs")
            for url in urls:
                dl = any(u == url for u, _ in fetched)
                section.add_row(TableRow(url=url, fetched="yes" if dl else "no"))
                section.add_tag("network.static.uri", url)
            result.add_section(section)

        if rc_persist:
            section = ResultTableSection("RC/Init Script Persistence")
            section.set_heuristic(12)
            for entry in rc_persist:
                section.add_row(TableRow(entry=entry))
                section.add_tag("file.string.extracted", entry)
            result.add_section(section)

        if container_escape:
            section = ResultTableSection("Container Escape")
            section.set_heuristic(13)
            for entry in container_escape:
                section.add_row(TableRow(entry=entry))
                section.add_tag("file.string.extracted", entry[:512])
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
                valid = _valid_btc_bech32(addr) if addr.startswith('bc1') else _valid_btc_legacy(addr)
                if not valid:
                    continue
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

        # user:pass@host — only emit in stratum context (mining credentials)
        if RE_STRATUM.search(data):
            for m in RE_USERPASS.finditer(data):
                user = m.group(1).decode('utf-8', errors='ignore')
                password = m.group(2).decode('utf-8', errors='ignore')
                host = m.group(3).decode('utf-8', errors='ignore')
                val = f"{user}:{password}@{host}"
                if val not in seen:
                    seen.add(val)
                    results.append(("user:pass@host", val))

        return results

    def _extract_droppers(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_DROPPER.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_cloud_meta(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_CLOUD_META.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_domains(self, data, emails: list[str]) -> list[str]:
        # Build set of hosts already covered by email extraction
        email_hosts = {e.split('@', 1)[1] for e in emails if '@' in e}
        seen = set()
        results = []
        for m in RE_DOMAIN.finditer(data):
            val = m.group(1).decode('ascii', errors='ignore').lower()
            # Drop if last label is a suppressed file extension
            ext = val.rsplit('.', 1)[-1]
            if ext in _DOMAIN_SUPPRESS_EXTS:
                continue
            # Drop if it's just an email host we already have
            if val in email_hosts:
                continue
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_cron_persist(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_CRON_PERSIST.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_systemd_persist(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_SYSTEMD_PERSIST.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_passwd_backdoor(self, data) -> list[str]:
        seen = set()
        results = []
        for pattern in (RE_PASSWD_BACKDOOR, RE_SU_PIPE):
            for m in pattern.finditer(data):
                val = m.group(0).decode('utf-8', errors='ignore').strip()
                if val not in seen:
                    seen.add(val)
                    results.append(val)
        return results

    def _extract_ldpreload(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_LDPRELOAD.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_urls(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_URL.finditer(data):
            url = m.group(0).decode('utf-8', errors='ignore').strip()
            if url not in seen:
                seen.add(url)
                results.append(url)
        return results

    def _fetch_url_payloads(self, request, urls: list[str]) -> list[tuple[str, str]]:
        fetched = []
        for url in urls:
            try:
                resp = _requests.get(url, timeout=10, verify=False)
                if resp.status_code != 200 or not resp.content:
                    continue
                filename = url.rstrip('/').split('/')[-1] or 'payload'
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='_' + filename)
                tmp.write(resp.content)
                tmp.close()
                request.add_extracted(tmp.name, filename, f"Payload fetched from {url}")
                fetched.append((url, filename))
            except Exception:
                pass
        return fetched

    def _extract_rc_persist(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_RC_PERSIST.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results

    def _extract_container_escape(self, data) -> list[str]:
        seen = set()
        results = []
        for m in RE_CONTAINER_ESCAPE.finditer(data):
            val = m.group(0).decode('utf-8', errors='ignore').strip()
            if val not in seen:
                seen.add(val)
                results.append(val)
        return results
