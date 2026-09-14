"""Regex patterns and curated word-lists for Magpie's string-based extraction.

Every pattern here operates on bytes extracted from a file's printable strings
(narrow ASCII + wide UTF-16LE) -- see extraction.py. No execution, no parsing of
any kind beyond regex matching and stdlib `ipaddress` validation.
"""
import re

# ---------------------------------------------------------------------------
# Mining ports -- hits on these elevate IP matches to heuristic-worthy
# ---------------------------------------------------------------------------
MINING_PORTS = {
    3333, 4444, 5555, 7777, 8888, 9999,
    14444, 14433, 45700, 3032, 5683,
}

# ---------------------------------------------------------------------------
# Cryptocurrency wallets
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

# ---------------------------------------------------------------------------
# Network indicators
# ---------------------------------------------------------------------------

# IPv4 with optional port
RE_IPV4 = re.compile(
    rb'(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?(?![.\d])'
)

# IPv6 -- coarse candidate locator only. Deliberately over-matches (requires >=2
# colons in the span, then greedily consumes the *entire* contiguous hex/colon
# run) rather than trying to encode every legal compression form in the regex
# itself -- the old single monolithic-alternation regex stopped early at the
# first "::" and silently truncated the most common compressed IPv6 form
# (e.g. "2001:db8::1" only matched "2001:db8::", losing the "1"). Correctness
# (does this candidate actually parse, what does it normalize to, is there
# really a port) is delegated to ipaddress.ip_address() in extraction.py --
# see _iter_ipv6_candidates.
RE_IPV6_CANDIDATE = re.compile(
    rb'(?<![A-Za-z0-9:])'
    rb'(\[?(?=[A-Fa-f0-9:]*:[A-Fa-f0-9:]*:)[A-Fa-f0-9:]{2,45}\]?)'
    rb'(?::(\d{2,5}))?'
    rb'(?![A-Za-z0-9:])'
)

# Onion addresses -- v2 is exactly 16 chars, v3 is exactly 56 chars, never in
# between. Must be an exact-length alternation, not a {16,56} range: a range lets
# any packed run of base32-charset bytes of ANY length in that window match, which
# is exactly what a Go binary's unbroken string-constant soup looks like (Go
# stdlib's `net` package embeds its own ".onion" TLD-handling constant amid a run
# of other packed keywords with no separator bytes between them -- confirmed via a
# real sample where a 40-char non-onion run matched under the old range). The
# existing (?<![A-Za-z0-9]) lookbehind already prevents matching a sub-window of a
# longer unbroken run, so exact-length alone is sufficient.
RE_ONION = re.compile(
    rb'(?<![A-Za-z0-9])((?:[a-z2-7]{56}|[a-z2-7]{16})\.onion)(?::(\d{2,5}))?',
    re.IGNORECASE,
)

# Email addresses
RE_EMAIL = re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')

# Cloud instance metadata API access -- credential theft from AWS/Azure/GCP IMDS
RE_CLOUD_META = re.compile(
    rb'http://169\.254\.169\.254/(?:latest/meta-data|metadata|computeMetadata)[^\s\x00]*',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Modern C2 / exfil channels
# ---------------------------------------------------------------------------

RE_DISCORD_WEBHOOK = re.compile(
    rb'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,90}',
    re.IGNORECASE,
)
RE_TELEGRAM_BOT_URL = re.compile(
    rb'https?://api\.telegram\.org/bot\d{8,10}:[A-Za-z0-9_\-]{35}(?:/\w+)?',
    re.IGNORECASE,
)
# Bare token form (no URL wrapper) -- still distinctive; dedupe against URL hits
# in extraction.py so the same token isn't reported twice.
RE_TELEGRAM_BOT_TOKEN = re.compile(rb'(?<![A-Za-z0-9_\-])\d{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])')
RE_PASTEBIN_RAW = re.compile(rb'https?://(?:www\.)?pastebin\.com/raw/[A-Za-z0-9]{6,10}\b', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Credential patterns
# ---------------------------------------------------------------------------

# password= / passwd= followed by non-whitespace value. Deliberately excludes
# bare "pwd" -- confirmed via a real sample that it collides with the extremely
# common $PWD (present working directory) environment variable, e.g. a plain
# "PWD=/home/user" line in an env dump or .bashrc would otherwise be reported as
# a leaked credential. Value capped at 32 chars so a rare genuine hit sitting
# next to more packed-string garbage (see RE_ONION comment) doesn't run away.
RE_CRED = re.compile(
    rb'(?i)\b(?:password|passwd)\s*[:=]\s*([^\s\x00\r\n"\']{4,32})'
)

# user:pass@host style -- password restricted to alphanumeric + common credential chars
RE_USERPASS = re.compile(
    rb'(?<![A-Za-z0-9])([A-Za-z0-9._%+\-]{3,}):([A-Za-z0-9!#$%&*+/=^_~.\-]{4,})@([A-Za-z0-9.\-]{4,}\.[A-Za-z0-9\-]{2,})'
)

# Obvious placeholder credential values -- suppressed to cut noise, since Magpie's
# accepts: .* means RE_CRED runs across every file type in the whole pipeline,
# including docs/configs/CI fixtures that are full of "password=changeme"-style
# examples. Compared case-insensitively after stripping surrounding quotes.
CRED_PLACEHOLDER_DENYLIST = frozenset({
    "password", "passwd", "pwd", "changeme", "change_me", "your_password_here",
    "xxxxx", "xxxxxxxx", "********", "placeholder", "insert_password_here",
    "secret", "test", "test123", "123456", "password123", "example",
})

# ---------------------------------------------------------------------------
# Shell dropper / cloud metadata already above; PE/binary-specific artifacts below
# ---------------------------------------------------------------------------

# Shell dropper: wget/curl (with or without literal URL) + chmod +x on same line
RE_DROPPER = re.compile(
    rb'(?:busybox\s+)?(?:wget|curl)\b[^\x00\n]{5,}chmod\s+\+x',
    re.IGNORECASE,
)

# PDB debug paths -- classic leak of the malware author's build machine
# username/project/directory structure. PE-specific but detectable as a pure
# string without any real PE parsing.
RE_PDB_PATH = re.compile(
    rb'[A-Za-z]:\\(?:Users\\(?P<user>[^\\]{1,64})\\)?'
    rb'(?:[^\\/:*?"<>|\r\n\x00]{1,120}\\)*'
    rb'(?P<pdbname>[^\\/:*?"<>|\r\n\x00]{1,120}\.pdb)\b',
    re.IGNORECASE,
)

# Go build-machine source paths -- the Linux/macOS analogue of a PDB leak. Go
# binaries embed absolute source paths of the build machine (via pclntab/DWARF
# line tables) unless built with -trimpath, and just as revealing of the
# project/author's directory naming as a PDB path. `project` captures the
# directory immediately containing the .go file (e.g. for
# "/root/eclipse-c2/eclipse-c2/bot_client.go" -> "eclipse-c2").
RE_GO_BUILD_PATH = re.compile(
    rb'(?<![\w/])(/(?:[\w.\-]+/)+(?P<project>[\w.\-]+)/[\w.\-]+\.go)\b'
)

# Every Go binary embeds hundreds of these (toolchain/stdlib/module-cache) --
# not informative about the malware's own project, filtered out in extraction.
GO_NOISE_PATH_MARKERS = (
    b"/usr/local/go/", b"/usr/lib/go", b"/pkg/mod/", b"/go/pkg/",
    b"/src/runtime/", b"/src/internal/", b"/src/vendor/", b"/src/cmd/",
    b"/.gvm/", b"/goroot/",
)

# Project-path keywords strongly associated with malicious tooling -- boosts the
# score when the leaked build path itself names the project this way (e.g.
# ".../eclipse-c2/bot_client.go"). Matched with boundary-awareness in
# extraction.py so short entries like "c2" don't fire on incidental substrings
# like "sync2"/"func2".
SUSPICIOUS_PROJECT_KEYWORDS = frozenset({
    b"c2", b"rat", b"bot", b"backdoor", b"implant", b"stager", b"loader",
    b"dropper", b"keylog", b"rootkit", b"trojan", b"stealer", b"exfil",
    b"payload", b"malware", b"miner", b"botnet", b"ddos", b"exploit",
    b"phish", b"beacon", b"shellcode", b"ransom", b"worm", b"cobaltstrike",
})

# Curated dangerous Win32 API name strings, grouped so combo-aware scoring can
# down-weight low-signal-alone categories (see extraction.py/magpie.py). These
# show up as literal strings in a PE's import/string table even before any real
# disassembly.
WIN32_API_CATEGORIES: dict = {
    "process_injection": (
        b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
        b"NtCreateThreadEx", b"QueueUserAPC", b"SetThreadContext",
        b"RtlCreateUserThread", b"NtUnmapViewOfSection", b"ZwUnmapViewOfSection",
        b"NtMapViewOfSection",
    ),
    "anti_debug_anti_vm": (
        b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess", b"OutputDebugStringA",
        b"NtSetInformationThread", b"NtQuerySystemInformation",
    ),
    "credential_access": (
        b"LsaEnumerateLogonSessions", b"SamIConnect", b"CredEnumerateA",
        b"CredEnumerateW", b"CryptUnprotectData", b"MiniDumpWriteDump",
    ),
    "hooking": (b"SetWindowsHookExA", b"SetWindowsHookExW"),
    "dynamic_resolution": (b"LoadLibraryA", b"LoadLibraryW", b"GetProcAddress"),
}
RE_WIN32_API_BY_CATEGORY: dict = {
    cat: re.compile(rb'\b(?:' + rb'|'.join(re.escape(n) for n in names) + rb')\b')
    for cat, names in WIN32_API_CATEGORIES.items()
}

# Anti-VM / anti-sandbox / anti-analysis artifact strings. Deliberately excludes
# generic sandbox usernames ("John"/"SANDBOX") -- too false-positive-prone (real
# people are named John); kept to distinctive vendor/service/file-name strings.
ANTIVM_STRINGS: tuple = (
    b"VMware", b"VBox", b"VirtualBox", b"vmtoolsd", b"vboxservice.exe",
    b"vboxtray.exe", b"SbieDll.dll", b"Sandboxie", b"vmci.sys", b"vmmouse",
    b"vm3dgl", b"VMwareService.exe", b"QEMU", b"qemu-ga",
    b"WDAGUtilityAccount", b"INNOTEK GMBH",
)
RE_ANTIVM = re.compile(rb'(?:' + rb'|'.join(re.escape(s) for s in ANTIVM_STRINGS) + rb')', re.IGNORECASE)

# Ransom-note-shaped language.
RANSOM_PHRASES = [
    rb'your\s+files?\s+(?:have\s+been|were|has\s+been)\s+encrypted',
    rb'all\s+your\s+(?:files|data)\s+(?:have\s+been|are)\s+encrypted',
    rb'decrypt(?:ion)?\s+(?:key|tool|service)',
    rb'restore\s+your\s+files',
    rb'do\s+not\s+(?:attempt\s+to\s+)?(?:rename|modify|decrypt)\s+(?:the\s+)?files?',
    rb'(?:you\s+have|deadline\s+of)\s+\d+\s+(?:hours?|days?)',
]
RE_RANSOM = [re.compile(p, re.IGNORECASE) for p in RANSOM_PHRASES]

# Suspicious staging/drop paths -- informational only (see manifest: no heuristic
# maps to this). Close to universal across legitimate software too (cron,
# package managers, every Windows installer/browser/updater), so it's kept as
# context, never scored.
RE_STAGING_PATH = re.compile(
    rb'(?:/dev/shm/\S*|/var/tmp/\S*|/tmp/\.[^\s"\'\\]{1,64}\S*'
    rb'|\\AppData\\Roaming\\\S*|\\AppData\\Local\\Temp\\\S*)',
    re.IGNORECASE,
)

# User-Agent strings -- informational only, same reasoning as staging paths.
RE_USER_AGENT_HEADER = re.compile(rb'User-Agent:\s*([^\r\n\x00]{4,200})', re.IGNORECASE)
RE_USER_AGENT_MOZILLA = re.compile(rb'Mozilla/\d\.\d\s*\([^\r\n\x00]{0,200}\)[^\r\n\x00"]{0,120}')

# ---------------------------------------------------------------------------
# Printable string extraction (narrow + wide)
# ---------------------------------------------------------------------------
RE_STRINGS_NARROW = re.compile(rb'[\x20-\x7e]{6,}')
RE_STRINGS_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')
