"""Magpie: hones in on the "shiny objects" a malware analyst would want plucked out
of a pile of strings -- cryptocurrency wallets, mining pool connections, network
IOCs, modern C2/exfil channels, credential patterns, and (since Magpie is the only
one of this author's AL4 services that ever sees compiled binaries) PE-specific
artifacts: PDB debug-path leaks, dangerous Win32 API strings, anti-VM/sandbox
artifacts, and ransom-note language.

Pure static string scanning (mmap + regex) -- no execution, no parsing beyond
regex matching and stdlib `ipaddress` validation. See README.md for detail.
"""
from __future__ import annotations

import mmap

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultTableSection, TableRow

from magpie import extraction as ext


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

        data = ext.build_string_blob(raw)

        if isinstance(raw, mmap.mmap):
            raw.close()

        wallets = ext.extract_wallets(data)
        stratum = ext.extract_stratum(data)
        ips = ext.extract_ips(data)
        onions = ext.extract_onions(data)
        emails = ext.extract_emails(data)
        creds = ext.extract_credentials(data)
        droppers = ext.extract_droppers(data)
        cloud_meta = ext.extract_cloud_meta(data)
        pdb_paths = ext.extract_pdb_paths(data)
        win32_apis = ext.extract_win32_apis(data)
        antivm = ext.extract_antivm_strings(data)
        c2_channels = ext.extract_c2_channels(data)
        ransom = ext.extract_ransom_language(data)
        staging_paths = ext.extract_staging_paths(data)
        user_agents = ext.extract_user_agents(data)

        # ---- scored categories -------------------------------------------------

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

        if creds:
            section = ResultTableSection("Credential Patterns")
            heur = Heuristic(3)
            for cred_type, value in creds:
                section.add_row(TableRow(type=cred_type, value=value))
                section.add_tag("file.string.extracted", value)
                heur.add_signature_id(cred_type)
            section.set_heuristic(heur)
            result.add_section(section)

        if ips:
            section = ResultTableSection("IP Addresses")
            has_suspicious = any(suspicious for _, _, suspicious in ips)
            if has_suspicious:
                section.set_heuristic(4)
            for ip, port, suspicious in ips:
                section.add_row(TableRow(ip=ip, port=port or "", suspicious="yes" if suspicious else "no"))
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

        if pdb_paths:
            section = ResultTableSection("PDB Debug Paths")
            section.set_heuristic(8)
            for path, user in pdb_paths:
                section.add_row(TableRow(path=path, username=user))
                section.add_tag("file.pe.pdb_filename", path)
            result.add_section(section)

        if win32_apis:
            section = ResultTableSection("Suspicious Win32 API Usage")
            for category, names in win32_apis.items():
                for name in sorted(names):
                    section.add_row(TableRow(category=category, api=name))
                    section.add_tag("file.pe.api_vector", name)
            # LoadLibraryA/GetProcAddress alone show up in nearly every
            # dynamically-linked PE, benign or not -- only score dynamic_resolution
            # when paired with a more distinctive category.
            only_dynamic_resolution = set(win32_apis.keys()) == {"dynamic_resolution"}
            if not only_dynamic_resolution:
                heur = Heuristic(9)
                for category in win32_apis:
                    heur.add_signature_id(category)
                section.set_heuristic(heur)
            result.add_section(section)

        if antivm:
            section = ResultTableSection("Anti-VM / Anti-Sandbox Artifacts")
            section.set_heuristic(10)
            for val in antivm:
                section.add_row(TableRow(artifact=val))
                section.add_tag("file.string.extracted", val)
            result.add_section(section)

        if c2_channels:
            section = ResultTableSection("Modern C2/Exfil Channels")
            heur = Heuristic(11)
            for channel_type, values in c2_channels.items():
                for val in values:
                    section.add_row(TableRow(type=channel_type, value=val))
                    section.add_tag("network.static.uri", val)
                    heur.add_signature_id(channel_type)
            section.set_heuristic(heur)
            result.add_section(section)

        if ransom:
            section = ResultTableSection("Ransom Note Language")
            for phrase in ransom:
                section.add_row(TableRow(phrase=phrase))
                section.add_tag("file.string.extracted", phrase)
            # Cross-category scoring: a ransom note paired with a wallet/onion
            # address already extracted elsewhere in this same file is stronger
            # evidence than ransom-shaped language alone.
            signature = "ransom_with_payment_evidence" if (wallets or onions) else "ransom_language_only"
            section.set_heuristic(12, signature=signature)
            result.add_section(section)

        # ---- informational-only, no heuristic -----------------------------------

        if emails:
            section = ResultTableSection("Email Addresses")
            for addr in emails:
                section.add_row(TableRow(address=addr))
                section.add_tag("network.email.address", addr)
            result.add_section(section)

        if staging_paths:
            section = ResultTableSection("Suspicious Staging/Drop Paths")
            for path in staging_paths:
                section.add_row(TableRow(path=path))
                section.add_tag("file.string.extracted", path)
            result.add_section(section)

        if user_agents:
            section = ResultTableSection("User-Agent Strings")
            for ua in user_agents:
                section.add_row(TableRow(user_agent=ua))
                section.add_tag("network.user_agent", ua)
            result.add_section(section)

        request.result = result
