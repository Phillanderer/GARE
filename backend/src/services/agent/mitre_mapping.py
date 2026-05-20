"""
MITRE ATT&CK technique mapping from Windows API imports.
Maps common API calls to ATT&CK technique IDs for automated triage.
"""

from typing import Dict, List, Tuple

# Mapping: API name -> (technique_id, technique_name, tactic)
API_TO_ATTACK: Dict[str, Tuple[str, str, str]] = {
    # ===== Execution =====
    "CreateProcessA":           ("T1106", "Native API", "Execution"),
    "CreateProcessW":           ("T1106", "Native API", "Execution"),
    "CreateProcessAsUserA":     ("T1106", "Native API", "Execution"),
    "CreateProcessAsUserW":     ("T1106", "Native API", "Execution"),
    "WinExec":                  ("T1106", "Native API", "Execution"),
    "ShellExecuteA":            ("T1106", "Native API", "Execution"),
    "ShellExecuteW":            ("T1106", "Native API", "Execution"),
    "ShellExecuteExA":          ("T1106", "Native API", "Execution"),
    "ShellExecuteExW":          ("T1106", "Native API", "Execution"),
    "system":                   ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CreateThread":             ("T1106", "Native API", "Execution"),
    "CreateRemoteThread":       ("T1055", "Process Injection", "Defense Evasion"),
    "CreateRemoteThreadEx":     ("T1055", "Process Injection", "Defense Evasion"),
    "NtCreateThreadEx":         ("T1055", "Process Injection", "Defense Evasion"),
    "RtlCreateUserThread":      ("T1055", "Process Injection", "Defense Evasion"),

    # ===== Process Injection =====
    "VirtualAllocEx":           ("T1055", "Process Injection", "Defense Evasion"),
    "NtAllocateVirtualMemory":  ("T1055", "Process Injection", "Defense Evasion"),
    "WriteProcessMemory":       ("T1055", "Process Injection", "Defense Evasion"),
    "NtWriteVirtualMemory":     ("T1055", "Process Injection", "Defense Evasion"),
    "QueueUserAPC":             ("T1055.004", "Asynchronous Procedure Call", "Defense Evasion"),
    "NtQueueApcThread":         ("T1055.004", "Asynchronous Procedure Call", "Defense Evasion"),
    "SetWindowsHookExA":        ("T1055.012", "Process Hollowing", "Defense Evasion"),
    "SetWindowsHookExW":        ("T1055.012", "Process Hollowing", "Defense Evasion"),

    # ===== Persistence =====
    "RegSetValueExA":           ("T1547.001", "Registry Run Keys", "Persistence"),
    "RegSetValueExW":           ("T1547.001", "Registry Run Keys", "Persistence"),
    "RegCreateKeyExA":          ("T1547.001", "Registry Run Keys", "Persistence"),
    "RegCreateKeyExW":          ("T1547.001", "Registry Run Keys", "Persistence"),
    "CreateServiceA":           ("T1543.003", "Windows Service", "Persistence"),
    "CreateServiceW":           ("T1543.003", "Windows Service", "Persistence"),
    "StartServiceA":            ("T1543.003", "Windows Service", "Persistence"),
    "StartServiceW":            ("T1543.003", "Windows Service", "Persistence"),
    "CreateFileMappingA":       ("T1055.001", "Dynamic-link Library Injection", "Defense Evasion"),

    # ===== Privilege Escalation =====
    "OpenProcessToken":         ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "AdjustTokenPrivileges":    ("T1134.001", "Token Impersonation", "Privilege Escalation"),
    "ImpersonateLoggedOnUser":  ("T1134.001", "Token Impersonation", "Privilege Escalation"),
    "DuplicateToken":           ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "DuplicateTokenEx":         ("T1134", "Access Token Manipulation", "Privilege Escalation"),

    # ===== Defense Evasion =====
    "VirtualProtect":           ("T1055", "Process Injection", "Defense Evasion"),
    "VirtualProtectEx":         ("T1055", "Process Injection", "Defense Evasion"),
    "IsDebuggerPresent":        ("T1622", "Debugger Evasion", "Defense Evasion"),
    "CheckRemoteDebuggerPresent": ("T1622", "Debugger Evasion", "Defense Evasion"),
    "NtQueryInformationProcess":("T1622", "Debugger Evasion", "Defense Evasion"),
    "OutputDebugStringA":       ("T1622", "Debugger Evasion", "Defense Evasion"),
    "GetTickCount":             ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    "GetTickCount64":           ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    "QueryPerformanceCounter":  ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    "Sleep":                    ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    "SleepEx":                  ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    "DeleteFileA":              ("T1070.004", "File Deletion", "Defense Evasion"),
    "DeleteFileW":              ("T1070.004", "File Deletion", "Defense Evasion"),

    # ===== Credential Access =====
    "CredEnumerateA":           ("T1555", "Credentials from Password Stores", "Credential Access"),
    "CredEnumerateW":           ("T1555", "Credentials from Password Stores", "Credential Access"),
    "LsaRetrievePrivateData":   ("T1003", "OS Credential Dumping", "Credential Access"),

    # ===== Discovery =====
    "GetComputerNameA":         ("T1082", "System Information Discovery", "Discovery"),
    "GetComputerNameW":         ("T1082", "System Information Discovery", "Discovery"),
    "GetUserNameA":             ("T1033", "System Owner/User Discovery", "Discovery"),
    "GetUserNameW":             ("T1033", "System Owner/User Discovery", "Discovery"),
    "GetVersionExA":            ("T1082", "System Information Discovery", "Discovery"),
    "GetVersionExW":            ("T1082", "System Information Discovery", "Discovery"),
    "GetSystemInfo":            ("T1082", "System Information Discovery", "Discovery"),
    "GetNativeSystemInfo":      ("T1082", "System Information Discovery", "Discovery"),
    "EnumProcesses":            ("T1057", "Process Discovery", "Discovery"),
    "CreateToolhelp32Snapshot": ("T1057", "Process Discovery", "Discovery"),
    "Process32First":           ("T1057", "Process Discovery", "Discovery"),
    "Process32Next":            ("T1057", "Process Discovery", "Discovery"),
    "FindFirstFileA":           ("T1083", "File and Directory Discovery", "Discovery"),
    "FindFirstFileW":           ("T1083", "File and Directory Discovery", "Discovery"),
    "FindNextFileA":            ("T1083", "File and Directory Discovery", "Discovery"),
    "FindNextFileW":            ("T1083", "File and Directory Discovery", "Discovery"),
    "NetShareEnum":             ("T1135", "Network Share Discovery", "Discovery"),
    "GetAdaptersInfo":          ("T1016", "System Network Configuration Discovery", "Discovery"),
    "GetAdaptersAddresses":     ("T1016", "System Network Configuration Discovery", "Discovery"),

    # ===== Networking / C2 =====
    "InternetOpenA":            ("T1071", "Application Layer Protocol", "Command and Control"),
    "InternetOpenW":            ("T1071", "Application Layer Protocol", "Command and Control"),
    "InternetOpenUrlA":         ("T1071.001", "Web Protocols", "Command and Control"),
    "InternetOpenUrlW":         ("T1071.001", "Web Protocols", "Command and Control"),
    "InternetConnectA":         ("T1071", "Application Layer Protocol", "Command and Control"),
    "InternetConnectW":         ("T1071", "Application Layer Protocol", "Command and Control"),
    "HttpOpenRequestA":         ("T1071.001", "Web Protocols", "Command and Control"),
    "HttpOpenRequestW":         ("T1071.001", "Web Protocols", "Command and Control"),
    "HttpSendRequestA":         ("T1071.001", "Web Protocols", "Command and Control"),
    "HttpSendRequestW":         ("T1071.001", "Web Protocols", "Command and Control"),
    "URLDownloadToFileA":       ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "URLDownloadToFileW":       ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "WSAStartup":               ("T1071", "Application Layer Protocol", "Command and Control"),
    "socket":                   ("T1071", "Application Layer Protocol", "Command and Control"),
    "connect":                  ("T1071", "Application Layer Protocol", "Command and Control"),
    "send":                     ("T1071", "Application Layer Protocol", "Command and Control"),
    "recv":                     ("T1071", "Application Layer Protocol", "Command and Control"),
    "WSASend":                  ("T1071", "Application Layer Protocol", "Command and Control"),
    "WSARecv":                  ("T1071", "Application Layer Protocol", "Command and Control"),
    "DnsQuery_A":               ("T1071.004", "DNS", "Command and Control"),
    "DnsQuery_W":               ("T1071.004", "DNS", "Command and Control"),
    "getaddrinfo":              ("T1071.004", "DNS", "Command and Control"),
    "gethostbyname":            ("T1071.004", "DNS", "Command and Control"),

    # ===== Collection / Exfiltration =====
    "GetClipboardData":         ("T1115", "Clipboard Data", "Collection"),
    "OpenClipboard":            ("T1115", "Clipboard Data", "Collection"),
    "GetKeyState":              ("T1056.001", "Keylogging", "Collection"),
    "GetAsyncKeyState":         ("T1056.001", "Keylogging", "Collection"),
    "SetWindowsHookEx":         ("T1056.001", "Keylogging", "Collection"),
    "GetForegroundWindow":      ("T1113", "Screen Capture", "Collection"),
    "BitBlt":                   ("T1113", "Screen Capture", "Collection"),
    "GetDC":                    ("T1113", "Screen Capture", "Collection"),

    # ===== Cryptography (may indicate ransomware or encrypted comms) =====
    "CryptEncrypt":             ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptDecrypt":             ("T1140", "Deobfuscate/Decode Files", "Defense Evasion"),
    "CryptAcquireContextA":     ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptAcquireContextW":     ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptGenKey":              ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptImportKey":           ("T1486", "Data Encrypted for Impact", "Impact"),
    "BCryptEncrypt":            ("T1486", "Data Encrypted for Impact", "Impact"),
    "BCryptDecrypt":            ("T1140", "Deobfuscate/Decode Files", "Defense Evasion"),

    # ===== DLL Loading (may indicate reflective loading) =====
    "LoadLibraryA":             ("T1129", "Shared Modules", "Execution"),
    "LoadLibraryW":             ("T1129", "Shared Modules", "Execution"),
    "LoadLibraryExA":           ("T1129", "Shared Modules", "Execution"),
    "LoadLibraryExW":           ("T1129", "Shared Modules", "Execution"),
    "GetProcAddress":           ("T1129", "Shared Modules", "Execution"),
    "LdrLoadDll":               ("T1055.001", "Dynamic-link Library Injection", "Defense Evasion"),
}


def map_imports_to_attack(imports: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """
    Map a list of imported API names to MITRE ATT&CK techniques.

    Args:
        imports: List of import strings (may be "address: name" format from Ghidra)

    Returns:
        Dict with techniques grouped by tactic
    """
    # Parse import names — handle both "name" and "address: name" formats
    api_names = set()
    for imp in imports:
        imp_str = str(imp).strip()
        if ":" in imp_str:
            # Format: "0x00401000: kernel32.dll::CreateProcessW"  or "kernel32.dll::CreateProcessW"
            parts = imp_str.split(":")
            name_part = parts[-1].strip()
            # Handle dll::func format
            if "::" in imp_str:
                name_part = imp_str.split("::")[-1].strip()
        else:
            name_part = imp_str

        # Also try just the function name after any namespace
        if "." in name_part:
            name_part = name_part.split(".")[-1]

        api_names.add(name_part)

    # Match against ATT&CK mapping
    by_tactic: Dict[str, List[Dict[str, str]]] = {}
    matched_techniques = set()

    for api_name in sorted(api_names):
        if api_name in API_TO_ATTACK:
            tech_id, tech_name, tactic = API_TO_ATTACK[api_name]
            key = (tech_id, tech_name, tactic)

            if key not in matched_techniques:
                matched_techniques.add(key)

            if tactic not in by_tactic:
                by_tactic[tactic] = []

            # Avoid duplicate entries per tactic
            existing_ids = {t["technique_id"] for t in by_tactic[tactic]}
            if tech_id not in existing_ids:
                by_tactic[tactic].append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "matched_apis": []
                })

            # Add API to the matching technique
            for entry in by_tactic[tactic]:
                if entry["technique_id"] == tech_id and api_name not in entry["matched_apis"]:
                    entry["matched_apis"].append(api_name)

    return {
        "tactics": by_tactic,
        "total_techniques_matched": len(matched_techniques),
        "total_apis_matched": sum(
            len(entry["matched_apis"])
            for entries in by_tactic.values()
            for entry in entries
        ),
    }
