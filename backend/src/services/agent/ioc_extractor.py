"""
IOC (Indicator of Compromise) extraction from binary strings.
Regex-based extraction of IPs, URLs, domains, file paths, registry keys.
"""

import re
from typing import Dict, List


# Compiled regex patterns for performance
PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "url": re.compile(
        r'https?://[^\s<>"\')\]}{,]{4,}',
        re.IGNORECASE
    ),
    "domain": re.compile(
        r'(?<![/\\])' # not preceded by path separator (avoid matching filenames)
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'{1,4}(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|gq|cc|'
        r'onion|bit)\b',
        re.IGNORECASE
    ),
    "file_path_windows": re.compile(
        r'[A-Za-z]:\\(?:[^\\\s<>"\'|?*]{1,60}\\){0,10}[^\\\s<>"\'|?*]{1,60}',
    ),
    "file_path_unix": re.compile(
        r'(?:/(?:etc|tmp|var|usr|home|opt|dev|proc|sys|bin|sbin|root|boot)'
        r'(?:/[^\s<>"\'|]{1,60}){0,8})',
    ),
    "registry_key": re.compile(
        r'(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|'
        r'HKLM|HKCU|HKCR|HKU)\\[^\s<>"\']{4,}',
        re.IGNORECASE
    ),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "crypto_wallet": re.compile(
        # Bitcoin (1/3/bc1) and Ethereum (0x) addresses
        r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,87}|'
        r'0x[0-9a-fA-F]{40})\b'
    ),
}

# Known false-positive IPs to exclude
PRIVATE_IP_RANGES = re.compile(
    r'^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|'
    r'192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|'
    r'255\.255\.255\.255)$'
)


def extract_iocs(strings: List[str], include_private_ips: bool = False) -> Dict[str, List[str]]:
    """
    Extract IOCs from a list of strings (e.g., from Ghidra string listing).

    Args:
        strings: List of strings from the binary
        include_private_ips: Whether to include RFC1918 / loopback IPs

    Returns:
        Dict mapping IOC type to list of unique matches
    """
    results: Dict[str, set] = {key: set() for key in PATTERNS}

    combined_text = "\n".join(str(s) for s in strings)

    for ioc_type, pattern in PATTERNS.items():
        matches = pattern.findall(combined_text)
        for match in matches:
            match = match.strip().rstrip(".,;:")  # Clean trailing punctuation

            # Filter private IPs unless requested
            if ioc_type == "ipv4" and not include_private_ips:
                if PRIVATE_IP_RANGES.match(match):
                    continue

            results[ioc_type].add(match)

    # Convert sets to sorted lists
    output = {}
    for ioc_type, matches in results.items():
        if matches:
            output[ioc_type] = sorted(matches)

    return output
