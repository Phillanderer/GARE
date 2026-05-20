# Compute per-section entropy for packing/encryption detection
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_entropy.py

import json
import sys
import math

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)


def compute_entropy(data):
    """Compute Shannon entropy of a byte sequence (0.0 - 8.0)"""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = float(len(data))
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log(p, 2)
    return round(entropy, 4)


try:
    memory = program.getMemory()
    blocks = memory.getBlocks()

    sections = []
    total_bytes = 0
    total_high_entropy = 0

    for block in blocks:
        name = str(block.getName())
        start = str(block.getStart())
        size = block.getSize()
        permissions = ""
        if block.isRead():
            permissions += "R"
        if block.isWrite():
            permissions += "W"
        if block.isExecute():
            permissions += "X"

        # Read block bytes for entropy calculation
        entropy = 0.0
        if block.isInitialized() and size > 0:
            # Cap read size to prevent memory issues
            read_size = min(size, 1024 * 1024)  # 1MB max per section
            data = bytearray(read_size)
            try:
                block.getBytes(block.getStart(), data)
                entropy = compute_entropy(data)
            except:
                entropy = -1.0  # Indicates read failure

        is_high_entropy = entropy > 7.0
        is_packed_indicator = entropy > 6.8 and block.isExecute()

        section_info = {
            "name": name,
            "address": start,
            "size": size,
            "permissions": permissions,
            "entropy": entropy,
            "high_entropy": is_high_entropy,
            "packed_indicator": is_packed_indicator
        }
        sections.append(section_info)
        total_bytes += size
        if is_high_entropy:
            total_high_entropy += size

    # Overall assessment
    high_entropy_ratio = total_high_entropy / total_bytes if total_bytes > 0 else 0
    likely_packed = high_entropy_ratio > 0.5

    result = {
        "sections": sections,
        "total_sections": len(sections),
        "total_bytes": total_bytes,
        "high_entropy_bytes": total_high_entropy,
        "high_entropy_ratio": round(high_entropy_ratio, 4),
        "likely_packed": likely_packed,
        "assessment": "LIKELY PACKED/ENCRYPTED" if likely_packed else "NOT PACKED"
    }
    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
