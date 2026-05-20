"""
Report generation for reverse engineering analysis
Structured static analysis report format
"""

from typing import Dict, Any, List
from src.utils.timezone import utc_now, format_display


class ReportGenerator:
    """Generates structured markdown reports from static analysis findings"""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.start_time = utc_now()

    def generate(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Generate a comprehensive static analysis report"""

        report_sections = []

        # Binary Information
        report_sections.append(self._build_challenge_info(metadata))

        # TL;DR Section (required)
        report_sections.append(self._build_tldr(findings, metadata))

        # Analysis Write-up
        report_sections.append(self._build_analysis_content(findings, metadata))

        # Solution Steps
        report_sections.append(self._build_solution_steps(findings))

        # Key Functions
        report_sections.append(self._build_function_analysis(findings))

        # Artifacts & IOCs
        report_sections.append(self._build_artifacts(findings, metadata))

        # Conclusion
        report_sections.append(self._build_conclusion(findings, metadata))

        # Reproducibility
        report_sections.append(self._build_reproducibility(metadata))

        return "\n".join(report_sections)

    def _build_challenge_info(self, metadata: Dict[str, Any]) -> str:
        """Build binary information section"""
        binary_name = metadata.get('name', 'unknown')

        return f"""# Binary Reverse Engineering Report: {binary_name}

## Binary Information

| Field | Value |
|-------|-------|
| **Binary Name** | `{binary_name}` |
| **Category** | Reverse Engineering |
| **Architecture** | {metadata.get('language', 'Unknown')} |
| **Format** | {metadata.get('executable_format', 'Unknown')} |
| **Compiler** | {metadata.get('compiler', 'Unknown')} |
| **SHA-256** | `{metadata.get('executable_sha256', 'N/A')[:16]}...` |
| **Analysis Date** | {format_display(fmt='%Y-%m-%d')} |

"""

    def _build_tldr(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Build TL;DR section (minimum 50 words required)"""
        binary_name = metadata.get('name', 'unknown binary')
        function_count = metadata.get('function_count', 0)
        arch = metadata.get('language', 'unknown architecture')

        # Extract key findings
        renamed_count = len(findings.get('renamed_functions', []))
        imports_count = len(findings.get('imports', []))
        suspicious_count = len(findings.get('suspicious', []))

        # Build capability summary
        capabilities = []
        imports = findings.get('imports', [])
        if any('socket' in str(i).lower() or 'internet' in str(i).lower() for i in imports):
            capabilities.append("**network communication**")
        if any('file' in str(i).lower() or 'write' in str(i).lower() for i in imports):
            capabilities.append("**file operations**")
        if any('process' in str(i).lower() or 'create' in str(i).lower() for i in imports):
            capabilities.append("**process manipulation**")

        caps_str = ", ".join(capabilities) if capabilities else "standard operations"

        return f"""## TL;DR

This write-up documents the **static analysis** of `{binary_name}`, a **{arch}** executable. Using **Ghidra** with automated tooling, the binary was fully decompiled and analyzed to understand its functionality. The analysis identified **{function_count} functions**, of which **{renamed_count}** were meaningfully renamed with descriptive identifiers. The binary imports **{imports_count} external functions** and demonstrates capabilities including {caps_str}. Key functions were decompiled to C pseudocode and annotated to reveal the program's logic flow. {"Security analysis flagged **" + str(suspicious_count) + " potential concerns** requiring further investigation." if suspicious_count > 0 else "No immediate security concerns were identified in static analysis."} All findings are documented below with **reproducible steps**, **code snippets**, and **detailed explanations** of the analysis methodology.

"""

    def _build_analysis_content(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Build main analysis content section"""
        section = ["## Analysis Approach\n"]

        section.append("### Initial Reconnaissance")
        section.append(f"The binary was loaded into **Ghidra** for static analysis. ")
        section.append(f"Initial examination revealed a **{metadata.get('language', 'unknown')}** ")
        section.append(f"executable in **{metadata.get('executable_format', 'unknown')}** format ")
        section.append(f"with **{metadata.get('function_count', 0)} total functions**.\n")

        # Memory layout
        segments = findings.get('segments', [])
        if segments:
            section.append("### Memory Layout\n")
            section.append("The binary's memory segments reveal the following structure:\n")
            section.append("| Segment | Address Range | Size | Permissions |")
            section.append("|---------|---------------|------|-------------|")

            for seg in segments[:15]:
                if isinstance(seg, dict):
                    name = seg.get('name', 'unknown')
                    start = seg.get('start', 'unknown')
                    end = seg.get('end', 'unknown')
                    size = seg.get('size', 0)
                    perms = []
                    if seg.get('read'): perms.append('R')
                    if seg.get('write'): perms.append('W')
                    if seg.get('execute'): perms.append('X')
                    perm_str = ''.join(perms) if perms else '-'

                    section.append(f"| `{name}` | {start} - {end} | {size} bytes | {perm_str} |")

            section.append("")

        # Entry points
        entry_points = findings.get('entry_points', [])
        if entry_points:
            section.append("### Entry Point Analysis\n")
            section.append("The binary's execution begins at the following entry points:\n")

            for ep in entry_points[:5]:
                if isinstance(ep, dict):
                    section.append(f"- **`{ep.get('name')}`** at `{ep.get('address')}` - Primary entry point")

            section.append("")

        return "\n".join(section) + "\n"

    def _build_solution_steps(self, findings: Dict[str, Any]) -> str:
        """Build step-by-step solution walkthrough"""
        section = ["## Solution Walkthrough\n"]

        section.append("### Step 1: Import and Auto-Analysis\n")
        section.append("The binary was imported into Ghidra, which automatically performed:")
        section.append("- **Function discovery** - Identified all subroutines and function boundaries")
        section.append("- **Data type analysis** - Detected strings, pointers, and data structures")
        section.append("- **Control flow analysis** - Mapped function calls and conditional branches\n")

        section.append("### Step 2: Function Enumeration\n")
        section.append("Using the `list_functions()` tool, all functions were enumerated. ")
        section.append("Functions with auto-generated names (e.g., `FUN_00401234`) were flagged for analysis.\n")

        section.append("### Step 3: Import Analysis\n")
        imports = findings.get('imports', [])
        if imports:
            section.append(f"The binary imports **{len(imports)} external functions**, revealing its dependencies and capabilities. ")
            section.append("Key imports were categorized by functionality (network, file, process, crypto).\n")

        section.append("### Step 4: String Analysis\n")
        strings = findings.get('strings', [])
        if strings:
            section.append(f"Extracted **{len(strings)} strings** from the binary. ")
            section.append("Strings were analyzed for patterns indicating functionality, ")
            section.append("such as error messages, file paths, URLs, and hardcoded credentials.\n")

        section.append("### Step 5: Function Decompilation\n")
        analyzed_funcs = findings.get('analyzed_functions', [])
        if analyzed_funcs:
            section.append(f"**{len(analyzed_funcs)} key functions** were decompiled to C pseudocode. ")
            section.append("Each function was examined to understand its purpose, logic flow, and potential security implications.\n")

        section.append("### Step 6: Function Renaming\n")
        renamed = findings.get('renamed_functions', [])
        if renamed:
            section.append(f"**{len(renamed)} functions** were renamed with descriptive identifiers prefixed with `VIBE_`. ")
            section.append("This improves code readability and documents the analysis findings directly in the Ghidra project.\n")

        return "\n".join(section) + "\n"

    def _build_function_analysis(self, findings: Dict[str, Any]) -> str:
        """Build detailed function analysis section"""
        analyzed_functions = findings.get('analyzed_functions', [])

        if not analyzed_functions:
            return "## Key Functions\n\n*No functions were specifically analyzed in detail.*\n\n"

        section = ["## Key Functions\n"]

        section.append("The following functions were identified as critical to understanding the binary's behavior. ")
        section.append("Each function has been **decompiled**, **analyzed**, and **renamed** with descriptive identifiers.\n")

        # Limit to most important functions
        for idx, func in enumerate(analyzed_functions[:10], 1):
            if isinstance(func, dict):
                name = func.get('name', 'unknown')
                address = func.get('address', 'unknown')
                desc = func.get('description', 'Function purpose not documented')

                section.append(f"### {idx}. `{name}` at `{address}`\n")
                section.append(f"**Purpose**: {desc}\n")

                if func.get('decompilation'):
                    section.append("**Decompiled C Code**:")
                    section.append("```c")
                    # Show first 800 characters
                    code = func['decompilation']
                    if len(code) > 800:
                        section.append(code[:800])
                        section.append("// ... (truncated for brevity)")
                    else:
                        section.append(code)
                    section.append("```\n")

                # Add analysis notes if present
                if func.get('notes'):
                    section.append(f"**Analysis Notes**: {func['notes']}\n")

        return "\n".join(section) + "\n"

    def _build_artifacts(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Build artifacts and IOCs section"""
        section = ["## Artifacts & Indicators\n"]

        # Imports categorized
        imports = findings.get('imports', [])
        if imports:
            section.append("### Imported Functions\n")

            # Categorize
            network_funcs = []
            file_funcs = []
            process_funcs = []
            crypto_funcs = []

            network_keywords = ['socket', 'connect', 'send', 'recv', 'internet', 'http', 'url', 'net', 'ws']
            file_keywords = ['file', 'read', 'write', 'open', 'close', 'delete', 'create', 'fopen']
            process_keywords = ['process', 'thread', 'exec', 'create', 'terminate', 'inject', 'alloc']
            crypto_keywords = ['crypt', 'hash', 'encrypt', 'decrypt', 'cipher', 'aes', 'rsa', 'md5', 'sha']

            for imp in imports:
                imp_str = str(imp).lower()
                if any(kw in imp_str for kw in network_keywords):
                    network_funcs.append(imp)
                elif any(kw in imp_str for kw in file_keywords):
                    file_funcs.append(imp)
                elif any(kw in imp_str for kw in process_keywords):
                    process_funcs.append(imp)
                elif any(kw in imp_str for kw in crypto_keywords):
                    crypto_funcs.append(imp)

            if network_funcs:
                section.append("**Network Functions** - Indicates network communication capability:")
                for f in network_funcs[:10]:
                    section.append(f"- `{f}`")
                section.append("")

            if file_funcs:
                section.append("**File Operations** - Indicates file system interaction:")
                for f in file_funcs[:10]:
                    section.append(f"- `{f}`")
                section.append("")

            if process_funcs:
                section.append("**Process/Memory Functions** - Indicates process manipulation:")
                for f in process_funcs[:10]:
                    section.append(f"- `{f}`")
                section.append("")

            if crypto_funcs:
                section.append("**Cryptographic Functions** - Indicates encryption/hashing:")
                for f in crypto_funcs[:10]:
                    section.append(f"- `{f}`")
                section.append("")

        # Interesting strings
        strings = findings.get('strings', [])
        suspicious_strings = [s for s in strings if any(
            kw in str(s).lower() for kw in ['password', 'secret', 'key', 'admin', 'root', 'http', 'url', 'flag']
        )]

        if suspicious_strings:
            section.append("### Notable Strings\n")
            section.append("The following strings may indicate functionality or contain sensitive information:\n")
            for s in suspicious_strings[:15]:
                section.append(f"- `{str(s)[:80]}`")
            section.append("")

        # Hash
        section.append("### Binary Identification\n")
        section.append("| Hash Type | Value |")
        section.append("|-----------|-------|")
        section.append(f"| **SHA-256** | `{metadata.get('executable_sha256', 'N/A')}` |")
        section.append("")

        return "\n".join(section) + "\n"

    def _build_conclusion(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Build conclusion section"""
        function_count = len(findings.get('analyzed_functions', []))
        renamed_count = len(findings.get('renamed_functions', []))
        total_funcs = metadata.get('function_count', 0)
        duration = str(utc_now() - self.start_time).split('.')[0]  # Remove microseconds

        section = ["## Conclusion\n"]

        # Summary
        section.append(f"Through **automated static analysis** using Ghidra, the binary `{metadata.get('name', 'unknown')}` ")
        section.append(f"has been thoroughly examined and documented. ")
        section.append(f"The analysis successfully **decompiled {function_count} critical functions**, ")
        section.append(f"**renamed {renamed_count} functions** for clarity, and identified the binary's capabilities ")
        section.append(f"through import and string analysis.\n")

        # Key Takeaways
        section.append("### Key Takeaways\n")
        section.append(f"- **Total Functions**: {total_funcs}")
        section.append(f"- **Functions Analyzed**: {function_count}")
        section.append(f"- **Functions Renamed**: {renamed_count}")
        section.append(f"- **Imported APIs**: {len(findings.get('imports', []))}")
        section.append(f"- **Strings Extracted**: {len(findings.get('strings', []))}")
        section.append(f"- **Analysis Duration**: {duration}\n")

        # Security assessment
        imports = findings.get('imports', [])
        has_network = any('socket' in str(i).lower() or 'internet' in str(i).lower() for i in imports)
        has_file = any('file' in str(i).lower() or 'write' in str(i).lower() for i in imports)
        has_process = any('process' in str(i).lower() or 'inject' in str(i).lower() for i in imports)

        section.append("### Capability Assessment\n")
        if has_network:
            section.append("- [*][*]  **Network Activity**: Binary has network communication capabilities")
        if has_file:
            section.append("- [*][*]  **File System Access**: Binary can interact with the file system")
        if has_process:
            section.append("- [*][*]  **Process Interaction**: Binary may manipulate other processes")
        if not (has_network or has_file or has_process):
            section.append("- [OK] **Limited Capabilities**: No obvious malicious indicators detected\n")

        section.append("\n### Recommended Next Steps\n")
        section.append("1. **Dynamic Analysis** - Execute in isolated sandbox to observe runtime behavior")
        section.append("2. **Network Monitoring** - Capture any network traffic during execution")
        section.append("3. **Manual Review** - Verify function renames and decompilation accuracy")
        section.append("4. **IOC Extraction** - Extract IP addresses, URLs, file paths for threat intelligence")
        section.append("5. **Malware Database Check** - Query hash against VirusTotal, MalwareBazaar, etc.\n")

        return "\n".join(section) + "\n"

    def _build_reproducibility(self, metadata: Dict[str, Any]) -> str:
        """Build reproducibility section"""
        section = ["## Reproducibility\n"]

        section.append("### Requirements\n")
        section.append("- **Ghidra**: Version 11.0+ (tested with 11.0.1)")
        section.append("- **Python**: 3.11+ with PyGhidra")
        section.append("- **Analysis Tools**: MCP tools for automated analysis")
        section.append("- **Binary**: SHA-256 hash provided above\n")

        section.append("### Steps to Reproduce\n")
        section.append("1. **Import Binary** - Load the binary into Ghidra")
        section.append("2. **Run Auto-Analysis** - Execute Ghidra's auto-analysis (may take 5-30 seconds)")
        section.append("3. **Use MCP Tools** - Access tools via `list_functions()`, `decompile_function()`, etc.")
        section.append("4. **Review Findings** - Compare decompiled functions against this write-up")
        section.append("5. **Verify Renames** - Functions prefixed with `VIBE_` match documented analysis\n")

        section.append("### Analysis Artifacts\n")
        section.append(f"- **Ghidra Project**: Available in job directory")
        section.append(f"- **Job ID**: `{self.job_id}`")
        section.append(f"- **Report Generated**: {format_display(fmt='%Y-%m-%d %H:%M:%S %Z')}\n")

        section.append("---\n")
        section.append("*This write-up was generated using automated reverse engineering tools. ")
        section.append("All findings should be independently verified for accuracy.*\n")

        return "\n".join(section)
