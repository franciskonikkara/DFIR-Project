"""
Memory forensics automation.

Wraps Volatility 3 (preferred) with fallback to Volatility 2 for:
  - Process listing and injection detection
  - Network connections from memory
  - DLL listing and suspicious DLL detection
  - String/IOC extraction from memory dumps
  - Credential extraction helpers (for authorized testing)
  - YARA scanning of memory

Requires:
    pip install volatility3
  or Volatility 3 installed at path configured in VOLATILITY_PATH env var.
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.ioc_extractor import IOCExtractor, IOCBundle
from src.utils.hash_utils import compute_hash


@dataclass
class MemoryProcess:
    pid: int
    ppid: int
    name: str
    offset: str
    threads: int
    handles: int
    session_id: Optional[int]
    wow64: bool
    create_time: Optional[str]
    exit_time: Optional[str]


@dataclass
class MemoryNetConn:
    offset: str
    protocol: str
    local_addr: str
    local_port: int
    foreign_addr: str
    foreign_port: int
    state: str
    pid: int
    owner: str
    created: Optional[str]


@dataclass
class MemoryDLL:
    pid: int
    base: str
    size: int
    name: str
    full_path: str
    load_time: Optional[str]


class MemoryForensics:
    """
    Interface for automated memory forensics using Volatility 3.

    Usage:
        mf = MemoryForensics("memory.dmp", "Win10x64_19041")
        processes = mf.list_processes()
        injected = mf.find_process_injection()
        iocs = mf.extract_strings_iocs()
    """

    def __init__(self, dump_path: str, profile: Optional[str] = None):
        self.dump_path = str(Path(dump_path).resolve())
        self.profile = profile
        self._vol_cmd = self._detect_volatility()
        self._ioc_extractor = IOCExtractor()

    # ------------------------------------------------------------------
    # Core Analysis
    # ------------------------------------------------------------------

    def list_processes(self) -> List[MemoryProcess]:
        """Run pslist/pstree and return structured process list."""
        raw = self._run_plugin("windows.pslist.PsList")
        processes = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 7 and parts[0].isdigit():
                try:
                    processes.append(MemoryProcess(
                        pid=int(parts[0]),
                        ppid=int(parts[1]),
                        name=parts[2],
                        offset=parts[3] if len(parts) > 3 else "",
                        threads=int(parts[4]) if parts[4].isdigit() else 0,
                        handles=int(parts[5]) if parts[5].isdigit() else 0,
                        session_id=int(parts[6]) if parts[6].isdigit() else None,
                        wow64=parts[7].strip().lower() == "true" if len(parts) > 7 else False,
                        create_time=parts[8].strip() if len(parts) > 8 else None,
                        exit_time=parts[9].strip() if len(parts) > 9 else None,
                    ))
                except (ValueError, IndexError):
                    continue
        return processes

    def list_network_connections(self) -> List[MemoryNetConn]:
        """Extract network connections via netscan/netstat."""
        raw = self._run_plugin("windows.netstat.NetStat")
        connections = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 8:
                try:
                    laddr, _, lport = parts[2].rpartition(":")
                    faddr, _, fport = parts[3].rpartition(":")
                    connections.append(MemoryNetConn(
                        offset=parts[0],
                        protocol=parts[1],
                        local_addr=laddr,
                        local_port=int(lport) if lport.isdigit() else 0,
                        foreign_addr=faddr,
                        foreign_port=int(fport) if fport.isdigit() else 0,
                        state=parts[4],
                        pid=int(parts[5]) if parts[5].isdigit() else 0,
                        owner=parts[6],
                        created=parts[7].strip() if len(parts) > 7 else None,
                    ))
                except (ValueError, IndexError):
                    continue
        return connections

    def list_dlls(self, pid: Optional[int] = None) -> List[MemoryDLL]:
        """List loaded DLLs for all processes or a specific PID."""
        plugin = "windows.dlllist.DllList"
        args = [f"--pid={pid}"] if pid else []
        raw = self._run_plugin(plugin, args)
        dlls = []
        current_pid = 0
        for line in raw.splitlines():
            # PID header lines
            pid_match = re.match(r"^(\d+)\s+(\S+)", line)
            if pid_match and not line.startswith("0x"):
                current_pid = int(pid_match.group(1))
                continue
            parts = line.split("\t")
            if len(parts) >= 4 and parts[0].startswith("0x"):
                try:
                    dlls.append(MemoryDLL(
                        pid=current_pid,
                        base=parts[0],
                        size=int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1]),
                        name=parts[2],
                        full_path=parts[3].strip() if len(parts) > 3 else "",
                        load_time=parts[4].strip() if len(parts) > 4 else None,
                    ))
                except (ValueError, IndexError):
                    continue
        return dlls

    def find_process_injection(self) -> List[dict]:
        """Detect common process injection techniques via malfind."""
        raw = self._run_plugin("windows.malfind.Malfind")
        injected = []
        current = {}
        for line in raw.splitlines():
            if line.startswith("PID:") or ("Process:" in line):
                if current:
                    injected.append(current)
                current = {"raw_line": line}
            elif current:
                current.setdefault("details", []).append(line)
        if current:
            injected.append(current)
        return injected

    def scan_with_yara(self, yara_rules_path: str) -> List[dict]:
        """Scan memory dump with YARA rules."""
        raw = self._run_plugin("yarascan.YaraScan", [f"--yara-file={yara_rules_path}"])
        hits = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                hits.append({
                    "rule": parts[0],
                    "offset": parts[1],
                    "pid": parts[2] if len(parts) > 2 else "N/A",
                    "process": parts[3] if len(parts) > 3 else "N/A",
                })
        return hits

    def extract_strings_iocs(self, min_length: int = 6) -> IOCBundle:
        """Extract printable strings from memory dump and parse IOCs."""
        strings_output = self._run_plugin(
            "windows.strings.Strings", [f"--min-length={min_length}"]
        )
        return self._ioc_extractor.extract(strings_output)

    def dump_process_memory(self, pid: int, output_dir: str) -> Optional[str]:
        """Dump a process's memory to disk for further analysis."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        raw = self._run_plugin(
            "windows.memmap.Memmap", [f"--pid={pid}", f"--dump", f"--output-dir={output_dir}"]
        )
        # Find dumped file path from output
        for line in raw.splitlines():
            if "dump" in line.lower() and ".dmp" in line.lower():
                return line.strip()
        return output_dir

    # ------------------------------------------------------------------
    # Analysis Helpers
    # ------------------------------------------------------------------

    def detect_rootkit_indicators(self) -> dict:
        """Run DKOM and hidden process detection."""
        pslist = self._run_plugin("windows.pslist.PsList")
        psscan = self._run_plugin("windows.psscan.PsScan")
        # PIDs in psscan but not pslist indicate hidden processes
        pslist_pids = set(re.findall(r"^\d+", pslist, re.MULTILINE))
        psscan_pids = set(re.findall(r"^\d+", psscan, re.MULTILINE))
        hidden_pids = psscan_pids - pslist_pids
        return {
            "hidden_process_pids": sorted(hidden_pids),
            "pslist_count": len(pslist_pids),
            "psscan_count": len(psscan_pids),
            "dkom_suspected": bool(hidden_pids),
        }

    def get_command_history(self) -> List[str]:
        """Extract console command history from memory."""
        raw = self._run_plugin("windows.cmdline.CmdLine")
        commands = []
        for line in raw.splitlines():
            if "Command line" in line or (": " in line and len(line) > 10):
                commands.append(line.strip())
        return commands

    def get_registry_hives(self) -> List[dict]:
        """List in-memory registry hives."""
        raw = self._run_plugin("windows.registry.hivelist.HiveList")
        hives = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                hives.append({"offset": parts[0], "name": parts[1].strip()})
        return hives

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_plugin(self, plugin: str, extra_args: list = None) -> str:
        """Execute a Volatility 3 plugin and return stdout."""
        cmd = self._build_command(plugin, extra_args or [])
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            return result.stdout
        except FileNotFoundError:
            return f"[ERROR] Volatility not found. Install with: pip install volatility3\nCommand: {' '.join(cmd)}"
        except subprocess.TimeoutExpired:
            return "[ERROR] Volatility plugin timed out (>300s)"

    def _build_command(self, plugin: str, extra_args: list) -> list:
        cmd = [self._vol_cmd, "-f", self.dump_path]
        if self.profile:
            cmd += ["--profile", self.profile]
        cmd.append(plugin)
        cmd += extra_args
        return cmd

    @staticmethod
    def _detect_volatility() -> str:
        """Detect the Volatility 3 executable name."""
        for candidate in ("vol", "vol.py", "volatility", "volatility3", "python -m volatility3"):
            if shutil.which(candidate.split()[0]):
                return candidate
        return "vol"  # default, will fail gracefully


# Lazy import shutil (already in stdlib)
import shutil
