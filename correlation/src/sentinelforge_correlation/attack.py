"""MITRE ATT&CK technique mapping for SentinelForge alerts and rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


def _normalize_reference(value: Any) -> str:
    """Normalize ATT&CK identifiers and names for case-insensitive matching."""
    text = str(value).strip()
    if not text:
        return ""

    normalized = text.lower()
    for prefix in (
        "mitre_attack.",
        "mitre.",
        "attack.",
        "mitre attack:",
        "mitre-attack:",
        "mitre:",
        "attack:",
        "att&ck:",
        "attck:",
    ):
        normalized = normalized.replace(prefix, "")

    normalized = normalized.replace("&", "and")
    normalized = normalized.replace("_", " ")
    normalized = normalized.replace("-", " ")
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


class Tactic(str, Enum):
    """MITRE ATT&CK tactics in kill-chain order."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

    @property
    def kill_chain_order(self) -> int:
        """Return the kill-chain order index for sorting."""
        order = {
            Tactic.RECONNAISSANCE: 0,
            Tactic.RESOURCE_DEVELOPMENT: 1,
            Tactic.INITIAL_ACCESS: 2,
            Tactic.EXECUTION: 3,
            Tactic.PERSISTENCE: 4,
            Tactic.PRIVILEGE_ESCALATION: 5,
            Tactic.DEFENSE_EVASION: 6,
            Tactic.CREDENTIAL_ACCESS: 7,
            Tactic.DISCOVERY: 8,
            Tactic.LATERAL_MOVEMENT: 9,
            Tactic.COLLECTION: 10,
            Tactic.COMMAND_AND_CONTROL: 11,
            Tactic.EXFILTRATION: 12,
            Tactic.IMPACT: 13,
        }
        return order.get(self, 99)


_TACTIC_IDS: dict[Tactic, str] = {
    Tactic.RECONNAISSANCE: "TA0043",
    Tactic.RESOURCE_DEVELOPMENT: "TA0042",
    Tactic.INITIAL_ACCESS: "TA0001",
    Tactic.EXECUTION: "TA0002",
    Tactic.PERSISTENCE: "TA0003",
    Tactic.PRIVILEGE_ESCALATION: "TA0004",
    Tactic.DEFENSE_EVASION: "TA0005",
    Tactic.CREDENTIAL_ACCESS: "TA0006",
    Tactic.DISCOVERY: "TA0007",
    Tactic.LATERAL_MOVEMENT: "TA0008",
    Tactic.COLLECTION: "TA0009",
    Tactic.EXFILTRATION: "TA0010",
    Tactic.COMMAND_AND_CONTROL: "TA0011",
    Tactic.IMPACT: "TA0040",
}


@dataclass(frozen=True, slots=True)
class Technique:
    """A single ATT&CK technique with metadata."""

    id: str  # e.g., "T1059.001"
    name: str
    tactic: Tactic
    description: str = ""
    subtechniques: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ("Windows", "Linux", "macOS")
    data_sources: tuple[str, ...] = ()

    @property
    def tactic_id(self) -> str:
        """Return the tactic ID (e.g., TA0002 for execution)."""
        return _TACTIC_IDS.get(self.tactic, "TA0000")


# Core ATT&CK techniques relevant to endpoint telemetry.
# This is a curated subset; in production, load from MITRE ATT&CK STIX data.
_TECHNIQUES: dict[str, Technique] = {
    # Initial Access
    "T1566.001": Technique(
        id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic=Tactic.INITIAL_ACCESS,
        description="Adversaries may send spearphishing emails with a malicious attachment.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Email", "File", "Process"),
    ),
    "T1190": Technique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic=Tactic.INITIAL_ACCESS,
        description="Adversaries may exploit vulnerabilities in public-facing applications.",
        platforms=("Windows", "Linux"),
        data_sources=("Web Logs", "Application Logs"),
    ),
    "T1078": Technique(
        id="T1078",
        name="Valid Accounts",
        tactic=Tactic.INITIAL_ACCESS,
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Authentication Logs", "Active Directory"),
    ),
    # Execution
    "T1059.001": Technique(
        id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic=Tactic.EXECUTION,
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
        platforms=("Windows",),
        data_sources=("Process", "Command Line", "Script Block Logging"),
    ),
    "T1059.003": Technique(
        id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic=Tactic.EXECUTION,
        description="Adversaries may abuse the Windows command shell for execution.",
        platforms=("Windows",),
        data_sources=("Process", "Command Line"),
    ),
    "T1059.004": Technique(
        id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic=Tactic.EXECUTION,
        description="Adversaries may abuse Unix shell commands and scripts for execution.",
        platforms=("Linux", "macOS"),
        data_sources=("Process", "Command Line", "Shell History"),
    ),
    "T1053.005": Technique(
        id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=Tactic.EXECUTION,
        description="Adversaries may abuse the Windows Task Scheduler to perform task scheduling.",
        platforms=("Windows",),
        data_sources=("Scheduled Task", "Process", "File"),
    ),
    # Persistence
    "T1547.001": Technique(
        id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic=Tactic.PERSISTENCE,
        description="Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry Run key.",
        platforms=("Windows",),
        data_sources=("Registry", "File", "Process"),
    ),
    "T1543.003": Technique(
        id="T1543.003",
        name="Create or Modify System Process: Windows Service",
        tactic=Tactic.PERSISTENCE,
        description="Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
        platforms=("Windows",),
        data_sources=("Service", "Registry", "Process"),
    ),
    "T1505.003": Technique(
        id="T1505.003",
        name="Server Software Component: Web Shell",
        tactic=Tactic.PERSISTENCE,
        description="Adversaries may backdoor web servers with web shells to establish persistent access.",
        platforms=("Windows", "Linux"),
        data_sources=("File", "Web Logs", "Process"),
    ),
    "T1037": Technique(
        id="T1037",
        name="Boot or Logon Initialization Scripts",
        tactic=Tactic.PERSISTENCE,
        description="Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Command Line"),
    ),
    # Privilege Escalation
    "T1068": Technique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        description="Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Process", "Module", "Vulnerability"),
    ),
    "T1548.002": Technique(
        id="T1548.002",
        name="Abuse Elevation Control Mechanism: Bypass User Account Control",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        description="Adversaries may bypass UAC mechanisms to elevate process privileges.",
        platforms=("Windows",),
        data_sources=("Process", "File", "Registry"),
    ),
    # Defense Evasion
    "T1070.004": Technique(
        id="T1070.004",
        name="Indicator Removal: File Deletion",
        tactic=Tactic.DEFENSE_EVASION,
        description="Adversaries may delete files to remove traces of their activity.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process"),
    ),
    "T1036.005": Technique(
        id="T1036.005",
        name="Masquerading: Match Legitimate Name or Location",
        tactic=Tactic.DEFENSE_EVASION,
        description="Adversaries may rename or relocate executables to match legitimate names/locations.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Module"),
    ),
    "T1562.001": Technique(
        id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic=Tactic.DEFENSE_EVASION,
        description="Adversaries may disable or modify security tools to avoid detection.",
        platforms=("Windows", "Linux"),
        data_sources=("Process", "Service", "Registry", "File"),
    ),
    "T1140": Technique(
        id="T1140",
        name="Deobfuscate/Decode Files or Information",
        tactic=Tactic.DEFENSE_EVASION,
        description="Adversaries may use obfuscation/encoding to hide artifacts.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Command Line"),
    ),
    # Credential Access
    "T1003.001": Technique(
        id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=Tactic.CREDENTIAL_ACCESS,
        description="Adversaries may dump LSASS memory to obtain credentials.",
        platforms=("Windows",),
        data_sources=("Process", "File", "API"),
    ),
    "T1555.003": Technique(
        id="T1555.003",
        name="Credentials from Password Stores: Credentials from Web Browsers",
        tactic=Tactic.CREDENTIAL_ACCESS,
        description="Adversaries may extract credentials from web browsers.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Browser"),
    ),
    "T1056.001": Technique(
        id="T1056.001",
        name="Input Capture: Keylogging",
        tactic=Tactic.CREDENTIAL_ACCESS,
        description="Adversaries may log keystrokes to intercept credentials.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Process", "Driver", "API"),
    ),
    # Discovery
    "T1082": Technique(
        id="T1082",
        name="System Information Discovery",
        tactic=Tactic.DISCOVERY,
        description="Adversaries may gather system information for situational awareness.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Process", "Command Line", "System"),
    ),
    "T1057": Technique(
        id="T1057",
        name="Process Discovery",
        tactic=Tactic.DISCOVERY,
        description="Adversaries may enumerate processes to understand the environment.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Process", "Command Line"),
    ),
    "T1018": Technique(
        id="T1018",
        name="Remote System Discovery",
        tactic=Tactic.DISCOVERY,
        description="Adversaries may enumerate remote systems for lateral movement targets.",
        platforms=("Windows", "Linux"),
        data_sources=("Network", "Process", "Command Line"),
    ),
    "T1083": Technique(
        id="T1083",
        name="File and Directory Discovery",
        tactic=Tactic.DISCOVERY,
        description="Adversaries may enumerate files and directories.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Command Line"),
    ),
    # Lateral Movement
    "T1021.001": Technique(
        id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        tactic=Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use RDP for lateral movement.",
        platforms=("Windows",),
        data_sources=("Network", "Authentication", "Process"),
    ),
    "T1021.002": Technique(
        id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic=Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use SMB and admin shares for lateral movement.",
        platforms=("Windows",),
        data_sources=("Network", "File", "Authentication"),
    ),
    "T1021.004": Technique(
        id="T1021.004",
        name="Remote Services: SSH",
        tactic=Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use SSH for lateral movement.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "Authentication", "Process"),
    ),
    "T1550.002": Technique(
        id="T1550.002",
        name="Use Alternate Authentication Material: Pass the Hash",
        tactic=Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use stolen password hashes to authenticate and move laterally.",
        platforms=("Windows",),
        data_sources=("Authentication", "Network", "Process"),
    ),
    "T1550.003": Technique(
        id="T1550.003",
        name="Use Alternate Authentication Material: Pass the Ticket",
        tactic=Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use stolen Kerberos tickets for lateral movement.",
        platforms=("Windows",),
        data_sources=("Authentication", "Network", "Ticket"),
    ),
    # Collection
    "T1005": Technique(
        id="T1005",
        name="Data from Local System",
        tactic=Tactic.COLLECTION,
        description="Adversaries may collect data from local system.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "Command Line"),
    ),
    "T1039": Technique(
        id="T1039",
        name="Data from Network Shared Drive",
        tactic=Tactic.COLLECTION,
        description="Adversaries may collect data from network shares.",
        platforms=("Windows", "Linux"),
        data_sources=("File", "Network", "Authentication"),
    ),
    # Command and Control
    "T1071.001": Technique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic=Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may use web protocols for C2.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "Process", "Flow"),
    ),
    "T1071.004": Technique(
        id="T1071.004",
        name="Application Layer Protocol: DNS",
        tactic=Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may use DNS for C2.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "DNS", "Process"),
    ),
    "T1573.001": Technique(
        id="T1573.001",
        name="Encrypted Channel: Symmetric Cryptography",
        tactic=Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may use symmetric encryption for C2.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "Process", "Flow"),
    ),
    # Exfiltration
    "T1041": Technique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic=Tactic.EXFILTRATION,
        description="Adversaries may exfiltrate data over existing C2 channel.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "Flow", "Process"),
    ),
    "T1048": Technique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic=Tactic.EXFILTRATION,
        description="Adversaries may exfiltrate data over alternative protocols.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("Network", "Flow", "Process"),
    ),
    # Impact
    "T1486": Technique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic=Tactic.IMPACT,
        description="Adversaries may encrypt data for impact.",
        platforms=("Windows", "Linux", "macOS"),
        data_sources=("File", "Process", "API"),
    ),
    "T1490": Technique(
        id="T1490",
        name="Inhibit System Recovery",
        tactic=Tactic.IMPACT,
        description="Adversaries may delete/disable recovery options.",
        platforms=("Windows", "Linux"),
        data_sources=("File", "Process", "Service", "Command Line"),
    ),
}


class ATTACKMapper:
    """Resolve ATT&CK techniques from IDs, names or alert metadata."""

    def __init__(self, techniques: Mapping[str, Technique] | None = None) -> None:
        self.techniques: dict[str, Technique] = dict(_TECHNIQUES)
        if techniques:
            self.techniques.update({key: value for key, value in techniques.items() if value is not None})

    def get(self, technique_id: str) -> Technique | None:
        """Return a technique by ID or name."""
        if not technique_id:
            return None

        key = str(technique_id).strip()
        if key in self.techniques:
            return self.techniques[key]

        search_key = key.lower()
        normalized = _normalize_reference(key)
        for technique in self.techniques.values():
            if technique.id.lower() == search_key:
                return technique
            if technique.name.lower() == search_key:
                return technique
            if _normalize_reference(technique.id) == normalized:
                return technique
            if _normalize_reference(technique.name) == normalized:
                return technique
        return None

    def resolve(self, value: str | Technique | None) -> Technique | None:
        """Resolve a technique reference to a Technique object."""
        if isinstance(value, Technique):
            return value
        if value is None:
            return None
        return self.get(str(value))

    def map(self, values: str | Technique | Iterable[str | Technique] | None) -> list[Technique]:
        """Return a de-duplicated list of techniques for the provided values."""
        if values is None:
            return []

        if isinstance(values, (str, Technique)):
            items: list[str | Technique] = [values]
        else:
            items = list(values)

        resolved: list[Technique] = []
        seen: set[str] = set()
        for item in items:
            technique = self.resolve(item)
            if technique is None:
                continue
            if technique.id in seen:
                continue
            seen.add(technique.id)
            resolved.append(technique)
        return resolved

    def map_alert(self, alert: Mapping[str, Any] | Any) -> list[Technique]:
        """Map a dict-like alert or rule payload into ATT&CK techniques."""
        if not isinstance(alert, Mapping):
            return []

        candidates: list[Any] = []
        for key in (
            "techniques",
            "technique",
            "mitre_techniques",
            "mitre_technique",
            "tags",
            "rule_tags",
            "attck",
            "attack",
        ):
            if key in alert:
                value = alert.get(key)
                if isinstance(value, (list, tuple, set)):
                    candidates.extend(value)
                elif value is not None:
                    candidates.append(value)

        if "rule" in alert and isinstance(alert["rule"], Mapping):
            rule = alert["rule"]
            for key in ("techniques", "technique", "mitre_techniques", "tags"):
                if key in rule:
                    value = rule[key]
                    if isinstance(value, (list, tuple, set)):
                        candidates.extend(value)
                    elif value is not None:
                        candidates.append(value)

        if not candidates and "title" in alert:
            title = str(alert["title"]).lower()
            if "powershell" in title:
                technique = self.get("T1059.001")
                return [technique] if technique else []
            if "cmd.exe" in title or "command shell" in title:
                technique = self.get("T1059.003")
                return [technique] if technique else []

        return self.map(candidates)

    def by_tactic(self, tactic: Tactic | str) -> list[Technique]:
        """Return all techniques in a given tactic."""
        if isinstance(tactic, str):
            normalized = tactic.lower().replace("-", " ")
            match = next(
                (item for item in Tactic if item.value.lower().replace("-", " ") == normalized),
                None,
            )
            if match is None:
                raise ValueError(f"Unknown ATT&CK tactic: {tactic!r}")
            tactic = match
        return sorted(
            (technique for technique in self.techniques.values() if technique.tactic == tactic),
            key=lambda technique: technique.id,
        )

    def tactics_for(self, alert: Mapping[str, Any] | Any) -> list[Tactic]:
        """Return the ATT&CK tactics associated with a mapped alert."""
        techniques = self.map_alert(alert)
        return list(dict.fromkeys(technique.tactic for technique in techniques))


__all__ = ["Tactic", "Technique", "ATTACKMapper", "_TECHNIQUES"]
