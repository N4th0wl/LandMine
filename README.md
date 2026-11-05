<div align="center">

# LandMine: Lightweight Windows EDR

**One process monitor for detecting LOLBin abuse, suspicious behavior, and active threats on Windows.**

Understand every process from its command line and parent lineage down to its network activity and image hash.

[![Rust](https://img.shields.io/badge/rust-2021-orange?logo=rust)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue?logo=windows)](https://www.microsoft.com/windows)
[![Threat Detection](https://img.shields.io/badge/threat-detection-red)](https://github.com/N4th0wl/LandMine)
[![GitHub Release](https://img.shields.io/github/v/release/N4th0wl/LandMine?logo=github)](https://github.com/N4th0wl/LandMine/releases)
[![Stars](https://img.shields.io/github/stars/N4th0wl/LandMine?style=social)](https://github.com/N4th0wl/LandMine/stargazers)

**Inspired by [lolbin-watcher](https://github.com/stevjoo/lolbin-watcher)**

</div>

## Overview

LandMine continuously inspects running processes in user space, evaluates process telemetry against layered behavioral heuristics and threat intelligence feeds, and emits structured security events.

- **Process Telemetry** — Captures PID, PPID, executable path, full command-line arguments, and PE `VS_VERSION_INFO` OriginalFilename metadata.
- **Layered Behavioral Detection** — Path heuristics, LOLBin database (28 execution and recon binaries), binary rename/masquerading analysis, obfuscated command-line detection, and anomalous parent-to-child process lineage tracking.
- **Authenticode Digital Signature Verification** — Verifies Microsoft Authenticode digital certificates via `WinVerifyTrust` to detect spoofed system binaries.
- **Network Connection Correlation** — Real-time tracking of outbound TCP connections (`GetExtendedTcpTable`) to flag LOLBin network beaconing and external C2 egress.
- **Threat Intelligence & Signature Scanning** — In-memory fast SHA-256 hash lookup and header pattern scanning (UPX packers, C2 beacon artifacts, Mimikatz signatures).
- **External Sigma-Lite TOML Rules** — Dynamic rule loader (`rules/detection_rules.toml`) allowing security analysts to deploy new detections without recompiling.
- **Stateful Lifecycle Deduplication** — Tracks processes across their entire lifecycle (`snapshot`, `started`, `elevated`, `terminated`) with token privilege escalation detection.
- **Active Defense & Forensic Mitigation** — Optional automated process suspension (`NtSuspendProcess`), termination (`TerminateProcess`), and crash minidump quarantine (`MiniDumpWriteDump`).
- **SIEM & Windows Event Log Integration** — Structured JSONL logging with size-based rotation, clean console alert cards, and native Windows Application Event Log forwarding.

---

## User Interface & Real-Time Monitoring

When launched, LandMine initializes an interactive terminal interface displaying the active engine configuration, loaded rule sets, threat intelligence feeds, and live alerts.

```text
  _                _      _               
 | |   __ _ _ _  _| |_ __(_)_ _  ___      
 | |__/ _` | ' \/ _ | '  \ | ' \/ -_)     
 |____\__,_|_||_\___|_|_|_|_|_||_\___|     
  [!] L I G H T W E I G H T   E D R [!]        
═════════════════════════════════════════════

  [ ENGINE PROFILE ]
  • Mode         : Continuous Monitoring (poll every 5s)
  • Privilege    : Administrator (Full System Visibility)
  • Log File     : logs/landmine.jsonl
  • Engine Rules : 41 custom rule(s) loaded (Sigma-lite)
  • Threat Intel : 14 malware hash(es) loaded
  • Defense      : ACTIVE (Suspend High + Kill Critical)
  • WinEvent Log : Enabled (Application Event Log)

  [ CLI USAGE & EXAMPLES ]
  landmine.exe --format pretty              Real-time colored terminal alerts
  landmine.exe --once                       Single-shot baseline audit and exit
  landmine.exe --winevent                   Forward Medium+ alerts to Windows Event Log
  landmine.exe --suspend-on-high            Pause execution of suspicious processes
  landmine.exe --kill-on-critical           Instantly terminate confirmed malicious attacks
  landmine.exe --dump-quarantine <DIR>      Capture memory minidump before killing

  Press [Ctrl + C] to stop monitoring.
═════════════════════════════════════════════════════════════════════════════
```

### Live Alert Cards

Suspicious process events are surfaced instantly in structured, box-drawing cards with severity-based color coding:

```text
[14:32:01] ┌──  CRIT   STARTED  ── office_spawning_shell ─────────────────────────
           │  Process : powershell.exe <- winword.exe (PID: 4821, PPID: 1200)
           │  Path    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
           │  Command : powershell.exe -nop -enc ZQBjAGgAbwA=
           │  Network : 185.220.101.5:443 (Outbound Public)
           │  SHA-256 : a3f1c2d4e5f6...
           │  Flags   : [lolbin_process, cmdline_obfuscation, suspicious_parent_spawn]
           └────────────────────────────────────────────────────────────────────────────
```

---

## Quick Start & Build

### Prerequisites

- Windows 10 / 11 or Windows Server 2016+
- Rust toolchain (`rustup` + `cargo`) — [install from rustup.rs](https://rustup.rs)
- **Run as Administrator** for full access to system-level process tokens and image paths.

### Compilation

```bash
git clone https://github.com/N4th0wl/LandMine
cd LandMine
cargo build --release
```

The compiled standalone executable (~1.3 MB) is located at:
```text
target\release\landmine.exe
```

---

## How to Run & Execution Scenarios

### 1. Default Interactive Real-Time Monitoring
Launches continuous monitoring, polling the system every 5 seconds with colored alert cards:
```powershell
.\target\release\landmine.exe
```

### 2. Single-Shot Baseline Audit
Performs a single evaluation pass across all running processes and exits:
```powershell
.\target\release\landmine.exe --once
```

### 3. Aggressive Monitoring with Custom Interval
Polls every 2 seconds and writes logs to a dedicated path:
```powershell
.\target\release\landmine.exe --interval 2 --out C:\Logs\edr_alerts.jsonl
```

### 4. SIEM Ingestion & JSON Stream Piping
Outputs raw JSONL lines without ANSI escape sequences, ready for piping to `jq`, Vector, or log forwarders:
```powershell
.\target\release\landmine.exe --format jsonl | jq 'select(.severity == "High" or .severity == "Critical")'
```

### 5. Windows Application Event Log Forwarding
Emits all Medium, High, and Critical detections into the Windows Event Log (`Application` source: `LandMine`) for SIEM agents (Wazuh, Splunk, Elastic Agent):
```powershell
.\target\release\landmine.exe --winevent
```

### 6. Active Defense & Forensic Mitigation
Automatically suspends suspicious processes, terminates confirmed critical attacks, and writes memory minidumps prior to termination:
```powershell
.\target\release\landmine.exe --suspend-on-high --kill-on-critical --dump-quarantine C:\Quarantine
```

---

## Portable Deployment

To deploy LandMine on target systems without installing Rust, distribute the following self-contained directory:

```text
LandMine-Portable/
├── landmine.exe             # Standalone binary (from target\release\landmine.exe)
├── rules/
│   ├── detection_rules.toml # Custom Sigma-lite detection rules
│   ├── malware_hashes.txt   # Threat intelligence hash database
│   └── allowlist.txt        # Trusted process allowlist
└── logs/                    # Output directory for rotating JSONL logs
```

Run from an elevated PowerShell or Command Prompt:
```powershell
.\landmine.exe
```

---

## Command-Line Arguments Reference

| Option | Default | Description |
|---|---|---|
| `--once` | `false` | Run a single snapshot evaluation then exit |
| `--interval <secs>` | `5` | Polling delay between process enumeration cycles |
| `--out <path>` | `logs/landmine.jsonl` | Destination JSONL log file |
| `--allowlist <path>` | `rules/allowlist.txt` | Trusted process names list (one per line) |
| `--rules <path>` | `rules/detection_rules.toml` | Custom Sigma-lite detection rules file |
| `--hash-db <path>` | `rules/malware_hashes.txt` | Threat intelligence SHA-256 hash list |
| `--format <pretty\|jsonl>` | `pretty` | Terminal console output format |
| `--min-severity <level>` | `low` | Minimum severity written to the log file (`low`, `medium`, `high`, `critical`) |
| `--max-size-mb <n>` | `50` | Maximum log file size in MB before rotation (`0` disables rotation) |
| `--max-backups <n>` | `5` | Number of rotated log backup files to retain |
| `--winevent` | `false` | Forward Medium+ detections to the Windows Application Event Log |
| `--suspend-on-high` | `false` | Active Defense: pause/suspend High and Critical severity processes |
| `--kill-on-critical` | `false` | Active Defense: terminate Critical severity processes |
| `--dump-quarantine <dir>` | `None` | Active Defense: capture full memory minidump before termination |
| `--no-color` | `false` | Disable ANSI terminal color codes |

---

## Detection Logic & Severity Matrix

### Core Detection Flags

| Flag | Trigger Condition |
|---|---|
| `lolbin_process` | Process name or OriginalFilename matches a known execution/scripting LOLBin |
| `lolbin_recon` | Process name matches a recon/discovery LOLBin (`whoami`, `net`, `schtasks`, …) |
| `renamed_binary` | PE `VS_VERSION_INFO` OriginalFilename differs from the on-disk file name |
| `lolbin_masquerade` | A LOLBin identified strictly via OriginalFilename (renamed to evade detection) |
| `unsigned_system_binary` | System binary name lacking a valid Microsoft Authenticode digital signature |
| `lolbin_network_beacon` | A LOLBin establishing an active outbound TCP connection to a public IPv4 address |
| `network_outbound_public` | Process established outbound TCP connection to a public IPv4 address |
| `known_malware_hash` | SHA-256 matches threat intelligence database (`malware_hashes.txt`) |
| `suspicious_packer_or_pattern` | Executable contains UPX packer headers, C2 beacon artifacts, or Mimikatz signatures |
| `exec_from_temp` | Process image resides in `\AppData\Local\Temp\` or `\Windows\Temp\` |
| `exec_from_downloads` | Process image resides in `\Downloads\` |
| `exec_from_appdata` | Process image resides in `\AppData\Roaming\` or `\AppData\Local\` |
| `cmdline_obfuscation` | Base64 flags (`-enc`), hidden window parameters, backtick escaping, or string concat |
| `cmdline_download_cradle` | `IEX`, `DownloadString`, `Invoke-WebRequest`, `certutil -urlcache`, or `bitsadmin` |
| `cmdline_tampering` | Shadow copy deletion, boot configuration tampering, or disabling Defender |
| `suspicious_parent_spawn` | Anomalous parent-to-child execution lineage |
| `office_spawns_script_engine` | Office application spawning command shells or script hosts |
| `webserver_spawns_shell` | Web server process (`w3wp`, `httpd`, `nginx`) spawning a command shell |
| `browser_spawns_temp_exe` | Web browser spawning an executable residing in a Temp directory |
| `rule:<id>` | A custom rule from `detection_rules.toml` matched |
| `no_exe_path` | Executable path inaccessible (privilege restriction; known OS processes excluded) |
| `allowlisted_name` | Process name is present in the allowlist |

### Severity Evaluation

| Severity | Qualification Criteria |
|---|---|
| `Critical` | Known malware hash match · `suspicious_parent_spawn` with a secondary high-risk indicator · shadow copy deletion · Defender disablement |
| `High` | Binary masquerade · suspicious parent-child spawn · malicious command line · unsigned system binary · LOLBin network beacon · packer/C2 signature |
| `Medium` | Unaccompanied `lolbin_process` · execution from `Temp`/`AppData`/`Downloads` · renamed binary · public network outbound connection |
| `Low` | Standard baseline events (isolated `lolbin_recon`, clean system processes) |

*Custom rules loaded from `detection_rules.toml` can elevate an event's severity.*

---

## Custom Rules (Sigma-Lite)

Rules are defined in `rules/detection_rules.toml`. All populated condition keys must match (logical AND); items within an array match on any element (logical OR), except `command_line_contains` which requires all substrings:

```toml
[[rules]]
id = "office_spawning_shell"
name = "Microsoft Office Spawning Shell"
severity = "Critical"
tags = ["mitre.t1059", "mitre.t1204"]
[rules.conditions]
parent_name = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
process_name = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
```

---

## Log Format

Each event is recorded as a single JSON line:

```json
{
  "ts_utc": "2026-10-23T14:32:01.123456Z",
  "event_type": "process_started",
  "pid": 4821,
  "ppid": 1200,
  "name": "powershell.exe",
  "parent_name": "WINWORD.EXE",
  "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "original_filename": "PowerShell.EXE",
  "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
  "sha256": "a3f1c2d4e5f6...",
  "is_elevated": false,
  "network_destinations": ["185.220.101.5:443"],
  "flags": ["lolbin_process", "cmdline_obfuscation", "suspicious_parent_spawn", "office_spawns_script_engine", "rule:office_spawning_shell"],
  "matched_rules": ["office_spawning_shell"],
  "severity": "Critical"
}
```

---

## Process Allowlist

Edit `rules/allowlist.txt` to suppress benign alerts. Specify one process name per line. Lines starting with `#` are treated as comments.

An allowlisted process is not trusted unconditionally: if it has been renamed, uses malicious command-line arguments, exhibits suspicious lineage, or triggers a custom rule, it is still evaluated and logged.

---

## Project Structure

```text
landmine/
├── src/
│   ├── main.rs               # Entry point: CLI args, banner, event dispatch loop
│   ├── lib.rs                # Library root
│   ├── cli.rs                # CLI flag definitions
│   ├── app.rs                # Monitor pipeline (collect -> dedup -> detect -> enrich)
│   ├── models/               # Domain data structures
│   │   ├── severity.rs       #   Severity enumeration (Low to Critical)
│   │   ├── snapshot.rs       #   Process snapshot model
│   │   └── event.rs          #   Security event model and detection result
│   ├── collector/
│   │   └── process.rs        # Sysinfo process collector (cmdline, parent, PE cache)
│   ├── detector/
│   │   ├── engine.rs         # Detection engine: signal aggregation and classification
│   │   ├── flags.rs          # Standard detection flag constants
│   │   ├── builtin.rs        # Built-in LOLBin catalog and lineage definitions
│   │   ├── path.rs           # Directory path heuristics
│   │   ├── filename.rs       # Masquerade and PE metadata inspection
│   │   ├── cmdline.rs        # Obfuscation and download cradle analysis
│   │   ├── lineage.rs        # Parent-child lineage correlation
│   │   └── custom_rules.rs   # TOML Sigma-lite rule parser and matcher
│   ├── state/
│   │   └── lifecycle.rs      # Stateful process tracking and privilege escalation
│   ├── enrich/
│   │   ├── hash.rs           # SHA-256 calculation with path caching
│   │   ├── hashdb.rs         # Threat intelligence hash database lookup
│   │   └── patterns.rs       # YARA-lite PE pattern and signature scanner
│   ├── logger/
│   │   ├── banner.rs         # ASCII banner and CLI UI profile renderer
│   │   ├── jsonl.rs          # Rotating JSONL writer with backup pruning
│   │   ├── console.rs        # Terminal alert card renderer
│   │   ├── winevent.rs       # Windows Application Event Log integration
│   │   └── sink.rs           # Multi-sink worker thread and dispatcher
│   └── platform/             # Windows Win32 FFI bindings
│       ├── mod.rs            #   Token elevation, image paths, ANSI support
│       ├── pe_version.rs     #   VS_VERSION_INFO parser
│       ├── authenticode.rs   #   WinVerifyTrust digital signature verification
│       ├── network.rs        #   GetExtendedTcpTable network correlation
│       └── defense.rs        #   NtSuspendProcess, TerminateProcess, minidump
├── rules/
│   ├── allowlist.txt         # Process allowlist
│   ├── detection_rules.toml  # Custom Sigma-lite rules
│   └── malware_hashes.txt    # Threat intelligence malware hashes
├── tests/
│   └── engine.rs             # Integration test suite
├── AGENTS.md                 # Technical roadmap and feature specifications
└── Cargo.toml
```

---

## Verification & Testing

Run the automated test suite and lint checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

---

## Dependencies

| Crate | Purpose |
|---|---|
| `sysinfo` | System process enumeration (command line, parent, start time) |
| `sha2` | SHA-256 cryptographic hashing |
| `serde` / `serde_json` | JSON serialization for telemetry events |
| `toml` | Parsing Sigma-lite detection rules |
| `chrono` | UTC timestamp generation and formatting |
| `clap` | Command-line argument parsing |
| `anyhow` | Error propagation and contextual reporting |
| `tempfile` *(dev)* | Integration test fixtures |