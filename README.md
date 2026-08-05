# WinDiag

**Enterprise Windows diagnostic data collector.**

Collects an exhaustive, read-only snapshot of a Windows 10/11 system so that a
technician — or an AI agent — who receives **only the output package** can work
out why the machine is slow, unstable, freezing, overheating or stuttering.

---

## Design principle: collect, do not conclude

This toolkit **does not diagnose**.

It performs no analysis, assigns no severities, flags nothing as "critical", and
offers no recommendations. It emits raw, labelled facts and reference context,
and nothing else.

That is deliberate. The output is intended to be handed to a separate analyst or
model, and a collector that pre-judges its own data biases whoever reads it. A
threshold baked in by the tool author is an opinion formed without knowing the
machine, the workload, or the question being asked.

So: **facts in the log, judgment left to the reader.**

Where a number is meaningless without reference, the log includes neutral
context — for example *"Windows default timer resolution is 15.6 ms (~64
interrupts/sec)"* — never *"this value is too high"*.

---

## Safety

- **Read-only.** Changes nothing. No registry writes, no service changes, no cleanup.
- **Non-fatal.** Every collector is isolated with try/catch, retries and timing.
  One failure never stops the run.
- **Crash-durable.** Every log line is flushed to disk immediately. If the
  machine bluescreens or the script is killed halfway, everything collected up
  to that moment is already on disk and readable.
- **Explicit absence.** A collector that fails is recorded in `logs/Errors.log`
  **and** in its section file, so missing data is distinguishable from a genuine
  empty result. This matters: "no data" and "nothing found" are different
  conclusions.

---

## Usage

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-WinDiag.ps1
```

Run **elevated** for the complete picture. Without elevation, SMART data, kernel
pool statistics, some event logs and parts of the service/driver inventory are
skipped (and recorded as skipped).

### Modes

| Mode | Runtime | Use for |
|---|---|---|
| `-Mode Quick` | ~2 min | Fast triage; skips deep filesystem scans and counter capture |
| `-Mode Full` | ~10 min | Default. Everything except long performance capture |
| `-Mode Deep` | 30-60+ min | Everything, extended counter capture, 1000-item enumerations |

### Examples

```powershell
.\Invoke-WinDiag.ps1 -Mode Deep -PerformanceMinutes 10
.\Invoke-WinDiag.ps1 -Mode Quick -OutputPath D:\Diag -NoCompress
.\Invoke-WinDiag.ps1 -NoInternet
.\Invoke-WinDiag.ps1 -OnlySection Storage,Memory
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `Full` | `Quick` / `Full` / `Deep` |
| `-OutputPath` | Desktop | Where the package is created |
| `-PerformanceMinutes` | 2 (5 in Deep) | Counter capture duration |
| `-TopN` | 50 | Rows in "top N" enumerations |
| `-EventDays` | 30 | Event log lookback window |
| `-RetryCount` | 2 | Retries per failed collector |
| `-NoCompress` | off | Skip the ZIP archive |
| `-NoInternet` | off | Suppress any network-touching collector |
| `-OnlySection` | — | Run only the named sections |
| `-SkipSection` | — | Skip the named sections |

---

## Output package

```
WinDiag_HOSTNAME_2026-08-04_170000/
├── logs/
│   ├── Master.log          full execution log, millisecond timestamps
│   ├── Errors.log          collectors that FAILED (data absent, not empty)
│   ├── Warnings.log
│   ├── Verbose.log
│   ├── Performance.log     per-collector execution time
│   └── Timeline.log        ordered event timeline
├── raw/                    human-readable dumps, one file per section
├── json/                   structured data for programmatic analysis
├── csv/                    tabular exports
├── eventlogs/              exported Windows event logs
├── counters/               performance counter captures
└── sysinternals/           output from Sysinternals tools, if present
```

A `MANIFEST.json` is written **first**, before any collection, so the package is
self-describing even if the run is interrupted.

Every log line follows one format:

```
[2026-08-04 17:04:22.117] [CHECK  ] [Get-DiskSmart] [+1.284s] C0042 SMART attributes
```

`timestamp | severity | collector | elapsed | message`

---

## Sysinternals integration

If any of these are on `PATH` or beside the script, their output is captured
into `sysinternals/`. If absent, the run continues normally.

`autorunsc` · `handle` · `pslist` · `psinfo` · `psservice` · `sigcheck` ·
`coreinfo` · `tcpvcon` · `RAMMap` · `VMMap`

Get them from <https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite>.

---

## What it collects

<details>
<summary><b>Hardware</b></summary>

CPU model, stepping, microcode, cache hierarchy, per-core utilisation,
frequency vs base, P-states, parking, virtualisation flags · memory modules with
manufacturer/part/serial/speed/slot population and channel configuration ·
motherboard, BIOS, UEFI, TPM, Secure Boot · GPU, VRAM, PCIe link speed and
width, display outputs, refresh rates · battery design vs full-charge capacity,
cycle count, wear · thermal sensors and fan speeds where exposed · USB,
Thunderbolt, Bluetooth, docking stations, PCI devices, unknown devices
</details>

<details>
<summary><b>Storage</b></summary>

Per-disk model, firmware, serial, SMART attributes, wear, temperature,
power-on hours · interface and NVMe/SATA/USB detail · TRIM state, alignment,
sector size · partition layout, BitLocker state · queue depth, read/write
latency, error counts · dirty bit and CHKDSK state · NTFS errors, MFT
fragmentation · Storage Spaces, VHDs, virtual disks · cloud drive sync state ·
filesystem filter drivers · top folders and files by size · Recycle Bin, temp
directories, WinSxS, Installer cache, SoftwareDistribution, Windows.old,
minidumps, WSL disks, Docker images
</details>

<details>
<summary><b>Memory</b></summary>

Physical, committed, standby, modified and compressed memory · page file
allocation, usage and peak · paged and nonpaged pool · handle, thread, GDI and
USER object counts per process · page fault and hard fault rates · transition
pages repurposed, free system PTEs · working set vs private bytes divergence ·
growth-rate sampling for leak evidence · .NET CLR heap sizes · VBS/HVCI overhead
</details>

<details>
<summary><b>CPU &amp; processes</b></summary>

Per-core utilisation and imbalance · processor queue length · context switches,
system calls, interrupts and DPC time · per-core interrupt distribution and RSS
configuration · priority class and affinity anomalies · thread and handle counts
· full process inventory with PID, PPID, tree, command line, path, signature,
integrity level, working set, I/O, connections and loaded modules
</details>

<details>
<summary><b>Startup, services, drivers</b></summary>

Run keys, RunOnce, Startup folders, scheduled tasks, services, drivers · Explorer
shell extensions, context menu handlers, icon overlay handlers, namespace
extensions · COM registrations · full service inventory with dependencies,
recovery configuration and start type · driver inventory with dates, versions,
signature status and problem codes · filter driver altitudes
</details>

<details>
<summary><b>Browsers</b></summary>

Auto-detects Chrome, Edge, Firefox, Brave, Opera, Vivaldi and other Chromium
builds, every profile · version, extensions by name and ID, permissions ·
cache, GPU cache, shader cache, Service Worker, IndexedDB, LocalStorage sizes ·
history and cookie DB sizes · enterprise policies · hardware acceleration
setting · startup pages and search providers · renderer process counts
</details>

<details>
<summary><b>Networking</b></summary>

Adapters, drivers, addressing, routes, ARP · Wi-Fi SSID, BSSID, RSSI, band,
channel, width, PHY rate, MIMO, retries and errors · 30-day per-profile data
usage · proxy and PAC configuration · VPN adapters · DNS servers, cache and
resolution timing · hosts file · mapped drives and SMB sessions · listening
ports and per-process connection counts · firewall profiles · time sync offset
</details>

<details>
<summary><b>Windows &amp; events</b></summary>

Edition, build, update history, pending reboot · Defender configuration and
exclusions · Core Isolation, Credential Guard, VBS · power plans and processor
power policy · crash dumps, WER, reliability history, LiveKernelEvents ·
System / Application / Setup / Update / Kernel / Power / Defender event logs
filtered and summarised by frequency
</details>

<details>
<summary><b>The things most scripts miss</b></summary>

Installed font count · shell extension count · PATH length · environment
variables · WMI repository health · component store health · search indexing
backlog · OneDrive/Dropbox/Drive backlog · pending file rename operations ·
registry hive sizes · huge event logs · thumbnail cache · OEM telemetry agents ·
background updaters · platform timer resolution · interrupt storms · clock
skew · profile size and corruption indicators · offline files · WSL, Docker and
Hyper-V resource reservations
</details>

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 (ships with Windows — PowerShell 7 also works)
- Administrator recommended, not required

---

## Licence

**Source-available, not open source.** AGPL-3.0 with the
[Commons Clause](https://commonsclause.com/) condition — see [LICENSE](LICENSE).

Free for personal, educational, research and evaluation use, subject to the AGPL
copyleft obligation: modify or build on this and you must publish the complete
corresponding source of your whole work under the same terms, including if you
only run it as a network service.

**Commercial and business use requires a separate paid licence.** That covers
internal use by a for-profit company, deployment to employees or clients,
bundling with any paid product or support offering, hosting it as a service, and
consulting or managed-service work. Request one by opening an issue.
