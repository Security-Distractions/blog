---
title: "ValleyRAT: 324 alerts, 39 rules, and the problem with volume"
date: 2026-08-17T12:11:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "valleyrat", "edr-evasion"]
summary: "A ValleyRAT shellcode loader was detonated in an isolated lab. It produced 324 alerts across 39 detection rules in under eight minutes — and four of those rules carried the entire story."
---

{{< takeaways >}}
- A **ValleyRAT** shellcode loader was detonated on an isolated analysis host. Family attribution is
  from abuse.ch ThreatFox, matched on the exact SHA256, and agrees with the observed behaviour.
- The sample injected unbacked shellcode using direct syscalls, escalated to SYSTEM, and neutralised
  Microsoft Defender through scheduled tasks.
- Persistence was established through services and registry Run keys. A secondary payload was dropped
  and side-loaded through two DLLs written to user-writable directories.
- Command and control was confirmed against three addresses, one matching a threat-intel indicator
  already present in the environment.
- **39 rules fired, producing 324 alerts. Four carried the finding.** The remaining 35 were duplicates
  of those four or single-shot noise — a cost measured in analyst attention, not a measure of coverage.
{{< /takeaways >}}

## Case Summary

ValleyRAT is an unsigned **shellcode-injecting loader** with heavy **EDR/AV evasion** (direct syscalls, unbacked shellcode) and **SYSTEM-level Windows Defender neutralization via scheduled tasks**. It drops a secondary payload and beacons to **threat-intel-confirmed C2**. Most capable of the samples tested.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 17:27:55 UTC · **Alert window:** 17:28:17–17:34:53 · **Detections:** 319 Elastic Defend/SIEM alerts · **Telemetry:** healthy (clock correct; Aug-6 backlog from an earlier snapshot filtered out)

{{< canvas key="valleyrat_overview" height="520" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-08-valleyrat-shellcode-loader/canvas/overview.json" >}}

Collapsed to the steps that matter, the same path reads as follows.

{{< attackpath key="valleyrat_shellcode_loader" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-08-valleyrat-shellcode-loader/canvas/on-host-attack-path.json" >}}

## Execution

- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted the archive to `C:\Users\analyst\Downloads\a43853c1…\`.
- `explorer.exe` → ValleyRAT `C:\Users\analyst\Downloads\sample\a43853c1…efdb47c.exe` at 17:27:55 (ProblemChild-flagged), then self-spawned.

## Persistence

- Scheduled tasks (see above) · **Startup/Run Key** registry modification · Suspicious string value written to a Run key.

## Privilege Escalation

- **PowerShell**: `Add-MpPreference -ExclusionPath 'C:\ProgramData','C:\Users','C:\Program Files (x86)','C:\'` (excludes the entire C: drive).
- **SYSTEM scheduled-task loop**: repeatedly `SCHTASKS /Create /F /TN "Task1" /SC ONCE /RL HIGHEST /RU "SYSTEM" /TR "cmd.exe /c reg add …\Windows Defender\Exclusions…"` → `/Run` → `/Delete` — runs `reg add` as SYSTEM to add Defender exclusions, bypassing UAC (×60 scheduled-task creations).
- Also: Defender exclusions via WMI; Disable Defender via PowerShell; **UAC disabled**; **service disabled** via registry; **WDAC policy** written by an unusual process.
- ⚠️ **Elastic Defend Alert Followed by Telemetry Loss ×4** — the sample degraded endpoint telemetry (EDR tampering).

## Defense Evasion

- Dropped/ran **`C:\Users\Public\Br3N37\xhMLks.exe`** (launched via `svchost.exe`).
- **Shellcode injection & execution** — Memory Threat: Shellcode Injection ×20; Unbacked Shellcode from Unsigned Module; **Direct Syscall from Unsigned Module** (EDR bypass); Network Module Loaded from Suspicious Unbacked Memory; VirtualAlloc from unsigned DLL.

## Command and Control

- **`134.209.42.122`** — **Threat-Intel IP Indicator Match** (62 alerts; bidirectional beaconing). Highest-confidence C2.
- **`39.103.20.88:443`**, **`47.79.64.254:443`** — endpoint-observed HTTPS egress (Alibaba Cloud ranges).
- 29× **Threat-Intel Hash Indicator Match** (sample/components matched known-bad hashes).

## Timeline

{{< timeline key="valleyrat_shellcode_loader" >}}

## Detections

{{< alerts key="valleyrat_shellcode_loader" >}}

Thirty-nine rules fired. The four that carried the story were the shellcode injection, the
scheduled-task persistence, the Defender tampering and the threat-intel hash match. The rest were
duplicates of those or fired once each.

That distinction matters because 324 alerts is the kind of number quoted as coverage. It is not
coverage, it is redundancy, and redundancy costs analyst attention. Running detonations against your
own ruleset is how you learn which rules carry signal and which are along for the ride.

## Indicators

{{< indicators key="valleyrat_shellcode_loader" >}}

## MITRE ATT&CK

{{< mitre key="valleyrat_shellcode_loader" >}}

## Threat Intelligence

{{< cti key="valleyrat_shellcode_loader" >}}

---

The write-up and indicators are in
[`detonations/2026-08-08-valleyrat-shellcode-loader`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-valleyrat-shellcode-loader).
