---
title: "ValleyRAT: 324 alerts, 39 rules, and the problem with volume"
date: 2026-08-17T12:11:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "valleyrat", "edr-evasion"]
summary: "One sample produced 324 alerts across 39 rules in under four minutes. That sounds like excellent detection coverage. It is also, from an analyst's chair, almost unusable — here's the walk-through, and what the volume hides."
---

Thirty-nine rules fired on this one. Three hundred and twenty-four alerts, inside a window
of about four minutes. If you judge a detection stack by how loudly it reacts, this was a triumph.

Sit in the analyst's chair instead and it is a different story. Thirty-nine rules is not thirty-nine
findings — it is the same handful of behaviours, reported repeatedly by rules that overlap, plus a
long tail firing once each. The useful question is not *did we detect it* but *what would you have
had to read, in what order, to understand what happened*. So that is what this post does: the
attack path first, then the alerts, then what the volume obscured.

{{< cti key="valleyrat_shellcode_loader" >}}

## The execution chain

This is the whole thing, drawn from the Compromise Canvas export: sixty-five processes and
forty-six spawn relationships, coloured by tactic. It opens on a readable window — press **fit**
to see how far it actually sprawls, which is itself the finding.

{{< canvas key="valleyrat_overview" height="520" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-08-valleyrat-shellcode-loader/canvas/overview.json" >}}

Collapsed to the eight steps that matter, the same path reads like this.

{{< attackpath key="valleyrat_shellcode_loader" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-08-valleyrat-shellcode-loader/canvas/on-host-attack-path.json" >}}

## What happened

> Detonated during a workshop as **Sample C**. That label survives in the file paths
> quoted below because it is what the telemetry recorded — the staging directory really was
> named that, and renaming it here would misreport the evidence.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 17:27:55 UTC · **Alert window:** 17:28:17–17:34:53 · **Detections:** 319 Elastic Defend/SIEM alerts · **Telemetry:** healthy (clock correct; Aug-6 backlog from an earlier snapshot filtered out)

---

## Overview
ValleyRAT is an unsigned **shellcode-injecting loader** with heavy **EDR/AV evasion** (direct syscalls, unbacked shellcode) and **SYSTEM-level Windows Defender neutralization via scheduled tasks**. It drops a secondary payload and beacons to **threat-intel-confirmed C2**. Most capable of the samples tested.

## Layer 1: Delivery & Execution
- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted the archive to `C:\Users\analyst\Downloads\a43853c1…\`.
- `explorer.exe` → **Sample C** `C:\Users\analyst\Downloads\Sample C\a43853c1…efdb47c.exe` at 17:27:55 (ProblemChild-flagged), then self-spawned.

## Layer 2: Payload Drop & Shellcode Injection
- Dropped/ran **`C:\Users\Public\Br3N37\xhMLks.exe`** (launched via `svchost.exe`).
- **Shellcode injection & execution** — Memory Threat: Shellcode Injection ×20; Unbacked Shellcode from Unsigned Module; **Direct Syscall from Unsigned Module** (EDR bypass); Network Module Loaded from Suspicious Unbacked Memory; VirtualAlloc from unsigned DLL.

## Layer 3: Privilege Escalation & Defense Evasion (SYSTEM)
- **PowerShell**: `Add-MpPreference -ExclusionPath 'C:\ProgramData','C:\Users','C:\Program Files (x86)','C:\'` (excludes the entire C: drive).
- **SYSTEM scheduled-task loop**: repeatedly `SCHTASKS /Create /F /TN "Task1" /SC ONCE /RL HIGHEST /RU "SYSTEM" /TR "cmd.exe /c reg add …\Windows Defender\Exclusions…"` → `/Run` → `/Delete` — runs `reg add` as SYSTEM to add Defender exclusions, bypassing UAC (×60 scheduled-task creations).
- Also: Defender exclusions via WMI; Disable Defender via PowerShell; **UAC disabled**; **service disabled** via registry; **WDAC policy** written by an unusual process.
- ⚠️ **Elastic Defend Alert Followed by Telemetry Loss ×4** — the sample degraded endpoint telemetry (EDR tampering).

## Layer 4: Persistence
- Scheduled tasks (see above) · **Startup/Run Key** registry modification · Suspicious string value written to a Run key.

## Layer 5: Command & Control (threat-intel confirmed)
- **`134.209.42.122`** — **Threat-Intel IP Indicator Match** (62 alerts; bidirectional beaconing). Highest-confidence C2.
- **`39.103.20.88:443`**, **`47.79.64.254:443`** — endpoint-observed HTTPS egress (Alibaba Cloud ranges).
- 29× **Threat-Intel Hash Indicator Match** (sample/components matched known-bad hashes).

## The alerts

{{< alerts key="valleyrat_shellcode_loader" >}}

## What the volume cost

Thirty-nine rules fired, and the four that actually told the story were the shellcode injection,
the scheduled task, the Defender tampering, and the threat-intel hash match. The rest were either
duplicates of those or single-shot noise.

That is worth saying plainly because 324 alerts is the kind of number that gets quoted as coverage.
It is not coverage, it is redundancy — and redundancy has a cost measured in analyst attention. The
value of running detonations against your own rules is precisely this: you find out which of them
carry the signal, and which are just along for the ride.

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-08-valleyrat-shellcode-loader`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-valleyrat-shellcode-loader).
