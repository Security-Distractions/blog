---
title: "RMM abuse, and an attribution I threw away"
date: 2026-08-17T11:46:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "rmm", "screenconnect", "threat-intel"]
summary: "A PyInstaller dropper that installs ScreenConnect as its remote access, blankets Defender with exclusions — and carries a threat-intel label that is almost certainly wrong. Why I published the label and refused to use it."
---

Attackers do not need to write a RAT when a signed, supported, commercially maintained one is
a download away. This sample installs **ScreenConnect** — legitimate remote-management software, with
a valid certificate and a vendor behind it — and uses that as its access.

That is the interesting half. The other half is a threat-intelligence label that does not survive
five minutes of scrutiny, which I have published anyway, because *what the intel said* and *what was
true* being different is the whole lesson.

{{< cti key="rmm_abuse_loader_screenconnect" >}}

## What happened

> Detonated during a workshop as **Sample A**. That label survives in the file paths
> quoted below because it is what the telemetry recorded — the staging directory really was
> named that, and renaming it here would misreport the evidence.

**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 15:59 UTC · **Status:** terminated (no activity after 16:27) · **Detections:** 76 Elastic Defend alerts

---

## Overview
The ScreenConnect RMM loader is a **PyInstaller-packaged Python dropper** that installs a **ScreenConnect (ConnectWise Control) RMM** implant for remote access and performs **aggressive Microsoft Defender neutralization**. Delivered as a 7-Zip archive, executed manually by the user.

## Layer 1: Initial Access / Delivery
- Archive extracted via **7-Zip** (`7zG.exe x`) to `C:\Users\analyst\Downloads\Sample A\`.
- User launched the sample from Explorer (T1204 User Execution).

## Layer 2: Execution & Payload
- Sample runs as a **PyInstaller** bundle (artifacts: `%Temp%\_MEI*` + `base_library.zip`).
- Drops second-stage payload **`C:\ProgramData\Microsoft\Windows\9yxt0.exe`** (masqueraded in a system-like path).

## Layer 3: RMM Deployment (ScreenConnect)
- Installs/executes **ScreenConnect 25.3.4.9288** via:
  `powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File "C:\Windows\SystemTemp\ScreenConnect\25.3.4.9288\UcVUmdnD5EmUrun.ps1"`
- Provides attacker remote control (T1219 Remote Access Software).

## Layer 4: Defense Evasion
- **Defender exclusions** added via **PowerShell AND WMI**:
  - Paths: `C:\Users\analyst\Downloads\Sample A`, `%Temp%`, `C:\Users\Public\AccountPictures\tesurov`
  - Drives: `D:` `E:` `F:` `G:` `X:` `Y:` `Z:`
  - Processes: `cmd.exe`, `clip.exe`
- **UAC disabled** via registry modification.
- **PowerShell script-block logging disabled.**

## Layer 5: Command & Control / Network
- **`198.23.185.237:8041`** — ScreenConnect relay (port 8041 = ScreenConnect default), egress confirmed from victim in OPNsense firewall logs.
- Excluded: `172.211.123.249:443` — evaluated and found to be legitimate Azure/Microsoft traffic (svchost/msedge), NOT C2.

## Visibility Gap (finding)
Raw endpoint **event** telemetry (Elastic Defend `endpoint.events.*` and Sysmon) is **absent for the detonation window 15:59–16:27**; both resumed at **16:27:20** with `elastic_agent` "failed to index document" errors. Elastic Defend **alerts** (fast path) were unaffected — this reconstruction is alert-derived. Recommend investigating the secdis agent event-shipping interruption (possible malware interference with logging vs. an ingest/mapping failure).

---

## The alerts

{{< alerts key="rmm_abuse_loader_screenconnect" >}}

## The attribution I rejected

ThreatFox lists this hash as `elf.kuiper`, at confidence 95. Kuiper is ransomware.

Three things say otherwise. MalwareBazaar reports the artefact as a Windows PE — `magika: pebin` —
not an ELF binary, so the family prefix is wrong about the platform. Nothing in the detonation
encrypted a single file. And the observed behaviour, RMM deployment plus Defender exclusions, is not
what ransomware does at this stage.

Could it be a Kuiper-adjacent loader whose ransomware stage never ran? Possibly. That is a hypothesis,
not an attribution, and it is not enough to put "Kuiper" in the title.

So the label is recorded in the write-up and deliberately absent from the name. Confidence 95 from a
community feed is a starting point for investigation, not a verdict — and a detonation is exactly how
you find out which one you are holding.

## A visibility gap worth noting

The Defender exclusions are the part a defender should care about most. This sample excluded whole
drive letters — `D:` through `G:`, `X:` through `Z:` — plus `%Temp%` and its own working directory.
Anything dropped into those paths afterwards is invisible to Defender.

The exclusions themselves alerted loudly, which is the saving grace: 24 alerts on the WMI route and
24 more on the PowerShell route. If you are choosing what to alert on in your own estate, exclusion
changes are cheap to detect and disproportionately valuable.

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-08-rmm-abuse-loader-screenconnect`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-rmm-abuse-loader-screenconnect).
