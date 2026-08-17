---
title: "PyInstaller dropper installs ScreenConnect and blankets Defender with exclusions"
date: 2026-08-17T11:46:07Z
draft: false
aliases: ["/posts/rmm-abuse-and-a-rejected-attribution/"]
tags: ["malware", "detonation", "elastic", "detection", "rmm", "screenconnect", "threat-intel"]
summary: "A PyInstaller dropper deployed ScreenConnect as its remote access, excluded whole drive letters from Microsoft Defender, and disabled UAC and script-block logging. Its threat-intel label says ransomware; the evidence does not support it."
---

{{< takeaways >}}
- A **PyInstaller-packaged dropper** installed **ScreenConnect** — legitimate, signed, commercially
  maintained remote-management software — and used it as its remote access. Writing a custom RAT was
  unnecessary.
- The sample added **Defender exclusions covering whole drive letters** (`D:`–`G:`, `X:`–`Z:`), `%Temp%`
  and its own working directory. Anything written there afterwards is invisible to Defender.
- Those exclusion changes alerted loudly: 24 alerts on the WMI route and 24 more on the PowerShell
  route. Exclusion modifications are cheap to detect and disproportionately valuable.
- **The threat-intel label was rejected.** ThreatFox lists this hash as `elf.kuiper` at confidence 95.
  Kuiper is ransomware; the artefact is a Windows PE rather than an ELF binary, and nothing in the
  detonation encrypted anything. The label is recorded below and deliberately unused in the title.

{{< /takeaways >}}

## Case Summary

The ScreenConnect RMM loader is a **PyInstaller-packaged Python dropper** that installs a **ScreenConnect (ConnectWise Control) RMM** implant for remote access and performs **aggressive Microsoft Defender neutralization**. Delivered as a 7-Zip archive, executed manually by the user.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 15:59 UTC · **Status:** terminated (no activity after 16:27) · **Detections:** 76 Elastic Defend alerts

## Initial Access

- Archive extracted via **7-Zip** (`7zG.exe x`) to `C:\Users\analyst\Downloads\sample\`.
- User launched the sample from Explorer (T1204 User Execution).

## Execution

- Sample runs as a **PyInstaller** bundle (artifacts: `%Temp%\_MEI*` + `base_library.zip`).
- Drops second-stage payload **`C:\ProgramData\Microsoft\Windows\9yxt0.exe`** (masqueraded in a system-like path).

## Persistence

- Installs/executes **ScreenConnect 25.3.4.9288** via:
  `powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File "C:\Windows\SystemTemp\ScreenConnect\25.3.4.9288\UcVUmdnD5EmUrun.ps1"`
- Provides attacker remote control (T1219 Remote Access Software).

## Defense Evasion

- **Defender exclusions** added via **PowerShell AND WMI**:
  - Paths: `C:\Users\analyst\Downloads\sample`, `%Temp%`, `C:\Users\Public\AccountPictures\tesurov`
  - Drives: `D:` `E:` `F:` `G:` `X:` `Y:` `Z:`
  - Processes: `cmd.exe`, `clip.exe`
- **UAC disabled** via registry modification.
- **PowerShell script-block logging disabled.**

## Command and Control

- **`198.23.185.237:8041`** — ScreenConnect relay (port 8041 = ScreenConnect default), egress confirmed from victim in the firewall firewall logs.
- Excluded: `172.211.123.249:443` — evaluated and found to be legitimate Azure/Microsoft traffic (svchost/msedge), NOT C2.

## Visibility gap

Raw endpoint **event** telemetry (Elastic Defend `endpoint.events.*` and Sysmon) is **absent for the detonation window 15:59–16:27**; both resumed at **16:27:20** with `elastic_agent` "failed to index document" errors. Elastic Defend **alerts** (fast path) were unaffected — this reconstruction is alert-derived. Recommend investigating the analysis-host agent event-shipping interruption (possible malware interference with logging vs. an ingest/mapping failure).

---

## Timeline

{{< timeline key="rmm_abuse_loader_screenconnect" >}}

## Detections

{{< alerts key="rmm_abuse_loader_screenconnect" >}}

## Attribution

ThreatFox labels this hash `elf.kuiper` at confidence 95. Kuiper is ransomware, and the label is not
adopted here for three reasons: MalwareBazaar reports the artefact as a Windows PE (`magika: pebin`)
rather than an ELF binary, nothing in the detonation encrypted a file, and the observed behaviour —
RMM deployment with Defender exclusions — is not consistent with ransomware at this stage.

A Kuiper-adjacent loader whose ransomware stage never executed cannot be excluded, but nothing
observed supports it.

## Indicators

{{< indicators key="rmm_abuse_loader_screenconnect" >}}

## MITRE ATT&CK

{{< mitre key="rmm_abuse_loader_screenconnect" >}}

## Threat Intelligence

{{< cti key="rmm_abuse_loader_screenconnect" >}}

---

The write-up and indicators are in
[`detonations/2026-08-08-rmm-abuse-loader-screenconnect`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-rmm-abuse-loader-screenconnect).
