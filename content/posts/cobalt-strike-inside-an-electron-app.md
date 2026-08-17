---
title: "A Cobalt Strike beacon inside a trojanised Electron app"
date: 2026-08-17T11:21:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "cobalt-strike", "shellcode"]
summary: "A trojanised Electron installer that presents as an ordinary desktop application unhooked ntdll, timestomped itself, and ran a Cobalt Strike beacon. 101 alerts across 15 rules."
---

{{< takeaways >}}
- A **Cobalt Strike** beacon was delivered inside a **trojanised Electron application**, presenting
  as an ordinary installer with a plausible version string and size. Attribution is from abuse.ch
  ThreatFox across four separate entries, matched on the exact SHA256.
- Electron applications make useful cover: they are large, ship a browser runtime and write extensively
  to `%AppData%`, so a malicious install resembles a legitimate one in endpoint telemetry.
- The loader attempted to **unhook `ntdll`** to strip userland API hooks, and **timestomped** its
  artefacts to blunt timeline analysis.
- The unhooking did not prevent detection. Behavioural and kernel-level telemetry surfaced the activity
  regardless — the practical argument against relying on a single instrumented layer.
- Command and control was confirmed to a Telegram typosquat domain and two addresses, with the payload
  staged from an S3 bucket.
{{< /takeaways >}}

## Case Summary

The Cobalt Strike loader is delivered as a **trojanized Electron application** ("wczt-win-8.1.65-x64"). It side-loads shellcode with EDR-evasion (NTDLL unhooking), timestomps dropped files, and beacons to a Telegram-typosquat C2, pulling a stage from an AWS S3 bucket.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 18:07:15 UTC · **Alert window:** 18:07:44–18:12:15 · **Detections:** 93 alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

## Execution

- 7-Zip-extracted to `C:\Users\analyst\Downloads\sample\`.
- `explorer.exe` → **loader** `39c69cb0…6c4f38.exe` (18:07:15) → spawns **`wczt-win-8.1.65-x64).exe`** (18:07:29) — the trojanized Electron installer.

## Persistence

- `wczt-win…exe` → drops/runs **`C:\Users\Public\00C04FC964FF\6F9619FF.exe`** (staging dir + filename use well-known OLE GUID fragments as camouflage).
- Installs an Electron app **`C:\Users\analyst\AppData\Local\Programs\wczt\wczt.exe`** (user-data `%AppData%\Roaming\wczt`); self-checks with `tasklist | find "wczt.exe"`.
- Pulls a stage from **AWS S3**: `xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com` (`52.219.129.86`).

## Defense Evasion

- **Shellcode injection** (Memory Threat ×4), **Network Connect API from Unbacked Memory**, **NTDLL unhooking**, Suspicious NTDLL image load, Shellcode from Low-Reputation Module — EDR evasion.
- **Timestomping** ×34 ("Potential Timestomp in Executable Files" / spoofed image-load creation time) — T1070.006.
- Unsigned DLL side-loading from a suspicious folder; execution from unusual directory.
- ⚠️ "Elastic Defend Alert Followed by Telemetry Loss" ×2 (endpoint telemetry degradation).

## Command and Control

- **C2 domain: `dm.telegrem.store`** (22 alerts) — Telegram typosquat on abused `.store` TLD.
- **C2 IPs: `118.107.43.16`, `118.107.43.138`**.

## Timeline

{{< timeline key="cobalt_strike_electron_trojan" >}}

## Detections

{{< alerts key="cobalt_strike_electron_trojan" >}}

## Assessment

The `ntdll` unhooking is the notable failure. The technique exists to remove the userland hooks that
endpoint products install to observe API calls; done successfully, a whole class of behavioural
detection goes quiet.

It fired anyway, because Elastic Defend does not depend solely on the hooks being removed. Kernel-level
and behavioural telemetry recorded the activity while the evasion was in progress. The evasion was
competent, and it still surfaced.

## Indicators

{{< indicators key="cobalt_strike_electron_trojan" >}}

## MITRE ATT&CK

{{< mitre key="cobalt_strike_electron_trojan" >}}

## Threat Intelligence

{{< cti key="cobalt_strike_electron_trojan" >}}

---

The write-up and indicators are in
[`detonations/2026-08-08-cobalt-strike-electron-trojan`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-cobalt-strike-electron-trojan).
