---
title: "A Cobalt Strike beacon inside an Electron app"
date: 2026-08-17T11:21:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "cobalt-strike", "shellcode"]
summary: "A trojanised Electron installer that looks like an ordinary desktop app, unhooks ntdll, timestomps itself, and runs a Cobalt Strike beacon. 101 alerts across 15 rules."
---

Electron applications are a gift to whoever is packaging malware. They are enormous, they
ship a browser runtime, they write all over `%AppData%`, and nobody blinks at any of it — a legitimate
Electron install looks, to an EDR, quite a lot like something misbehaving.

This sample arrived as `wczt-win-8.1.65-x64.exe`: a plausible version string, a plausible size, a
plausible installer. Inside it was shellcode, an attempt to unhook `ntdll`, timestomping to blunt
timeline analysis, and a beacon.

{{< cti key="cobalt_strike_electron_trojan" >}}

## What happened

> Detonated during a workshop as **Sample E**. That label survives in the file paths
> quoted below because it is what the telemetry recorded — the staging directory really was
> named that, and renaming it here would misreport the evidence.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 18:07:15 UTC · **Alert window:** 18:07:44–18:12:15 · **Detections:** 93 alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

---

## Overview
The Cobalt Strike loader is delivered as a **trojanized Electron application** ("wczt-win-8.1.65-x64"). It side-loads shellcode with EDR-evasion (NTDLL unhooking), timestomps dropped files, and beacons to a Telegram-typosquat C2, pulling a stage from an AWS S3 bucket.

## Layer 1: Delivery & Execution
- 7-Zip-extracted to `C:\Users\analyst\Downloads\Sample E\`.
- `explorer.exe` → **loader** `39c69cb0…6c4f38.exe` (18:07:15) → spawns **`wczt-win-8.1.65-x64).exe`** (18:07:29) — the trojanized Electron installer.

## Layer 2: Payload Drop & Install
- `wczt-win…exe` → drops/runs **`C:\Users\Public\00C04FC964FF\6F9619FF.exe`** (staging dir + filename use well-known OLE GUID fragments as camouflage).
- Installs an Electron app **`C:\Users\analyst\AppData\Local\Programs\wczt\wczt.exe`** (user-data `%AppData%\Roaming\wczt`); self-checks with `tasklist | find "wczt.exe"`.
- Pulls a stage from **AWS S3**: `xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com` (`52.219.129.86`).

## Layer 3: Injection & Defense Evasion
- **Shellcode injection** (Memory Threat ×4), **Network Connect API from Unbacked Memory**, **NTDLL unhooking**, Suspicious NTDLL image load, Shellcode from Low-Reputation Module — EDR evasion.
- **Timestomping** ×34 ("Potential Timestomp in Executable Files" / spoofed image-load creation time) — T1070.006.
- Unsigned DLL side-loading from a suspicious folder; execution from unusual directory.
- ⚠️ "Elastic Defend Alert Followed by Telemetry Loss" ×2 (endpoint telemetry degradation).

## Layer 4: Command & Control
- **C2 domain: `dm.telegrem.store`** (22 alerts) — Telegram typosquat on abused `.store` TLD.
- **C2 IPs: `118.107.43.16`, `118.107.43.138`**.

## The alerts

{{< alerts key="cobalt_strike_electron_trojan" >}}

## The part that nearly worked

The `ntdll` unhooking is the interesting failure here. The technique exists to strip userland hooks
that EDR products install to watch API calls — do it successfully and a whole class of behavioural
detection goes quiet.

It fired anyway, because Elastic Defend is not relying solely on the hooks that were being removed.
That is the argument for having kernel-level and behavioural telemetry rather than one instrumented
layer: the evasion was competent, and it still surfaced. Worth remembering the next time a vendor
claims a single technique defeats their product.

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-08-cobalt-strike-electron-trojan`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-cobalt-strike-electron-trojan).
