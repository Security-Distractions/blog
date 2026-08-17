---
title: "A .NET RAT with no name"
date: 2026-08-17T10:31:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "rat", "keylogger"]
summary: "Keylogging, Run-key persistence, masquerading as a Windows binary — and no family attribution anywhere. What to write up when the intel comes back empty."
---

Every write-up wants a name. It makes the finding quotable, it slots neatly into a report, and
it lets you point at somebody else's research for the parts you did not observe.

This sample does not have one. No ThreatFox entry, no MalwareBazaar signature. What I have is the
behaviour: a .NET executable that copies itself for Run-key persistence, masquerades under a Windows
binary name, and logs keystrokes.

That is enough to detect and enough to write up. It is not enough to name, and inventing a family
would be worse than leaving the field empty.

{{< cti key="dotnet_rat_keylogger" >}}

## What happened

> Detonated during a workshop as **Sample D**. That label survives in the file paths
> quoted below because it is what the telemetry recorded — the staging directory really was
> named that, and renaming it here would misreport the evidence.

**Host:** `secdis` (192.168.2.2) · **User:** `analyst` · **Detonated:** 2026-08-08 17:47:10 UTC · **Alert window:** 17:47:28–17:51:59 · **Detections:** 25 Elastic Defend alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

---

## Overview
The .NET RAT is a **.NET remote-access trojan (RAT)** with **keylogging**. It self-copies for **Run-key/Startup persistence** under a System32-masquerading name and attempts C2. Delivered as a 7-Zip archive, run manually.

## Layer 1: Delivery & Execution
- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted to `C:\Users\analyst\Downloads\bc033453…\`.
- `explorer.exe` → **Sample D** `C:\Users\analyst\Downloads\Sample D\bc033453…e48674.exe` at 17:47:10 (ProblemChild-flagged).

## Layer 2: Persistence & Masquerading
- Self-copied to **`C:\Users\analyst\AppData\Roaming\MPC-AH\AggregatorHost.exe`** (identical SHA256) — masquerading as the legitimate System32 `AggregatorHost.exe` ("Potential Masquerading as System32 Executable").
- **Startup / Run-key persistence** pointing at the copy — "Startup Persistence by a Low Reputation Process" ×4, "Startup Persistence from a Browser/Compression Utility Descendant" ×4, "Startup or Run Key Registry Modification" ×2.

## Layer 3: Collection (keylogging)
- **Keystroke capture** — "Keystrokes Input Capture from a Managed Application" ×2 (T1056.001).

## Layer 4: Command & Control
- C2 attempted **via the system proxy `192.168.2.1:3128`**; **no external egress observed** (dead/sinkholed in the isolated lab) — no external C2 IP/domain captured this run.
- 2× "Malicious Reputation of Executable Download" (component matched a bad-reputation indicator — T1105).

## The alerts

{{< alerts key="dotnet_rat_keylogger" >}}

## Naming is not understanding

It is tempting to reach for the nearest well-known .NET RAT — there are several, they behave similarly,
and one of them would probably sound right. That is exactly the reasoning that puts wrong attributions
into circulation, where they get cited.

What this detonation gives me is concrete: the persistence mechanism, the masquerade, the collection
capability, and ten rules that fired on it. A defender can act on every one of those without knowing
the family name. The name would be nice. It is not load-bearing.

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-08-dotnet-rat-keylogger`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-dotnet-rat-keylogger).
