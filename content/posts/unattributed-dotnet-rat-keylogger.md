---
title: "Unattributed .NET RAT: keylogging, Run-key persistence and System32 masquerading"
date: 2026-08-17T10:31:07Z
draft: true
aliases: ["/posts/dotnet-rat-with-no-name/"]
tags: ["malware", "detonation", "elastic", "detection", "rat", "keylogger"]
summary: "A .NET remote-access trojan self-copied under a Windows binary name, established Run-key persistence, and collected keystrokes. No family attribution is available from any source."
---

{{< takeaways >}}
- A **.NET remote-access trojan with keylogging** was detonated. **No family attribution is
  available**: the hash has no ThreatFox entry, no MalwareBazaar signature, and is unknown to the
  environment's own threat-intel feeds.
- MalwareBazaar's TrID output identifies the artefact only as a Generic CIL (.NET) executable, so the
  sample is described here by behaviour and runtime rather than by family.
- Persistence was established by self-copying and a **registry Run key**, with the copy **masquerading
  under a Windows binary name**.
- **Keystroke collection was observed.** No external command-and-control endpoint resolved during this
  run, so the collection had nowhere to go.
- Ten rules fired across 29 alerts. Every capability needed to act on this sample was observable without
  knowing its name.
{{< /takeaways >}}

## Case Summary

The .NET RAT is a **.NET remote-access trojan (RAT)** with **keylogging**. It self-copies for **Run-key/Startup persistence** under a System32-masquerading name and attempts C2. Delivered as a 7-Zip archive, run manually.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 17:47:10 UTC · **Alert window:** 17:47:28–17:51:59 · **Detections:** 25 Elastic Defend alerts · **Family/attribution:** _left for analyst to determine from the IOCs below_

## Execution

- 7-Zip (`7zFM.exe`→`7zG.exe x`) extracted to `C:\Users\analyst\Downloads\bc033453…\`.
- `explorer.exe` → the .NET RAT `C:\Users\analyst\Downloads\sample\bc033453…e48674.exe` at 17:47:10 (ProblemChild-flagged).

## Persistence

- Self-copied to **`C:\Users\analyst\AppData\Roaming\MPC-AH\AggregatorHost.exe`** (identical SHA256) — masquerading as the legitimate System32 `AggregatorHost.exe` ("Potential Masquerading as System32 Executable").
- **Startup / Run-key persistence** pointing at the copy — "Startup Persistence by a Low Reputation Process" ×4, "Startup Persistence from a Browser/Compression Utility Descendant" ×4, "Startup or Run Key Registry Modification" ×2.

## Collection

- **Keystroke capture** — "Keystrokes Input Capture from a Managed Application" ×2 (T1056.001).

## Command and Control

- C2 attempted **via the system proxy the proxy**; **no external egress observed** (dead/sinkholed in the isolated lab) — no external C2 IP/domain captured this run.
- 2× "Malicious Reputation of Executable Download" (component matched a bad-reputation indicator — T1105).

## Timeline

{{< timeline key="dotnet_rat_keylogger" >}}

## Detections

{{< alerts key="dotnet_rat_keylogger" >}}

## Attribution

No family label is available. The hash has no ThreatFox entry, no MalwareBazaar signature, and is
unknown to the threat-intel feeds ingested in this environment. MalwareBazaar's TrID output identifies
the artefact only as a Generic CIL (.NET) executable.

The observed capability is nonetheless complete: the persistence mechanism, the masquerade and the
keystroke collection are all documented above, and each is actionable without a family name.

## Indicators

{{< indicators key="dotnet_rat_keylogger" >}}

## MITRE ATT&CK

{{< mitre key="dotnet_rat_keylogger" >}}

## Threat Intelligence

{{< cti key="dotnet_rat_keylogger" >}}

---

The write-up and indicators are in
[`detonations/2026-08-08-dotnet-rat-keylogger`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-dotnet-rat-keylogger).
