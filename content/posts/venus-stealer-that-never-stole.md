---
title: "Venus Stealer: the stealer that never got to steal"
date: 2026-08-17T10:56:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "venus-stealer", "dns"]
summary: "A stealer that established persistence, reached for its C2 over DNS, and got nothing — the domain never resolved. What you can and cannot conclude from a detonation that half-failed."
---

This one is useful precisely because it did not work.

The sample established persistence, set up a COM registry override, installed a shim database, and
then queried DNS for `strmer.top`. The domain did not resolve. No session, no tasking, no collection,
nothing exfiltrated — the isolated lab has no route out except through a proxy, and the name was
dead besides.

So what do you actually know? You know the persistence, because you watched it happen. You know the
intent to reach a `.top` domain, because the query is in the telemetry. You do **not** know what it
would have stolen, and a write-up that implies otherwise is guessing.

{{< cti key="venus_stealer_com_hijack_dns_c2" >}}

## What happened

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 16:59 UTC · **Alert window:** 17:00:00–17:02:15 · **Detections:** 31 Elastic Defend alerts · **Telemetry:** healthy (Defend events + Sysmon logging with correct timestamps — full reconstruction available)

---

## Overview
Venus Stealer is an unsigned Windows executable that, on execution, attempts **C2 over DNS to a suspicious `.top` domain** and establishes host persistence via **Application Shimming (sdbinst)** and **COM registry modification**. Delivered as a 7-Zip archive and run manually. The C2 domain did not resolve during the run.

## Layer 1: Initial Access / Delivery
- Archive opened in 7-Zip (`7zFM.exe`), extracted via `7zG.exe x` to `C:\Users\analyst\Downloads\f0a10f8d…272b8\`.
- Sample staged in `C:\Users\analyst\Downloads\sample\`.

## Layer 2: Execution
- `explorer.exe` → **Venus Stealer exe** at 16:59:36 (and again 16:59:41) — user execution.
- Flagged by ProblemChild ML (`problemchild.prediction=1`).

## Layer 3: Command & Control
- Sample issued **DNS queries for `strmer.top`** (suspicious `.top` TLD) at 16:59:40–45 (process `f0a10f8d…272b8.exe`, also via `svchost.exe` DNS client).
- **Domain did NOT resolve** (`dns.resolved_ip: []`, no firewall egress) — C2 dead/sinkholed in the isolated lab, so no session established. Domain is the key network IOC.

## Layer 4: Persistence / Defense Evasion
- **Application Shimming** — `C:\Windows\System32\sdbinst.exe -m -bg` at 17:02:48 (ProblemChild-flagged) — installs a shim database (T1546.011).
- **COM registry modification** — per-user CLSID overrides written:
  - `{47E6DCAF-41F8-441C-BD0E-A50D5FE6C4D1}` and `{917E8742-AA3B-7318-FA12-10485FB322A2}` → `LocalServer32` = `…\AppData\Local\Microsoft\OneDrive\26.129.0706.0004\OneDrive.Sync.Service.exe` (+ WOW6432Node).
  - ⚠️ The referenced `OneDrive.Sync.Service.exe` is **Microsoft-signed/trusted** — this may be legitimate OneDrive COM registration flagged as suspicious rather than confirmed malicious persistence. **Recommend validation.**

## Additional
- **Malicious Reputation of Executable Download** ×4 — a downloaded/executed component matched a bad-reputation indicator (T1105 Ingress Tool Transfer).

## The alerts

{{< alerts key="venus_stealer_com_hijack_dns_c2" >}}

## Attribution without observation

ThreatFox labels this hash `py.venus_stealer` at confidence 95, and I have adopted that — it is
consistent with a Python-packed stealer, and nothing observed contradicts it.

But notice what that means: the family label comes from an indicator match, not from watching it
steal anything. Those are different grades of evidence and it is worth keeping them apart in your own
notes. "ThreatFox says Venus Stealer" and "I observed credential theft" are not interchangeable
claims, even when both appear in the same report.

The other finding here is quieter: one of the COM CLSID overrides pointed at a **Microsoft-signed**
`OneDrive.Sync.Service.exe`. That may well be legitimate OneDrive registration caught in the blast
radius rather than malicious persistence. I have left it flagged rather than resolved, because I did
not prove it either way.

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-08-venus-stealer-com-hijack-dns-c2`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-venus-stealer-com-hijack-dns-c2).
