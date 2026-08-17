---
title: "Venus Stealer: a stealer that never got to steal"
date: 2026-08-17T10:56:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "venus-stealer", "dns"]
summary: "The sample established persistence, reached for its command and control over DNS, and got nothing — the domain never resolved. What can and cannot be concluded from a detonation that half-failed."
---

{{< takeaways >}}
- A **Venus Stealer** sample established persistence and attempted command and control over DNS.
  Attribution is from abuse.ch ThreatFox, matched on the exact SHA256.
- The C2 domain, a suspicious `.top` TLD, **did not resolve**. No session was established, no tasking
  received, nothing exfiltrated.
- Persistence used **application shimming** via `sdbinst.exe` and **COM registry modification**.
- **The collection stage was never observed.** The attribution is therefore by indicator, not by
  observed theft — a distinction worth preserving in any write-up.
- One COM CLSID override pointed at a **Microsoft-signed** `OneDrive.Sync.Service.exe`. That may be
  legitimate OneDrive registration caught in the blast radius rather than malicious persistence, and it
  is left flagged rather than resolved.
{{< /takeaways >}}

## Case Summary

Venus Stealer is an unsigned Windows executable that, on execution, attempts **C2 over DNS to a suspicious `.top` domain** and establishes host persistence via **Application Shimming (sdbinst)** and **COM registry modification**. Delivered as a 7-Zip archive and run manually. The C2 domain did not resolve during the run.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-08-08 16:59 UTC · **Alert window:** 17:00:00–17:02:15 · **Detections:** 31 Elastic Defend alerts · **Telemetry:** healthy (Defend events + Sysmon logging with correct timestamps — full reconstruction available)

## Initial Access

- Archive opened in 7-Zip (`7zFM.exe`), extracted via `7zG.exe x` to `C:\Users\analyst\Downloads\f0a10f8d…272b8\`.
- Sample staged in `C:\Users\analyst\Downloads\sample\`.

## Execution

- `explorer.exe` → **Venus Stealer exe** at 16:59:36 (and again 16:59:41) — user execution.
- Flagged by ProblemChild ML (`problemchild.prediction=1`).

## Persistence

- **Application Shimming** — `C:\Windows\System32\sdbinst.exe -m -bg` at 17:02:48 (ProblemChild-flagged) — installs a shim database (T1546.011).
- **COM registry modification** — per-user CLSID overrides written:
  - `{47E6DCAF-41F8-441C-BD0E-A50D5FE6C4D1}` and `{917E8742-AA3B-7318-FA12-10485FB322A2}` → `LocalServer32` = `…\AppData\Local\Microsoft\OneDrive\26.129.0706.0004\OneDrive.Sync.Service.exe` (+ WOW6432Node).
  - ⚠️ The referenced `OneDrive.Sync.Service.exe` is **Microsoft-signed/trusted** — this may be legitimate OneDrive COM registration flagged as suspicious rather than confirmed malicious persistence. **Recommend validation.**

## Command and Control

- Sample issued **DNS queries for `strmer.top`** (suspicious `.top` TLD) at 16:59:40–45 (process `f0a10f8d…272b8.exe`, also via `svchost.exe` DNS client).
- **Domain did NOT resolve** (`dns.resolved_ip: []`, no firewall egress) — C2 dead/sinkholed in the isolated lab, so no session established. Domain is the key network IOC.

## Additional observations

- **Malicious Reputation of Executable Download** ×4 — a downloaded/executed component matched a bad-reputation indicator (T1105 Ingress Tool Transfer).

## Timeline

{{< timeline key="venus_stealer_com_hijack_dns_c2" >}}

## Detections

{{< alerts key="venus_stealer_com_hijack_dns_c2" >}}

## Assessment

This detonation is useful precisely because it did not complete.

What is established: the persistence, because it was observed happening, and the intent to reach a
`.top` domain, because the query is in the telemetry. What is not established: what the sample would
have collected. A write-up implying otherwise would be guessing.

"ThreatFox says Venus Stealer" and "credential theft was observed" are different grades of evidence,
and they are not interchangeable even when both appear in the same report.

## Indicators

{{< indicators key="venus_stealer_com_hijack_dns_c2" >}}

## MITRE ATT&CK

{{< mitre key="venus_stealer_com_hijack_dns_c2" >}}

## Threat Intelligence

{{< cti key="venus_stealer_com_hijack_dns_c2" >}}

---

The write-up and indicators are in
[`detonations/2026-08-08-venus-stealer-com-hijack-dns-c2`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-08-venus-stealer-com-hijack-dns-c2).
