---
title: "Agent Tesla hides inside RegSvcs.exe, and two Sigma rules that catch it"
date: 2026-10-29T10:00:00Z
draft: false
tags: ["malware","detonation","elastic","detection","sigma","agent-tesla","process-hollowing"]
summary: "An Agent Tesla dropper hollowed the signed .NET registration utility RegSvcs.exe, then read both browser credential stores and the Windows Credential Vault from inside it, leaving no persistence behind. Two draft Sigma rules came out of it, and a live retrohunt returned 19 true positives with no false positives across two independent samples of the family."
---

{{< takeaways >}}
- An **Agent Tesla** dropper was detonated on an isolated analysis host. The family label came from
  a sandbox verdict and was corroborated independently by a memory-scan signature read from the
  hollowed process, so it is attribution with two sources rather than one.
- The dropper spawned `RegSvcs.exe` with **no arguments**, overwrote its image, and exited, leaving
  the payload running inside a signed Microsoft binary.
- From inside that binary it read Chrome's and Edge's `Login Data` and loaded `vaultcli.dll`.
  **No persistence was established at all.** No Run key, no scheduled task, no service.
- The only destination host telemetry ever recorded was the **internal proxy**. Any detection that
  filters on "external destination" would have seen nothing.
- **One indicator in the enrichment was not this sample's.** `198.23.185.237` is the ScreenConnect
  relay from an earlier detonation, still beaconing from the host. Its "30 sightings" were 30
  rollups of a single flow that began before the sample ran.
- Two draft Sigma rules came out of it, and **both carried a defect no validator catches**. One was
  caught by reading the compiled query, the other by labelling each condition against the evidence,
  which exposed a reasonable inference that quietly narrowed the rule past the behaviour it was
  written for.
- Run against 90 days of live data the two rules produced **19 hits, every one a true positive,
  across two independent Agent Tesla samples**.
{{< /takeaways >}}

## Case Summary

A commodity **.NET infostealer** that uses **process hollowing against a signed Microsoft .NET
utility** as its entire defence-evasion strategy, then reads **browser credential stores and the
Windows Credential Manager vault** from inside it. No persistence, no second stage, no tampering
with the endpoint agent. Commodity infostealer volume looks like this.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-10-27 21:20:27 UTC ·
**Alert window:** 21:21:03–21:30:18 · **Capture:** 10,652 documents, 35 alerts ·
**Telemetry:** healthy

Sample: `fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c`, delivered as a 7-Zip
archive and executed by double-click from the Downloads directory.

**Assessment: a commodity stealer that spends its whole evasion budget on one trick and then works
fast.** It buys a signed Microsoft process to run inside, takes what it can reach, and leaves
nothing behind to find later. The absence of persistence is the part worth planning
against: there is no Run key to hunt for afterwards, so the sample is only detectable while it is
still running.

### Attribution

| | |
|---|---|
| Family | **Agent Tesla** (Keylogger, Trojan) |
| Source | Sandbox detonation at [tria.ge](https://tria.ge/261027-pnet9ady9p), score 10, 14 signatures, detection `Agent Tesla`, **0 C2 indicators** |
| Independent corroboration | Elastic Defend memory scan matched `Windows.Trojan.AgentTesla` inside the hollowed process, which is a different method on a different artefact |

Attribution adopted. Two methods agree on the family: a hash-keyed sandbox verdict, and a memory
signature read from the running process. That is a stronger position than either alone. The sandbox's
zero-C2-indicator finding bears on the indicator section below.

## Execution

- **21:20:01.** `7zFM.exe` spawned `7zG.exe x -o"...\Downloads\fdc9cb25…b42c\"`. The archive
  extracted into a directory named after the sample's own SHA256, which is an artefact of how
  *analysts* file samples, not of the malware.
- **21:20:27.** Launched from Explorer by double-click, no arguments. It loaded `clr.dll`, so a
  .NET assembly.

## Defense Evasion

This is the whole trick, and it takes three events to tell:

```
21:20:59.3014  start  RegSvcs.exe   pid 25204   ppid 14396
   image   C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
   cmdline "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"
   parent  C:\Users\analyst\Downloads\fdc9cb25…b42c\fdc9cb25…b42c.exe

21:20:59.4159  end    fdc9cb25…b42c.exe   pid 14396
```

`RegSvcs.exe` registers .NET assemblies with COM+. It is useless without an assembly to act on, and
here it was given **nothing at all**. The command line is its own quoted path and nothing else. That
is not a misconfiguration, it is the signature of a hollowing container: start the signed Microsoft
binary suspended, overwrite its image with the payload, resume it, then exit. The dropper exited
immediately after spawning it.

Elastic Defend saw the mechanics directly, raising three behaviours together:
*Suspicious Suspended Process Creation*, *Suspicious Remote Memory Allocation* and *Remote Thread
Context Manipulation*. That triad is `CreateProcess(SUSPENDED)` → `VirtualAllocEx` →
`SetThreadContext`/`ResumeThread`, which is hollowing written out in API calls.

From this point everything the sample does is attributed to a signed Microsoft binary sitting in
`C:\Windows\Microsoft.NET\`.

## Discovery

`RegSvcs.exe` then loaded the entire WMI client stack: `wmiutils.dll`, `wbemcomn.dll`,
`wbemprox.dll`, `WMINet_Utils.dll`, `wbemsvc.dll`, `fastprox.dll`. A registration utility has no
reason to hold a WMI connection. Agent Tesla uses WMI to enumerate the host and the installed
security products before it decides what to do, and the module loads are the only trace of it in
this capture, because the queries themselves were never logged.

## Credential Access

After the hollowing, in this order:

| Time | What |
|---|---|
| 21:21:02.1831 | opened `...\Google\Chrome\User Data\Default\Login Data` |
| 21:21:02.2012 | opened `...\Microsoft\Edge\User Data\Default\Login Data` |
| 21:21:02.2349 | loaded `vaultcli.dll` from `SysWOW64` |

Both browser profiles were read back to back. The sample then reached the Windows Credential
Manager vault through its client library, from a process whose real identity is a COM+ registration
tool.

Nine alerts fired on this half of the chain, all tagged T1555.004, split between *Access to Windows
Passwords Vault by Unusual Process* and *Suspicious Vault Client Image Load*. It is the most
confidently detected part of the intrusion and the least evadable, because an infostealer that wants
vault contents has to load that DLL into whatever process it is running as.

## Command and Control

```
21:21:01.6059  RegSvcs.exe  →  <proxy-ip>:3128   connection_attempted
21:22:42.1162  RegSvcs.exe  →  <proxy-ip>:3128   disconnect_received
```

One socket, and **the destination is the internal proxy**. That is the only
destination the endpoint agent can record on a proxied estate. A detection rule testing for "a .NET
utility connected to an external address" would not have fired here. One testing for "a .NET utility
opened a socket at all" would.

No DNS query and no TLS SNI is attributable to the sample. Triage reported 0 C2 indicators, and
nothing in this capture contradicts that.

## The indicator that was not ours

The enrichment file lists `198.23.185.237` as an external destination with **30 local sightings**,
ASN 63025, NOHAVPS LLC, Draper, Utah, with three low-confidence risk rules behind it. The enrichment
was careful about it and recorded it as *not a confirmed command-and-control host*, but it is still
sitting in an indicator list for an Agent Tesla detonation, and that is how an indicator gets
believed.

It is not this sample's. The telemetry is unambiguous:

- there is exactly **one** TCP session to it, `<analysis-host-ip>:57803 → 198.23.185.237:8041`, one
  `network.community_id`, and its `event.start` is **21:16:48.667Z**, which is *before* the sample
  executed at 21:20:27;
- the **30 sightings are 30 repeats of that one flow**, because Packetbeat re-reports a live flow
  on a fixed interval. Thirty rollups of one connection is not thirty connections;
- `ScreenConnect.WindowsClient.exe` is installed at `C:\Program Files (x86)\Windows VC\` and runs as
  `"RunRole" "<guid>" "System"`, logging a service event throughout the window;
- port **8041** is the ScreenConnect relay default, and `198.23.185.237:8041` is written down as the
  ScreenConnect relay in the August RMM-abuse write-up from this same lab;
- the hollowed `RegSvcs.exe` never touched it.

So the August implant is still alive on the analysis host, and it put a VPS in Utah into October's
indicator set. Lab hygiene is the smaller problem that exposes.

The larger problem is **sighting counts**. "30 local sightings" reads like corroboration. It was
one flow, counted thirty times by a rollup interval, and the only thing that distinguishes the two
is looking at `event.start` and `network.community_id` rather than the row count. Any enrichment
pipeline that scores confidence by how many times an indicator appears in local telemetry will make
this mistake, and it will make it in the direction of over-confidence.

## Timeline

{{< timeline key="agent_tesla_regsvcs_hollowing" >}}

## Detections

{{< alerts key="agent_tesla_regsvcs_hollowing" >}}

Nine of the 35 are Elastic Defend endpoint alerts and the rest are detection-engine alerts the
engine escalated from them, so the same behaviour is counted in both layers. The table above merges
each pair into the behaviour it describes, which is why the rule count is lower than a raw
`terms` aggregation on the alert index would give.

Four alerts evidenced the findings: the suspended-process creation, the remote thread context
manipulation, the vault client image load, then the memory scan that named the family. The rest
duplicated coverage.

## Indicators

{{< indicators key="agent_tesla_regsvcs_hollowing" >}}

Two things are deliberately missing from that table.

`083bc9319eb8066131b8005dd7013f85f2a27c7908767f94183d3e153b8db12b` is **not an indicator**. It is
`RegSvcs.exe` itself, 39,400 bytes of .NET Framework v4.0.30319, catalogued by NIST as a known
software file. It has 21 local sightings in this capture and it is the second
most-seen hash in the capture, and publishing it would have people hunting for a file on every
Windows host with .NET installed. The abused binary is not the malicious one.

`198.23.185.237` is absent for the reason given above.

The dropper's other hashes, for feed matching: MD5 `afeb6d5fc91e7f54feb84544c13f086e`, SHA1
`c8fc8fdc508bfdbacced8192b229233f095e5771`. The MD5 has no entity of its own in the enrichment and
resolves only through the SHA256's file-hash list, which is worth knowing if your pipeline enriches
on MD5.

## MITRE ATT&CK

{{< mitre key="agent_tesla_regsvcs_hollowing" >}}

A note on the tactic names: the alerts say *Defense Evasion*, and that is what is recorded above,
because it is what fired. ATT&CK retired that tactic in v19 and redistributed its techniques across
`stealth` and `defense-impairment`, so the Sigma rules below carry `attack.stealth` while the
Elastic alerts that prompted them still say Defense Evasion. Both are correct for their own
vintage. Anything that maps between them needs to know which side it is standing on.

## Threat Intelligence

{{< cti key="agent_tesla_regsvcs_hollowing" >}}

## Two Sigma rules, and what testing changed

The detonation produced two draft Sigma rules, both `status: experimental`. They are deliberately
two cuts at one chain rather than one compound rule, because a compound rule cannot be tuned:
suppressing the noisy half suppresses the useful half.

| Rule | Targets | Level |
|---|---|---|
| `proc_creation_win_dotnet_framework_utility_no_arguments` | a .NET utility started with an empty argument list | high |
| `net_connection_win_dotnet_framework_utility_outbound` | a .NET utility opening a socket, with no destination condition | medium |

The first is the more fragile. One junk argument on the `RegSvcs.exe` command line defeats it, so it
is a rule about current tradecraft rather than about the technique. The second survives that, which
is why the two ship linked with `related: type: similar` and are meant to be deployed together.

### The condition that came out

The first draft of the spawn rule had a third clause requiring the parent process to be running from
a user-writable directory: `\Downloads\`, `\AppData\Local\Temp\`, `\Users\Public\` and four more. It
looks like exactly the sort of thing that belongs in a loader rule.

Labelling each condition against what the capture actually showed is what undid it. Only
`\Downloads\` was sourced from the evidence. The other six paths were inference, and the clause as a
whole was doing something worse than being partly invented: **it was narrowing the rule on an
inference.** Stage the dropper into a new directory under `C:\`, or a writable subdirectory of
`Program Files`, and the whole rule goes quiet with nothing in the telemetry looking wrong.

The clause was removed. `ParentImage` stays in the rule's `fields` as a triage aid, which is where a
parent belongs when it cannot be defended as a condition.

The trade runs both ways. The rule is **more durable**, because path variation no longer defeats it.
It is also **broader**: it will now fire when an administrator runs `RegSvcs.exe` interactively to
read its usage text. Nothing was substituted for it, because a filter on shell parentage would have
needed a value this environment has not confirmed, and a fabricated filter looks tested while
excluding nothing.

### Reading the compiled query

Static validation says a rule parses and compiles. It says nothing about whether it fires.

The network rule's first draft carried `Initiated: 'true'`, which is correct for Sysmon event ID 3.
Converted through the `ecs_windows` pipeline it became:

```
network.direction:true
```

ECS `network.direction` carries `ingress`, `egress`, `inbound`, `outbound` or `internal`. It never
carries a boolean. That clause would have reduced the rule to a query matching nothing, and it
passed every validator on the way. The clause was removed.

A second caveat applies to both rules and is not fixable in the YAML. The converted queries carry
**no event-category binding**, so they match on field presence alone. Unscoped, the network rule
also matches process-creation documents, because `process.executable` is populated there too. Both
need scoping by index pattern or an added `event.category` clause before they go near an alerting
queue.

## Testing against live data

The converted queries went read-only against the live cluster: the detonation window first, then 90
days across every host.

The detonation window was the easy part. The spawn rule returned the hollowing event and the network
rule returned the socket.

The retrohunt returned something more interesting. Both rules had hits from an earlier date, well
before the run this post is about. An unexplained hit is a false positive until proven otherwise, so
those needed attributing before anything could be called clean.

They were a **second, independent Agent Tesla detonation**. Different sample, but the same shape:
`RegSvcs.exe` spawned with an empty command line, parent sitting in a hash-named Downloads
directory. The cluster's own alerts for that window settle it, 51 signals including four
`Memory Threat Detection Alert: Windows.Trojan.AgentTesla`.

So the rules produced **19 hits, every one a true positive, across two samples of the same family**.
They generalise past the sample they were drafted from, which a single detonation cannot establish.

The honest caveat is the estate. Two hosts report process telemetry and only one runs Windows. Zero
false positives here means zero on a single lab workstation, during which no .NET Framework utility
was invoked for any legitimate purpose at all. There was never an opportunity for a false positive.

---

The rules, their validation notes and the test results are in
[`detections/sigma`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detections/sigma)
and
[`detonations/2026-10-27-agent-tesla-regsvcs-hollowing`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-10-27-agent-tesla-regsvcs-hollowing).
Both are drafts for testing. Neither has run against a populated estate, and the retrohunt in each
validation note is a prerequisite rather than a suggestion.
