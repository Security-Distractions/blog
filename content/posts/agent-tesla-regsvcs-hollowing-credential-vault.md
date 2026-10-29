---
title: "Agent Tesla in RegSvcs.exe: a 100-second credential grab, and the two Sigma rules that survived testing"
date: 2026-10-29T10:00:00Z
draft: false
tags: ["malware","detonation","elastic","detection","sigma","agent-tesla","process-hollowing","recorded-future"]
summary: "An Agent Tesla dropper hollowed the signed .NET registration utility RegSvcs.exe. From inside it the sample read both browser credential stores and the Windows Credential Vault, then was gone in a hundred seconds. Three draft Sigma rules came out of it. Two survived 90 days of live testing with 19 true positives and no false positives. The third converted cleanly and passed every validator, yet could never fire."
---

{{< takeaways >}}
- An **Agent Tesla** dropper was detonated on an isolated analysis host. The family label came from
  the Recorded Future MCP server and was corroborated independently by a memory-scan signature on
  the hollowed process, so it is attribution with two sources rather than one.
- The whole chain ran in **32 seconds**, from double-click to credential vault. The dropper spawned
  `RegSvcs.exe` with **no arguments**, overwrote it, and exited **114 ms later**.
- From inside the signed Microsoft binary it read Chrome's and Edge's `Login Data` 18 ms apart and
  loaded `vaultcli.dll`. **No persistence was established at all.** No Run key, no scheduled task, no service.
- The only destination host telemetry ever recorded was the **internal proxy**. Any detection that
  filters on "external destination" would have seen nothing.
- **One indicator in the enrichment was not this sample's.** `198.23.185.237` is the ScreenConnect
  relay from an August detonation, still beaconing from the host 80 days later. Its "30 sightings"
  were 30 rollups of one flow that started three and a half minutes before the sample ran.
- Three draft Sigma rules came out of it, and **all three had a defect that no validator catches**.
  Two were caught by reading the compiled query; the third by labelling each condition against the
  evidence, which exposed a reasonable inference that quietly narrowed a rule past the behaviour it
  was written for.
- **Two shipped, one was withdrawn.** Run against 90 days of live data the two survivors produced
  **19 hits, every one a true positive, across two independent Agent Tesla samples 82 days apart**.
  The third converted cleanly and passed every validator, then returned **zero**, because its pipeline pointed
  at a field the estate does not populate for that event type.
{{< /takeaways >}}

## Case Summary

A commodity **.NET infostealer** that uses **process hollowing against a signed Microsoft .NET
utility** as its entire defence-evasion strategy, then reads **browser credential stores and the
Windows Credential Manager vault** from inside it. No persistence, no second stage, no tampering
with the endpoint agent. Commodity infostealer volume looks like this.

**Host:** `analysis-host` · **User:** `analyst` · **Detonated:** 2026-10-27 21:20:27 UTC ·
**Alert window:** 21:21:03–21:30:18 · **Capture:** 10,652 documents, 35 alerts over 15 minutes ·
**Telemetry:** healthy

Sample: `fdc9cb253a2ebb99df48133a5c2e0d35cfa5fb4ee7578f6648bded8b5187b42c`, delivered as a 7-Zip
archive and executed by double-click from the Downloads directory.

**Assessment: a commodity stealer that spends its whole evasion budget on one trick and then works
fast.** It buys a signed Microsoft process to run inside, takes what it can reach in three seconds,
and leaves nothing behind to find later. The absence of persistence is the part worth planning
against: there is no Run key to hunt for afterwards, so the only window in which this is detectable
is the hundred seconds it was running.

### Attribution

| | |
|---|---|
| Family | **Agent Tesla** (Keylogger, Trojan) |
| Source | Recorded Future intelligence card, master ID `hd4fiZ`, risk 65/99, rule fired: *Positive Malware Verdict* |
| Independent corroboration | Elastic Defend memory scan matched `Windows.Trojan.AgentTesla` inside the hollowed process, which is a different method on a different artefact |
| Sandbox | Triage score 10, 14 signatures, **0 C2 indicators** |

Attribution adopted. Two methods agree on the family: a hash-keyed intelligence lookup, and a memory
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
**114 milliseconds** after spawning it.

Elastic Defend saw the mechanics directly, three behaviours within 25 ms of each other:
*Suspicious Suspended Process Creation*, *Suspicious Remote Memory Allocation* and *Remote Thread
Context Manipulation*. That triad is `CreateProcess(SUSPENDED)` → `VirtualAllocEx` →
`SetThreadContext`/`ResumeThread`, which is hollowing written out in API calls.

From this point everything the sample does is attributed to a signed Microsoft binary sitting in
`C:\Windows\Microsoft.NET\`.

## Discovery

`RegSvcs.exe` then loaded the entire WMI client stack in 150 ms: `wmiutils.dll`, `wbemcomn.dll`,
`wbemprox.dll`, `WMINet_Utils.dll`, `wbemsvc.dll`, `fastprox.dll`. A registration utility has no
reason to hold a WMI connection. Agent Tesla uses WMI to enumerate the host and the installed
security products before it decides what to do, and the module loads are the only trace of it in
this capture, because the queries themselves were never logged.

## Credential Access

Three seconds after the hollowing, and in this order:

| Time | What |
|---|---|
| 21:21:02.1831 | opened `...\Google\Chrome\User Data\Default\Login Data` |
| 21:21:02.2012 | opened `...\Microsoft\Edge\User Data\Default\Login Data` |
| 21:21:02.2349 | loaded `vaultcli.dll` from `SysWOW64` |

Eighteen milliseconds separate the two browser reads. The sample then reached the Windows
Credential Manager vault through its client library, from a process whose real identity is a COM+
registration tool.

Nine alerts fired on this half of the chain, all tagged T1555.004, split between *Access to Windows
Passwords Vault by Unusual Process* and *Suspicious Vault Client Image Load*. It is the most
confidently detected part of the intrusion and the least evadable, because an infostealer that wants
vault contents has to load that DLL into whatever process it is running as.

## Command and Control

```
21:21:01.6059  RegSvcs.exe  →  <proxy-ip>:3128   connection_attempted
21:22:42.1162  RegSvcs.exe  →  <proxy-ip>:3128   disconnect_received
```

One socket, about 100 seconds, and **the destination is the internal proxy**. That is the only
destination the endpoint agent can record on a proxied estate. A detection rule testing for "a .NET
utility connected to an external address" would not have fired here. One testing for "a .NET utility
opened a socket at all" would.

No DNS query and no TLS SNI is attributable to the sample. Triage reported 0 C2 indicators, and
nothing in this capture contradicts that.

## The indicator that was not ours

The enrichment file lists `198.23.185.237` as an external destination with **30 local sightings**,
ASN 63025, NOHAVPS LLC, Draper, Utah, with three low-confidence risk rules behind it. Recorded
Future was careful about it, and the card says *not a confirmed command-and-control host*, but it is
sitting in an indicator list for an Agent Tesla detonation, and that is how an indicator gets
believed.

It is not this sample's. The telemetry is unambiguous:

- there is exactly **one** TCP session to it, `<analysis-host-ip>:57803 → 198.23.185.237:8041`, one
  `network.community_id`, and its `event.start` is **21:16:48.667Z**, three minutes and thirty-nine
  seconds *before* the sample executed;
- the **30 sightings are 30 repeats of that one flow**, because Packetbeat re-reports a live flow
  every ten seconds. Thirty rollups of one connection is not thirty connections;
- `ScreenConnect.WindowsClient.exe` is installed at `C:\Program Files (x86)\Windows VC\` and runs as
  `"RunRole" "<guid>" "System"`, logging a service event every 60 seconds throughout the window;
- port **8041** is the ScreenConnect relay default, and `198.23.185.237:8041` is written down as the
  ScreenConnect relay in the August RMM-abuse write-up from this same lab;
- the hollowed `RegSvcs.exe` never touched it.

So the August implant is still alive on the analysis host eighty days later, and it put a VPS in
Utah into October's indicator set. Lab hygiene is the smaller problem that exposes.

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
software file, 0 of 17 risk rules, Cleanset Match. It has 21 local sightings and it is the second
most-seen hash in the capture, and publishing it would have people hunting for a file on every
Windows host with .NET installed. The abused binary is not the malicious one.

`198.23.185.237` is absent for the reason given above.

The dropper's other hashes, for feed matching: MD5 `afeb6d5fc91e7f54feb84544c13f086e`, SHA1
`c8fc8fdc508bfdbacced8192b229233f095e5771`. The MD5 has no direct Recorded Future entity of its own
and resolves only through the SHA256's `fileHashes` list, which is worth knowing if your pipeline
enriches on MD5.

## MITRE ATT&CK

{{< mitre key="agent_tesla_regsvcs_hollowing" >}}

A note on the tactic names: the alerts say *Defense Evasion*, and that is what is recorded above,
because it is what fired. ATT&CK retired that tactic in v19 and redistributed its techniques across
`stealth` and `defense-impairment`, so the Sigma rules below carry `attack.stealth` while the
Elastic alerts that prompted them still say Defense Evasion. Both are correct for their own
vintage. Anything that maps between them needs to know which side it is standing on.

## Threat Intelligence

{{< cti key="agent_tesla_regsvcs_hollowing" >}}

## Three rules, and what the compiler caught

The detonation produced three draft Sigma rules, all `status: experimental`, none of them ever run
against production data. They are deliberately three cuts at one chain rather than one compound
rule, because a compound rule cannot be tuned: suppressing the noisy half suppresses the useful
half.

| Rule | Targets | Level | Outcome |
|---|---|---|---|
| `proc_creation_win_dotnet_framework_utility_no_arguments` | the hollowing spawn: a .NET utility started with an empty argument list | high | shipped |
| `net_connection_win_dotnet_framework_utility_outbound` | a .NET utility opening a socket, with no destination condition at all | medium | shipped |
| `image_load_win_vaultcli_by_dotnet_framework_utility` | `vaultcli.dll` loaded into a .NET utility | high | **withdrawn** |

The first is the more fragile of the two survivors and it says so in its own validation note. **One junk
argument on the `RegSvcs.exe` command line defeats it.** It earns a place by being cheap and precise
and aimed at the chokepoint the loader cannot skip, but it is a rule about this month's tradecraft.
The second survives the evasion that kills it, which is why the two ship linked with
`related: type: similar` and are meant to be deployed together.

### The condition that came out

The first draft of rule one had a third clause, requiring the parent process to be running from a
user-writable directory: `\Downloads\`, `\AppData\Local\Temp\`, `\Users\Public\` and four
more. It looks like exactly the sort of thing that belongs in a loader rule.

Labelling each condition against what the capture actually showed is what undid it. Only
`\Downloads\` was sourced: the observed parent really did run from there. The other six paths
were inference, and the clause as a whole was doing something worse than being partly invented.
**It was narrowing the rule on an inference.** Stage the dropper into a new directory under
`C:\`, or a writable subdirectory of `Program Files`, and the whole rule goes quiet with nothing
in the telemetry looking wrong.

The clause was removed. `ParentImage` stays in `fields` as a triage aid, which is where a parent
belongs when it cannot be defended as a condition, and the path list survives in the validation note
as a tuning pattern with the values left blank for whoever deploys it.

The trade runs both ways. The rule is **more durable**, because path variation no longer defeats it.
It is also **broader**: it will now fire
when an administrator runs `RegSvcs.exe` interactively to read its usage text, which is the false
positive the parent clause had been quietly suppressing. Nothing was substituted for it, because
a filter on shell parentage would have needed a value this environment has not confirmed, and a
fabricated filter looks tested while excluding nothing.

The other two came through the same pass without a logic change. Every narrowing condition
in both is sourced straight from the capture; their inferred values sit only on broadening
alternatives inside OR lists, which widen the match rather than tighten it. That distinction is what
the labelling exists to force.

The validation step is where this gets useful. `sigma check` passed all three cleanly, and **two of
them were still wrong**. Only reading the converted query found it.

**The network rule compiled to a query that can never be true.** The draft carried
`Initiated: 'true'`, which is right for Sysmon EventID 3. Converted through `ecs_windows` it became:

```
network.direction:true
```

ECS `network.direction` carries `ingress`, `egress`, `inbound`, `outbound` or `internal`. It never
carries a boolean. That clause would have silently reduced the rule to nothing, and it passed every
validator. The clause was removed rather than left in, and the rule now notes that an analyst
deploying against raw Sysmon should add it back while one deploying against ECS must not.

**The vault rule asserted a field describing the wrong object.** The draft offered
`OriginalFileName` as an alternative to `Image`, which is the standard hardening against a renamed
binary. Under `category: image_load` the pipeline maps that field to `file.pe.original_file_name`,
the original name of the **loaded module**, not of the loading process. The rule was quietly
claiming "the DLL being loaded is called RegSvcs.exe". It was dropped, and the renaming gap is
written down as a residual gap instead of papered over with a field that looks like it closes it.

A third caveat applies to all three and is not fixable in the YAML. The converted queries carry
**no event-category binding**, and neither `ecs_windows` nor `windows-logsources` adds one, so they
match on field presence alone. The network rule is the dangerous one: unscoped, it matches
process-creation documents too, because `process.executable` is populated there as well. These must
be scoped by index pattern or by an added `event.category` clause before they go anywhere near an
alerting queue.

And one more, for anyone running the vault rule against Elastic Defend rather than Winlogbeat:
`ImageLoaded` converts to `file.path`, but Defend's library events carry `dll.path`. The query is
correct and returns nothing, which looks exactly like the behaviour being absent. Both variants are
in the validation note.

## Testing them against 90 days of real data

Static validation says a rule parses and compiles. It says nothing about whether it fires. So the
converted queries went read-only against the live cluster: the detonation window first, then 90
days across every host.

The detonation window was the easy part: the spawn rule returned the hollowing event, the network
rule returned the socket. Both correct.

The 90-day retrohunt returned something more interesting. Both rules had hits dated **2026-08-06**,
eighty-two days before the run this post is about. An unexplained hit is a false positive until
proven otherwise, so those needed attributing before anything could be called clean.

They were a **second, independent Agent Tesla detonation**. Different sample, a different
SHA256-named binary entirely, but the same shape: `RegSvcs.exe` spawned with an empty command line,
parent sitting in a hash-named Downloads directory. The cluster's own alerts for that window settle
it, 51 signals including four `Memory Threat Detection Alert: Windows.Trojan.AgentTesla`. That run
also did things October's did not, adding Defender exclusions through both PowerShell and WMI.

So: **19 hits over 90 days, every one a true positive, across two samples of the same family
eighty-two days apart.** The rules generalise past the sample they were drafted from, which a
single detonation cannot establish.

The honest caveat is the estate. Two hosts report process telemetry and only one runs Windows. "Zero
false positives" here means zero on a single lab workstation over ninety days, during which no .NET
Framework utility was invoked for any legitimate purpose at all. There was never an opportunity for
a false positive. That satisfies the letter of the test plan and not its spirit.

### The rule that returned zero

The vault rule, the most durable logic of the three and the one that survives every evasion that
defeats the other two, returned **nothing**. Not in the detonation window, not in ninety days.

That August detonation raised `Suspicious Vault Client Image Load` four times, so the library load
certainly happened. Querying that window on the field this estate actually populates for module
loads returns **23 documents** containing `vaultcli.dll`. Querying the field the conversion pipeline
chose returns **0**. Estate-wide across ninety days the split is **39,033 documents against 9**.

The logic was never wrong. `ImageLoaded` is the correct Sigma field for `category: image_load`, and
hard-coding this estate's field name would have stopped it being a Sigma rule. The entire point of
a generic logsource is that the mapping lives in the pipeline. What was missing was a pipeline that
knows where this estate's module loads land.

**It was withdrawn rather than shipped.** A rule that converts cleanly, passes every validator and
returns zero does not look broken. It looks like a quiet estate. Shipped, it would have stood as
evidence the credential vault was never touched, on a host where it demonstrably was, twice. One
working pipeline restores it unchanged.


## What this detonation actually taught

Five things, in ascending order of how much they cost to learn.

1. **An argument list can be the detection.** The strongest single signal in 10,652 documents was a
   command line with nothing in it. No hash, no domain, no exotic API. A signed Microsoft binary
   invoked in a way that cannot do its job.
2. **Destination-based logic fails behind a proxy.** The endpoint agent recorded the proxy. If the
   rule had tested for an external address, the C2 channel would have been invisible to it, on an
   estate configured exactly as most managed estates are.
3. **Sighting counts are not corroboration.** Thirty rollups of one flow look identical to thirty
   connections unless you read `event.start` and `community_id`. This is the kind of error that gets
   more convincing as it propagates.
4. **Reading the compiled query is not optional, and running it matters even more.** Two of three
   rules passed `sigma check` and would have shipped broken, and the third only revealed itself as
   undeployable when a real query went to a real index. Neither failure is exotic; both are field-mapping mismatches between
   a generic logsource and a specific schema, which is the normal case, not the edge case.
5. **An unsourced inference that narrows a rule passes every tool in the chain.** The clause
   restricting the parent to a user-writable path would have created a silent blind spot, and
   nothing in the validation chain flagged it. It surfaced only when each condition was labelled
   with where it came from, under a constraint that an unsourced one may not tighten the match.

---

The rules, their validation notes and the package summary are in
[`detections/sigma`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detections/sigma)
and
[`detonations/2026-10-27-agent-tesla-regsvcs-hollowing`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-10-27-agent-tesla-regsvcs-hollowing).
Every rule is a draft for testing. None of them has run against production data, and the retrohunt
in each note is a prerequisite, not a suggestion.
