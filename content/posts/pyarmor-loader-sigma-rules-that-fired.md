---
title: "Two of three Sigma rules fired. The third was right not to."
date: 2026-08-17T12:36:07Z
draft: false
tags: ["malware", "detonation", "elastic", "detection", "sigma", "pyarmor", "pyinstaller"]
summary: "A PyArmor-obfuscated PyInstaller loader, detonated specifically to test three freshly converted Sigma rules. Two fired. The third stayed silent — and that silence turned out to be the correct answer, for a reason worth knowing."
---

Converting a Sigma rule into your own SIEM's language is easy to do and easy to do badly. The
conversion succeeds, the rule enables cleanly, the syntax is valid, and you have no idea whether it
would ever fire — because nothing has tested it.

So this detonation had a specific purpose. Three Sigma rules had just been converted to Elastic
detections: one for double-extension executables launched from user-writable paths, one for PyArmor
obfuscated PyInstaller payload extraction, one for Defender exclusions added via WMIC. The sample was
chosen to exercise all three.

Two of them fired. The third did not — and it was right not to, which took some checking to
establish. Below is the path, the alerts, and why a silent rule is not automatically a broken one.

{{< cti key="pyarmor_pyinstaller_loader" >}}

## The attack path

Both the diagram and the steps below are rendered from the Compromise Canvas export itself, so this
is the same picture the tool draws — not a screenshot that will drift out of date. Drag to pan,
scroll to zoom.

{{< canvas key="pyarmor_pyinstaller_loader" height="430" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-17-pyarmor-pyinstaller-loader/canvas/on-host-attack-path.json" >}}

{{< attackpath key="pyarmor_pyinstaller_loader" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-17-pyarmor-pyinstaller-loader/canvas/on-host-attack-path.json" >}}

## What happened

## Summary

A PyInstaller-packaged, **PyArmor-obfuscated Python loader** was detonated on `analysis-host` at **10:22:48 UTC on 2026-08-17**. It extracted its obfuscated payload to `%TEMP%\_MEI*`, used **WMIC** to add Microsoft Defender exclusions for its own download directory and a `C:\Users\Public` staging path, then **exited cleanly without retrieving a second stage, establishing persistence, or contacting any C2**.

Sample: `d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1` (MalwareBazaar; ships in the wild as `composer.php.exe`, imitating a Composer artefact so a developer double-clicking it believes they are opening a PHP file).

**Assessment: a first-stage loader that prepared the ground and declined to deploy.** It carved out Defender exclusions and then never wrote to the path it had just excluded. Because it made *no network attempt at all* — rather than a failed one — the most probable explanation is anti-analysis logic aborting execution, not dead infrastructure. A payload whose C2 was merely unreachable would still show a connection attempt in endpoint telemetry.

## Timeline (UTC)

| Time | Event | Evidence |
|---|---|---|
| 10:21:22 | Sample downloaded from `bazaar.abuse.ch` | Squid proxy log, Edge user-agent |
| 10:22:48 | `explorer.exe` launches the sample from `C:\Users\analyst\Downloads\` | endpoint.events.process |
| 10:22:50 | PyInstaller unpacks to `_MEI161842`, `_MEI57082`, `_MEI29322`; `pyarmor_runtime.pyd` written to each | endpoint.events.file |
| 10:22:59 | Payload spawns `cmd.exe` | endpoint.events.process |
| 10:23:08 | `cmd.exe /c wmic ... MSFT_MpPreference call Add ExclusionPath="C:\Users\analyst\Downloads"` | process command line |
| 10:23:09 | Second exclusion: `ExclusionPath="C:\Users\Public\IIPaint\ceduwoc"` | process command line |
| 10:23:02-13 | All six sample processes exit, **code 0** | process end events |
| - | **No further activity. Nothing was ever written to the excluded staging path.** | file telemetry |

**Elapsed download to execution: 86 seconds.**

## What it did

1. **T1204.002 User Execution: Malicious File** - launched interactively from `Downloads` by `explorer.exe`.
2. **T1027.002 Obfuscated Files: Software Packing** - PyInstaller one-file extraction to `%TEMP%\_MEI*`, with `pyarmor_runtime_000000\pyarmor_runtime.pyd` in each. The bundled bytecode was deliberately obfuscated with PyArmor before packaging. Three separate extractions, as it ran three times.
3. **T1059 Command and Scripting Interpreter** - `cmd.exe` used as the launcher for WMIC.
4. **T1562.001 / T1564.012 Impair Defenses: Disable or Modify Tools / File-Path Exclusions** - Defender exclusions added through the `MSFT_MpPreference` WMI class rather than the `Add-MpPreference` cmdlet. Administrators and vendor installers overwhelmingly use the cmdlet, so the WMIC path is a strong signal of automated payload behaviour.
5. **T1047 Windows Management Instrumentation** - WMIC as the execution vehicle for step 4.

## What it did NOT do, corroborated four ways

**No C2, no second-stage download, no exfiltration:**

- **Endpoint network telemetry** - zero connection events attributed to the sample or any child (`cmd.exe`, `WMIC.exe`). Elastic Defend records connection *attempts*, so a blocked or failed connection would still appear. There were none.
- **DNS** - nothing resolved during the window that was not ordinary operating-system traffic.
- **Firewall** - no blocked egress from the host.
- **Squid proxy, 874 parsed records across 10:20-11:10** - every destination in the window belongs
  either to routine OS and browser activity, or to my own fetching of the sample beforehand. Each one
  carries a browser or named-updater user-agent and, apart from the sample download, all of it
  pre-dates execution. Nothing during the detonation itself is attributable to the sample.

**No persistence** - no Run keys, scheduled tasks, services, or COM hijacking by the sample. **No credential access, collection, or lateral movement.**

## Detections

Fired, all true positives:

| Rule | Alerts | Severity |
|---|---|---|
| `[Sigma] Suspicious Microsoft Defender Exclusion Added Via WMIC` | 10 | high |
| `[Sigma] Potential PyArmor Obfuscated PyInstaller Payload Extraction` | 6 | medium |
| `Malicious Behavior Detection Alert: Windows Defender Exclusions via WMIC` (Elastic built-in) | 20 | critical |
| ML: suspicious Windows event, high and low malicious probability | 15 | high / low |

**Correctly silent:** `[Sigma] Suspicious Double Extension Executable Launched From User Writable Path`. The sample was executed under its **hash filename**, not as `composer.php.exe`, so the double-extension condition did not match; the user-writable-path half did. This is correct rule behaviour. Re-running the sample renamed to `composer.php.exe` would exercise it.

**False positives identified during triage - do not chase these:**

- `Component Object Model Hijacking`, 4 alerts: `OneDrive.Sync.Service.exe` registering **its own** CLSIDs `{917E8742-...}` and `{47E6DCAF-...}` under `HKCU\..._Classes\CLSID\...\LocalServer32`. OneDrive was mid-setup throughout the window; unrelated to the intrusion.
- `File Compressed or Archived into Common Format by Unsigned Process`, 3 alerts: `base_library.zip` inside the `_MEI*` folders. That is PyInstaller's own standard-library archive, not data theft.

## Indicators

```
SHA256                  d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1
Filename in the wild    composer.php.exe / composer.dat.exe
Artefact paths          %TEMP%\_MEI*\pyarmor_runtime_000000\pyarmor_runtime.pyd
                        C:\Users\Public\IIPaint\ceduwoc   (Defender exclusion, never written to)
Command pattern         cmd.exe /c "wmic /namespace:\\root\Microsoft\Windows\Defender
                                    path MSFT_MpPreference call Add ExclusionPath=..."
Source                  hxxps://bazaar.abuse[.]ch/sample/d97ea10d.../
```

No network indicators - none were observed.

## Lab findings raised by this investigation

1. **Squid proxy logs were unqueryable.** The the firewall integration JSON-decodes the relayed access log into a nested `squid` object but never maps it to ECS, leaving `source.ip`, `url.*`, `http.*` and `user_agent.*` empty, so egress was invisible to queries and detection rules. Fixed during this investigation with a `logs-the firewall.log@custom` ingest pipeline, chosen because version-pinned managed pipelines are replaced on package upgrade. Applies to new documents only; historical squid records remain nested.
2. **The WMIC rule covers only the WMIC path.** A payload using `Add-MpPreference` would not trigger it. Elastic's PowerShell-based Defender-exclusion rule should be confirmed enabled.
3. **`/var/log/squid/access.log` is 0 bytes** - the squid integration's `filestream` inputs collect nothing. All proxy visibility arrives via syslog into `the firewall.log`.
4. **Fleet reports the analysis-host agent as offline** (last check-in 2026-08-08) while telemetry flows normally. Data output works, Fleet check-in does not, so the agent receives no policy updates.

## Attack path diagram

Compromise Canvas export of the on-host attack path:
**[`canvas/on-host-attack-path.json`](canvas/on-host-attack-path.json)** (in this directory)

Download it, then in [CompromiseCanvas](https://github.com/SagaLabs/CompromiseCanvas) choose **Import
JSON** and **double-click the `analysis-host` host** to walk the four steps. The full write-up is published alongside it in `cases/`.

(Case file attachments are disabled on this Elastic Cloud deployment — `POST /api/files/files/...`
returns "exists but is not available with the current configuration" — so canvases are versioned in
that repository rather than attached here.)


## Analyst note 1

### Process tree (endpoint.events.process, analysis-host)

```
explorer.exe
└─ d97ea10d…acf05b1.exe            10:22:48  C:\Users\analyst\Downloads\   pid 16184  exit 0
   ├─ d97ea10d…acf05b1.exe         10:22:50  PyInstaller child re-exec      pid 9568   exit 0
   │                                         → _MEI161842 / _MEI57082 / _MEI29322
   │                                           pyarmor_runtime_000000\pyarmor_runtime.pyd
   │                                           base_library.zip
   ├─ cmd.exe                      10:22:59  /c "C:\Users\analyst\Downloads\d97ea10d…exe"
   │  └─ d97ea10d…acf05b1.exe      10:23:00  third execution                pid 2932   exit 0
   └─ cmd.exe                      10:23:08  /c "wmic /namespace:\\root\Microsoft\Windows\Defender
      │                                          path MSFT_MpPreference call Add
      │                                          ExclusionPath=\"C:\Users\analyst\Downloads\""
      └─ WMIC.exe                  10:23:09  → and ExclusionPath="C:\Users\Public\IIPaint\ceduwoc"
```

Six process instances in total, all exiting with **code 0** between 10:23:02 and 10:23:13. Total
on-host lifetime approximately 25 seconds.


## Analyst note 2

### Egress analysis (Squid proxy, 874 parsed records, 10:20–11:10 UTC)

66 distinct destinations across the hour, and none of them is an indicator. Everything that is not
routine operating-system or browser traffic pre-dates the detonation, and the only download of
interest is my own retrieval of the sample from MalwareBazaar at 10:21:22–30. Between 10:22:48 and
10:24:30 — the entire execution — the proxy saw nothing but ordinary Microsoft and browser activity.

I am deliberately not listing those destinations. They are benign OS and browser endpoints, and
publishing them under a heading like "indicators" is how a defender ends up alerting on Windows
telemetry or a font CDN. The finding here is an absence, and an absence does not have IOCs.

Note also that the sample's processes generated **no endpoint network events at all**, so the
possibility of C2 tunnelled inside allowed sessions is excluded too — nothing belonging to the sample
opened a socket.

## The alerts

{{< alerts key="pyarmor_pyinstaller_loader" >}}

## Validation is the whole point

Seventeen rules fired in total, two of them the freshly converted Sigma rules: the PyArmor extraction
rule at 10:26:20, and the WMIC Defender-exclusion rule three seconds later.

The third — double-extension executables launched from a user-writable path — produced nothing. Not on
this detonation, and, as it turns out, not ever: zero alerts in its entire lifetime.

That looks like a broken rule until you read its condition against what actually ran. The rule wants a
filename ending in a decoy extension pair — `.php.exe`, `.dat.exe` and so on — inside a user-writable
directory. This sample ships in the wild as `composer.php.exe`, imitating a Composer artefact so that a
developer double-clicking it thinks they are opening a PHP file. That is exactly the case the rule is
built for.

But it did not run under that name. Downloaded from MalwareBazaar, it arrives named after its own
SHA256, and that is how it executed: `d97ea10d….exe`. One half of the rule matched — the path was
`\Downloads\` — and the half that defines it did not. So the rule was correctly silent, and it remains
**untested**. Those are different states from "working", and only one of them is reassuring.

The fix is a re-run with the sample renamed to `composer.php.exe`, which is now on the list. Until then
I have a rule that is live, syntactically valid, and completely unproven — which is precisely the
condition I detonated the sample to find out about.

There is a detail here worth stealing. When I first checked, the Sigma rules appeared not to have
fired at all, and I nearly wrote them off. They had simply not run yet: the last rule execution cycle
finished at 10:21:20 and the detonation was at 10:22:50. They fired at 10:26:20, on the next cycle.
If you are validating detections, check the rule's execution schedule before concluding it failed —
an interval-based rule cannot detect something that has not happened yet.

The other half of this story is the traffic. Every outbound request from this host goes through a
proxy, which means the endpoint agent records a connection to the proxy and nothing else. Finding out
where the malware actually wanted to go needed the proxy logs, and those turned out to be arriving in
Elasticsearch unparsed — tens of thousands of records sitting unread while a query for outbound
traffic returned nothing. That is [its own post](/posts/proxy-blind-spot/).

---

The full write-up, the indicators and the canvas export live in
[`detonations/2026-08-17-pyarmor-pyinstaller-loader`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-17-pyarmor-pyinstaller-loader).
