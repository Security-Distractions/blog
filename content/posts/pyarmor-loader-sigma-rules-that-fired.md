---
title: "Two of three Sigma rules fired. The third was right not to."
date: 2026-08-17T12:36:07Z
draft: false
tags: ["malware","detonation","elastic","detection","sigma","pyarmor","pyinstaller"]
summary: "A PyArmor-obfuscated PyInstaller loader, detonated specifically to test three freshly converted Sigma rules. Two fired. The third stayed silent, and that silence was the correct answer for a reason worth knowing."
---

{{< takeaways >}}
- A **PyArmor-obfuscated PyInstaller loader** was detonated to validate three Sigma rules just
  converted to Elastic detections. The sample was chosen to exercise all three.
- **Two of the three fired**: PyArmor payload extraction, and Defender exclusion addition via WMIC.
- **The third has never fired — zero alerts in its lifetime.** It requires a decoy double extension
  such as `.php.exe`; the sample executed under its own SHA256 filename, so the condition never
  existed. The rule is *correctly silent* and therefore still **unproven**, which is not the same as
  working.
- The loader added Defender exclusions covering its download directory and a `C:\Users\Public`
  staging path, then **exited without retrieving a second stage, establishing persistence, or
  contacting any C2**.
- Because it made *no network attempt at all* rather than a failed one, the likeliest explanation is
  anti-analysis logic aborting execution, not dead infrastructure. **There are therefore no network
  indicators**, and the benign operating-system traffic in the window is deliberately not published
  as one.
- The rules initially appeared not to have fired. They had simply not run yet: the last execution cycle
  finished at 10:21:20 and the detonation was at 10:22:50. Check a rule's schedule before concluding
  it failed.
{{< /takeaways >}}

## Case Summary

A PyInstaller-packaged, **PyArmor-obfuscated Python loader** was detonated on `analysis-host` at **10:22:48 UTC on 2026-08-17**. It extracted its obfuscated payload to `%TEMP%\_MEI*`, used **WMIC** to add Microsoft Defender exclusions for its own download directory and a `C:\Users\Public` staging path, then **exited cleanly without retrieving a second stage, establishing persistence, or contacting any C2**.

Sample: `d97ea10d1dbfe2a69e0d2387e8985635b20628495918abd54c4b052c0acf05b1` (MalwareBazaar; ships in the wild as `composer.php.exe`, imitating a Composer artefact so a developer double-clicking it believes they are opening a PHP file).

**Assessment: a first-stage loader that prepared the ground and declined to deploy.** It carved out Defender exclusions and then never wrote to the path it had just excluded. Because it made *no network attempt at all* — rather than a failed one — the most probable explanation is anti-analysis logic aborting execution, not dead infrastructure. A payload whose C2 was merely unreachable would still show a connection attempt in endpoint telemetry.

Both the diagram and the step list below are rendered from the Compromise Canvas export, so they are
the same path the tool draws. Drag to pan, scroll to zoom.

{{< canvas key="pyarmor_pyinstaller_loader" height="430" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-17-pyarmor-pyinstaller-loader/canvas/on-host-attack-path.json" >}}

{{< attackpath key="pyarmor_pyinstaller_loader" download="https://github.com/Security-Distractions/cti-driven-detection-engine/raw/main/detonations/2026-08-17-pyarmor-pyinstaller-loader/canvas/on-host-attack-path.json" >}}

## Execution

1. **T1204.002 User Execution: Malicious File** - launched interactively from `Downloads` by `explorer.exe`.
2. **T1027.002 Obfuscated Files: Software Packing** - PyInstaller one-file extraction to `%TEMP%\_MEI*`, with `pyarmor_runtime_000000\pyarmor_runtime.pyd` in each. The bundled bytecode was deliberately obfuscated with PyArmor before packaging. Three separate extractions, as it ran three times.
3. **T1059 Command and Scripting Interpreter** - `cmd.exe` used as the launcher for WMIC.
4. **T1562.001 / T1564.012 Impair Defenses: Disable or Modify Tools / File-Path Exclusions** - Defender exclusions added through the `MSFT_MpPreference` WMI class rather than the `Add-MpPreference` cmdlet. Administrators and vendor installers overwhelmingly use the cmdlet, so the WMIC path is a strong signal of automated payload behaviour.
5. **T1047 Windows Management Instrumentation** - WMIC as the execution vehicle for step 4.

## Process tree

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

## What was not observed

**No C2, no second-stage download, no exfiltration:**

- **Endpoint network telemetry** - zero connection events attributed to the sample or any child (`cmd.exe`, `WMIC.exe`). Elastic Defend records connection *attempts*, so a blocked or failed connection would still appear. There were none.
- **DNS** - nothing resolved during the window that was not ordinary operating-system traffic.
- **Firewall** - no blocked egress from the host.
- **Squid proxy, 874 parsed records across 10:20-11:10** - every destination in the window belongs
  either to routine operating-system and browser activity, or to the analyst retrieval of the sample
  beforehand. Each one
  carries a browser or named-updater user-agent and, apart from the sample download, all of it
  pre-dates execution. Nothing during the detonation itself is attributable to the sample.

**No persistence** - no Run keys, scheduled tasks, services, or COM hijacking by the sample. **No credential access, collection, or lateral movement.**

### Egress analysis

66 distinct destinations across the hour, and none of them is an indicator. Everything that is not
routine operating-system or browser traffic pre-dates the detonation, and the only download of
interest is the analyst retrieval of the sample from MalwareBazaar at 10:21:22–30. Between 10:22:48 and
10:24:30 — the entire execution — the proxy saw nothing but ordinary Microsoft and browser activity.

Those destinations are deliberately not listed. They are benign operating-system and browser
endpoints, and publishing them under a heading like "indicators" is how a defender ends up alerting on
Windows telemetry or a font CDN. The finding here is an absence, and an absence has no indicators.

Note also that the sample's processes generated **no endpoint network events at all**, so the
possibility of C2 tunnelled inside allowed sessions is excluded too — nothing belonging to the sample
opened a socket.

## Timeline

{{< timeline key="pyarmor_pyinstaller_loader" >}}

## Detections

{{< alerts key="pyarmor_pyinstaller_loader" >}}

Seventeen rules fired, two of them the freshly converted Sigma rules: the PyArmor extraction rule at
10:26:20, and the WMIC Defender-exclusion rule three seconds later.

The third — double-extension executables launched from a user-writable path — produced nothing, and has
produced nothing in its entire lifetime. That reads as a broken rule until its condition is compared
against what actually ran. The rule requires a filename ending in a decoy extension pair (`.php.exe`,
`.dat.exe` and similar) inside a user-writable directory. This sample ships in the wild as
`composer.php.exe`, imitating a Composer artefact so a developer double-clicking it believes they are
opening a PHP file — exactly the case the rule was written for.

It did not run under that name. Downloaded from MalwareBazaar it arrives named after its own SHA256,
and that is how it executed. One half of the rule matched, the path; the half that defines it did not.
The rule was correctly silent and remains **untested**. Those are different states from "working", and
only one of them is reassuring. A re-run with the sample renamed is outstanding.

## Indicators

{{< indicators key="pyarmor_pyinstaller_loader" >}}

## MITRE ATT&CK

{{< mitre key="pyarmor_pyinstaller_loader" >}}

## Threat Intelligence

{{< cti key="pyarmor_pyinstaller_loader" >}}

## Findings raised by this investigation

1. **Squid proxy logs were unqueryable.** The the firewall integration JSON-decodes the relayed access log into a nested `squid` object but never maps it to ECS, leaving `source.ip`, `url.*`, `http.*` and `user_agent.*` empty, so egress was invisible to queries and detection rules. Fixed during this investigation with a `logs-the firewall.log@custom` ingest pipeline, chosen because version-pinned managed pipelines are replaced on package upgrade. Applies to new documents only; historical squid records remain nested.
2. **The WMIC rule covers only the WMIC path.** A payload using `Add-MpPreference` would not trigger it. Elastic's PowerShell-based Defender-exclusion rule should be confirmed enabled.
3. **`/var/log/squid/access.log` is 0 bytes** - the squid integration's `filestream` inputs collect nothing. All proxy visibility arrives via syslog into `the firewall.log`.
4. **Fleet reports the analysis-host agent as offline** (last check-in 2026-08-08) while telemetry flows normally. Data output works, Fleet check-in does not, so the agent receives no policy updates.

---

Every outbound request from this host egresses through a proxy, so the endpoint agent records a
connection to the proxy and nothing else. Establishing where the malware wanted to go required the
proxy logs, which were arriving in Elasticsearch unparsed — tens of thousands of records unread while a
query for outbound traffic returned nothing. That is [its own post](/posts/proxy-blind-spot/).

The write-up, indicators and canvas export are in
[`detonations/2026-08-17-pyarmor-pyinstaller-loader`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-17-pyarmor-pyinstaller-loader).
