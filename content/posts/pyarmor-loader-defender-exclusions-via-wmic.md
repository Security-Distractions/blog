---
title: "PyArmor-obfuscated loader: Defender exclusions via WMIC, then nothing"
date: 2026-08-17T12:36:07Z
draft: false
aliases: ["/posts/pyarmor-loader-sigma-rules-that-fired/"]
tags: ["malware","detonation","elastic","detection","sigma","pyarmor","pyinstaller"]
summary: "A PyInstaller loader, obfuscated with PyArmor, unpacked itself, added Microsoft Defender exclusions through WMIC, and exited without retrieving a second stage, persisting, or contacting any C2."
---

{{< takeaways >}}
- A **PyInstaller loader, obfuscated with PyArmor**, extracted its payload to `%TEMP%\_MEI*` and
  re-executed itself twice.
- It added **Microsoft Defender exclusions via WMIC**, covering its own download directory and a
  `C:\Users\Public` staging path, through the `MSFT_MpPreference` WMI class rather than the
  `Add-MpPreference` cmdlet.
- It then **exited**: no second stage was retrieved, no persistence was established and **no C2 was
  contacted**. It never wrote to the path it had just excluded.
- Because it made *no network attempt at all* rather than a failed one, the likeliest explanation is
  anti-analysis logic aborting execution rather than dead infrastructure.
- **There are no network indicators.** Nothing belonging to the sample reached the network, so every
  destination in the window was ordinary operating-system or browser traffic.
- 17 rules produced 69 alerts, two of them Sigma-derived: PyArmor extraction, and the WMIC exclusion.
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

**No C2, no second-stage download, no exfiltration.** Four independent sources agree:

- **Endpoint network telemetry** — zero connection events attributed to the sample or to any child
  process. Elastic Defend records connection *attempts*, so a blocked or failed connection would still
  appear. There were none.
- **DNS** — nothing resolved during the window beyond ordinary operating-system traffic.
- **Firewall** — no blocked egress from the host.
- **Proxy** — every destination in the window belongs to routine operating-system or browser activity,
  and all of it pre-dates execution.

Because the sample's processes opened no sockets at all, C2 tunnelled inside an allowed session is
excluded as well.

**No persistence** — no Run keys, scheduled tasks, services or COM hijacking. **No credential access,
collection or lateral movement.** The sample never wrote to the directory it had just excluded from
Defender.

An absence of network activity produces no indicators, so none are listed for it. The benign
operating-system and browser destinations seen in the window are not indicators of this sample.

## Timeline

{{< timeline key="pyarmor_pyinstaller_loader" >}}

## Detections

{{< alerts key="pyarmor_pyinstaller_loader" >}}

Two detections are Sigma-derived: PyArmor payload extraction fired at 10:26:20, and the WMIC
Defender-exclusion rule three seconds later.

A third Sigma rule covering double-extension executables did not fire. It requires a filename ending
in a decoy pair such as `.php.exe`; although this sample ships in the wild as `composer.php.exe`, it
executed under its SHA256 filename, so the condition was absent rather than missed.

## Indicators

{{< indicators key="pyarmor_pyinstaller_loader" >}}

## MITRE ATT&CK

{{< mitre key="pyarmor_pyinstaller_loader" >}}

## Threat Intelligence

{{< cti key="pyarmor_pyinstaller_loader" >}}


---

The write-up, indicators and canvas export are in
[`detonations/2026-08-17-pyarmor-pyinstaller-loader`](https://github.com/Security-Distractions/cti-driven-detection-engine/tree/main/detonations/2026-08-17-pyarmor-pyinstaller-loader).
