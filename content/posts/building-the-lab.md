---
title: "Building a malware lab in the wrong order, over two years"
date: 2026-09-02
draft: true
tags: ["lab", "process", "proxmox", "elastic", "meta"]
summary: "The part that looks like building a lab took a single day. Everything that made it useful took two years, happened out of order, and is only reconstructable because the machines kept better notes than I did."
---

{{< takeaways >}}
- The **SIEM predates the lab by two years**. That accident turned out to be the single most useful thing about the sequence.
- **Network telemetry before host telemetry.** It is cheaper, needs no agent on the victim, and survives the reimaging that a detonation lab does constantly.
- The platform migration, the bit that looks like "building a lab", took **under 24 hours** and is the narrowest band on the timeline.
- The two steps everyone skips are **the clean snapshot** and **reading the log of the backup that said it worked**. Both are cheap. Both are unrecoverable.
{{< /takeaways >}}

Every date in this post was recovered from the machines rather than from memory: VM creation
times out of `ctime` on the Proxmox config files, commissioning out of the host task log,
telemetry start dates out of the earliest document per dataset in Elastic. This was less
nostalgic than it sounds. It is mostly the experience of doing digital forensics on your own
lab and discovering that past you left no notes whatsoever.

## The timeline, such as it is

| When | What happened |
|---|---|
| **2024-03-08** | First security alert ever fires. The rule is called `My First Rule`. |
| **2025-08** | Detonations running in anger: 113, 535 and 352 critical alerts on three separate days |
| **2026-04-05** | Firewall logs start reaching Elastic |
| **2026-06-08** | Windows endpoint telemetry starts |
| **2026-06-23** | Sysmon added on top, fifteen days later |
| **2026-07-21 18:49** | Proxmox host commissioned. Its first recorded act is an `apt update`. |
| **2026-07-22 09:45** | The victim VM is created |
| **2026-07-22 14:41** | The firewall first starts, and was *imported*, not built |
| **2026-07-22 15:33** | The utility box is created |
| **2026-07-22 18:44** | Snapshot `golden-baseline`, the clean state everything now depends on |
| **2026-08-08** | Workshop: five samples, 420 critical alerts |
| **2026-08-18** | Whole environment backed up, 245 GB, every checksum verified |

Two years, three months, and the actual construction happens in the middle of a single Tuesday.

## Step 1: have somewhere to put the data, ideally by accident

The Elastic deployment predates this lab by over two years. The first alert it ever produced
came from a detection rule named, and I want to be clear that I am not inventing this, `My First Rule`.

I would love to claim this as architectural foresight. It was not. But it is still the most
useful thing about the whole sequence, because it meant **there was somewhere to send telemetry
before there was anything generating it.** Build the detonation host first and you get to run
malware with nowhere to look, which is not research. It is just malware.

## Step 2: detonate on whatever you already have

Through 2025 the lab ran on pre-Proxmox infrastructure that I would not describe as a lab so
much as a collection of things that happened to be plugged in. It produced 535 critical alerts
in a single day in August 2025. The firewall was a VMware appliance whose `.ovf` and `.vmdk`
exports are still sitting on the external drive like a fossil layer.

The analysis work started long before the platform was tidy, and that was correct. Waiting for
the proper lab would have cost a year of detonations, and the proper lab would have been designed
around guesses instead of around what actually turned out to matter.

## Step 3: network telemetry first

Firewall logs reached Elastic in April 2026. Endpoint telemetry did not arrive until June. That
order was deliberate and I would defend it in public.

Network telemetry is cheap, needs no agent on the victim, and, crucially, survives the host
being reimaged, which in a detonation lab happens roughly every twenty minutes. It also answers
the one question host telemetry cannot: *where did it go.* An endpoint agent watches a process
open a socket to the proxy and considers its work done. The proxy knows the rest.

## Step 4: add host telemetry one source at a time

Elastic Defend on 8 June. Sysmon on 23 June. The fifteen-day gap was not procrastination, for
once.

Install both together and every gap in your data is unattributable. You cannot tell whether a
missing event means Sysmon is misconfigured, or Defend never saw it, or the thing simply did not
happen. Stagger them and each new source arrives against a known baseline. It is the difference
between a controlled experiment and a pile of logs you feel vaguely optimistic about.

## Step 5: migrate only once the workflow is proven

By July the loop was known: detonate, look in Elastic, restore. Only then did the whole thing
move to Proxmox, and the move took less than a day:

1. **Commission the host** `apt update`, storage, bridges
2. **Create the victim first**, because it has the long tail of driver, licensing and
   telemetry-agent misery attached to it
3. **Import the firewall rather than rebuild it**
4. **Create the utility box last**, since it is the easiest to rebuild and needs the others to exist
5. **Snapshot as soon as each thing boots**
6. **Snapshot again once it is actually configured, and name that one unmistakably**

A small piece of forensic comedy from step 3: the firewall VM has no `qmcreate` entry in the task
log at all. It simply appears, fully formed, at 14:41. I spent a genuinely embarrassing amount of
time wondering whether I had lost a log file before working out that it was an OVF import, which
is why no creation task exists. Years of firewall, proxy and IDS configuration that nobody sane
would retype, preserved by the simple expedient of not touching it.

## Step 6: make the destructive bit repeatable *before* being destructive

`golden-baseline` is not a backup. It is the entire workflow: restore, detonate, restore. Without
a clean snapshot every detonation permanently degrades the host and your results quietly stop
being comparable to each other.

It was taken at 18:44, two hours after the VM first booted, and before any malware ran. Those two
hours are the whole difference between a lab and a mess, and they cost nothing but the discipline
to not immediately start clicking on things.

## Step 7: tune the telemetry only once it hurts

In August the cluster reached 1,086 shards, 96.7 GB and 97% heap, at which point Kibana began
returning 500s. This is a SIEM's way of filing a formal complaint.

The fix was deletion, which is never the fix anybody wants: retention cuts, dropped replicas,
thinned per-agent telemetry. That took it to 634 shards and 41 GB, and it has since drifted down
to 24.8 GB on its own. Only afterwards was there headroom to raise enabled detection rules from
620 to 1,111.

Doing this at the start would have been premature optimisation on an empty cluster. Doing it when
Kibana started failing was late, but not too late, which is where most infrastructure work
actually lives.

## Step 8: protect it last, and check what "protected" means

The full backup ran on 18 August: three VMs, all 18 snapshot volumes, host configuration, 245 GB,
every checksum verified.

Buried in the `vzdump` output was this line:

```text
snapshots found (not included into backup)
```

The job reported success. It had faithfully backed up everything except the snapshots, which is
to say everything except `golden-baseline`, which is to say everything except step 6, the thing
the entire workflow depends on. A backup that says "OK" and a backup that contains what you think
it does are two different objects, and only one of them is discoverable by reading the log.

## If you were building this again

Stripped of the history, the order that worked:

1. **Somewhere to send telemetry**, before anything generates any
2. **A firewall you control**, logging into it. Import an existing config if you have one
3. **Network telemetry first** cheap, agentless, survives reimaging
4. **A victim VM**, then host telemetry **one source at a time**
5. **A clean snapshot, unmistakably named**, before the first sample runs
6. **One detonation end to end** prove you can see it, then restore
7. **Detection content against what you actually collect**, tested by detonating rather than by hoping
8. **Retention and cost control** when the cluster complains, not before
9. **Backups, then verify the backup contains what you think it does**

The two that get skipped are 5 and 9. They are also the only two on the list that cannot be fixed
retrospectively, which is either a coincidence or the entire point.
