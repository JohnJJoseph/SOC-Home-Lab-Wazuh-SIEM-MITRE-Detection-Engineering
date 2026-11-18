# SOC Home Lab — Wazuh SIEM, Sysmon & MITRE ATT&CK Detection Engineering

A self-built Security Operations Center (SOC) home lab used to practice end-to-end detection
engineering: deploying a SIEM, onboarding log sources over an encrypted pipeline, writing and
tuning custom detection rules, and triaging simulated attacks mapped to the MITRE ATT&CK
framework.

> This lab was built and run locally; this repository documents the design, implementation
> steps and detection logic. [Add screenshots, exported rule files, or config snippets below
> if you still have them — even a few dashboard screenshots make this much stronger.]

## Objectives

- Stand up a working SIEM/XDR platform from scratch (Wazuh) rather than just reading about one.
- Onboard a realistic mix of log sources over an encrypted transport.
- Write custom detection rules mapped to MITRE ATT&CK and NIST SP 800-53, instead of relying
  only on out-of-the-box rules.
- Simulate attacker behaviour across the kill chain and measure how well the lab detected it.
- Tune rules to cut false positives without losing real detections.

## Architecture

```
                    ┌───────────────────────────────┐
                    │        Log Sources             │
                    │  Windows Event Logs, Sysmon,    │
                    │  PowerShell logs, network        │
                    │  telemetry                        │
                    └───────────────┬────────────────┘
                                    │  Wazuh Agent /
                                    │  Syslog over TLS
                                    ▼
                    ┌───────────────────────────────┐
                    │        Wazuh Manager            │
                    │  Decoders → Rules → Alert level  │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │        Wazuh Indexer            │
                    │  Stores & indexes alerts         │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │        Wazuh Dashboard          │
                    │  Search, visualize, triage       │
                    └───────────────────────────────┘
```

## Core Components

| Component | Role |
|---|---|
| Wazuh Manager | Applies decoders and rules to incoming logs; assigns an alert level 0–15 |
| Wazuh Indexer | Stores and makes alerts searchable |
| Wazuh Dashboard | Web interface for search, visualization and triage |
| Wazuh Agent | Installed on each endpoint; collects logs, runs file integrity monitoring (FIM) and active response |
| Sysmon | Installed on Windows endpoints for high-fidelity process, network and registry telemetry |
| [Attacker host, e.g. Kali Linux] | Used to generate the simulated attack traffic |

## Log Sources

[State your real count and breakdown here — a log source can mean a host, a device, or a log
*channel* (Security, Sysmon and PowerShell on one host count separately if you counted that
way). Example format:]

- Windows endpoints: [N] hosts × 3 channels each (Security, Sysmon, PowerShell) = [N×3]
- Linux hosts: [N] (syslog / auth.log)
- Network devices / firewall: [N]
- **Total log sources: [your real number]**

## Implementation Steps

1. **Deployed the Wazuh server** (manager, indexer and dashboard) on [OS/VM details — e.g. a
   single Ubuntu VM using the Wazuh all-in-one install script].
2. **Installed Wazuh agents** on each endpoint (Windows and Linux hosts) and registered them
   with the manager.
3. **Installed and configured Sysmon** on Windows endpoints using [the SwiftOnSecurity config /
   your own config] as a baseline, to capture process creation, network connections, and
   registry activity that native Windows logging misses by default.
4. **Enabled the Windows audit policies** needed for Event ID 4688 (process creation) with
   command-line auditing turned on, plus PowerShell Module and Script Block logging
   (Event IDs 4103/4104).
5. **Secured log transport with TLS** instead of plain syslog, since plain syslog is
   unencrypted and can be read or spoofed on the network, and UDP delivery can silently drop
   messages. [Describe exactly how you set this up — which component terminated TLS and how
   certificates were generated/trusted, since this is a common follow-up question.]
6. **Wrote custom detection rules** in `local_rules.xml`, using the reserved custom rule ID
   range (100000+), extending Wazuh's built-in parent rules with `if_sid` and adding MITRE
   ATT&CK tags. Example:

   ```xml
   <rule id="100010" level="10">
     <if_sid>PARENT_RULE_ID</if_sid>
     <field name="win.eventdata.commandLine">-enc</field>
     <description>Encoded PowerShell command</description>
     <mitre>
       <id>T1059.001</id>
     </mitre>
   </rule>
   ```

7. **Ported Sigma rule logic to Wazuh by hand.** Sigma is a vendor-neutral, YAML-based
   detection format; since Wazuh uses its own XML rule syntax, the underlying logic (log
   source, matched fields, conditions) was re-written as native Wazuh rules.
8. **Mapped each rule to NIST SP 800-53 controls** alongside its MITRE ATT&CK technique, to
   connect the technical detection back to a compliance control.
9. **Simulated the attack kill chain** across the stages recon → weaponization → delivery →
   exploitation → installation → command and control → actions on objectives (Lockheed
   Martin Cyber Kill Chain), using [the real tools you used — e.g. Atomic Red Team, manual
   PowerShell/cmd commands, Kali Linux tools] to generate matching telemetry.
10. **Triaged the resulting alerts**: correlated related log entries, investigated root
    cause, and separated true findings from noise.
11. **Tuned rules to reduce false positives** by raising alert thresholds, using `frequency`
    and `timeframe` to require repeated events before alerting, excluding known-good admin
    hosts/accounts, and narrowing field conditions so only the suspicious pattern matched.
    After each tuning change, re-ran the attack simulation to confirm real detections were
    not lost.
12. **Tracked relative MTTD/MTTR** (time to detect / time to respond) informally, comparing
    before and after tuning, as a home-lab practice metric rather than a formal SLA.

## MITRE ATT&CK Techniques Detected

| Technique | Description | Detection logic |
|---|---|---|
| T1059 – Command and Scripting Interpreter | Attacker runs commands via PowerShell, cmd, or bash | Sysmon Event ID 1 and Security Event ID 4688 with suspicious command lines (encoded commands, hidden windows, download cradles); PowerShell Event ID 4104 |
| T1078 – Valid Accounts | Attacker uses stolen or default credentials | Logon from an unusual time/location; a success (4624) shortly after repeated failures (4625); admin logon on an unexpected host |
| T1041 – Exfiltration Over C2 Channel | Data sent out over the same channel used for command and control | Large outbound transfers to rare external IPs, regular beaconing intervals, unusual DNS query volume |

## Results

[Fill in your real figures — don't carry over any number you can't explain in an interview.
Example shape:]

- [N] detection rules written, covering [N] MITRE ATT&CK techniques.
- [N] attack scenarios simulated across the kill chain; [N] detected by the lab's rules.
- False positive rate reduced from [X] to [Y] after tuning. *(Only include this if you
  actually measured it — otherwise describe the tuning qualitatively instead.)*

## Limitations

- This is a home-lab environment, not a production SOC; log volume and traffic patterns are
  far smaller and less noisy than a real enterprise network.
- Attack simulation was [manual / scripted — be specific], not live adversary traffic.
- The custom CVE/detection logic reflects a fixed point in time and was not kept
  continuously updated against newly published techniques.

## Future Improvements

- [ ] Add Wazuh's vulnerability detection and Security Configuration Assessment (SCA) modules.
- [ ] Forward alerts to a SOAR-style active response for automated containment.
- [ ] Expand log sources to cloud (e.g. AWS CloudTrail) telemetry.
- [ ] Automate the attack simulation with a tool like Atomic Red Team for repeatable testing.

## Disclaimer

This lab was built entirely in an isolated, self-owned environment for learning purposes.
No real organizations' systems or data were involved.
