# WEEK 8 — ADVERSARY EMULATION PLAN

**Initial Access → Persistence → Data Exfiltration | ATT&CK Project Increment**

**Project context:** Analysis of SIEM priority evasion techniques and development of threat hunting scenarios for low-severity threats.

## 1. Introduction

This plan tests whether a Windows lab and its SIEM can observe a short sequence of attacker-like behavior: use of a local account, an autostart entry, and transfer of a synthetic file to a controlled receiver. It is a proposed exercise, not a record of completed testing. The sequence is mapped to MITRE ATT&CK so that each action has a defined objective, expected telemetry, and review criterion.

## 2. Scenario and Scope

**Scenario:** An operator starts with the credentials of a precreated, low-privilege local test account on one Windows workstation. After signing in, the operator configures a harmless test program to start at the next logon. The operator then sends a small synthetic file over HTTP to an isolated lab receiver. No real user data, production host, public destination, or credential collection is in scope.

**Preconditions:** One approved Windows VM, one isolated HTTP receiver, a dedicated test account, a uniquely named test file, and a documented exercise window. Collect Windows Security, Sysmon (if installed), and receiver or proxy logs into the SIEM. Confirm clock synchronization and log ingestion before beginning.

## 3. Selected ATT&CK Techniques

| Phase | ATT&CK technique | Emulated behavior | Evidence to collect |
|---|---|---|---|
| Initial access | **T1078.003 — Valid Accounts: Local Accounts** | Sign in to the lab workstation using the dedicated local test account. | Windows Security Event ID 4624; account, host, logon type, source, and timestamp. |
| Persistence | **T1547.001 — Registry Run Keys / Startup Folder** | Create a current-user autostart entry for a benign marker program, then sign out and back in. | Registry change (Sysmon Event ID 13 if configured); process creation (Event ID 4688 or Sysmon Event ID 1). |
| Exfiltration | **T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol** | Send only the synthetic file by HTTP to the separate lab receiver. | HTTP request, destination, byte count, receiver receipt, file hash. |

### ATT&CK reference screenshots

**Figure 1. T1078.003 — Valid Accounts: Local Accounts**  
![MITRE ATT&CK screenshot for T1078.003](images/figure_01.png)

**Figure 2. T1547.001 — Registry Run Keys / Startup Folder**  
![MITRE ATT&CK screenshot for T1547.001](images/figure_02.png)

**Figure 3. T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol**  
![MITRE ATT&CK screenshot for T1048.003](images/figure_03.png)

## 4. Test Procedure

### 4.1 Preparation

The exercise will take place on one approved Windows VM using a precreated, low-privilege local test account and an isolated lab receiver. The exercise worksheet will document the VM name, test account, receiver address, start time, and synthetic file’s name, size, and SHA-256 hash. The receiver will accept connections only from the lab network. Preparation will include verification that the intended telemetry reaches the SIEM and collection of a baseline covering account logons, autostart entries, and HTTP traffic.

### 4.2 Initial Access

The operator will sign in to the approved VM using the supplied local test account. This stage will emulate the use of previously obtained credentials; credential theft or collection will remain outside the exercise scope. The exact sign-in time and session details will be documented. A corresponding Windows Security Event ID 4624 will provide evidence of the logon, with its availability in the SIEM assessed through the account and host fields.

### 4.3 Persistence

The operator will establish harmless persistence by adding one clearly labeled entry to the test account’s Run key or Startup folder. This entry will launch a marker program that writes only a timestamped “emulation test” message to a lab file. A single sign-out and subsequent sign-in will trigger the program. Evidence will cover the autostart entry, its associated registry or file modification, and the resulting process creation. The entry’s name and path will be documented to support its removal after the exercise.

### 4.4 Data Exfiltration Simulation

The operator will create a small synthetic text file containing only the exercise identifier and dummy values, then transfer it over plain HTTP to the isolated lab receiver. The transfer will use a channel separate from any command-and-control channel. Comparison of the original and received files’ SHA-256 hashes and byte counts will establish whether the transfer completed correctly. HTTP request records and receiver logs will provide supporting evidence. This phase will emulate observable data transfer behavior using synthetic content, with no real user data or public destination involved.

## 5. Evidence and Evaluation

Each phase will produce an execution timestamp and a screenshot or exported event identifying the host, account, action, and relevant event fields. The initial access, persistence, and simulated exfiltration stages will be correlated through the shared test account, workstation, and exercise time window.

Evaluation will assess both whether the planned actions occurred and whether their evidence was available in the SIEM. The expected evidence will include the Security Event ID 4624 logon, the autostart modification and subsequent logon-triggered process, and the HTTP transfer to the isolated receiver. Success will depend on evidence matching these specific actions rather than a broad increase in event counts. Missing or incomplete telemetry will be documented as a visibility gap, separately from any failure to execute an emulation action.

| Phase | Pass condition | Record if absent |
|---|---|---|
| Initial access | Test logon is visible locally and in the SIEM. | Check audit policy, account name, host filter, and collection delay. |
| Persistence | Autostart entry and marker execution after sign-in are both evidenced. | Check Sysmon/registry coverage and process command-line collection. |
| Exfiltration | Receiver obtains matching synthetic file; network logs identify transfer. | Check receiver access, proxy/flow coverage, byte fields, and time range. |

## 6. Limitations and Cleanup

A dedicated account sign-in is a simplified stand-in for misuse of compromised credentials, and an isolated HTTP transfer cannot fully reproduce real data theft. Sysmon events depend on its installed configuration; Security Event IDs 4688 and 4624 depend on audit settings and ingestion. A missing SIEM event may reflect collection or query gaps rather than absence of the activity. This three-stage plan omits discovery, collection, staging, and command and control.

After evidence is saved, remove the autostart entry and marker file, delete the synthetic file from the VM and receiver, disable or reset the test account, and verify that no test entry remains. Record actual timestamps, event IDs, SIEM queries, observed counts, gaps, and cleanup confirmation in the final exercise report.

## 7. Conclusion and Next Steps

The plan gives a small, repeatable chain for testing whether the SIEM can connect a local account logon, a persistence change, and an outbound file transfer. Run it only in the defined lab, compare actual evidence with the pass conditions, and use any visibility gaps to prioritize audit configuration, forwarding, and correlation improvements. No detection or successful exfiltration is claimed until the exercise is performed and the records are reviewed.

## References

- MITRE Center for Threat-Informed Defense. [Adversary Emulation Library](https://ctid.mitre.org/resources/adversary-emulation-library/).
- MITRE ATT&CK. [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/).
- MITRE ATT&CK. [Registry Run Keys / Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/).
- MITRE ATT&CK. [Exfiltration Over Unencrypted Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/).
- MITRE ATT&CK. Detection strategies DET0407, DET0365, and DET0149. [Detection Strategies](https://attack.mitre.org/detectionstrategies/).

---

**Status:** This is a proposed plan, not a completed test. Add real screenshots, event exports, actual query results, and cleanup confirmation after the approved lab exercise.
