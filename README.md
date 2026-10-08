# **Analysis of SIEM Priority Evasion Techniques and Development of Threat Hunting Scenarios for Low-Severity Threats**

## **Week 4 - The Cyber Kill Chain and MITRE ATT&CK Analysis**

### **1. Introduction**

The project focuses on the analysis of SIEM priority evasion techniques and the development of threat hunting scenarios for low-severity threats. During Week 4, we analyze the **SolarWinds Compromise** and connect documented attacker activities with the **Cyber Kill Chain** and **MITRE ATT&CK** frameworks.

This attack is relevant to our project because some malicious activities can look similar to legitimate software updates, administrative actions, HTTP traffic, or DNS activity when viewed separately. Understanding how these activities fit into a larger attack can help analysts investigate events that initially appear to have low severity.

The main objectives of this week are to:

- study the seven stages of the Cyber Kill Chain;
- analyze the SolarWinds Compromise;
- map documented attacker activities to relevant MITRE ATT&CK techniques;
- explain how this analysis supports the investigation of low-severity SIEM alerts.

### **2. Cyber Kill Chain**

The **Cyber Kill Chain** is a model developed by Lockheed Martin for describing the main stages of a cyber intrusion. It contains seven stages:

| Stage | Description |
| --- | --- |
| **Reconnaissance** | Collecting information that can help prepare an attack. |
| **Weaponization** | Preparing malware or other capabilities for use in an intrusion. |
| **Delivery** | Transmitting the malicious payload to the target. |
| **Exploitation** | Triggering the payload or exploiting a weakness to gain execution. |
| **Installation** | Installing malware or establishing a mechanism to maintain access. |
| **Command and Control** | Establishing communication between the compromised system and attacker-controlled infrastructure. |
| **Actions on Objectives** | Carrying out the attacker's goals, such as collecting or exfiltrating information. |

**The seven stages of the Cyber Kill Chain:**

![Figure 1 - The seven stages of the Cyber Kill Chain](images/image3.png)

The Cyber Kill Chain describes the sequence of an intrusion. MITRE ATT&CK provides more detailed information about specific adversary tactics and techniques. The two frameworks do not have a strict one-to-one mapping.

### **3. SolarWinds Compromise**

The **SolarWinds Compromise** was a supply-chain cyber operation associated with **APT29**. Attackers compromised the SolarWinds Orion software build process and inserted malicious code into the software. The malicious code was then distributed to customers through a normal software update.

The campaign was discovered in **December 2020**. MITRE ATT&CK documents multiple techniques used during the campaign, including supply-chain compromise, PowerShell activity, valid accounts, remote services, command and control, data collection, and exfiltration.

**MITRE ATT&CK SolarWinds Compromise campaign page:**

![Figure 2 - MITRE ATT&CK SolarWinds Compromise campaign page](images/image2.png)

Source: [MITRE ATT&CK - SolarWinds Compromise (C0024)](https://attack.mitre.org/campaigns/C0024/).

### **4. Cyber Kill Chain Analysis**

The following table connects documented SolarWinds activities with the seven Cyber Kill Chain stages and relevant ATT&CK techniques.

| Stage | SolarWinds Activity | Related MITRE ATT&CK Techniques |
| --- | --- | --- |
| **Reconnaissance** | Obtaining information and credentials that could help access victim environments. | **T1589.001** - Gather Victim Identity Information: Credentials |
| **Weaponization** | Using custom malware, including SUNBURST, SUNSPOT, Raindrop, and TEARDROP. | **T1587.001** - Develop Capabilities: Malware |
| **Delivery** | Distributing malicious code through a trojanized SolarWinds Orion software update. | **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain |
| **Exploitation** | Using the compromised update to gain initial access to some victim environments. | **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain |
| **Installation** | Using scheduled tasks and WMI event subscriptions to execute malware or maintain access. | **T1053.005** - Scheduled Task/Job: Scheduled Task; **T1546.003** - Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| **Command and Control** | Using HTTP and dynamic DNS resolution for communication with attacker-controlled infrastructure. | **T1071.001** - Application Layer Protocol: Web Protocols; **T1568** - Dynamic Resolution |
| **Actions on Objectives** | Collecting internal information, emails, and files, followed by data exfiltration. | **T1213** - Data from Information Repositories; **T1114.002** - Remote Email Collection; **T1005** - Data from Local System; **T1048.002** - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |

**Mapping note:** This table is our analytical mapping of documented SolarWinds activities to the Cyber Kill Chain. It is not an official MITRE mapping of the campaign to the seven Kill Chain stages. One ATT&CK technique can be relevant to more than one stage. In particular, T1195.002 describes the supply-chain initial-access mechanism; its inclusion under Exploitation does not establish a separate software vulnerability exploit.

### **5. Reconnaissance**

During reconnaissance, an attacker collects information that can help with later stages of an operation. For the SolarWinds Compromise, MITRE documents credential-related information gathering under **T1589.001 - Gather Victim Identity Information: Credentials**.

For our project, this highlights the importance of examining account and credential-related activity in context. Some activity may resemble legitimate work, while its connection to other suspicious events can make it relevant to an investigation.

**MITRE ATT&CK technique T1589.001:**

![Figure 3 - Gather Victim Identity Information: Credentials](images/image6.png)

Source: [MITRE ATT&CK - T1589.001](https://attack.mitre.org/techniques/T1589/001/).

### **6. Weaponization**

MITRE maps malware development activity associated with SolarWinds to **T1587.001 - Develop Capabilities: Malware**. The campaign used malware including **SUNBURST**, **SUNSPOT**, **Raindrop**, and **TEARDROP**.

This stage helps explain how the attackers prepared capabilities used throughout the operation. These capabilities supported the compromised software build process and subsequent activity in victim environments.

**MITRE ATT&CK technique T1587.001:**

![Figure 4 - Develop Capabilities: Malware](images/image5.png)

Source: [MITRE ATT&CK - T1587.001](https://attack.mitre.org/techniques/T1587/001/).

### **7. Delivery**

The main delivery mechanism was a **supply-chain compromise**. MITRE documents that APT29 gained initial network access to some victims through a trojanized update of SolarWinds Orion software. The relevant technique is **T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain**.

A software update can appear to be a normal operational event. This makes the SolarWinds case relevant to our project: the apparent legitimacy of an individual event is not enough to determine whether related activity is safe.

**MITRE ATT&CK Supply Chain Compromise technique page:**

![Figure 5 - Supply Chain Compromise](images/image8.png)

Source: [MITRE ATT&CK - T1195.002](https://attack.mitre.org/techniques/T1195/002/).

### **8. Exploitation**

The trojanized Orion update provided a way for the attackers to gain initial network access. **T1195.002** is therefore relevant to this part of our analytical Kill Chain mapping as well as to Delivery.

This overlap illustrates why Kill Chain stages and ATT&CK techniques should not be treated as identical categories. The mapping describes the role of the compromised update in the intrusion without claiming that this initial-access path required a separate vulnerability exploit.

### **9. Installation**

MITRE documents **T1053.005 - Scheduled Task/Job: Scheduled Task** and **T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription** in the SolarWinds campaign.

For T1546.003, MITRE states that APT29 used a WMI event filter to invoke a command-line event consumer at system boot and launch a backdoor with `rundll32.exe`. These mechanisms are relevant to execution and maintaining access.

Scheduled tasks and WMI also have legitimate administrative uses. Investigating them requires context about what was created or changed, which account performed the action, and what program was executed.

**MITRE ATT&CK Event Triggered Execution technique page:**

![Figure 6 - Event Triggered Execution and WMI event subscriptions](images/image1.png)

Sources: [MITRE ATT&CK - T1053.005](https://attack.mitre.org/techniques/T1053/005/) and [MITRE ATT&CK - T1546.003](https://attack.mitre.org/techniques/T1546/003/).

### **10. Command and Control**

MITRE documents the use of HTTP for command and control and data exfiltration during the campaign. The attackers also used dynamic DNS resolution for C2. Relevant techniques are **T1071.001 - Application Layer Protocol: Web Protocols** and **T1568 - Dynamic Resolution**.

HTTP and DNS traffic are common in normal network operations. For threat hunting, these events become more useful when analysts consider their destinations, the processes generating the traffic, and other related activity.

**MITRE ATT&CK technique T1568:**

![Figure 7 - Dynamic Resolution](images/image7.png)

Sources: [MITRE ATT&CK - T1071.001](https://attack.mitre.org/techniques/T1071/001/) and [MITRE ATT&CK - T1568](https://attack.mitre.org/techniques/T1568/).

### **11. Actions on Objectives**

MITRE documents access to internal knowledge repositories, email collection, file extraction, data staging, and exfiltration. Examples include:

| Technique | Activity |
| --- | --- |
| **T1213 - Data from Information Repositories** | Accessing internal repositories containing organizational information. |
| **T1114.002 - Remote Email Collection** | Collecting emails from targeted accounts. |
| **T1005 - Data from Local System** | Extracting files from compromised systems. |
| **T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol** | Exfiltrating collected data using an encrypted protocol outside the existing C2 channel. |

These activities show how earlier stages of the intrusion supported the attackers' information collection objectives.

**MITRE ATT&CK technique T1005:**

![Figure 8 - Data from Local System](images/image4.png)

Source: [MITRE ATT&CK - T1005](https://attack.mitre.org/techniques/T1005/).

### **12. Connection to Our SIEM Project**

The SolarWinds attack is relevant to our project because some malicious activities can look normal when viewed separately. Examples include:

- software updates;
- HTTP traffic;
- DNS traffic;
- PowerShell activity;
- legitimate or compromised accounts;
- scheduled tasks.

A SIEM can record these activities as security events, but additional context may be needed to determine whether they are suspicious. The investigation workflow used in our project is:

**SIEM event → IOC → OSINT → data processing → threat analysis**

| Project Stage | Tools or Frameworks | Contribution to the Investigation |
| --- | --- | --- |
| **Week 2 - Data Collection** | VirusTotal, Shodan, and Maltego | Collecting additional information about suspicious indicators and their relationships. |
| **Week 3 - Data Processing** | MISP | Organizing, filtering, and normalizing collected IOCs. |
| **Week 4 - Threat Analysis** | Cyber Kill Chain and MITRE ATT&CK | Understanding how individual activities can fit into a larger attack. |

An event that appears low-severity by itself may become more important when combined with related events and threat intelligence. This analysis supports that reasoning; it does not measure SIEM detection performance or demonstrate tested detection rules.

### **13. Week 4 Results and Conclusion**

During Week 4, we:

- studied the seven stages of the Cyber Kill Chain;
- analyzed the SolarWinds Compromise using publicly documented campaign information;
- connected attacker activities with relevant MITRE ATT&CK techniques;
- created an analytical mapping between the campaign and Kill Chain stages;
- explained the limitations of mapping two different frameworks;
- connected the analysis with our investigation of low-severity SIEM events.

The SolarWinds Compromise demonstrates how an attack can involve multiple stages and different attacker techniques. The Cyber Kill Chain helps describe the sequence of an intrusion, while MITRE ATT&CK provides detailed information about adversary behavior.

For our SIEM project, the main finding is the importance of combining individual events with context and threat intelligence. Examining related activity together can help analysts recognize suspicious patterns that may be missed when each event is reviewed separately.

---

## **References**

1. [Lockheed Martin - Gaining the Advantage: Applying Cyber Kill Chain Methodology](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf)
2. [MITRE ATT&CK - SolarWinds Compromise (C0024)](https://attack.mitre.org/campaigns/C0024/)
3. [MITRE ATT&CK - T1589.001: Gather Victim Identity Information: Credentials](https://attack.mitre.org/techniques/T1589/001/)
4. [MITRE ATT&CK - T1587.001: Develop Capabilities: Malware](https://attack.mitre.org/techniques/T1587/001/)
5. [MITRE ATT&CK - T1195.002: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
6. [MITRE ATT&CK - T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
7. [MITRE ATT&CK - T1546.003: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
8. [MITRE ATT&CK - T1071.001: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
9. [MITRE ATT&CK - T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
10. [MITRE ATT&CK - T1213: Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
11. [MITRE ATT&CK - T1114.002: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
12. [MITRE ATT&CK - T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/)
13. [MITRE ATT&CK - T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

---

## **Use of AI Tools**

ChatGPT was used to convert the supplied project report into GitHub Markdown and organize its headings, tables, captions, and links. The campaign analysis and screenshots were taken from the supplied report.
