# Lab 3 — Splunk SIEM & Log Analysis on Azure

---

## Overview

This lab builds a functional SIEM (Security Information and Event Management) pipeline from scratch using free tooling on Azure. By the end, you will have:

- A **Splunk Enterprise** instance running on an Azure Ubuntu VM, receiving and indexing live Windows Event Logs
- A **Universal Forwarder** installed on a Windows Server VM (from [Lab 1](https://github.com/aitarurachel/active-directory-azure-lab)), shipping logs to Splunk automatically over an encrypted channel
- Working **SPL (Splunk Processing Language)** searches that detect failed logins, account lockouts, and after-hours access
- A **security dashboard** showing login activity, failure trends, and top offending accounts
- An **automated alert** that fires when brute-force indicators are detected. No human polling required

The same architectural pattern: forwarders at endpoints, a centralised indexer, analyst access via a web UI, is what enterprise Splunk deployments use at scale.

---

## The Problem This Lab Solves

A medium-sized organisation generates millions of log events every day: Windows Event Logs from workstations, authentication logs from Active Directory, firewall logs, web server access logs, and cloud resource logs. Without a SIEM, those logs sit in separate systems, and no one can search across them, correlate events, or identify patterns that indicate an attack.

**Without a SIEM:** An analyst investigating a potential breach must log into each system individually, manually grep through text files, and mentally correlate timestamps across disparate sources. A brute-force attack spread across 50 workstations is practically invisible.

**With a SIEM:** One analyst can run a single SPL query across every endpoint simultaneously, identify the attacking source IP, see which accounts were targeted, and determine whether any login succeeded in under two minutes.

This lab teaches that core skill set: getting data in, searching it effectively, and turning searches into automated detection.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Microsoft Azure — Free Account                                 │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Azure Virtual Network — 10.0.0.0/16                    │    │
│  │                                                         │    │
│  │  ┌─────────────────────┐       ┌─────────────────────┐  │    │
│  │  │  DC01 — Windows     │       │  Splunk Enterprise  │  │    │
│  │  │  Server VM (Lab 1)  │──────▶│  Ubuntu 22.04 LTS   │  │    │
│  │  │                     │ :9997 │  Standard_B2s       │  │    │
│  │  │  Universal Forwarder│  TLS  │                     │  │    │
│  │  │  inputs.conf        │       │  Index: windows_logs│  │    │
│  │  │  EventLog: Security │       │  Web UI: port 8000  │  │    │
│  │  │  EventLog: System   │       │  SPL · Dashboards   │  │    │
│  │  │  EventLog: Applic.  │       │  Alerts             │  │    │
│  │  └─────────────────────┘       └──────────┬──────────┘  │    │
│  │                                           │ HTTPS       │    │
│  │  ┌────────────────────────────────────────┼──────────┐  │    │
│  │  │  NSG Rules                             │          │  │    │
│  │  │  Port 22  → your IP only               │          │  │    │
│  │  │  Port 8000→ your IP only               │          │  │    │
│  │  │  Port 9997→ VNet only (10.0.0.0/16)    │          │  │    │
│  │  └────────────────────────────────────────┼──────────┘  │    │
│  └───────────────────────────────────────────┼──────────-──┘    │
└──────────────────────────────────────────────┼─────-──────────-─┘
                                                │
                                    ┌───────────▼──────────┐
                                    │  SOC Analyst          │
                                    │  Browser · port 8000  │
                                    │  Search · Dashboards  │
                                    │  Alert investigation  │
                                    └──────────────────────┘
```

**Data flow summary:**
1. Windows Server VM generates Event Log entries (4624, 4625, 4740) from normal AD operations and simulated attack traffic
2. Universal Forwarder reads `inputs.conf`, compresses and encrypts log batches, and ships them to the Splunk indexer on port 9997
3. Splunk parses and indexes all events into the `windows_logs` index
4. The SOC analyst opens a browser, connects to port 8000, and runs SPL searches against the indexed data
5. Scheduled alert searches run every 15 minutes in the background and trigger when thresholds are crossed

---

## Tech Stack & Tools

| Component | Tool / Service | Why this choice |
|---|---|---|
| **SIEM platform** | Splunk Enterprise (free licence) | Industry-standard. Appears on more job descriptions than any other SIEM. 500 MB/day free licence is more than sufficient for a home lab. |
| **Log shipper** | Splunk Universal Forwarder | Purpose-built for this job. Lightweight, encrypted, handles Windows Event Logs natively without any custom scripting. |
| **SIEM host OS** | Ubuntu 22.04 LTS | Native Linux support for Splunk. Stable LTS release. `dpkg` installation is straightforward. |
| **Log source** | Windows Server 2022 VM (Lab 1) | Generates real Active Directory authentication events |
| **Cloud platform** | Microsoft Azure | Free-tier VMs are sufficient. Azure's internal VNet allows forwarder-to-indexer traffic without traversing the public internet. |
| **VM size (Splunk)** | Standard_B2s (2 vCPU, 4 GB RAM) | Splunk's minimum documented RAM requirement is 4 GB. B2s is the smallest Azure VM that meets it and falls within free-tier-eligible sizes. |
| **Query language** | SPL (Splunk Processing Language) | The native language of Splunk. Pipeline-style syntax maps directly to analyst workflows: find events, then shape results. |
| **Network security** | Azure NSG (Network Security Group) | Stateful firewall rules applied at the NIC level. Restricts port 9997 to internal VNet traffic and ports 22/8000 to a single trusted IP. |

---

## Step-by-Step Instructions

### Step 1: Download Splunk Enterprise

Splunk Enterprise is free for home lab use. After a 60-day full trial, it automatically converts to the permanent free licence (500 MB/day indexing limit, which is more than enough for this lab).

**Privacy note:** Splunk requires account registration to download. Use [temp-mail.org](https://temp-mail.org/en/) for a throwaway address. Fill the remaining fields with dummy information. None of it is verified.

1. Navigate to `splunk.com/en_us/download/splunk-enterprise.html`
2. Create a free Splunk account using a temporary email address
3. Select **Splunk Enterprise**, not Splunk Cloud, not Splunk SOAR
4. Choose the **Linux (.deb)** package (for the Ubuntu VM you will create next)
5. Copy the `wget` download command shown on the download page

   <img width="1223" height="507" alt="splunk download" src="https://github.com/user-attachments/assets/ac1bc15c-5481-475a-b29a-d5f87f61ece7" />
<br>

---

### Step 2: Deploy the Ubuntu VM in Azure

Splunk will run on a dedicated Ubuntu VM. This keeps it isolated from your Windows Server log source and mirrors a real enterprise deployment pattern.

| Setting | Value |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Size | Standard_B2s (2 vCPU, 4 GB RAM), minimum for Splunk |
| Disk | 30 GB minimum |
| Inbound ports | 22 (SSH) · 8000 (Web UI) · 9997 (Forwarder input) |

**NSG rules to configure:**

| Port | Source | Reason |
|---|---|---|
| 22 | Your public IP only | SSH access — do not open to 0.0.0.0/0 |
| 8000 | Your public IP only | Splunk web UI — analyst access |
| 9997 | VNet CIDR (e.g. 10.0.0.0/16) | Forwarder input, internal only, never public internet |

---

### Step 3: Install Splunk on the Ubuntu VM

SSH into your new Ubuntu VM, then run the following commands:

**macOS / Linux:**
```bash
ssh yourusername@YOUR_VM_PUBLIC_IP
```

**Windows (PuTTY):** Open PuTTY → enter the VM's public IP → port 22 → SSH → Open → accept the host key → enter credentials.

**Note:** When typing your password in a Linux terminal, nothing appears on screen — no dots, no asterisks. This is normal. Type your password and press Enter.

Once connected, install Splunk:

```bash
# Download Splunk Enterprise (current version as of April 2026)
wget -O splunk-10.2.2-linux-amd64.deb \
  "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# NOTE: Splunk updates the download URL with every new release.
# If wget returns a 404, log into splunk.com → Free Trials & Downloads → Linux .deb
# and copy the updated wget command from that page.

# Install the package
sudo dpkg -i splunk-10.2.2-linux-amd64.deb

# Start Splunk and accept the licence
# You will be prompted to create an admin username and password
sudo /opt/splunk/bin/splunk start --accept-license

# Configure Splunk to start automatically on VM reboot
sudo /opt/splunk/bin/splunk enable boot-start
```

Open your browser and navigate to `http://YOUR_VM_PUBLIC_IP:8000` — the Splunk login screen confirms the installation succeeded.

<img width="919" height="674" alt="Splunk login" src="https://github.com/user-attachments/assets/997fdbe7-5805-4fc7-a455-f5652321443e" />
<br>

---

### Step 4: Configure Splunk to Receive Logs

Splunk needs to be told which port to listen on before the Universal Forwarder can send data.

**4a — Enable receiving on port 9997:**

1. Log into the Splunk web UI at `http://YOUR_VM_PUBLIC_IP:8000`
2. Click **Settings** → **Forwarding and Receiving**
3. Click **Configure Receiving** → **New Receiving Port** → enter `9997` → **Save**

**4b — Create the `windows_logs` index:**

1. Click **Settings** → **Indexes**
2. Click **Create New Index**
3. Name: `windows_logs` → **Save**

---

### Step 5: Install the Universal Forwarder on Windows Server

> **Run these steps on your Windows Server VM (DC01) — not on the Ubuntu/Splunk VM.**

1. On DC01, open a browser and navigate to `splunk.com/en_us/download/universal-forwarder.html`
2. Download the **Windows 64-bit** installer
3. Run the installer:
   - When prompted for **Deployment Server**: enter your Splunk VM's **private** IP and port `8089`
   - When prompted for **Receiving Indexer**: enter your Splunk VM's **private** IP and port `9997`
   - Complete installation with all other defaults

**Use the private IP (e.g. 10.0.x.x), not the public IP.** Forwarder traffic stays inside the Azure VNet. This is faster, more secure, and required by the NSG rules configured in Step 2.

---

### Step 6: Configure `inputs.conf`

The `inputs.conf` file tells the Universal Forwarder exactly which log channels to collect. Create this file on your **Windows Server VM**.

**File location (must be exact):**
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

Open Notepad **as Administrator**, then save the file to the path above. If the `local` folder does not exist, create it manually in Windows Explorer.

```ini
[WinEventLog://Security]
# Security log: all authentication events — logins, failures, lockouts
disabled = 0
# disabled=0 means enabled; disabled=1 would turn this source off
start_from = oldest
# Collect historical events, not just new events going forward
current_only = 0
evt_resolve_ad_obj = 1
# Resolve AD object names so usernames appear instead of SIDs

[WinEventLog://System]
# System log: OS-level events — service starts/stops, driver failures
disabled = 0

[WinEventLog://Application]
# Application log: events from installed applications
disabled = 0
```

After saving, restart the forwarder to apply the new configuration. Run this in **PowerShell as Administrator**:

```powershell
Restart-Service SplunkForwarder
```

---

### Step 7: Essential SPL Searches

All searches are entered in the search bar of the **Search & Reporting** app. Adjust the time picker on the right for the window you want to analyse.

---

**Confirm data is flowing:**
```spl
index=windows_logs | head 100
```
Returns the 100 most recent events. If this returns nothing, confirm the `SplunkForwarder` service is running on DC01 (`Get-Service SplunkForwarder` in PowerShell).

<img width="1452" height="797" alt="100 most recent events" src="https://github.com/user-attachments/assets/97ae9952-f8c8-4d82-bd04-e55e40ef86c9" />
<br>

---

**Find failed login attempts (EventCode 4625):**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```
Groups all failed logon events by username and source machine, sorted by volume. Five or more failures for one account in a short window is a potential brute-force indicator.

---

**Find successful logins (EventCode 4624):**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```
<img width="1456" height="432" alt="successful login" src="https://github.com/user-attachments/assets/9aa31dc6-009b-420b-abde-41c27feb4d5d" />
<br>

---

**Find account lockout events (EventCode 4740):**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```
Multiple lockouts for the same account originating from the same machine is a strong brute-force signal.

---

**Top 10 failed login usernames — last 24 hours:**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```
Usernames that do not exist in Active Directory indicate an account enumeration attack. Accounts with 20+ failures warrant immediate investigation.

---

**Detect after-hours logins (outside 08:00–19:00):**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```
<img width="1452" height="796" alt="after hours" src="https://github.com/user-attachments/assets/ab842c96-91f2-4190-9c9f-1c72a4a66e2a" />
<br>

Service account logins (Type 5) after hours are expected. Interactive or RDP logins (Type 2 or 10) from regular user accounts after hours warrant review.

---

### Step 8: Build a Security Dashboard

1. In Splunk, click **Dashboards** → **Create New Dashboard**
2. Name it `Windows Security Overview` → **Create Dashboard**
3. Add the following panels using **Add Panel → New Search**:

| Panel name | Search | Visualisation |
|---|---|---|
| Failed Logins — Last 24h | EventCode=4625 with `stats count by Account_Name` | Bar chart |
| Account Lockouts — Last 7d | EventCode=4740 with `table` output | Events list |
| Login Activity Over Time | EventCode=4624 with `timechart count` | Line chart |
| Top Source IPs — After Hours | After-hours search with `stats count by Workstation_Name` | Column chart |

<img width="1135" height="283" alt="login overtime chart" src="https://github.com/user-attachments/assets/a44a4199-502d-49e6-be7f-9fdf0841f1c0" />
<br>

---

### Step 9: Create an Automated Alert

Alerts replace manual dashboard monitoring. Splunk runs a search on a schedule and notifies you when the condition is met — this is the foundation of automated SOC detection.

First, validate the search works manually:
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Then save it as an alert:

1. Click **Save As → Alert**
2. **Name:** `Potential Brute Force — High Failure Count`
3. **Alert type:** Scheduled
4. **Run every:** 15 minutes
5. **Trigger condition:** Number of Results is greater than 0
6. **Trigger actions:** Add to Triggered Alerts
7. Click **Save**
   
<img width="1452" height="270" alt="alert" src="https://github.com/user-attachments/assets/cc87d34e-4977-4a90-a909-b3acc8034e98" />
<br>

**Threshold tuning note:** A threshold of 10 failures is a starting point. In a real environment you would observe baseline activity for 2–4 weeks and adjust to minimise false positives without missing genuine attacks. Alert fatigue — too many low-quality alerts — is one of the primary causes of SOC analyst burnout.

---

## Verification Checklist

| Check | How to verify | Expected result |
|---|---|---|
| Splunk is running | Browse to `http://YOUR_VM_IP:8000` | Login screen loads |
| Data is flowing | Run `index=windows_logs \| head 10` | Returns recent events |
| Security events present | Run EventCode=4625 search | Returns failed login events |
| Dashboard populated | Open Windows Security Overview | All panels show data |
| Alert is active | Settings → Searches, Reports, and Alerts | Alert listed as Enabled |
| NSG rules correct | Azure portal → VM → Networking | Ports 22/8000 scoped to your IP; 9997 scoped to VNet CIDR |

**Generating test data:** If the 4625 search returns nothing, intentionally type the wrong password on your Windows Server VM three or four times, then run the search again. The events typically appear in Splunk within 60 seconds.

---

## Architectural Decisions & Trade-offs

### Decision 1: Two separate VMs instead of Splunk and AD on a single machine

**What I did:** Splunk runs on a dedicated Ubuntu VM. The Windows Server (Lab 1) is the log source only.

**Why:** In production, you never co-locate your log collector with a monitored endpoint. If that machine is compromised, the attacker controls both the evidence and the investigative tool. Keeping them separate mirrors real-world architecture and also avoids the RAM contention between Splunk and Active Directory services.

**Trade-off:** You pay for two VMs instead of one. In this lab, the cost is $0 because both fall within Azure's free-tier budget unless it is retired. A single-VM setup is tempting on cost grounds; it is the wrong call on security grounds.


### Decision 2: Universal Forwarder over Syslog or WinRM

**What I did:** Installed Splunk's own Universal Forwarder agent on the Windows Server to ship logs.

**Why:** The Universal Forwarder is purpose-built for this job. It handles Windows Event Log formatting natively (no parsing required), compresses data before sending, encrypts the stream to Splunk, and has built-in buffering so logs are not lost if the network drops temporarily. Syslog is a common alternative but requires a Syslog-to-Splunk relay and loses some Windows event field fidelity in the conversion.

**Trade-off:** The Universal Forwarder is a proprietary agent. Every endpoint you want to monitor needs it installed. At scale, think 10,000 endpoints. Agent management becomes its own operational burden. This is why large enterprises typically pair Splunk with a deployment server (also Splunk) or an endpoint management tool like SCCM or Ansible. In this lab, one manual install is entirely reasonable.


### Decision 3: Single index (`windows_logs`) for all event sources

**What I did:** All three Windows Event Log channels (Security, System, Application) write to one index called `windows_logs`.

**Why:** Simplicity. For a single-source lab, one index is easier to manage, easier to search, and avoids the complexity of index-level access control policies.

**Trade-off:** In production, mixing Security, System, and Application logs into one index makes it harder to apply different retention policies per log type, assign different RBAC permissions per team, and control storage costs at a granular level. A production deployment would typically have separate indexes: `win_security`, `win_system`, `win_app` at minimum, with retention windows tuned to compliance requirements (security logs often need 12 months; application logs may only need 30 days).


---

## What I'd Do Differently in Production

This lab is intentionally scoped for learning. A production Splunk deployment for even a small organisation would address the following gaps:

**TLS on the web UI (port 8000)**

The lab runs the Splunk web UI over plain HTTP. In production, you would place Splunk behind a reverse proxy (nginx or HAProxy) with a valid TLS certificate, or configure Splunk's native SSL settings directly. Analyst credentials transmitted over plain HTTP are trivially interceptable on any network that is not fully trusted.

**Splunk deployment server for forwarder management**

Installing the Universal Forwarder manually on one machine is fine for a lab. At 50+ endpoints, you need a Splunk Deployment Server to push `inputs.conf`, `outputs.conf`, and app configurations centrally. At 500+ endpoints, you integrate forwarder deployment with your endpoint management platform (SCCM, Ansible, Chef, or Puppet).

**Index-level retention policies and tiered storage**

The lab uses a single index with default retention (unlimited, until disk fills). In production, you define retention windows per index aligned to compliance requirements, commonly 90 days hot/warm and 12 months cold for security logs. Azure Blob Storage (Splunk SmartStore) handles the cold tier at a fraction of the cost of VM disk.

**Role-based access control (RBAC)**

The lab uses a single admin account. Production Splunk maps to your identity provider (Azure AD / Entra ID via SAML) and enforces index-level read permissions. A Tier 1 analyst should not be able to modify alert configurations; a Tier 3 analyst should not see HR data that happens to flow through the SIEM.

**High availability and indexer clustering**

A single-indexer setup has no redundancy. If the VM goes down, you lose both the search capability and any events that arrive during the outage (the forwarder queues them locally, but queue limits exist). Production Splunk uses an indexer cluster (minimum 3 nodes) with a replication factor of 2, plus a search head cluster for HA on the query side.

**Broader data sources**

This lab ingests only Windows Event Logs. A production SIEM ingests firewall logs (Palo Alto, Fortinet), cloud audit logs (Azure Monitor, AWS CloudTrail), identity provider logs (Entra ID sign-in logs), EDR telemetry (Defender for Endpoint), email security logs, and DNS query logs at minimum. Correlation across these sources is where real threat detection lives.

---

## Key Takeaways

- **The SIEM is only as good as its data.** Splunk with one log source is better than nothing, but detection coverage is directly proportional to how many systems you can ingest from. Getting data in is the first and most important skill.
- **SPL is a force multiplier.** An analyst who can write SPL searches efficiently can investigate in minutes what would otherwise take hours of manual log review.
- **Threshold tuning is an ongoing operation, not a one-time task.** Alerts require continuous refinement based on observed behaviour. A static threshold set at deployment rarely stays correct.
- **Dashboards tell you the state; searches tell you the story.** Use dashboards for ongoing situational awareness; use ad-hoc SPL searches when you need to investigate a specific incident.
- **This architecture pattern is universal.** Microsoft Sentinel, AWS Security Hub, Elastic SIEM, and Chronicle all follow the same conceptual model: agents forward logs to a centralised platform where analysts search, correlate, and alert. The tool changes; the mental model does not.

---
