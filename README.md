# Azure Honeypot SOC Lab
**Real Internet Attack Data | Microsoft Sentinel | Azure**

---

## What This Lab Is

I exposed a Windows Server VM to the open internet overnight and used Microsoft Sentinel to collect, detect, and investigate real attacks from actual threat actors around the world.

This is not simulated data. Every failed login, every brute force attempt, every incident in this lab came from real attackers on the internet hitting a live machine.

| Detail | Value |
|---|---|
| Platform | Microsoft Azure (Free Trial) |
| VM | CORP-NET-Central (Windows Server 2022) |
| Public IP | 98.70.65.251 |
| Region | Central India |
| Workspace | soc-lab-logs |
| Exposure Window | ~14 hours overnight |
| Real Failed Logins Collected | 3,404+ (Event ID 4625) |
| Real Incidents Generated | 43 High severity |
| Custom Analytics Rules Built | 4 |
| Custom Workbooks Built | 2 |


---

## Architecture

```
Internet (Real Attackers)
        |
        v
Azure VM - CORP-NET-Central (Windows Server 2022)
        |  Public IP: 98.70.65.251
        |  NSG: DANGER_AllowAnyCustomAnyInbound (all ports open)
        |  Windows Firewall: Disabled
        |
        v
Azure Monitor Agent
        |
        v
Log Analytics Workspace (soc-lab-logs)
        |
        v
Microsoft Sentinel
        |
   +----+----+
   |         |
Analytics  Workbooks
  Rules    (Attack Map)
   |
   v
Incidents + Investigation
```

---

## Step 1 - Create and Configure the Honeypot VM

Created a Windows Server 2022 VM on Azure with a public IP address. Then intentionally removed all firewall protection to make it visible and reachable from anywhere on the internet.

**Network Security Group rule created:**

```
Rule name:  DANGER_AllowAnyCustomAnyInbound
Priority:   100
Source:     Any
Destination: Any
Protocol:   Any
Action:     Allow
```

This rule sits at priority 100 which means it overrides all other rules. Every port on the VM became open to the entire internet.

Also disabled the Windows Firewall inside the VM itself for full exposure.

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123255" src="https://github.com/user-attachments/assets/bf68ab76-6017-4e16-93b8-8aff5ceb7a05" />

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123133" src="https://github.com/user-attachments/assets/b59e48e9-7048-4f78-a1d1-98638144d222" />

---

## Step 2 - Forward Logs to Microsoft Sentinel

Installed the Azure Monitor Agent on the VM. This agent reads Windows Security Event logs in real time and forwards them to a Log Analytics Workspace. Microsoft Sentinel sits on top of that workspace and processes every event as it arrives.

Connected a new Sentinel workspace (soc-lab-logs) and configured it to receive Windows Security Events including Event ID 4625 (failed logon) and Event ID 4624 (successful logon).

---

## Step 3 - Create the GeoIP Watchlist

Downloaded a GeoIP CSV file that maps IP address ranges to cities, countries, latitude, and longitude. Uploaded this as a Sentinel Watchlist named "geoip".

This watchlist is what allows KQL queries to convert raw attacker IP addresses into geographic locations for the attack map.

---

## Step 4 - Build Custom Analytics Rules

Created 4 analytics rules from scratch. All rules run every 5 minutes against the last 10 minutes of data.

**Rule 1 - RDP Brute Force Detection (High severity)**
```kql
SecurityEvent
| where EventID == 4625
| where LogonType in (3, 10)
| summarize FailedAttempts = count() by IpAddress, Account
| where FailedAttempts >= 5
```
MITRE: T1110 - Credential Access (Brute Force)

**Rule 2 - Multiple Accounts Targeted (High severity)**
```kql
SecurityEvent
| where EventID == 4625
| summarize AccountsTargeted = dcount(Account) by IpAddress
| where AccountsTargeted > 1
```
MITRE: T1110 - Credential Access

**Rule 3 - Successful RDP Login (Medium severity)**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Account, IpAddress, Computer
```
MITRE: T1078 - Valid Accounts (Initial Access)

**Rule 4 - Guest Account Activity (Medium severity)**
```kql
SecurityEvent
| where EventID == 4625
| where Account contains "Guest"
| project TimeGenerated, Account, IpAddress, Computer
```
MITRE: T1078 - Persistence

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123654" src="https://github.com/user-attachments/assets/9b3ed795-86db-4526-897f-a1de77ee9cee" />

---

## Step 5 - Results After One Night

Left the VM running overnight. Within minutes of going live, automated scanners and bots from around the world found the open RDP port and started attacking.

**Attack volume by morning:**

| City | Country | Failed Attempts |
|---|---|---|
| Comodoro Rivadavia | Argentina | 600 |
| Hong Kong | China | 510 |
| Obando | Philippines | 509 |
| Virar | India | 508 |
| Yokkaichi | Japan | 508 |
| Cagayan de Oro | Philippines | 480 |
| Shijiazhuang | China | 233 |
| Hwaseong-si | South Korea | 25 |
| Other | Various | 19 |
| Guayaquil | Ecuador | 13 |

**Total:** 3,404 real failed RDP login attempts collected in 14 hours.

**Incidents generated:** 43 High severity incidents, all triggered by my custom analytics rules firing on real attack traffic.

---

## Step 6 - KQL Queries Used for Investigation

**Query to find failed logins with geolocation:**
```kql
let GeoIPDB_Full = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "186.24.16.52"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_Full, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress,
    cityname, countryname, latitude, longitude
```

**Query to find all failed logins (basic brute force view):**
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, AttackerIp = IpAddress, Activity
```

<img width="1920" height="1080" alt="Screenshot 2026-04-15 120112" src="https://github.com/user-attachments/assets/2a35c482-de22-4f9e-a4c3-5e0d929c7fb4" />

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123641" src="https://github.com/user-attachments/assets/3f328c37-c60f-49d4-8ef8-1cb81b33751a" />

---

## Step 7 - Attack Map Workbooks

Built 2 custom workbooks that visualize attack data on a world map:

- Windows VM Attack-map: plots every unique attacker IP as a bubble, sized by attack volume
- Windows Failed Login Attack-map: filtered view of failed login attempts only

The map uses the GeoIP watchlist joined to SecurityEvent data via KQL to convert IP addresses into coordinates.

<img width="1920" height="1080" alt="Screenshot 2026-04-15 120902" src="https://github.com/user-attachments/assets/d901a7ae-5e55-4498-8509-82492162225a" />

<img width="1920" height="1080" alt="Screenshot 2026-04-15 122123" src="https://github.com/user-attachments/assets/579fc1e8-87cd-49f4-b808-58afece843ce" />

---

## Step 8 - Incident Investigation

Investigated real incidents generated by my analytics rules.

**Incident #44 - RDP Brute Force Detected from 80.66.83.43**

- Severity: High
- Status: Active
- Owner: rohith tony
- Entities: account \Test, IP 80.66.83.43
- Evidence: 2 events, 2 alerts
- MITRE: Credential Access (T1110)
- Analytics rule: RDP Brute Force Detection

Opened the investigation graph to map entity relationships. The graph showed the attacker IP connected to the targeted account and the two triggered alerts, giving a clear visual picture of the attack chain.

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123915" src="https://github.com/user-attachments/assets/fff947fe-e7a6-4e3c-955f-c02faef64b60" />

<img width="1920" height="1080" alt="Screenshot 2026-04-15 123937" src="https://github.com/user-attachments/assets/ec3482c8-3e64-4754-962d-4038988a2501" />

<img width="1920" height="1080" alt="Screenshot 2026-04-15 124137" src="https://github.com/user-attachments/assets/5eae4ece-396f-480a-ae7d-d1566202533e" />

---

## Key Learnings

The internet is hostile by default. Within minutes of a Windows machine going online with RDP open, automated scanners find it and begin attacking. No notice, no warning, no invitation needed.

Building detection rules before the VM went live meant Sentinel was watching from the first event. Every rule fired on real data within hours. The incidents that appeared were not sample data or simulations. They were real credential access attempts from real IPs in real cities.

The most interesting finding was that most attacks came from a handful of cities hitting the same accounts over and over. This is characteristic of botnet-driven scanning rather than targeted human attacks. The volume, timing, and account targeting patterns all match automated credential stuffing tools.

**Full SOC pipeline executed end to end:**
```
VM deployed with intentional vulnerabilities
   -> Real attackers hit open RDP port
      -> Azure Monitor Agent forwards logs
         -> Log Analytics stores events
            -> Analytics Rules detect patterns
               -> Sentinel generates High severity incidents
                  -> Investigation graph maps attack chain
                     -> VM decommissioned after data collection
```

---

## Tools Used

• Microsoft Azure - VM, NSG, Log Analytics, Azure Monitor Agent  
• Microsoft Sentinel - SIEM, Analytics Rules, Workbooks, Incidents  
• KQL (Kusto Query Language) - Detection logic and investigation queries  
• MITRE ATT&CK - T1110 Brute Force, T1078 Valid Accounts  
• GeoIP Watchlist - IP to geographic location mapping  

---
