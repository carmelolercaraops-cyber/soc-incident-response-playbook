# 🛡️ SOC Incident Response Playbook — Practical Splunk Edition

**Autore:** Carmelo Lercara  
**Certificazioni:** CompTIA Security+, Splunk Search Expert (101/102/103)  
**Data:** Agosto 2026  
**Ecosistema:** Companion guide & framework operativo integrato con [mitre-mapper](https://github.com/carmelolercaraops-cyber/mitre-mapper)

> **Scopo:** Guida pratica e interattiva per investigare incidenti di sicurezza in qualità di SOC Analyst, ottimizzata per ridurre il Mean Time to Detect (MTTD) e Mean Time to Respond (MTTR).

---

## 🎯 Clicca sulle sezioni sottostanti per espandere i moduli del Playbook

<details>
<summary><b>🚨 1. Alert Triage Workflow (Triage rapido in 2 minuti)</b></summary>

<br>

### Step 1: Decision Matrix (Primi 120 secondi)
- [ ] **Falso Positivo:** Rientra nella baseline ordinaria del sistema?
- [ ] **Esistenza Asset:** L'host o l'utente indicato esiste ed è attivo?
- [ ] **Temporalità:** Il timestamp è recente o legato a un log pregresso?
- [ ] **Frequenza:** È un evento isolato o parte di un picco anomalo?

### Step 2: Severity Level
* 🔴 **CRITICO (Escalate NOW):** Data exfiltration confermata, malware attivo, tentativi di ransomware, lateral movement, account Admin compromesso.
* 🟠 **ALTO (Investigate in 30m):** Brute force (>10 fallimenti), esecuzione di processi anomali (powershell/cmd), modifiche d'integrità dei file.
* 🟡 **MEDIO (Investigate Today):** Superamento soglie di banda, crash applicativi, modifiche di configurazione.
* 🟢 **BASSO (Log Review):** Comportamento normale verificato, falso positivo noto.

</details>

<details>
<summary><b>🔍 2. Splunk Queries Essenziali (Libreria SPL)</b></summary>

<br>

#### 1. Timeline Builder (Ricostruzione primo evento)
```splunk
sourcetype=windows_security OR sourcetype=syslog OR sourcetype=firewall
(EventCode=4625 OR EventCode=4720 OR failed OR unauthorized)
| stats min(_time) as first_event, max(_time) as last_event by user, src_ip, dest_ip
| convert ctime(first_event) ctime(last_event)
```

#### 2. User Behavior Profile
```splunk
index=main user=TARGET_USER
| stats count by sourcetype, action, dest_ip, dest_port
| sort - count
```

#### 3. Brute Force Detection
```splunk
sourcetype=windows_security EventCode=4625
| stats count as failed_logins by src_ip, user
| where failed_logins > 5
| table src_ip, user, failed_logins
```

#### 4. Execution Hunt (Processi Parent-Child)
```splunk
sourcetype=WinEventLog:Security EventCode=4688
(CommandLine=*powershell* OR CommandLine=*cmd.exe* OR CommandLine=*svchost*)
(ParentImage=*explorer.exe OR ParentImage=*winlogon.exe)
| table _time, Computer, Image, CommandLine, ParentImage
```

#### 5. C2 Hunt (Traffico Outbound Anomalo)
```splunk
sourcetype=firewall action=allowed 
dest_ip!="10.0.0.0/8" dest_ip!="172.16.0.0/12" dest_ip!="192.168.0.0/16"
dest_port NOT IN (80,443,53,25,587,993,995,22)
| stats count, sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where count > 100 OR total_bytes > 1000000
```

#### 6. File Modifications (Data Exfil Check)
```splunk
sourcetype=windows_file_monitor (file_path=*\AppData\* OR file_path=*\Documents\*)
(action=modified OR action=created)
| stats count by user, file_path, action, _time
| convert ctime(_time)
```

#### 7. Timeline Reconstruction (Completo)
```splunk
(user=TARGET_USER OR src_ip=TARGET_IP OR dest_ip=TARGET_IP)
| timeline sourcetype, user, src_ip, dest_ip, action, EventCode, CommandLine
| convert ctime(_time) as timestamp
| table timestamp, sourcetype, user, action
| sort + _time
```

#### 8. IoC Hunting su scala di rete
```splunk
index=main (src_ip=MALICIOUS_IP OR dest_ip=MALICIOUS_IP OR user=COMPROMISED_USER OR file_hash=MALWARE_HASH)
| stats count by host, user, src_ip, dest_ip
| where count > 0
```

</details>

<details>
<summary><b>🕵️ 3. Investigation Workflow Completo</b></summary>

<br>

* **Fase 1: Alert Confirmation (5 min)**  
  Verifica la fonte, conferma se l'alert è un reale incidente o falso positivo ed esegui la prima query di scoping.
* **Fase 2: Scope Identification (15 min)**  
  Identifica il perimetro: **Chi** (utente/servizio), **Cosa** (file o registri modificati), **Quando** (primo e ultimo timestamp) e **Dove** (percorso di rete).
* **Fase 3: Deep Dive Analysis (30-45 min)**  
  Analisi dettagliata della catena dei processi (`EventCode 4688`), connessioni verso l'esterno (potenziale C2) ed estrazione IoC.

</details>

<details>
<summary><b>📋 4. IoC Extraction & Incident Report Template</b></summary>

<br>

```markdown
## INCIDENT REPORT — IoC EXTRACTION

**Incident ID:** INC-2026-08-001  
**Severity:** CRITICO  
**Status:** Under Investigation  

### Network IoCs
- **Source IP:** 192.168.1.100 (Workstation compromessa)
- **Destination IP:** 8.8.8.8 (Server C2)
- **Domain:** evil.com
- **Port/Protocol:** TCP 4444 (Outbound)

### File & Host IoCs
- **File Name:** malware.exe
- **SHA256:** a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
- **Persistence Path:** C:\Users\john.smith\AppData\Roaming\Microsoft\Windows\Start Menu\Startup\persistence.bat
- **Registry Key:** HKLM\Software\Microsoft\Windows\Run ("svchost")
```

</details>

<details>
<summary><b>🎯 5. MITRE ATT&CK Mapping Matrix</b></summary>

<br>

| Chain Phase | MITRE Tactic | Technique | Observable | Confidence |
|-------------|-------------|-----------|-----------|-----------|
| 1 | Initial Access | T1566 - Phishing | Email con link malevolo | HIGH |
| 2 | Execution | T1059.001 - PowerShell | Esecuzione script offuscato | HIGH |
| 3 | Persistence | T1547.001 - Registry Run | Modifica chiave di registro | HIGH |
| 4 | Defense Evasion | T1140 - Deobfuscate | Comandi codificati in Base64 | HIGH |
| 5 | Lateral Movement | T1570 - Tool Transfer | Copia file su condivisione di rete | MEDIUM |
| 6 | Collection | T1005 - Local Data | Accesso anomalo a documenti | HIGH |
| 7 | Exfiltration | T1041 - C2 | Trasferimento dati outbound massivo | HIGH |

</details>

<details>
<summary><b>📈 6. Incident Response Escalation</b></summary>

<br>

### Regole di Escalation
- 🔴 **Malware Confermato / Exfiltration / Lateral Movement:** Escalation Immediata a Tier 2 / IR Team.
- 🟠 **Privilege Escalation:** Escalation entro 30 min.
- 🟡 **Attività Sospetta non confermata:** Continua investigazione locale.

### Template Email di Escalation
```text
SUBJECT: ESCALATION — INC-2026-08-001 — Confirmed Malware + Data Exfil
TO: Tier2Security@company.com

EXECUTIVE SUMMARY:
Confirmed incident on WKS-001 (john.smith). Malware detected, 2.3 GB data exfiltrated.
Immediate isolation and response required.

KEY FACTS:
- Host: WKS-001 | User: john.smith@company.com
- Severity: CRITICO | Status: ACTIVE
- IoCs: Malware Hash: a1b2c3d4... | C2 Domain: evil.com

ACTIONS TAKEN:
- WKS-001 isolated from network
- Malicious processes killed
- C2 IP/Domain blocked on Firewall/DNS
```

</details>

<details>
<summary><b>⚡ 7. Quick Reference Templates</b></summary>

<br>

#### Template: 2-Minute Triage Checklist
```text
ALERT NAME: ________________________
Real or False Positive?  [ ] Real   [ ] Likely FP   [ ] Unknown
Severity:                [ ] Critico [ ] Alto [ ] Medio [ ] Basso
Action Required:         [ ] Close  [ ] Investigate [ ] Escalate NOW
```

</details>

---

🔗 **Integrazione Portfolio:** Questo Playbook si affianca allo strumento Python [mitre-mapper](https://github.com/carmelolercaraops-cyber/mitre-mapper) per automatizzare la correlazione delle tecniche MITRE ATT&CK durante la fase di triage.
