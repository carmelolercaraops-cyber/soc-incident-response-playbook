# 🛡️ SOC Incident Response Playbook — Practical Splunk Edition

**Autore:** Carmelo Lercara  
**Certificazioni:** CompTIA Security+
**Corsi completati:** Splunk Search Expert (101/102/103)  
**Data:** Settembre 2026  
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
  
Le query sono scritte per un laboratorio con dati Windows (Security, Sysmon), Linux (syslog/auth), rete (firewall/proxy). **Non sono state eseguite**: nomi di index, sourcetype e campi dipendono dall'ambiente. Vanno provate su un dataset noto (per esempio BOTS di Splunk).

  ## Prima di usare qualsiasi query

1. **Trova gli index disponibili:** `| eventcount summarize=false index=* | dedup index | fields index`
2. **Guarda i campi veri di un evento:** `index=wineventlog | head 1 | table *` (ripeti per Sysmon, rete e proxy).
3. **Controlla il formato Windows:** se vedi `Account_Name` due volte (classico) usa `mvindex(Account_Name,-1)` per l'account di destinazione; se vedi `TargetUserName` (XML) usalo direttamente.
4. **Sysmon:** gli eventi `EventCode=1` e `11` esistono solo se Sysmon è installato e configurato.
5. **Evento 4688:** la riga di comando c'è solo se l'audit "Include command line in process creation events" è attivo.
6. **Imposta sempre un periodo** (`earliest=`) e, in produzione, gli index specifici al posto di `index=*`.
7. **Regola d'oro dell'ordine:** `sort` prima di `convert ctime`, altrimenti l'ordinamento diventa alfabetico.

---

<br>

## 1. Timeline per utente e origine (Windows + Linux)

**Da modificare:** nomi degli index; campi utente e IP se diversi; eventuale periodo.

```
index IN (wineventlog, linux, network) earliest=-24h
(EventCode IN (4624,4625,4720) OR "Failed password" OR "Accepted password")
| rex field=_raw "(?:invalid user |for )(?<linux_user>\S+) from (?<linux_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval utente=coalesce(TargetUserName, mvindex(Account_Name,-1), linux_user, "-")
| eval sorgente=coalesce(src_ip, Source_Network_Address, linux_ip, "-")
| eval evento=case(
    EventCode="4624","login riuscito (Windows)",
    EventCode="4625","login fallito (Windows)",
    EventCode="4720","account creato (Windows)",
    match(_raw,"Failed password"),"login fallito (SSH)",
    match(_raw,"Accepted password"),"login riuscito (SSH)",
    true(),"altro")
| stats count min(_time) AS primo max(_time) AS ultimo by utente, sorgente, host, evento
| sort 0 primo
| convert ctime(primo) ctime(ultimo)
```


## 2. Profilo di comportamento di un utente

**Da modificare:** `"UTENTE"` con l'account reale; gli index; verificare che il campo `user` esista in tutte le sorgenti.

```
index=* user="UTENTE" earliest=-30d
| eval periodo=if(_time>=relative_time(now(),"-1d"),"ultime_24h","baseline_30d")
| fillnull value="-" action dest_ip dest_port
| stats count by periodo, sourcetype, action, dest_ip, dest_port
| sort 0 -count
```
Le righe presenti solo in `ultime_24h` sono quelle da guardare.

## 3. Brute force e password spraying

**Da modificare:** `LogonType`/`Logon_Type` (a seconda del formato); soglia `falliti>=10` e `utenti_falliti>=5`; finestra `span=10m`.

```
index=wineventlog EventCode IN (4625,4624) (LogonType IN (3,10) OR Logon_Type IN (3,10)) earliest=-1h
| eval utente=coalesce(TargetUserName, mvindex(Account_Name,-1), user)
| eval sorgente=coalesce(src_ip, Source_Network_Address)
| bin _time span=10m
| stats count(eval(EventCode=4625)) AS falliti
        count(eval(EventCode=4624)) AS riusciti
        dc(eval(if(EventCode=4625,utente,null()))) AS utenti_falliti by _time, sorgente
| where falliti>=10
| eval tipo=if(utenti_falliti>=5,"possibile password spraying","possibile brute force")
| eval esito=if(riusciti>0,"ATTENZIONE: login riuscito dallo stesso IP","nessun successo")
| sort 0 _time
```

## 4. Esecuzione sospetta (Sysmon)

**Da modificare:** index Sysmon; campo `user` (a volte `User`); aggiungere padri legittimi nel vostro ambiente se generano rumore.

```
index=sysmon EventCode=1 earliest=-24h
(
  ((Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
   AND (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe"))
  OR (Image="*\\svchost.exe" AND NOT ParentImage="*\\services.exe")
  OR (Image="*\\powershell.exe" AND (CommandLine="* -enc *" OR CommandLine="* -encodedcommand *"))
)
| sort 0 _time
| table _time host user ParentImage Image CommandLine
```

## 5. Beaconing verso l'esterno

**Da modificare:** index e campi di rete (`action`, `dest_ip`, `dest_port`); soglie `count>20`, `media>=10`, `dev<media*0.2`; intervalli IP interni se diversi.

```
index=network action=allowed earliest=-24h
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))
| sort 0 src_ip dest_ip dest_port _time
| streamstats current=f last(_time) AS prev by src_ip dest_ip dest_port
| eval delta=_time-prev
| stats count avg(delta) AS media stdev(delta) AS dev by src_ip dest_ip dest_port
| where count>20 AND media>=10 AND dev<media*0.2
| sort 0 -count
```
Anche aggiornamenti e telemetria sono regolari: verifica sempre dominio e ASN prima di concludere.

## 6a. File sospetti in cartelle di staging (Sysmon)

**Da modificare:** index Sysmon; elenco di cartelle ed estensioni.

```
index=sysmon EventCode=11 earliest=-24h
(TargetFilename="*\\AppData\\*" OR TargetFilename="*\\Temp\\*" OR TargetFilename="*\\Users\\Public\\*")
(TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.ps1" OR TargetFilename="*.bat" OR TargetFilename="*.zip" OR TargetFilename="*.7z")
| stats count min(_time) AS primo max(_time) AS ultimo values(TargetFilename) AS file by host, user, Image
| sort 0 primo
| convert ctime(primo) ctime(ultimo)
```

## 6b. Volume in uscita per host

**Da modificare:** campo `bytes_out` (nome dipende dal firewall); soglia `MB>500`, da tarare sul traffico normale.

```
index=network action=allowed earliest=-24h
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))
| stats sum(bytes_out) AS byte_out dc(dest_ip) AS destinazioni by src_ip
| eval MB=round(byte_out/1024/1024,1)
| where MB>500
| sort 0 -MB
```

## 7. Timeline completa di un caso

**Da modificare:** `UTENTE`, `IP`, `HOST` (cancella le condizioni che non servono); periodo.

```
index=* earliest=-24h (user="UTENTE" OR src_ip="IP" OR dest_ip="IP" OR host="HOST")
| sort 0 _time
| eval ora=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table ora index sourcetype host user src_ip dest_ip action EventCode CommandLine
```

## 8. Ricerca di IoC

**Da modificare:** gli IP, il dominio e l'hash con quelli dell'incidente; i nomi dei campi (`dest_host`, `query`, `SHA256`, `Hashes`) in base ai vostri log.

```
index=* earliest=-30d
( src_ip IN ("203.0.113.45","198.51.100.77") OR dest_ip IN ("203.0.113.45","198.51.100.77")
  OR dest_host="login-azienda-sso.example" OR query="login-azienda-sso.example"
  OR SHA256="<hash>" OR Hashes="*<hash>*" )
| fillnull value="-" host user src_ip dest_ip
| stats count min(_time) AS primo max(_time) AS ultimo values(sourcetype) AS fonti by host, user, src_ip, dest_ip
| sort 0 primo
| convert ctime(primo) ctime(ultimo)
```

## 9. Phishing: clic e invio di credenziali

**Da modificare:** il dominio sospetto; i nomi dei campi del proxy (`dest_host`, `url`, `http_method`, `status`, `user`).

```
index=proxy earliest=-24h (dest_host="login-azienda-sso.example" OR url="*login-azienda-sso.example*")
| sort 0 _time
| eval ora=strftime(_time,"%Y-%m-%d %H:%M:%S")
| eval credenziali=if(http_method="POST","POSSIBILE INVIO CREDENZIALI","")
| table ora src_ip user http_method url status credenziali
```

## 10. Persistenza (servizio, task, account, gruppo)

**Da modificare:** index; i nomi dei campi (`Task_Name` o `TaskName`). Attenzione: per **4732** il campo `TargetUserName` è il **gruppo**, non l'utente aggiunto; per **4720** è l'account creato.

```
index=wineventlog earliest=-24h EventCode IN (7045,4698,4720,4732)
| eval cosa=case(EventCode=7045,"nuovo servizio",
                 EventCode=4698,"scheduled task creata",
                 EventCode=4720,"account creato",
                 EventCode=4732,"aggiunto a gruppo")
| eval oggetto=case(EventCode=7045,Service_Name,
                    EventCode=4698,coalesce(Task_Name,TaskName),
                    EventCode=4720,TargetUserName,
                    EventCode=4732,TargetUserName." (gruppo)")
| sort 0 _time
| table _time host cosa oggetto SubjectUserName MemberName
```
Il 7045 è nel log System e gli altri nel Security: controlla che arrivino entrambi a Splunk.

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

**Incident ID:** INC-yyyy-mm-dd  
**Severity:** (severity level)  
**Status:** (status)  

### Network IoCs
- **Source IP:** X.X.X.X (Workstation compromessa)
- **Destination IP:** X.X.X.X (Server C2)
- **Domain:** evil.com
- **Port/Protocol:** TCP 4444 (Outbound)

### File & Host IoCs
- **File Name:** malware.exe
- **SHA256:** (<SHA256: 64 caratteri esadecimali>)
- **Persistence Path:** C:\Users\john.smith\AppData\Roaming\Microsoft\Windows\Start Menu\Startup\persistence.bat
- **Registry Key:** HKLM\Software\Microsoft\Windows\CurrentVersion\Run ("svchost")
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

### Template Email di Escalation (È IMPORTANTE RISPONDERE IN MODO ESAUSTIVO ALLE 5W)
```text
Time of activity: 

List of Affected Entities: 
(USER)
(ROLE)
(MAIL)
(HOST)
(IP)
Reason for Classifying as True Positive: 

Reason for Escalating the Alert:  

Recommended Remediation Actions: Isolate the host and the user. Investigate the host and user compromise and implement a firewall rule.

List of Attack Indicators: 
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
