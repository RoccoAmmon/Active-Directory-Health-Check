# GUI-Bedienung (WPF)

Ab **Version 2.2** startet das Skript standardmäßig eine moderne WPF-GUI zur Auswahl der Checks und des Ausgabepfads.

---

## Übersicht

Die GUI besteht aus folgenden Bereichen:

| Bereich | Funktion |
|---------|----------|
| **Header** | Titel und Kurzbeschreibung |
| **Ausgabepfad** | Textfeld + "Durchsuchen..."-Button (FolderBrowserDialog) |
| **Schnellauswahl** | Buttons "Alle auswählen" / "Keine" |
| **Suite-Buttons** | Vorauswahl pro Gruppe (DC-Infrastruktur, Security, Identity, Topologie, System) |
| **Check-Gruppen** | 5 aufklappbare Expander mit Gruppen-Checkbox und Einzel-Checks |
| **Footer** | "Abbrechen" und "Health Check starten" |

---

## Check-Gruppen

| Gruppe | Checks |
|--------|--------|
| **DC-Infrastruktur** | System-Info, Dienste, DCDiag, Replikation, FSMO, DNS, SYSVOL, NTDS-DB, Zeitsync, Backup |
| **Security & Hardening** | TLS, Cipher, SMB, NTLM, LLMNR, LDAP-Security, Firewall, LSA, PrintSpooler, SecureBoot, Zertifikate |
| **Identity & Kerberos** | Privilegierte Accounts, Password-Policy, Kerberos/krbtgt, Delegation, Kerberoasting, SPN-Dubletten, AS-REP-Roasting, AdminSDHolder, FGPP |
| **AD-Topologie & Objekte** | Sites, Subnets, Trusts, Recycle Bin, Tombstone, Levels, GPO, Inaktive User/Computer, PW-Never-Expires |
| **System & Updates** | Event-Log, Installierte Programme, Windows Updates, DNS-Hygiene |

---

## Suite-Buttons

Ein Klick auf einen Suite-Button deselektiert alle Checks und wählt dann nur die Checks der jeweiligen Gruppe an:

- **DC-Infrastruktur** → 11 Checks
- **Security & Hardening** → 11 Checks (rot hervorgehoben)
- **Identity & Kerberos** → 9 Checks
- **AD-Topologie & Objekte** → 10 Checks
- **System & Updates** → 4 Checks

---

## Ausgabepfad

- Standard: `C:\ScriptLog`
- Per GUI änderbar über "Durchsuchen..."-Button
- Per Parameter: `.\AD_Health_Check.ps1 -OutputPath 'D:\Reports\AD'`
- Der Report wird unter `<Pfad>\AD_HealthCheck_<Timestamp>\` gespeichert

---

## GUI umgehen

Für Automatisierung / Scheduled Tasks die GUI überspringen:

```powershell
# Alle Checks ohne GUI
.\AD_Health_Check.ps1 -FullRun

# Bestimmte Checks ohne GUI
.\AD_Health_Check.ps1 -OnlyChecks '22_PrintSpooler','18_Kerberos'

# Ohne Interaktion (= Full Run)
.\AD_Health_Check.ps1 -NoInteractive

# Mit eigenem Ausgabepfad ohne GUI
.\AD_Health_Check.ps1 -FullRun -OutputPath 'D:\Reports'
```

---

## Voraussetzungen

Die WPF-GUI benötigt:
- **.NET Framework 4.5+** (auf Windows Server 2016+ immer vorhanden)
- **Kein zusätzliches Modul** erforderlich (PresentationFramework ist Teil von .NET)
- Funktioniert auch über RDP-Sitzungen
