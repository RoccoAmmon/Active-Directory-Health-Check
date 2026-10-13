# 🛡️ Active Directory Health Check v2.6

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202016%2B-lightgrey.svg)](https://www.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.6-brightgreen.svg)]()
[![Checks](https://img.shields.io/badge/Checks-54-orange.svg)]()
[![Releases](https://img.shields.io/gitlab/v/release/RoccoAmmon/Active-Directory-Health-Check)](https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check/-/releases)

> 🇩🇪 [Deutsch](#-deutsch) | 🇬🇧 [English](#-english)

> Ein umfassendes PowerShell-Skript zur automatisierten Überprüfung der Gesundheit und Sicherheit einer Active Directory-Umgebung. Mit Best-Practice-Bewertung, farbcodiertem HTML-Report und CSV-Export.

---

## 🇩🇪 Deutsch

### 📑 Inhaltsverzeichnis

- [Features](#-features)
- [Die 54 Checks](#-die-54-checks)
- [Systemanforderungen](#-systemanforderungen)
- [Installation](#-installation)
- [Verwendung](#-verwendung)
- [Sprache / Language](#-sprache--language)
- [Screenshots](#-screenshots)
- [Konfiguration](#-konfiguration)
- [Report-Ausgabe](#-report-ausgabe)
- [Architektur](#-architektur)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

### ✨ Features

- 🎯 **54 Best-Practice-Checks** thematisch sortiert (DC-Basis, Security, Struktur, Monitoring)
- 🖼️ **Moderne WPF-GUI** (Light Theme) mit Gruppen-Auswahl, Suite-Buttons und Ausgabepfad-Wahl
- 🎨 **Farbcodierter HTML-Report** mit Executive Dashboard (OK / WARN / KRITISCH / INFO)
- 📊 **CSV-Export** aller Check-Ergebnisse
- 🖥️ **Interaktives Startmenü** als Fallback für Konsolen-Betrieb
- ⚡ **Parameter-basierte Ausführung** für Scheduled Tasks / Automatisierung
- 📁 **Frei wählbarer Ausgabepfad** per GUI oder `-OutputPath` Parameter
- 🔍 **DCDiag mit Einzeltest-Parsing** (DE/EN sprachunabhängig)
- 🔄 **Loopback-Erkennung** für lokale DCs (nutzt `localhost` statt FQDN)
- 📡 **Ping-Skip-Logik** für nicht erreichbare DCs mit Fallback auf WinRM
- 🌍 **Sprachunabhängig** via Well-Known SIDs
- 🗣️ **Automatische Spracherkennung & DE/EN-Sprachumschalter** – live umschaltbar in der WPF-GUI, überschreibbar per Parameter `-Language de|en`
- 📝 **Ausführliches Logging** (`C:\ScriptLog`)
- 🔧 **Modular aufgebaut** - einzelne Checks können gezielt ausgeführt werden

### 📋 Die 54 Checks

### 🏗️ DC-Basis-Infrastruktur
| # | Check | Beschreibung |
|---|---|---|
| 1 | **DC System-Informationen** | OS, RAM, Uptime, Hardware |
| 2 | **Dienste** | NTDS, DNS, Netlogon, KDC, W32Time, DFSR |
| 3 | **DCDiag-Tests** | Detailliertes Parsing aller DC-Diagnose-Tests |
| 4 | **Replikation (Partner)** | Status pro DC-Partner |
| 4b | **Replikations-Fehler (Forest)** | Forest-weite Replikationsprobleme |
| 5 | **FSMO-Rollen** | Alle 5 FSMO-Rolleninhaber |
| 6 | **DNS-Konfiguration** | Zonen, AD-Integration, Dynamic Updates |
| 7 | **SYSVOL & NETLOGON** | Erreichbarkeit |
| 8 | **NTDS-Datenbank** | Größe, freier Festplattenplatz |

### 🔒 Security: Netzwerk-Protokolle
| # | Check | Beschreibung |
|---|---|---|
| 9 | **TLS-Protokolle (SCHANNEL)** | SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3 |
| 10 | **Cipher & Algorithmen** | RC4, DES, MD5 und andere schwache Cipher |
| 11 | **SMB1 & SMB-Signing** | WannaCry-Schutz, Signing erzwungen |
| 12 | **NTLM / LAN-Manager Auth Level** | `LmCompatibilityLevel=5` Best Practice |
| 13 | **LLMNR / NetBIOS / WPAD** | Responder-Angriffs-Schutz |
| 14 | **LDAP-Security** | Signing + Channel Binding (ADV190023) |
| 15 | **Windows Firewall** | Alle 3 Profile aktiv? |

### 👥 Security: Accounts & Kerberos
| # | Check | Beschreibung |
|---|---|---|
| 16 | **Privilegierte Accounts** | Domain/Enterprise/Schema Admins etc. |
| 17 | **Password-Policy** | MinLen, History, MaxAge, Complexity, Lockout |
| 18 | **Kerberos / krbtgt** | Passwort-Alter (Best Practice: ≤180 Tage) |
| 19 | **Kerberos Unconstrained Delegation** | Domain-Takeover-Risiko-Erkennung |
| 20 | **Kerberoasting-Risiko** | User-Accounts mit SPN analysieren |
| 21 | **LSA Protection (RunAsPPL)** | Schutz gegen Credential-Dumping (Mimikatz) |

### 🛡️ Security: System Hardening
| # | Check | Beschreibung |
|---|---|---|
| 22 | **Print Spooler auf DCs** | CVE-2021-34527 (PrintNightmare) |
| 23 | **Secure Boot Zertifikats-Update** | Windows UEFI CA 2023 Deployment-Status |
| 24 | **Zertifikate** | Ablauf-Überwachung, EKU-Check |

### 🌐 AD-Struktur
| # | Check | Beschreibung |
|---|---|---|
| 25 | **AD-Sites** | Site-Übersicht |
| 26 | **AD-Subnetze** | Subnetz-zu-Site-Zuordnung |
| 27 | **Vertrauensstellungen** | Domain/Forest Trusts |
| 28 | **AD Recycle Bin** | Aktivierungsstatus des Features |
| 29 | **Tombstone Lifetime** | Best Practice ≥180 Tage |
| 30 | **Forest-/Domain-Level** | Functional Level |
| 31 | **GPO-Health** | Sysvol/DS-Version-Mismatch |

### 👤 Inaktive Accounts
| # | Check | Beschreibung |
|---|---|---|
| 32a | **Inaktive User** | >90 Tage kein Login |
| 32b | **Inaktive Computer** | >90 Tage kein Login |
| 32c | **Passwort läuft nie ab** | Flag-Check |

### 📊 Monitoring & Betrieb
| # | Check | Beschreibung |
|---|---|---|
| 33 | **Event-Log-Auswertung** | System / Directory Service / DNS (letzte 24h) |
| 34 | **Zeitsynchronisation** | PDC + Domain-DCs |
| 35 | **AD-Backup-Status** | via `repadmin /showbackup` |
| 36 | **Installierte Programme** | Inventory pro DC |
| 37 | **Windows Updates** | Letzte 20 Updates, Altersbewertung |
| 45 | **Installierte Windows Features** | Installierte Rollen & Features pro DC (ServerManager) |
| 46 | **SMB-Freigaben (Shares)** | Alle Freigaben inkl. Pfade, Berechtigungen und Verschlüsselung |

### 🧬 Identity & DNS (neu)
| # | Check | Beschreibung |
|---|---|---|
| 38 | **SPN-Dubletten** | Erkennung mehrfach vergebener SPNs (Kerberos-Konflikte) |
| 39 | **AS-REP-Roasting-Risiko** | User ohne Kerberos Pre-Authentication |
| 40 | **AdminSDHolder / AdminCount-Drift** | AdminCount=1 ohne aktuelle Schutzgruppen-Mitgliedschaft |
| 41 | **Fine-Grained Password Policies** | FGPP-Haerte, Lockout und Zielgruppen-Zuordnung |
| 42 | **DNS-Hygiene (Aging / Scavenging)** | Aging/Scavenging, Reverse-Zonen, Dynamic-Update-Risiken |
| 43 | **LAPS-Konfiguration** | Local Admin Password Solution - Aktivierungsstatus, Computer-Abdeckung (ab Server 2019) |
| 44 | **Konten ohne AES** | Findet Accounts mit RC4-only oder ohne AES-Verschluesselung (Sicherheitsrisiko) |

### 🎯 Security: Angriffsvektoren 2025/2026
| # | Check | Beschreibung |
|---|---|---|
| 47 | **RC4 → AES Migrations-Audit** | Konten ohne AES vor der RC4-Abschaltung 2026 (CVE-2026-20833) + KDC-Registry der DCs |
| 48 | **DCSync-Berechtigungen** | Replikations-Rechte ausserhalb der DCs (Passwort-Hash-Extraktions-Risiko) |
| 49 | **RBCD & Constrained Delegation** | `msDS-AllowedToActOnBehalfOfOtherIdentity` und `msDS-AllowedToDelegateTo` inkl. Protokollwechsel |
| 50 | **dMSA / BadSuccessor** | Delegated Managed Service Accounts (Server 2025) und Superseding-Muster |
| 51 | **MachineAccountQuota** | `ms-DS-MachineAccountQuota` (Best Practice: 0) |
| 52 | **Anonymer LDAP-Zugriff** | Anonymer Bind-Test gegen PDC + dSHeuristics |
| 53 | **GPP/cpassword in SYSVOL** | Klartext-dechiffrierbare Passwörter in GPP-XMLs (MS14-025) |
| 54 | **Protected Users Audit** | Alle privilegierten Konten in der Protected-Users-Gruppe? |

### 💻 Systemanforderungen

- **Windows Server 2016** oder neuer
- **PowerShell 5.1+**
- **RSAT / AD-Tools** installiert:
  - ActiveDirectory-Modul
  - GroupPolicy-Modul
  - DnsServer-Modul
- **Domain Admin**-Rechte empfohlen
- **WinRM** auf allen DCs aktiviert (oder DCOM-Fallback)
- Ausführung **auf einem DC oder Management-Server** mit AD-Connectivity

### 🚀 Installation

```powershell
# Repository klonen
git clone https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check.git
cd Active-Directory-Health-Check

# Skript ausführen (interaktiv)
.\AD_Health_Check.ps1

# Oder automatisiert (alle 54 Checks)
.\AD_Health_Check.ps1 -FullRun
```

### ⚙️ Verwendung

```powershell
# Interaktive WPF-GUI (Standard)
.\AD_Health_Check.ps1

# Vollständiger Lauf ohne GUI (für Scheduled Tasks)
.\AD_Health_Check.ps1 -FullRun

# Vollständiger Lauf mit englischer Berichtssprache
.\AD_Health_Check.ps1 -FullRun -Language en

# Nur bestimmte Checks ausführen
.\AD_Health_Check.ps1 -OnlyChecks '22_PrintSpooler','19_Unconstrained'

# Ohne Interaktion
.\AD_Health_Check.ps1 -NoInteractive

# Eigenen Ausgabepfad angeben
.\AD_Health_Check.ps1 -OutputPath 'D:\Reports\AD'
```

### 🗣️ Sprache / Language

Die Berichtssprache wird beim Start automatisch erkannt und kann bei Bedarf per Parameter überschrieben werden.

- **Automatische Spracherkennung:** Beim Start wird die Sprache aus der Betriebssystemsprache ermittelt (`Get-UICulture`). Deutsche Windows-Oberfläche → Deutsch, englische Windows-Oberfläche → Englisch, alles andere → Deutsch.
- **Sprachumschalter DE/EN in der WPF-GUI:** Live umschaltbar; wirkt sofort auf alle GUI-Texte, Check-Titel und Gruppennamen.
- **Parameter `-Language de|en`:** Überschreibt die automatische Erkennung – z. B. für Scheduled Tasks.
- **Gültige Werte:** `de`, `en` – Standard: Betriebssystemsprache.
- **Ausgabemedien:** HTML-Report, Konsolenausgabe und Menüs erscheinen in der gewählten Sprache. Die Spaltennamen des CSV-Exports bleiben technisch und unabhängig von der Sprache unverändert.

```powershell
# Beispiel: Vollständiger Lauf mit englischer Ausgabe
.\AD_Health_Check.ps1 -FullRun -Language en
```

### 📸 Screenshots

> Screenshots des HTML-Reports folgen.

### ⚙️ Konfiguration

Alle Schwellwerte sind im Variablen-Block am Anfang des Skripts konfigurierbar:

| Variable | Standard | Beschreibung |
|---|---|---|
| `InactiveDaysUser` | 90 | Tage ohne Login → User inaktiv |
| `InactiveDaysComputer` | 90 | Tage ohne Login → Computer inaktiv |
| `CertExpiryWarnDays` | 60 | Zertifikat-Ablauf Warnung |
| `CertExpiryCritDays` | 14 | Zertifikat-Ablauf Kritisch |
| `KrbtgtMaxAgeDays` | 180 | Max. krbtgt-Passwort-Alter |
| `BackupMaxAgeDays` | 7 | Backup-Alter Warnung |
| `BackupCritAgeDays` | 14 | Backup-Alter Kritisch |
| `WUMaxAgeDaysWarn` | 35 | Windows Update Alter Warnung |
| `WUMaxAgeDaysCrit` | 60 | Windows Update Alter Kritisch |

Vollständige Konfigurationsreferenz: [Wiki → Schwellwerte](https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check/-/wikis/Konfiguration)

### 📄 Report-Ausgabe

Ergebnisse werden unter `C:\ScriptLog` gespeichert:
- **HTML-Report** mit Executive Dashboard (farbcodiert)
- **CSV-Exporte** pro Check (für Excel/Power BI/SIEM)
- **Log-Datei** mit Ausführungsprotokoll

### 🏗️ Architektur

- Modularer Aufbau mit einzeln aufrufbaren Check-Funktionen
- Loopback-Erkennung für lokale DCs
- Sprachunabhängig via Well-Known SIDs (DE/EN)
- WinRM-basierte Remote-Abfragen mit Ping-Fallback

### 🔧 Troubleshooting

Siehe [Wiki → Troubleshooting](https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check/-/wikis/Troubleshooting)

### 🤝 Contributing

1. Fork erstellen
2. Feature-Branch anlegen (`git checkout -b feature/mein-feature`)
3. Änderungen committen (`git commit -m 'Add: Mein Feature'`)
4. Branch pushen (`git push origin feature/mein-feature`)
5. Pull Request erstellen

### 📋 Changelog

### v2.6 (aktuell)
- **Automatische Spracherkennung & DE/EN-Sprachumschalter** – die Sprache wird aus der Betriebssystemsprache ermittelt (`Get-UICulture`), Live-Umschalter DE/EN in der WPF-GUI, neuer Parameter `-Language de|en`
- HTML-Report, Konsolenausgabe und Menüs erscheinen in der gewählten Sprache; CSV-Export-Spaltennamen bleiben technisch/unverändert

### v2.5
- **8 neue Checks** (47–54): RC4→AES-Migrations-Audit, DCSync-Rechte, RBCD & Constrained Delegation, dMSA/BadSuccessor, MachineAccountQuota, anonymer LDAP, GPP/cpassword, Protected Users
- Check 47: RC4→AES-Migrations-Audit (CVE-2026-20833) – Konten ohne AES, SPN-Dienstkonten mit KDC-RC4-Default, RC4-only/DES, KDC-Registry aller DCs
- Check 48: Wer hat „Replicating Directory Changes All" ausserhalb der DCs? (DCSync = Hash-Extraktion)
- Check 49: RBCD-Einträge (Warnung bei User-Prinzipalen) + Constrained Delegation inkl. Protokollwechsel (S4U2Self)
- Check 50: dMSA-Objekte und BadSuccessor-Muster (`msDS-DelegatedMSAState=2` mit privilegiertem übernommenem Konto = kritisch)
- Check 53: Sucht SYSVOL nach `cpassword`-Attributen in GPP-XMLs (MS14-025)
- **Bugfix Check 44**: Korrekte Bitmasken für `msDS-SupportedEncryptionTypes` (RC4=0x04, AES=0x18, DES=0x03 statt vorher 0x02/0x30/0x01) – AES128-only-Konten werden nicht mehr fälschlich als „ohne AES" gemeldet
- **Bugfix Check 02 (Dienste)**: NTDS auf lokalen DCs wird zuverlässig erkannt – 4-stufiges Matching (Name → DE/EN-Anzeigename → ASCII-Patterns → direkte CIM-Abfrage + lokaler Get-Service); Datei jetzt UTF-8 mit BOM (PS 5.1 liest Umlaut-Strings korrekt)
- Menüpunkte „Forest" und „Security" enthielten die Checks 43/44 nicht – ergänzt

### v2.4
- **2 neue Checks** (45–46): Installierte Windows Features, SMB-Freigaben (Shares)
- Check 45: Installierte Rollen & Features pro DC via `Get-WindowsFeature` (Fallback: `Get-WindowsOptionalFeature`)
- Check 46: Alle SMB-Freigaben inkl. Pfade, Berechtigungen (`Get-SmbShareAccess`) und Verschlüsselung (Fallback: `Win32_Share`); Standard-Freigaben (SYSVOL, NETLOGON, ADMIN$) werden nicht beanstandet
- **HTML-Report nach GUI-Kategorien gruppiert** (Kategorie-Banner + gruppierte Übersicht)
- Dienste-Check per CIM/WinRM mit DE/EN-Anzeigenamen (NTDS „Active Directory-Domänendienste" wird erkannt)
- NTFRS gestoppt = Best Practice (grün), nur NTFRS aktiv wird gewarnt
- Beide Checks in der Gruppe „System & Updates" (GUI) und in den per-DC-Checks

### v2.2
- **Moderne WPF-GUI** (Light Theme) mit Check-Gruppen, Suite-Buttons und Ausgabepfad-Wahl
- Neuer Parameter `-OutputPath`
- Shell-Menü bleibt als Fallback erhalten

### v2.1
- Verbessertes Loopback-Handling für lokale DCs
- Erweiterte Ping-Skip-Logik mit WinRM-Fallback
- Performance-Optimierungen bei der DC-Discovery
- Bugfixes im HTML-Report-Rendering
- Wiki-Dokumentation erstellt

### v2.0
- **5 neue Checks** (38–42): SPN-Dubletten, AS-REP-Roasting, AdminSDHolder, FGPP, DNS-Hygiene
- Executive Dashboard im HTML-Report
- Interaktives Startmenü mit 7 Optionen
- Parameter-basierte Ausführung (`-FullRun`, `-OnlyChecks`, `-NoInteractive`)
- CSV-Export aller Check-Ergebnisse
- Progress-Tracking während der Ausführung

### v1.0
- Initiale Version mit 37 Checks
- Basis-HTML-Report und Logging

### 📜 License

Dieses Projekt ist unter der [MIT License](LICENSE) lizenziert.

---

## 🇬🇧 English

### 📑 Table of Contents

- [Features](#-features)
- [The 54 Checks](#-the-54-checks)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sprache / Language](#-sprache--language)
- [Screenshots](#-screenshots)
- [Configuration](#-configuration)
- [Report Output](#-report-output)
- [Architecture](#-architecture)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

### ✨ Features

- 🎯 **54 best-practice checks**, sorted thematically (DC fundamentals, security, structure, monitoring)
- 🖼️ **Modern WPF GUI** (light theme) with group selection, suite buttons and output path selection
- 🎨 **Color-coded HTML report** with executive dashboard (OK / WARN / CRITICAL / INFO)
- 📊 **CSV export** of all check results
- 🖥️ **Interactive start menu** as a fallback for console operation
- ⚡ **Parameter-based execution** for scheduled tasks / automation
- 📁 **Freely selectable output path** via the GUI or the `-OutputPath` parameter
- 🔍 **DCDiag with per-test parsing** (language-independent, DE/EN)
- 🔄 **Loopback detection** for local DCs (uses `localhost` instead of the FQDN)
- 📡 **Ping skip logic** for unreachable DCs with WinRM fallback
- 🌍 **Language-independent** via well-known SIDs
- 🗣️ **Automatic language detection & DE/EN language switch** – switchable live in the WPF GUI, overridable via the `-Language de|en` parameter
- 📝 **Verbose logging** (`C:\ScriptLog`)
- 🔧 **Modular design** – individual checks can be run selectively

### 📋 The 54 Checks

### 🏗️ DC Core Infrastructure
| # | Check | Description |
|---|---|---|
| 1 | **DC System Information** | OS, RAM, uptime, hardware |
| 2 | **Services** | NTDS, DNS, Netlogon, KDC, W32Time, DFSR |
| 3 | **DCDiag Tests** | Detailed parsing of all DC diagnostic tests |
| 4 | **Replication (Partners)** | Status per DC partner |
| 4b | **Replication Failures (Forest)** | Forest-wide replication problems |
| 5 | **FSMO Roles** | All 5 FSMO role holders |
| 6 | **DNS Configuration** | Zones, AD integration, dynamic updates |
| 7 | **SYSVOL & NETLOGON** | Reachability |
| 8 | **NTDS Database** | Size, free disk space |

### 🔒 Security: Network Protocols
| # | Check | Description |
|---|---|---|
| 9 | **TLS Protocols (SCHANNEL)** | SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3 |
| 10 | **Ciphers & Algorithms** | RC4, DES, MD5 and other weak ciphers |
| 11 | **SMB1 & SMB Signing** | WannaCry protection, signing enforced |
| 12 | **NTLM / LAN Manager Authentication Level** | `LmCompatibilityLevel=5` best practice |
| 13 | **LLMNR / NetBIOS / WPAD** | Protection against Responder attacks |
| 14 | **LDAP Security** | Signing + channel binding (ADV190023) |
| 15 | **Windows Firewall** | Are all 3 profiles enabled? |

### 👥 Security: Accounts & Kerberos
| # | Check | Description |
|---|---|---|
| 16 | **Privileged Accounts** | Domain/Enterprise/Schema Admins, etc. |
| 17 | **Password Policy** | MinLen, History, MaxAge, Complexity, Lockout |
| 18 | **Kerberos / krbtgt** | Password age (best practice: ≤180 days) |
| 19 | **Kerberos Unconstrained Delegation** | Domain takeover risk detection |
| 20 | **Kerberoasting Risk** | Analyze user accounts with SPNs |
| 21 | **LSA Protection (RunAsPPL)** | Protection against credential dumping (Mimikatz) |

### 🛡️ Security: System Hardening
| # | Check | Description |
|---|---|---|
| 22 | **Print Spooler on DCs** | CVE-2021-34527 (PrintNightmare) |
| 23 | **Secure Boot Certificate Update** | Windows UEFI CA 2023 deployment status |
| 24 | **Certificates** | Expiry monitoring, EKU check |

### 🌐 AD Structure
| # | Check | Description |
|---|---|---|
| 25 | **AD Sites** | Site overview |
| 26 | **AD Subnets** | Subnet-to-site mapping |
| 27 | **Trusts** | Domain/forest trusts |
| 28 | **AD Recycle Bin** | Feature activation status |
| 29 | **Tombstone Lifetime** | Best practice ≥180 days |
| 30 | **Forest/Domain Level** | Functional level |
| 31 | **GPO Health** | SYSVOL/DS version mismatch |

### 👤 Inactive Accounts
| # | Check | Description |
|---|---|---|
| 32a | **Inactive Users** | No logon for >90 days |
| 32b | **Inactive Computers** | No logon for >90 days |
| 32c | **Password Never Expires** | Flag check |

### 📊 Monitoring & Operations
| # | Check | Description |
|---|---|---|
| 33 | **Event Log Analysis** | System / Directory Service / DNS (last 24 h) |
| 34 | **Time Synchronization** | PDC + domain DCs |
| 35 | **AD Backup Status** | via `repadmin /showbackup` |
| 36 | **Installed Software** | Inventory per DC |
| 37 | **Windows Updates** | Last 20 updates, age rating |
| 45 | **Installed Windows Features** | Installed roles & features per DC (ServerManager) |
| 46 | **SMB Shares** | All shares including paths, permissions and encryption |

### 🧬 Identity & DNS (new)
| # | Check | Description |
|---|---|---|
| 38 | **Duplicate SPNs** | Detection of duplicate SPNs (Kerberos conflicts) |
| 39 | **AS-REP-Roasting Risk** | Users without Kerberos pre-authentication |
| 40 | **AdminSDHolder / AdminCount Drift** | AdminCount=1 without current protected-group membership |
| 41 | **Fine-Grained Password Policies** | FGPP strength, lockout and target group mapping |
| 42 | **DNS Hygiene (Aging / Scavenging)** | Aging/scavenging, reverse zones, dynamic update risks |
| 43 | **LAPS Configuration** | Local Admin Password Solution – activation status, computer coverage (Server 2019 and later) |
| 44 | **Accounts without AES** | Finds accounts with RC4-only or without AES encryption (security risk) |

### 🎯 Security: Attack Vectors 2025/2026
| # | Check | Description |
|---|---|---|
| 47 | **RC4 → AES Migration Audit** | Accounts without AES ahead of the 2026 RC4 shutdown (CVE-2026-20833) + KDC registry of the DCs |
| 48 | **DCSync Permissions** | Replication rights outside the DCs (password hash extraction risk) |
| 49 | **RBCD & Constrained Delegation** | `msDS-AllowedToActOnBehalfOfOtherIdentity` and `msDS-AllowedToDelegateTo` including protocol transition |
| 50 | **dMSA / BadSuccessor** | Delegated Managed Service Accounts (Server 2025) and superseding patterns |
| 51 | **MachineAccountQuota** | `ms-DS-MachineAccountQuota` (best practice: 0) |
| 52 | **Anonymous LDAP Access** | Anonymous bind test against the PDC + dSHeuristics |
| 53 | **GPP/cpassword in SYSVOL** | Passwords in GPP XML files that can be decrypted to plain text (MS14-025) |
| 54 | **Protected Users Audit** | Are all privileged accounts in the Protected Users group? |

### 💻 System Requirements

- **Windows Server 2016** or later
- **PowerShell 5.1+**
- **RSAT / AD tools** installed:
  - ActiveDirectory module
  - GroupPolicy module
  - DnsServer module
- **Domain Admin** rights recommended
- **WinRM** enabled on all DCs (or DCOM fallback)
- Run **on a DC or management server** with AD connectivity

### 🚀 Installation

```powershell
# Clone the repository
git clone https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check.git
cd Active-Directory-Health-Check

# Run the script (interactive)
.\AD_Health_Check.ps1

# Or automated (all 54 checks)
.\AD_Health_Check.ps1 -FullRun
```

### ⚙️ Usage

```powershell
# Interactive WPF GUI (default)
.\AD_Health_Check.ps1

# Full run without GUI (for scheduled tasks)
.\AD_Health_Check.ps1 -FullRun

# Full run with English report language
.\AD_Health_Check.ps1 -FullRun -Language en

# Run only specific checks
.\AD_Health_Check.ps1 -OnlyChecks '22_PrintSpooler','19_Unconstrained'

# Without interaction
.\AD_Health_Check.ps1 -NoInteractive

# Specify a custom output path
.\AD_Health_Check.ps1 -OutputPath 'D:\Reports\AD'
```

### 🗣️ Sprache / Language

The report language is detected automatically at startup and can be overridden with a parameter if required.

- **Automatic language detection:** On startup the language is determined from the operating system language (`Get-UICulture`). German Windows UI → German, English Windows UI → English, anything else → German.
- **DE/EN language switch in the WPF GUI:** Switchable at runtime; takes effect immediately on all GUI texts, check titles and group names.
- **Parameter `-Language de|en`:** Overrides automatic detection – e.g. for scheduled tasks.
- **Valid values:** `de`, `en` – default: operating system language.
- **Output media:** The HTML report, console output and menus appear in the selected language. The CSV export column names remain technical and unchanged, regardless of the language.

```powershell
# Example: Full run with English output
.\AD_Health_Check.ps1 -FullRun -Language en
```

### 📸 Screenshots

> Screenshots of the HTML report will follow.

### ⚙️ Configuration

All thresholds can be configured in the variable block at the beginning of the script:

| Variable | Default | Description |
|---|---|---|
| `InactiveDaysUser` | 90 | Days without logon → user inactive |
| `InactiveDaysComputer` | 90 | Days without logon → computer inactive |
| `CertExpiryWarnDays` | 60 | Certificate expiry warning |
| `CertExpiryCritDays` | 14 | Certificate expiry critical |
| `KrbtgtMaxAgeDays` | 180 | Maximum krbtgt password age |
| `BackupMaxAgeDays` | 7 | Backup age warning |
| `BackupCritAgeDays` | 14 | Backup age critical |
| `WUMaxAgeDaysWarn` | 35 | Windows Update age warning |
| `WUMaxAgeDaysCrit` | 60 | Windows Update age critical |

Full configuration reference: [Wiki → Konfiguration](https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check/-/wikis/Konfiguration)

### 📄 Report Output

Results are stored under `C:\ScriptLog`:
- **HTML report** with executive dashboard (color-coded)
- **CSV exports** per check (for Excel/Power BI/SIEM)
- **Log file** with the execution record

### 🏗️ Architecture

- Modular design with individually callable check functions
- Loopback detection for local DCs
- Language-independent via well-known SIDs (DE/EN)
- WinRM-based remote queries with ping fallback

### 🔧 Troubleshooting

See [Wiki → Troubleshooting](https://gitlab.com/RoccoAmmon/Active-Directory-Health-Check/-/wikis/Troubleshooting)

### 🤝 Contributing

1. Create a fork
2. Create a feature branch (`git checkout -b feature/mein-feature`)
3. Commit your changes (`git commit -m 'Add: Mein Feature'`)
4. Push the branch (`git push origin feature/mein-feature`)
5. Open a pull request

### 📋 Changelog

### v2.6 (current)
- **Automatic language detection & DE/EN language switch** – the language is determined from the operating system language (`Get-UICulture`), live DE/EN switch in the WPF GUI, new `-Language de|en` parameter
- HTML report, console output and menus appear in the selected language; CSV export column names remain technical/unchanged

### v2.5
- **8 new checks** (47–54): RC4→AES migration audit, DCSync permissions, RBCD & constrained delegation, dMSA/BadSuccessor, machine account quota, anonymous LDAP, GPP/cpassword, protected users
- Check 47: RC4→AES migration audit (CVE-2026-20833) – accounts without AES, SPN service accounts with KDC RC4 default, RC4-only/DES, KDC registry of all DCs
- Check 48: Who has "Replicating Directory Changes All" outside the DCs? (DCSync = hash extraction)
- Check 49: RBCD entries (warning for user principals) + constrained delegation including protocol transition (S4U2Self)
- Check 50: dMSA objects and BadSuccessor patterns (`msDS-DelegatedMSAState=2` with a privileged superseded account = critical)
- Check 53: Searches SYSVOL for `cpassword` attributes in GPP XML files (MS14-025)
- **Bugfix check 44**: Correct bitmasks for `msDS-SupportedEncryptionTypes` (RC4=0x04, AES=0x18, DES=0x03 instead of the previous 0x02/0x30/0x01) – AES128-only accounts are no longer incorrectly reported as "without AES"
- **Bugfix check 02 (Services)**: NTDS on local DCs is now reliably detected – four-stage matching (name → DE/EN display name → ASCII patterns → direct CIM query + local Get-Service); the file is now UTF-8 with BOM (PS 5.1 reads umlaut strings correctly)
- The menu items "Forest" and "Security" did not include checks 43/44 – added

### v2.4
- **2 new checks** (45–46): installed Windows features, SMB shares
- Check 45: Installed roles & features per DC via `Get-WindowsFeature` (fallback: `Get-WindowsOptionalFeature`)
- Check 46: All SMB shares including paths, permissions (`Get-SmbShareAccess`) and encryption (fallback: `Win32_Share`); default shares (SYSVOL, NETLOGON, ADMIN$) are not flagged
- **HTML report grouped by GUI categories** (category banners + grouped overview)
- Service check via CIM/WinRM with DE/EN display names (NTDS "Active Directory Domain Services" is detected)
- NTFRS stopped = best practice (green), only a running NTFRS triggers a warning
- Both checks are in the "System & Updates" group (GUI) and in the per-DC checks

### v2.2
- **Modern WPF GUI** (light theme) with check groups, suite buttons and output path selection
- New `-OutputPath` parameter
- The shell menu is retained as a fallback

### v2.1
- Improved loopback handling for local DCs
- Extended ping skip logic with WinRM fallback
- Performance optimizations for DC discovery
- Bugfixes in HTML report rendering
- Wiki documentation created

### v2.0
- **5 new checks** (38–42): duplicate SPNs, AS-REP-Roasting, AdminSDHolder, FGPP, DNS hygiene
- Executive dashboard in the HTML report
- Interactive start menu with 7 options
- Parameter-based execution (`-FullRun`, `-OnlyChecks`, `-NoInteractive`)
- CSV export of all check results
- Progress tracking during execution

### v1.0
- Initial version with 37 checks
- Basic HTML report and logging

### 📜 License

This project is licensed under the [MIT License](LICENSE).
