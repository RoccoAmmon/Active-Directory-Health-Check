# 🛡️ Active Directory Health Check v2.0

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202016%2B-lightgrey.svg)](https://www.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1-brightgreen.svg)]()
[![Checks](https://img.shields.io/badge/Checks-42-orange.svg)]()

> Ein umfassendes PowerShell-Skript zur automatisierten Überprüfung der Gesundheit und Sicherheit einer Active Directory-Umgebung. Mit Best-Practice-Bewertung, farbcodiertem HTML-Report und CSV-Export.

## 📑 Inhaltsverzeichnis

- [Features](#-features)
- [Die 42 Checks](#-die-42-checks)
- [Systemanforderungen](#-systemanforderungen)
- [Installation](#-installation)
- [Verwendung](#-verwendung)
- [Screenshots](#-screenshots)
- [Konfiguration](#-konfiguration)
- [Report-Ausgabe](#-report-ausgabe)
- [Architektur](#-architektur)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- 🎯 **42 Best-Practice-Checks** thematisch sortiert (DC-Basis, Security, Struktur, Monitoring)
- 🎨 **Farbcodierter HTML-Report** mit Executive Dashboard (OK / WARN / KRITISCH / INFO)
- 📊 **CSV-Export** aller Check-Ergebnisse
- 🖥️ **Interaktives Startmenü** mit 7 Optionen (Full, Einzel, Security-Suite etc.)
- ⚡ **Parameter-basierte Ausführung** für Scheduled Tasks / Automatisierung
- 🔍 **DCDiag mit Einzeltest-Parsing** (DE/EN sprachunabhängig)
- 🔄 **Loopback-Erkennung** für lokale DCs (nutzt `localhost` statt FQDN)
- 📡 **Ping-Skip-Logik** für nicht erreichbare DCs mit Fallback auf WinRM
- 🌍 **Sprachunabhängig** via Well-Known SIDs
- 📝 **Ausführliches Logging** (`C:\ScriptLog`)
- 🔧 **Modular aufgebaut** - einzelne Checks können gezielt ausgeführt werden

## 📋 Die 42 Checks

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

### 🧬 Identity & DNS (neu)
| # | Check | Beschreibung |
|---|---|---|
| 38 | **SPN-Dubletten** | Erkennung mehrfach vergebener SPNs (Kerberos-Konflikte) |
| 39 | **AS-REP-Roasting-Risiko** | User ohne Kerberos Pre-Authentication |
| 40 | **AdminSDHolder / AdminCount-Drift** | AdminCount=1 ohne aktuelle Schutzgruppen-Mitgliedschaft |
| 41 | **Fine-Grained Password Policies** | FGPP-Haerte, Lockout und Zielgruppen-Zuordnung |
| 42 | **DNS-Hygiene (Aging / Scavenging)** | Aging/Scavenging, Reverse-Zonen, Dynamic-Update-Risiken |

## 💻 Systemanforderungen

- **Windows Server 2016** oder neuer
- **PowerShell 5.1+**
- **RSAT / AD-Tools** installiert:
  - ActiveDirectory-Modul
  - GroupPolicy-Modul
  - DnsServer-Modul
- **Domain Admin**-Rechte empfohlen
- **WinRM** auf allen DCs aktiviert (oder DCOM-Fallback)
- Ausführung **auf einem DC oder Management-Server** mit AD-Connectivity

## 🚀 Installation

```powershell
# Repository klonen
git clone https://github.com/<DEIN-USERNAME>/AD-Health-Check.git
cd AD-Health-Check
