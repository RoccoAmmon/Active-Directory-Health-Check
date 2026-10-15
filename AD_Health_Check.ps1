<#
.SYNOPSIS
    Umfassender Active Directory Health Check v2.7 mit Best-Practice-Bewertung.
.DESCRIPTION
    54 thematisch sortierte Pruefpunkte auf allen DCs im Forest mit farbcodiertem
    HTML-Report, Executive Dashboard, CSV-Exporten, Loopback-Erkennung und
    interaktivem Startmenue.
    Zweisprachig (Deutsch/Englisch): Die Ausgabesprache wird automatisch aus der
    Betriebssystemsprache ermittelt, kann per Parameter -Language <de|en>
    ueberschrieben werden und laesst sich in der GUI per DE/EN-Schalter live
    umschalten (GUI, Konsolen-Ausgabe und HTML-Report folgen der Auswahl).
    Beim Start wird das neueste GitLab-Release abgefragt (Timeout 3 s). Ist eine
    neuere Version veroeffentlicht, erscheint eine klickbare Update-Anzeige neben
    der Versionsnummer in der GUI bzw. eine Info-Zeile in der Konsole. Ohne
    Internet, hinter Proxy-Sperren oder per -NoUpdateCheck bleibt die Anzeige aus.
.PARAMETER FullRun
    Fuehrt alle Checks ohne Menue aus (fuer Scheduled Tasks).
.PARAMETER OnlyChecks
    Fuehrt nur die angegebenen Checks aus (z.B. '22_PrintSpooler','19_Unconstrained').
.PARAMETER NoInteractive
    Ueberspringt das Menue (= Full Run).
.PARAMETER OutputPath
    Zielordner fuer Log, CSV-Exporte und HTML-Report (Standard: C:\ScriptLog).
.PARAMETER Language
    Ausgabesprache 'de' oder 'en'. Standard: automatische Erkennung aus der
    Betriebssystemsprache (englische Windows-Oberflaeche => en, sonst de).
.PARAMETER NoUpdateCheck
    Unterdrueckt den Update-Check gegen die GitLab-Releases-API
    (fuer Luftschacht-/Airgap-Umgebungen oder streng firewalled Server).
.NOTES
    Autor   : Rocco Ammon
    Version : 2.7 (54 Checks, Internationalisierung DE/EN, Update-Anzeige GitLab)
    Sprache : automatisch aus dem Betriebssystem, sonst -Language <de|en>
    LogPfad : C:\ScriptLog
.EXAMPLE
    .\AD_HealthCheck.ps1
    .\AD_HealthCheck.ps1 -FullRun
    .\AD_HealthCheck.ps1 -FullRun -Language en
    .\AD_HealthCheck.ps1 -OnlyChecks '22_PrintSpooler'
#>

[CmdletBinding()]
param(
    [switch]$FullRun,
    [string[]]$OnlyChecks,
    [switch]$NoInteractive,
    [string]$OutputPath,
    # Ausgabesprache (de/en). Standard: automatische Erkennung aus der Betriebssystemsprache.
    # Ueberschreibung z.B. fuer Scheduled Tasks: -Language en
    [ValidateSet('de','en')]
    [string]$Language = '',
    # Update-Check gegen die GitLab-Releases-API unterdruecken (Airgap/Offline)
    [switch]$NoUpdateCheck,
    # Kein automatischer Neustart mit Administratorrechten.
    # Ohne diese Rechte lehnt Windows die DNS-/WMI-Abfragen ab (z.B. root\MicrosoftDNS).
    [switch]$NoElevate
)

#region ============================ VARIABLEN ================================

$Global:ScriptName      = "AD_Health_Check"
$Global:ScriptVersion   = "2.7"
$Global:NoUpdateCheck   = [bool]$NoUpdateCheck
$Global:Timestamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$Global:LogDirectory    = if ($OutputPath) { $OutputPath } else { "C:\ScriptLog" }
$Global:ReportDirectory = Join-Path $Global:LogDirectory "AD_HealthCheck_$Global:Timestamp"
$Global:LogFile         = Join-Path $Global:LogDirectory "$Global:ScriptName`_$Global:Timestamp.log"
$Global:HtmlReport      = Join-Path $Global:ReportDirectory "AD_HealthCheck_Report_$Global:Timestamp.html"
$Global:CsvDirectory    = Join-Path $Global:ReportDirectory "CSV"

# Schwellwerte
$Global:InactiveDaysUser     = 90
$Global:InactiveDaysComputer = 90
$Global:CertExpiryWarnDays   = 60
$Global:CertExpiryCritDays   = 14
$Global:KrbtgtMaxAgeDays     = 180
$Global:BackupMaxAgeDays     = 7
$Global:BackupCritAgeDays    = 14
$Global:EventLogHours        = 24
$Global:WUMaxAgeDaysWarn     = 35
$Global:WUMaxAgeDaysCrit     = 60
$Global:ReplFailuresWarn     = 1
$Global:ReplFailuresCrit     = 5
$Global:WinRMTimeoutSec      = 30
$Global:TombstoneMinDays     = 180
$Global:KerberoastPwdAgeWarn = 180
$Global:FGPPMinPasswordLength = 14
$Global:FGPPPasswordHistoryMin = 24
$Global:DNSAgingMinDays      = 7
# v2.9 Thresholds
$Global:KMSMinCountServer    = 5
$Global:KMSMinCountClient    = 25
$Global:StaleDCWarnAgeDays   = 0
$Global:RC4EventDays         = 7
$Global:RC4EventSampleLimit  = 5000
$Global:EncTypesAesCoverageMin = 90
$Global:DNSZoneRefreshMaxHours = 24
$Global:DNSZoneExpireMinDays   = 7
$Global:ReportOverviewFindingsMax = 5
$Global:SPNMaxObjSpns        = 20
$Global:SPNMaxDnsProbe       = 200
$Global:SPNInventoryMaxRows  = 200
$Global:SPNUserAccountClassWarn = @('User','InetOrgPerson')
# Reverse-Lookup-Zonen, die der DNS-Dienst automatisch anlegt (Default).
$Global:DNSDefaultReverseZones = @('0.in-addr.arpa','127.in-addr.arpa','255.in-addr.arpa')
# Systemzonen, die der DNS-Dienst selbst verwaltet.
$Global:DNSSystemZones       = @('TrustAnchors')

# Ping-Skip-Verhalten
$Global:SkipUnreachableDCs   = $true
$Global:PingCount            = 2
$Global:TryWinRMIfNoPing     = $true

# Container
$Global:Results           = [ordered]@{}
$Global:Assessments       = [ordered]@{}
$Global:DCConnectivity    = @{}
$Global:LocalIdentifiers  = $null
$Global:SelectedChecks    = @()
$Global:RunMode           = 'Full'

# Progress
$Global:ProgressStats = [ordered]@{
    TotalChecks=0; CompletedChecks=0; FailedChecks=0; CurrentDC=''; StartTime=$null
}

# Dienste mit Beschreibung
# Patterns = ASCII-sichere Regex-Muster (unabhaengig von Datei-Encoding UND OS-Sprache)
$Global:ServiceMap = [ordered]@{
    'NTDS'     = @{ Names=@('NTDS');      DisplayNames=@('Active Directory Domain Services','Active Directory-Domänendienste'); Patterns=@('^Active Directory'); Description='Active Directory Domain Services - Kerndienst.' }
    'DNS'      = @{ Names=@('DNS');       DisplayNames=@('DNS Server','DNS-Server'); Patterns=@('^DNS.Server','^DNS-Server'); Description='DNS Server - Namensaufloesung, SRV-Records.' }
    'Netlogon' = @{ Names=@('Netlogon');  DisplayNames=@('Netlogon','Netlogon (Anmeldedienst)','Anmeldedienst'); Patterns=@('^Netlogon','Anmeldedienst'); Description='Netlogon - Sicherer Kanal, Authentifizierung.' }
    'KDC'      = @{ Names=@('Kdc','KDC'); DisplayNames=@('Kerberos Key Distribution Center','Kerberos-Schlüsselverteilungscenter'); Patterns=@('^Kerberos'); Description='Kerberos KDC - Stellt Kerberos-Tickets aus.' }
    'W32Time'  = @{ Names=@('W32Time');   DisplayNames=@('Windows Time','Windows-Zeitgeber','Windows-Zeit'); Patterns=@('Windows[- ]Zeit'); Description='Windows-Zeit - Kerberos-Pflicht.' }
    'DFSR'     = @{ Names=@('DFSR');      DisplayNames=@('DFS Replication','DFS-Replikation'); Patterns=@('^DFS[- ]Replication','^DFS-Replikation'); Description='DFS Replication - Repliziert SYSVOL.' }
    'NTFRS'    = @{ Names=@('NtFrs');     DisplayNames=@('File Replication Service','Dateireplikationsdienst'); Patterns=@('File Replication','Dateireplikation'); Description='File Replication (LEGACY).' }
}

# Check-Gruppen fuer GUI UND HTML-Report (identisch, thematisch sortiert)
$Global:CheckGroups = [ordered]@{
    'DC-Infrastruktur' = @(
        '01_DCSystemInfo','02_Services','03_DCDiag','04_Replication','04b_ReplicationFailures',
        '05_FSMO','06_DNS','60_ZonenSOA','61_Forwarder','62_ReverseLookup','07_SYSVOL','08_Database','34_TimeSync','35_Backup'
    )
    'Security & Hardening' = @(
        '09_TLS','10_Cipher','11_SMB','12_NTLMAuth','13_LLMNR','14_LDAPSecurity',
        '15_WindowsFirewall','21_LSAProtection','22_PrintSpooler','23_SecureBoot','24_Certificates',
        '51_MachineAccountQuota','52_AnonymousLDAP','53_GPPPasswords'
    )
    'Identity & Kerberos' = @(
        '16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos','19_UnconstrainedDelegation',
        '20_KerberoastingRisk','38_SPNDuplicates','39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','43_LAPS','44_AccountsWithoutAES',
        '47_RCAESMigration','48_DCSyncPermissions','49_RBCDDelegation','50_dMSA','54_ProtectedUsers'
    )
    'AD-Topologie & Objekte' = @(
        '25_Sites','26_Subnets','27_Trusts','28_ADRecycleBin','29_TombstoneLifetime',
        '30_Levels','31_GPO','32a_InactiveUsers','32b_InactiveComputers','32c_PasswordNeverExpires'
    )
    'System & Updates' = @(
        '33_EventLog','36_InstalledPrograms','37_WindowsUpdates','42_DNSHygiene',
        '45_WindowsFeatures','46_Shares'
    )
}

# Report-Titel - THEMATISCH sortiert
$Global:ReportTitles = [ordered]@{
    '00_SkippedDCs'              = 'Uebersprungene DCs (nicht erreichbar)'
    '01_DCSystemInfo'            = 'DC System-Informationen'
    '02_Services'                = 'Dienste'
    '03_DCDiag'                  = 'DCDiag-Tests (detailliert)'
    '04_Replication'             = 'Replikation (Partner)'
    '04b_ReplicationFailures'    = 'Replikations-Fehler (Forest)'
    '05_FSMO'                    = 'FSMO-Rollen'
    '06_DNS'                     = 'DNS-Konfiguration'
    '60_ZonenSOA'                = 'DNS-Zonen: SOA & Replikation'
    '61_Forwarder'               = 'DNS-Forwarder & Conditional Forwarder'
    '62_ReverseLookup'           = 'DNS-Reverse-Lookup-Vollstaendigkeit'
    '07_SYSVOL'                  = 'SYSVOL & NETLOGON'
    '08_Database'                = 'NTDS-Datenbank'
    '09_TLS'                     = 'TLS-Protokolle (SCHANNEL)'
    '10_Cipher'                  = 'Cipher & Algorithmen'
    '11_SMB'                     = 'SMB1 & SMB-Signing'
    '12_NTLMAuth'                = 'NTLM / LAN-Manager Auth Level'
    '13_LLMNR'                   = 'LLMNR / NetBIOS / WPAD'
    '14_LDAPSecurity'            = 'LDAP-Security (Signing & Channel Binding)'
    '15_WindowsFirewall'         = 'Windows Firewall'
    '16_PrivilegedAccounts'      = 'Privilegierte Accounts'
    '17_PasswordPolicy'          = 'Password-Policy'
    '18_Kerberos'                = 'Kerberos / krbtgt'
    '19_UnconstrainedDelegation' = 'Kerberos Unconstrained Delegation'
    '20_KerberoastingRisk'       = 'Kerberoasting-Risiko (User mit SPN)'
    '21_LSAProtection'           = 'LSA Protection (RunAsPPL)'
    '22_PrintSpooler'            = 'Print Spooler auf DCs (PrintNightmare)'
    '23_SecureBoot'              = 'Secure Boot Zertifikats-Update (UEFI CA 2023)'
    '24_Certificates'            = 'Zertifikate'
    '25_Sites'                   = 'AD-Sites'
    '26_Subnets'                 = 'AD-Subnetze'
    '27_Trusts'                  = 'Vertrauensstellungen'
    '28_ADRecycleBin'            = 'AD Recycle Bin'
    '29_TombstoneLifetime'       = 'Tombstone Lifetime'
    '30_Levels'                  = 'Forest-/Domain-Level'
    '31_GPO'                     = 'GPO-Health'
    '32a_InactiveUsers'          = 'Inaktive User'
    '32b_InactiveComputers'      = 'Inaktive Computer'
    '32c_PasswordNeverExpires'   = 'Passwort laeuft nie ab'
    '33_EventLog'                = 'Event-Log-Auswertung'
    '34_TimeSync'                = 'Zeitsynchronisation'
    '35_Backup'                  = 'AD-Backup-Status'
    '36_InstalledPrograms'       = 'Installierte Programme'
    '37_WindowsUpdates'          = 'Windows Updates'
    '38_SPNDuplicates'           = 'SPN-Dubletten'
    '39_ASREPRoasting'           = 'AS-REP-Roasting-Risiko'
    '40_AdminSDHolderDrift'      = 'AdminSDHolder / AdminCount-Drift'
    '41_FGPP'                    = 'Fine-Grained Password Policies'
    '42_DNSHygiene'              = 'DNS-Hygiene (Aging / Scavenging)'
    '43_LAPS'                    = 'LAPS-Konfiguration (Local Admin Password Solution)'
    '44_AccountsWithoutAES'      = 'Konten ohne AES-Verschluesselung'
    '45_WindowsFeatures'         = 'Installierte Windows Features'
    '46_Shares'                  = 'SMB-Freigaben (Shares)'
    '47_RCAESMigration'          = 'RC4 -> AES Migrations-Audit (CVE-2026-20833)'
    '48_DCSyncPermissions'       = 'DCSync-Berechtigungen (Replikations-Rechte)'
    '49_RBCDDelegation'          = 'RBCD & Constrained Delegation'
    '50_dMSA'                    = 'dMSA / BadSuccessor (Delegated MSA)'
    '51_MachineAccountQuota'     = 'MachineAccountQuota (ms-DS-MachineAccountQuota)'
    '52_AnonymousLDAP'           = 'Anonymer LDAP-Zugriff'
    '53_GPPPasswords'            = 'GPP/cpassword in SYSVOL'
    '54_ProtectedUsers'          = 'Protected Users Audit'
}

#endregion

#region ==================== INTERNATIONALISIERUNG (DE/EN) ====================
# Sprachwahl:
#   1. Automatisch aus der Betriebssystemsprache (Get-UICulture)
#      => englisches Windows: 'en', alles andere: 'de'
#   2. Ueberschreibung per Parameter -Language <de|en> (z.B. Scheduled Tasks)
#   3. Live-Umschaltung ueber die DE/EN-Schalter in der GUI
# Alle sichtbaren deutschen Texte (GUI, Konsole, Log, HTML-Report) laufen durch
# Format-L10n. Rohdaten und CSV-Export bleiben technisch unveraendert.

function Get-SystemLanguage {
    <# Ermittelt die Ausgabesprache aus der Betriebssystemsprache des Rechners. #>
    try {
        if ((Get-UICulture).TwoLetterISOLanguageName -ieq 'en') { return 'en' }
    } catch { }
    return 'de'
}

function Set-HealthCheckLanguage {
    <# Setzt die Ausgabesprache zur Laufzeit (GUI-Schalter). #>
    param([Parameter(Mandatory)][ValidateSet('de','en')][string]$Code)
    $Global:Lang = $Code
    return $Global:Lang
}

# Startsprache: Parameter hat Vorrang, sonst Betriebssystemsprache
$Global:Lang = if ($Language) { $Language.ToLower() } else { Get-SystemLanguage }

# --- Uebersetzungstabelle, Zeilenformat:  Deutsch=>English  ---
$Global:L10nSource = @'
# ---- Check-Titel (GUI, Konsole, HTML-Report) ----
Uebersprungene DCs (nicht erreichbar)=>Skipped DCs (unreachable)
DC System-Informationen=>DC System Information
Dienste=>Services
DCDiag-Tests (detailliert)=>DCDiag Tests (detailed)
Replikation (Partner)=>Replication (partners)
Replikations-Fehler (Forest)=>Replication failures (forest)
FSMO-Rollen=>FSMO Roles
DNS-Konfiguration=>DNS Configuration
NTDS-Datenbank=>NTDS Database
TLS-Protokolle (SCHANNEL)=>TLS Protocols (SCHANNEL)
Cipher & Algorithmen=>Ciphers & algorithms
LDAP-Security (Signing & Channel Binding)=>LDAP Security (Signing & Channel Binding)
Privilegierte Accounts=>Privileged Accounts
Password-Policy=>Password Policy
Kerberoasting-Risiko (User mit SPN)=>Kerberoasting risk (users with SPN)
Print Spooler auf DCs (PrintNightmare)=>Print Spooler on DCs (PrintNightmare)
Secure Boot Zertifikats-Update (UEFI CA 2023)=>Secure Boot certificate update (UEFI CA 2023)
Zertifikate=>Certificates
AD-Sites=>AD Sites
AD-Subnetze=>AD Subnets
Vertrauensstellungen=>Trust relationships
Forest-/Domain-Level=>Forest / domain level
GPO-Health=>GPO Health
Inaktive User=>Inactive users
Inaktive Computer=>Inactive computers
Passwort laeuft nie ab=>Passwords that never expire
Event-Log-Auswertung=>Event log analysis
Zeitsynchronisation=>Time synchronisation
AD-Backup-Status=>AD backup status
Installierte Programme=>Installed programs
SPN-Dubletten=>Duplicate SPNs
AS-REP-Roasting-Risiko=>AS-REP roasting risk
DNS-Hygiene (Aging / Scavenging)=>DNS hygiene (aging / scavenging)
LAPS-Konfiguration (Local Admin Password Solution)=>LAPS configuration (Local Admin Password Solution)
Konten ohne AES-Verschluesselung=>Accounts without AES encryption
Installierte Windows Features=>Installed Windows features
SMB-Freigaben (Shares)=>SMB shares
RC4 -> AES Migrations-Audit (CVE-2026-20833)=>RC4 -> AES migration audit (CVE-2026-20833)
DCSync-Berechtigungen (Replikations-Rechte)=>DCSync permissions (replication rights)
Anonymer LDAP-Zugriff=>Anonymous LDAP access
# ---- Check-Gruppen / GUI-Kategorien ----
DC-Infrastruktur=>DC Infrastructure
AD-Topologie & Objekte=>AD topology & objects
Allgemein=>General
# ---- GUI ----
Waehlen Sie die gewuenschten Pruefungen und den Ausgabepfad.=>Select the desired checks and the output path.
Ausgabepfad:=>Output path:
Ausgabepfad waehlen=>Select output path
Durchsuchen...=>Browse...
Alle auswaehlen=>Select all
Checks ausgewaehlt=>checks selected
Check(s)=>check(s)
Checks=>checks
Health Check starten=>Start Health Check
Bitte mindestens einen Check auswaehlen.=>Please select at least one check.
Hinweis=>Notice
Sprache:=>Language:
Abbrechen=>Cancel
Update verfügbar: =>Update available: 
 (aktuell => (currently 
Oeffnet die Release-Seite dieses Projekts.=>Opens the release page of this project.
Keine=>No
Keine Fehler=>No errors
Keine erreichbaren DCs=>No reachable DCs
fehlt=>missing
dMSA mit Superseding gefunden=>dMSA with Superseding found
uebersprungen=>skipped
Bis zu =>up to 
Alter Client (=>Old client (
 ohne AES-Attribute - nutzt vermutlich RC4, nach RC4-Abschaltung pruefen/migrieren=> without AES attributes - probably uses RC4, review/migrate after the RC4 shutdown
 ohne aktuelle geschuetzte Gruppenmitgliedschaft=> without current protected group membership
DFS-Replikation=>DFS replication
# ---- HTML-Report ----
Erstellt:=>Created:
Modus:=>Mode:
Uebersicht aller Checks=>Overview of all checks
Zusammenfassung:=>Summary:
Zusammenfassung=>Summary
Auffaelligkeiten / Handlungsempfehlungen:=>Findings / recommendations:
Auffaelligkeiten=>findings
Auffaelligkeit(en)=>finding(s)
Keine Daten.=>No data.
Erzeugt von=>Generated by
Laufzeit:=>Runtime:
WARNUNGEN=>WARNINGS
WARNUNG=>WARNING
KRITISCH=>CRITICAL
Zeilen (Status:=>rows (status:
-> leer=>-> empty
Eintraege=>entries
Keine Eintraege.=>No entries.
# ---- Konsolen-Banner, Menue und Fortschritt ----
VERFUEGBARE CHECKS=>AVAILABLE CHECKS
AUSWAHLMENUE=>SELECTION MENU
BEST-PRACTICE-BEWERTUNG=>BEST-PRACTICE ASSESSMENT
CSV-EXPORT=>CSV EXPORT
HTML-REPORT=>HTML REPORT
DC-ERKENNUNG=>DC DISCOVERY
CONNECTIVITY-TEST=>CONNECTIVITY TEST
PRO-DC-CHECKS=>PER-DC CHECKS
FOREST-WEITE CHECKS=>FOREST-WIDE CHECKS
AD HEALTH CHECK ABGESCHLOSSEN=>AD HEALTH CHECK COMPLETED
Gesamtdauer=>Total duration
Ausgefuehrte Checks=>Completed checks
Davon Fehler=>Of which failed
Best-Practice-Bewertung=>Best-practice assessment
UEBERSPRUNGENE DCs=>SKIPPED DCS
UEBERSPRUNGEN:=>Skipped:
CSV-Ordner=>CSV folder
Log-Datei=>Log file
Ausgewaehlte Checks:=>Selected checks:
Gefundene DCs:=>DCs found:
Gesamt:=>Total:
Erreichbar:=>Reachable:
Uebersprungen:=>Skipped:
Methode:=>Method:
kein Ping, aber WinRM OK=>no ping, but WinRM OK
uebersprungen:=>skipped:
Abbruch durch Benutzer.=>Cancelled by user.
[i] Administratorrechte fehlen - DNS-/WMI-Abfragen werden ohne erhoehte Rechte abgelehnt.=>[i] Administrator rights are missing - DNS/WMI queries are rejected without elevated rights.
[i] Starte das Skript mit Administratorrechten neu (UAC-Bestaetigung erforderlich).=>[i] Restarting the script with administrator rights (UAC confirmation required).
[i] Die erhoehte Instanz wurde gestartet; dieses Fenster kann geschlossen werden.=>[i] The elevated instance has been started; this window can be closed.
[!] Neustart abgelehnt oder fehlgeschlagen: =>[!] Restart declined or failed: 
[i] Es wird ohne erhoehte Rechte weitergemacht - einzelne Checks werden fehlschlagen.=>[i] Continuing without elevated rights - individual checks will fail.
Keine Administratorrechte - Neustart mit erhoehten Rechten.=>No administrator rights - restarting with elevated rights.
Elevation abgelehnt: =>Elevation declined: 
Ungueltige Check-Keys:=>Invalid check keys:
Verfuegbar:=>Available:
Full Run   - Alle Checks (empfohlen)=>Full Run   - all checks (recommended)
Einzel     - Genau EINEN Check=>Single     - exactly ONE check
Mehrere    - Mehrere Checks (Komma-Liste)=>Multiple   - several checks (comma separated)
Forest     - Nur Forest-weite Checks=>Forest     - forest-wide checks only
Pro-DC     - Nur DC-spezifische Checks=>Per-DC     - DC-specific checks only
Security   - Komplette Security-Suite=>Security   - complete security suite
Liste      - Alle verfuegbaren Checks=>List       - all available checks
Quit       - Abbrechen=>Quit       - exit
Ihre Auswahl=>Your selection
[ENTER] fuer Menue=>[ENTER] for menu
[!] Abbruch.=>[!] Cancelled.
[X] Ungueltig=>[X] Invalid
Erneut versuchen? (J/N)=>Try again? (Y/N)
Geben Sie Nummer ODER Key ein (oder 'B' = zurueck):=>Enter number OR key (or 'B' = back):
Geben Sie Nummern/Keys komma-getrennt ein (z.B. '1,3,5') oder 'B' = zurueck:=>Enter numbers/keys separated by commas (e.g. '1,3,5') or 'B' = back:
[LOKAL]=>[LOCAL]
[und =>[and 
mehrdeutig:=>ambiguous:
nicht erkannt=>not recognised
Nummer=>Number
ausserhalb (=>outside (
Laufzeit:=>Runtime:
Modul '=>Module '
geladen.=>loaded.
nicht ladbar:=>not loadable:
# ---- Konnektivitaet / allgemeine Statusmeldungen ----
Kein Ping=>No ping
Alle Methoden fehlgeschlagen:=>All methods failed:
Kein Ping UND kein WinRM/CIM/WMI=>No ping AND no WinRM/CIM/WMI
WinRM/CIM/WMI alle fehlgeschlagen=>WinRM/CIM/WMI all failed
Keine Daten=>No data
Keine Bewertung=>No assessment
Fehler:=>Error:
FEHLER:=>ERROR:
Fehler=>errors
# ---- Spaltenueberschriften ----
Aktiv=>Active
Benutzer=>Users
Datei=>File
Einstellung=>Setting
Gruppen=>Groups
IstStandardTraeger=>IsStandardHolder
KontoPrivilegiert=>AccountPrivileged
ObjektTyp=>ObjectType
Privilegiert=>Privileged
Prinzipal=>Principal
PrinzipalTyp=>PrincipalType
Protokollwechsel=>ProtocolTransition
Rechte=>Rights
UebernommenesKonto=>SupersededAccount
Wert=>Value
Ziel=>Target
# ---- Zellwerte und Statusmeldungen der Datensammlung ----
NICHT KONFIGURIERT (= deaktiviert!)=>NOT CONFIGURED (= disabled!)
NICHT KONFIGURIERT (Default=3)=>NOT CONFIGURED (default=3)
NICHT KONFIGURIERT (Risiko!)=>NOT CONFIGURED (risk!)
NICHT KONFIGURIERT=>NOT CONFIGURED
(nicht gesetzt)=>(not set)
nicht gesetzt=>not set
Secure Boot nicht aktiv=>Secure Boot not active
Registry-Fehler=>Registry error
 gesetzt - wartet auf Reboot=> set - waiting for reboot
nicht gesetzt=>not set
Geraet NICHT faehig - Firmware-Update pruefen=>Device NOT capable - check firmware update
Hinweis:=>Note:
noch offen=>still pending
Reboot empfohlen=>reboot recommended
(keine Zertifikate)=>(no certificates)
(keine Daten)=>(no data)
Spooler gestoppt und deaktiviert - PrintNightmare-sicher=>Spooler stopped and disabled - PrintNightmare-safe
Spooler LAEUFT auf DC! PrintNightmare-Risiko=>Spooler RUNNING on DC! PrintNightmare risk
Enabled - aktiv=>Enabled - active
RunAsPPL=1 - aktiv. Tipp: Auf 2 erhoehen=>RunAsPPL=1 - active. Tip: raise to 2
RunAsPPL NICHT gesetzt - Default deaktiviert=>RunAsPPL NOT set - disabled by default
SMB1 AKTIV (WannaCry-Risiko!)=>SMB1 ENABLED (WannaCry risk!)
SMB-Signing NICHT erzwungen=>SMB signing not enforced
 - OK, aber 5 ist besser=> - OK, but 5 is better
AD Recycle Bin NICHT aktiv - kein Restore geloeschter Objekte (ausser Backup)=>AD Recycle Bin NOT enabled - no restore of deleted objects (except backup)
AD Recycle Bin aktiv=>AD Recycle Bin enabled
Abfrage-Fehler:=>Query error:
Keine Zuordnung=>No mapping
Server-weites Scavenging aktiviert=>Server-wide scavenging enabled
Server-weites Scavenging deaktiviert=>Server-wide scavenging disabled
nicht AD-integriert=>not AD-integrated
DynamicUpdate='None' auf AD-Zone - Eintraege werden nicht dynamisch registriert=>DynamicUpdate='None' on an AD zone - records are not registered dynamically
SOA-Abfrage fehlgeschlagen auf =>SOA query failed on 
kein DC mit auswertbaren DNS-Zonen (DNS-Abfrage fehlgeschlagen: =>no DC with evaluable DNS zones (DNS query failed: 
kein DNS-Server auswertbar (=>no DNS server evaluable (
keine DNS-Server gefunden=>no DNS servers found
kein MasterServer hinterlegt - Conditional Forwarder kann keine Aufloesung leisten=>no master server configured - the conditional forwarder cannot resolve
nachfolgende DNS-Server ohne Ziel-IP hinterlegt: =>following DNS servers without a target IP: 
Forwarder-Ziel ist ein eigener DNS-Server (=>forwarder target is one of our own DNS servers (
) - kann Weiterleitungsschleife verursachen=>) - may cause a forwarding loop
hinterlegt auf =>configured on 
Kein _vlmcs SRV-Eintrag=>no _vlmcs SRV record
Dienst nicht lauffaehig =>service not running 
Port nicht abhoerend=>port not listening
Aktivierungen < Server-Min=>activations below server min
Anfragen < Client-Min=>requests below client min
Port != 1688=>port != 1688
Kein Host-Key =>no host key
Key-Kanal != Volume=>key channel != Volume
Mehr als 50% Fehlanfragen=>more than 50% failed requests
Nur ein KMS-Host =>only one KMS host
Kein _vlmcs SRV-Eintrag=>no _vlmcs SRV record
Dienst nicht lauffaehig=>service not running
Port nicht abhoerend=>port not listening
Aktivierungen < Server-Min=>activations below server min
Anfragen < Client-Min=>requests below client min
Port != 1688=>port != 1688
Kein Host-Key =>no host key
Key-Kanal != Volume=>key channel != Volume
Mehr als 50% Fehlanfragen=>more than 50% failed requests
Nur ein KMS-Host=>only one KMS host
Globaler Forwarder=>Global Forwarder
Conditional Forwarder=>Conditional Forwarder
Root Hints=>Root Hints
Kein globaler Forwarder auf keinem DNS-Server konfiguriert=>no global forwarder configured on any DNS server
Inkonsistente globale Forwarder=>inconsistent global forwarders
Globale Forwarder konsistent=>global forwarders consistent
Nur teilweise verteilt=>partially distributed
Kein MasterServer hinterlegt - Conditional Forwarder kann keine Aufloesung leisten=>no master server configured - the conditional forwarder cannot resolve
Keine Root Hints auf keinem DNS-Server=>no root hints on any DNS server
Inkonsistente Root Hints=>inconsistent root hints
Root Hints konsistent=>root hints consistent
Kein globaler Forwarder UND keine Root-Hints -> externe Aufloesung moeglicherweise nicht moeglich=>no global forwarder AND no root hints - external resolution may not be possible 
SOA-Intervalle (Refresh/Expire) nicht auslesbar - Schwellen koennen nicht geprueft werden=>SOA intervals (refresh/expire) not readable - thresholds cannot be checked
Keine Reverse-Lookup-Zonen gefunden=>No reverse lookup zones found
DNS-Reverse-Lookup-Vollstaendigkeit=>DNS reverse lookup completeness
Keine erreichbaren DCs mit IPv4=>No reachable DCs with IPv4
Keine DNS-Zonen vom DC abrufbar=>No DNS zones retrievable from DC
Keine A/AAAA Records in Forward-Zonen gefunden=>No A/AAAA records found in forward zones
Alle Forward-IPs haben eine passende Reverse-Zone=>All forward IPs have a matching reverse zone
Fehlende Reverse-Zone: =>Missing reverse zone: 
 betrifft => affecting 
 IP(s) => IP(s) 
Forward-Zone: =>Forward zone: 
IP: =>IP: 
Host: =>Host: 
Abfrage fehlgeschlagen: =>Query failed:
DNS-Reverse-Lookup-Vollstaendigkeit=>DNS reverse lookup completeness
Keine erreichbaren DCs mit IPv4=>No reachable DCs with IPv4
Keine DNS-Zonen vom DC abrufbar=>No DNS zones retrievable from DC
Keine A/AAAA Records in Forward-Zonen gefunden=>No A/AAAA records found in forward zones
Alle Forward-IPs haben eine passende Reverse-Zone=>All forward IPs have a matching reverse zone
Fehlende Reverse-Zone: =>Missing reverse zone: 
 betrifft => affecting 
 IP(s) => IP(s) 
Forward-Zone: =>Forward zone: 
IP: =>IP: 
Host: =>Host: 
Abfrage fehlgeschlagen: =>Query failed:
NICHT aktiviert=>NOT enabled
Aktiviert=>Enabled
LAPS Schema-Erweiterung nicht installiert=>LAPS schema extension not installed
Computer mit LAPS=>Computers with LAPS
Keine Computer gefunden=>No computers found
WARNUNG: Kein Computer mit LAPS konfiguriert!=>WARNING: No computer with LAPS configured!
 mit LAPS | => with LAPS | 
mit nicht-unterstuetztem OS (2016 oder aelter)=>with unsupported OS (2016 or older)
 | OS NICHT UNTERSTUETZT (LAPS ab 2019)=> | OS NOT SUPPORTED (LAPS requires 2019+)
Nicht konfiguriert - OS: =>Not configured - OS: 
KRITISCH: LAPS konfiguriert aber OS nicht unterstuetzt=>CRITICAL: LAPS configured but OS not supported
LAPS benoetigt 2019+=>LAPS requires 2019+
KRITISCH: User mit RC4/DES OHNE AES!=>CRITICAL: user with RC4/DES WITHOUT AES!
User ohne AES konfiguriert=>User without AES configured
User mit RC4+AES: Ermoeglicht Downgrade-Angriffe=>User with RC4+AES: allows downgrade attacks
KRITISCH: Computer mit RC4/DES OHNE AES!=>CRITICAL: computer with RC4/DES WITHOUT AES!
Computer ohne AES konfiguriert=>Computer without AES configured
Computer mit RC4+AES: Ermoeglicht Downgrade-Angriffe=>Computer with RC4+AES: allows downgrade attacks
(alle Konten)=>(all accounts)
Alle Konten: Standard-Verschluesselung (AES) aktiv, keine RC4-Only Konfiguration=>All accounts: standard encryption (AES) enabled, no RC4-only configuration
(Fehler)=>(error)
Dienst (SPN)=>Service (SPN)
Konto=>Account
Konten=>accounts
Dienstkonto (SPN) OHNE msDS-SupportedEncryptionTypes - KDC stellt derzeit RC4-Tickets aus, Ausfall nach RC4-Abschaltung (Juli 2026). AES aktivieren + Passwort/PwdLastSet aktualisieren=>Service account (SPN) WITHOUT msDS-SupportedEncryptionTypes - the KDC currently issues RC4 tickets, outage after the RC4 shutdown (July 2026). Enable AES and update password/PwdLastSet
unterstuetzt DES (=>supports DES (
 - bricht nach RC4/DES-Abschaltung, AES ist Pflicht=> - breaks after RC4/DES shutdown, AES is mandatory
 - bricht nach RC4/DES-Abschaltung=> - breaks after RC4/DES shutdown
: KEIN AES - bricht nach RC4-Abschaltung (Juli 2026). Migration: AES aktivieren, Passwort zuruecksetzen=>: NO AES - breaks after RC4 shutdown (July 2026). Migration: enable AES, reset password
ermoeglicht Downgrade auf RC4 - nach AES-Migration RC4-Flag entfernen=>allows downgrade to RC4 - remove the RC4 flag after AES migration
: Downgrade auf RC4 moeglich=>: downgrade to RC4 possible
(nicht lesbar)=>(not readable)
; Aktiv==>; Active=
Registry-Wert 'SupportedEncryptionTypes' nicht auslesbar=>Registry value 'SupportedEncryptionTypes' not readable
(kein WinRM)=>(no WinRM)
KDC erlaubt explizit RC4=>KDC explicitly allows RC4
 - nach Migration auf AES-only (0x18) setzen=> - set to AES-only (0x18) after migration
 geprueft | ohne AES-Attribute: => checked | without AES attributes: 
 problembehaftet: => with issues: 
 || WICHTIG: => || IMPORTANT: 
RC4 wird 2026 abgeschaltet=>RC4 will be shut down in 2026
alle problembehafteten Konten VORHER auf AES migrieren=>migrate all affected accounts to AES beforehand
Standard-Rechteinhaber=>Standard permission holders
NICHT-Standard-Principal=>Non-standard principal
volle DCSync-Faehigkeit: alle Passwort-Hashes der Domain extrahierbar!=>full DCSync capability: all domain password hashes can be extracted!
Replikations-Rechte ohne=>Replication rights without
kein Hash-Zugriff, aber Replikation lesbar=>no hash access, but replication readable
Rechtnotwendigkeit pruefen=>review whether the rights are necessary
(keine)=>(none)
Keine Replikations-Rechte auf dem Domain-NC gefunden=>No replication rights found on the domain NC
USER mit RBCD-Recht auf=>USER with RBCD right on
kompromittierte User-Credentials erlauben Delegation/PrivEsc auf diesen Computer=>compromised user credentials allow delegation / privilege escalation on this computer
RBCD-Prinzipal=>RBCD principal
 darf auf => may delegate to 
 uebliche Bastion/Management-Konfiguration, Noetigkeit pruefen=> common bastion/management configuration, review whether it is necessary
Constrained Delegation an:=>Constrained delegation to:
Protokollwechsel (S4U2Self):=>Protocol transition (S4U2Self):
 - Protokollwechsel ermoeglicht TGT-Erwerb ohne Passwort, Ziel-SPNs pruefen=> - protocol transition allows TGT acquisition without a password, check the target SPNs
Schema-Klasse nicht vorhanden (kein Windows Server 2025 Schema) - BadSuccessor nicht anwendbar=>Schema class not present (no Windows Server 2025 schema) - BadSuccessor not applicable
(keine dMSA)=>(no dMSA)
Schema vorhanden, aber keine dMSA-Objekte gefunden - BadSuccessor-Angriffsvektor derzeit nicht genutzt=>Schema present, but no dMSA objects found - BadSuccessor attack vector not in use at the moment
2 (Migration abgeschlossen - Superseding AKTIV)=>2 (migration completed - superseding ACTIVE)
0 (keine Migration)=>0 (no migration)
BADSUCCESSOR-MUSTER: dMSA uebernimmt PRIVILEGIELIERTES Konto=>BADSUCCESSOR PATTERN: dMSA takes over a PRIVILEGED account
(adminCount=1) - Tickets des dMSA gelten mit dessen Rechten! Objekt pruefen und ggf. loeschen=>(adminCount=1) - tickets of the dMSA carry those privileges! Review the object and delete it if necessary
dMSA uebernimmt Konto=>dMSA takes over account
(Migration abgeschlossen) - legitim nur wenn beabsichtigt, sonst Takeover-Pfad=>(migration completed) - legitimate only if intended, otherwise a takeover path
Superseding AKTIV, aber kein uebernommenes Konto lesbar - Zustand pruefen=>Superseding ACTIVE, but no superseded account readable - check the state
dMSA existiert (State=>dMSA exists (state=
dMSA-Objekte sind neue Angriffsflaechen: Wer darf sie erstellen/aendern? (Write-Rechte auf Ziel-OU pruefen)=>dMSA objects are new attack surfaces: who may create/modify them? (check write permissions on the target OU)
 (Wert nicht lesbar - Default 10 angenommen)=> (value not readable - assuming default 10)
MAQ=0 - Benutzer koennen keine Computerkonten erstellen (Best Practice)=>MAQ=0 - users cannot create computer accounts (best practice)
 Computerkonten pro Benutzer erstellbar. Angreifer koennen so eigene Computerkonten fuer Enrollment/Delegation/ADCS-Angriffe anlegen. Empfehlung: => computer accounts can be created per user. Attackers can create their own computer accounts for enrollment / delegation / ADCS attacks. Recommendation: 
Anonym ohne Anmeldung lesbar=>Readable anonymously without authentication
AD-Struktur fuer Angreifer ausforschbar=>AD structure can be enumerated by attackers
Anonyme RootDSE-Abfrage liefert keine NC-Informationen (Windows-Default) - OK=>Anonymous RootDSE query returns no NC information (Windows default) - OK
Anonymer LDAP-Bind wurde abgelehnt (Default ab Server 2003) - OK=>Anonymous LDAP bind was rejected (default since Server 2003) - OK
dSHeuristics gesetzt: '=>dSHeuristics set: '
Heuristiken koennen u.a. anonymen LDAP-Zugriff erweitern (Position 7). Noetigkeit pruefen=>heuristics can, among other things, extend anonymous LDAP access (position 7). Review whether they are necessary
dSHeuristics nicht gesetzt (Windows-Default) - OK=>dSHeuristics not set (Windows default) - OK
SYSVOL-Pfad nicht erreichbar=>SYSVOL path not reachable
Klartext-dechiffrierbares Passwort in GPP-XML (cpassword) - entschluesselbar durch JEDES domaeneangemeldete Konto (MS14-025). Passwort SOFORT setzen und Datei bereinigen=>Password in GPP XML (cpassword) decryptable in clear text - decryptable by EVERY domain-joined account (MS14-025). Change the password IMMEDIATELY and clean up the file
Keine cpassword-Eintraege in =>No cpassword entries in 
 GPP-XML-Dateien gefunden - OK=> GPP-XML files found - OK
GESAMT =>TOTAL 
 Funde - Anzeige auf => matches - display limited to 
 Zeilen begrenzt, uebrige Funde nicht aufgelistet=> rows, remaining matches not listed
Mitglieder von '=>Members of '
 nicht auslesbar (fremde Domain/Vertrauensstellung?): => not readable (foreign domain/trust?): 
Built-in Administrator NICHT in Protected Users (Break-Glass - Ausnahme oft beabsichtigt, trotzdem dokumentieren)=>Built-in administrator NOT in Protected Users (break-glass - exception is often intentional, but document it anyway)
Privilegiertes Konto NICHT in Protected Users - erhaelt weiterhin volle NTLM/NetNTLM/DES-Faehigkeiten. Empfehlung: aufnehmen (Ausnahme: dokumentiertes Break-Glass-Konto)=>Privileged account NOT in Protected Users - still has full NTLM/NetNTLM/DES capabilities. Recommendation: add it (exception: documented break-glass account)
Gruppe mit RID 525 nicht gefunden - Domain Level < 2012? Protected Users nicht verfuegbar=>Group with RID 525 not found - domain level < 2012? Protected Users not available
# ---- Bewertungen (Summary / Findings) ----
Alle DCs erreichbar=>All DCs reachable
DC(s) nicht erreichbar=>DC(s) not reachable
KRIT:=>CRITICAL:
KRITISCH:=>CRITICAL:
WARN:=>WARNING:
WARNUNG:=>WARNING:
DC(s) OK=>DC(s) OK
auf=>on
und=>and
nicht=>not
mit=>with
fuer=>for
Alle Dienste OK (NTFRS gestoppt = Best Practice)=>All services OK (NTFRS stopped = best practice)
DFSR auf =>DFSR on 
 - SYSVOL-Replizierung betroffen!=> - SYSVOL replication affected!
NTFRS (LEGACY) laeuft auf=>NTFRS (LEGACY) running on
nur noetig, wenn SYSVOL noch via FRS repliziert wird=>only required if SYSVOL is still replicated via FRS
Warnung=>Warning
Alle =>All 
Keine Partner=>No partners
Fehler=>errors
Alle synchron=>All in sync
Replikations-Fehler=>replication failures
Keine Zonen=>No zones
SYSVOL/NETLOGON auf =>SYSVOL/NETLOGON on 
nicht deaktiviert=>not disabled
AKTIV=>ACTIVE
nicht explizit aktiviert=>not explicitly enabled
Keine Cipher (Defaults)=>No ciphers (defaults)
Schwach:=>Weak:
LLMNR/NetBIOS/WPAD aus=>LLMNR/NetBIOS/WPAD disabled
Channel Binding NICHT aktiv=>Channel Binding NOT enabled
LDAPS Port 636 NICHT erreichbar=>LDAPS port 636 NOT reachable
Alle Firewall-Profile aktiv=>All firewall profiles enabled
inaktiv=>inactive
krbtgt-Passwort=>krbtgt password
Passwort=>password
alt - RESET!=>old - RESET!
alt=>old
alt oder NeverExpires=>old or NeverExpires
Privilegierter Account mit SPN!=>privileged account with SPN!
kann auf 2 (UEFI) erhoeht werden=>can be raised to 2 (UEFI)
RunAsPPL nicht gesetzt=>RunAsPPL not set
SUCCESS aber Bit=>SUCCESS but bit
 (Reboot empfohlen)=> (reboot recommended)
ABGELAUFEN:=>EXPIRED:
 Zertifikate, => certificates, 
 ohne Daten=> without data
Keine Sites=>No sites
Keine Subnetze!=>No subnets!
Keine Trusts=>No trusts
Keine GPOs=>No GPOs
Keine Errors in=>No errors in
KEIN AD-Backup!=>NO AD BACKUP!
keine Daten=>no data
Alle aktuell=>All current
Freigabe '=>share '
' erlaubt '=>' allows '
 mit Full/Change-Zugriff=> with full/change access
ohne PreAuth, Passwort alt/NeverExpires=>without PreAuth, password old/NeverExpires
Keine Fine-Grained Policies=>No fine-grained policies
LAPS-Daten nicht verfuegbar=>LAPS data not available
KRITISCH: LAPS Schema-Erweiterung ist NICHT installiert!=>CRITICAL: LAPS schema extension is NOT installed!
Computer mit nicht-unterstuetztem OS (Server 2016 oder aelter)=>computers with unsupported OS (Server 2016 or older)
 der Computer (=> of the computers (
) haben LAPS konfiguriert (alle Systeme unterstuetzen LAPS)=>) have LAPS configured (all systems support LAPS)
WARNUNG: =>WARNING: 
 der Computer mit LAPS konfiguriert. Unconfigured: => of the computers with LAPS configured. Unconfigured: 
KRITISCH: Nur=>CRITICAL: Only
 der Computer mit LAPS konfiguriert!=> of the computers with LAPS configured!
NICHT UNTERSTUETZT=>NOT SUPPORTED
weitere Systeme ohne LAPS]=>more systems without LAPS]
Keine AES-Daten verfuegbar=>No AES data available
Verschluesselung: Standard-AES aktiv, keine RC4-Only Konfigurationen gefunden=>Encryption: standard AES enabled, no RC4-only configurations found
 Konten geprueft | => accounts checked | 
Keine RC4/AES-Migrationsdaten=>No RC4/AES migration data
... und =>... and 
 weitere Befunde (siehe Detailtabelle/CSV)=> more findings (see detail table/CSV)
 weitere Eintraege (siehe Detailtabelle/CSV)=> more entries (see detail table/CSV)
 kritische | => critical | 
Warnung(en)=>warning(s)
 - RC4-Migration (=> - RC4 migration (
Keine DCSync-Daten=>No DCSync data
DCSync-Rechte ausserhalb der DCs=>DCSync rights outside the DCs
Hash-Extraktion moeglich!=>hash extraction possible!
 Rechteinhaber | => permission holders | 
Nicht-Standard:=>Non-standard:
 (davon mit Get-Changes-All: => (of which with Get-Changes-All: 
 Eintraege (RBCD => entries (RBCD 
Keine dMSA-Daten=>No dMSA data
Schema-Klasse nicht vorhanden - BadSuccessor nicht anwendbar=>Schema class not present - BadSuccessor not applicable
BADSUCCESSOR-MUSTER PRUEFEN!=>CHECK BADSUCCESSOR PATTERN!
dMSA-Objekt(e), kein Superseding aktiv - Objekte auf Missbrauch pruefen=>dMSA object(s), no Superseding active - check the objects for misuse
Keine dMSA-Objekte - BadSuccessor-Vektor nicht vorhanden=>No dMSA objects - BadSuccessor vector not present
Keine MAQ-Daten=>No MAQ data
Keine LDAP-Anonym-Daten=>No LDAP anonymous data
 Pruefpunkt(e) - anonymer LDAP-Zugriff=> check point(s) - anonymous LDAP access
Keine SYSVOL-Daten=>No SYSVOL data
 - cpassword gefunden=> - cpassword found
 weitere Funde=> more matches
 GPP-XML(s) mit entschluesselbarem cpassword=> GPP-XML file(s) with decryptable cpassword
Keine cpassword-Eintraege in SYSVOL=>No cpassword entries in SYSVOL
Keine Protected-Users-Daten=>No Protected Users data
 weitere Konten ohne Protected-Users-Mitgliedschaft=> more accounts without Protected Users membership
 privilegierte Konten in Protected Users=> privileged accounts in Protected Users
Alle 5 FSMO OK=>All 5 FSMO OK
Keine Unconstrained Delegation=>No unconstrained delegation
Keine User mit SPN=>No users with SPN
Keine inaktiven User=>No inactive users
Keine inaktiven Computer=>No inactive computers
Keine PwdNeverExpires=>No PwdNeverExpires
inaktive User=>inactive users
inaktive Computer=>inactive computers
Keine Subnetze=>No subnets
Auffaelligkeit(en)=>finding(s)
# ---- allgemeue Worte und Spaltenwerte ----
Ja=>Yes
Nein=>No
Aktiv=>Active
aktiv=>active
Aktiviert=>Enabled
aktiviert=>enabled
deaktiviert=>disabled
unbekannt=>unknown
nicht konfiguriert=>not configured
inaktive=>inactive
inaktiven=>inactive
Eintrag=>entry
Zertifikat=>certificate
Replikations-Fehler=>replication failures
'@

# --- Tabelle + Regex aufbauen -------------------------------------------------
function ConvertTo-L10nCanonical {
    <#
    .SYNOPSIS
        Normalisiert Umlaut-Schreibweisen auf die ASCII-Kanoform der Tabelle.
    .NOTES
        Das Skript schreibt Teile der deutschen Quelltexte als "ue"/"ae"/"oe"
        und andere mit echtem Umlaut ("ue"/"ü"). Damit beide Formen denselben
        Tabelleneintrag finden, wird der Fundtext vor dem Nachschlagen normalisiert.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $Text -notmatch '[äöüÄÖÜß]') { return $Text }
    $t = [regex]::Replace($Text, '[äÄ]', 'ae')
    $t = [regex]::Replace($t,     '[öÖ]', 'oe')
    $t = [regex]::Replace($t,     '[üÜ]', 'ue')
    $t = [regex]::Replace($t,     '[ß]',  'ss')
    return $t
}

function Initialize-L10nDictionary {
    <# Baut die deutsche=>englische Uebersetzungstabelle samt Regex auf. #>
    $Global:L10nMap = @{}
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Global:L10nSource -split "`r?`n")) {
        if (-not $line -or $line.TrimStart().StartsWith('#')) { continue }
        $sep = $line.IndexOf('=>')
        if ($sep -lt 1) { continue }
        $srcTxt = $line.Substring(0, $sep)
        $dstTxt = $line.Substring($sep + 2)
        if ([string]::Equals($srcTxt, $dstTxt, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($Global:L10nMap.ContainsKey($srcTxt)) { continue }
        $Global:L10nMap[$srcTxt] = $dstTxt
        # Kanonische Form ebenfalls hinterlegen ("Unterstützung" -> Schlüssel "Unterstuetzung")
        $srcNorm = ConvertTo-L10nCanonical -Text $srcTxt
        if (-not [string]::Equals($srcNorm, $srcTxt, [System.StringComparison]::Ordinal) -and
            -not $Global:L10nMap.ContainsKey($srcNorm)) { $Global:L10nMap[$srcNorm] = $dstTxt }
        $keys.Add($srcTxt)
    }
    # Laengste Zuerst: "Replikations-Fehler" muss vor "Fehler" greifen
    # Hinweis: Das Skript mischt Umschrift und Umlaute ("unterstuetzt" UND "unterstützt"),
    # deshalb matcht jeder Eintrag beide Schreibweisen (ae|ä, oe|ö, ue|ü, ss|ß).
    $umlautMap = @{ 'ae' = 'ä'; 'oe' = 'ö'; 'ue' = 'ü'; 'ss' = 'ß' }
    $digraphRx = [regex]'(?:ae|oe|ue|ss)'
    $parts = foreach ($entry in (@($keys) | Sort-Object -Property Length -Descending | Select-Object -Unique)) {
        $p = [regex]::Escape($entry)
        # Einzelschritt ersetzen (kein Delegate - sonst greift die Umlaut-Toleranz nicht)
        $exp = New-Object System.Text.StringBuilder
        $epos = 0
        foreach ($dm in $digraphRx.Matches($p)) {
            if ($dm.Index -gt $epos) { [void]$exp.Append($p.Substring($epos, $dm.Index - $epos)) }
            [void]$exp.Append("(?:$($dm.Value)|$($umlautMap[$dm.Value]))")
            $epos = $dm.Index + $dm.Length
        }
        if ($epos -lt $p.Length) { [void]$exp.Append($p.Substring($epos)) }
        $p = $exp.ToString()
        if ($entry -match '^[\p{L}\p{N}_]') { $p = "(?<![\p{L}\p{N}_])$p" }
        if ($entry -match '[\p{L}\p{N}_]$') { $p = "$p(?![\p{L}\p{N}_])" }
        $p
    }
    $Global:L10nRegex = [regex]::new('(?:' + ($parts -join '|') + ')',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    return $Global:L10nMap.Count
}
[void](Initialize-L10nDictionary)

function Format-L10n {
    <#
    .SYNOPSIS
        Uebersetzt einen deutschen Anzeigetext nach Englisch (oder gibt ihn zurueck).
    .NOTES
        Bei -Language de ist die Funktion ein No-OP (Originaltext bleibt erhalten).
        Bereits uebersetzte Texte bleiben unveraendert (Idempotenz).
    #>
    param([AllowNull()][AllowEmptyString()][object]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    if ($Global:Lang -ne 'en') { return $s }
    if ($s.Length -lt 2) { return $s }
    $rx = $Global:L10nRegex
    if ($null -eq $rx -or -not $rx.IsMatch($s)) { return $s }
    $sb  = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($m in $rx.Matches($s)) {
        if ($m.Index -gt $pos) { [void]$sb.Append($s.Substring($pos, $m.Index - $pos)) }
        $v = $Global:L10nMap[$m.Value]
        # Umlaut-Schreibweise im Fundstueck ("unterstützt") -> Kanoform der Tabelle ("unterstuetzt")
        if (-not $v) { $v = $Global:L10nMap[(ConvertTo-L10nCanonical -Text $m.Value)] }
        [void]$sb.Append($(if ($v) { $v } else { $m.Value }))
        $pos = $m.Index + $m.Length
    }
    if ($pos -lt $s.Length) { [void]$sb.Append($s.Substring($pos)) }
    return $sb.ToString()
}

# --- Konsolen-Shims: uebersetzt ALLE Konsolenausgaben/-Eingaben zentral ------
function Write-Host {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromRemainingArguments=$true)][object[]]$Object,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [switch]$NoNewline,
        [object]$Separator = ' '
    )
    $msg = ($Object | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } }) -join ([string]$Separator)
    $splat = @{ Object = (Format-L10n -Text $msg) }
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $splat['ForegroundColor'] = $ForegroundColor }
    if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $splat['BackgroundColor'] = $BackgroundColor }
    if ($NoNewline)                                        { $splat['NoNewline']    = $true }
    Microsoft.PowerShell.Utility\Write-Host @splat
}

function Read-Host {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)][string]$Prompt,
        [switch]$AsSecureString
    )
    $p = Format-L10n -Text $Prompt
    if ($AsSecureString) { return Microsoft.PowerShell.Utility\Read-Host -Prompt $p -AsSecureString }
    return Microsoft.PowerShell.Utility\Read-Host -Prompt $p
}

#endregion

#region ============================ LOGGING ==================================

function Initialize-LogEnvironment {
    try {
        foreach ($d in $Global:LogDirectory, $Global:ReportDirectory, $Global:CsvDirectory) {
            if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
        }
    } catch { Write-Host "FEHLER: $_" -ForegroundColor Red; throw }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG','OK')][string]$Level='INFO',
        [switch]$NoConsole
    )
    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $line = "[$ts] [$Level] $Message"
        # Logdatei in der aktuell gewaehlten Sprache (wie Konsolenausgabe/Report)
        Add-Content -Path $Global:LogFile -Value (Format-L10n -Text $line) -ErrorAction Stop
        if (-not $NoConsole) {
            $c = switch ($Level) { 'ERROR'{'Red'} 'WARN'{'Yellow'} 'OK'{'Green'} 'DEBUG'{'DarkGray'} default{'Cyan'} }
            Write-Host $line -ForegroundColor $c
        }
    } catch { Write-Host "LOG-FEHLER: $_" -ForegroundColor Red }
}

#endregion

#region ============= UPDATE-CHECK (GitLab Releases) ==========================

$Global:GitLabProjectId = '87409197'
$Global:UpdateCheckUrl  = "https://gitlab.com/api/v4/projects/$($Global:GitLabProjectId)/releases?per_page=1&order_by=released_at&sort=desc"

function Get-RemoteReleaseInfo {
    <#
    .SYNOPSIS
        Fragt die GitLab-Releases-API nach dem neuesten Release ab.
    .NOTES
        Timeout 3 s. Offline, Proxy-Sperren und TLS-Probleme werden verschluckt:
        Der Update-Check darf einen Health Check nie verzoegern oder abbrechen.
    .OUTPUTS
        PSCustomObject: LatestTag, LatestVersion, Url, UpdateAvailable, CurrentTag
    #>
    $res = [PSCustomObject]@{
        LatestTag       = $null
        LatestVersion   = $null
        Url             = $null
        UpdateAvailable = $false
        CurrentTag      = "v$Global:ScriptVersion"
    }
    try {
        # Windows PowerShell 5.1 wuerde sonst nur TLS 1.0/1.1 anbieten
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $latest = Invoke-RestMethod -Uri $Global:UpdateCheckUrl -TimeoutSec 3 -ErrorAction Stop | Select-Object -First 1
        if (-not $latest) { return $res }
        $res.LatestTag = [string]$latest.tag_name
        if ($res.LatestTag -match 'v?(?<ver>\d+(?:\.\d+)*)') { $res.LatestVersion = [version]$matches['ver'] }
        if ($latest._links -and $latest._links.self) { $res.Url = [string]$latest._links.self }
        if ($res.LatestVersion -and $res.LatestVersion -gt ([version]$Global:ScriptVersion)) { $res.UpdateAvailable = $true }
    } catch { }
    return $res
}

function Start-UpdateCheckAsync {
    <#
    .SYNOPSIS
        Startet den Update-Check in einem eigenen Runspace, damit die GUI nicht einfriert.
    .NOTES
        Das Skriptblock-Laeufwerk kennt die Hilfsfunktionen nicht - alles wird per
        Argument uebergeben und das Ergebnis per EndInvoke geholt (DispatcherTimer pollt).
    .OUTPUTS
        PSCustomObject: Handle (IAsyncResult), PowerShell (Instanz zum Aufraeumen)
    #>
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($url, $currentTag)
        $out = [PSCustomObject]@{ LatestTag = $null; Url = $null; UpdateAvailable = $false }
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $latest = Invoke-RestMethod -Uri $url -TimeoutSec 3 -ErrorAction Stop | Select-Object -First 1
            if ($latest) {
                $out.LatestTag = [string]$latest.tag_name
                if ($latest._links -and $latest._links.self) { $out.Url = [string]$latest._links.self }
                if ($out.LatestTag -match 'v?(?<ver>\d+(?:\.\d+)*)' -and
                    ([version]$matches['ver']) -gt ([version]$currentTag)) { $out.UpdateAvailable = $true }
            }
        } catch { }
        return $out
    }).AddArgument($Global:UpdateCheckUrl).AddArgument("v$Global:ScriptVersion")
    return [PSCustomObject]@{ Handle = $ps.BeginInvoke(); PowerShell = $ps }
}

#endregion

#region ============= INTERAKTIVES MENUE / GUI ================================

function Show-HealthCheckGUI {
    <#
    .SYNOPSIS
        Zeigt eine moderne WPF-GUI (Light-Theme) zur Auswahl der Checks, Gruppen und des Ausgabepfads.
    .OUTPUTS
        PSCustomObject mit Properties: SelectedChecks, OutputPath, Cancelled
    #>
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms  # fuer FolderBrowserDialog

    # Check-Gruppen aus globaler Definition (identisch zum HTML-Report)
    $checkGroups = $Global:CheckGroups

    # === XAML Definition (Light Theme) ===
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD Health Check v$($Global:ScriptVersion)"
        Width="860" Height="780"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResizeWithGrip"
        Background="#F5F5F5">
    <Window.Resources>
        <Style TargetType="TextBlock">
            <Setter Property="Foreground" Value="#1E1E1E"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#1E1E1E"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style x:Key="AccentButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="20,10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#106EBE"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="QuickButton" TargetType="Button">
            <Setter Property="Background" Value="#E8E8E8"/>
            <Setter Property="Foreground" Value="#1E1E1E"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#D4D4D4"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="SuiteButton" TargetType="Button">
            <Setter Property="Background" Value="#DFF0FF"/>
            <Setter Property="Foreground" Value="#0050A0"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#A0C8F0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#C0DFFF"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="SecuritySuiteButton" TargetType="Button">
            <Setter Property="Background" Value="#FFE0E0"/>
            <Setter Property="Foreground" Value="#C02020"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#F0A0A0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#FFC8C8"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="CancelButton" TargetType="Button">
            <Setter Property="Background" Value="#E0E0E0"/>
            <Setter Property="Foreground" Value="#333333"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="20,10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#CCCCCC"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid Margin="24">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header inkl. Sprachumschalter DE/EN -->
        <Grid Grid.Row="0" Margin="0,0,0,18">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0">
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="AD Health Check" FontSize="24" FontWeight="Bold" Foreground="#0078D4"/>
                    <TextBlock x:Name="lblVersion" Text="v$($Global:ScriptVersion)" FontSize="16" FontWeight="SemiBold"
                               Foreground="#777777" VerticalAlignment="Bottom" Margin="10,0,0,4"/>
                    <!-- Update-Anzeige: erscheint nur, wenn auf GitLab eine neuere Version liegt -->
                    <Border x:Name="brdUpdate" Visibility="Collapsed" Background="#FFF4CE" BorderBrush="#E0A800" BorderThickness="1"
                            CornerRadius="4" Padding="8,3" Margin="10,0,0,0" VerticalAlignment="Bottom" Cursor="Hand">
                        <TextBlock x:Name="lblUpdate" Text="" FontSize="11" FontWeight="SemiBold" Foreground="#8A6100"/>
                    </Border>
                </StackPanel>
                <TextBlock x:Name="lblSubtitle" Text="Waehlen Sie die gewuenschten Pruefungen und den Ausgabepfad." FontSize="12" Foreground="#555555" Margin="0,4,0,0"/>
            </StackPanel>
            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Top" Margin="0,4,0,0">
                <TextBlock x:Name="lblLanguage" Text="Sprache:" FontSize="12" FontWeight="SemiBold" Foreground="#555555" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <Button x:Name="btnLangDe" Content="Deutsch" MinWidth="76" Style="{StaticResource QuickButton}"/>
                <Button x:Name="btnLangEn" Content="English" MinWidth="76" Margin="8,0,0,0" Style="{StaticResource QuickButton}"/>
            </StackPanel>
        </Grid>

        <!-- Ausgabepfad -->
        <Border Grid.Row="1" Background="White" CornerRadius="6" Padding="14,10" Margin="0,0,0,14"
                BorderBrush="#D0D0D0" BorderThickness="1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="lblOutputPath" Grid.Column="0" Text="Ausgabepfad:" VerticalAlignment="Center" Margin="0,0,12,0" FontSize="12" FontWeight="SemiBold"/>
                <TextBox x:Name="txtOutputPath" Grid.Column="1"
                         Background="White" Foreground="#1E1E1E" BorderBrush="#C0C0C0"
                         BorderThickness="1" Padding="8,6" FontSize="12" VerticalContentAlignment="Center"/>
                <Button x:Name="btnBrowse" Grid.Column="2" Content="Durchsuchen..."
                        Style="{StaticResource QuickButton}" Margin="8,0,0,0"/>
            </Grid>
        </Border>

        <!-- Schnellauswahl: Alle / Keine -->
        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,8">
            <Button x:Name="btnAll" Content="Alle auswaehlen" Style="{StaticResource QuickButton}" Margin="0,0,8,0"/>
            <Button x:Name="btnNone" Content="Keine" Style="{StaticResource QuickButton}" Margin="0,0,24,0"/>
            <TextBlock x:Name="lblCount" VerticalAlignment="Center" Foreground="#666666" FontSize="11"/>
        </StackPanel>

        <!-- Suite-Buttons -->
        <WrapPanel Grid.Row="3" Margin="0,0,0,12">
            <Button x:Name="btnSuiteDC" Content="DC-Infrastruktur" Style="{StaticResource SuiteButton}" Margin="0,0,6,4"/>
            <Button x:Name="btnSuiteSecurity" Content="Security &amp; Hardening" Style="{StaticResource SecuritySuiteButton}" Margin="0,0,6,4"/>
            <Button x:Name="btnSuiteIdentity" Content="Identity &amp; Kerberos" Style="{StaticResource SuiteButton}" Margin="0,0,6,4"/>
            <Button x:Name="btnSuiteTopo" Content="AD-Topologie &amp; Objekte" Style="{StaticResource SuiteButton}" Margin="0,0,6,4"/>
            <Button x:Name="btnSuiteSystem" Content="System &amp; Updates" Style="{StaticResource SuiteButton}" Margin="0,0,6,4"/>
        </WrapPanel>

        <!-- Check-Gruppen ScrollViewer -->
        <Border Grid.Row="4" Background="White" CornerRadius="6" Padding="4"
                BorderBrush="#D0D0D0" BorderThickness="1">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="10">
                <StackPanel x:Name="pnlChecks"/>
            </ScrollViewer>
        </Border>

        <!-- Footer Buttons -->
        <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button x:Name="btnCancel" Content="Abbrechen" Style="{StaticResource CancelButton}" Margin="0,0,12,0"/>
            <Button x:Name="btnStart" Content="Health Check starten" Style="{StaticResource AccentButton}"/>
        </StackPanel>
    </Grid>
</Window>
"@

    # === Window aus XAML erstellen ===
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    # Shared State (statt $script: - funktioniert zuverlaessig in Event-Handlern)
    $state = @{
        AllCheckBoxes   = @{}
        GroupCheckBoxes = @{}
        SuppressEvents  = $false
        Result          = [PSCustomObject]@{ SelectedChecks=@(); OutputPath=''; Cancelled=$true; Language=$Global:Lang }
        Window          = $window
        CheckGroups     = $checkGroups
    }

    # Controls referenzieren
    $txtOutputPath  = $window.FindName('txtOutputPath')
    $btnBrowse      = $window.FindName('btnBrowse')
    $btnAll         = $window.FindName('btnAll')
    $btnNone        = $window.FindName('btnNone')
    $lblCount       = $window.FindName('lblCount')
    $pnlChecks      = $window.FindName('pnlChecks')
    $btnStart       = $window.FindName('btnStart')
    $btnCancel      = $window.FindName('btnCancel')
    $btnSuiteDC     = $window.FindName('btnSuiteDC')
    $btnSuiteSecurity = $window.FindName('btnSuiteSecurity')
    $btnSuiteIdentity = $window.FindName('btnSuiteIdentity')
    $btnSuiteTopo   = $window.FindName('btnSuiteTopo')
    $btnSuiteSystem = $window.FindName('btnSuiteSystem')
    $lblSubtitle    = $window.FindName('lblSubtitle')
    $lblLanguage    = $window.FindName('lblLanguage')
    $lblOutputPath  = $window.FindName('lblOutputPath')
    $btnLangDe      = $window.FindName('btnLangDe')
    $btnLangEn      = $window.FindName('btnLangEn')
    $brdUpdate      = $window.FindName('brdUpdate')
    $lblUpdate      = $window.FindName('lblUpdate')

    $txtOutputPath.Text = $Global:LogDirectory

    # === Mehrsprachigkeit: alle beschrifteten Controls registrieren ==========
    # Original = deutscher Text, beim Umschalten wird er uebersetzt dargestellt.
    $state.LocalizedControls = [System.Collections.ArrayList]::new()
    $addLocalized = {
        param($control, $property, $original, $english)
        [void]$state.LocalizedControls.Add([pscustomobject]@{ Control=$control; Property=$property; Original=$original; English=$english })
    }
    # Optionaler 4. Parameter: eigener englischer Text (sonst Uebersetzungstabelle)
    foreach ($spec in @(
        @( $lblSubtitle,     'Text',    'Waehlen Sie die gewuenschten Pruefungen und den Ausgabepfad.' ),
        @( $lblLanguage,     'Text',    'Sprache:' ),
        @( $lblOutputPath,   'Text',    'Ausgabepfad:' ),
        @( $btnBrowse,       'Content', 'Durchsuchen...' ),
        @( $btnAll,          'Content', 'Alle auswaehlen' ),
        @( $btnNone,         'Content', 'Keine', 'None' ),
        @( $btnSuiteDC,      'Content', 'DC-Infrastruktur' ),
        @( $btnSuiteSecurity,'Content', 'Security & Hardening' ),
        @( $btnSuiteIdentity,'Content', 'Identity & Kerberos' ),
        @( $btnSuiteTopo,    'Content', 'AD-Topologie & Objekte' ),
        @( $btnSuiteSystem,  'Content', 'System & Updates' ),
        @( $btnStart,        'Content', 'Health Check starten' ),
        @( $btnCancel,       'Content', 'Abbrechen' )
    )) {
        if ($spec.Count -gt 3) { & $addLocalized $spec[0] $spec[1] $spec[2] $spec[3] }
        else                   { & $addLocalized $spec[0] $spec[1] $spec[2] '' }
    }

    # Hilfsfunktion: Anzahl aktualisieren
    $updateCount = {
        param($st, $lbl)
        if ($st.SuppressEvents) { return }
        $checked = 0; $total = 0
        foreach ($c in $st.AllCheckBoxes.Values) {
            $total++
            if ($c.IsChecked -eq $true) { $checked++ }
        }
        $lbl.Text = (Format-L10n -Text "$checked / $total Checks ausgewaehlt")
    }

    # Suite-Aktivierung: Nur die Keys einer Gruppe anwaehlen
    $activateSuite = {
        param($st, $lbl, $groupName, $updateFn)
        $st.SuppressEvents = $true
        foreach ($cb in $st.AllCheckBoxes.Values) { $cb.IsChecked = $false }
        foreach ($gb in $st.GroupCheckBoxes.Values) { $gb.IsChecked = $false }
        $keys = $st.CheckGroups[$groupName]
        foreach ($k in $keys) {
            if ($st.AllCheckBoxes.ContainsKey($k)) { $st.AllCheckBoxes[$k].IsChecked = $true }
        }
        if ($st.GroupCheckBoxes.ContainsKey($groupName)) { $st.GroupCheckBoxes[$groupName].IsChecked = $true }
        $st.SuppressEvents = $false
        & $updateFn $st $lbl
    }

    # === Checkboxen dynamisch erzeugen ===
    foreach ($groupName in $checkGroups.Keys) {
        $expander = New-Object System.Windows.Controls.Expander
        $expander.IsExpanded = $true
        $expander.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)

        # Header
        $headerPanel = New-Object System.Windows.Controls.StackPanel
        $headerPanel.Orientation = 'Horizontal'

        $grpCb = New-Object System.Windows.Controls.CheckBox
        $grpCb.IsChecked = $true
        $grpCb.Tag = $groupName
        $grpCb.VerticalAlignment = 'Center'
        $headerPanel.Children.Add($grpCb) | Out-Null

        $headerText = New-Object System.Windows.Controls.TextBlock
        $headerText.Text = " $groupName"
        & $addLocalized $headerText 'Text' " $groupName"
        $headerText.FontSize = 13
        $headerText.FontWeight = 'SemiBold'
        $headerText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#0078D4')
        $headerText.VerticalAlignment = 'Center'
        $headerText.Margin = [System.Windows.Thickness]::new(6, 0, 0, 0)
        $headerPanel.Children.Add($headerText) | Out-Null

        $expander.Header = $headerPanel

        # Content
        $groupPanel = New-Object System.Windows.Controls.StackPanel
        $groupPanel.Margin = [System.Windows.Thickness]::new(24, 2, 0, 2)

        $checksInGroup = [System.Collections.ArrayList]::new()
        foreach ($checkKey in $checkGroups[$groupName]) {
            if (-not $Global:ReportTitles.Contains($checkKey)) { continue }
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = $Global:ReportTitles[$checkKey]
            & $addLocalized $cb 'Content' $Global:ReportTitles[$checkKey]
            $cb.Tag = $checkKey
            $cb.IsChecked = $true
            $cb.FontSize = 12
            $cb.Add_Checked({ param($s,$e); & $updateCount $state $lblCount }.GetNewClosure())
            $cb.Add_Unchecked({ param($s,$e); & $updateCount $state $lblCount }.GetNewClosure())
            $groupPanel.Children.Add($cb) | Out-Null
            $state.AllCheckBoxes[$checkKey] = $cb
            $checksInGroup.Add($cb) | Out-Null
        }
        $expander.Content = $groupPanel
        $pnlChecks.Children.Add($expander) | Out-Null
        $state.GroupCheckBoxes[$groupName] = $grpCb

        # Gruppen-Checkbox steuert Kinder
        $childList = $checksInGroup.ToArray()
        $grpCb.Add_Checked({
            param($s,$e)
            $state.SuppressEvents = $true
            foreach ($child in $childList) { $child.IsChecked = $true }
            $state.SuppressEvents = $false
            & $updateCount $state $lblCount
        }.GetNewClosure())
        $grpCb.Add_Unchecked({
            param($s,$e)
            $state.SuppressEvents = $true
            foreach ($child in $childList) { $child.IsChecked = $false }
            $state.SuppressEvents = $false
            & $updateCount $state $lblCount
        }.GetNewClosure())
    }

    # Initial Count
    & $updateCount $state $lblCount

    # === Sprachumschalter DE/EN (wirkt live auf alle GUI-Texte) ==============
    $applyLanguage = {
        foreach ($e in $state.LocalizedControls) {
            $txt = if ($Global:Lang -eq 'en' -and $e.English) { $e.English } else { Format-L10n -Text $e.Original }
            switch ($e.Property) {
                'Text'    { $e.Control.Text = $txt }
                'Content' { $e.Control.Content = $txt }
            }
        }
        $isDe = ($Global:Lang -eq 'de')
        $btnLangDe.FontWeight = $(if ($isDe) { 'Bold' } else { 'Normal' })
        $btnLangEn.FontWeight = $(if ($isDe) { 'Normal' } else { 'Bold' })
        $btnLangDe.Opacity    = $(if ($isDe) { 1.0 } else { 0.6 })
        $btnLangEn.Opacity    = $(if ($isDe) { 0.6 } else { 1.0 })
        & $updateCount $state $lblCount
    }

    $btnLangDe.Add_Click({
        param($s,$e)
        Set-HealthCheckLanguage -Code 'de'
        & $applyLanguage
    }.GetNewClosure())

    $btnLangEn.Add_Click({
        param($s,$e)
        Set-HealthCheckLanguage -Code 'en'
        & $applyLanguage
    }.GetNewClosure())

    # Alle Texte in der Start-/Betriebssprache setzen
    & $applyLanguage

    # === Button-Events ===
    $btnBrowse.Add_Click({
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = (Format-L10n -Text 'Ausgabepfad waehlen')
        $fbd.SelectedPath = $txtOutputPath.Text
        if ($fbd.ShowDialog() -eq 'OK') { $txtOutputPath.Text = $fbd.SelectedPath }
    }.GetNewClosure())

    $btnAll.Add_Click({
        param($s,$e)
        $state.SuppressEvents = $true
        foreach ($cb in $state.AllCheckBoxes.Values) { $cb.IsChecked = $true }
        foreach ($gb in $state.GroupCheckBoxes.Values) { $gb.IsChecked = $true }
        $state.SuppressEvents = $false
        & $updateCount $state $lblCount
    }.GetNewClosure())

    $btnNone.Add_Click({
        param($s,$e)
        $state.SuppressEvents = $true
        foreach ($cb in $state.AllCheckBoxes.Values) { $cb.IsChecked = $false }
        foreach ($gb in $state.GroupCheckBoxes.Values) { $gb.IsChecked = $false }
        $state.SuppressEvents = $false
        & $updateCount $state $lblCount
    }.GetNewClosure())

    # Suite-Buttons
    $btnSuiteDC.Add_Click({
        param($s,$e)
        & $activateSuite $state $lblCount 'DC-Infrastruktur' $updateCount
    }.GetNewClosure())

    $btnSuiteSecurity.Add_Click({
        param($s,$e)
        & $activateSuite $state $lblCount 'Security & Hardening' $updateCount
    }.GetNewClosure())

    $btnSuiteIdentity.Add_Click({
        param($s,$e)
        & $activateSuite $state $lblCount 'Identity & Kerberos' $updateCount
    }.GetNewClosure())

    $btnSuiteTopo.Add_Click({
        param($s,$e)
        & $activateSuite $state $lblCount 'AD-Topologie & Objekte' $updateCount
    }.GetNewClosure())

    $btnSuiteSystem.Add_Click({
        param($s,$e)
        & $activateSuite $state $lblCount 'System & Updates' $updateCount
    }.GetNewClosure())

    # Start
    $btnStart.Add_Click({
        param($s,$e)
        $selected = @()
        foreach ($k in $state.AllCheckBoxes.Keys) {
            if ($state.AllCheckBoxes[$k].IsChecked) { $selected += $k }
        }
        if ($selected.Count -eq 0) {
            [System.Windows.MessageBox]::Show((Format-L10n -Text 'Bitte mindestens einen Check auswaehlen.'), (Format-L10n -Text 'Hinweis'),
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
            return
        }
        $state.Result = [PSCustomObject]@{
            SelectedChecks = $selected
            OutputPath     = $txtOutputPath.Text
            Cancelled      = $false
            Language       = $Global:Lang
        }
        $state.Window.Close()
    }.GetNewClosure())

    $btnCancel.Add_Click({ param($s,$e); $state.Window.Close() }.GetNewClosure())

    # === Update-Anzeige: asynchron pruefen, Badge nur bei neuerer Version einblenden ===
    # Shared State (wie $state) - Hashtable-Zugriffe funktionieren zuverlaessig in Event-Handlern
    $updState = @{ Task = $null; Timer = $null; Url = $null }
    if (-not $Global:NoUpdateCheck) {
        $updState.Task  = Start-UpdateCheckAsync
        $updState.Timer = New-Object System.Windows.Threading.DispatcherTimer
        $updState.Timer.Interval = [TimeSpan]::FromMilliseconds(400)
        $updState.Timer.Add_Tick({
            $t = $updState.Task
            if ($null -eq $t -or -not $t.Handle.IsCompleted) { return }
            $updState.Timer.Stop()
            $info = $null
            try { $info = @($t.PowerShell.EndInvoke($t.Handle)) | Select-Object -First 1 } catch { }
            try { $t.PowerShell.Dispose() } catch { }
            $updState.Task = $null
            if ($info -and $info.UpdateAvailable) {
                $updState.Url         = $info.Url
                $lblUpdate.Text       = (Format-L10n -Text ('Update verfügbar: ' + $info.LatestTag))
                $brdUpdate.ToolTip    = (Format-L10n -Text 'Oeffnet die Release-Seite dieses Projekts.')
                $brdUpdate.Visibility = 'Visible'
            }
        })
        $updState.Timer.Start()
        # Klick auf das Badge oeffnet die Release-Seite im Browser
        $brdUpdate.Add_MouseLeftButtonDown({ if ($updState.Url) { Start-Process $updState.Url } })
    }

    # === Window anzeigen ===
    $window.ShowDialog() | Out-Null

    return $state.Result
}

function Show-CheckList {
    Clear-Host
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host "  VERFUEGBARE CHECKS" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    $i = 0
    foreach ($k in $Global:ReportTitles.Keys) {
        if ($k -eq '00_SkippedDCs') { continue }
        $i++
        Write-Host ("  {0,3}.  {1}" -f $i, $Global:ReportTitles[$k]) -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkCyan
}

function Show-CheckPicker {
    param([switch]$SingleSelect, [switch]$MultiSelect)
    $allKeys = @($Global:ReportTitles.Keys | Where-Object { $_ -ne '00_SkippedDCs' })
    while ($true) {
        Show-CheckList
        $prompt = if ($SingleSelect) { "  Geben Sie Nummer ODER Key ein (oder 'B' = zurueck): " }
                  else { "  Geben Sie Nummern/Keys komma-getrennt ein (z.B. '1,3,5') oder 'B' = zurueck: " }
        Write-Host ""
        $in = Read-Host $prompt
        if ($in -match '^B$|^BACK$|^ZURUECK$') { return $null }
        if ([string]::IsNullOrWhiteSpace($in)) { Start-Sleep 1; continue }

        $parts = $in -split '[,;\s]+' | Where-Object { $_ -and $_.Trim() }
        $sel = @(); $err = @()
        foreach ($p in $parts) {
            $p = $p.Trim()
            if ($p -match '^\d+$') {
                $idx = [int]$p - 1
                if ($idx -ge 0 -and $idx -lt $allKeys.Count) { $sel += $allKeys[$idx] }
                else { $err += "Nummer '$p' ausserhalb (1-$($allKeys.Count))" }
            }
            elseif ($allKeys -contains $p) { $sel += $p }
            else {
                $m = $allKeys | Where-Object { $_ -ilike "*$p*" }
                if (@($m).Count -eq 1) { $sel += $m }
                elseif (@($m).Count -gt 1) { $err += "'$p' mehrdeutig: $($m -join ', ')" }
                else { $err += "'$p' nicht erkannt" }
            }
        }
        if ($err.Count -gt 0) {
            foreach ($e in $err) { Write-Host "  [!] $e" -ForegroundColor Yellow }
            $retry = Read-Host "  Erneut versuchen? (J/N)"
            if ($retry -match '^[NnQq]') { return $null }
            continue
        }
        if ($SingleSelect -and $sel.Count -gt 1) { return $sel[0] }
        return ($sel | Select-Object -Unique)
    }
}

function Show-ScriptMenu {
    $all = @($Global:ReportTitles.Keys | Where-Object { $_ -ne '00_SkippedDCs' })
    $perDC = @('01_DCSystemInfo','02_Services','03_DCDiag','04_Replication','06_DNS','07_SYSVOL','08_Database',
               '09_TLS','10_Cipher','11_SMB','12_NTLMAuth','13_LLMNR','14_LDAPSecurity','15_WindowsFirewall',
               '21_LSAProtection','22_PrintSpooler','23_SecureBoot','24_Certificates',
               '33_EventLog','34_TimeSync','36_InstalledPrograms','37_WindowsUpdates',
               '45_WindowsFeatures','46_Shares')
    $forest = @('04b_ReplicationFailures','05_FSMO','16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos',
                '19_UnconstrainedDelegation','20_KerberoastingRisk','25_Sites','26_Subnets','27_Trusts',
                '28_ADRecycleBin','29_TombstoneLifetime','30_Levels','31_GPO','32a_InactiveUsers',
                '32b_InactiveComputers','32c_PasswordNeverExpires','35_Backup','38_SPNDuplicates',
                '39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','42_DNSHygiene','43_LAPS','44_AccountsWithoutAES',
                '47_RCAESMigration','48_DCSyncPermissions','49_RBCDDelegation','50_dMSA',
                '51_MachineAccountQuota','52_AnonymousLDAP','53_GPPPasswords','54_ProtectedUsers','60_ZonenSOA','61_Forwarder','62_ReverseLookup')
    $sec = @('09_TLS','10_Cipher','11_SMB','12_NTLMAuth','13_LLMNR','14_LDAPSecurity','15_WindowsFirewall',
             '16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos','19_UnconstrainedDelegation',
             '20_KerberoastingRisk','21_LSAProtection','22_PrintSpooler','23_SecureBoot','24_Certificates',
             '38_SPNDuplicates','39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','43_LAPS','44_AccountsWithoutAES',
             '47_RCAESMigration','48_DCSyncPermissions','49_RBCDDelegation','50_dMSA',
             '51_MachineAccountQuota','52_AnonymousLDAP','53_GPPPasswords','54_ProtectedUsers')

    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host "  AD HEALTH CHECK v$Global:ScriptVersion - AUSWAHLMENUE" -ForegroundColor White
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "   [1]  Full Run   - Alle Checks (empfohlen)"      -ForegroundColor Green
        Write-Host "   [2]  Einzel     - Genau EINEN Check"            -ForegroundColor Cyan
        Write-Host "   [3]  Mehrere    - Mehrere Checks (Komma-Liste)" -ForegroundColor Cyan
        Write-Host "   [4]  Forest     - Nur Forest-weite Checks"      -ForegroundColor Cyan
        Write-Host "   [5]  Pro-DC     - Nur DC-spezifische Checks"    -ForegroundColor Cyan
        Write-Host "   [6]  Security   - Komplette Security-Suite"     -ForegroundColor Magenta
        Write-Host "   [7]  Liste      - Alle verfuegbaren Checks"     -ForegroundColor Gray
        Write-Host "   [Q]  Quit       - Abbrechen"                    -ForegroundColor Red
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkCyan
        $c = Read-Host "  Ihre Auswahl"

        switch -Regex ($c.Trim().ToUpper()) {
            '^1$|^F$' { $Global:RunMode='Full'; $Global:SelectedChecks=@($all); Write-Host "`n  [+] Full: $($all.Count) Checks" -ForegroundColor Green; Start-Sleep 2; return }
            '^2$' { $s = Show-CheckPicker -SingleSelect; if ($s) { $Global:RunMode='Single'; $Global:SelectedChecks=@($s); Write-Host "`n  [+] $s" -ForegroundColor Green; Start-Sleep 2; return } }
            '^3$' { $s = Show-CheckPicker -MultiSelect; if ($s -and $s.Count -gt 0) { $Global:RunMode='Multi'; $Global:SelectedChecks=@($s); Write-Host "`n  [+] $($s.Count) Checks." -ForegroundColor Green; Start-Sleep 2; return } }
            '^4$' { $Global:RunMode='Multi'; $Global:SelectedChecks=@($forest); Write-Host "`n  [+] Forest: $($forest.Count)" -ForegroundColor Green; Start-Sleep 2; return }
            '^5$' { $Global:RunMode='Multi'; $Global:SelectedChecks=@($perDC);  Write-Host "`n  [+] Pro-DC: $($perDC.Count)"  -ForegroundColor Green; Start-Sleep 2; return }
            '^6$' { $Global:RunMode='Multi'; $Global:SelectedChecks=@($sec);    Write-Host "`n  [+] Security: $($sec.Count)" -ForegroundColor Green; Start-Sleep 2; return }
            '^7$|^L$' { Show-CheckList; Read-Host "`n  [ENTER] fuer Menue" }
            '^Q$|^QUIT$|^EXIT$' { Write-Host "`n  [!] Abbruch." -ForegroundColor Yellow; exit 0 }
            default { Write-Host "`n  [X] Ungueltig" -ForegroundColor Red; Start-Sleep 2 }
        }
    }
}

function Test-IsCheckSelected {
    param([Parameter(Mandatory)][string]$CheckKey)
    return ($Global:SelectedChecks -contains $CheckKey)
}

#endregion

#region ============= PROGRESS ===============================================

function Write-CheckProgress {
    param(
        [Parameter(Mandatory)][string]$CheckKey,
        [string]$DCName='',
        [ValidateSet('Start','OK','Warn','Error','Skip')][string]$Status='Start',
        [double]$Duration=0,
        [string]$Message=''
    )
    $title = if ($Global:ReportTitles.Contains($CheckKey)) { $Global:ReportTitles[$CheckKey] } else { $CheckKey }
    $title = Format-L10n -Text $title
    $percent = 0
    if ($Global:ProgressStats.TotalChecks -gt 0) {
        $percent = [math]::Min(100, [math]::Round(($Global:ProgressStats.CompletedChecks / $Global:ProgressStats.TotalChecks)*100,1))
    }
    $elapsed = ''
    if ($Global:ProgressStats.StartTime) {
        $ts = (New-TimeSpan -Start $Global:ProgressStats.StartTime -End (Get-Date))
        $elapsed = "{0:D2}:{1:D2}:{2:D2}" -f $ts.Hours,$ts.Minutes,$ts.Seconds
    }
    $pStatus = if ($DCName) { "$title | DC: $DCName" } else { $title }
    Write-Progress -Activity (Format-L10n -Text "AD Health Check (Laufzeit: $elapsed)") `
                   -Status "$pStatus ($($Global:ProgressStats.CompletedChecks)/$($Global:ProgressStats.TotalChecks))" `
                   -PercentComplete $percent -CurrentOperation $Message

    $ts = Get-Date -Format "HH:mm:ss"
    $tag = switch ($Status) { 'Start'{'[*]'} 'OK'{'[+]'} 'Warn'{'[!]'} 'Error'{'[X]'} 'Skip'{'[-]'} }
    $col = switch ($Status) { 'Start'{'Cyan'} 'OK'{'Green'} 'Warn'{'Yellow'} 'Error'{'Red'} 'Skip'{'DarkGray'} }
    $dcP = if ($DCName) { " | DC: $DCName" } else { '' }
    $tP  = if ($Duration -gt 0) { " ({0:N2}s)" -f $Duration } else { '' }
    $mP  = if ($Message) { " - $Message" } else { '' }
    Write-Host ("{0} [{1}] [{2,5:N1}%] {3}{4}{5}{6}" -f $tag,$ts,$percent,$title,$dcP,$tP,$mP) -ForegroundColor $col
    $lvl = switch ($Status) { 'OK'{'OK'} 'Warn'{'WARN'} 'Error'{'ERROR'} default{'INFO'} }
    Write-Log -Message "[$Status] $title$dcP$tP$mP" -Level $lvl -NoConsole
}

function Invoke-TimedCheck {
    param(
        [Parameter(Mandatory)][string]$CheckKey,
        [string]$DCName='',
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    Write-CheckProgress -CheckKey $CheckKey -DCName $DCName -Status 'Start'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $ScriptBlock; $sw.Stop()
        $c = @($r).Count
        $m = if ($c -gt 0) { "$c Eintraege" } else { "Keine Daten" }
        Write-CheckProgress -CheckKey $CheckKey -DCName $DCName -Status 'OK' -Duration $sw.Elapsed.TotalSeconds -Message $m
        $Global:ProgressStats.CompletedChecks++
        return $r
    } catch {
        $sw.Stop()
        Write-CheckProgress -CheckKey $CheckKey -DCName $DCName -Status 'Error' -Duration $sw.Elapsed.TotalSeconds -Message "$_"
        $Global:ProgressStats.CompletedChecks++
        $Global:ProgressStats.FailedChecks++
        return $null
    }
}

#endregion
#region ====================== HELPER ========================================

function Get-SortedResultKeys {
    # Reihenfolge direkt aus $Global:ReportTitles (= thematisch sortiert)
    return @($Global:ReportTitles.Keys | Where-Object { $Global:Results.Contains($_) })
}

function Get-ReportKeys {
    <#
    .SYNOPSIS
        Liefert nur die Keys, die im Report erscheinen sollen.
        - 00_SkippedDCs nur wenn DCs uebersprungen wurden
        - Alle anderen nur wenn ausgewaehlt
    #>
    $out = @()
    foreach ($k in $Global:ReportTitles.Keys) {
        if ($k -eq '00_SkippedDCs') {
            if ($Global:Results[$k] -and @($Global:Results[$k]).Count -gt 0) { $out += $k }
            continue
        }
        if ($Global:SelectedChecks -contains $k) { $out += $k }
    }
    return $out
}

function Get-GroupedReportKeys {
    <#
    .SYNOPSIS
        Liefert die Report-Keys nach GUI-Kategorien gruppiert ([ordered] KatName -> Keys).
        Keys ohne Kategorie (z.B. 00_SkippedDCs) stehen in der Gruppe 'Allgemein'.
    #>
    $reportKeys = @(Get-ReportKeys)
    $grouped = [ordered]@{}
    $assigned = @()
    foreach ($cat in $Global:CheckGroups.Keys) {
        $keys = @($reportKeys | Where-Object { $Global:CheckGroups[$cat] -contains $_ })
        if ($keys.Count -gt 0) { $grouped[$cat] = $keys; $assigned += $keys }
    }
    $rest = @($reportKeys | Where-Object { $assigned -notcontains $_ })
    if ($rest.Count -gt 0) {
        $tmp = [ordered]@{ 'Allgemein' = $rest }
        foreach ($k in $grouped.Keys) { $tmp[$k] = $grouped[$k] }
        $grouped = $tmp
    }
    return $grouped
}

function Initialize-ResultKeys {
    foreach ($k in $Global:ReportTitles.Keys) { $Global:Results[$k] = @() }
}

function Import-RequiredModules {
    foreach ($mod in 'ActiveDirectory','GroupPolicy','DnsServer') {
        try {
            if (-not (Get-Module -Name $mod)) {
                Import-Module $mod -ErrorAction Stop
                Write-Log "Modul '$mod' geladen." -Level OK
            }
        } catch { Write-Log "Modul '$mod' nicht ladbar: $_" -Level WARN }
    }
}

#endregion

#region ======================= CONNECTIVITY ==================================

function Test-IsLocalComputer {
    <#
    .SYNOPSIS
        Prueft, ob ein Computername den lokalen Rechner bezeichnet.
    .NOTES
        Erkennt den lokalen Rechner in NetBIOS-Form, FQDN-Form, IP-Form und 'localhost'.
        Fuer FQDN (z.B. 'DC1.contoso.local') wird der Kurzname vor dem ersten Punkt
        mit $env:COMPUTERNAME verglichen.
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        if (-not $Global:LocalIdentifiers) {
            $local = @('localhost','127.0.0.1','::1',$env:COMPUTERNAME)
            try { $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; if ($fqdn) { $local += $fqdn } } catch {}
            try { $local += Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress } catch {}
            $Global:LocalIdentifiers = $local | Select-Object -Unique
        }
        # Exakter Vergleich (NetBIOS, FQDN, IP, localhost)
        foreach ($id in $Global:LocalIdentifiers) { if ($ComputerName -ieq $id) { return $true } }
        # FQDN-Erkennung: Kurzname vor erstem Punkt gegen $env:COMPUTERNAME
        if ($ComputerName -match '\.') {
            $short = $ComputerName.Substring(0, $ComputerName.IndexOf('.'))
            if ($short -ieq $env:COMPUTERNAME) { return $true }
        }
        return $false
    } catch { return $false }
}

function Get-DnsServerTargets {
    <#
    .SYNOPSIS
        Liefert die zu versuchenden Ziel-Parameter fuer DnsServer-Cmdlets.
    .NOTES
        Problem: DnsServer-Cmdlets mit -ComputerName <lokaler DC> erzwingen CIM/WMI-Remoting
        ueber sich selbst. Bei gesperrtem WinRM-Loopback/DCOM schlaegt das fehl,
        obwohl DNS lokal installiert ist. Check 42 war nie betroffen, da er ohne
        -ComputerName abfragt.
        Loesung: Pruefreihenfolge fuer lokalen DC:
          1. @{}                    -> in-process (kein -ComputerName)
          2. @{ComputerName='localhost'} -> CIM gegen localhost
          3. @{ComputerName=$ComputerName} -> CIM gegen uebergebenen Namen
        Fuer remote DCs: nur @{ComputerName=$ComputerName}
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    $isLocal = Test-IsLocalComputer -ComputerName $ComputerName
    if ($isLocal) {
        # Lokal: erst in-process, dann localhost, dann uebergebener Name
        @(@{}, @{ComputerName='localhost'}, @{ComputerName=$ComputerName})
    }
    else {
        # Remote: nur uebergebener Name
        @(@{ComputerName=$ComputerName})
    }
}

function Test-DCPing {
    param([Parameter(Mandatory)][string]$DCName)
    if (Test-IsLocalComputer -ComputerName $DCName) { return $true }
    try {
        for ($i=1; $i -le $Global:PingCount; $i++) {
            try { if (Test-Connection -ComputerName $DCName -Count 1 -Quiet -ErrorAction Stop) { return $true } }
            catch { Start-Sleep -Milliseconds 500 }
        }
        return $false
    } catch { return $false }
}

function Test-DCConnectivity {
    param([Parameter(Mandatory)][string]$DCName)
    $isLocal = Test-IsLocalComputer -ComputerName $DCName
    $result = [pscustomobject]@{
        DCName=$DCName; IsLocalComputer=$isLocal; EffectiveTarget=$DCName
        Ping=$false; WinRM=$false; WinRM_Loopback=$false; CIM_DCOM=$false; WMI=$false
        Method='None'; Reachable=$false; SkipReason=''; ErrorMsg=''
    }
    if ($isLocal) { $result.Ping = $true } else { $result.Ping = Test-DCPing -DCName $DCName }
    if (-not $result.Ping -and -not $Global:TryWinRMIfNoPing) { $result.SkipReason="Kein Ping"; return $result }
    try { $null = Test-WSMan -ComputerName $DCName -ErrorAction Stop; $result.WinRM=$true; $result.Method='WinRM'; $result.Reachable=$true; return $result } catch {}
    if ($isLocal) {
        try { $null = Test-WSMan -ComputerName 'localhost' -ErrorAction Stop; $result.WinRM=$true; $result.WinRM_Loopback=$true; $result.Method='WinRM_Loopback'; $result.EffectiveTarget='localhost'; $result.Reachable=$true; return $result } catch {}
    }
    try {
        $t = if ($isLocal) { 'localhost' } else { $DCName }
        $opt = New-CimSessionOption -Protocol Dcom
        $cim = New-CimSession -ComputerName $t -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop
        Remove-CimSession $cim
        $result.CIM_DCOM=$true; $result.Method='CIM_DCOM'; $result.EffectiveTarget=$t; $result.Reachable=$true
        return $result
    } catch {}
    try {
        $t = if ($isLocal) { '.' } else { $DCName }
        $null = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $t -ErrorAction Stop
        $result.WMI=$true; $result.Method='WMI'; $result.EffectiveTarget=$t; $result.Reachable=$true; return $result
    } catch { $result.ErrorMsg="Alle Methoden fehlgeschlagen: $_" }
    $result.SkipReason = if (-not $result.Ping) { "Kein Ping UND kein WinRM/CIM/WMI" } else { "WinRM/CIM/WMI alle fehlgeschlagen" }
    return $result
}

function Invoke-RemoteCommand {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    $conn = $Global:DCConnectivity[$ComputerName]
    if (-not $conn) { $conn = Test-DCConnectivity -DCName $ComputerName }
    $isLocal = $conn.IsLocalComputer
    $target  = if ($conn.EffectiveTarget) { $conn.EffectiveTarget } else { $ComputerName }
    try {
        if ($isLocal) { if ($ArgumentList) { return & $ScriptBlock @ArgumentList } else { return & $ScriptBlock } }
        if ($conn.WinRM) { return Invoke-Command -ComputerName $target -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop }
        return $null
    } catch {
        if ($isLocal) { try { if ($ArgumentList) { return & $ScriptBlock @ArgumentList } else { return & $ScriptBlock } } catch { return $null } }
        Write-Log "Invoke-RemoteCommand '$ComputerName': $_" -Level ERROR -NoConsole
        return $null
    }
}

function Get-RemoteCimData {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$ClassName,
        [string]$Filter,
        [string]$Namespace='root\cimv2'
    )
    $isLocal = Test-IsLocalComputer -ComputerName $ComputerName
    if ($isLocal) {
        try {
            if ($Filter) { return Get-CimInstance -ClassName $ClassName -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
            else         { return Get-CimInstance -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop }
        } catch { return $null }
    }
    $sess = $null
    try { $opt = New-CimSessionOption -Protocol Wsman; $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop }
    catch {
        try { $opt = New-CimSessionOption -Protocol Dcom; $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop }
        catch { return $null }
    }
    try {
        if ($Filter) { return Get-CimInstance -CimSession $sess -ClassName $ClassName -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
        else         { return Get-CimInstance -CimSession $sess -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop }
    } catch { return $null }
      finally { if ($sess) { Remove-CimSession $sess -ErrorAction SilentlyContinue } }
}

#endregion

#region ============= DATENSAMMEL-FUNKTIONEN (BESTEHEND) =====================

function Get-DCSystemInfo {
    param([Parameter(Mandatory)][string]$DC)
    $os=Get-RemoteCimData -ComputerName $DC -ClassName Win32_OperatingSystem
    $cs=Get-RemoteCimData -ComputerName $DC -ClassName Win32_ComputerSystem
    $bio=Get-RemoteCimData -ComputerName $DC -ClassName Win32_BIOS
    [pscustomobject]@{
        DCName=$DC; OS=$os.Caption; OSVersion=$os.Version; OSBuild=$os.BuildNumber
        InstallDate=$os.InstallDate; LastBoot=$os.LastBootUpTime
        Manufacturer=$cs.Manufacturer; Model=$cs.Model
        TotalRAM_GB=[math]::Round(($cs.TotalPhysicalMemory/1GB),2)
        LogicalProcessors=$cs.NumberOfLogicalProcessors
        BIOSVersion=$bio.SMBIOSBIOSVersion; Domain=$cs.Domain
    }
}

function Get-DCServiceStatus {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        param($map)
        $rows = @()
        # Alle Dienste in EINER CIM-Abfrage holen (ueber WinRM - kein RPC noetig)
        $all = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
        if ($all.Count -eq 0) {
            # Fallback: Get-Service in der Remoting-Session
            $all = @(Get-Service -ErrorAction SilentlyContinue |
                Select-Object Name, DisplayName, @{n='State';e={ "$($_.Status)" }}, @{n='StartMode';e={ "$($_.StartType)" }})
        }
        foreach ($svc in $map.Keys) {
            $cfg = $map[$svc]
            $names = @($cfg.Names); $displays = @($cfg.DisplayNames); $patterns = @($cfg.Patterns)
            # Stufe 1: Matching per Service-Name (sprachunabhaengig) ODER Display-Name (DE/EN)
            $found = $all | Where-Object { $names -contains $_.Name -or $displays -contains $_.DisplayName } | Select-Object -First 1
            # Stufe 2: ASCII-sichere Prefix/Regex-Muster (unabhaengig von Datei-Encoding und OS-Sprache)
            if (-not $found -and $patterns.Count -gt 0) {
                $found = $all | Where-Object {
                    $dn = "$($_.DisplayName)"; $nm = "$($_.Name)"
                    @($patterns | Where-Object { $dn -match $_ -or $nm -match $_ }).Count -gt 0
                } | Select-Object -First 1
            }
            # Stufe 3: Direkte CIM-Einzelabfrage per Name-Filter (umgeht jegliches Listen-Matching)
            if (-not $found) {
                foreach ($n in $names) {
                    try {
                        $found = Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($found) { break }
                    } catch {}
                }
            }
            # Stufe 4: Lokaler Get-Service in der Session (funktioniert auch, wenn CIM eingeschraenkt ist)
            if (-not $found) {
                foreach ($n in $names) {
                    try {
                        $s = Get-Service -Name $n -ErrorAction Stop
                        $found = [pscustomobject]@{ Name=$s.Name; DisplayName=$s.DisplayName; State="$($s.Status)"; StartMode="$($s.StartType)" }
                        break
                    } catch {}
                }
            }
            if ($found) {
                $st = "$($found.State)"; $sm = "$($found.StartMode)"
                if ($sm -eq 'Auto') { $sm = 'Automatic' }
                $rows += [pscustomobject]@{
                    Service=$svc; Description=$cfg.Description; RealName=$found.Name
                    DisplayName=$found.DisplayName; Status=$st; StartType=$sm
                }
            } else {
                $rows += [pscustomobject]@{ Service=$svc; Description=$cfg.Description; RealName='N/A'; DisplayName='-'; Status='NotFound'; StartType='N/A' }
            }
        }
        $rows
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb -ArgumentList @($Global:ServiceMap)
    if (-not $data) {
        # Letzter Fallback: Get-Service ueber RPC (alter Ansatz)
        $res = @()
        foreach ($svc in $Global:ServiceMap.Keys) {
            $cfg = $Global:ServiceMap[$svc]; $ok = $false
            foreach ($n in $cfg.Names) {
                try {
                    $s = Get-Service -ComputerName $DC -Name $n -ErrorAction Stop
                    $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName=$s.Name; DisplayName=$s.DisplayName; Status="$($s.Status)"; StartType="$($s.StartType)" }
                    $ok=$true; break
                } catch {}
            }
            if (-not $ok) { $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName='N/A'; DisplayName='-'; Status='NotFound'; StartType='N/A' } }
        }
        return $res
    }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Invoke-DCDiag {
    param([Parameter(Mandatory)][string]$DC)
    try { $raw = & dcdiag.exe /s:$DC /v /test:DNS /DnsBasic /DnsForwarders /DnsDelegation /DnsDynamicUpdate /DnsRecordRegistration 2>&1 | Out-String }
    catch { return @([pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='dcdiag.exe'; PartitionOrScope='-'; Result='ERROR'; ErrorDetails="$_"; RawSnippet='-' }) }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @([pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='dcdiag.exe'; PartitionOrScope='-'; Result='ERROR'; ErrorDetails='Keine Ausgabe'; RawSnippet='-' }) }
    $lines = $raw -split "`r?`n"; $results = @()
    $curCat='Server'; $curScope=$DC; $curTest=$null; $curErr=@()
    $rxStart='^\s*(?:Starting test|Starttest)\s*:\s*(\S+)'
    $rxPass='(?:passed test|bestandener Test|Test.*bestanden)\s+(\S+)'
    $rxFail='(?:failed test|fehlgeschlagener Test|Test.*fehlgeschlagen)\s+(\S+)'
    $rxPart='(?:Running partition tests on|Partitionstests)\s*:\s*(\S+)'
    $rxFor='(?:Running enterprise tests on|Unternehmenstests)\s*:\s*(\S+)'
    $rxSrv='(?:Testing server|Server wird getestet)\s*:\s*(\S+)'
    foreach ($line in $lines) {
        if ($line -match $rxSrv)  { $curCat='Server';    $curScope=$Matches[1]; continue }
        if ($line -match $rxPart) { $curCat='Partition'; $curScope=$Matches[1]; continue }
        if ($line -match $rxFor)  { $curCat='Forest';    $curScope=$Matches[1]; continue }
        if ($line -match $rxStart) {
            if ($curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='UNKNOWN'; ErrorDetails=($curErr -join "`n").Trim(); RawSnippet='-' } }
            $curTest=$Matches[1]; $curErr=@(); continue
        }
        if ($line -match $rxPass) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$Matches[1]; PartitionOrScope=$curScope; Result='PASSED'; ErrorDetails=''; RawSnippet='' }; $curTest=$null; $curErr=@(); continue }
        if ($line -match $rxFail) {
            $n=$Matches[1]; $e=($curErr | Where-Object { $_.Trim() } | Select-Object -First 20) -join "`n"; if (-not $e) { $e=$line.Trim() }
            $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$n; PartitionOrScope=$curScope; Result='FAILED'; ErrorDetails=$e.Trim(); RawSnippet=$line.Trim() }
            $curTest=$null; $curErr=@(); continue
        }
        if ($line -match '^\s*TEST\s*:\s*(\S+)') { $curTest=$Matches[1]; $curErr=@(); $curCat='DNS'; continue }
        if ($line -match '^\s*(Passed|Bestanden)\s*:\s*(\S+)') { $results += [pscustomobject]@{ DCName=$DC; Category='DNS'; TestName=$Matches[2]; PartitionOrScope=$curScope; Result='PASSED'; ErrorDetails=''; RawSnippet='' }; $curTest=$null; $curErr=@(); continue }
        if ($line -match '^\s*(Warning|Warnung)\s*:\s*(.+)' -and $curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='WARNING'; ErrorDetails=$Matches[2].Trim(); RawSnippet=$line.Trim() }; $curTest=$null; $curErr=@(); continue }
        if ($curTest -and $line.Trim() -and $line -notmatch '^\s*\.{3,}\s*$') { $curErr += $line.TrimEnd() }
    }
    if ($curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='UNKNOWN'; ErrorDetails=($curErr -join "`n").Trim(); RawSnippet='-' } }
    if (@($results).Count -eq 0) { $results += [pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='(parsed=0)'; PartitionOrScope='-'; Result='UNKNOWN'; ErrorDetails='Nicht parsebar'; RawSnippet=$raw.Substring(0,[math]::Min(500,$raw.Length)) } }
    $results
}

function Get-ReplicationPartners {
    param([Parameter(Mandatory)][string]$DC)
    Get-ADReplicationPartnerMetadata -Target $DC -Scope Server -ErrorAction Stop |
        Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures
}

function Get-ReplicationFailures {
    $failures = @()
    try { $fn = (Get-ADForest -ErrorAction Stop).Name; $failures = Get-ADReplicationFailure -Target $fn -Scope Forest -ErrorAction Stop }
    catch { try { foreach ($dc in (Get-ADDomainController -Filter * -ErrorAction Stop)) { try { $f = Get-ADReplicationFailure -Target $dc.HostName -Scope Server -ErrorAction Stop; if ($f) { $failures += $f } } catch {} } } catch {} }
    $failures
}

function Get-FSMORoles {
    $f=Get-ADForest -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ SchemaMaster=$f.SchemaMaster; DomainNamingMaster=$f.DomainNamingMaster; PDCEmulator=$d.PDCEmulator; RIDMaster=$d.RIDMaster; InfrastructureMaster=$d.InfrastructureMaster }
}

function Get-DNSConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $result = @()
    foreach ($t in (Get-DnsServerTargets -ComputerName $DC)) {
        try {
            $result += @(Get-DnsServerZone @t -ErrorAction Stop |
                Select-Object @{n='DCName';e={$DC}}, ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate)
            break
        } catch {}
    }
    return $result
}

function Get-SysvolStatus {
    param([Parameter(Mandatory)][string]$DC)
    [pscustomobject]@{ DCName=$DC; SYSVOL_Accessible=Test-Path "\\$DC\SYSVOL"; NETLOGON_Accessible=Test-Path "\\$DC\NETLOGON"; SYSVOL_Path="\\$DC\SYSVOL"; NETLOGON_Path="\\$DC\NETLOGON" }
}

function Get-NTDSDatabase {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $p = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop).'DSA Database file'
        if (-not $p) { return $null }
        $f = Get-Item $p -ErrorAction SilentlyContinue
        if ($f) {
            $d = Get-PSDrive ($f.PSDrive.Name)
            [pscustomobject]@{ DBPath=$f.FullName; DBSize_MB=[math]::Round(($f.Length/1MB),2); DriveFree_GB=[math]::Round(($d.Free/1GB),2); DriveUsed_GB=[math]::Round(($d.Used/1GB),2) }
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-TLSConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $protos = 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'
        $out = @()
        foreach ($p in $protos) {
            foreach ($side in 'Client','Server') {
                $key = Join-Path $base "$p\$side"
                $ex = Test-Path $key
                $e = $null; $d = $null; $st = 'NotConfigured'
                if ($ex) {
                    $e = (Get-ItemProperty $key -Name Enabled -ErrorAction SilentlyContinue).Enabled
                    $d = (Get-ItemProperty $key -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
                    if ($e -eq 0) { $st='Disabled' } elseif ($e -eq 1) { $st='Enabled' } elseif ($d -eq 1) { $st='DisabledByDefault' } else { $st='EnabledByDefault' }
                }
                $out += [pscustomobject]@{ Protocol=$p; Side=$side; RegistryKeyExists=$ex; Enabled=$e; DisabledByDefault=$d; State=$st }
            }
        }
        $out
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-CipherConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
        if (-not (Test-Path $base)) { return @() }
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{ Cipher=$_.PSChildName; Enabled=$p.Enabled }
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-LDAPSecurity {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $r = [ordered]@{}
        $n = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $si = $null; try { $si = (Get-ItemProperty $n -Name LDAPServerIntegrity -ErrorAction Stop).LDAPServerIntegrity } catch {}
        $r.LDAPServerIntegrity = $si
        $r.LDAPServerIntegrity_Meaning = switch ($si) { 0{'None (unsicher!)'} 1{'Negotiate'} 2{'Require - Best Practice'} $null{'NICHT KONFIGURIERT'} default{"Unbekannt ($si)"} }
        $cb = $null; try { $cb = (Get-ItemProperty $n -Name LdapEnforceChannelBinding -ErrorAction Stop).LdapEnforceChannelBinding } catch {}
        $r.LdapEnforceChannelBinding = $cb
        $r.LdapEnforceChannelBinding_Meaning = switch ($cb) { 0{'Disabled (unsicher!)'} 1{'When Supported'} 2{'Always - Best Practice'} $null{'NICHT KONFIGURIERT'} default{"Unbekannt ($cb)"} }
        $r.LDAPSPortOpen = $null
        try { $r.LDAPSPortOpen = Test-NetConnection -ComputerName 'localhost' -Port 636 -WarningAction SilentlyContinue -InformationLevel Quiet } catch {}
        $r.UnsignedLDAPBinds_7d = 0
        try { $r.UnsignedLDAPBinds_7d = @(Get-WinEvent -FilterHashtable @{ LogName='Directory Service'; ID=2889; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue).Count } catch {}
        [pscustomobject]$r
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; LDAPServerIntegrity=$null; LDAPServerIntegrity_Meaning='(Abfrage fehlgeschlagen)'; LdapEnforceChannelBinding=$null; LdapEnforceChannelBinding_Meaning='-'; LDAPSPortOpen=$null; UnsignedLDAPBinds_7d=$null }) }
    $data | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force
}

function Get-PrivilegedAccounts {
    $result = @()
    try { $dSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value } catch { return $result }
    $g = @(
        [pscustomobject]@{ DisplayName='Domain Admins'; SID="$dSid-512" }
        [pscustomobject]@{ DisplayName='Enterprise Admins'; SID="$dSid-519" }
        [pscustomobject]@{ DisplayName='Schema Admins'; SID="$dSid-518" }
        [pscustomobject]@{ DisplayName='Group Policy Creator Owners'; SID="$dSid-520" }
        [pscustomobject]@{ DisplayName='DnsAdmins'; SID=$null; FallbackName='DnsAdmins' }
        [pscustomobject]@{ DisplayName='Administrators'; SID='S-1-5-32-544' }
        [pscustomobject]@{ DisplayName='Account Operators'; SID='S-1-5-32-548' }
        [pscustomobject]@{ DisplayName='Server Operators'; SID='S-1-5-32-549' }
        [pscustomobject]@{ DisplayName='Print Operators'; SID='S-1-5-32-550' }
        [pscustomobject]@{ DisplayName='Backup Operators'; SID='S-1-5-32-551' }
    )
    foreach ($x in $g) {
        try {
            $grp = $null
            if ($x.SID) { try { $grp = Get-ADGroup -Identity $x.SID -ErrorAction Stop } catch {} }
            if (-not $grp -and $x.FallbackName) { try { $grp = Get-ADGroup -Identity $x.FallbackName -ErrorAction Stop } catch {} }
            if (-not $grp) { continue }
            $mem = @()
            try { $mem = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop }
            catch { try { $mem = Get-ADGroupMember -Identity $grp -ErrorAction Stop } catch { continue } }
            if (@($mem).Count -eq 0) {
                $result += [pscustomobject]@{ Group=$x.DisplayName; LocalizedName=$grp.Name; MemberName='<leer>'; SamAccountName='-'; ObjectClass='-'; DistinguishedName='-' }
                continue
            }
            foreach ($m in $mem) {
                $result += [pscustomobject]@{ Group=$x.DisplayName; LocalizedName=$grp.Name; MemberName=$m.Name; SamAccountName=$m.SamAccountName; ObjectClass=$m.objectClass; DistinguishedName=$m.DistinguishedName }
            }
        } catch {}
    }
    return $result
}

function Get-PasswordPolicy {
    $def = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $r = @([pscustomobject]@{ Type='Default Domain Policy'; Name='Default'; MinPasswordLength=$def.MinPasswordLength; PasswordHistoryCount=$def.PasswordHistoryCount; MaxPasswordAge=$def.MaxPasswordAge; MinPasswordAge=$def.MinPasswordAge; LockoutThreshold=$def.LockoutThreshold; LockoutDuration=$def.LockoutDuration; ComplexityEnabled=$def.ComplexityEnabled })
    try {
        Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | ForEach-Object {
            $r += [pscustomobject]@{ Type='Fine-Grained Policy'; Name=$_.Name; MinPasswordLength=$_.MinPasswordLength; PasswordHistoryCount=$_.PasswordHistoryCount; MaxPasswordAge=$_.MaxPasswordAge; MinPasswordAge=$null; LockoutThreshold=$null; LockoutDuration=$null; ComplexityEnabled=$null }
        }
    } catch {}
    $r
}

function Get-KerberosInfo {
    $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet,PasswordNeverExpires,Enabled -ErrorAction Stop
    $a = if ($k.PasswordLastSet) { (New-TimeSpan -Start $k.PasswordLastSet -End (Get-Date)).Days } else { $null }
    [pscustomobject]@{ Account='krbtgt'; PasswordLastSet=$k.PasswordLastSet; PasswordAgeDays=$a; MaxAllowedDays=$Global:KrbtgtMaxAgeDays; NeedsReset=($a -gt $Global:KrbtgtMaxAgeDays); Enabled=$k.Enabled }
}

function Get-SecureBootStatus {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $fw = 'Unknown'
        try { $f = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType; if ($f) { $fw="$f" } }
        catch { $ef = [System.Environment]::GetEnvironmentVariable('firmware_type'); if ($ef) { $fw=$ef } }
        $sbEn = 'Unknown'
        try { $sbEn = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' } }
        catch { if ($_.Exception.Message -match 'not supported|nicht unterstuetzt|Cmdlet wird') { $sbEn='NotSupported' } else { $sbEn='Error' } }
        $regBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
        $au=$null; $auSet=$false
        try { $p = Get-ItemProperty $regBase -Name AvailableUpdates -ErrorAction Stop; $au=$p.AvailableUpdates; $auSet=$true } catch {}
        $auHex = if ($null -ne $au) { ('0x{0:X}' -f $au) } else { '(nicht gesetzt)' }
        $wc=$null; $us=$null; $ue=$null
        try {
            $s = Get-ItemProperty (Join-Path $regBase 'Servicing') -ErrorAction Stop
            if ($s.PSObject.Properties.Name -contains 'WindowsUEFICA2023Capable') { $wc = [int]$s.WindowsUEFICA2023Capable }
            if ($s.PSObject.Properties.Name -contains 'UEFICA2023Status') { $us = "$($s.UEFICA2023Status)" }
            if ($s.PSObject.Properties.Name -contains 'UEFICA2023Error')  { $ue = $s.UEFICA2023Error }
        } catch {}
        if (-not $us) { $us = '(nicht gesetzt)' }
        $h2023=$false; $k2023=$false
        try { $db = Get-SecureBootUEFI -Name db -ErrorAction Stop; if ($db -and $db.bytes) { $h2023 = [System.Text.Encoding]::ASCII.GetString($db.bytes) -match 'Windows UEFI CA 2023' } } catch {}
        try { $kek = Get-SecureBootUEFI -Name KEK -ErrorAction Stop; if ($kek -and $kek.bytes) { $k2023 = [System.Text.Encoding]::ASCII.GetString($kek.bytes) -match 'Microsoft Corporation KEK (2K )?CA 2023' } } catch {}
        $lastSucc=$null; $lastFail=$null; $lastFailMsg=''
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-TPM-WMI'; Id=1796,1798,1801,1808 } -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($e in $ev) {
                if ($e.Id -in 1796,1798,1808) { if (-not $lastSucc -or $e.TimeCreated -gt $lastSucc) { $lastSucc=$e.TimeCreated } }
                if ($e.Id -eq 1801)           { if (-not $lastFail -or $e.TimeCreated -gt $lastFail) { $lastFail=$e.TimeCreated; $lastFailMsg=($e.Message -split "`n")[0] } }
            }
        } catch {}
        $status='UNKNOWN'; $detail=''
        if ($sbEn -match 'Disabled|NotSupported') { $status='NOT_APPLICABLE'; $detail='Secure Boot nicht aktiv' }
        elseif ($us -match 'Updated' -or ($h2023 -and $k2023)) { $status='SUCCESS'; $detail = if ($lastSucc) { "Erfolgreich am $lastSucc (UEFI CA 2023 + KEK CA 2023)" } else { "UEFI CA 2023 in DB/KEK vorhanden" } }
        elseif ($us -match 'In Progress|InProgress') { $status='IN_PROGRESS'; $detail="Update laeuft" }
        elseif ($lastFail -and -not $h2023) { $status='FAILED'; $detail="Letzter Versuch $lastFail fehlgeschlagen: $lastFailMsg" }
        elseif (($null -ne $ue) -and ($ue -ne 0) -and -not $h2023) { $status='FAILED'; $detail=("Registry-Fehler UEFICA2023Error=0x{0:X}" -f $ue) }
        elseif ($auSet -and $au -gt 0) { $status='PENDING'; $detail="AvailableUpdates=$auHex gesetzt - wartet auf Reboot" }
        elseif ($us -match 'Not Started|NotStarted' -or ($wc -eq 1 -and -not $auSet)) { $status='NOT_STARTED'; $detail="Registry 'AvailableUpdates' nicht gesetzt" }
        elseif ($wc -eq 0) { $status='NOT_CAPABLE'; $detail="Geraet NICHT faehig - Firmware-Update pruefen" }
        else { $status='UNKNOWN'; $detail="Capable=$wc, Status='$us', AU=$auHex, DB2023=$h2023, KEK2023=$k2023" }
        $residual = ''
        if ($status -eq 'SUCCESS' -and $auSet -and $au -gt 0) {
            $bits = @()
            if ($au -band 0x10) { $bits += 'BootMgr' }; if ($au -band 0x40) { $bits += 'DB' }; if ($au -band 0x100) { $bits += 'DBX' }
            if ($au -band 0x400) { $bits += 'KEK' }; if ($au -band 0x1000) { $bits += 'PCA2011-Revoke' }
            if ($au -band 0x2000) { $bits += 'BootMgr-Revoke' }; if ($au -band 0x4000) { $bits += 'DBX-SVN' }
            $residual = $bits -join ','
            $detail += " | Hinweis: Registry-Bit(s) [$residual] noch offen - Reboot empfohlen"
        }
        [pscustomobject]@{
            SecureBoot=$sbEn; UpdateStatus=$status; Registry_AvailableUpdates=$auHex
            Registry_UEFICA2023Status=$us; Detail=$detail
            _Firmware=$fw; _ResidualBits=$residual
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; UpdateStatus='UNKNOWN'; SecureBoot='-'; Registry_AvailableUpdates='-'; Registry_UEFICA2023Status='-'; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{
        DCName=$DC; UpdateStatus=$data.UpdateStatus; SecureBoot=$data.SecureBoot
        Registry_AvailableUpdates=$data.Registry_AvailableUpdates
        Registry_UEFICA2023Status=$data.Registry_UEFICA2023Status; Detail=$data.Detail
        _Firmware=$data._Firmware; _ResidualBits=$data._ResidualBits
    }
}

function Get-DCCertificates {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        param($wd)
        $out = @()
        foreach ($st in 'Cert:\LocalMachine\My','Cert:\LocalMachine\WebHosting') {
            try {
                foreach ($c in (Get-ChildItem -Path $st -ErrorAction SilentlyContinue)) {
                    $out += [pscustomobject]@{ Store=$st; Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint; NotBefore=$c.NotBefore; NotAfter=$c.NotAfter; DaysToExpiry=[int]($c.NotAfter - (Get-Date)).TotalDays; IsExpiringSoon=($c.NotAfter - (Get-Date)).TotalDays -le $wd; HasPrivateKey=$c.HasPrivateKey; EnhancedKeyUsage=($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join '; ' }
                }
            } catch {}
        }
        if (@($out).Count -eq 0) { $out += [pscustomobject]@{ Store='Cert:\LocalMachine\My'; Subject='(keine Zertifikate)'; Issuer='-'; Thumbprint='-'; NotBefore=$null; NotAfter=$null; DaysToExpiry=$null; IsExpiringSoon=$false; HasPrivateKey=$false; EnhancedKeyUsage='-' } }
        $out
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb -ArgumentList $Global:CertExpiryWarnDays
    if (-not $data) { $data = @([pscustomobject]@{ Store='N/A'; Subject='(Abfrage fehlgeschlagen)'; Issuer='-'; Thumbprint='-'; NotBefore=$null; NotAfter=$null; DaysToExpiry=$null; IsExpiringSoon=$false; HasPrivateKey=$false; EnhancedKeyUsage='-' }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-ADSitesInfo { Get-ADReplicationSite -Filter * -Properties * -ErrorAction Stop | Select-Object Name, Description, Location, whenCreated, whenChanged }
function Get-ADSubnetsInfo { Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop | Select-Object Name, Site, Description, Location, whenCreated }
function Get-ADTrusts { Get-ADTrust -Filter * -ErrorAction Stop | Select-Object Name, Source, Target, Direction, TrustType, ForestTransitive, IntraForest, whenCreated }

function Get-ADLevels {
    $f=Get-ADForest -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ ForestName=$f.Name; ForestMode=$f.ForestMode; DomainName=$d.DNSRoot; DomainMode=$d.DomainMode; SchemaMaster=$f.SchemaMaster; DomainController=($d.ReplicaDirectoryServers -join ', ') }
}

function Get-GPOHealth {
    Get-GPO -All -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ DisplayName=$_.DisplayName; Id=$_.Id; GpoStatus=$_.GpoStatus; CreationTime=$_.CreationTime; ModificationTime=$_.ModificationTime; Owner=$_.Owner; UserVersion_DS=$_.User.DSVersion; UserVersion_Sys=$_.User.SysvolVersion; CompVersion_DS=$_.Computer.DSVersion; CompVersion_Sys=$_.Computer.SysvolVersion }
    }
}

function Get-InactiveAccounts {
    $d = [ordered]@{ InactiveUsers=@(); InactiveComputers=@(); PasswordNeverExpires=@() }
    $cu=(Get-Date).AddDays(-$Global:InactiveDaysUser); $cc=(Get-Date).AddDays(-$Global:InactiveDaysComputer)
    try { $d.InactiveUsers = @(Get-ADUser -Filter { LastLogonDate -lt $cu -and Enabled -eq $true } -Properties LastLogonDate,PasswordLastSet -ErrorAction Stop | Select-Object SamAccountName,Name,Enabled,LastLogonDate,PasswordLastSet,DistinguishedName) } catch {}
    try { $d.InactiveComputers = @(Get-ADComputer -Filter { LastLogonDate -lt $cc -and Enabled -eq $true } -Properties LastLogonDate,OperatingSystem -ErrorAction Stop | Select-Object Name,Enabled,LastLogonDate,OperatingSystem,DistinguishedName) } catch {}
    try { $d.PasswordNeverExpires = @(Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires,PasswordLastSet -ErrorAction Stop | Select-Object SamAccountName,Name,PasswordLastSet,DistinguishedName) } catch {}
    [pscustomobject]$d
}

function Get-DCEventLog {
    param([Parameter(Mandatory)][string]$DC)
    $since = (Get-Date).AddHours(-$Global:EventLogHours)
    $all = @()
    foreach ($log in 'System','Directory Service','DNS Server') {
        try {
            $ev = Get-WinEvent -ComputerName $DC -FilterHashtable @{ LogName=$log; Level=1,2; StartTime=$since } -MaxEvents 50 -ErrorAction Stop
            foreach ($e in $ev) {
                $all += [pscustomobject]@{ DCName=$DC; LogName=$log; TimeCreated=$e.TimeCreated; Level=$e.LevelDisplayName; EventID=$e.Id; Provider=$e.ProviderName; Message=($e.Message -split "`n")[0] }
            }
        } catch {}
    }
    $all
}

function Get-TimeSyncStatus {
    param([Parameter(Mandatory)][string]$DC, [string]$PDCEmulator='')
    $sb = {
        $sR = & w32tm /query /status /verbose 2>&1 | Out-String
        $cR = & w32tm /query /configuration  2>&1 | Out-String
        $srcR = & w32tm /query /source 2>&1 | Out-String
        $src = ($srcR -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^Die Abfrage|^The following|^$' } | Select-Object -First 1).Trim()
        $strat=$null; if ($sR -match 'Stratum\s*:\s*(\d+)') { $strat=[int]$Matches[1] }
        $ls=$null; $m=[regex]::Match($sR,'(?:Last Successful Sync Time|Letzte erfolgreiche Synchronisierungszeit)\s*:\s*(.+)'); if ($m.Success) { $ls=$m.Groups[1].Value.Trim() }
        $type=$null; $m=[regex]::Match($cR,'(?:^|\s)Type:\s*([^\r\n]+)'); if ($m.Success) { $type=$m.Groups[1].Value.Trim() }
        $ntp=$null; $m=[regex]::Match($cR,'NtpServer:\s*([^\r\n]+)'); if ($m.Success) { $ntp=$m.Groups[1].Value.Trim() }
        [pscustomobject]@{ Source=$src; Stratum=$strat; LastSyncTime=$ls; ConfiguredType=$type; ConfiguredNtpSrv=$ntp }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return }
    $isPDC = ($DC -ieq $PDCEmulator -or $DC -ilike "$PDCEmulator*" -or $PDCEmulator -ilike "$DC*")
    $sk='Unknown'
    if     ($data.Source -match 'Local CMOS Clock|Lokale CMOS-Uhr') { $sk='LocalClock' }
    elseif ($data.Source -match 'Free-running') { $sk='FreeRunning' }
    elseif ($data.Source -match 'VM IC Time Provider') { $sk='HyperVHost' }
    elseif ($data.Source -match '^[\w\.\-]+$') { $sk='Server' }
    [pscustomobject]@{ DCName=$DC; IsPDCEmulator=$isPDC; Source=$data.Source; SourceKind=$sk; Stratum=$data.Stratum; LastSyncTime=$data.LastSyncTime; ConfiguredType=$data.ConfiguredType; ConfiguredNtpSrv=$data.ConfiguredNtpSrv }
}

function Get-ADBackupStatus {
    $dom = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $raw = & repadmin /showbackup $dom 2>&1 | Out-String
    $lb = $null; if ($raw -match 'dSASignature.*:\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') { $lb = [datetime]$Matches[1] }
    $a = if ($lb) { (New-TimeSpan -Start $lb -End (Get-Date)).Days } else { $null }
    [pscustomobject]@{ LastBackup=$lb; AgeDays=$a; MaxAllowedDays=$Global:BackupMaxAgeDays; BackupOverdue=($a -gt $Global:BackupMaxAgeDays); RawOutput=($raw -split "`n" | Select-Object -First 20) -join "`n" }
}

function Get-InstalledPrograms {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $out = @()
        foreach ($k in $keys) {
            try {
                Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DisplayName) {
                        $id = $null
                        if ($_.InstallDate -and $_.InstallDate -match '^\d{8}$') { try { $id = [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null) } catch {} }
                        $out += [pscustomobject]@{ DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallDate=$id; InstallLocation=$_.InstallLocation; EstimatedSizeMB=if ($_.EstimatedSize) { [math]::Round(($_.EstimatedSize/1024),2) } else { $null }; Architecture=if ($k -match 'Wow6432Node') { 'x86' } else { 'x64' } }
                    }
                }
            } catch {}
        }
        $out | Sort-Object -Property InstallDate -Descending
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-WindowsUpdates {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        try {
            Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 20 |
                Select-Object HotFixID, Description, InstalledOn, InstalledBy, @{n='DaysAgo';e={ [int](New-TimeSpan -Start $_.InstalledOn -End (Get-Date)).TotalDays }}
        } catch {
            Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 20 |
                Select-Object @{n='HotFixID';e={$_.HotFixID}}, Description, InstalledOn, InstalledBy, @{n='DaysAgo';e={ [int](New-TimeSpan -Start $_.InstalledOn -End (Get-Date)).TotalDays }}
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; HotFixID='(keine Daten)'; Description='-'; InstalledOn=$null; InstalledBy='-'; DaysAgo=$null }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

#endregion
#region ====================== HELPER ========================================

function Get-SortedResultKeys {
    # Reihenfolge direkt aus $Global:ReportTitles (= thematisch)
    return @($Global:ReportTitles.Keys | Where-Object { $Global:Results.Contains($_) })
}

function Get-ReportKeys {
    <#
    .SYNOPSIS
        Liefert die Keys, die im Report erscheinen sollen.
    #>
    $out = @()
    foreach ($k in $Global:ReportTitles.Keys) {
        if ($k -eq '00_SkippedDCs') {
            if ($Global:Results[$k] -and @($Global:Results[$k]).Count -gt 0) { $out += $k }
            continue
        }
        if ($Global:SelectedChecks -contains $k) { $out += $k }
    }
    return $out
}

function Initialize-ResultKeys {
    foreach ($k in $Global:ReportTitles.Keys) { $Global:Results[$k] = @() }
}

function Import-RequiredModules {
    foreach ($mod in 'ActiveDirectory','GroupPolicy','DnsServer') {
        try {
            if (-not (Get-Module -Name $mod)) {
                Import-Module $mod -ErrorAction Stop
                Write-Log "Modul '$mod' geladen." -Level OK
            }
        } catch { Write-Log "Modul '$mod' nicht ladbar: $_" -Level WARN }
    }
}

#endregion

#region ======================= CONNECTIVITY ==================================

function Test-IsLocalComputer {
    <#
    .SYNOPSIS
        Prueft, ob ein Computername den lokalen Rechner bezeichnet.
    .NOTES
        Erkennt den lokalen Rechner in NetBIOS-Form, FQDN-Form, IP-Form und 'localhost'.
        Fuer FQDN (z.B. 'DC1.contoso.local') wird der Kurzname vor dem ersten Punkt
        mit $env:COMPUTERNAME verglichen.
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        if (-not $Global:LocalIdentifiers) {
            $local = @('localhost','127.0.0.1','::1',$env:COMPUTERNAME)
            try { $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; if ($fqdn) { $local += $fqdn } } catch {}
            try { $local += Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress } catch {}
            $Global:LocalIdentifiers = $local | Select-Object -Unique
        }
        # Exakter Vergleich (NetBIOS, FQDN, IP, localhost)
        foreach ($id in $Global:LocalIdentifiers) { if ($ComputerName -ieq $id) { return $true } }
        # FQDN-Erkennung: Kurzname vor erstem Punkt gegen $env:COMPUTERNAME
        if ($ComputerName -match '\.') {
            $short = $ComputerName.Substring(0, $ComputerName.IndexOf('.'))
            if ($short -ieq $env:COMPUTERNAME) { return $true }
        }
        return $false
    } catch { return $false }
}

function Get-DnsServerTargets {
    <#
    .SYNOPSIS
        Liefert die zu versuchenden Ziel-Parameter fuer DnsServer-Cmdlets.
    .NOTES
        Problem: DnsServer-Cmdlets mit -ComputerName <lokaler DC> erzwingen CIM/WMI-Remoting
        ueber sich selbst. Bei gesperrtem WinRM-Loopback/DCOM schlaegt das fehl,
        obwohl DNS lokal installiert ist. Check 42 war nie betroffen, da er ohne
        -ComputerName abfragt.
        Loesung: Pruefreihenfolge fuer lokalen DC:
          1. @{}                    -> in-process (kein -ComputerName)
          2. @{ComputerName='localhost'} -> CIM gegen localhost
          3. @{ComputerName=$ComputerName} -> CIM gegen uebergebenen Namen
        Fuer remote DCs: nur @{ComputerName=$ComputerName}
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    $isLocal = Test-IsLocalComputer -ComputerName $ComputerName
    if ($isLocal) {
        # Lokal: erst in-process, dann localhost, dann uebergebener Name
        @(@{}, @{ComputerName='localhost'}, @{ComputerName=$ComputerName})
    }
    else {
        # Remote: nur uebergebener Name
        @(@{ComputerName=$ComputerName})
    }
}

function Test-DCPing {
    param([Parameter(Mandatory)][string]$DCName)
    if (Test-IsLocalComputer -ComputerName $DCName) { return $true }
    try {
        for ($i=1; $i -le $Global:PingCount; $i++) {
            try { if (Test-Connection -ComputerName $DCName -Count 1 -Quiet -ErrorAction Stop) { return $true } }
            catch { Start-Sleep -Milliseconds 500 }
        }
        return $false
    } catch { return $false }
}

function Test-DCConnectivity {
    param([Parameter(Mandatory)][string]$DCName)
    $isLocal = Test-IsLocalComputer -ComputerName $DCName
    $result = [pscustomobject]@{
        DCName=$DCName; IsLocalComputer=$isLocal; EffectiveTarget=$DCName
        Ping=$false; WinRM=$false; WinRM_Loopback=$false; CIM_DCOM=$false; WMI=$false
        Method='None'; Reachable=$false; SkipReason=''; ErrorMsg=''
    }
    if ($isLocal) { $result.Ping = $true } else { $result.Ping = Test-DCPing -DCName $DCName }
    if (-not $result.Ping -and -not $Global:TryWinRMIfNoPing) { $result.SkipReason="Kein Ping"; return $result }
    try { $null = Test-WSMan -ComputerName $DCName -ErrorAction Stop; $result.WinRM=$true; $result.Method='WinRM'; $result.Reachable=$true; return $result } catch {}
    if ($isLocal) {
        try { $null = Test-WSMan -ComputerName 'localhost' -ErrorAction Stop; $result.WinRM=$true; $result.WinRM_Loopback=$true; $result.Method='WinRM_Loopback'; $result.EffectiveTarget='localhost'; $result.Reachable=$true; return $result } catch {}
    }
    try {
        $t = if ($isLocal) { 'localhost' } else { $DCName }
        $opt = New-CimSessionOption -Protocol Dcom
        $cim = New-CimSession -ComputerName $t -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop
        Remove-CimSession $cim
        $result.CIM_DCOM=$true; $result.Method='CIM_DCOM'; $result.EffectiveTarget=$t; $result.Reachable=$true
        return $result
    } catch {}
    try {
        $t = if ($isLocal) { '.' } else { $DCName }
        $null = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $t -ErrorAction Stop
        $result.WMI=$true; $result.Method='WMI'; $result.EffectiveTarget=$t; $result.Reachable=$true; return $result
    } catch { $result.ErrorMsg="Alle Methoden fehlgeschlagen: $_" }
    $result.SkipReason = if (-not $result.Ping) { "Kein Ping UND kein WinRM/CIM/WMI" } else { "WinRM/CIM/WMI alle fehlgeschlagen" }
    return $result
}

function Invoke-RemoteCommand {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    $conn = $Global:DCConnectivity[$ComputerName]
    if (-not $conn) { $conn = Test-DCConnectivity -DCName $ComputerName }
    $isLocal = $conn.IsLocalComputer
    $target  = if ($conn.EffectiveTarget) { $conn.EffectiveTarget } else { $ComputerName }
    try {
        if ($isLocal) { if ($ArgumentList) { return & $ScriptBlock @ArgumentList } else { return & $ScriptBlock } }
        if ($conn.WinRM) { return Invoke-Command -ComputerName $target -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop }
        return $null
    } catch {
        if ($isLocal) { try { if ($ArgumentList) { return & $ScriptBlock @ArgumentList } else { return & $ScriptBlock } } catch { return $null } }
        Write-Log "Invoke-RemoteCommand '$ComputerName': $_" -Level ERROR -NoConsole
        return $null
    }
}

function Get-RemoteCimData {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$ClassName,
        [string]$Filter,
        [string]$Namespace='root\cimv2'
    )
    $isLocal = Test-IsLocalComputer -ComputerName $ComputerName
    if ($isLocal) {
        try {
            if ($Filter) { return Get-CimInstance -ClassName $ClassName -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
            else         { return Get-CimInstance -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop }
        } catch { return $null }
    }
    $sess = $null
    try { $opt = New-CimSessionOption -Protocol Wsman; $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop }
    catch {
        try { $opt = New-CimSessionOption -Protocol Dcom; $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec $Global:WinRMTimeoutSec -ErrorAction Stop }
        catch { return $null }
    }
    try {
        if ($Filter) { return Get-CimInstance -CimSession $sess -ClassName $ClassName -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
        else         { return Get-CimInstance -CimSession $sess -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop }
    } catch { return $null }
      finally { if ($sess) { Remove-CimSession $sess -ErrorAction SilentlyContinue } }
}

#endregion

#region ============= DATENSAMMEL-FUNKTIONEN (BESTEHEND) =====================

function Get-DCSystemInfo {
    param([Parameter(Mandatory)][string]$DC)
    $os=Get-RemoteCimData -ComputerName $DC -ClassName Win32_OperatingSystem
    $cs=Get-RemoteCimData -ComputerName $DC -ClassName Win32_ComputerSystem
    $bio=Get-RemoteCimData -ComputerName $DC -ClassName Win32_BIOS
    [pscustomobject]@{
        DCName=$DC; OS=$os.Caption; OSVersion=$os.Version; OSBuild=$os.BuildNumber
        InstallDate=$os.InstallDate; LastBoot=$os.LastBootUpTime
        Manufacturer=$cs.Manufacturer; Model=$cs.Model
        TotalRAM_GB=[math]::Round(($cs.TotalPhysicalMemory/1GB),2)
        LogicalProcessors=$cs.NumberOfLogicalProcessors
        BIOSVersion=$bio.SMBIOSBIOSVersion; Domain=$cs.Domain
    }
}

function Get-DCServiceStatus {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        param($map)
        $rows = @()
        # Alle Dienste in EINER CIM-Abfrage holen (ueber WinRM - kein RPC noetig)
        $all = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
        if ($all.Count -eq 0) {
            # Fallback: Get-Service in der Remoting-Session
            $all = @(Get-Service -ErrorAction SilentlyContinue |
                Select-Object Name, DisplayName, @{n='State';e={ "$($_.Status)" }}, @{n='StartMode';e={ "$($_.StartType)" }})
        }
        foreach ($svc in $map.Keys) {
            $cfg = $map[$svc]
            $names = @($cfg.Names); $displays = @($cfg.DisplayNames); $patterns = @($cfg.Patterns)
            # Stufe 1: Matching per Service-Name (sprachunabhaengig) ODER Display-Name (DE/EN)
            $found = $all | Where-Object { $names -contains $_.Name -or $displays -contains $_.DisplayName } | Select-Object -First 1
            # Stufe 2: ASCII-sichere Prefix/Regex-Muster (unabhaengig von Datei-Encoding und OS-Sprache)
            if (-not $found -and $patterns.Count -gt 0) {
                $found = $all | Where-Object {
                    $dn = "$($_.DisplayName)"; $nm = "$($_.Name)"
                    @($patterns | Where-Object { $dn -match $_ -or $nm -match $_ }).Count -gt 0
                } | Select-Object -First 1
            }
            # Stufe 3: Direkte CIM-Einzelabfrage per Name-Filter (umgeht jegliches Listen-Matching)
            if (-not $found) {
                foreach ($n in $names) {
                    try {
                        $found = Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($found) { break }
                    } catch {}
                }
            }
            # Stufe 4: Lokaler Get-Service in der Session (funktioniert auch, wenn CIM eingeschraenkt ist)
            if (-not $found) {
                foreach ($n in $names) {
                    try {
                        $s = Get-Service -Name $n -ErrorAction Stop
                        $found = [pscustomobject]@{ Name=$s.Name; DisplayName=$s.DisplayName; State="$($s.Status)"; StartMode="$($s.StartType)" }
                        break
                    } catch {}
                }
            }
            if ($found) {
                $st = "$($found.State)"; $sm = "$($found.StartMode)"
                if ($sm -eq 'Auto') { $sm = 'Automatic' }
                $rows += [pscustomobject]@{
                    Service=$svc; Description=$cfg.Description; RealName=$found.Name
                    DisplayName=$found.DisplayName; Status=$st; StartType=$sm
                }
            } else {
                $rows += [pscustomobject]@{ Service=$svc; Description=$cfg.Description; RealName='N/A'; DisplayName='-'; Status='NotFound'; StartType='N/A' }
            }
        }
        $rows
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb -ArgumentList @($Global:ServiceMap)
    if (-not $data) {
        # Letzter Fallback: Get-Service ueber RPC (alter Ansatz)
        $res = @()
        foreach ($svc in $Global:ServiceMap.Keys) {
            $cfg = $Global:ServiceMap[$svc]; $ok = $false
            foreach ($n in $cfg.Names) {
                try {
                    $s = Get-Service -ComputerName $DC -Name $n -ErrorAction Stop
                    $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName=$s.Name; DisplayName=$s.DisplayName; Status="$($s.Status)"; StartType="$($s.StartType)" }
                    $ok=$true; break
                } catch {}
            }
            if (-not $ok) { $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName='N/A'; DisplayName='-'; Status='NotFound'; StartType='N/A' } }
        }
        return $res
    }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Invoke-DCDiag {
    param([Parameter(Mandatory)][string]$DC)
    try { $raw = & dcdiag.exe /s:$DC /v /test:DNS /DnsBasic /DnsForwarders /DnsDelegation /DnsDynamicUpdate /DnsRecordRegistration 2>&1 | Out-String }
    catch { return @([pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='dcdiag.exe'; PartitionOrScope='-'; Result='ERROR'; ErrorDetails="$_"; RawSnippet='-' }) }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @([pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='dcdiag.exe'; PartitionOrScope='-'; Result='ERROR'; ErrorDetails='Keine Ausgabe'; RawSnippet='-' }) }
    $lines = $raw -split "`r?`n"; $results = @()
    $curCat='Server'; $curScope=$DC; $curTest=$null; $curErr=@()
    $rxStart='^\s*(?:Starting test|Starttest)\s*:\s*(\S+)'
    $rxPass='(?:passed test|bestandener Test|Test.*bestanden)\s+(\S+)'
    $rxFail='(?:failed test|fehlgeschlagener Test|Test.*fehlgeschlagen)\s+(\S+)'
    $rxPart='(?:Running partition tests on|Partitionstests)\s*:\s*(\S+)'
    $rxFor='(?:Running enterprise tests on|Unternehmenstests)\s*:\s*(\S+)'
    $rxSrv='(?:Testing server|Server wird getestet)\s*:\s*(\S+)'
    foreach ($line in $lines) {
        if ($line -match $rxSrv)  { $curCat='Server';    $curScope=$Matches[1]; continue }
        if ($line -match $rxPart) { $curCat='Partition'; $curScope=$Matches[1]; continue }
        if ($line -match $rxFor)  { $curCat='Forest';    $curScope=$Matches[1]; continue }
        if ($line -match $rxStart) {
            if ($curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='UNKNOWN'; ErrorDetails=($curErr -join "`n").Trim(); RawSnippet='-' } }
            $curTest=$Matches[1]; $curErr=@(); continue
        }
        if ($line -match $rxPass) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$Matches[1]; PartitionOrScope=$curScope; Result='PASSED'; ErrorDetails=''; RawSnippet='' }; $curTest=$null; $curErr=@(); continue }
        if ($line -match $rxFail) {
            $n=$Matches[1]; $e=($curErr | Where-Object { $_.Trim() } | Select-Object -First 20) -join "`n"; if (-not $e) { $e=$line.Trim() }
            $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$n; PartitionOrScope=$curScope; Result='FAILED'; ErrorDetails=$e.Trim(); RawSnippet=$line.Trim() }
            $curTest=$null; $curErr=@(); continue
        }
        if ($line -match '^\s*TEST\s*:\s*(\S+)') { $curTest=$Matches[1]; $curErr=@(); $curCat='DNS'; continue }
        if ($line -match '^\s*(Passed|Bestanden)\s*:\s*(\S+)') { $results += [pscustomobject]@{ DCName=$DC; Category='DNS'; TestName=$Matches[2]; PartitionOrScope=$curScope; Result='PASSED'; ErrorDetails=''; RawSnippet='' }; $curTest=$null; $curErr=@(); continue }
        if ($line -match '^\s*(Warning|Warnung)\s*:\s*(.+)' -and $curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='WARNING'; ErrorDetails=$Matches[2].Trim(); RawSnippet=$line.Trim() }; $curTest=$null; $curErr=@(); continue }
        if ($curTest -and $line.Trim() -and $line -notmatch '^\s*\.{3,}\s*$') { $curErr += $line.TrimEnd() }
    }
    if ($curTest) { $results += [pscustomobject]@{ DCName=$DC; Category=$curCat; TestName=$curTest; PartitionOrScope=$curScope; Result='UNKNOWN'; ErrorDetails=($curErr -join "`n").Trim(); RawSnippet='-' } }
    if (@($results).Count -eq 0) { $results += [pscustomobject]@{ DCName=$DC; Category='ALL'; TestName='(parsed=0)'; PartitionOrScope='-'; Result='UNKNOWN'; ErrorDetails='Nicht parsebar'; RawSnippet=$raw.Substring(0,[math]::Min(500,$raw.Length)) } }
    $results
}

function Get-ReplicationPartners {
    param([Parameter(Mandatory)][string]$DC)
    Get-ADReplicationPartnerMetadata -Target $DC -Scope Server -ErrorAction Stop |
        Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures
}

function Get-ReplicationFailures {
    $failures = @()
    try { $fn = (Get-ADForest -ErrorAction Stop).Name; $failures = Get-ADReplicationFailure -Target $fn -Scope Forest -ErrorAction Stop }
    catch { try { foreach ($dc in (Get-ADDomainController -Filter * -ErrorAction Stop)) { try { $f = Get-ADReplicationFailure -Target $dc.HostName -Scope Server -ErrorAction Stop; if ($f) { $failures += $f } } catch {} } } catch {} }
    $failures
}

function Get-FSMORoles {
    $f=Get-ADForest -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ SchemaMaster=$f.SchemaMaster; DomainNamingMaster=$f.DomainNamingMaster; PDCEmulator=$d.PDCEmulator; RIDMaster=$d.RIDMaster; InfrastructureMaster=$d.InfrastructureMaster }
}

function Get-DNSConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $result = @()
    foreach ($t in (Get-DnsServerTargets -ComputerName $DC)) {
        try {
            $result += @(Get-DnsServerZone @t -ErrorAction Stop |
                Select-Object @{n='DCName';e={$DC}}, ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate)
            break
        } catch {}
    }
    return $result
}

function Get-SysvolStatus {
    param([Parameter(Mandatory)][string]$DC)
    [pscustomobject]@{ DCName=$DC; SYSVOL_Accessible=Test-Path "\\$DC\SYSVOL"; NETLOGON_Accessible=Test-Path "\\$DC\NETLOGON"; SYSVOL_Path="\\$DC\SYSVOL"; NETLOGON_Path="\\$DC\NETLOGON" }
}

function Get-NTDSDatabase {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $p = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop).'DSA Database file'
        if (-not $p) { return $null }
        $f = Get-Item $p -ErrorAction SilentlyContinue
        if ($f) {
            $d = Get-PSDrive ($f.PSDrive.Name)
            [pscustomobject]@{ DBPath=$f.FullName; DBSize_MB=[math]::Round(($f.Length/1MB),2); DriveFree_GB=[math]::Round(($d.Free/1GB),2); DriveUsed_GB=[math]::Round(($d.Used/1GB),2) }
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-TLSConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $protos = 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'
        $out = @()
        foreach ($p in $protos) {
            foreach ($side in 'Client','Server') {
                $key = Join-Path $base "$p\$side"
                $ex = Test-Path $key
                $e = $null; $d = $null; $st = 'NotConfigured'
                if ($ex) {
                    $e = (Get-ItemProperty $key -Name Enabled -ErrorAction SilentlyContinue).Enabled
                    $d = (Get-ItemProperty $key -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
                    if ($e -eq 0) { $st='Disabled' } elseif ($e -eq 1) { $st='Enabled' } elseif ($d -eq 1) { $st='DisabledByDefault' } else { $st='EnabledByDefault' }
                }
                $out += [pscustomobject]@{ Protocol=$p; Side=$side; RegistryKeyExists=$ex; Enabled=$e; DisabledByDefault=$d; State=$st }
            }
        }
        $out
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-CipherConfiguration {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
        if (-not (Test-Path $base)) { return @() }
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{ Cipher=$_.PSChildName; Enabled=$p.Enabled }
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-LDAPSecurity {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $r = [ordered]@{}
        $n = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $si = $null; try { $si = (Get-ItemProperty $n -Name LDAPServerIntegrity -ErrorAction Stop).LDAPServerIntegrity } catch {}
        $r.LDAPServerIntegrity = $si
        $r.LDAPServerIntegrity_Meaning = switch ($si) { 0{'None (unsicher!)'} 1{'Negotiate'} 2{'Require - Best Practice'} $null{'NICHT KONFIGURIERT'} default{"Unbekannt ($si)"} }
        $cb = $null; try { $cb = (Get-ItemProperty $n -Name LdapEnforceChannelBinding -ErrorAction Stop).LdapEnforceChannelBinding } catch {}
        $r.LdapEnforceChannelBinding = $cb
        $r.LdapEnforceChannelBinding_Meaning = switch ($cb) { 0{'Disabled (unsicher!)'} 1{'When Supported'} 2{'Always - Best Practice'} $null{'NICHT KONFIGURIERT'} default{"Unbekannt ($cb)"} }
        $r.LDAPSPortOpen = $null
        try { $r.LDAPSPortOpen = Test-NetConnection -ComputerName 'localhost' -Port 636 -WarningAction SilentlyContinue -InformationLevel Quiet } catch {}
        $r.UnsignedLDAPBinds_7d = 0
        try { $r.UnsignedLDAPBinds_7d = @(Get-WinEvent -FilterHashtable @{ LogName='Directory Service'; ID=2889; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue).Count } catch {}
        [pscustomobject]$r
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; LDAPServerIntegrity=$null; LDAPServerIntegrity_Meaning='(Abfrage fehlgeschlagen)'; LdapEnforceChannelBinding=$null; LdapEnforceChannelBinding_Meaning='-'; LDAPSPortOpen=$null; UnsignedLDAPBinds_7d=$null }) }
    $data | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force
}

function Get-PrivilegedAccounts {
    $result = @()
    try { $dSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value } catch { return $result }
    $g = @(
        [pscustomobject]@{ DisplayName='Domain Admins'; SID="$dSid-512" }
        [pscustomobject]@{ DisplayName='Enterprise Admins'; SID="$dSid-519" }
        [pscustomobject]@{ DisplayName='Schema Admins'; SID="$dSid-518" }
        [pscustomobject]@{ DisplayName='Group Policy Creator Owners'; SID="$dSid-520" }
        [pscustomobject]@{ DisplayName='DnsAdmins'; SID=$null; FallbackName='DnsAdmins' }
        [pscustomobject]@{ DisplayName='Administrators'; SID='S-1-5-32-544' }
        [pscustomobject]@{ DisplayName='Account Operators'; SID='S-1-5-32-548' }
        [pscustomobject]@{ DisplayName='Server Operators'; SID='S-1-5-32-549' }
        [pscustomobject]@{ DisplayName='Print Operators'; SID='S-1-5-32-550' }
        [pscustomobject]@{ DisplayName='Backup Operators'; SID='S-1-5-32-551' }
    )
    foreach ($x in $g) {
        try {
            $grp = $null
            if ($x.SID) { try { $grp = Get-ADGroup -Identity $x.SID -ErrorAction Stop } catch {} }
            if (-not $grp -and $x.FallbackName) { try { $grp = Get-ADGroup -Identity $x.FallbackName -ErrorAction Stop } catch {} }
            if (-not $grp) { continue }
            $mem = @()
            try { $mem = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop }
            catch { try { $mem = Get-ADGroupMember -Identity $grp -ErrorAction Stop } catch { continue } }
            if (@($mem).Count -eq 0) {
                $result += [pscustomobject]@{ Group=$x.DisplayName; LocalizedName=$grp.Name; MemberName='<leer>'; SamAccountName='-'; ObjectClass='-'; DistinguishedName='-' }
                continue
            }
            foreach ($m in $mem) {
                $result += [pscustomobject]@{ Group=$x.DisplayName; LocalizedName=$grp.Name; MemberName=$m.Name; SamAccountName=$m.SamAccountName; ObjectClass=$m.objectClass; DistinguishedName=$m.DistinguishedName }
            }
        } catch {}
    }
    return $result
}

function Get-PasswordPolicy {
    $def = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $r = @([pscustomobject]@{ Type='Default Domain Policy'; Name='Default'; MinPasswordLength=$def.MinPasswordLength; PasswordHistoryCount=$def.PasswordHistoryCount; MaxPasswordAge=$def.MaxPasswordAge; MinPasswordAge=$def.MinPasswordAge; LockoutThreshold=$def.LockoutThreshold; LockoutDuration=$def.LockoutDuration; ComplexityEnabled=$def.ComplexityEnabled })
    try {
        Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | ForEach-Object {
            $r += [pscustomobject]@{ Type='Fine-Grained Policy'; Name=$_.Name; MinPasswordLength=$_.MinPasswordLength; PasswordHistoryCount=$_.PasswordHistoryCount; MaxPasswordAge=$_.MaxPasswordAge; MinPasswordAge=$null; LockoutThreshold=$null; LockoutDuration=$null; ComplexityEnabled=$null }
        }
    } catch {}
    $r
}

function Get-KerberosInfo {
    $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet,PasswordNeverExpires,Enabled -ErrorAction Stop
    $a = if ($k.PasswordLastSet) { (New-TimeSpan -Start $k.PasswordLastSet -End (Get-Date)).Days } else { $null }
    [pscustomobject]@{ Account='krbtgt'; PasswordLastSet=$k.PasswordLastSet; PasswordAgeDays=$a; MaxAllowedDays=$Global:KrbtgtMaxAgeDays; NeedsReset=($a -gt $Global:KrbtgtMaxAgeDays); Enabled=$k.Enabled }
}

function Get-SecureBootStatus {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $fw = 'Unknown'
        try { $f = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType; if ($f) { $fw="$f" } }
        catch { $ef = [System.Environment]::GetEnvironmentVariable('firmware_type'); if ($ef) { $fw=$ef } }
        $sbEn = 'Unknown'
        try { $sbEn = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' } }
        catch { if ($_.Exception.Message -match 'not supported|nicht unterstuetzt|Cmdlet wird') { $sbEn='NotSupported' } else { $sbEn='Error' } }
        $regBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
        $au=$null; $auSet=$false
        try { $p = Get-ItemProperty $regBase -Name AvailableUpdates -ErrorAction Stop; $au=$p.AvailableUpdates; $auSet=$true } catch {}
        $auHex = if ($null -ne $au) { ('0x{0:X}' -f $au) } else { '(nicht gesetzt)' }
        $wc=$null; $us=$null; $ue=$null
        try {
            $s = Get-ItemProperty (Join-Path $regBase 'Servicing') -ErrorAction Stop
            if ($s.PSObject.Properties.Name -contains 'WindowsUEFICA2023Capable') { $wc = [int]$s.WindowsUEFICA2023Capable }
            if ($s.PSObject.Properties.Name -contains 'UEFICA2023Status') { $us = "$($s.UEFICA2023Status)" }
            if ($s.PSObject.Properties.Name -contains 'UEFICA2023Error')  { $ue = $s.UEFICA2023Error }
        } catch {}
        if (-not $us) { $us = '(nicht gesetzt)' }
        $h2023=$false; $k2023=$false
        try { $db = Get-SecureBootUEFI -Name db -ErrorAction Stop; if ($db -and $db.bytes) { $h2023 = [System.Text.Encoding]::ASCII.GetString($db.bytes) -match 'Windows UEFI CA 2023' } } catch {}
        try { $kek = Get-SecureBootUEFI -Name KEK -ErrorAction Stop; if ($kek -and $kek.bytes) { $k2023 = [System.Text.Encoding]::ASCII.GetString($kek.bytes) -match 'Microsoft Corporation KEK (2K )?CA 2023' } } catch {}
        $lastSucc=$null; $lastFail=$null; $lastFailMsg=''
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-TPM-WMI'; Id=1796,1798,1801,1808 } -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($e in $ev) {
                if ($e.Id -in 1796,1798,1808) { if (-not $lastSucc -or $e.TimeCreated -gt $lastSucc) { $lastSucc=$e.TimeCreated } }
                if ($e.Id -eq 1801)           { if (-not $lastFail -or $e.TimeCreated -gt $lastFail) { $lastFail=$e.TimeCreated; $lastFailMsg=($e.Message -split "`n")[0] } }
            }
        } catch {}
        $status='UNKNOWN'; $detail=''
        if ($sbEn -match 'Disabled|NotSupported') { $status='NOT_APPLICABLE'; $detail='Secure Boot nicht aktiv' }
        elseif ($us -match 'Updated' -or ($h2023 -and $k2023)) { $status='SUCCESS'; $detail = if ($lastSucc) { "Erfolgreich am $lastSucc (UEFI CA 2023 + KEK CA 2023)" } else { "UEFI CA 2023 in DB/KEK vorhanden" } }
        elseif ($us -match 'In Progress|InProgress') { $status='IN_PROGRESS'; $detail="Update laeuft" }
        elseif ($lastFail -and -not $h2023) { $status='FAILED'; $detail="Letzter Versuch $lastFail fehlgeschlagen: $lastFailMsg" }
        elseif (($null -ne $ue) -and ($ue -ne 0) -and -not $h2023) { $status='FAILED'; $detail=("Registry-Fehler UEFICA2023Error=0x{0:X}" -f $ue) }
        elseif ($auSet -and $au -gt 0) { $status='PENDING'; $detail="AvailableUpdates=$auHex gesetzt - wartet auf Reboot" }
        elseif ($us -match 'Not Started|NotStarted' -or ($wc -eq 1 -and -not $auSet)) { $status='NOT_STARTED'; $detail="Registry 'AvailableUpdates' nicht gesetzt" }
        elseif ($wc -eq 0) { $status='NOT_CAPABLE'; $detail="Geraet NICHT faehig - Firmware-Update pruefen" }
        else { $status='UNKNOWN'; $detail="Capable=$wc, Status='$us', AU=$auHex, DB2023=$h2023, KEK2023=$k2023" }
        $residual = ''
        if ($status -eq 'SUCCESS' -and $auSet -and $au -gt 0) {
            $bits = @()
            if ($au -band 0x10) { $bits += 'BootMgr' }; if ($au -band 0x40) { $bits += 'DB' }; if ($au -band 0x100) { $bits += 'DBX' }
            if ($au -band 0x400) { $bits += 'KEK' }; if ($au -band 0x1000) { $bits += 'PCA2011-Revoke' }
            if ($au -band 0x2000) { $bits += 'BootMgr-Revoke' }; if ($au -band 0x4000) { $bits += 'DBX-SVN' }
            $residual = $bits -join ','
            $detail += " | Hinweis: Registry-Bit(s) [$residual] noch offen - Reboot empfohlen"
        }
        [pscustomobject]@{
            SecureBoot=$sbEn; UpdateStatus=$status; Registry_AvailableUpdates=$auHex
            Registry_UEFICA2023Status=$us; Detail=$detail
            _Firmware=$fw; _ResidualBits=$residual
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; UpdateStatus='UNKNOWN'; SecureBoot='-'; Registry_AvailableUpdates='-'; Registry_UEFICA2023Status='-'; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{
        DCName=$DC; UpdateStatus=$data.UpdateStatus; SecureBoot=$data.SecureBoot
        Registry_AvailableUpdates=$data.Registry_AvailableUpdates
        Registry_UEFICA2023Status=$data.Registry_UEFICA2023Status; Detail=$data.Detail
        _Firmware=$data._Firmware; _ResidualBits=$data._ResidualBits
    }
}

function Get-DCCertificates {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        param($wd)
        $out = @()
        foreach ($st in 'Cert:\LocalMachine\My','Cert:\LocalMachine\WebHosting') {
            try {
                foreach ($c in (Get-ChildItem -Path $st -ErrorAction SilentlyContinue)) {
                    $out += [pscustomobject]@{ Store=$st; Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint; NotBefore=$c.NotBefore; NotAfter=$c.NotAfter; DaysToExpiry=[int]($c.NotAfter - (Get-Date)).TotalDays; IsExpiringSoon=($c.NotAfter - (Get-Date)).TotalDays -le $wd; HasPrivateKey=$c.HasPrivateKey; EnhancedKeyUsage=($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join '; ' }
                }
            } catch {}
        }
        if (@($out).Count -eq 0) { $out += [pscustomobject]@{ Store='Cert:\LocalMachine\My'; Subject='(keine Zertifikate)'; Issuer='-'; Thumbprint='-'; NotBefore=$null; NotAfter=$null; DaysToExpiry=$null; IsExpiringSoon=$false; HasPrivateKey=$false; EnhancedKeyUsage='-' } }
        $out
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb -ArgumentList $Global:CertExpiryWarnDays
    if (-not $data) { $data = @([pscustomobject]@{ Store='N/A'; Subject='(Abfrage fehlgeschlagen)'; Issuer='-'; Thumbprint='-'; NotBefore=$null; NotAfter=$null; DaysToExpiry=$null; IsExpiringSoon=$false; HasPrivateKey=$false; EnhancedKeyUsage='-' }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-ADSitesInfo { Get-ADReplicationSite -Filter * -Properties * -ErrorAction Stop | Select-Object Name, Description, Location, whenCreated, whenChanged }
function Get-ADSubnetsInfo { Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop | Select-Object Name, Site, Description, Location, whenCreated }
function Get-ADTrusts { Get-ADTrust -Filter * -ErrorAction Stop | Select-Object Name, Source, Target, Direction, TrustType, ForestTransitive, IntraForest, whenCreated }

function Get-ADLevels {
    $f=Get-ADForest -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ ForestName=$f.Name; ForestMode=$f.ForestMode; DomainName=$d.DNSRoot; DomainMode=$d.DomainMode; SchemaMaster=$f.SchemaMaster; DomainController=($d.ReplicaDirectoryServers -join ', ') }
}

function Get-GPOHealth {
    Get-GPO -All -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ DisplayName=$_.DisplayName; Id=$_.Id; GpoStatus=$_.GpoStatus; CreationTime=$_.CreationTime; ModificationTime=$_.ModificationTime; Owner=$_.Owner; UserVersion_DS=$_.User.DSVersion; UserVersion_Sys=$_.User.SysvolVersion; CompVersion_DS=$_.Computer.DSVersion; CompVersion_Sys=$_.Computer.SysvolVersion }
    }
}

function Get-InactiveAccounts {
    $d = [ordered]@{ InactiveUsers=@(); InactiveComputers=@(); PasswordNeverExpires=@() }
    $cu=(Get-Date).AddDays(-$Global:InactiveDaysUser); $cc=(Get-Date).AddDays(-$Global:InactiveDaysComputer)
    try { $d.InactiveUsers = @(Get-ADUser -Filter { LastLogonDate -lt $cu -and Enabled -eq $true } -Properties LastLogonDate,PasswordLastSet -ErrorAction Stop | Select-Object SamAccountName,Name,Enabled,LastLogonDate,PasswordLastSet,DistinguishedName) } catch {}
    try { $d.InactiveComputers = @(Get-ADComputer -Filter { LastLogonDate -lt $cc -and Enabled -eq $true } -Properties LastLogonDate,OperatingSystem -ErrorAction Stop | Select-Object Name,Enabled,LastLogonDate,OperatingSystem,DistinguishedName) } catch {}
    try { $d.PasswordNeverExpires = @(Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires,PasswordLastSet -ErrorAction Stop | Select-Object SamAccountName,Name,PasswordLastSet,DistinguishedName) } catch {}
    [pscustomobject]$d
}

function Get-DCEventLog {
    param([Parameter(Mandatory)][string]$DC)
    $since = (Get-Date).AddHours(-$Global:EventLogHours)
    $all = @()
    foreach ($log in 'System','Directory Service','DNS Server') {
        try {
            $ev = Get-WinEvent -ComputerName $DC -FilterHashtable @{ LogName=$log; Level=1,2; StartTime=$since } -MaxEvents 50 -ErrorAction Stop
            foreach ($e in $ev) {
                $all += [pscustomobject]@{ DCName=$DC; LogName=$log; TimeCreated=$e.TimeCreated; Level=$e.LevelDisplayName; EventID=$e.Id; Provider=$e.ProviderName; Message=($e.Message -split "`n")[0] }
            }
        } catch {}
    }
    $all
}

function Get-TimeSyncStatus {
    param([Parameter(Mandatory)][string]$DC, [string]$PDCEmulator='')
    $sb = {
        $sR = & w32tm /query /status /verbose 2>&1 | Out-String
        $cR = & w32tm /query /configuration  2>&1 | Out-String
        $srcR = & w32tm /query /source 2>&1 | Out-String
        $src = ($srcR -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^Die Abfrage|^The following|^$' } | Select-Object -First 1).Trim()
        $strat=$null; if ($sR -match 'Stratum\s*:\s*(\d+)') { $strat=[int]$Matches[1] }
        $ls=$null; $m=[regex]::Match($sR,'(?:Last Successful Sync Time|Letzte erfolgreiche Synchronisierungszeit)\s*:\s*(.+)'); if ($m.Success) { $ls=$m.Groups[1].Value.Trim() }
        $type=$null; $m=[regex]::Match($cR,'(?:^|\s)Type:\s*([^\r\n]+)'); if ($m.Success) { $type=$m.Groups[1].Value.Trim() }
        $ntp=$null; $m=[regex]::Match($cR,'NtpServer:\s*([^\r\n]+)'); if ($m.Success) { $ntp=$m.Groups[1].Value.Trim() }
        [pscustomobject]@{ Source=$src; Stratum=$strat; LastSyncTime=$ls; ConfiguredType=$type; ConfiguredNtpSrv=$ntp }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return }
    $isPDC = ($DC -ieq $PDCEmulator -or $DC -ilike "$PDCEmulator*" -or $PDCEmulator -ilike "$DC*")
    $sk='Unknown'
    if     ($data.Source -match 'Local CMOS Clock|Lokale CMOS-Uhr') { $sk='LocalClock' }
    elseif ($data.Source -match 'Free-running') { $sk='FreeRunning' }
    elseif ($data.Source -match 'VM IC Time Provider') { $sk='HyperVHost' }
    elseif ($data.Source -match '^[\w\.\-]+$') { $sk='Server' }
    [pscustomobject]@{ DCName=$DC; IsPDCEmulator=$isPDC; Source=$data.Source; SourceKind=$sk; Stratum=$data.Stratum; LastSyncTime=$data.LastSyncTime; ConfiguredType=$data.ConfiguredType; ConfiguredNtpSrv=$data.ConfiguredNtpSrv }
}

function Get-ADBackupStatus {
    $dom = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $raw = & repadmin /showbackup $dom 2>&1 | Out-String
    $lb = $null; if ($raw -match 'dSASignature.*:\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') { $lb = [datetime]$Matches[1] }
    $a = if ($lb) { (New-TimeSpan -Start $lb -End (Get-Date)).Days } else { $null }
    [pscustomobject]@{ LastBackup=$lb; AgeDays=$a; MaxAllowedDays=$Global:BackupMaxAgeDays; BackupOverdue=($a -gt $Global:BackupMaxAgeDays); RawOutput=($raw -split "`n" | Select-Object -First 20) -join "`n" }
}

function Get-InstalledPrograms {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $out = @()
        foreach ($k in $keys) {
            try {
                Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DisplayName) {
                        $id = $null
                        if ($_.InstallDate -and $_.InstallDate -match '^\d{8}$') { try { $id = [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null) } catch {} }
                        $out += [pscustomobject]@{ DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallDate=$id; InstallLocation=$_.InstallLocation; EstimatedSizeMB=if ($_.EstimatedSize) { [math]::Round(($_.EstimatedSize/1024),2) } else { $null }; Architecture=if ($k -match 'Wow6432Node') { 'x86' } else { 'x64' } }
                    }
                }
            } catch {}
        }
        $out | Sort-Object -Property InstallDate -Descending
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if ($data) { $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force } }
}

function Get-WindowsUpdates {
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        try {
            Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 20 |
                Select-Object HotFixID, Description, InstalledOn, InstalledBy, @{n='DaysAgo';e={ [int](New-TimeSpan -Start $_.InstalledOn -End (Get-Date)).TotalDays }}
        } catch {
            Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 20 |
                Select-Object @{n='HotFixID';e={$_.HotFixID}}, Description, InstalledOn, InstalledBy, @{n='DaysAgo';e={ [int](New-TimeSpan -Start $_.InstalledOn -End (Get-Date)).TotalDays }}
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; HotFixID='(keine Daten)'; Description='-'; InstalledOn=$null; InstalledBy='-'; DaysAgo=$null }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-WindowsFeatures {
    <#
    .SYNOPSIS
        Installierte Windows Features (Rollen & Features) pro DC.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $out = @()
        try {
            Import-Module ServerManager -ErrorAction Stop
            $out = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed } |
                ForEach-Object {
                    [pscustomobject]@{
                        Name=$_.Name; DisplayName=$_.DisplayName; FeatureType=$_.FeatureType
                        Installed=$_.Installed; InstallState="$($_.InstallState)"
                    }
                })
        } catch {
            # Fallback, falls ServerManager-Modul nicht verfuegbar ist
            try {
                $out = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                    Where-Object { $_.State -eq 'Enabled' } |
                    ForEach-Object {
                        [pscustomobject]@{
                            Name=$_.FeatureName; DisplayName=$_.FeatureName; FeatureType='OptionalFeature'
                            Installed=$true; InstallState="$($_.State)"
                        }
                    })
            } catch {}
        }
        $out | Sort-Object DisplayName
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; Name='(keine Daten)'; DisplayName='-'; FeatureType='-'; Installed=$null; InstallState='-' }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-Shares {
    <#
    .SYNOPSIS
        Alle SMB-Freigaben (Shares) pro DC inkl. Freigabeberechtigungen.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $rows = @()
        $shares = $null
        try { $shares = Get-SmbShare -ErrorAction Stop } catch {}
        if ($shares) {
            foreach ($s in $shares) {
                $perm = ''
                try {
                    $perm = ((Get-SmbShareAccess -Name $s.Name -ErrorAction Stop) |
                        ForEach-Object { "$($_.AccountName): $($_.AccessRight)/$($_.AccessControlType)" }) -join '; '
                } catch {}
                $rows += [pscustomobject]@{
                    Name=$s.Name; Path=$s.Path; Description=$s.Description; ScopeName=$s.ScopeName
                    CachingMode="$($s.CachingMode)"; EncryptData=$s.EncryptData
                    CurrentUsers=$s.CurrentUsers; Permissions=$perm
                }
            }
        }
        if ($rows.Count -eq 0) {
            # Fallback ueber CIM (Win32_Share)
            foreach ($s in @(Get-CimInstance -ClassName Win32_Share -ErrorAction SilentlyContinue)) {
                $rows += [pscustomobject]@{
                    Name=$s.Name; Path=$s.Path; Description=$s.Description; ScopeName='-'
                    CachingMode='-'; EncryptData=$null
                    CurrentUsers=$null; Permissions=''
                }
            }
        }
        $rows
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; Name='(keine Daten)'; Path='-'; Description='-'; ScopeName='-'; CachingMode='-'; EncryptData=$null; CurrentUsers=$null; Permissions='' }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

#endregion

#region ============= 10 NEUE DATENSAMMEL-FUNKTIONEN =========================

function Get-PrintSpoolerStatus {
    <#
    .SYNOPSIS
        PrintNightmare CVE-2021-34527: Spooler auf DCs muss DEAKTIVIERT sein.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        try {
            $svc = Get-Service -Name 'Spooler' -ErrorAction Stop
            $queues = 0
            try { $queues = @(Get-Printer -ErrorAction SilentlyContinue).Count } catch {}
            $startMode = 'Unknown'
            try {
                $reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler' -Name Start -ErrorAction Stop
                $startMode = switch ($reg.Start) { 2{'Automatic'} 3{'Manual'} 4{'Disabled'} default{"Unknown($($reg.Start))"} }
            } catch {}
            $st='UNKNOWN'; $d=''
            if ($svc.Status -eq 'Stopped' -and $startMode -eq 'Disabled') { $st='SECURE'; $d='Spooler gestoppt und deaktiviert - PrintNightmare-sicher' }
            elseif ($svc.Status -eq 'Stopped') { $st='AT_RISK'; $d="Spooler gestoppt, aber StartType='$startMode' - koennte starten!" }
            elseif ($svc.Status -eq 'Running') { $st='VULNERABLE'; $d="Spooler LAEUFT auf DC! PrintNightmare-Risiko (StartType='$startMode')" }
            [pscustomobject]@{ SpoolerStatus="$($svc.Status)"; StartType=$startMode; SecurityStatus=$st; PrintQueues=$queues; Detail=$d }
        } catch { [pscustomobject]@{ SpoolerStatus='Error'; StartType='-'; SecurityStatus='UNKNOWN'; PrintQueues=$null; Detail="Error: $_" } }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; SecurityStatus='UNKNOWN'; SpoolerStatus='-'; StartType='-'; PrintQueues=$null; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{ DCName=$DC; SecurityStatus=$data.SecurityStatus; SpoolerStatus=$data.SpoolerStatus; StartType=$data.StartType; PrintQueues=$data.PrintQueues; Detail=$data.Detail }
}

function Get-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Computer/User mit TrustedForDelegation=true (ausser DCs = Risiko!).
    #>
    $result = @()
    try {
        $dcDNs = @((Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object { $_.ComputerObjectDN }))
        $computers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, OperatingSystem, LastLogonDate, DistinguishedName -ErrorAction Stop
        foreach ($c in $computers) {
            $isDC = $dcDNs -contains $c.DistinguishedName
            $result += [pscustomobject]@{
                Type='Computer'; Name=$c.Name; SamAccount=$c.SamAccountName
                IsDC=$isDC; OS=$c.OperatingSystem; LastLogon=$c.LastLogonDate
                Risk=if ($isDC) { 'NORMAL' } else { 'HIGH' }
                DistinguishedName=$c.DistinguishedName
            }
        }
        $users = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, LastLogonDate -ErrorAction Stop
        foreach ($u in $users) {
            $result += [pscustomobject]@{
                Type='User'; Name=$u.Name; SamAccount=$u.SamAccountName
                IsDC=$false; OS='-'; LastLogon=$u.LastLogonDate
                Risk='CRITICAL'; DistinguishedName=$u.DistinguishedName
            }
        }
    } catch { Write-Log "UnconstrainedDelegation: $_" -Level WARN -NoConsole }
    return $result
}

function Get-KerberoastingRisk {
    <#
    .SYNOPSIS
        User-Accounts mit SPN = Kerberoasting-Ziel.
    #>
    $result = @()
    try {
        $users = Get-ADUser -Filter { ServicePrincipalName -like '*' -and Enabled -eq $true } `
                            -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, AdminCount `
                            -ErrorAction Stop
        foreach ($u in $users) {
            $age = if ($u.PasswordLastSet) { (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days } else { $null }
            $isPriv = ($u.AdminCount -eq 1)
            $risk = 'LOW'
            if ($isPriv)                                   { $risk='CRITICAL' }
            elseif ($u.PasswordNeverExpires)               { $risk='HIGH' }
            elseif ($age -gt $Global:KerberoastPwdAgeWarn) { $risk='HIGH' }
            elseif ($age -gt 90)                           { $risk='MEDIUM' }
            $result += [pscustomobject]@{
                SamAccount=$u.SamAccountName; Name=$u.Name
                SPNCount=@($u.ServicePrincipalName).Count
                SPNs=($u.ServicePrincipalName -join '; ')
                PasswordLastSet=$u.PasswordLastSet; PasswordAgeDays=$age
                PasswordNeverExpires=$u.PasswordNeverExpires
                IsPrivileged=$isPriv; Risk=$risk
                DistinguishedName=$u.DistinguishedName
            }
        }
    } catch { Write-Log "KerberoastingRisk: $_" -Level WARN -NoConsole }
    return $result
}

function Get-LSAProtectionStatus {
    <#
    .SYNOPSIS
        LSA Protection (RunAsPPL) gegen Credential-Dumping.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $rp = $null
        try { $rp  = (Get-ItemProperty $p -Name RunAsPPL     -ErrorAction Stop).RunAsPPL } catch {}
        $m = switch ($rp) { 0{'DEAKTIVIERT (unsicher!)'} 1{'Enabled - aktiv'} 2{'Enabled + UEFI-locked (Best Practice)'} $null{'NICHT KONFIGURIERT (= deaktiviert!)'} default{"Unbekannt ($rp)"} }
        $uefi = ($rp -eq 2)
        $st='UNKNOWN'; $d=''
        if ($rp -eq 2)    { $st='EXCELLENT'; $d='RunAsPPL=2 (UEFI-locked) - LSASS geschuetzt' }
        elseif ($rp -eq 1){ $st='GOOD'; $d='RunAsPPL=1 - aktiv. Tipp: Auf 2 erhoehen' }
        elseif ($rp -eq 0){ $st='VULNERABLE'; $d='RunAsPPL=0 - DEAKTIVIERT! Mimikatz-Risiko' }
        elseif ($null -eq $rp) { $st='NOT_CONFIGURED'; $d='RunAsPPL NICHT gesetzt - Default deaktiviert' }
        else { $st='UNKNOWN'; $d="Wert: $rp" }
        [pscustomobject]@{ SecurityStatus=$st; RunAsPPL=$rp; RunAsPPLMeaning=$m; UEFILocked=$uefi; Detail=$d }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; SecurityStatus='UNKNOWN'; RunAsPPL=$null; RunAsPPLMeaning='-'; UEFILocked=$false; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{ DCName=$DC; SecurityStatus=$data.SecurityStatus; RunAsPPL=$data.RunAsPPL; RunAsPPLMeaning=$data.RunAsPPLMeaning; UEFILocked=$data.UEFILocked; Detail=$data.Detail }
}

function Get-SMBConfiguration {
    <#
    .SYNOPSIS
        SMB1/SMB-Signing/SMBv2.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        $smb1Feat = 'Unknown'
        try { $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; $smb1Feat = $f.State } catch {}
        $st='UNKNOWN'; $issues=@()
        if ($cfg) {
            if ($cfg.EnableSMB1Protocol -eq $true -or $smb1Feat -eq 'Enabled') { $issues += "SMB1 AKTIV (WannaCry-Risiko!)"; $st='CRITICAL' }
            if ($cfg.RequireSecuritySignature -ne $true) { $issues += "SMB-Signing NICHT erzwungen"; if ($st -ne 'CRITICAL') { $st='WARN' } }
            if ($cfg.EnableSMB2Protocol -ne $true) { $issues += "SMBv2/v3 deaktiviert"; $st='CRITICAL' }
        }
        if ($st -eq 'UNKNOWN' -and $issues.Count -eq 0) { $st='OK'; $d='SMB1 aus, SMB2/3 aktiv, Signing erzwungen' } else { $d = $issues -join ' | ' }
        [pscustomobject]@{
            SecurityStatus=$st
            SMB1Enabled=if ($cfg) { $cfg.EnableSMB1Protocol } else { $null }
            SMB2Enabled=if ($cfg) { $cfg.EnableSMB2Protocol } else { $null }
            RequireSigning=if ($cfg) { $cfg.RequireSecuritySignature } else { $null }
            EnableSigning=if ($cfg) { $cfg.EnableSecuritySignature } else { $null }
            SMB1Feature=$smb1Feat; Detail=$d
        }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; SecurityStatus='UNKNOWN'; SMB1Enabled=$null; SMB2Enabled=$null; RequireSigning=$null; EnableSigning=$null; SMB1Feature='-'; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{ DCName=$DC; SecurityStatus=$data.SecurityStatus; SMB1Enabled=$data.SMB1Enabled; SMB2Enabled=$data.SMB2Enabled; RequireSigning=$data.RequireSigning; EnableSigning=$data.EnableSigning; SMB1Feature=$data.SMB1Feature; Detail=$data.Detail }
}

function Get-NTLMAuthLevel {
    <#
    .SYNOPSIS
        LmCompatibilityLevel Check. Best Practice: 5
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lmc = $null; try { $lmc = (Get-ItemProperty $p -Name LmCompatibilityLevel -ErrorAction Stop).LmCompatibilityLevel } catch {}
        $m = switch ($lmc) {
            0 { 'LM & NTLM senden (HOECHST UNSICHER)' }
            1 { 'LM & NTLM senden, NTLMv2 wenn verhandelt' }
            2 { 'Nur NTLM senden' }
            3 { 'Nur NTLMv2 senden' }
            4 { 'Nur NTLMv2 senden, LM verweigern' }
            5 { 'Nur NTLMv2 senden, LM & NTLM verweigern (Best Practice)' }
            $null { 'NICHT KONFIGURIERT (Default=3)' }
            default { "Unbekannt ($lmc)" }
        }
        $ntlm_7d = 0
        try { $ntlm_7d = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-NTLM/Operational'; ID=8001,8002,8003,8004; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue).Count } catch {}
        $st='UNKNOWN'; $d=''
        if ($lmc -eq 5)        { $st='OK'; $d='LmCompatibilityLevel=5 - Best Practice' }
        elseif ($lmc -eq 4 -or $lmc -eq 3) { $st='WARN'; $d="LmCompatibilityLevel=$lmc - OK, aber 5 ist besser" }
        elseif ($null -eq $lmc) { $st='WARN'; $d='NICHT KONFIGURIERT (Default=3)' }
        elseif ($lmc -le 2)    { $st='CRITICAL'; $d="LmCompatibilityLevel=$lmc - unsicher!" }
        [pscustomobject]@{ SecurityStatus=$st; LmCompatibilityLevel=$lmc; LmCompatibilityMeaning=$m; NTLMv1Events_7d=$ntlm_7d; Detail=$d }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; SecurityStatus='UNKNOWN'; LmCompatibilityLevel=$null; LmCompatibilityMeaning='-'; NTLMv1Events_7d=$null; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{ DCName=$DC; SecurityStatus=$data.SecurityStatus; LmCompatibilityLevel=$data.LmCompatibilityLevel; LmCompatibilityMeaning=$data.LmCompatibilityMeaning; NTLMv1Events_7d=$data.NTLMv1Events_7d; Detail=$data.Detail }
}

function Get-LLMNRConfiguration {
    <#
    .SYNOPSIS
        LLMNR / NetBIOS-NS / WPAD = Responder-Risiken.
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $llmnr = $null
        try { $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction Stop).EnableMulticast } catch {}
        $llmnrStatus = switch ($llmnr) { 0{'DISABLED (gut)'} 1{'ENABLED (Risiko!)'} $null{'NICHT KONFIGURIERT (Risiko!)'} default{"Unbekannt ($llmnr)"} }

        $nbt = 'Unknown'
        try {
            $ints = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction SilentlyContinue
            $tcpip = foreach ($i in $ints) { $i.TcpipNetbiosOptions }
            if (($tcpip | Sort-Object -Unique) -contains 2 -and -not (($tcpip | Sort-Object -Unique) -contains 0) -and -not (($tcpip | Sort-Object -Unique) -contains 1)) { $nbt='DISABLED (gut)' }
            elseif (($tcpip | Sort-Object -Unique) -contains 1 -or ($tcpip | Sort-Object -Unique) -contains 0) { $nbt='ENABLED (Risiko!)' }
        } catch {}

        $wpad = 'Unknown'
        try { $w = Get-Service WinHttpAutoProxySvc -ErrorAction Stop; $wpad = "$($w.Status)/$($w.StartType)" } catch {}

        $issues=@()
        if ($llmnr -ne 0) { $issues += "LLMNR: $llmnrStatus" }
        if ($nbt -match 'ENABLED') { $issues += "NetBIOS-NS: $nbt" }
        if ($wpad -notmatch 'Stopped|Disabled' -and $wpad -ne 'Unknown') { $issues += "WPAD: $wpad" }
        $st = if ($issues.Count -eq 0) { 'OK' } elseif ($llmnr -ne 0 -and $nbt -match 'ENABLED') { 'CRITICAL' } else { 'WARN' }
        $d = if ($st -eq 'OK') { 'LLMNR/NetBIOS-NS/WPAD deaktiviert - Best Practice' } else { $issues -join ' | ' }
        [pscustomobject]@{ SecurityStatus=$st; LLMNR=$llmnrStatus; NetBIOS_NS=$nbt; WPAD_Service=$wpad; Detail=$d }
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; SecurityStatus='UNKNOWN'; LLMNR='-'; NetBIOS_NS='-'; WPAD_Service='-'; Detail='Abfrage fehlgeschlagen' }) }
    [pscustomobject]@{ DCName=$DC; SecurityStatus=$data.SecurityStatus; LLMNR=$data.LLMNR; NetBIOS_NS=$data.NetBIOS_NS; WPAD_Service=$data.WPAD_Service; Detail=$data.Detail }
}

function Get-WindowsFirewallStatus {
    <#
    .SYNOPSIS
        Windows Firewall: Alle 3 Profile aktiv?
    #>
    param([Parameter(Mandatory)][string]$DC)
    $sb = {
        $out = @()
        try {
            Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                $out += [pscustomobject]@{ Profile=$_.Name; Enabled=$_.Enabled; DefaultInbound="$($_.DefaultInboundAction)"; DefaultOutbound="$($_.DefaultOutboundAction)"; LogBlocked=$_.LogBlocked }
            }
        } catch { $out += [pscustomobject]@{ Profile='Error'; Enabled=$null; DefaultInbound='-'; DefaultOutbound='-'; LogBlocked=$null } }
        $out
    }
    $data = Invoke-RemoteCommand -ComputerName $DC -ScriptBlock $sb
    if (-not $data) { return @([pscustomobject]@{ DCName=$DC; Profile='(Abfrage fehlgeschlagen)'; Enabled=$null; DefaultInbound='-'; DefaultOutbound='-'; LogBlocked=$null }) }
    $data | ForEach-Object { $_ | Add-Member -NotePropertyName DCName -NotePropertyValue $DC -PassThru -Force }
}

function Get-ADRecycleBinStatus {
    <#
    .SYNOPSIS
        Prueft ob AD Recycle Bin Feature aktiv ist.
    #>
    try {
        $feat = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } -ErrorAction Stop
        $enabled = ($feat.EnabledScopes.Count -gt 0)
        [pscustomobject]@{
            FeatureName=$feat.Name; RequiredMode=$feat.RequiredForestMode
            EnabledScopes=($feat.EnabledScopes -join '; '); IsEnabled=$enabled
            Detail=if ($enabled) { "AD Recycle Bin aktiv (Scope: $($feat.EnabledScopes -join ', '))" } else { "AD Recycle Bin NICHT aktiv - kein Restore geloeschter Objekte (ausser Backup)" }
        }
    } catch {
        [pscustomobject]@{ FeatureName='-'; RequiredMode='-'; EnabledScopes='-'; IsEnabled=$false; Detail="Abfrage-Fehler: $_" }
    }
}

function Get-TombstoneLifetime {
    <#
    .SYNOPSIS
        Tombstone Lifetime - Best Practice >=180 Tage.
    #>
    try {
        $config = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $tsl = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$config" -Properties tombstoneLifetime -ErrorAction Stop).tombstoneLifetime
        if (-not $tsl) { $tsl = 60 }
        [pscustomobject]@{
            TombstoneLifetimeDays=$tsl; Recommended=$Global:TombstoneMinDays
            MeetsBestPractice=($tsl -ge $Global:TombstoneMinDays)
            Detail=if ($tsl -ge $Global:TombstoneMinDays) { "Tombstone = $tsl Tage (Best Practice: >=$Global:TombstoneMinDays)" } else { "Tombstone = $tsl Tage - zu niedrig!" }
        }
    } catch {
        [pscustomobject]@{ TombstoneLifetimeDays=$null; Recommended=$Global:TombstoneMinDays; MeetsBestPractice=$false; Detail="Abfrage-Fehler: $_" }
    }
}

function Get-SPNDuplicateReport {
    <#
    .SYNOPSIS
        Erkennt doppelte SPNs im Verzeichnis.
    #>
    $result = @()
    try {
        $spnEntries = foreach ($obj in (Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, sAMAccountName, distinguishedName, objectClass, name -ErrorAction Stop)) {
            $objClass = if ($obj.objectClass -is [array]) { $obj.objectClass[-1] } else { $obj.objectClass }
            foreach ($spn in @($obj.servicePrincipalName | Where-Object { $_ })) {
                [pscustomobject]@{
                    SPN=$spn.ToLowerInvariant(); DisplaySPN=$spn; Name=$obj.Name; SamAccount=$obj.sAMAccountName
                    ObjectClass=$objClass; DistinguishedName=$obj.DistinguishedName
                }
            }
        }

        foreach ($dup in ($spnEntries | Group-Object SPN | Where-Object { $_.Count -gt 1 })) {
            foreach ($entry in $dup.Group) {
                $result += [pscustomobject]@{
                    SPN=$entry.DisplaySPN; DuplicateCount=$dup.Count; Name=$entry.Name; SamAccount=$entry.SamAccount
                    ObjectClass=$entry.ObjectClass; DistinguishedName=$entry.DistinguishedName
                }
            }
        }
    } catch {
        Write-Log "SPNDuplicates: $_" -Level WARN -NoConsole
    }
    return $result
}

function Get-ASREPRoastingRisk {
    <#
    .SYNOPSIS
        Erkennt Benutzer ohne Kerberos Pre-Authentication.
    #>
    $result = @()
    try {
        $users = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
                            -Properties PasswordLastSet, PasswordNeverExpires, AdminCount, MemberOf, DoesNotRequirePreAuth -ErrorAction Stop
        foreach ($u in $users) {
            $pwdAge = if ($u.PasswordLastSet) { (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days } else { $null }
            $directGroups = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
            $risk = 'WARN'
            if ($u.AdminCount -eq 1) { $risk = 'CRITICAL' }
            elseif ($u.PasswordNeverExpires) { $risk = 'HIGH' }
            elseif ($pwdAge -ge $Global:KerberoastPwdAgeWarn) { $risk = 'HIGH' }

            $result += [pscustomobject]@{
                SamAccount=$u.SamAccountName; Name=$u.Name; PasswordLastSet=$u.PasswordLastSet; PasswordAgeDays=$pwdAge
                PasswordNeverExpires=$u.PasswordNeverExpires; IsPrivileged=($u.AdminCount -eq 1); Risk=$risk
                MemberOf=($directGroups -join '; '); DistinguishedName=$u.DistinguishedName
            }
        }
    } catch {
        Write-Log "ASREPRoasting: $_" -Level WARN -NoConsole
    }
    return $result
}

function Get-AdminSDHolderDrift {
    <#
    .SYNOPSIS
        Findet Objekte mit AdminCount=1, die nicht mehr in geschuetzten Gruppen sind.
    #>
    $result = @()
    try {
        $protectedGroups = @(
            'Administrators','Domain Admins','Enterprise Admins','Schema Admins','Account Operators',
            'Server Operators','Backup Operators','Print Operators','Domain Controllers',
            'Read-only Domain Controllers','DnsAdmins','Key Admins','Enterprise Key Admins'
        )

        $protectedDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($groupName in $protectedGroups) {
            try {
                Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop | ForEach-Object {
                    if ($_.DistinguishedName) { [void]$protectedDns.Add($_.DistinguishedName) }
                }
            } catch {}
        }

        $objects = @()
        $objects += Get-ADUser -LDAPFilter '(&(adminCount=1)(objectCategory=person)(objectClass=user))' -Properties AdminCount, MemberOf -ErrorAction Stop
        $objects += Get-ADComputer -LDAPFilter '(adminCount=1)' -Properties AdminCount, MemberOf, OperatingSystem -ErrorAction Stop

        foreach ($obj in $objects) {
            $directGroups = @($obj.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
            $isProtected = $protectedDns.Contains($obj.DistinguishedName)
            $result += [pscustomobject]@{
                ObjectClass=if ($obj.objectClass -is [array]) { $obj.objectClass[-1] } else { $obj.objectClass }
                Name=$obj.Name; SamAccount=$obj.SamAccountName; AdminCount=$obj.AdminCount
                ProtectedByMembership=$isProtected; Risk=if ($isProtected) { 'OK' } else { 'DRIFT' }
                DirectGroups=($directGroups -join '; '); DistinguishedName=$obj.DistinguishedName
            }
        }
    } catch {
        Write-Log "AdminSDHolderDrift: $_" -Level WARN -NoConsole
    }
    return $result
}

function Get-FGPPOverview {
    <#
    .SYNOPSIS
        Prueft Fine-Grained Password Policies auf Staerke und Zuordnung.
    #>
    $result = @()
    try {
        $policies = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction Stop
        foreach ($policy in $policies) {
            $subjects = @()
            try { $subjects = @(Get-ADFineGrainedPasswordPolicySubject -Identity $policy -ErrorAction Stop) } catch {}
            $maxAgeDays = if ($policy.MaxPasswordAge) { [math]::Abs([int]$policy.MaxPasswordAge.TotalDays) } else { 0 }
            $issues = @()
            if ($policy.MinPasswordLength -lt $Global:FGPPMinPasswordLength) { $issues += "MinPasswordLength=$($policy.MinPasswordLength)" }
            if ($policy.PasswordHistoryCount -lt $Global:FGPPPasswordHistoryMin) { $issues += "PasswordHistory=$($policy.PasswordHistoryCount)" }
            if (-not $policy.ComplexityEnabled) { $issues += 'Complexity disabled' }
            if ($maxAgeDays -eq 0 -or $maxAgeDays -gt 90) { $issues += "MaxPasswordAge=$maxAgeDays" }
            if ($policy.LockoutThreshold -eq 0 -or $policy.LockoutThreshold -gt 10) { $issues += "LockoutThreshold=$($policy.LockoutThreshold)" }
            if ($subjects.Count -eq 0) { $issues += 'Keine Zuordnung' }

            $result += [pscustomobject]@{
                Name=$policy.Name; Precedence=$policy.Precedence; MinPasswordLength=$policy.MinPasswordLength
                PasswordHistoryCount=$policy.PasswordHistoryCount; ComplexityEnabled=$policy.ComplexityEnabled
                MaxPasswordAgeDays=$maxAgeDays; LockoutThreshold=$policy.LockoutThreshold
                AppliesToCount=$subjects.Count; AppliesTo=($subjects.Name -join '; ')
                Risk=if ($issues.Count -eq 0) { 'OK' } elseif ($issues.Count -ge 3) { 'CRITICAL' } else { 'WARN' }
                Detail=($issues -join ' | ')
            }
        }
    } catch {
        Write-Log "FGPP: $_" -Level WARN -NoConsole
    }
    return $result
}

function Get-DNSHygiene {
    <#
    .SYNOPSIS
        Prueft DNS-Aging/Scavenging und Reverse-Lookup-Grundlagen.
    #>
    $result = @()
    try {
        $zones = @(Get-DnsServerZone -ErrorAction Stop)
        $reverseZones = @($zones | Where-Object { $_.IsReverseLookupZone })

        try {
            $scavenging = Get-DnsServerScavenging -ErrorAction Stop
            $result += [pscustomobject]@{
                Kind='Server'; Target='DNS Server Scavenging'; Status=if ($scavenging.ScavengingState) { 'OK' } else { 'WARN' }
                DynamicUpdate='-'; AgingEnabled=$scavenging.ScavengingState; NoRefreshDays=$null; RefreshDays=$null
                ReverseZoneCount=$reverseZones.Count
                Detail=if ($scavenging.ScavengingState) { 'Server-weites Scavenging aktiviert' } else { 'Server-weites Scavenging deaktiviert' }
            }
        } catch {
            $result += [pscustomobject]@{
                Kind='Server'; Target='DNS Server Scavenging'; Status='WARN'; DynamicUpdate='-'; AgingEnabled=$null
                NoRefreshDays=$null; RefreshDays=$null; ReverseZoneCount=$reverseZones.Count; Detail="Scavenging-Abfrage fehlgeschlagen: $_"
            }
        }

        foreach ($zone in ($zones | Where-Object { $_.ZoneType -eq 'Primary' })) {
            $aging = $null
            try { $aging = Get-DnsServerZoneAging -Name $zone.ZoneName -ErrorAction Stop } catch {}
            $status = 'OK'
            $issues = @()
            if (-not $zone.IsDsIntegrated) { $issues += 'nicht AD-integriert'; $status = 'WARN' }
            if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') { $issues += 'unsichere Dynamic Updates'; $status = 'CRITICAL' }
            if (-not $aging -or -not $aging.AgingEnabled) { $issues += 'Aging deaktiviert'; if ($status -ne 'CRITICAL') { $status = 'WARN' } }
            if ($aging) {
                $noRefresh = [int]$aging.NoRefreshInterval.TotalDays
                $refresh = [int]$aging.RefreshInterval.TotalDays
                if ($noRefresh -lt $Global:DNSAgingMinDays) { $issues += "NoRefresh=$noRefresh"; if ($status -ne 'CRITICAL') { $status = 'WARN' } }
                if ($refresh -lt $Global:DNSAgingMinDays) { $issues += "Refresh=$refresh"; if ($status -ne 'CRITICAL') { $status = 'WARN' } }
            } else {
                $noRefresh = $null
                $refresh = $null
            }

            $result += [pscustomobject]@{
                Kind='Zone'; Target=$zone.ZoneName; Status=$status; DynamicUpdate=$zone.DynamicUpdate; AgingEnabled=if ($aging) { $aging.AgingEnabled } else { $false }
                NoRefreshDays=$noRefresh; RefreshDays=$refresh; ReverseZoneCount=$reverseZones.Count
                Detail=if ($issues.Count -eq 0) { 'Zone-Hygiene unauffaellig' } else { $issues -join ' | ' }
            }
        }

        if ($reverseZones.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Summary'; Target='Reverse Lookup Zones'; Status='WARN'; DynamicUpdate='-'; AgingEnabled=$null
                NoRefreshDays=$null; RefreshDays=$null; ReverseZoneCount=0; Detail='Keine Reverse-Lookup-Zonen gefunden'
            }
        }
    } catch {
        Write-Log "DNSHygiene: $_" -Level WARN -NoConsole
    }
    return $result
}

function Get-ReverseLookupCompleteness {
    <#
    .SYNOPSIS
        Prueft, ob fuer alle im Forward-Lookup registrierten IPs (A/AAAA Records)
        eine passende Reverse-Lookup-Zone (in-addr.arpa / ip6.arpa) existiert.
    .NOTES
        - Forest-weiter Check (einmalig, nicht pro DC)
        - Sammelt alle A/AAAA Records aus allen Primary-Zonen (AD-integriert und nicht)
        - Ermittelt pro IP die zugehoerige Reverse-Zone
        - Meldet fehlende Reverse-Zonen
        - NICHT: Pruefung ob PTR-Record existiert (nur Zone)
        - Verwendet direkte Get-DnsServerZone/-ResourceRecord Aufrufe (v2.7-Stil)
    #>
    $result = @()
    try {
        # Hole einen erreichbaren DC mit DNS
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Where-Object { $_.IPv4Address })
        if ($dcs.Count -eq 0) {
            return @([pscustomobject]@{ Kind='Fehler'; Target='Reverse Lookup'; Status='WARN'; Detail='Kein erreichbarer DC mit IPv4 gefunden'; Risk='WARN' })
        }
        $dc = $dcs[0]

        # Alle Primary-Zonen (Forward und Reverse) vom DC holen
        $allZones = @()
        try { $allZones = @(Get-DnsServerZone -ComputerName $dc -ErrorAction Stop) } catch {
            return @([pscustomobject]@{ Kind='Fehler'; Target='Reverse Lookup'; Status='WARN'; Detail='Keine DNS-Zonen vom DC abrufbar'; Risk='WARN' })
        }
        if ($allZones.Count -eq 0) {
            return @([pscustomobject]@{ Kind='Fehler'; Target='Reverse Lookup'; Status='WARN'; Detail='Keine DNS-Zonen vom DC abrufbar'; Risk='WARN' })
        }

        # Forward-Zonen filtern (Primary, nicht Reverse, nicht Forwarder-Typ)
        $forwardZones = @($allZones | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and $_.ZoneType -ne 'Forwarder' })

        # Alle A/AAAA Records aus Forward-Zonen sammeln
        $forwardIPs = @{}
        foreach ($zone in $forwardZones) {
            $zn = $zone.ZoneName
            try {
                $records = @(Get-DnsServerResourceRecord -ComputerName $dc -ZoneName $zn -RRType 'A','AAAA' -ErrorAction Stop)
                foreach ($rec in $records) {
                    $rd = $rec.RecordData
                    if ($null -ne $rd) {
                        $ip = if ($rec.RRType -eq 'A') { [string]$rd.IPv4Address } else { [string]$rd.IPv6Address }
                        if ($ip) {
                            $key = "$zn|$ip"
                            if (-not $forwardIPs.ContainsKey($key)) {
                                $forwardIPs[$key] = [pscustomobject]@{
                                    ZoneName = $zn; IP = $ip; RRType = $rec.RRType; HostName = [string]$rec.HostName
                                }
                            }
                        }
                    }
                }
            } catch {}
        }

        if ($forwardIPs.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Summary'; Target='Reverse Lookup'; Status='OK'
                Detail='Keine A/AAAA Records in Forward-Zonen gefunden'; Risk='OK'
            }
            return $result
        }

        # Existierende Reverse-Zonen ermitteln
        $reverseZoneNames = @($allZones | Where-Object { $_.IsReverseLookupZone } | ForEach-Object { $_.ZoneName })

        function Get-ReverseZoneNameFromIP {
            param([string]$IP)
            if ($IP -match '^\d+\.\d+\.\d+\.\d+$') {
                $octets = $IP.Split('.')
                if ($octets.Count -eq 4) { return ('{2}.{1}.{0}.in-addr.arpa' -f $octets[0], $octets[1], $octets[2]) }
            }
            elseif ($IP -match ':') {
                try {
                    $ip6 = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
                    $nibbles = ($ip6 | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                    $nibbles = $nibbles.PadLeft(32, '0')
                    $rev = ($nibbles.ToCharArray() | ForEach-Object { $_ }) -join '.'
                    return "$rev.ip6.arpa"
                } catch {}
            }
            return $null
        }

        $missing = @()
        foreach ($kv in $forwardIPs.GetEnumerator()) {
            $entry = $kv.Value
            $revZone = Get-ReverseZoneNameFromIP -IP $entry.IP
            if ($null -eq $revZone) {
                $missing += [pscustomobject]@{ ZoneName=$entry.ZoneName; IP=$entry.IP; HostName=$entry.HostName; Reason='IP-Format nicht erkannt' }
            }
            elseif ($reverseZoneNames -notcontains $revZone) {
                $missing += [pscustomobject]@{ ZoneName=$entry.ZoneName; IP=$entry.IP; HostName=$entry.HostName; MissingReverseZone=$revZone }
            }
        }

        if ($missing.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Summary'; Target='Reverse Lookup'; Status='OK'
                Detail=("Alle {0} Forward-IPs haben eine passende Reverse-Zone" -f $forwardIPs.Count); Risk='OK'
            }
        }
        else {
            $byMissingZone = $missing | Group-Object MissingReverseZone
            $details = @()
            foreach ($grp in $byMissingZone) {
                $sample = @($grp.Group | Select-Object -First 3 | ForEach-Object { "{0} ({1})" -f $_.IP, $_.HostName }) -join ', '
                $more = if ($grp.Count -gt 3) { " ... und {0} weitere" -f ($grp.Count - 3) } else { '' }
                $details += "Fehlende Reverse-Zone: {0} -> betrifft {1} IP(s) ({2}{3})" -f $grp.Name, $grp.Count, $sample, $more
            }
            $result += [pscustomobject]@{
                Kind='Summary'; Target='Reverse Lookup'; Status='WARN'
                Detail=($details -join ' | '); Risk='WARN'
            }
            foreach ($m in $missing) {
                $result += [pscustomobject]@{
                    Kind='MissingReverseZone'; Target=$m.MissingReverseZone; Status='WARN'
                    Detail="Forward-Zone: {0}, IP: {1}, Host: {2}" -f $m.ZoneName, $m.IP, $m.HostName
                    Risk='WARN'
                }
            }
        }
    } catch {
        $result += [pscustomobject]@{
            Kind='Fehler'; Target='Reverse Lookup'; Status='WARN'
            Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN'
        }
    }
    return $result
}

function Test-Check-ReverseLookupComplete {
    <#
    .SYNOPSIS
        Bewertet das Ergebnis von Get-ReverseLookupCompleteness.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $summary = @($data | Where-Object { $_.Kind -eq 'Summary' })
    if ($summary.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Zusammenfassung' }
    $s = $summary[0]
    if ($s.Status -eq 'OK') {
        return New-Assessment -OverallStatus 'OK' -Summary $s.Detail -Findings @()
    }
    else {
        $findings = @($data | Where-Object { $_.Kind -eq 'MissingReverseZone' } | ForEach-Object { $_.Detail })
        return New-Assessment -OverallStatus 'WARN' -Summary $s.Detail -Findings $findings
    }
}


function Get-KMSConfiguration {
    <#
    .SYNOPSIS
        Sucht KMS-Hosts per DNS-SRV (_vlmcs._tcp) und liest deren Konfiguration aus.
    .NOTES
        - Forest-weiter Check
        - Discovery per Resolve-DnsName -Type SRV auf _vlmcs._tcp.<ForestRoot> und _vlmcs._tcp.<Domain>
        - Falls kein SRV-Eintrag: Scan aller erreichbaren DCs nach installiertem KeyManagementService
        - Konfiguration je Host: Dienst, Port, Prozess, Aktivierungszahlen, Host-Key, Key-Kanal
        - Mehrstufige Diensterkennung (Get-Service, CIM Win32_Service, Registry)
        - Registry-Lesen in expliziter 64-Bit-Ansicht mit PS-Provider-Fallback
    #>
    $result = @()
    try {
        $forest = Get-ADForest -ErrorAction Stop
        
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Where-Object { $_.IPv4Address })
        if ($dcs.Count -eq 0) {
            return @([pscustomobject]@{ Kind='Fehler'; Target='KMS'; Detail='Keine erreichbaren DCs'; Risk='WARN' })
        }

        # 1) SRV-Discovery
        $srvTargets = @("_vlmcs._tcp.$($forest.RootDomain)", "_vlmcs._tcp.$($domain.DNSRoot)")
        $kmsHosts = @{}
        foreach ($srv in $srvTargets) {
            try {
                $records = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop -DnsOnly
                foreach ($r in $records) {
                    $hn = $r.NameHost.TrimEnd('.')
                    if (-not $kmsHosts.ContainsKey($hn)) { $kmsHosts[$hn] = @{ SRV=$true; Source=$srv } }
                }
            } catch {}
        }

        # 2) Falls keine SRV-Eintraege: DCs nach KMS-Dienst scannen
        if ($kmsHosts.Count -eq 0) {
            foreach ($dc in $dcs) {
                $hn = $dc.HostName
                if (-not $kmsHosts.ContainsKey($hn)) { $kmsHosts[$hn] = @{ SRV=$false; Source='DC-Scan' } }
            }
        }

        # 3) Konfiguration je Host auslesen
        foreach ($hostEntry in $kmsHosts.GetEnumerator()) {
            $kmsHost = $hostEntry.Key
            $meta = $hostEntry.Value
            $detail = [ordered]@{
                HostName = $kmsHost
                HasSRV   = $meta.SRV
                Source   = $meta.Source
                Service  = 'Nicht gefunden'
                StartType= '-'
                Port     = '-'
                Process  = '-'
                ActivationCount = 0
                RequestCount    = 0
                FailedCount     = 0
                PartialProductKey = '-'
                KeyChannel        = '-'
                Issue          = $null
            }

            $target = $kmsHost
            $cim = $null
            try {
                $cim = New-CimSession -ComputerName $target -OperationTimeoutSec 10 -ErrorAction Stop
            } catch {
                $detail.Issue = "CIM-Verbindung fehlgeschlagen: $_"
                $result += [pscustomobject]@{ Kind='Host'; Target=$kmsHost; Detail=($detail.Values -join ' | '); Risk='WARN'; HostName=$kmsHost; Service=$detail.Service; StartType=$detail.StartType; Port=$detail.Port; Process=$detail.Process; ActivationCount=$detail.ActivationCount; RequestCount=$detail.RequestCount; FailedCount=$detail.FailedCount; PartialProductKey=$detail.PartialProductKey; KeyChannel=$detail.KeyChannel; HasSRV=$detail.HasSRV }
                continue
            }

            # Dienst erkennen (mehrstufig)
            $svc = $null
            try { $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='KeyManagementService'" -ErrorAction Stop } catch {}
            if (-not $svc) {
                try { $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "DisplayName='Key Management Service'" -ErrorAction Stop } catch {}
            }
            if (-not $svc) {
                try { $allSvcs = Get-CimInstance -CimSession $cim -ClassName Win32_Service -ErrorAction Stop; $svc = $allSvcs | Where-Object { $_.Name -like '*KeyManagement*' -or $_.DisplayName -like '*Key Management*' } | Select-Object -First 1 } catch {}
            }
            if (-not $svc) {
                # Registry-Fallback
                try {
                    $reg = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\KeyManagementService' -ErrorAction Stop
                    if ($reg) { $svc = [pscustomobject]@{ Name='KeyManagementService'; State='Unknown'; StartMode=$reg.Start } }
                } catch {}
            }

            if ($svc) {
                $detail.Service = $svc.Name
                $detail.StartType = if ($svc.StartMode) { $svc.StartMode } else { 'Unknown' }
                $detail.State = if ($svc.State) { $svc.State } else { 'Unknown' }
            }

            # Port aus Registry
            try {
                $portReg = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\KeyManagementService\Parameters' -ErrorAction Stop
                if ($portReg -and $portReg.Port) { $detail.Port = $portReg.Port }
            } catch {}

            # Prozess auf Port (lokal oder remote via CIM)
            if ($detail.Port -ne '-') {
                try {
                    $conns = Get-CimInstance -CimSession $cim -ClassName Win32_TCPConnection -Filter "LocalPort=$($detail.Port) AND State='Listen'" -ErrorAction Stop
                    if ($conns) { $detail.Process = $conns[0].OwningProcess }
                } catch {}
            }

            # SoftwareLicensingService Daten
            try {
                $sls = Get-CimInstance -CimSession $cim -Namespace 'root\cimv2' -ClassName SoftwareLicensingService -ErrorAction Stop
                if ($sls) {
                    $detail.ActivationCount = if ($sls.ActivationCount) { $sls.ActivationCount } else { 0 }
                    $detail.RequestCount    = if ($sls.RequestCount) { $sls.RequestCount } else { 0 }
                    $detail.FailedCount     = if ($sls.FailedRequestCount) { $sls.FailedRequestCount } else { 0 }
                    $detail.PartialProductKey = if ($sls.PartialProductKey) { $sls.PartialProductKey } else { '-' }
                    $detail.KeyChannel = if ($sls.LicenseChannel) { $sls.LicenseChannel } else { '-' }
                }
            } catch {}

            # Bewertung je Host
            $risk = 'OK'
            $issues = @()
            if (-not $detail.HasSRV) { $issues += 'Kein _vlmcs SRV-Eintrag'; $risk = 'CRITICAL' }
            if ($detail.Service -eq 'Nicht gefunden' -or $detail.State -ne 'Running') { $issues += "Dienst nicht lauffaehig ($($detail.State))"; $risk = 'CRITICAL' }
            if ($detail.Port -ne '-' -and $detail.Process -eq '-') { $issues += "Port $($detail.Port) nicht abhoerend"; $risk = 'CRITICAL' }
            if ($detail.ActivationCount -lt $Global:KMSMinCountServer) { $issues += "Aktivierungen ($($detail.ActivationCount)) < Server-Min ($Global:KMSMinCountServer)"; $risk = 'CRITICAL' }
            if ($detail.RequestCount -lt $Global:KMSMinCountClient) { $issues += "Anfragen ($($detail.RequestCount)) < Client-Min ($Global:KMSMinCountClient)"; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }
            if ($detail.Port -ne '-' -and $detail.Port -ne 1688) { $issues += "Port $($detail.Port) != 1688"; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }
            if ($detail.PartialProductKey -eq '-') { $issues += 'Kein Host-Key (PartialProductKey)'; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }
            if ($detail.KeyChannel -ne 'Volume') { $issues += "Key-Kanal '$($detail.KeyChannel)' != Volume"; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }
            if ($detail.FailedCount -gt 0 -and ($detail.RequestCount -gt 0) -and (($detail.FailedCount / $detail.RequestCount) -gt 0.5)) { $issues += "Mehr als 50% Fehlanfragen"; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }
            if ($detail.HasSRV -and $kmsHosts.Count -eq 1) { $issues += 'Nur ein KMS-Host (kein Failover)'; if ($risk -ne 'CRITICAL') { $risk = 'WARN' } }

            $detail.Issue = if ($issues.Count) { $issues -join ' | ' } else { 'OK' }
            $result += [pscustomobject]@{
                Kind='Host'; Target=$kmsHost; Detail=($detail.Values -join ' | '); Risk=$risk
                HostName=$kmsHost; Service=$detail.Service; StartType=$detail.StartType; Port=$detail.Port
                Process=$detail.Process; ActivationCount=$detail.ActivationCount; RequestCount=$detail.RequestCount
                FailedCount=$detail.FailedCount; PartialProductKey=$detail.PartialProductKey; KeyChannel=$detail.KeyChannel
                HasSRV=$detail.HasSRV; Method=$detail.Source
            }
            Remove-CimSession $cim -ErrorAction SilentlyContinue
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='KMS'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-KMS {
    <#
    .SYNOPSIS
        Bewertet KMS-Konfiguration.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $hosts = @($data | Where-Object { $_.Kind -eq 'Host' })
    if ($hosts.Count -eq 0) {
        $err = @($data | Where-Object { $_.Kind -eq 'Fehler' })
        if ($err.Count) { return New-Assessment -OverallStatus 'WARN' -Summary $err[0].Detail -Findings @($err[0].Detail) }
        return New-Assessment -OverallStatus 'CRITICAL' -Summary 'Keine KMS-Hosts gefunden (weder SRV noch DC-Scan)' -Findings @('Keine KMS-Hosts gefunden')
    }
    $critical = @($hosts | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($hosts | Where-Object { $_.Risk -eq 'WARN' })
    $ok = @($hosts | Where-Object { $_.Risk -eq 'OK' })
    $findings = @()
    foreach ($h in $hosts) { if ($h.Risk -ne 'OK') { $findings += $h.Detail } }
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($hosts.Count) KMS-Host(s): OK $($ok.Count), WARN $($warn.Count), CRITICAL $($critical.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-StaleDCObjects {
    <#
    .SYNOPSIS
        Gleicht 7 unabhaengige Quellen fuer „welche DCs gibt es“ gegeneinander ab.
    .NOTES
        Quellen:
        1. Live-DCs (Get-ADDomainController -Filter *)
        2. Computer-Objekte in OU=Domain Controllers
        3. Server-Objekte + NTDS-Settings im Config-NC
        4. Replikationspartner aller Domänen
        5. FSMO-Rollen-Inhaber
        6. DNS SRV _ldap._tcp.dc._msdcs
        7. DNS A-Eintraege fuer DC-Hostnamen
        Bewertung:
        - CRITICAL: Aktiver DC deaktiviert / ohne DNS-A / ohne DNS-SRV
        - CRITICAL: Nicht-lebender DC traegt noch FSMO/NTDS/Account-Reste
        - WARN: Inkonsistenzen zwischen Quellen
        Schwellwert: $Global:StaleDCWarnAgeDays (0 = jedes verwaiste Objekt)
    #>
    $result = @()
    try {
        $forest = Get-ADForest -ErrorAction Stop
        
        $domainDN = $domain.DistinguishedName
        $configNC = "CN=Configuration,$domainDN"
        $dcOU = "OU=Domain Controllers,$domainDN"

        # Quelle 1: Live DCs
        $liveDCs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object -Unique)

        # Quelle 2: Computer-Objekte in DC-OU
        $ouComputers = @()
        try { $ouComputers = @(Get-ADComputer -SearchBase $dcOU -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object -Unique) } catch {}

        # Quelle 3: Server-Objekte + NTDS-Settings im Config-NC
        $configServers = @()
        try {
            $servers = Get-ADObject -SearchBase $configNC -LDAPFilter '(objectClass=server)' -Properties 'name' -ErrorAction Stop
            foreach ($s in $servers) {
                $ntds = Get-ADObject -SearchBase "CN=NTDS Settings,$($s.DistinguishedName)" -LDAPFilter '(objectClass=nTDSDSA)' -ErrorAction SilentlyContinue
                if ($ntds) { $configServers += $s.Name }
            }
        } catch {}
        $configServers = $configServers | Sort-Object -Unique

        # Quelle 4: Replikationspartner
        $replPartners = @()
        try {
            $parts = Get-ADReplicationPartnerMetadata -Target $forest.RootDomain -Scope Forest -ErrorAction Stop
            $replPartners = @($parts | Select-Object -ExpandProperty Server | Sort-Object -Unique)
        } catch {}

        # Quelle 5: FSMO
        $fsmo = @()
        try {
            $f = Get-ADForest -ErrorAction Stop; $d = Get-ADDomain -ErrorAction Stop
            $fsmo += $f.SchemaMaster, $f.DomainNamingMaster, $d.PDCEmulator, $d.RIDMaster, $d.InfrastructureMaster
        } catch {}
        $fsmo = $fsmo | Where-Object { $_ } | Sort-Object -Unique

        # Quelle 6: DNS SRV _ldap._tcp.dc._msdcs
        $srvDCs = @()
        try {
            $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($forest.RootDomain)" -Type SRV -ErrorAction Stop -DnsOnly
            $srvDCs = @($srv | Select-Object -ExpandProperty NameHost | ForEach-Object { $_.TrimEnd('.') } | Sort-Object -Unique)
        } catch {}

        # Quelle 7: DNS A-Eintraege fuer Live-DCs
        $dnsA = @()
        foreach ($dc in $liveDCs) {
            try {
                $a = Resolve-DnsName -Name $dc -Type A -ErrorAction Stop -DnsOnly
                if ($a) { $dnsA += $dc }
            } catch {}
        }

        # Alle gefundenen Namen sammeln
        $allNames = @($liveDCs + $ouComputers + $configServers + $replPartners + $fsmo + $srvDCs + $dnsA) | Sort-Object -Unique

        # Bewertung je Name
        foreach ($name in $allNames) {
            $row = [ordered]@{
                Name = $name
                Live = $false
                InOU = $false
                InConfig = $false
                InRepl = $false
                InFSMO = $false
                InSRV = $false
                InDNS = $false
                Issues = @()
            }
            if ($liveDCs -contains $name) { $row.Live = $true }
            if ($ouComputers -contains $name) { $row.InOU = $true }
            if ($configServers -contains $name) { $row.InConfig = $true }
            if ($replPartners -contains $name) { $row.InRepl = $true }
            if ($fsmo -contains $name) { $row.InFSMO = $true }
            if ($srvDCs -contains $name) { $row.InSRV = $true }
            if ($dnsA -contains $name) { $row.InDNS = $true }

            # Bewertung
            if ($row.Live) {
                if (-not $row.InOU) { $row.Issues += 'Computer-Objekt in OU=Domain Controllers fehlt' }
                if (-not $row.InConfig) { $row.Issues += 'NTDS-Settings im Config-NC fehlen' }
                if (-not $row.InDNS) { $row.Issues += 'Kein DNS-A-Eintrag' }
                if (-not $row.InSRV) { $row.Issues += 'Kein DNS-SRV (_ldap._tcp)' }
            }
            else {
                # Nicht live, aber in anderen Quellen vorhanden -> verwaister DC
                $sources = @()
                if ($row.InOU) { $sources += 'OU' }
                if ($row.InConfig) { $sources += 'Config' }
                if ($row.InRepl) { $sources += 'Repl' }
                if ($row.InFSMO) { $sources += 'FSMO' }
                if ($row.InSRV) { $sources += 'SRV' }
                if ($row.InDNS) { $sources += 'DNS' }
                if ($sources.Count) {
                    $row.Issues += "Verwaist, aber in Quellen: $($sources -join ', ')"
                }
            }

            # Ausgabe
            $detail = "Live:$($row.Live) OU:$($row.InOU) Config:$($row.InConfig) Repl:$($row.InRepl) FSMO:$($row.InFSMO) SRV:$($row.InSRV) DNS:$($row.InDNS)"
            if ($row.Issues.Count) { $detail += " | " + ($row.Issues -join '; ') }
            $risk = if ($row.Issues.Count -and $row.Live) { 'CRITICAL' } elseif ($row.Issues.Count -and -not $row.Live) { 'CRITICAL' } elseif ($row.Issues.Count) { 'WARN' } else { 'OK' }

            $result += [pscustomobject]@{
                Kind='DC'; Target=$name; Risk=$risk; Detail=$detail
                Live=$row.Live; InOU=$row.InOU; InConfig=$row.InConfig; InRepl=$row.InRepl
                InFSMO=$row.InFSMO; InSRV=$row.InSRV; InDNS=$row.InDNS
                RowKey="DC|$name"
            }
        }

        # Quellen-Zusammenfassung
        $qNames = @('Live','OU','Config','Repl','FSMO','SRV','DNS')
        $qCounts = @($liveDCs.Count, $ouComputers.Count, $configServers.Count, $replPartners.Count, $fsmo.Count, $srvDCs.Count, $dnsA.Count)
        for ($i=0; $i -lt $qNames.Count; $i++) {
            $result += [pscustomobject]@{
                Kind='Quelle'; Target=$qNames[$i]; Risk='OK'
                Detail="Quelle $($qNames[$i]): $($qCounts[$i]) Eintraege"
                RowKey="Quelle|$($qNames[$i])"
            }
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='StaleDCs'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-StaleDCs {
    <#
    .SYNOPSIS
        Bewertet Stale-DC-Analyse.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $dcRows = @($data | Where-Object { $_.Kind -eq 'DC' })
    if ($dcRows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine DC-Daten' }
    $critical = @($dcRows | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($dcRows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($dcRows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($dcRows.Count) DCs geprueft: OK $($dcRows.Count - $critical.Count - $warn.Count), WARN $($warn.Count), CRITICAL $($critical.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-RCAudit {
    <#
    .SYNOPSIS
        Sammelt echte Belege fuer RC4/LM-Nutzung je DC (Check 57).
    .NOTES
        - Netlogon Secure Channel EncryptionTypes
        - NoLMHash Registry
        - Security Log Events 4768/4769 (Kerberos Tickets, Type 0x17/0x18)
        - Zeitfenster: $Global:RC4EventDays (Default 7), Sample: $Global:RC4EventSampleLimit (Default 5000)
    #>
    $result = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Where-Object { $_.IPv4Address })
        $days = $Global:RC4EventDays
        $limit = $Global:RC4EventSampleLimit
        $since = (Get-Date).AddDays(-$days)

        foreach ($dc in $dcs) {
            $dcName = $dc.HostName

            # 1) Netlogon Secure Channel EncryptionTypes
            try {
                $nls = Get-ADDomainController -Identity $dcName -Properties 'msDS-NetlogonSecureChannelEncryptionTypes' -ErrorAction Stop
                $enc = $nls.'msDS-NetlogonSecureChannelEncryptionTypes'
                $result += [pscustomobject]@{
                    Kind='Netlogon'; DCName=$dcName; Risk=if ($enc -band 0x0C) { 'OK' } else { 'WARN' }
                    Detail="Netlogon Secure Channel EncryptionTypes=0x$([Convert]::ToString($enc,16))"; RowKey="Netlogon|$dcName"
                }
            } catch { $result += [pscustomobject]@{ Kind='Netlogon'; DCName=$dcName; Risk='WARN'; Detail="Netlogon EncryptionTypes nicht lesbar: $_"; RowKey="Netlogon|$dcName" } }

            # 2) NoLMHash
            try {
                $reg = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
                $noLM = $reg.'NoLMHash'
                $result += [pscustomobject]@{
                    Kind='NoLMHash'; DCName=$dcName; Risk=if ($noLM -eq 1) { 'OK' } else { 'CRITICAL' }
                    Detail="NoLMHash=$($noLM)"; RowKey="NoLMHash|$dcName"
                }
            } catch { $result += [pscustomobject]@{ Kind='NoLMHash'; DCName=$dcName; Risk='WARN'; Detail="NoLMHash nicht lesbar: $_"; RowKey="NoLMHash|$dcName" } }

            # 3) Security Log: Events 4768 (TGT) + 4769 (ST) mit Ticket-EncryptionType 0x17 (RC4) / 0x18 (DES)
            try {
                $cim = New-CimSession -ComputerName $dc.HostName -OperationTimeoutSec 10 -ErrorAction Stop
                $filter = @"
SELECT * FROM Win32_NTLogEvent 
WHERE Logfile='Security' 
AND (EventCode=4768 OR EventCode=4769) 
AND TimeGenerated >= '$($since.ToString("yyyyMMddHHmmss.000000+000"))'
"@
                $events = Get-CimInstance -CimSession $cim -Namespace 'root/cimv2' -Query $filter -ErrorAction Stop | Select-Object -First $limit
                Remove-CimSession $cim -ErrorAction SilentlyContinue

                $total = $events.Count
                $rc4Count = 0
                $desCount = 0
                foreach ($e in $events) {
                    $xml = $e.Message
                    # TicketEncryptionType im Message suchen (0x17=RC4, 0x18=DES)
                    if ($xml -match 'TicketEncryptionType.*?(0x17|0x18)') {
                        if ($matches[1] -eq '0x17') { $rc4Count++ } else { $desCount++ }
                    }
                }
                $rc4Pct = if ($total -gt 0) { [math]::Round($rc4Count / $total * 100, 1) } else { 0 }
                $risk = 'OK'
                if ($desCount -gt 0) { $risk = 'CRITICAL' }
                elseif ($rc4Pct -ge 50) { $risk = 'CRITICAL' }
                elseif ($rc4Pct -gt 0) { $risk = 'WARN' }
                $result += [pscustomobject]@{
                    Kind='RC4-Tickets'; DCName=$dcName; Risk=$risk
                    Detail="Security-Log: $total Tickets (RC4: $rc4Count, DES: $desCount) -> RC4-Anteil: $rc4Pct%"
                    RowKey="RC4-Tickets|$dcName"
                }
            } catch {
                $result += [pscustomobject]@{
                    Kind='RC4-Tickets'; DCName=$dcName; Risk='WARN'
                    Detail="Security-Log nicht lesbar: $_"; RowKey="RC4-Tickets|$dcName"
                }
            }
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='RCAudit'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-RCAudit {
    <#
    .SYNOPSIS
        Bewertet RC4/LM-Audit.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $rows = @($data | Where-Object { $_.Kind -in @('Netlogon','NoLMHash','RC4-Tickets') })
    if ($rows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $critical = @($rows | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($rows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($rows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($rows.Count) Belege: OK $($rows.Count - $critical.Count - $warn.Count), WARN $($warn.Count), CRITICAL $($critical.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-SPNInventory {
    <#
    .SYNOPSIS
        Inventarisiert alle SPNs nach Dienstklasse, Objekt, Host; erkennt verwaiste SPNs.
    .NOTES
        - Ergaenzt Check 38 (nur Dubletten)
        - Row-Kinds: Zusammenfassung, Objekt, Klasse, Host, Fehler
        - Schwellwerte: $Global:SPNMaxObjSpns (20), $Global:SPNMaxDnsProbe (200), $Global:SPNInventoryMaxRows (200)
        - Meldet: SPNs auf deaktivierten Konten, unerwartete Klassen auf User-Konten ($Global:SPNUserAccountClassWarn)
        - DNS-Aufloesung fuer SPN-Hostnamen (max $Global:SPNMaxDnsProbe)
    #>
    $result = @()
    try {
        $all = @(Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties 'servicePrincipalName','samAccountName','userAccountControl','objectClass','distinguishedName' -ErrorAction Stop)
        $disabledFlag = 2
        $classWarn = $Global:SPNUserAccountClassWarn
        $maxObj = $Global:SPNMaxObjSpns
        $maxDns = $Global:SPNMaxDnsProbe
        $maxRows = $Global:SPNInventoryMaxRows
        $dnsDone = 0

        $byClass = @{}; $byHost = @{}; $byObj = @{}; $deaktSpns = 0; $unexpClass = @(); $dnsFail = @()
        foreach ($o in $all) {
            $spns = $o.servicePrincipalName
            if (-not $spns) { continue }
            $isDisabled = ($o.userAccountControl -band $disabledFlag)
            $objClass = $o.objectClass
            foreach ($spn in $spns) {
                $class = $spn.Split('/')[0]
                $hostPart = $spn.Split('/')[1]
                $spnHost = $hostPart.Split(':')[0]
                if (-not $byClass.Contains($class)) { $byClass[$class] = 0 }; $byClass[$class]++
                if (-not $byHost.Contains($spnHost)) { $byHost[$spnHost] = 0 }; $byHost[$spnHost]++
                if (-not $byObj.Contains($o.samAccountName)) { $byObj[$o.samAccountName] = @() }; $byObj[$o.samAccountName] += $spn
                if ($isDisabled) { $deaktSpns++ }
                if ($objClass -in $classWarn) { $unexpClass += "$($o.samAccountName) ($objClass): $spn" }
                # DNS-Aufloesung
                if ($dnsDone -lt $maxDns) {
                    try { $ip = [System.Net.Dns]::GetHostAddresses($spnHost); if (-not $ip) { $dnsFail += $spnHost } } catch { $dnsFail += $spnHost }
                    $dnsDone++
                }
            }
        }

        # Zusammenfassung
        $result += [pscustomobject]@{
            Kind='Zusammenfassung'; Target='SPN-Inventar'; Risk=if ($deaktSpns -or $unexpClass.Count -or $dnsFail.Count) { 'WARN' } else { 'OK' }
            Detail="Objekte: $($byObj.Count), SPNs gesamt: $($all | ForEach-Object { ($_.servicePrincipalName).Count } | Measure-Object -Sum).Sum, Klassen: $($byClass.Count), Hosts: $($byHost.Count), DeaktSPNs: $deaktSpns, UnerwKlassen: $($unexpClass.Count), DNS-Fails: $($dnsFail.Count)"
            DeaktKonten=$deaktSpns; RowKey='Zusammenfassung|Bestand'
        }

        # Objekte mit vielen SPNs
        foreach ($obj in $byObj.Keys | Sort-Object { -($byObj[$_].Count) }) {
            $cnt = $byObj[$obj].Count
            if ($cnt -gt $maxObj) {
                $result += [pscustomobject]@{
                    Kind='Objekt'; Target=$obj; Risk='WARN'
                    Detail="$cnt SPNs (Schwellwert $maxObj): $($byObj[$obj] -join ', ')"
                    RowKey="Objekt|$obj"
                }
            }
        }

        # Klassen-Uebersicht
        foreach ($c in $byClass.Keys | Sort-Object) {
            $result += [pscustomobject]@{
                Kind='Klasse'; Target=$c; Risk='OK'
                Detail="$($byClass[$c]) SPNs"; RowKey="Klasse|$c"
            }
        }

        # Host-Uebersicht
        foreach ($h in $byHost.Keys | Sort-Object) {
            $result += [pscustomobject]@{
                Kind='Host'; Target=$h; Risk='OK'
                Detail="$($byHost[$h]) SPNs"; RowKey="Host|$h"
            }
        }

        # Deaktivierte Konten
        if ($deaktSpns -gt 0) {
            $result += [pscustomobject]@{
                Kind='DeaktKonten'; Target='SPNs auf deaktivierten Konten'; Risk='WARN'
                Detail="$deaktSpns SPNs auf deaktivierten Konten"; DeaktKonten=$deaktSpns; RowKey='DeaktKonten|SPNs auf deaktivierten Konten'
            }
        }

        # Unerwartete Klassen
        if ($unexpClass.Count -gt 0) {
            $result += [pscustomobject]@{
                Kind='UnerwarteteKlasse'; Target='Unerwartete SPN-Klassen auf User-Konten'; Risk='WARN'
                Detail=($unexpClass -join '; '); RowKey='UnerwarteteKlasse|User-Konten'
            }
        }

        # DNS-Fails
        if ($dnsFail.Count -gt 0) {
            $result += [pscustomobject]@{
                Kind='DNSFehler'; Target='SPN-Hostnamen ohne DNS-Aufloesung'; Risk='WARN'
                Detail=($dnsFail | Select-Object -Unique -First $maxRows -join ', '); RowKey='DNSFehler|SPN-Hosts'
            }
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='SPN-Inventar'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-SPNInventory {
    <#
    .SYNOPSIS
        Bewertet SPN-Inventar.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $rows = @($data | Where-Object { $_.Kind -ne 'Zusammenfassung' })
    if ($rows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $warn = @($rows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($rows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($rows.Count) SPN-Positionen: OK $($rows.Count - $warn.Count), WARN $($warn.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-EncryptionTypeDistribution {
    <#
    .SYNOPSIS
        Verteilt alle Konten nach EncType-Kombination, prueft AES-Abdeckung, korreliert OS x EncType.
    .NOTES
        - Schwellwert: $Global:EncTypesAesCoverageMin (90%)
        - Row-Kinds: Verteilung, OS, Fazit (Fazit-Row 'AES-Abdeckung'), Fehler
        - Moderne OS-Gruppe ohne AES = CRITICAL
    #>
    $result = @()
    try {
        $accounts = @(Get-ADObject -LDAPFilter '(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties 'msDS-SupportedEncryptionTypes','OperatingSystem','samAccountName','distinguishedName' -ErrorAction Stop)
        $dist = @{}; $osDist = @{}; $total = 0; $aesCount = 0
        $modernOS = @('Windows 10','Windows 11','Windows Server 2016','Windows Server 2019','Windows Server 2022')
        
        foreach ($a in $accounts) {
            $enc = $a.'msDS-SupportedEncryptionTypes'
            if ($null -eq $enc) { $enc = 0 }
            $total++
            $os = $a.OperatingSystem
            if (-not $os) { $os = 'Unbekannt' }
            $label = "0x$([Convert]::ToString($enc,16))"
            if (-not $dist.Contains($label)) { $dist[$label] = 0 }; $dist[$label]++
            if (-not $osDist.Contains($os)) { $osDist[$os] = @{Total=0; AES=0} }
            $osDist[$os].Total++
            $hasAES = ($enc -band 0x18) -ne 0
            if ($hasAES) { $aesCount++; $osDist[$os].AES++ }
        }

        # Verteilung
        foreach ($k in $dist.Keys | Sort-Object) {
            $result += [pscustomobject]@{
                Kind='Verteilung'; Target=$k; Risk='OK'
                Detail="$($dist[$k]) Konten"; RowKey="Verteilung|$k"
            }
        }

        # OS-Korrelation
        foreach ($os in $osDist.Keys | Sort-Object) {
            $d = $osDist[$os]
            $pct = if ($d.Total -gt 0) { [math]::Round($d.AES / $d.Total * 100, 1) } else { 0 }
            $isModern = $modernOS | Where-Object { $os -like "*$_*" }
            $risk = 'OK'
            if ($isModern -and $d.AES -eq 0) { $risk = 'CRITICAL' }
            elseif ($pct -lt $Global:EncTypesAesCoverageMin) { $risk = 'WARN' }
            $result += [pscustomobject]@{
                Kind='OS'; Target=$os; Risk=$risk
                Detail="Total: $($d.Total), AES: $($d.AES) ($pct%)"
                RowKey="OS|$os"
            }
        }

        # Fazit: AES-Abdeckung
        $covPct = if ($total -gt 0) { [math]::Round($aesCount / $total * 100, 1) } else { 0 }
        $fazitRisk = if ($covPct -lt $Global:EncTypesAesCoverageMin) { 'CRITICAL' } else { 'OK' }
        $result += [pscustomobject]@{
            Kind='Fazit'; Target='AES-Abdeckung'; Risk=$fazitRisk
            Detail="AES-Abdeckung: $covPct% ($aesCount / $total) – Schwelle: $Global:EncTypesAesCoverageMin%"
            RowKey='Fazit|AES-Abdeckung'
        }

        # Moderne OS ohne AES als separater Befund
        foreach ($os in $osDist.Keys) {
            if ($modernOS | Where-Object { $os -like "*$_*" }) {
                $d = $osDist[$os]
                if ($d.AES -eq 0 -and $d.Total -gt 0) {
                    $result += [pscustomobject]@{
                        Kind='Fazit'; Target="Moderne OS ohne AES: $os"; Risk='CRITICAL'
                        Detail="OS $os hat $($d.Total) Konto(s), keines mit AES"
                        RowKey="Fazit|ModerneOS|$os"
                    }
                }
            }
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='EncTypes'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-EncryptionTypes {
    <#
    .SYNOPSIS
        Bewertet Encryption-Type-Verteilung.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $rows = @($data | Where-Object { $_.Kind -ne 'Verteilung' })
    if ($rows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $critical = @($rows | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($rows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($rows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($rows.Count) EncType-Positionen: OK $($rows.Count - $critical.Count - $warn.Count), WARN $($warn.Count), CRITICAL $($critical.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}
    
function Get-ConditionalForwarding {
    <#
    .SYNOPSIS
        Globale DNS-Forwarder und Conditional Forwarder, ueber alle DNS-Server aggregiert.
    .NOTES
        NICHT dupliziert:
          Check 3 -> dcdiag /test:DnsForwarders meldet nur "forwarder nicht erreichbar" je DC;
                        kein Inventar und keinen Abgleich zwischen den Servern
          Check 6 -> Zonen (ZoneType, IsDsIntegrated, DynamicUpdate) via Get-DnsServerZone
          Check 42 -> Scavenging, Aging, Reverse-Lookup-Zonen
          Check 60 -> SOA-Werte, ReplicationScope, Zonenkonsistenz
        Neu hier:
          - Conditional Forwarder: Ziel-IPs und auf welchen DNS-Servern sie hinterlegt sind
          - Registry-basierte CF, die nur auf einem Teil der DNS-Server liegen
          - CF ohne Ziel-IP sowie Ziele, die auf eigene DNS-Server zeigen (Weiterleitungsschleife)
          - Globale Forwarder zwischen den DNS-Servern ungleich
          - Kein globaler Forwarder UND keine Root-Hints -> externe Aufloesung tot
        Bewusst NICHT: Erreichbarkeit der Forwarder-IPs - das leistet dcdiag /test:DnsForwarders.
    #>
    $result = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Where-Object { $_.IPv4Address })
        if ($dcs.Count -eq 0) { return @([pscustomobject]@{ Kind='Fehler'; Target='Forwarder'; Detail='Keine erreichbaren DCs'; Risk='WARN' }) }

        $allGlobalForwarders = @{}
        $allCondForwarders = @{}
        $allRootHints = @{}
        $dnsServers = @()

        foreach ($dc in $dcs) {
            $name = $dc.HostName
            $dnsServers += $name
            $gf = @(); $cf = @(); $rh = @()

            foreach ($t in (Get-DnsServerTargets -ComputerName $dc)) {
                # Globale Forwarder
                try { $gf = @(Get-DnsServerForwarder @t -ErrorAction Stop) } catch {}
                # Conditional Forwarder
                try { $cf = @(Get-DnsServerConditionalForwarderZone @t -ErrorAction Stop) } catch {}
                # Root Hints
                try { $rh = @(Get-DnsServerRootHint @t -ErrorAction Stop) } catch {}
            }

            # Globale Forwarder aggregieren
            $ips = @($gf | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
            $key = $ips -join ','
            if (-not $allGlobalForwarders.ContainsKey($key)) { $allGlobalForwarders[$key] = @{ IPs=$ips; Servers=@() } }
            $allGlobalForwarders[$key].Servers += $name

            # Conditional Forwarder aggregieren
            foreach ($z in $cf) {
                $name = $z.ZoneName
                $master = @($z.MasterServers | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
                $mkey = $master -join ','
                if (-not $allCondForwarders.ContainsKey($name)) { $allCondForwarders[$name] = @{} }
                if (-not $allCondForwarders[$name].ContainsKey($mkey)) { $allCondForwarders[$name][$mkey] = @{ Masters=$master; Servers=@() } }
                $allCondForwarders[$name][$mkey].Servers += $name
            }

            # Root Hints aggregieren
            $rhIPs = @($rh | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
            $rhKey = $rhIPs -join ','
            if (-not $allRootHints.ContainsKey($rhKey)) { $allRootHints[$rhKey] = @{ IPs=$rhIPs; Servers=@() } }
            $allRootHints[$rhKey].Servers += $name
        }

        # 1) Globale Forwarder - Konsistenz pruefen
        if ($allGlobalForwarders.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Globaler Forwarder'; Risk='CRITICAL'
                Detail='Kein globaler Forwarder auf keinem DNS-Server konfiguriert'; RowKey='Forwarder|Global'
            }
        }
        elseif ($allGlobalForwarders.Count -gt 1) {
            $details = @()
            foreach ($k in $allGlobalForwarders.Keys) {
                $v = $allGlobalForwarders[$k]
                $details += "IPs: $($v.IPs -join ', ') auf $($v.Servers.Count) Server ($($v.Servers -join ', '))"
            }
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Globaler Forwarder'; Risk='WARN'
                Detail="Inkonsistente globale Forwarder: $($details -join ' | ')"; RowKey='Forwarder|Global'
            }
        }
        else {
            $v = $allGlobalForwarders.Values[0]
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Globaler Forwarder'; Risk='OK'
                Detail="Globale Forwarder konsistent: $($v.IPs -join ', ') auf allen $($v.Servers.Count) DNS-Servern"; RowKey='Forwarder|Global'
            }
        }

        # 2) Conditional Forwarder
        foreach ($zone in ($allCondForwarders.Keys | Sort-Object)) {
            $entries = $allCondForwarders[$zone]
            if ($entries.Count -gt 1) {
                $details = @()
                foreach ($mkey in $entries.Keys) {
                    $v = $entries[$mkey]
                    $details += "Master: $($v.Masters -join ', ') auf $($v.Servers.Count) Server ($($v.Servers -join ', '))"
                }
                $result += [pscustomobject]@{
                    Kind='ConditionalForwarder'; Target=$zone; Risk='WARN'
                    Detail="Nur teilweise verteilt: $($details -join ' | ')"; RowKey="ConditionalForwarder|$zone"
                }
            }
            else {
                $mkey = $entries.Keys[0]
                $v = $entries[$mkey]
                $risk = 'OK'; $issues = @()
                if ($v.Masters.Count -eq 0) { $issues += 'Kein MasterServer hinterlegt - Conditional Forwarder kann keine Aufloesung leisten'; $risk = 'CRITICAL' }
                foreach ($m in $v.Masters) {
                    if ($dnsServers -contains $m) { $issues += "Forwarder-Ziel $m ist ein eigener DNS-Server"; $risk = 'WARN' }
                }
                $result += [pscustomobject]@{
                    Kind='ConditionalForwarder'; Target=$zone; Risk=$risk
                    Detail="Ziel-IPs: $($v.Masters -join ', ') auf $($v.Servers.Count) Server ($($v.Servers -join ', ')) $(if ($issues.Count) { '| ' + ($issues -join '; ') })"
                    RowKey="ConditionalForwarder|$zone"
                }
            }
        }

        # 3) Root Hints
        if ($allRootHints.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Root Hints'; Risk='WARN'
                Detail='Keine Root Hints auf keinem DNS-Server'; RowKey='Forwarder|RootHints'
            }
        }
        elseif ($allRootHints.Count -gt 1) {
            $details = @()
            foreach ($k in $allRootHints.Keys) {
                $v = $allRootHints[$k]
                $details += "IPs: $($v.IPs -join ', ') auf $($v.Servers.Count) Server"
            }
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Root Hints'; Risk='WARN'
                Detail="Inkonsistente Root Hints: $($details -join ' | ')"; RowKey='Forwarder|RootHints'
            }
        }
        else {
            $v = $allRootHints.Values[0]
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Root Hints'; Risk='OK'
                Detail="Root Hints konsistent: $($v.IPs.Count) IPs auf allen $($v.Servers.Count) DNS-Servern"; RowKey='Forwarder|RootHints'
            }
        }

        # 4) Externe Aufloesung moeglich?
        $hasGlobal = $allGlobalForwarders.Count -gt 0
        $hasRootHints = $allRootHints.Count -gt 0
        if (-not $hasGlobal -and -not $hasRootHints) {
            $result += [pscustomobject]@{
                Kind='Forwarder'; Target='Externe Aufloesung'; Risk='CRITICAL'
                Detail='Kein globaler Forwarder UND keine Root-Hints -> externe Aufloesung moeglicherweise nicht moeglich'; RowKey='Forwarder|ExternalResolution'
            }
        }

    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='Forwarder'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-ConditionalForwarders {
    <#
    .SYNOPSIS
        Bewertet Conditional Forwarder, globale Forwarder und Root Hints.
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $rows = @($data | Where-Object { $_.Kind -in @('Forwarder','ConditionalForwarder') })
    if ($rows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Forwarder-Daten' }
    $critical = @($rows | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($rows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($rows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = "$($rows.Count) Forwarder-Positionen: OK $($rows.Count - $critical.Count - $warn.Count), WARN $($warn.Count), CRITICAL $($critical.Count)"
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-DNSZoneConfiguration {
    <#
    .SYNOPSIS
        DNS-Zonen: SOA-Refresh/-Expire, ReplicationScope, DynamicUpdate, Seriennummern-Konsistenz.
    .NOTES
        - Forest-weiter Check (Check 60)
        - Nutzt $Global:DNSZoneRefreshMaxHours (24), $Global:DNSZoneExpireMinDays (7)
        - Prueft: ReplicationScope='Server', DynamicUpdate='None' auf AD-Zonen, abweichende SOA-Serien/Scopes
        - Nutzt Get-DnsServerTargets fuer lokale/remote Abfragen
        - ConvertFrom-SOAInterval wertet [timespan] und Sekunden korrekt aus
    #>
    $result = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Where-Object { $_.IPv4Address })
        if ($dcs.Count -eq 0) { return @([pscustomobject]@{ Kind='Fehler'; Target='DNS-Zonen'; Detail='Keine erreichbaren DCs'; Risk='WARN' }) }

        $byZone = @{}; $qErr = @{}
        foreach ($dc in $dcs) {
            $allZones = @()
            foreach ($t in (Get-DnsServerTargets -ComputerName $dc)) {
                try { $allZones = @(Get-DnsServerZone @t -ErrorAction Stop); break } catch {}
            }
            if ($allZones.Count -eq 0) { $qErr += "${dc}: keine Zonen"; continue }

            foreach ($z in $allZones) {
                $n = [string]$z.ZoneName
                if (-not $n) { continue }
                if ($n -in $Global:DNSDefaultReverseZones) { continue }
                if ($z.ZoneType -eq 'Forwarder') { continue }
                if (-not $byZone.Contains($n)) {
                    $byZone[$n] = [pscustomobject]@{
                        Name=$n; Dc=0; Scope=@(); Updates=@(); Ds=@(); Type=@()
                        Serials=@(); Refresh=@(); Expire=@(); SoaErr=0; SoaDcs=@(); NoSoaInt=0
                    }
                }
                $b = $byZone[$n]
                $b.Dc++
                $sc = [string]$z.ReplicationScope; if (-not $sc) { $sc = '-' }
                $up = [string]$z.DynamicUpdate;   if (-not $up) { $up = '-' }
                $ds = [string]$z.IsDsIntegrated;  if (-not $ds) { $ds = '-' }
                $ty = [string]$z.ZoneType;        if (-not $ty) { $ty = '-' }
                if ($b.Scope   -notcontains $sc) { $b.Scope   = @($b.Scope)   + $sc }
                if ($b.Updates -notcontains $up) { $b.Updates = @($b.Updates) + $up }
                if ($b.Ds      -notcontains $ds) { $b.Ds      = @($b.Ds)      + $ds }
                if ($b.Type    -notcontains $ty) { $b.Type    = @($b.Type)    + $ty }

                # SOA abfragen
                try {
                    $soaRec = $null
                    foreach ($t in (Get-DnsServerTargets -ComputerName $dc)) {
                        try { $soaRec = @(Get-DnsServerResourceRecord @t -ZoneName $n -RRType SOA -ErrorAction Stop) | Select-Object -First 1; break } catch {}
                    }
                    if (-not $soaRec) { throw 'keine SOA-Ressource' }
                    $rd = $soaRec.RecordData
                    if ($null -eq $rd) { throw 'keine SOA-Ressource' }
                    $ser  = [int]$rd.SerialNumber
                    $refH = ConvertFrom-SOAInterval -Value $rd.RefreshInterval -Unit Hours
                    $expD = ConvertFrom-SOAInterval -Value $rd.ExpireInterval  -Unit Days
                    if ($b.Serials -notcontains $ser)  { $b.Serials = @($b.Serials) + $ser }
                    if ($null -ne $refH -and $b.Refresh -notcontains $refH) { $b.Refresh = @($b.Refresh) + $refH }
                    if ($null -ne $expD -and $b.Expire  -notcontains $expD) { $b.Expire  = @($b.Expire)  + $expD }
                    if ($null -eq $refH -and $null -eq $expD) { $b.NoSoaInt++ }
                } catch { $b.SoaErr++; if ($b.SoaDcs -notcontains $dc) { $b.SoaDcs = @($b.SoaDcs) + $dc } }
            }
        }

        if ($byZone.Count -eq 0) {
            $why = if ($qErr.Count) { 'kein DC mit auswertbaren DNS-Zonen (DNS-Abfrage fehlgeschlagen: ' + ($qErr -join ', ') + ')' } else { 'keine DNS-Zonen gefunden' }
            return @([pscustomobject]@{
                Kind='Fehler'; Name='Abfrage'; ZoneTyp='-'; Replikation='-'; Updates='-'; Serien='-'; Refresh='-'; Expire='-'
                Detail='Abfrage der DNS-Zonen fehlgeschlagen: ' + $why; Risk='WARN'
            })
        }

        $nTotal=0; $okN=0; $badN=0; $flagSrv=0; $flagRef=0; $flagExp=0; $flagMix=0
        foreach ($k in ($byZone.Keys | Sort-Object)) {
            $b = $byZone[$k]
            $nTotal++
            $scopeList = ($b.Scope   | Sort-Object) -join ', '
            $updList   = ($b.Updates | Sort-Object) -join ', '
            $typeList  = ($b.Type    | Sort-Object) -join ', '
            $serList   = ($b.Serials | Sort-Object) -join ' / '

            $issues = @(); $risk = 'OK'; $mix = $false
            $isAd = ($b.Ds -contains 'True')

            if ($b.Scope -contains 'Server') {
                $issues += "ReplicationScope='Server' - Zone nur auf einem Server, nicht repliziert"
                $risk = 'CRITICAL'; $flagSrv++
            } elseif ($b.Scope.Count -gt 1) {
                $issues += "ReplicationScope variiert zwischen DCs ($scopeList)"
                $risk = 'WARN'; $mix = $true
            }

            if ($isAd -and $b.Updates -contains 'None' -and -not ($Global:DNSSystemZones -contains $b.Name)) {
                $issues += "DynamicUpdate='None' auf AD-Zone - Eintraege werden nicht dynamisch registriert"
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }
            }

            if ($b.Serials.Count -gt 1) {
                $issues += "SOA-Seriennummer variiert zwischen DCs ($serList) - Zonenstand nicht ueberall identisch"
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }; $mix = $true
            }

            $maxRef = if ($b.Refresh.Count) { ($b.Refresh | Measure-Object -Maximum).Maximum } else { $null }
            if ($null -ne $maxRef -and [double]$maxRef -gt [double]$Global:DNSZoneRefreshMaxHours) {
                $issues += "SOA-Refresh $maxRef h ueberschreitet die Schwelle"
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }; $flagRef++
            }
            $minExp = if ($b.Expire.Count) { ($b.Expire | Measure-Object -Minimum).Minimum } else { $null }
            if ($null -ne $minExp -and [double]$minExp -lt [double]$Global:DNSZoneExpireMinDays) {
                $issues += "SOA-Expire $minExp Tage unterschreitet die Schwelle"
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }; $flagExp++
            }

            if ($b.SoaErr -gt 0 -and $b.SoaErr -ge $b.Dc) {
                $issues += 'SOA-Abfrage fehlgeschlagen auf ' + ($b.SoaDcs -join ', ')
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }
            }
            elseif ($b.NoSoaInt -gt 0 -and $b.NoSoaInt -ge $b.Dc) {
                $issues += 'SOA-Intervalle (Refresh/Expire) nicht auslesbar - Schwellen koennen nicht geprueft werden'
                if ($risk -ne 'CRITICAL') { $risk = 'WARN' }
            }

            if ($mix) { $flagMix++ }
            if ($issues.Count -eq 0) { $okN++ } else { $badN++ }

            $result += [pscustomobject]@{
                Kind='Zone'; Name=$b.Name
                ZoneTyp=$typeList; Replikation=$scopeList; Updates=$updList; Serien=$serList
                Refresh=$(if ($null -ne $maxRef) { "$maxRef h" } else { '-' })
                Expire=$(if ($null -ne $minExp) { "$minExp d" } else { '-' })
                Detail=($issues -join ' | '); Risk=$risk
                RowKey="Zone|$k"
            }
        }

        $sum = "Zusammenfassung: $nTotal Zone(n) ausgewertet (DCs: $($dcs.Count)): unauffaellig $okN, auffaellig $badN | SOA ueber der Refresh-Schwelle: $flagRef, SOA unter der Expire-Schwelle: $flagExp, nicht repliziert: $flagSrv, inkonsistent: $flagMix"
        $sumRisk = if ($flagSrv -or $flagRef -or $flagExp) { 'CRITICAL' } elseif ($badN) { 'WARN' } else { 'OK' }
        $result += [pscustomobject]@{
            Kind='Zusammenfassung'; Name='Bestand'
            ZoneTyp='-'; Replikation='-'; Updates='-'; Serien='-'; Refresh='-'; Expire='-'
            Detail=$sum; Risk=$sumRisk
            RowKey='Zusammenfassung|Bestand'
        }
    } catch {
        $result += [pscustomobject]@{ Kind='Fehler'; Target='DNS-Zonen'; Detail="Abfrage fehlgeschlagen: $_"; Risk='WARN' }
    }
    return $result
}

function Test-Check-ZonenSOA {
    <#
    .SYNOPSIS
        Bewertet DNS-Zonen (SOA & Replikation).
    #>
    param($data)
    if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $zoneRows = @($data | Where-Object { $_.Kind -eq 'Zone' })
    if ($zoneRows.Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $sumRow = @($data | Where-Object { $_.Kind -eq 'Zusammenfassung' })
    $critical = @($zoneRows | Where-Object { $_.Risk -eq 'CRITICAL' })
    $warn = @($zoneRows | Where-Object { $_.Risk -eq 'WARN' })
    $findings = @($zoneRows | Where-Object { $_.Risk -ne 'OK' } | ForEach-Object { $_.Detail })
    $status = if ($critical.Count) { 'CRITICAL' } elseif ($warn.Count) { 'WARN' } else { 'OK' }
    $summary = if ($sumRow) { $sumRow[0].Detail } else { "$($zoneRows.Count) Zonen: OK $($zoneRows.Count - $critical.Count - $warn.Count), WARN $($warn.Count), CRITICAL $($critical.Count)" }
    New-Assessment -OverallStatus $status -Summary $summary -Findings $findings
}

function Get-LAPSConfiguration {
    <#
    .SYNOPSIS
        Prueft LAPS-Aktivierung im Forest und zeigt Computer ohne LAPS-Konfiguration.
        Kennzeichnet Server 2016 und aelter als nicht unterstuetzt.
    #>
    $result = @()
    try {
        # Prüfung: LAPS im Forest aktiviert? (Schema-Erweiterung vorhanden)
        $forest = Get-ADForest -ErrorAction Stop
        
        
        # LAPS wird über ms-mcs-admpwd Attribut konfiguriert
        # Prüfe, ob LAPS-Objekt im Konfigurationsbereich existiert
        $lapsConfPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$($forest.RootDomain.Replace('.',',DC='))"
        $lapsExists = $false
        try {
            $null = Get-ADObject -Identity $lapsConfPath -ErrorAction Stop
            $lapsExists = $true
        } catch {}
        
        
        $result += [pscustomobject]@{
            Type='Forest-Config'; Target='LAPS Schema-Extension'; LAPSEnabled=$lapsExists; ComputerCount=0; ConfiguredCount=0
            UnconfiguredCount=0; ConfiguredPercent=0; OSUnsupported=0; Issue=if (-not $lapsExists) { 'LAPS Schema-Erweiterung nicht installiert' } else { 'OK' }
        }
        
        # Wenn LAPS aktiviert, zähle konfigurierte vs. unkonfigurierte Computer
        if ($lapsExists) {
            try {
                $allComps = @(Get-ADComputer -Filter * -Properties 'ms-mcs-admpwdexpirationtime','OperatingSystem' -ErrorAction Stop)
                $configuredComps = @($allComps | Where-Object { $_.PSObject.Properties['ms-mcs-admpwdexpirationtime'].Value })
                
                # Zaehle Computer mit nicht unterstütztem OS (2016 oder aelter)
                $osUnsupported = @($allComps | Where-Object { 
                    $os = $_.OperatingSystem
                    $os -match '2012|2008|2003' -or ($os -match '2016' -and $os -notmatch '2019|2022')
                })
                
                $result += [pscustomobject]@{
                    Type='Summary'; Target='Computer mit LAPS'; LAPSEnabled=$lapsExists; ComputerCount=$allComps.Count; ConfiguredCount=$configuredComps.Count
                    UnconfiguredCount=($allComps.Count - $configuredComps.Count); ConfiguredPercent=if ($allComps.Count -gt 0) { [math]::Round(($configuredComps.Count / $allComps.Count) * 100, 2) } else { 0 }
                    OSUnsupported=$osUnsupported.Count
                    Issue=if ($allComps.Count -eq 0) { 'Keine Computer gefunden' } elseif ($configuredComps.Count -eq 0) { "WARNUNG: Kein Computer mit LAPS konfiguriert!" } else { "OK: $($configuredComps.Count)/$($allComps.Count) mit LAPS | $($osUnsupported.Count) mit nicht-unterstütztem OS (2016 oder älter)" }
                }
                
                # Liste der unkonfigurierten Computer (nur Top 50 zum Log)
                $unconfigured = @($allComps | Where-Object { -not $_.PSObject.Properties['ms-mcs-admpwdexpirationtime'].Value }) | Select-Object -First 50
                foreach ($comp in $unconfigured) {
                    $osCheck = if ($comp.OperatingSystem -match '2012|2008|2003' -or ($comp.OperatingSystem -match '2016' -and $comp.OperatingSystem -notmatch '2019|2022')) {
                        " | OS NICHT UNTERSTUETZT (LAPS ab 2019)"
                    } else { '' }
                    $result += [pscustomobject]@{
                        Type='Computer'; Target=$comp.Name; LAPSEnabled=$false; ComputerCount=1; ConfiguredCount=0
                        UnconfiguredCount=1; ConfiguredPercent=0; OSUnsupported=0
                        Issue="Nicht konfiguriert - OS: $($comp.OperatingSystem)$osCheck"
                    }
                }
                
                # Auch konfigurierte Computer mit älterem OS zeigen (Problem: läuft dort nicht)
                $configuredWithOldOS = @($configuredComps | Where-Object {
                    $os = $_.OperatingSystem
                    $os -match '2012|2008|2003' -or ($os -match '2016' -and $os -notmatch '2019|2022')
                }) | Select-Object -First 20
                foreach ($comp in $configuredWithOldOS) {
                    $result += [pscustomobject]@{
                        Type='Computer'; Target=$comp.Name; LAPSEnabled=$true; ComputerCount=1; ConfiguredCount=1
                        UnconfiguredCount=0; ConfiguredPercent=100; OSUnsupported=1
                        Issue="KRITISCH: LAPS konfiguriert aber OS nicht unterstuetzt (OS: $($comp.OperatingSystem) - LAPS benoetigt 2019+)"
                    }
                }
            } catch {
                Write-Log "LAPS Computer-Abfrage: $_" -Level WARN -NoConsole
            }
        }
    } catch {
        Write-Log "LAPSConfiguration: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Type='Error'; Target='LAPS-Abfrage'; LAPSEnabled=$null; ComputerCount=0; ConfiguredCount=0
            UnconfiguredCount=0; ConfiguredPercent=0; OSUnsupported=0; Issue="Fehler: $_"
        }
    }
    return $result
}

function Get-AccountsWithoutAES {
    <#
    .SYNOPSIS
        Findet User und Computer, die mit RC4 (unsicher) verschluesselt sind ODER explizit NICHT auf AES konfiguriert.
        Achte: Leere msds-SupportedEncryptionTypes = Default (meist OK). Problem: RC4 aktiviert OHNE AES!
    #>
    $result = @()
    try {
        # Encryption Type Flags (msDS-SupportedEncryptionTypes Bitmaske):
        #   0x01 DES-CBC-CRC | 0x02 DES-CBC-MD5 | 0x04 RC4-HMAC | 0x08 AES128 | 0x10 AES256
        $aesFlags = 0x18      # AES128 (0x08) | AES256 (0x10)
        $rc4Flag  = 0x04      # RC4-HMAC (unsicher)
        $desFlag  = 0x03      # DES-CBC-CRC | DES-CBC-MD5 (sehr unsicher)
        
        # Suche User mit explizit gesetzten Encryption Types (nicht null/leer)
        try {
            $users = @(Get-ADUser -Filter { msds-SupportedEncryptionTypes -like "*" } `
                     -Properties msds-SupportedEncryptionTypes, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue)
            
            foreach ($u in $users) {
                $encTypes = $u.'msds-SupportedEncryptionTypes'
                if (-not $encTypes) { continue }  # Skip wenn null/leer trotz Filter
                
                $encValue = [int]$encTypes
                $hasAES = (($encValue -band $aesFlags) -ne 0)
                $hasRC4 = (($encValue -band $rc4Flag) -ne 0)
                $hasDES = (($encValue -band $desFlag) -ne 0)
                
                # KRITISCH: RC4 oder DES ohne AES
                if ((-not $hasAES) -and ($hasRC4 -or $hasDES)) {
                    $result += [pscustomobject]@{
                        Type='User'; ObjectName=$u.SamAccountName; Enabled=$u.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$u.LastLogonDate; PasswordLastSet=$u.PasswordLastSet
                        Risk='CRITICAL'
                        Issue="KRITISCH: User mit RC4/DES OHNE AES! EncryptionTypes=0x$([Convert]::ToString($encValue,16))"
                    }
                }
                # WARNUNG: Explizit AES disabled
                elseif ((-not $hasAES) -and ($encValue -ne 0)) {
                    $result += [pscustomobject]@{
                        Type='User'; ObjectName=$u.SamAccountName; Enabled=$u.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$u.LastLogonDate; PasswordLastSet=$u.PasswordLastSet
                        Risk='HIGH'
                        Issue="User ohne AES konfiguriert (EncryptionTypes=0x$([Convert]::ToString($encValue,16)))"
                    }
                }
                # WARNUNG: RC4 als Option zusammen mit AES (Legacy-Support)
                elseif ($hasRC4 -and $hasAES) {
                    $result += [pscustomobject]@{
                        Type='User'; ObjectName=$u.SamAccountName; Enabled=$u.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$u.LastLogonDate; PasswordLastSet=$u.PasswordLastSet
                        Risk='MEDIUM'
                        Issue="User mit RC4+AES: Ermoeglicht Downgrade-Angriffe (EncryptionTypes=0x$([Convert]::ToString($encValue,16)))"
                    }
                }
            }
        } catch { Write-Log "AES User-Abfrage: $_" -Level WARN -NoConsole }
        
        # Suche Computer mit explizit gesetzten Encryption Types
        try {
            $comps = @(Get-ADComputer -Filter { msds-SupportedEncryptionTypes -like "*" } `
                     -Properties msds-SupportedEncryptionTypes, LastLogonDate, OperatingSystem -ErrorAction SilentlyContinue)
            
            foreach ($c in $comps) {
                $encTypes = $c.'msds-SupportedEncryptionTypes'
                if (-not $encTypes) { continue }  # Skip wenn null/leer trotz Filter
                
                $encValue = [int]$encTypes
                $hasAES = (($encValue -band $aesFlags) -ne 0)
                $hasRC4 = (($encValue -band $rc4Flag) -ne 0)
                $hasDES = (($encValue -band $desFlag) -ne 0)
                
                # KRITISCH: RC4 oder DES ohne AES
                if ((-not $hasAES) -and ($hasRC4 -or $hasDES)) {
                    $result += [pscustomobject]@{
                        Type='Computer'; ObjectName=$c.Name; Enabled=$c.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$c.LastLogonDate; OperatingSystem=$c.OperatingSystem
                        Risk='CRITICAL'
                        Issue="KRITISCH: Computer mit RC4/DES OHNE AES! EncryptionTypes=0x$([Convert]::ToString($encValue,16))"
                    }
                }
                # WARNUNG: Explizit AES disabled
                elseif ((-not $hasAES) -and ($encValue -ne 0)) {
                    $result += [pscustomobject]@{
                        Type='Computer'; ObjectName=$c.Name; Enabled=$c.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$c.LastLogonDate; OperatingSystem=$c.OperatingSystem
                        Risk='HIGH'
                        Issue="Computer ohne AES konfiguriert (EncryptionTypes=0x$([Convert]::ToString($encValue,16)))"
                    }
                }
                # WARNUNG: RC4 als Option zusammen mit AES
                elseif ($hasRC4 -and $hasAES) {
                    $result += [pscustomobject]@{
                        Type='Computer'; ObjectName=$c.Name; Enabled=$c.Enabled
                        EncryptionTypes=$encTypes; HasAES=$hasAES; HasRC4=$hasRC4; HasDES=$hasDES
                        LastLogon=$c.LastLogonDate; OperatingSystem=$c.OperatingSystem
                        Risk='MEDIUM'
                        Issue="Computer mit RC4+AES: Ermoeglicht Downgrade-Angriffe (EncryptionTypes=0x$([Convert]::ToString($encValue,16)))"
                    }
                }
            }
        } catch { Write-Log "AES Computer-Abfrage: $_" -Level WARN -NoConsole }
        
        # Summary bei keine Probleme gefunden
        if ($result.Count -eq 0) {
            $result += [pscustomobject]@{
                Type='Summary'; ObjectName='(alle Konten)'; Enabled=$true
                EncryptionTypes='OK'; HasAES=$true; HasRC4=$false; HasDES=$false
                LastLogon=$null; OperatingSystem=$null
                Risk='OK'
                Issue='Alle Konten: Standard-Verschluesselung (AES) aktiv, keine RC4-Only Konfiguration'
            }
        }
    } catch {
        Write-Log "AccountsWithoutAES: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Type='Error'; ObjectName='(Fehler)'; Enabled=$null
            EncryptionTypes=$null; HasAES=$null; HasRC4=$null; HasDES=$null
            LastLogon=$null; OperatingSystem=$null; Risk='UNKNOWN'
            Issue="Abfrage fehlgeschlagen: $_"
        }
    }
    return $result
}

function Get-RCAESMigration {
    <#
    .SYNOPSIS
        RC4 -> AES Migrations-Audit (CVE-2026-20833): Microsoft schaltet RC4 im
        Kerberos ab 2026 ab (Juli-Updates). Zeigt Konten ohne AES-Unterstuetzung
        (= koennten nach der Abschaltung nicht mehr authentifizieren) und die
        KDC-Registry der DCs.
    #>
    $result = @()
    $aesBits = 0x18   # AES128 (0x08) | AES256 (0x10)
    $rc4Bit  = 0x04   # RC4-HMAC
    $desBits = 0x03   # DES-CBC-CRC (0x01) | DES-CBC-MD5 (0x02)

    function ConvertTo-EtypeName {
        param([int]$Enc)
        if ($Enc -eq 0) { return 'nicht gesetzt' }
        $p = @()
        if ($Enc -band 0x01) { $p += 'DES-CBC-CRC' }
        if ($Enc -band 0x02) { $p += 'DES-CBC-MD5' }
        if ($Enc -band 0x04) { $p += 'RC4' }
        if ($Enc -band 0x08) { $p += 'AES128' }
        if ($Enc -band 0x10) { $p += 'AES256' }
        if ($Enc -band 0x20) { $p += 'CompoundId' }
        if ($Enc -band 0x40) { $p += 'Claims' }
        if ($p.Count -eq 0) { return "unbekannteBits(0x$($Enc.ToString('X')))" }
        return ($p -join '+')
    }

    $userTotal=0; $unsetUsers=0; $aesUsers=0; $problemUsers=0
    $compTotal=0; $unsetComps=0; $aesComps=0; $problemComps=0

    # --- User ---
    try {
        $users = @(Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes, AdminCount, Enabled, ServicePrincipalName -ErrorAction Stop)
        foreach ($u in $users) {
            $userTotal++
            $enc = 0
            try { if ($null -ne $u.'msDS-SupportedEncryptionTypes') { $enc = [int]$u.'msDS-SupportedEncryptionTypes' } } catch {}
            $hasAES = (($enc -band $aesBits) -ne 0)
            $hasRC4 = (($enc -band $rc4Bit)  -ne 0)
            $hasDES = (($enc -band $desBits) -ne 0)
            $isPriv = ($u.AdminCount -eq 1)
            $hasSpn = (@($u.ServicePrincipalName).Count -gt 0)
            $objType = if ($hasSpn) { 'Dienst (SPN)' } else { 'User' }
            if ($enc -eq 0 -or (-not $hasAES -and -not $hasRC4 -and -not $hasDES)) {
                $unsetUsers++
                if ($hasSpn) {
                    # SPN-Konto ohne AES-Attribute: KDC stellt derzeit RC4-TGS aus -> bricht nach RC4-Ende
                    $problemUsers++
                    $result += [pscustomobject]@{
                        Kind='Konto'; Name=$u.SamAccountName; ObjektTyp=$objType
                        EncryptionTypes='nicht gesetzt'; AES='Nein'; RC4='(KDC-Default)'; DES='Nein'
                        Privilegiert=$(if ($isPriv) { 'Ja' } else { 'Nein' })
                        Aktiv=$(if ($u.Enabled) { 'Ja' } else { 'Nein' })
                        Detail='Dienstkonto (SPN) OHNE msDS-SupportedEncryptionTypes - KDC stellt derzeit RC4-Tickets aus, Ausfall nach RC4-Abschaltung (Juli 2026). AES aktivieren + Passwort/PwdLastSet aktualisieren'
                        Risk=$(if ($isPriv) { 'HIGH' } else { 'MEDIUM' })
                    }
                }
                continue
            }
            if ($hasAES -and -not $hasRC4 -and -not $hasDES) { $aesUsers++; continue }
            # Problemfaellig: RC4/DES gesetzt
            $problemUsers++
            $etype = ConvertTo-EtypeName -Enc $enc
            if ($hasDES) {
                $risk = if ($isPriv) { 'CRITICAL' } else { 'HIGH' }
                $detail = "Konto unterstuetzt DES ($etype) - bricht nach RC4/DES-Abschaltung, AES ist Pflicht"
            } elseif ($hasRC4 -and -not $hasAES) {
                $risk = if ($isPriv) { 'CRITICAL' } else { 'HIGH' }
                $detail = "RC4-only ($etype): KEIN AES - bricht nach RC4-Abschaltung (Juli 2026). Migration: AES aktivieren, Passwort zuruecksetzen"
            } else {
                $risk = 'MEDIUM'
                $detail = "RC4+AES ($etype): ermoeglicht Downgrade auf RC4 - nach AES-Migration RC4-Flag entfernen"
            }
            $result += [pscustomobject]@{
                Kind='Konto'; Name=$u.SamAccountName; ObjektTyp=$objType
                EncryptionTypes=$etype; AES=$(if ($hasAES) { 'Ja' } else { 'Nein' }); RC4=$(if ($hasRC4) { 'Ja' } else { 'Nein' }); DES=$(if ($hasDES) { 'Ja' } else { 'Nein' })
                Privilegiert=$(if ($isPriv) { 'Ja' } else { 'Nein' })
                Aktiv=$(if ($u.Enabled) { 'Ja' } else { 'Nein' })
                Detail=$detail; Risk=$risk
            }
        }
    } catch { Write-Log "RCAESMigration User: $_" -Level WARN -NoConsole }

    # --- Computer ---
    try {
        $comps = @(Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes, AdminCount, Enabled, OperatingSystem -ErrorAction Stop)
        foreach ($c in $comps) {
            $compTotal++
            $enc = 0
            try { if ($null -ne $c.'msDS-SupportedEncryptionTypes') { $enc = [int]$c.'msDS-SupportedEncryptionTypes' } } catch {}
            $hasAES = (($enc -band $aesBits) -ne 0)
            $hasRC4 = (($enc -band $rc4Bit)  -ne 0)
            $hasDES = (($enc -band $desBits) -ne 0)
            $isPriv = ($c.AdminCount -eq 1)
            $oldOS  = ("$($c.OperatingSystem)" -match '2003|2008|2012')
            if ($enc -eq 0 -or (-not $hasAES -and -not $hasRC4 -and -not $hasDES)) {
                $unsetComps++
                if ($oldOS) {
                    # Alter Client ohne AES-Attribute: nutzt vermutlich RC4
                    $problemComps++
                    $result += [pscustomobject]@{
                        Kind='Konto'; Name=$c.Name; ObjektTyp='Computer'
                        EncryptionTypes='nicht gesetzt'; AES='Nein'; RC4='(KDC-Default)'; DES='Nein'
                        Privilegiert=$(if ($isPriv) { 'Ja' } else { 'Nein' })
                        Aktiv=$(if ($c.Enabled) { 'Ja' } else { 'Nein' })
                        Detail="Alter Client ($($c.OperatingSystem)) ohne AES-Attribute - nutzt vermutlich RC4, nach RC4-Abschaltung pruefen/migrieren"
                        Risk='MEDIUM'
                    }
                }
                continue
            }
            if ($hasAES -and -not $hasRC4 -and -not $hasDES) { $aesComps++; continue }
            $problemComps++
            $etype = ConvertTo-EtypeName -Enc $enc
            if ($hasDES) {
                $risk = 'HIGH'
                $detail = "Computer unterstuetzt DES ($etype) - bricht nach RC4/DES-Abschaltung"
            } elseif ($hasRC4 -and -not $hasAES) {
                $risk = 'HIGH'
                $detail = "Computer RC4-only ($etype): KEIN AES - bricht nach RC4-Abschaltung (Juli 2026)"
            } else {
                $risk = 'MEDIUM'
                $detail = "Computer RC4+AES ($etype): Downgrade auf RC4 moeglich"
            }
            $result += [pscustomobject]@{
                Kind='Konto'; Name=$c.Name; ObjektTyp='Computer'
                EncryptionTypes=$etype; AES=$(if ($hasAES) { 'Ja' } else { 'Nein' }); RC4=$(if ($hasRC4) { 'Ja' } else { 'Nein' }); DES=$(if ($hasDES) { 'Ja' } else { 'Nein' })
                Privilegiert=$(if ($isPriv) { 'Ja' } else { 'Nein' })
                Aktiv=$(if ($c.Enabled) { 'Ja' } else { 'Nein' })
                Detail=$detail; Risk=$risk
            }
        }
    } catch { Write-Log "RCAESMigration Computer: $_" -Level WARN -NoConsole }

    # --- KDC-Registry auf DCs (HKLM SupportedEncryptionTypes) ---
    foreach ($dcName in @($Global:DCConnectivity.Keys)) {
        $conn = $Global:DCConnectivity[$dcName]
        if (-not $conn -or -not $conn.Reachable) { continue }
        $sb = {
            try {
                $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -ErrorAction Stop).SupportedEncryptionTypes
                [pscustomobject]@{ Found=$true; Value=[int]$v }
            } catch { [pscustomobject]@{ Found=$false; Value=0 } }
        }
        $reg = Invoke-RemoteCommand -ComputerName $dcName -ScriptBlock $sb
        if (-not $reg) {
            $result += [pscustomobject]@{
                Kind='KDC-Registry'; Name=$dcName; ObjektTyp='KDC'
                EncryptionTypes='(nicht lesbar)'; AES='-'; RC4='-'; DES='-'
                Privilegiert='-'; Aktiv='-'
                Detail="Registry-Wert 'SupportedEncryptionTypes' nicht auslesbar (kein WinRM)"
                Risk='-'
            }
            continue
        }
        if (-not $reg.Found) {
            $result += [pscustomobject]@{
                Kind='KDC-Registry'; Name=$dcName; ObjektTyp='KDC'
                EncryptionTypes='nicht gesetzt'; AES='(Default)'; RC4='(Default)'; DES='(Default)'
                Privilegiert='-'; Aktiv='-'
                Detail='KDC nutzt Windows-Default-Etypes (nach RC4-Abschaltung: AES) - OK'
                Risk='OK'
            }
        } else {
            $enc = [int]$reg.Value
            $hasRC4 = (($enc -band $rc4Bit) -ne 0)
            $etype = ConvertTo-EtypeName -Enc $enc
            $risk = if ($hasRC4) { 'MEDIUM' } else { 'OK' }
            $detail = if ($hasRC4) { "KDC erlaubt explizit RC4 ($etype) - nach Migration auf AES-only (0x18) setzen" } else { "KDC-Registry gesetzt: $etype" }
            $result += [pscustomobject]@{
                Kind='KDC-Registry'; Name=$dcName; ObjektTyp='KDC'
                EncryptionTypes=$etype; AES=$(if ($enc -band $aesBits) { 'Ja' } else { 'Nein' }); RC4=$(if ($hasRC4) { 'Ja' } else { 'Nein' }); DES=$(if ($enc -band $desBits) { 'Ja' } else { 'Nein' })
                Privilegiert='-'; Aktiv='-'
                Detail=$detail; Risk=$risk
            }
        }
    }

    # --- Summary ---
    $result += [pscustomobject]@{
        Kind='Summary'; Name='(Gesamt)'; ObjektTyp='-'
        EncryptionTypes='-'; AES='-'; RC4='-'; DES='-'; Privilegiert='-'; Aktiv='-'
        Detail=("User: {0} geprueft | ohne AES-Attribute: {1} | AES-ready: {2} | problembehaftet: {3} || Computer: {4} geprueft | ohne AES-Attribute: {5} | AES-ready: {6} | problembehaftet: {7} || WICHTIG: RC4 wird 2026 abgeschaltet (CVE-2026-20833) - alle problembehafteten Konten VORHER auf AES migrieren" `
                -f $userTotal, $unsetUsers, $aesUsers, $problemUsers, $compTotal, $unsetComps, $aesComps, $problemComps)
        Risk='OK'
    }
    return $result
}

function Get-DCSyncPermissions {
    <#
    .SYNOPSIS
        Findet Objekte mit Replikations-Rechten (DCSync) auf dem Domain-Naming
        Context. Ausserhalb der Standard-traeger (SYSTEM, Administrators, Domain
        Controllers) erlauben diese Rechte die Extraktion ALLER Passwort-Hashes.
    #>
    $result = @()
    try {
        
        $domainSID = $domain.DomainSID.Value
        $acl = Get-Acl -Path "AD:$($domain.DistinguishedName)" -ErrorAction Stop
        $rightMap = @{
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicate-Changes'
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicate-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'Replicate-Changes-FilteredSet'
        }
        $expectedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', "$domainSID-516")
        $bySid = @{}
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $guid = if ($ace.ObjectType) { $ace.ObjectType.ToString().ToLower() } else { '' }
            if (-not $rightMap.ContainsKey($guid)) { continue }
            $sid = ''
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $sid = "$($ace.IdentityReference)" }
            if (-not $bySid.ContainsKey($sid)) { $bySid[$sid] = @{ Rights = @{}; Name = "$($ace.IdentityReference)" } }
            $bySid[$sid].Rights[$rightMap[$guid]] = $true
        }
        foreach ($sid in ($bySid.Keys | Sort-Object)) {
            $entry = $bySid[$sid]
            $rights = @($entry.Rights.Keys | Sort-Object)
            $hasAll = $entry.Rights.ContainsKey('Replicate-Changes-All')
            $isExpected = ($expectedSids -contains $sid)
            if ($isExpected) {
                $risk = 'OK'
                $detail = 'Standard-Rechteinhaber (DCs/SYSTEM/Administrators) - OK'
            } elseif ($hasAll) {
                $risk = 'CRITICAL'
                $detail = "NICHT-Standard-Principal mit 'DS-Replication-Get-Changes-All' - volle DCSync-Faehigkeit: alle Passwort-Hashes der Domain extrahierbar!"
            } else {
                $risk = 'WARN'
                $detail = "Replikations-Rechte ohne 'Get-Changes-All' - kein Hash-Zugriff, aber Replikation lesbar. Rechtnotwendigkeit pruefen"
            }
            $result += [pscustomobject]@{
                Kind='DCSync-Recht'
                Identity=$entry.Name; SID=$sid
                Rechte=($rights -join '; ')
                HatGetChangesAll=$(if ($hasAll) { 'Ja' } else { 'Nein' })
                IstStandardTraeger=$(if ($isExpected) { 'Ja' } else { 'Nein' })
                Detail=$detail; Risk=$risk
            }
        }
        if ($result.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Summary'; Identity='(keine)'; SID='-'; Rechte='-'
                HatGetChangesAll='Nein'; IstStandardTraeger='Ja'
                Detail='Keine Replikations-Rechte auf dem Domain-NC gefunden' ; Risk='OK'
            }
        }
    } catch {
        Write-Log "DCSyncPermissions: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Kind='Error'; Identity='(Abfrage)'; SID='-'; Rechte='-'
            HatGetChangesAll='-'; IstStandardTraeger='-'
            Detail="ACL-Abfrage fehlgeschlagen: $_"; Risk='-'
        }
    }
    return $result
}

function Get-RBCDDelegation {
    <#
    .SYNOPSIS
        RBCD (resource-based constrained delegation) und Constrained Delegation.
        RBCD-Eintrag = Prinzipal darf auf diesen Computer delegieren (PrivEsc-Pfad).
        Constrained Delegation = Objekt darf auf bestimmte Dienste delegieren.
    #>
    $result = @()
    # --- RBCD ---
    try {
        $comps = @(Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, OperatingSystem -ErrorAction Stop)
        foreach ($c in $comps) {
            $sd = $c.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            if (-not $sd) { continue }
            $rules = @()
            try { $rules = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) } catch {}
            foreach ($rule in $rules) {
                $sid = $rule.IdentityReference.Value
                $name = $sid; $cls = 'unbekannt'
                try { $name = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value } catch {}
                try { $cls = (Get-ADObject -Identity $sid -Properties objectClass -ErrorAction Stop).objectClass } catch {}
                if ($cls -eq 'user') {
                    $risk = 'HIGH'
                    $detail = "USER mit RBCD-Recht auf '$($c.Name)' - kompromittierte User-Credentials erlauben Delegation/PrivEsc auf diesen Computer"
                } else {
                    $risk = 'MEDIUM'
                    $detail = "RBCD-Prinzipal ($cls) darf auf '$($c.Name)' delegieren - uebliche Bastion/Management-Konfiguration, Noetigkeit pruefen"
                }
                $result += [pscustomobject]@{
                    Kind='RBCD'; Name=$c.Name; ObjektTyp='Computer'; OS=$c.OperatingSystem
                    Prinzipal=$name; PrinzipalTyp=$cls; Rechte='msDS-AllowedToActOnBehalfOfOtherIdentity'
                    Protokollwechsel='-'; Detail=$detail; Risk=$risk
                }
            }
        }
    } catch { Write-Log "RBCD: $_" -Level WARN -NoConsole }

    # --- Constrained Delegation ---
    foreach ($kind in 'User','Computer') {
        try {
            if ($kind -eq 'User') {
                $objs = @(Get-ADUser -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -ErrorAction Stop)
            } else {
                $objs = @(Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -ErrorAction Stop)
            }
            foreach ($o in $objs) {
                $targets = (@($o.'msDS-AllowedToDelegateTo') -join '; ')
                $trans = ($o.TrustedToAuthForDelegation -eq $true)
                $risk = if ($kind -eq 'User' -and $trans) { 'HIGH' }
                         elseif ($kind -eq 'User' -or $trans) { 'MEDIUM' }
                         else { 'LOW' }
                $detail = "Constrained Delegation an: $targets | Protokollwechsel (S4U2Self): $(if ($trans) { 'AKTIV' } else { 'Nein' })"
                if ($trans) { $detail += ' - Protokollwechsel ermoeglicht TGT-Erwerb ohne Passwort, Ziel-SPNs pruefen' }
                $result += [pscustomobject]@{
                    Kind='Constrained'; Name=$o.SamAccountName; ObjektTyp=$kind; OS='-'
                    Prinzipal=$targets; PrinzipalTyp='Ziel-SPNs'; Rechte='msDS-AllowedToDelegateTo'
                    Protokollwechsel=$(if ($trans) { 'Ja' } else { 'Nein' }); Detail=$detail; Risk=$risk
                }
            }
        } catch { Write-Log "ConstrainedDelegation $kind : $_" -Level WARN -NoConsole }
    }
    return $result
}

function Get-dMSAObjects {
    <#
    .SYNOPSIS
        BadSuccessor (dMSA): Findet Delegated Managed Service Accounts und prueft,
        ob msDS-DelegatedMSAState=2 (Migration abgeschlossen) gesetzt ist - dann
        werden Kerberos-Tickets des dMSA mit den Rechten des uebernommenen Kontos
        ausgestellt (BadSuccessor-Muster, 2025).
    #>
    $result = @()
    try {
        $schemaNC = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
        $class = Get-ADObject -LDAPFilter '(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)' -SearchBase $schemaNC -SearchScope Subtree -ErrorAction Stop
        if (-not $class) {
            $result += [pscustomobject]@{
                Kind='Schema'; Name='msDS-DelegatedManagedServiceAccount'; State='-'
                UebernommenesKonto='-'; KontoPrivilegiert='-'
                Detail='Schema-Klasse nicht vorhanden (kein Windows Server 2025 Schema) - BadSuccessor nicht anwendbar'
                Risk='OK'
            }
            return $result
        }
        $dmsas = @()
        try {
            $dmsas = @(Get-ADObject -Filter "objectClass -eq 'msDS-DelegatedManagedServiceAccount'" -Properties msDS-DelegatedMSAState, msDS-SupersededServiceAccountState, msDS-ManagedAccountPrecededByLink -ErrorAction Stop)
        } catch {
            try { $dmsas = @(Get-ADObject -Filter "objectClass -eq 'msDS-DelegatedManagedServiceAccount'" -Properties msDS-DelegatedMSAState -ErrorAction Stop) }
            catch { $dmsas = @(Get-ADObject -Filter "objectClass -eq 'msDS-DelegatedManagedServiceAccount'" -ErrorAction Stop) }
        }
        if ($dmsas.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind='Summary'; Name='(keine dMSA)'; State='-'
                UebernommenesKonto='-'; KontoPrivilegiert='-'
                Detail='Schema vorhanden, aber keine dMSA-Objekte gefunden - BadSuccessor-Angriffsvektor derzeit nicht genutzt'
                Risk='OK'
            }
            return $result
        }
        foreach ($o in $dmsas) {
            $state = -1
            try { $state = [int]$o.'msDS-DelegatedMSAState' } catch {}
            $supDn = ''
            try { $supDn = "$($o.'msDS-ManagedAccountPrecededByLink')" } catch {}
            $supName = $supDn; $supPriv = '-'
            if ($supDn) {
                try {
                    $sup = Get-ADUser -Identity $supDn -Properties adminCount -ErrorAction Stop
                    $supName = $sup.SamAccountName
                    $supPriv = if ($sup.adminCount -eq 1) { 'Ja' } else { 'Nein' }
                } catch { $supName = $supDn }
            }
            $stateTxt = switch ($state) {
                2 { '2 (Migration abgeschlossen - Superseding AKTIV)' }
                1 { '1 (Migration angegeben)' }
                0 { '0 (keine Migration)' }
                default { "$state (unbekannt)" }
            }
            if ($state -eq 2) {
                if ($supPriv -eq 'Ja') {
                    $risk = 'CRITICAL'
                    $detail = "BADSUCCESSOR-MUSTER: dMSA uebernimmt PRIVILEGIELIERTES Konto '$supName' (adminCount=1) - Tickets des dMSA gelten mit dessen Rechten! Objekt pruefen und ggf. loeschen"
                } elseif ($supDn) {
                    $risk = 'WARN'
                    $detail = "dMSA uebernimmt Konto '$supName' (Migration abgeschlossen) - legitim nur wenn beabsichtigt, sonst Takeover-Pfad"
                } else {
                    $risk = 'WARN'
                    $detail = 'Superseding AKTIV, aber kein uebernommenes Konto lesbar - Zustand pruefen'
                }
            } else {
                $risk = 'MEDIUM'
                $detail = "dMSA existiert (State=$state) - dMSA-Objekte sind neue Angriffsflaechen: Wer darf sie erstellen/aendern? (Write-Rechte auf Ziel-OU pruefen)"
            }
            $result += [pscustomobject]@{
                Kind='dMSA'; Name=$o.Name; State=$stateTxt
                UebernommenesKonto=$supName; KontoPrivilegiert=$supPriv
                Detail=$detail; Risk=$risk
            }
        }
    } catch {
        Write-Log "dMSA: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Kind='Error'; Name='(Abfrage)'; State='-'
            UebernommenesKonto='-'; KontoPrivilegiert='-'
            Detail="Abfrage fehlgeschlagen: $_"; Risk='-'
        }
    }
    return $result
}

function Get-MachineAccountQuota {
    <#
    .SYNOPSIS
        ms-DS-MachineAccountQuota: Default 10 erlaubt jedem beliebigen Benutzer,
        bis zu 10 Computerkonten zu erstellen (Missbrauch fuer Enrollment-/
        Delegation/ADCS-Angriffe). Best Practice: 0.
    #>
    $result = @()
    try {
        
        $root = Get-ADObject -Identity $domain.DistinguishedName -Properties ms-DS-MachineAccountQuota -ErrorAction Stop
        $q = -1
        try { $q = [int]$root.'ms-DS-MachineAccountQuota' } catch {}
        $note = ''
        if ($q -lt 0) { $q = 10; $note = ' (Wert nicht lesbar - Default 10 angenommen)' }
        if ($q -eq 0) {
            $risk = 'OK'
            $detail = 'MAQ=0 - Benutzer koennen keine Computerkonten erstellen (Best Practice)'
        } else {
            $risk = 'WARN'
            $detail = "MAQ=$q$note - bis zu $q Computerkonten pro Benutzer erstellbar. Angreifer koennen so eigene Computerkonten fuer Enrollment/Delegation/ADCS-Angriffe anlegen. Empfehlung: Set-ADObject `"$($domain.DistinguishedName)`" -Replace @{'ms-DS-MachineAccountQuota'='0'}"
        }
        $result += [pscustomobject]@{
            Einstellung='ms-DS-MachineAccountQuota'; Domain=$domain.DNSRoot; Wert=$q
            Detail=$detail; Risk=$risk
        }
    } catch {
        Write-Log "MachineAccountQuota: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Einstellung='ms-DS-MachineAccountQuota'; Domain='-'; Wert=-1
            Detail="Abfrage fehlgeschlagen: $_"; Risk='-'
        }
    }
    return $result
}

function Get-AnonymousLDAP {
    <#
    .SYNOPSIS
        Anonymer LDAP-Zugriff: Testet per anonymem Bind, ob ohne Anmeldung
        Domain-Informationen lesbar sind, und zeigt die dSHeuristics.
    #>
    $result = @()
    $pdc = $null
    try { $pdc = (Get-ADDomain -ErrorAction Stop).PDCEmulator } catch {}
    if (-not $pdc) { try { $pdc = (Get-ADRootDSE).dnsHostName } catch {} }

    # --- Funktionaler Test: anonymer RootDSE-Bind ---
    $ncExposed = $false
    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$pdc/rootDSE", $null, $null, [System.DirectoryServices.AuthenticationTypes]::Anonymous)
        $nc  = $de.Properties['defaultNamingContext'].Value
        $ncs = @($de.Properties['namingContexts'] | ForEach-Object { $_.Value })
        if ($nc) { $ncExposed = $true }
        if ($ncs.Count -gt 0) { $ncExposed = $true }
        if ($ncExposed) {
            $risk = 'WARN'
            $detail = "Anonym ohne Anmeldung lesbar: defaultNamingContext='$nc' / namingContexts=$($ncs.Count) - AD-Struktur fuer Angreifer ausforschbar"
            $werte = 'NC-Informationen lesbar'
        } else {
            $risk = 'OK'
            $detail = 'Anonyme RootDSE-Abfrage liefert keine NC-Informationen (Windows-Default) - OK'
            $werte = 'nur RootDSE-Basis'
        }
        $result += [pscustomobject]@{ Test='Anonymer LDAP-Bind (funktional)'; Ziel=$pdc; Wert=$werte; Detail=$detail; Risk=$risk }
    } catch {
        $result += [pscustomobject]@{ Test='Anonymer LDAP-Bind (funktional)'; Ziel=$pdc; Wert='abgelehnt'; Detail="Anonymer LDAP-Bind wurde abgelehnt (Default ab Server 2003) - OK"; Risk='OK' }
    }

    # --- dSHeuristics aus Konfigurations-NC ---
    try {
        $confNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $ds = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$confNC" -Properties dSHeuristics -ErrorAction Stop
        $heur = $ds.dSHeuristics
        if ($heur) {
            $result += [pscustomobject]@{ Test='dSHeuristics'; Ziel='Directory Service'; Wert=$heur; Detail="dSHeuristics gesetzt: '$heur' - Heuristiken koennen u.a. anonymen LDAP-Zugriff erweitern (Position 7). Noetigkeit pruefen"; Risk='MEDIUM' }
        } else {
            $result += [pscustomobject]@{ Test='dSHeuristics'; Ziel='Directory Service'; Wert='(nicht gesetzt)'; Detail='dSHeuristics nicht gesetzt (Windows-Default) - OK'; Risk='OK' }
        }
    } catch {
        $result += [pscustomobject]@{ Test='dSHeuristics'; Ziel='Directory Service'; Wert='-'; Detail="Abfrage fehlgeschlagen: $_"; Risk='-' }
    }
    return $result
}

function Get-GPPPasswords {
    <#
    .SYNOPSIS
        Sucht in SYSVOL nach Group Policy Preferences XMLs mit cpassword-Attribut
        (MS14-025): Die AES-Klartextschluessel sind oeffentlich, Passworte sind
        damit fuer jedes domaeneangemeldete Konto entschluesselbar.
    #>
    $result = @()
    try {
        
        $polPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
        if (-not (Test-Path -LiteralPath $polPath)) {
            $result += [pscustomobject]@{ Kind='Error'; Datei='(SYSVOL)'; Benutzer='-'; Detail="SYSVOL-Pfad nicht erreichbar: $polPath"; Risk='-' }
            return $result
        }
        $files = @(Get-ChildItem -LiteralPath $polPath -Recurse -File -Filter '*.xml' -ErrorAction SilentlyContinue)
        $hits = 0; $maxRows = 200
        foreach ($file in $files) {
            $content = $null
            try { $content = [System.IO.File]::ReadAllText($file.FullName) } catch { continue }
            if (-not $content) { continue }
            if ($content -match 'cpassword\s*=\s*"([^"]+)"') {
                $cp = $Matches[1]
                if ([string]::IsNullOrWhiteSpace($cp)) { continue }   # leeres Attribut = kein Passwort hinterlegt
                $hits++
                if ($hits -gt $maxRows) { continue }
                $user = ''
                if ($content -match 'userName\s*=\s*"([^"]*)"') { $user = $Matches[1] }
                $rel = $file.FullName.Substring($polPath.Length).TrimStart('\')
                $result += [pscustomobject]@{
                    Kind='Fund'; Datei=$rel; Benutzer=$(if ($user) { $user } else { '(siehe Datei)' })
                    Detail='Klartext-dechiffrierbares Passwort in GPP-XML (cpassword) - entschluesselbar durch JEDES domaeneangemeldete Konto (MS14-025). Passwort SOFORT setzen und Datei bereinigen'
                    Risk='CRITICAL'
                }
            }
        }
        if ($hits -eq 0) {
            $result += [pscustomobject]@{ Kind='Summary'; Datei='(SYSVOL)'; Benutzer='-'; Detail="Keine cpassword-Eintraege in $($files.Count) GPP-XML-Dateien gefunden - OK"; Risk='OK' }
        } elseif ($hits -gt $maxRows) {
            $result += [pscustomobject]@{ Kind='Summary'; Datei='(SYSVOL)'; Benutzer='-'; Detail="GESAMT $hits Funde - Anzeige auf $maxRows Zeilen begrenzt, uebrige Funde nicht aufgelistet"; Risk='CRITICAL' }
        }
    } catch {
        Write-Log "GPPPasswords: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{ Kind='Error'; Datei='(SYSVOL)'; Benutzer='-'; Detail="Abfrage fehlgeschlagen: $_"; Risk='-' }
    }
    return $result
}

function Get-ProtectedUsersAudit {
    <#
    .SYNOPSIS
        Prueft, ob alle privilegierten Konten (Domain/Enterprise/Schema Admins,
        BUILTIN Administrators, Built-in Administrator) Mitglied der Gruppe
        'Protected Users' sind (Best Practice ab Server 2012).
    #>
    $result = @()
    try {
        
        $forest = Get-ADForest -ErrorAction Stop
        $domainSID = $domain.DomainSID.Value
        $rootDomainSID = $null
        try { $rootDomainSID = (Get-ADDomain -Identity $forest.RootDomain -ErrorAction Stop).DomainSID.Value } catch { $rootDomainSID = $domainSID }

        # Protected Users per Well-Known RID 525 (sprachunabhaengig)
        $protSids = @{}
        $protGroup = $null
        try { $protGroup = Get-ADGroup -Identity "$domainSID-525" -ErrorAction Stop } catch {}
        if ($protGroup) {
            try {
                foreach ($m in @(Get-ADGroupMember -Identity $protGroup -Recursive -ErrorAction Stop)) { $protSids[$m.SID.Value] = $true }
            } catch { Write-Log "ProtectedUsers Mitglieder: $_" -Level WARN -NoConsole }
        }

        $targets = @(
            @{ Name='Domain Admins';       SID="$domainSID-512" }
            @{ Name='Enterprise Admins';   SID="$rootDomainSID-519" }
            @{ Name='Schema Admins';       SID="$rootDomainSID-518" }
            @{ Name='BUILTIN Administrators'; SID="$domainSID-544" }
        )
        $seen = @{}
        foreach ($t in $targets) {
            $grp = $null
            try { $grp = Get-ADGroup -Identity $t.SID -ErrorAction Stop } catch {}
            if (-not $grp) { continue }
            $members = @()
            try { $members = @(Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop) }
            catch {
                $result += [pscustomobject]@{
                    Kind='Gruppe'; Account="($($t.Name))"; Gruppen='-'; InProtectedUsers='-'; Aktiv='-'
                    Detail="Mitglieder von '$($t.Name)' nicht auslesbar (fremde Domain/Vertrauensstellung?): $_"
                    Risk='MEDIUM'
                }
                continue
            }
            foreach ($m in $members) {
                if ($m.objectClass -ne 'user') { continue }
                if ($m.SamAccountName -ieq 'krbtgt') { continue }
                $sid = $m.SID.Value
                if ($seen.ContainsKey($sid)) { $seen[$sid].Groups += $t.Name; continue }
                $inProt = $protSids.ContainsKey($sid)
                $enabled = '-'
                try { $enabled = if ((Get-ADUser -Identity $sid -Properties Enabled -ErrorAction Stop).Enabled) { 'Ja' } else { 'Nein' } } catch {}
                $isBreakGlass = ($sid -eq "$domainSID-500")
                if ($inProt) {
                    $risk = 'OK'
                    $detail = 'In Protected Users - OK'
                } elseif ($isBreakGlass) {
                    $risk = 'WARN'
                    $detail = 'Built-in Administrator NICHT in Protected Users (Break-Glass - Ausnahme oft beabsichtigt, trotzdem dokumentieren)'
                } else {
                    $risk = 'WARN'
                    $detail = 'Privilegiertes Konto NICHT in Protected Users - erhaelt weiterhin volle NTLM/NetNTLM/DES-Faehigkeiten. Empfehlung: aufnehmen (Ausnahme: dokumentiertes Break-Glass-Konto)'
                }
                $seen[$sid] = @{ Name=$m.SamAccountName; Groups=@($t.Name); InProt=$inProt; Enabled=$enabled; Risk=$risk; Detail=$detail }
            }
        }
        foreach ($sid in ($seen.Keys | Sort-Object)) {
            $e = $seen[$sid]
            $result += [pscustomobject]@{
                Kind='Konto'; Account=$e.Name; Gruppen=(@($e.Groups) -join ', ')
                InProtectedUsers=$(if ($e.InProt) { 'Ja' } else { 'Nein' })
                Aktiv=$e.Enabled; Detail=$e.Detail; Risk=$e.Risk
            }
        }
        if (-not $protGroup) {
            $result += [pscustomobject]@{
                Kind='Summary'; Account='(Protected Users)'; Gruppen='-'; InProtectedUsers='-'; Aktiv='-'
                Detail='Gruppe mit RID 525 nicht gefunden - Domain Level < 2012? Protected Users nicht verfuegbar'
                Risk='WARN'
            }
        }
    } catch {
        Write-Log "ProtectedUsers: $_" -Level WARN -NoConsole
        $result += [pscustomobject]@{
            Kind='Error'; Account='(Abfrage)'; Gruppen='-'; InProtectedUsers='-'; Aktiv='-'
            Detail="Abfrage fehlgeschlagen: $_"; Risk='-'
        }
    }
    return $result
}

#endregion

#region ============= ASSESSMENT-ENGINE ======================================

function New-Assessment {
    param([ValidateSet('OK','WARN','CRITICAL','INFO','NODATA')][string]$OverallStatus='OK', [string]$Summary='', [array]$Findings=@(), [hashtable]$RowFlags=$null)
    [pscustomobject]@{ OverallStatus=$OverallStatus; Summary=$Summary; Findings=$Findings; RowFlags=$RowFlags }
}

function Test-Check-DCSystemInfo {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $c=$false
    foreach ($dc in $data) {
        if ($dc.OSBuild -and [int]$dc.OSBuild -lt 14393) { $f += "DC '$($dc.DCName)' OS <Server 2016"; $c=$true }
        if ($dc.TotalRAM_GB -lt 4) { $f += "DC '$($dc.DCName)' <4GB RAM" }
        if ($dc.LastBoot -and ((New-TimeSpan -Start $dc.LastBoot -End (Get-Date)).Days -gt 90)) { $f += "DC '$($dc.DCName)' >90d ohne Reboot" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){"$($data.Count) DC(s) OK"}else{"$($f.Count) Auffaelligkeit(en)"}) -Findings $f
}

function Test-Check-Services {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($s in $data) {
        $id="$($s.DCName)|$($s.Service)"
        switch ($s.Service) {
            { $_ -in 'NTDS','Netlogon','KDC','W32Time','DNS' } {
                if ($s.Status -eq 'NotFound') { $f += "KRIT: $($_) auf $($s.DCName) fehlt"; $rf[$id]='CRITICAL'; $c=$true }
                elseif ($s.Status -ne 'Running') { $f += "$($_) auf $($s.DCName): $($s.Status)"; $rf[$id]='WARN' }
                else { $rf[$id]='OK' }
            }
            'DFSR' {
                # SYSVOL-Replikation via DFSR = Best Practice
                if ($s.Status -eq 'Running') { $rf[$id]='OK' }
                else { $f += "DFSR auf $($s.DCName): $($s.Status) - SYSVOL-Replizierung betroffen!"; $rf[$id]='WARN' }
            }
            'NTFRS' {
                # Legacy-FRS: Gestoppt/Disabled/NotFound = OPTIMAL (DFSR uebernimmt SYSVOL)
                if ($s.Status -eq 'Running') { $f += "NTFRS (LEGACY) laeuft auf $($s.DCName) - nur noetig, wenn SYSVOL noch via FRS repliziert wird"; $rf[$id]='WARN' }
                else { $rf[$id]='OK' }
            }
            default {
                if ($s.Status -ne 'Running' -and $s.Status -ne 'NotFound') { $f += "$($s.Service) auf $($s.DCName): $($s.Status)"; $rf[$id]='WARN' }
                else { $rf[$id]='OK' }
            }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary $(if($st -eq 'OK'){'Alle Dienste OK (NTFRS gestoppt = Best Practice)'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-DCDiag {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $ct=@('Connectivity','Replications','NetLogons','Advertising','Services','Systemlog','RidManager','MachineAccount','KnowsOfRoleHolders','ObjectsReplicated','FsmoCheck','Basic','RecordRegistrations','Delegations','Forwarders','DnsBasic','Intersite')
    $f=@(); $rf=@{}; $c=$false; $w=$false; $p=0; $fl=0
    foreach ($r in $data) {
        $id="$($r.DCName)|$($r.Category)|$($r.PartitionOrScope)|$($r.TestName)"
        switch ($r.Result) {
            'PASSED' { $p++; $rf[$id]='OK' }
            'FAILED' {
                $fl++
                $es = (($r.ErrorDetails -split "`n") | Select-Object -First 3) -join ' | '
                if ($r.TestName -in $ct -or $r.TestName -match 'Dns|DNS') { $f += "[$($r.DCName)] KRIT: $($r.TestName) FAILED -> $es"; $rf[$id]='CRITICAL'; $c=$true }
                else { $f += "[$($r.DCName)] WARN: $($r.TestName) -> $es"; $rf[$id]='WARN'; $w=$true }
            }
            'WARNING' { $rf[$id]='WARN'; $w=$true; $f += "[$($r.DCName)] Warnung $($r.TestName)" }
            'UNKNOWN' { $rf[$id]='WARN' }
            default   { $rf[$id]='WARN' }
        }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){"Alle $p Tests OK"}else{"$p OK | $fl FAILED"}) -Findings $f -RowFlags $rf
}

function Test-Check-Replication {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Partner' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($r in $data) {
        $id="$($r.Server)|$($r.Partner)"
        if ($r.LastReplicationResult -ne 0) { $f += "$($r.Server)->$($r.Partner): Code $($r.LastReplicationResult)"; $rf[$id]='CRITICAL'; $c=$true }
        elseif ($r.ConsecutiveReplicationFailures -gt 0) { $f += "$($r.Server)->$($r.Partner): $($r.ConsecutiveReplicationFailures) Fehler"; $rf[$id]='WARN' }
        else { $rf[$id]='OK' }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){"Alle synchron"}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-ReplicationFailures { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine Fehler' }; $s = if ($c -ge $Global:ReplFailuresCrit) { 'CRITICAL' } elseif ($c -ge $Global:ReplFailuresWarn) { 'WARN' } else { 'OK' }; New-Assessment -OverallStatus $s -Summary "$c Replikations-Fehler" }

function Test-Check-FSMO {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@()
    foreach ($r in 'SchemaMaster','DomainNamingMaster','PDCEmulator','RIDMaster','InfrastructureMaster') { if (-not $data.$r) { $f += "$r fehlt" } }
    New-Assessment -OverallStatus $(if($f.Count){'CRITICAL'}else{'OK'}) -Summary $(if($f.Count){"$($f.Count) fehlt"}else{'Alle 5 FSMO OK'}) -Findings $f
}

function Test-Check-DNS {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'WARN' -Summary 'Keine Zonen' }
    $f=@(); $rf=@{}
    foreach ($z in $data) {
        $id="$($z.DCName)|$($z.ZoneName)"
        $zn = [string]$z.ZoneName
        # Vom DNS-Dienst automatisch angelegte Reverse-Zonen sind korrekt nicht
        # AD-integriert und werden hier NICHT als Befund gewertet.
        $isDefaultRev = [bool]($z.IsReverseLookupZone -and ($Global:DNSDefaultReverseZones -contains $zn))
        if ($z.ZoneType -eq 'Primary' -and -not $z.IsDsIntegrated -and -not $isDefaultRev) { $f += "$zn nicht AD-integriert"; $rf[$id]='WARN' }
        elseif ($z.DynamicUpdate -eq 'NonsecureAndSecure') { $f += "$zn erlaubt unsichere Updates!"; $rf[$id]='CRITICAL' }
        else { $rf[$id]='OK' }
    }
    $s = if ($rf.Values -contains 'CRITICAL') { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){"$($data.Count) Zonen OK"}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-SYSVOL {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}
    foreach ($s in $data) { if (-not $s.SYSVOL_Accessible -or -not $s.NETLOGON_Accessible) { $f += "SYSVOL/NETLOGON auf $($s.DCName)"; $rf[$s.DCName]='CRITICAL' } else { $rf[$s.DCName]='OK' } }
    New-Assessment -OverallStatus $(if($f.Count){'CRITICAL'}else{'OK'}) -Summary $(if($f.Count){"$($f.Count) Problem(e)"}else{'SYSVOL/NETLOGON OK'}) -Findings $f -RowFlags $rf
}

function Test-Check-Database {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($d in $data) {
        if ($d.DriveFree_GB -lt 5)       { $f += "$($d.DCName): $($d.DriveFree_GB) GB frei"; $rf[$d.DCName]='CRITICAL'; $c=$true }
        elseif ($d.DriveFree_GB -lt 20)  { $f += "$($d.DCName): $($d.DriveFree_GB) GB frei"; $rf[$d.DCName]='WARN' }
        else { $rf[$d.DCName]='OK' }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'DB OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-TLS {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    $ins = 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1'
    foreach ($t in $data) {
        $id="$($t.DCName)|$($t.Protocol)|$($t.Side)"
        if ($t.Protocol -in $ins) {
            if (-not $t.RegistryKeyExists) { $f += "KRIT: $($t.Protocol) ($($t.Side)) auf $($t.DCName) nicht deaktiviert"; $rf[$id]='CRITICAL'; $c=$true }
            elseif ($t.Enabled -eq 1) { $f += "KRIT: $($t.Protocol) auf $($t.DCName) AKTIV"; $rf[$id]='CRITICAL'; $c=$true }
            elseif ($t.Enabled -eq 0 -or $t.DisabledByDefault -eq 1) { $rf[$id]='OK' }
            else { $rf[$id]='WARN' }
        } elseif ($t.Protocol -eq 'TLS 1.2') {
            if (-not $t.RegistryKeyExists) { $f += "WARN: TLS 1.2 nicht explizit aktiviert"; $rf[$id]='WARN' }
            elseif ($t.Enabled -eq 0) { $f += "KRIT: TLS 1.2 DEAKTIVIERT"; $rf[$id]='CRITICAL'; $c=$true }
            else { $rf[$id]='OK' }
        } else { $rf[$id]='OK' }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'TLS OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-Cipher {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'INFO' -Summary 'Keine Cipher (Defaults)' }
    $f=@(); $rf=@{}
    foreach ($c in $data) {
        $id="$($c.DCName)|$($c.Cipher)"
        if (('RC4','DES','NULL','EXPORT','MD5' | Where-Object { $c.Cipher -match $_ }) -and $c.Enabled -eq 1) { $f += "Schwach: $($c.Cipher) auf $($c.DCName)"; $rf[$id]='CRITICAL' } else { $rf[$id]='OK' }
    }
    New-Assessment -OverallStatus $(if($f.Count){'CRITICAL'}else{'OK'}) -Summary "$($data.Count) Cipher" -Findings $f -RowFlags $rf
}

function Test-Check-SMB {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($s in $data) {
        switch ($s.SecurityStatus) {
            'OK'       { $rf[$s.DCName]='OK' }
            'WARN'     { $f += "[$($s.DCName)] $($s.Detail)"; $rf[$s.DCName]='WARN'; $w=$true }
            'CRITICAL' { $f += "[$($s.DCName)] $($s.Detail)"; $rf[$s.DCName]='CRITICAL'; $c=$true }
            default    { $rf[$s.DCName]='WARN'; $w=$true }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary $(if($st -eq 'OK'){'SMB Best-Practice OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-NTLMAuth {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($n in $data) {
        switch ($n.SecurityStatus) {
            'OK'       { $rf[$n.DCName]='OK' }
            'WARN'     { $f += "[$($n.DCName)] $($n.Detail)"; $rf[$n.DCName]='WARN'; $w=$true }
            'CRITICAL' { $f += "[$($n.DCName)] $($n.Detail)"; $rf[$n.DCName]='CRITICAL'; $c=$true }
        }
        if ($n.NTLMv1Events_7d -gt 0) { $f += "[$($n.DCName)] $($n.NTLMv1Events_7d) NTLM-Events in 7d"; if ($rf[$n.DCName] -eq 'OK') { $rf[$n.DCName]='WARN'; $w=$true } }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary $(if($st -eq 'OK'){'LmCompatibility=5 OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-LLMNR {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($l in $data) {
        switch ($l.SecurityStatus) {
            'OK'       { $rf[$l.DCName]='OK' }
            'WARN'     { $f += "[$($l.DCName)] $($l.Detail)"; $rf[$l.DCName]='WARN'; $w=$true }
            'CRITICAL' { $f += "[$($l.DCName)] $($l.Detail)"; $rf[$l.DCName]='CRITICAL'; $c=$true }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary $(if($st -eq 'OK'){'LLMNR/NetBIOS/WPAD aus'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-LDAPSecurity {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($l in $data) {
        $id=$l.DCName; $p=@()
        if ($l.LDAPServerIntegrity -ne 2) {
            if ($l.LDAPServerIntegrity -eq 0) { $p += "LDAP Signing DEAKTIVIERT"; $rf[$id]='CRITICAL'; $c=$true }
            else { $p += "LDAP Signing nur Negotiate"; if ($rf[$id] -ne 'CRITICAL') { $rf[$id]='WARN' } }
        }
        if ($l.LdapEnforceChannelBinding -ne 2) {
            if ($null -eq $l.LdapEnforceChannelBinding -or $l.LdapEnforceChannelBinding -eq 0) { $p += "Channel Binding NICHT aktiv"; $rf[$id]='CRITICAL'; $c=$true }
            else { $p += "Channel Binding nur WhenSupported"; if ($rf[$id] -ne 'CRITICAL') { $rf[$id]='WARN' } }
        }
        if ($l.LDAPSPortOpen -eq $false) { $p += "LDAPS Port 636 NICHT erreichbar"; $rf[$id]='CRITICAL'; $c=$true }
        if ($l.UnsignedLDAPBinds_7d -gt 0) { $p += "$($l.UnsignedLDAPBinds_7d) unsichere Binds in 7d"; if ($rf[$id] -ne 'CRITICAL') { $rf[$id]='WARN' } }
        if (-not $rf[$id]) { $rf[$id]='OK' }
        foreach ($x in $p) { $f += "[$($l.DCName)] $x" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'LDAP-Security OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-WindowsFirewall {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($p in $data) {
        $id = "$($p.DCName)|$($p.Profile)"
        if ($p.Enabled -eq $false) { $f += "[$($p.DCName)] Firewall-Profil '$($p.Profile)' DEAKTIVIERT"; $rf[$id]='CRITICAL'; $c=$true }
        else { $rf[$id]='OK' }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'Alle Firewall-Profile aktiv'}else{"$($f.Count) inaktiv"}) -Findings $f -RowFlags $rf
}

function Test-Check-PrivilegedAccounts {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'WARN' -Summary 'Keine Daten' }
    $f=@()
    $da = @($data | Where-Object { $_.Group -eq 'Domain Admins' -and $_.MemberName -ne '<leer>' })
    $ea = @($data | Where-Object { $_.Group -eq 'Enterprise Admins' -and $_.MemberName -ne '<leer>' })
    $sa = @($data | Where-Object { $_.Group -eq 'Schema Admins' -and $_.MemberName -ne '<leer>' })
    if ($da.Count -gt 5) { $f += "$($da.Count) Domain Admins (Best: <=5)" }
    if ($ea.Count -gt 2) { $f += "$($ea.Count) Enterprise Admins (Best: <=2)" }
    if ($sa.Count -gt 2) { $f += "$($sa.Count) Schema Admins (Best: <=2)" }
    New-Assessment -OverallStatus $(if($f.Count){'WARN'}else{'OK'}) -Summary "DA:$($da.Count) | EA:$($ea.Count) | SA:$($sa.Count)" -Findings $f
}

function Test-Check-PasswordPolicy {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@()
    $def = $data | Where-Object { $_.Type -eq 'Default Domain Policy' } | Select-Object -First 1
    if ($def) {
        if ($def.MinPasswordLength -lt 14) { $f += "MinLen: $($def.MinPasswordLength) (Best: >=14)" }
        if ($def.PasswordHistoryCount -lt 24) { $f += "History: $($def.PasswordHistoryCount) (Best: >=24)" }
        if ($def.MaxPasswordAge.Days -gt 60 -or $def.MaxPasswordAge.Days -eq 0) { $f += "MaxAge: $($def.MaxPasswordAge.Days)d" }
        if (-not $def.ComplexityEnabled) { $f += "Complexity DEAKTIVIERT" }
        if ($def.LockoutThreshold -eq 0 -or $def.LockoutThreshold -gt 10) { $f += "Lockout: $($def.LockoutThreshold)" }
    }
    $s = if ($f.Count -gt 3) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'Policy OK'}else{"$($f.Count) Abweichung(en)"}) -Findings $f
}

function Test-Check-Kerberos {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@()
    if ($data.PasswordAgeDays -gt $Global:KrbtgtMaxAgeDays) { $f += "krbtgt-Passwort $($data.PasswordAgeDays)d alt - RESET!" }
    $s = if ($data.PasswordAgeDays -gt ($Global:KrbtgtMaxAgeDays*2)) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "krbtgt: $($data.PasswordAgeDays)d" -Findings $f
}

function Test-Check-UnconstrainedDelegation {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine Unconstrained Delegation' }
    $f=@(); $rf=@{}; $c=$false
    $dcs=0; $risky=0; $crit=0
    foreach ($d in $data) {
        $id = "$($d.Type)|$($d.SamAccount)"
        if ($d.Risk -eq 'NORMAL') { $dcs++; $rf[$id]='OK' }
        elseif ($d.Risk -eq 'HIGH') { $risky++; $f += "[Computer] $($d.Name) hat Unconstrained Delegation - DOMAIN-TAKEOVER-Risiko!"; $rf[$id]='CRITICAL'; $c=$true }
        elseif ($d.Risk -eq 'CRITICAL') { $crit++; $f += "[User] $($d.Name) hat Unconstrained Delegation - KRITISCH!"; $rf[$id]='CRITICAL'; $c=$true }
    }
    $s = if ($c) { 'CRITICAL' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "DCs:$dcs | Computer-Risiko:$risky | User-Kritisch:$crit" -Findings $f -RowFlags $rf
}

function Test-Check-KerberoastingRisk {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine User mit SPN' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    $low=0; $med=0; $high=0; $crit=0
    foreach ($u in $data) {
        $id = $u.SamAccount
        switch ($u.Risk) {
            'LOW'      { $low++; $rf[$id]='OK' }
            'MEDIUM'   { $med++; $rf[$id]='WARN'; $w=$true; $f += "[$($u.SamAccount)] MEDIUM: Passwort $($u.PasswordAgeDays)d alt" }
            'HIGH'     { $high++; $rf[$id]='WARN'; $w=$true; $f += "[$($u.SamAccount)] HIGH: Passwort $($u.PasswordAgeDays)d alt oder NeverExpires" }
            'CRITICAL' { $crit++; $rf[$id]='CRITICAL'; $c=$true; $f += "[$($u.SamAccount)] KRIT: Privilegierter Account mit SPN!" }
        }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "LOW:$low | MEDIUM:$med | HIGH:$high | CRITICAL:$crit" -Findings $f -RowFlags $rf
}

function Test-Check-LSAProtection {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    $exc=0; $good=0; $vuln=0; $nc=0
    foreach ($s in $data) {
        $id=$s.DCName
        switch ($s.SecurityStatus) {
            'EXCELLENT'      { $exc++; $rf[$id]='OK' }
            'GOOD'           { $good++; $rf[$id]='OK'; $f += "[$($s.DCName)] RunAsPPL=1 - kann auf 2 (UEFI) erhoeht werden" }
            'VULNERABLE'     { $vuln++; $f += "[$($s.DCName)] KRIT: RunAsPPL=0 - Credential-Dumping moeglich"; $rf[$id]='CRITICAL'; $c=$true }
            'NOT_CONFIGURED' { $nc++; $f += "[$($s.DCName)] KRIT: RunAsPPL nicht gesetzt"; $rf[$id]='CRITICAL'; $c=$true }
            default          { $rf[$id]='WARN'; $w=$true }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary "EXC:$exc | GOOD:$good | VULN:$vuln | NOT_CONFIG:$nc" -Findings $f -RowFlags $rf
}

function Test-Check-PrintSpooler {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    $sec=0; $risk=0; $vuln=0
    foreach ($s in $data) {
        switch ($s.SecurityStatus) {
            'SECURE'     { $sec++; $rf[$s.DCName]='OK' }
            'AT_RISK'    { $risk++; $f += "[$($s.DCName)] StartType='$($s.StartType)'"; $rf[$s.DCName]='WARN'; $w=$true }
            'VULNERABLE' { $vuln++; $f += "[$($s.DCName)] KRIT: Spooler laeuft - PrintNightmare!"; $rf[$s.DCName]='CRITICAL'; $c=$true }
            default      { $rf[$s.DCName]='WARN'; $w=$true }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary "SECURE:$sec | AT_RISK:$risk | VULN:$vuln" -Findings $f -RowFlags $rf
}

function Test-Check-SecureBoot {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    $cnt = @{ SUCCESS=0; IN_PROGRESS=0; PENDING=0; FAILED=0; NOT_STARTED=0; NOT_CAPABLE=0; NOT_APPLICABLE=0; UNKNOWN=0 }
    foreach ($s in $data) {
        $id=$s.DCName
        if ($s._Firmware -match 'Legacy|BIOS' -and $s._Firmware -notmatch 'UEFI') { $f += "[$($s.DCName)] Firmware Legacy-BIOS"; $rf[$id]='CRITICAL'; $c=$true; continue }
        if ($s.SecureBoot -match 'Disabled') { $f += "[$($s.DCName)] Secure Boot DEAKTIVIERT"; $rf[$id]='CRITICAL'; $c=$true }
        switch ($s.UpdateStatus) {
            'SUCCESS' {
                $cnt['SUCCESS']++
                if ($s._ResidualBits) { $f += "[$($s.DCName)] SUCCESS aber Bit [$($s._ResidualBits)] offen (Reboot empfohlen)"; if (-not $rf[$id]) { $rf[$id]='WARN'; $w=$true } }
                elseif (-not $rf[$id]) { $rf[$id]='OK' }
            }
            'IN_PROGRESS'    { $cnt['IN_PROGRESS']++;    $f += "[$($s.DCName)] $($s.Detail)"; if ($rf[$id] -ne 'CRITICAL') { $rf[$id]='WARN'; $w=$true } }
            'PENDING'        { $cnt['PENDING']++;        $f += "[$($s.DCName)] $($s.Detail)"; if ($rf[$id] -ne 'CRITICAL') { $rf[$id]='WARN'; $w=$true } }
            'FAILED'         { $cnt['FAILED']++;         $f += "[$($s.DCName)] $($s.Detail)"; $rf[$id]='CRITICAL'; $c=$true }
            'NOT_STARTED'    { $cnt['NOT_STARTED']++;    $f += "[$($s.DCName)] $($s.Detail)"; $rf[$id]='CRITICAL'; $c=$true }
            'NOT_CAPABLE'    { $cnt['NOT_CAPABLE']++;    $f += "[$($s.DCName)] $($s.Detail)"; $rf[$id]='CRITICAL'; $c=$true }
            'NOT_APPLICABLE' { $cnt['NOT_APPLICABLE']++; if (-not $rf[$id]) { $rf[$id]='WARN'; $w=$true } }
            default          { $cnt['UNKNOWN']++; $f += "[$($s.DCName)] UNKNOWN: $($s.Detail)"; if (-not $rf[$id]) { $rf[$id]='WARN'; $w=$true } }
        }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    $sum = "SUCCESS:$($cnt['SUCCESS']) | PENDING:$($cnt['PENDING']) | IN_PROGRESS:$($cnt['IN_PROGRESS']) | FAILED:$($cnt['FAILED']) | NOT_STARTED:$($cnt['NOT_STARTED']) | NOT_CAPABLE:$($cnt['NOT_CAPABLE']) | N/A:$($cnt['NOT_APPLICABLE'])"
    New-Assessment -OverallStatus $st -Summary $sum -Findings $f -RowFlags $rf
}

function Test-Check-Certificates {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $real = @($data | Where-Object { $_.NotAfter }); $ph = @($data | Where-Object { -not $_.NotAfter })
    $f=@(); $rf=@{}; $c=$false
    foreach ($x in $real) {
        $id="$($x.DCName)|$($x.Store)|$($x.Thumbprint)"
        if ($x.DaysToExpiry -lt 0) { $f += "ABGELAUFEN: $($x.Subject) auf $($x.DCName)"; $rf[$id]='CRITICAL'; $c=$true }
        elseif ($x.DaysToExpiry -le $Global:CertExpiryCritDays) { $f += "KRIT: $($x.Subject) in $($x.DaysToExpiry)d"; $rf[$id]='CRITICAL'; $c=$true }
        elseif ($x.DaysToExpiry -le $Global:CertExpiryWarnDays) { $f += "WARN: $($x.Subject) in $($x.DaysToExpiry)d"; $rf[$id]='WARN' }
        else { $rf[$id]='OK' }
    }
    foreach ($p in $ph) { $rf["$($p.DCName)|$($p.Store)|$($p.Thumbprint)"]='WARN'; $f += "$($p.DCName): $($p.Subject)" }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$($real.Count) Zertifikate, $($ph.Count) ohne Daten" -Findings $f -RowFlags $rf
}

function Test-Check-Sites { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'WARN' -Summary 'Keine Sites' }; New-Assessment -OverallStatus 'INFO' -Summary "$c Site(s)" }
function Test-Check-Subnets { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'WARN' -Summary 'Keine Subnetze!' }; $u = @($data | Where-Object { -not $_.Site }).Count; if ($u) { return New-Assessment -OverallStatus 'WARN' -Summary "$c Subnetze, $u ohne Site" }; New-Assessment -OverallStatus 'OK' -Summary "$c Subnetze OK" }
function Test-Check-Trusts { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'INFO' -Summary 'Keine Trusts' }; New-Assessment -OverallStatus 'INFO' -Summary "$c Trust(s)" }

function Test-Check-ADRecycleBin {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    if ($data.IsEnabled) { New-Assessment -OverallStatus 'OK' -Summary 'AD Recycle Bin aktiv' }
    else { New-Assessment -OverallStatus 'WARN' -Summary 'AD Recycle Bin NICHT aktiv' -Findings @($data.Detail) }
}

function Test-Check-TombstoneLifetime {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    if ($data.MeetsBestPractice) { New-Assessment -OverallStatus 'OK' -Summary "Tombstone = $($data.TombstoneLifetimeDays)d" }
    else { New-Assessment -OverallStatus 'WARN' -Summary "Tombstone = $($data.TombstoneLifetimeDays)d - zu niedrig!" -Findings @($data.Detail) }
}

function Test-Check-Levels {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $v = 'Windows2016Forest','Windows2016Domain','WinThreshold','Windows2025Forest','Windows2025Domain'
    if ($data.ForestMode -notin $v) { $f += "ForestMode: $($data.ForestMode)" }
    if ($data.DomainMode -notin $v) { $f += "DomainMode: $($data.DomainMode)" }
    New-Assessment -OverallStatus $(if($f.Count){'WARN'}else{'OK'}) -Summary "Forest:$($data.ForestMode) | Domain:$($data.DomainMode)" -Findings $f
}

function Test-Check-GPO {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'WARN' -Summary 'Keine GPOs' }
    $f=@(); $rf=@{}
    foreach ($g in $data) {
        $p=@()
        if ($g.GpoStatus -eq 'AllSettingsDisabled') { $p += 'deaktiviert' }
        if ($g.UserVersion_DS -ne $g.UserVersion_Sys) { $p += 'User-Mismatch' }
        if ($g.CompVersion_DS -ne $g.CompVersion_Sys) { $p += 'Comp-Mismatch' }
        if ($p.Count) { $f += "$($g.DisplayName): $($p -join ', ')"; $rf["$($g.Id)"]='WARN' } else { $rf["$($g.Id)"]='OK' }
    }
    New-Assessment -OverallStatus $(if($f.Count){'WARN'}else{'OK'}) -Summary $(if($f.Count){"$($f.Count) Problem(e)"}else{"$($data.Count) GPOs OK"}) -Findings $f -RowFlags $rf
}

function Test-Check-InactiveUsers { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine inaktiven User' }; New-Assessment -OverallStatus $(if($c -gt 50){'WARN'}else{'INFO'}) -Summary "$c inaktive User" }
function Test-Check-InactiveComputers { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine inaktiven Computer' }; New-Assessment -OverallStatus $(if($c -gt 50){'WARN'}else{'INFO'}) -Summary "$c inaktive Computer" }
function Test-Check-PasswordNeverExpires { param($data); $c=@($data).Count; if ($c -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine PwdNeverExpires' }; New-Assessment -OverallStatus $(if($c -gt 10){'WARN'}else{'INFO'}) -Summary "$c PwdNeverExpires" }

function Test-Check-EventLog {
    param($data); $c=@($data).Count
    if ($c -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary "Keine Errors in $Global:EventLogHours h" }
    $cr = @($data | Where-Object { $_.Level -eq 'Critical' }).Count
    $er = @($data | Where-Object { $_.Level -eq 'Error' }).Count
    $s = if ($cr) { 'CRITICAL' } elseif ($er) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$cr Critical, $er Errors"
}

function Test-Check-TimeSync {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($t in $data) {
        $id=$t.DCName; $p=@()
        if ($t.IsPDCEmulator) {
            if ($t.SourceKind -in 'LocalClock','FreeRunning') { $p += "PDC nutzt LokaleUhr!"; $rf[$id]='CRITICAL'; $c=$true }
            elseif ($t.ConfiguredType -notmatch 'NTP|AllSync') { $p += "PDC Type='$($t.ConfiguredType)' statt NTP"; $rf[$id]='WARN' }
            elseif (-not $t.ConfiguredNtpSrv -or $t.ConfiguredNtpSrv -match 'time\.windows\.com') { $p += "PDC NTP: '$($t.ConfiguredNtpSrv)'"; $rf[$id]='WARN' }
            else { $rf[$id]='OK' }
        } else {
            if ($t.SourceKind -in 'LocalClock','FreeRunning') { $p += "DC nutzt LokaleUhr statt PDC!"; $rf[$id]='CRITICAL'; $c=$true }
            elseif ($t.ConfiguredType -notmatch 'NT5DS|AllSync') { $p += "Type='$($t.ConfiguredType)' statt NT5DS"; $rf[$id]='WARN' }
            else { $rf[$id]='OK' }
        }
        foreach ($x in $p) { $f += "[$($t.DCName)] $x" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'Zeitsync OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
}

function Test-Check-Backup {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    if (-not $data.LastBackup) { return New-Assessment -OverallStatus 'CRITICAL' -Summary 'KEIN AD-Backup!' }
    if ($data.AgeDays -gt $Global:BackupCritAgeDays) { return New-Assessment -OverallStatus 'CRITICAL' -Summary "Backup $($data.AgeDays)d alt" }
    if ($data.AgeDays -gt $Global:BackupMaxAgeDays)  { return New-Assessment -OverallStatus 'WARN' -Summary "Backup $($data.AgeDays)d alt" }
    New-Assessment -OverallStatus 'OK' -Summary "Backup $($data.AgeDays)d alt"
}

function Test-Check-InstalledPrograms {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $total = @($data).Count
    $per = $data | Group-Object DCName | ForEach-Object { "$($_.Name): $($_.Count)" }
    New-Assessment -OverallStatus 'INFO' -Summary "Gesamt $total Programme | $($per -join ' | ')"
}

function Test-Check-WindowsUpdates {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false
    foreach ($g in ($data | Group-Object DCName)) {
        $latest = $g.Group | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (-not $latest) { $f += "$($g.Name): keine Daten"; continue }
        foreach ($row in $g.Group) { $rf["$($row.DCName)|$($row.HotFixID)"]='OK' }
        $d = $latest.DaysAgo
        if ($d -gt $Global:WUMaxAgeDaysCrit) { $f += "$($g.Name): Letztes Update $d d alt (KRIT)"; $c=$true }
        elseif ($d -gt $Global:WUMaxAgeDaysWarn) { $f += "$($g.Name): $d d alt" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $(if($s -eq 'OK'){'Alle aktuell'}else{"$($f.Count) veraltet"}) -Findings $f -RowFlags $rf
}

function Test-Check-WindowsFeatures {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $total = @($data).Count
    $per = $data | Group-Object DCName | ForEach-Object { "$($_.Name): $($_.Count)" }
    New-Assessment -OverallStatus 'INFO' -Summary "Gesamt $total installierte Feature(s) | $($per -join ' | ')"
}

function Test-Check-Shares {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $w=$false
    # Standard-Freigaben auf DCs: SYSVOL/NETLOGON haben per Default 'Everyone'-Rechte (nur Lesen auf Freigabenebene,
    # die eigentliche Steuerung erfolgt ueber NTFS). ADMIN$/C$/IPC$ sind System-Freigaben.
    $stdShares = @('SYSVOL','NETLOGON','ADMIN$','C$','D$','E$','IPC$','print$','FAX$')
    foreach ($row in $data) {
        $id = "$($row.DCName)|$($row.Name)"
        if (-not $row.Name -or $row.Name -eq '(keine Daten)') { continue }
        $rf[$id]='OK'
        # Warnung nur bei NICHT-Standard-Freigaben mit Everyone/Gast + Full/Change
        if ($stdShares -notcontains $row.Name -and $row.Permissions -and
            $row.Permissions -match '(?i)(everyone|jeder|anonymous|anonym|gast|guest).*(full|change|vollzugriff|ändern|aendern)') {
            $f += "$($row.DCName): Freigabe '$($row.Name)' erlaubt 'Everyone' mit Full/Change-Zugriff"
            $rf[$id]='WARN'; $w=$true
        }
    }
    $custom = @($data | Where-Object { $stdShares -notcontains $_.Name -and $_.Name -ne '(keine Daten)' })
    $per = $data | Group-Object DCName | ForEach-Object { "$($_.Name): $($_.Count)" }
    $sum = "Gesamt $($data.Count) Freigabe(n), davon $($custom.Count) benutzerdefiniert | $($per -join ' | ')"
    $s = if ($w) { 'WARN' } else { 'INFO' }
    New-Assessment -OverallStatus $s -Summary $sum -Findings $f -RowFlags $rf
}

function Test-Check-SPNDuplicates {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine SPN-Dubletten' }
    $f=@(); $rf=@{}
    $dupCount = @($data | Group-Object SPN).Count
    foreach ($row in $data) {
        $rf["$($row.SPN)|$($row.SamAccount)"]='CRITICAL'
    }
    foreach ($dup in ($data | Group-Object SPN)) {
        $accounts = @($dup.Group | ForEach-Object { if ($_.SamAccount) { $_.SamAccount } else { $_.Name } }) -join ', '
        $f += "SPN '$($dup.Name)' mehrfach vergeben: $accounts"
    }
    New-Assessment -OverallStatus 'CRITICAL' -Summary "$dupCount doppelte SPN(s)" -Findings $f -RowFlags $rf
}

function Test-Check-ASREPRoasting {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine AS-REP-Roasting-Ziele' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($row in $data) {
        $id = $row.SamAccount
        switch ($row.Risk) {
            'CRITICAL' { $rf[$id]='CRITICAL'; $c=$true; $f += "[$($row.SamAccount)] privilegiert ohne PreAuth" }
            'HIGH'     { $rf[$id]='WARN'; $w=$true; $f += "[$($row.SamAccount)] ohne PreAuth, Passwort alt/NeverExpires" }
            default    { $rf[$id]='WARN'; $w=$true; $f += "[$($row.SamAccount)] ohne Kerberos PreAuth" }
        }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) AS-REP-Roasting-Ziel(e)" -Findings $f -RowFlags $rf
}

function Test-Check-AdminSDHolderDrift {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine AdminCount-Objekte' }
    $f=@(); $rf=@{}
    $drift = @($data | Where-Object { $_.Risk -eq 'DRIFT' })
    foreach ($row in $data) {
        $rf[$row.SamAccount] = if ($row.Risk -eq 'DRIFT') { 'WARN' } else { 'OK' }
    }
    foreach ($row in $drift) {
        $f += "[$($row.SamAccount)] AdminCount=1 ohne aktuelle geschuetzte Gruppenmitgliedschaft"
    }
    $status = if ($drift.Count -gt 0) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $status -Summary "AdminCount=1: $(@($data).Count) | Drift: $($drift.Count)" -Findings $f -RowFlags $rf
}

function Test-Check-FGPP {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'INFO' -Summary 'Keine Fine-Grained Policies' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($row in $data) {
        $rf[$row.Name] = switch ($row.Risk) { 'CRITICAL' { 'CRITICAL' } 'WARN' { 'WARN' } default { 'OK' } }
        if ($row.Risk -eq 'CRITICAL') { $c=$true; $f += "[$($row.Name)] $($row.Detail)" }
        elseif ($row.Risk -eq 'WARN') { $w=$true; $f += "[$($row.Name)] $($row.Detail)" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) FGPP(s)" -Findings $f -RowFlags $rf
}

function Test-Check-DNSHygiene {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($row in $data) {
        $id = "$($row.Kind)|$($row.Target)"
        switch ($row.Status) {
            'CRITICAL' { $rf[$id]='CRITICAL'; $c=$true; $f += "[$($row.Target)] $($row.Detail)" }
            'WARN'     { $rf[$id]='WARN'; $w=$true; $f += "[$($row.Target)] $($row.Detail)" }
            default    { $rf[$id]='OK' }
        }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) DNS-Hygiene-Pruefpunkt(e)" -Findings $f -RowFlags $rf
}

function Test-Check-LAPS {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'INFO' -Summary 'LAPS-Daten nicht verfuegbar' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    
    # Auswerten der Ergebnisse
    $configRow = @($data | Where-Object { $_.Type -eq 'Summary' }) | Select-Object -First 1
    
    if ($configRow) {
        if ($configRow.LAPSEnabled -eq $false) {
            $c = $true
            $f += "KRITISCH: LAPS Schema-Erweiterung ist NICHT installiert!"
            $rf['Forest-Config'] = 'CRITICAL'
        } else {
            $rf['Forest-Config'] = 'OK'
            
            # Pruefe auf Computer mit nicht unterstütztem OS
            if ($configRow.OSUnsupported -gt 0) {
                $c = $true
                $f += "KRITISCH: $($configRow.OSUnsupported) Computer mit nicht-unterstütztem OS (Server 2016 oder aelter)"
            }
            
            if ($configRow.ComputerCount -gt 0) {
                $percent = $configRow.ConfiguredPercent
                if ($percent -eq 100 -and $configRow.OSUnsupported -eq 0) {
                    $f += "OPTIMAL: 100% der Computer ($($configRow.ComputerCount)) haben LAPS konfiguriert (alle Systeme unterstützen LAPS)"
                    $rf['Summary'] = 'OK'
                } elseif ($percent -ge 90 -and $configRow.OSUnsupported -eq 0) {
                    $w = $true
                    $f += "WARNUNG: $percent% ($($configRow.ConfiguredCount)/$($configRow.ComputerCount)) der Computer mit LAPS konfiguriert. Unconfigured: $($configRow.UnconfiguredCount)"
                    $rf['Summary'] = 'WARN'
                } else {
                    if ($c -eq $false) { $c = $true }  # Wenn OSUnsupported > 0, ist bereits CRITICAL
                    $f += "KRITISCH: Nur $percent% ($($configRow.ConfiguredCount)/$($configRow.ComputerCount)) der Computer mit LAPS konfiguriert!"
                    $rf['Summary'] = 'CRITICAL'
                }
            }
        }
    }
    
    # Details Computer mit kritischen OS-Problemen (konfiguriert aber OS nicht unterstuetzt)
    $osProblems = @($data | Where-Object { $_.Type -eq 'Computer' -and $_.OSUnsupported -eq 1 -and $_.LAPSEnabled -eq $true })
    foreach ($op in $osProblems) {
        $c = $true
        $rf[$op.Target] = 'CRITICAL'
        $f += "  [CRITICAL] $($op.Target): $($op.Issue)"
    }
    
    # Details unkonfigurierter Computer (falls vorhanden)
    $unconfigured = @($data | Where-Object { $_.Type -eq 'Computer' -and $_.LAPSEnabled -eq $false })
    if ($unconfigured.Count -gt 0 -and $unconfigured.Count -le 50) {
        foreach ($uc in $unconfigured) {
            # Prüfe ob OS-Problem in der Issue-Beschreibung ist
            if ($uc.Issue -match 'NICHT UNTERSTUETZT') {
                $rf[$uc.Target] = 'CRITICAL'
            } else {
                $rf[$uc.Target] = 'WARN'
            }
            $f += "  [$($uc.Target)] $($uc.Issue)"
        }
    } elseif ($unconfigured.Count -gt 50) {
        $f += "  [und $($unconfigured.Count - 50) weitere Systeme ohne LAPS]"
    }
    
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    $summary = if ($configRow) { "LAPS: $($configRow.Issue)" } else { "LAPS-Status unbekannt" }
    New-Assessment -OverallStatus $s -Summary $summary -Findings $f -RowFlags $rf
}

function Test-Check-AccountsWithoutAES {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'INFO' -Summary 'Keine AES-Daten verfuegbar' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    
    # Gruppiere nach Risk-Level
    $critical = @($data | Where-Object { $_.Type -in 'User','Computer' -and $_.Risk -eq 'CRITICAL' })
    $high     = @($data | Where-Object { $_.Type -in 'User','Computer' -and $_.Risk -eq 'HIGH' })
    $medium   = @($data | Where-Object { $_.Type -in 'User','Computer' -and $_.Risk -eq 'MEDIUM' })
    $summary  = @($data | Where-Object { $_.Type -eq 'Summary' }) | Select-Object -First 1
    
    # CRITICAL: RC4/DES ohne AES
    foreach ($row in $critical) {
        $c = $true
        $id = "$($row.Type)|$($row.ObjectName)"
        $rf[$id] = 'CRITICAL'
        $f += "  [CRITICAL] $($row.Type) '$($row.ObjectName)': $($row.Issue)"
    }
    
    # HIGH: Explizit AES disabled
    foreach ($row in $high) {
        $c = $true
        $id = "$($row.Type)|$($row.ObjectName)"
        $rf[$id] = 'CRITICAL'
        $f += "  [CRITICAL] $($row.Type) '$($row.ObjectName)': $($row.Issue)"
    }
    
    # MEDIUM: RC4+AES (Downgrade moeglich)
    foreach ($row in $medium) {
        $w = $true
        $id = "$($row.Type)|$($row.ObjectName)"
        $rf[$id] = 'WARN'
        $f += "  [WARN] $($row.Type) '$($row.ObjectName)': $($row.Issue)"
    }
    
    # Summary
    if ($summary) {
        if ($summary.Risk -eq 'OK') {
            $f += "Verschluesselung: Standard-AES aktiv, keine RC4-Only Konfigurationen gefunden"
        }
    }
    
    # Zusammenfassung
    $accountsCount = @($data | Where-Object { $_.Type -in 'User','Computer' }).Count
    $criticalHighCount = $critical.Count + $high.Count
    $summary_text = "$accountsCount Konten geprueft | CRITICAL: $criticalHighCount | MEDIUM: $($medium.Count)"
    
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary $summary_text -Findings $f -RowFlags $rf
}

function Test-Check-RCAESMigration {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine RC4/AES-Migrationsdaten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false; $critN=0; $warnN=0
    foreach ($row in $data) {
        $id = "$($row.Kind)|$($row.Name)"
        if ($row.Kind -eq 'Summary') { $rf[$id]='OK'; continue }
        switch ($row.Risk) {
            'CRITICAL' { $rf[$id]='CRITICAL'; $c=$true; $critN++; if ($f.Count -lt 30) { $f += "  [KRITISCH] $($row.Name) ($($row.ObjektTyp)): $($row.Detail)" } }
            'HIGH'     { $rf[$id]='CRITICAL'; $c=$true; $critN++; if ($f.Count -lt 30) { $f += "  [KRITISCH] $($row.Name) ($($row.ObjektTyp)): $($row.Detail)" } }
            'MEDIUM'   { $rf[$id]='WARN'; $w=$true; $warnN++; if ($f.Count -lt 30) { $f += "  [WARN] $($row.Name) ($($row.ObjektTyp)): $($row.Detail)" } }
            'WARN'     { $rf[$id]='WARN'; $w=$true; $warnN++; if ($f.Count -lt 30) { $f += "  [WARN] $($row.Name) ($($row.ObjektTyp)): $($row.Detail)" } }
            default    { $rf[$id]='OK' }
        }
    }
    if (($critN + $warnN) -gt 30) { $f += "  ... und $($critN + $warnN - 30) weitere Befunde (siehe Detailtabelle/CSV)" }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$critN kritische | $warnN Warnung(en) - RC4-Migration (CVE-2026-20833, RC4-Ende 2026)" -Findings $f -RowFlags $rf
}

function Test-Check-DCSyncPermissions {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine DCSync-Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    $bad    = @($data | Where-Object { $_.IstStandardTraeger -eq 'Nein' })
    $crit   = @($bad    | Where-Object { $_.HatGetChangesAll -eq 'Ja' })
    $warner = @($bad    | Where-Object { $_.HatGetChangesAll -ne 'Ja' })
    foreach ($row in $data) {
        $id = "$($row.Kind)|$($row.SID)"
        $rf[$id] = switch ($row.Risk) { 'CRITICAL' { 'CRITICAL' } 'WARN' { 'WARN' } 'OK' { 'OK' } default { '' } }
    }
    foreach ($row in $crit) { $c=$true; $f += "  [KRITISCH] '$($row.Identity)' ($($row.SID)): DCSync-Rechte ausserhalb der DCs - Hash-Extraktion moeglich!" }
    foreach ($row in $warner) { $w=$true; $f += "  [WARN] '$($row.Identity)' ($($row.SID)): $($row.Rechte)" }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) Rechteinhaber | Nicht-Standard: $($bad.Count) (davon mit Get-Changes-All: $($crit.Count))" -Findings $f -RowFlags $rf
}

function Test-Check-RBCDDelegation {
    param($data); if (-not $data -or @($data).Count -eq 0) { return New-Assessment -OverallStatus 'OK' -Summary 'Keine RBCD/Constrained-Delegation-Eintraege' }
    $f=@(); $rf=@{}; $c=$false; $w=$false; $critN=0; $warnN=0
    foreach ($row in $data) {
        $id = "$($row.Kind)|$($row.Name)|$($row.Prinzipal)"
        switch ($row.Risk) {
            'HIGH'   { $rf[$id]='CRITICAL'; $c=$true; $critN++;   if ($f.Count -lt 30) { $f += "  [KRITISCH] [$($row.Kind)] $($row.Name) -> $($row.Prinzipal): $($row.Detail)" } }
            'MEDIUM' { $rf[$id]='WARN';     $w=$true; $warnN++;   if ($f.Count -lt 30) { $f += "  [WARN] [$($row.Kind)] $($row.Name) -> $($row.Prinzipal)" } }
            default  { $rf[$id]='OK' }
        }
    }
    if (($critN + $warnN) -gt 30) { $f += "  ... und $($critN + $warnN - 30) weitere Eintraege (siehe Detailtabelle/CSV)" }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'INFO' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) Eintraege (RBCD + Constrained Delegation) | KRITISCH: $critN | WARN: $warnN" -Findings $f -RowFlags $rf
}

function Test-Check-dMSA {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine dMSA-Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false; $dmsaN=0
    $schemaRow = @($data | Where-Object { $_.Kind -eq 'Schema' }) | Select-Object -First 1
    foreach ($row in $data) {
        $id = "$($row.Kind)|$($row.Name)"
        switch ($row.Risk) {
            'CRITICAL' { $rf[$id]='CRITICAL'; $c=$true; $f += "  [KRITISCH] $($row.Name): $($row.Detail)" }
            'WARN'     { $rf[$id]='WARN';     $w=$true; $f += "  [WARN] $($row.Name): $($row.Detail)" }
            'MEDIUM'   { $rf[$id]='';         $dmsaN++; if ($f.Count -lt 20) { $f += "  [INFO] $($row.Name): $($row.Detail)" } }
            default    { $rf[$id]='OK' }
        }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } elseif ($dmsaN -gt 0) { 'INFO' } else { 'OK' }
    $sum = if ($schemaRow)     { 'Schema-Klasse nicht vorhanden - BadSuccessor nicht anwendbar' }
           elseif ($c -or $w)  { 'dMSA mit Superseding gefunden - BADSUCCESSOR-MUSTER PRUEFEN!' }
           elseif ($dmsaN -gt 0) { "$dmsaN dMSA-Objekt(e), kein Superseding aktiv - Objekte auf Missbrauch pruefen" }
           else                { 'Keine dMSA-Objekte - BadSuccessor-Vektor nicht vorhanden' }
    New-Assessment -OverallStatus $s -Summary $sum -Findings $f -RowFlags $rf
}

function Test-Check-MachineAccountQuota {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine MAQ-Daten' }
    $f=@(); $rf=@{}
    $row = @($data) | Select-Object -First 1
    $rf['ms-DS-MachineAccountQuota'] = switch ($row.Risk) { 'WARN' { 'WARN' } 'OK' { 'OK' } default { '' } }
    if ($row.Risk -eq 'WARN') { $f += "  [WARN] $($row.Detail)" } else { $f += "  $($row.Detail)" }
    $s = if ($row.Risk -in 'OK','WARN') { $row.Risk } else { 'NODATA' }
    New-Assessment -OverallStatus $s -Summary "MachineAccountQuota = $($row.Wert)" -Findings $f -RowFlags $rf
}

function Test-Check-AnonymousLDAP {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine LDAP-Anonym-Daten' }
    $f=@(); $rf=@{}; $c=$false; $w=$false
    foreach ($row in $data) {
        $rf[$row.Test] = switch ($row.Risk) { 'CRITICAL' { 'CRITICAL' } 'WARN' { 'WARN' } 'MEDIUM' { 'WARN' } 'OK' { 'OK' } default { '' } }
        if ($row.Risk -eq 'CRITICAL') { $c=$true; $f += "  [KRITISCH] $($row.Test): $($row.Detail)" }
        elseif ($row.Risk -in 'WARN','MEDIUM') { $w=$true; $f += "  [WARN] $($row.Test): $($row.Detail)" }
        else { $f += "  $($row.Test): $($row.Detail)" }
    }
    $s = if ($c) { 'CRITICAL' } elseif ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$(@($data).Count) Pruefpunkt(e) - anonymer LDAP-Zugriff" -Findings $f -RowFlags $rf
}

function Test-Check-GPPPasswords {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine SYSVOL-Daten' }
    $f=@(); $rf=@{}
    $hits = @($data | Where-Object { $_.Kind -eq 'Fund' })
    foreach ($row in $hits) {
        $rf[$row.Datei] = 'CRITICAL'
        if ($f.Count -lt 20) {
            $who = if ($row.Benutzer -ne '(siehe Datei)') { " ($($row.Benutzer))" } else { '' }
            $f += "  [KRITISCH] $($row.Datei)$who - cpassword gefunden"
        }
    }
    if ($hits.Count -gt 20) { $f += "  ... und $($hits.Count - 20) weitere Funde" }
    $s = if ($hits.Count -gt 0) { 'CRITICAL' } else { 'OK' }
    $sum = if ($hits.Count -gt 0) { "$($hits.Count) GPP-XML(s) mit entschluesselbarem cpassword (MS14-025)" } else { 'Keine cpassword-Eintraege in SYSVOL' }
    New-Assessment -OverallStatus $s -Summary $sum -Findings $f -RowFlags $rf
}

function Test-Check-ProtectedUsers {
    param($data); if (-not $data) { return New-Assessment -OverallStatus 'NODATA' -Summary 'Keine Protected-Users-Daten' }
    $f=@(); $rf=@{}; $w=$false
    $accounts = @($data | Where-Object { $_.Kind -eq 'Konto' })
    $inProt   = @($accounts | Where-Object { $_.InProtectedUsers -eq 'Ja' })
    $missing  = @($accounts | Where-Object { $_.InProtectedUsers -eq 'Nein' })
    foreach ($row in $data) {
        $rf[$row.Account] = switch ($row.Risk) { 'WARN' { 'WARN' } 'MEDIUM' { 'WARN' } 'OK' { 'OK' } default { '' } }
        if ($row.Risk -in 'WARN','MEDIUM') {
            $w = $true
            if ($f.Count -lt 25) { $f += "  [WARN] $($row.Account) ($($row.Gruppen)): $($row.Detail)" }
        }
    }
    if ($missing.Count -gt 25) { $f += "  ... und $($missing.Count - 25) weitere Konten ohne Protected-Users-Mitgliedschaft" }
    $s = if ($w) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $s -Summary "$($inProt.Count)/$($accounts.Count) privilegierte Konten in Protected Users" -Findings $f -RowFlags $rf
}

function Invoke-AllAssessments {
    Write-Host "`n==== BEST-PRACTICE-BEWERTUNG ====" -ForegroundColor Magenta
    $map = @{
        '00_SkippedDCs' = {
            $d = $Global:Results['00_SkippedDCs']
            if (-not $d -or @($d).Count -eq 0) { New-Assessment -OverallStatus 'OK' -Summary 'Alle DCs erreichbar' }
            else { $fd=@(); foreach ($s in $d) { $fd += "$($s.DCName): $($s.SkipReason)" }; New-Assessment -OverallStatus 'CRITICAL' -Summary "$(@($d).Count) DC(s) nicht erreichbar" -Findings $fd }
        }
        '01_DCSystemInfo'            = { Test-Check-DCSystemInfo            $Global:Results['01_DCSystemInfo'] }
        '02_Services'                = { Test-Check-Services                $Global:Results['02_Services'] }
        '03_DCDiag'                  = { Test-Check-DCDiag                  $Global:Results['03_DCDiag'] }
        '04_Replication'             = { Test-Check-Replication             $Global:Results['04_Replication'] }
        '04b_ReplicationFailures'    = { Test-Check-ReplicationFailures     $Global:Results['04b_ReplicationFailures'] }
        '05_FSMO'                    = { Test-Check-FSMO                    ($Global:Results['05_FSMO'] | Select-Object -First 1) }
        '06_DNS'                     = { Test-Check-DNS                     $Global:Results['06_DNS'] }
        '07_SYSVOL'                  = { Test-Check-SYSVOL                  $Global:Results['07_SYSVOL'] }
        '08_Database'                = { Test-Check-Database                $Global:Results['08_Database'] }
        '09_TLS'                     = { Test-Check-TLS                     $Global:Results['09_TLS'] }
        '10_Cipher'                  = { Test-Check-Cipher                  $Global:Results['10_Cipher'] }
        '11_SMB'                     = { Test-Check-SMB                     $Global:Results['11_SMB'] }
        '12_NTLMAuth'                = { Test-Check-NTLMAuth                $Global:Results['12_NTLMAuth'] }
        '13_LLMNR'                   = { Test-Check-LLMNR                   $Global:Results['13_LLMNR'] }
        '14_LDAPSecurity'            = { Test-Check-LDAPSecurity            $Global:Results['14_LDAPSecurity'] }
        '15_WindowsFirewall'         = { Test-Check-WindowsFirewall         $Global:Results['15_WindowsFirewall'] }
        '16_PrivilegedAccounts'      = { Test-Check-PrivilegedAccounts      $Global:Results['16_PrivilegedAccounts'] }
        '17_PasswordPolicy'          = { Test-Check-PasswordPolicy          $Global:Results['17_PasswordPolicy'] }
        '18_Kerberos'                = { Test-Check-Kerberos                ($Global:Results['18_Kerberos'] | Select-Object -First 1) }
        '19_UnconstrainedDelegation' = { Test-Check-UnconstrainedDelegation $Global:Results['19_UnconstrainedDelegation'] }
        '20_KerberoastingRisk'       = { Test-Check-KerberoastingRisk       $Global:Results['20_KerberoastingRisk'] }
        '21_LSAProtection'           = { Test-Check-LSAProtection           $Global:Results['21_LSAProtection'] }
        '22_PrintSpooler'            = { Test-Check-PrintSpooler            $Global:Results['22_PrintSpooler'] }
        '23_SecureBoot'              = { Test-Check-SecureBoot              $Global:Results['23_SecureBoot'] }
        '24_Certificates'            = { Test-Check-Certificates            $Global:Results['24_Certificates'] }
        '25_Sites'                   = { Test-Check-Sites                   $Global:Results['25_Sites'] }
        '26_Subnets'                 = { Test-Check-Subnets                 $Global:Results['26_Subnets'] }
        '27_Trusts'                  = { Test-Check-Trusts                  $Global:Results['27_Trusts'] }
        '28_ADRecycleBin'            = { Test-Check-ADRecycleBin            ($Global:Results['28_ADRecycleBin']      | Select-Object -First 1) }
        '29_TombstoneLifetime'       = { Test-Check-TombstoneLifetime       ($Global:Results['29_TombstoneLifetime'] | Select-Object -First 1) }
        '30_Levels'                  = { Test-Check-Levels                  ($Global:Results['30_Levels']            | Select-Object -First 1) }
        '31_GPO'                     = { Test-Check-GPO                     $Global:Results['31_GPO'] }
        '32a_InactiveUsers'          = { Test-Check-InactiveUsers           $Global:Results['32a_InactiveUsers'] }
        '32b_InactiveComputers'      = { Test-Check-InactiveComputers       $Global:Results['32b_InactiveComputers'] }
        '32c_PasswordNeverExpires'   = { Test-Check-PasswordNeverExpires    $Global:Results['32c_PasswordNeverExpires'] }
        '33_EventLog'                = { Test-Check-EventLog                $Global:Results['33_EventLog'] }
        '34_TimeSync'                = { Test-Check-TimeSync                $Global:Results['34_TimeSync'] }
        '35_Backup'                  = { Test-Check-Backup                  ($Global:Results['35_Backup'] | Select-Object -First 1) }
        '36_InstalledPrograms'       = { Test-Check-InstalledPrograms       $Global:Results['36_InstalledPrograms'] }
        '37_WindowsUpdates'          = { Test-Check-WindowsUpdates          $Global:Results['37_WindowsUpdates'] }
        '38_SPNDuplicates'           = { Test-Check-SPNDuplicates           $Global:Results['38_SPNDuplicates'] }
        '39_ASREPRoasting'           = { Test-Check-ASREPRoasting           $Global:Results['39_ASREPRoasting'] }
        '40_AdminSDHolderDrift'      = { Test-Check-AdminSDHolderDrift      $Global:Results['40_AdminSDHolderDrift'] }
        '41_FGPP'                    = { Test-Check-FGPP                    $Global:Results['41_FGPP'] }
        '42_DNSHygiene'              = { Test-Check-DNSHygiene              $Global:Results['42_DNSHygiene'] }
        '43_LAPS'                    = { Test-Check-LAPS                    $Global:Results['43_LAPS'] }
        '44_AccountsWithoutAES'      = { Test-Check-AccountsWithoutAES      $Global:Results['44_AccountsWithoutAES'] }
        '45_WindowsFeatures'         = { Test-Check-WindowsFeatures         $Global:Results['45_WindowsFeatures'] }
        '46_Shares'                  = { Test-Check-Shares                  $Global:Results['46_Shares'] }
        '47_RCAESMigration'          = { Test-Check-RCAESMigration          $Global:Results['47_RCAESMigration'] }
        '48_DCSyncPermissions'       = { Test-Check-DCSyncPermissions       $Global:Results['48_DCSyncPermissions'] }
        '49_RBCDDelegation'          = { Test-Check-RBCDDelegation          $Global:Results['49_RBCDDelegation'] }
        '50_dMSA'                    = { Test-Check-dMSA                    $Global:Results['50_dMSA'] }
        '51_MachineAccountQuota'     = { Test-Check-MachineAccountQuota     $Global:Results['51_MachineAccountQuota'] }
        '52_AnonymousLDAP'           = { Test-Check-AnonymousLDAP           $Global:Results['52_AnonymousLDAP'] }
        '53_GPPPasswords'            = { Test-Check-GPPPasswords            $Global:Results['53_GPPPasswords'] }
        '54_ProtectedUsers'          = { Test-Check-ProtectedUsers          $Global:Results['54_ProtectedUsers'] }
        '60_ZonenSOA'                = { Test-Check-ZonenSOA              $Global:Results['60_ZonenSOA'] }
        '61_Forwarder'               = { Test-Check-ConditionalForwarders  $Global:Results['61_Forwarder'] }
        '62_ReverseLookup'           = { Test-Check-ReverseLookupComplete  $Global:Results['62_ReverseLookup'] }
    }
    $toAssess = @()
    foreach ($k in $Global:ReportTitles.Keys) {
        if ($k -eq '00_SkippedDCs') { if ($Global:Results[$k] -and @($Global:Results[$k]).Count -gt 0) { $toAssess += $k }; continue }
        if ($Global:SelectedChecks -contains $k) { $toAssess += $k }
    }
    foreach ($k in $toAssess) {
        try {
            $a = if ($map.Contains($k)) { & $map[$k] } else { New-Assessment -OverallStatus 'INFO' -Summary 'Keine Bewertung' }
            $Global:Assessments[$k] = $a
            $ic = switch ($a.OverallStatus) { 'OK'{'[OK] '} 'WARN'{'[!!] '} 'CRITICAL'{'[XX] '} 'INFO'{'[i]  '} 'NODATA'{'[-]  '} }
            $co = switch ($a.OverallStatus) { 'OK'{'Green'} 'WARN'{'Yellow'} 'CRITICAL'{'Red'} 'INFO'{'Cyan'} 'NODATA'{'DarkGray'} }
            Write-Host ("  {0} {1,-55} {2}" -f $ic, $Global:ReportTitles[$k], $a.Summary) -ForegroundColor $co
        } catch {
            Write-Log "Assessment '$k': $_" -Level WARN -NoConsole
            $Global:Assessments[$k] = New-Assessment -OverallStatus 'INFO' -Summary "Fehler: $_"
        }
    }
}

#endregion
#region ============= EXPORT ================================================

function Export-ResultsToCsv {
    Write-Host "`n==== CSV-EXPORT ====" -ForegroundColor Magenta
    foreach ($k in Get-ReportKeys) {
        try {
            $d = $Global:Results[$k]
            $p = Join-Path $Global:CsvDirectory "$k.csv"
            if ($null -eq $d -or @($d).Count -eq 0) {
                Write-Host ("  [-] {0,-32} -> leer" -f $k) -ForegroundColor DarkGray
                (Format-L10n -Text 'Keine Eintraege.') | Out-File -FilePath $p -Encoding UTF8 -ErrorAction SilentlyContinue
                continue
            }
            # Interne '_'-Felder beim Export ausblenden
            $firstItem = @($d) | Select-Object -First 1
            $cols = $firstItem.PSObject.Properties |
                    Where-Object { $_.Name -notlike '_*' } |
                    Select-Object -ExpandProperty Name
            $d | Select-Object $cols | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host ("  [+] {0,-32} -> {1,4} Eintraege" -f $k, @($d).Count) -ForegroundColor Green
        } catch {
            Write-Host ("  [X] {0,-32} -> $_" -f $k) -ForegroundColor Red
        }
    }
}

function Get-StatusBadgeHtml {
    <#
    .SYNOPSIS
        Status-Badge fuer HTML - nur Text, kein doppeltes Icon.
        Beschriftung folgt der gewaehlten Sprache (de/en).
    #>
    param([string]$Status)
    $cfg = switch ($Status) {
        'OK'       { @{ Text='OK';          Class='badge-ok' } }
        'WARN'     { @{ Text=$(if ($Global:Lang -eq 'en') { 'WARNING'  } else { 'WARNUNG'    }); Class='badge-warn' } }
        'CRITICAL' { @{ Text=$(if ($Global:Lang -eq 'en') { 'CRITICAL' } else { 'KRITISCH'   }); Class='badge-critical' } }
        'INFO'     { @{ Text='INFO';        Class='badge-info' } }
        'NODATA'   { @{ Text=$(if ($Global:Lang -eq 'en') { 'NO DATA'  } else { 'KEINE DATEN' }); Class='badge-nodata' } }
        default    { @{ Text=$Status;       Class='badge-info' } }
    }
    "<span class='badge $($cfg.Class)'>$($cfg.Text)</span>"
}

function New-HtmlReport {
    try {
        Write-Host "`n==== HTML-REPORT ====" -ForegroundColor Magenta
        $head = @"
<meta charset='UTF-8'>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;margin:20px;background:#f5f5f7;color:#1a1a1a;}
h1{color:#003366;border-bottom:3px solid #003366;padding-bottom:8px;}
h2{color:#0066aa;padding:8px 10px;margin-top:30px;border-left:6px solid #0066aa;background:#b4ddfa;}
h2 .badge{float:right;margin-top:-2px;}
table{border-collapse:collapse;width:100%;background:#fff;margin:10px 0 20px 0;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
th{background:#003366;color:#fff;padding:8px;text-align:left;font-size:13px;}
td{border:1px solid #e0e0e0;padding:5px 8px;font-size:12px;vertical-align:top;}
tr:nth-child(even){background:#fafafa;}
.badge{
    display:inline-block;
    min-width:120px;
    padding:4px 12px;
    border-radius:12px;
    font-size:11px;
    font-weight:bold;
    letter-spacing:0.5px;
    text-align:center;
    box-sizing:border-box;
    white-space:nowrap;
}
.badge-ok{background:#28a745;color:#fff;}
.badge-warn{background:#ffc107;color:#000;}
.badge-critical{background:#dc3545;color:#fff;}
.badge-info{background:#17a2b8;color:#fff;}
.badge-nodata{background:#6c757d;color:#fff;}
.dashboard{background:#fff;padding:15px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:25px;}
.dash-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:10px;}
.dash-tile{padding:15px;border-radius:6px;text-align:center;color:#fff;font-weight:bold;min-height:80px;}
.dash-tile .n{font-size:32px;display:block;}
.dash-tile .l{font-size:12px;letter-spacing:1px;}
.dash-ok{background:#28a745;} .dash-warn{background:#ffc107;color:#000;}
.dash-crit{background:#dc3545;} .dash-info{background:#17a2b8;}
.overview th,.overview td{text-align:left;} .overview .status-cell{width:150px;}
.findings{background:#fff3cd;border-left:4px solid #ffc107;padding:10px;margin:10px 0;}
.findings.crit{background:#f8d7da;border-left-color:#dc3545;}
.findings ul{margin:5px 0 5px 20px;}
tr.row-warn{background:#fff3cd !important;}
tr.row-crit{background:#f8d7da !important;}
.group-banner{background:#003366;color:#fff;padding:10px 12px;margin-top:30px;border-radius:6px;font-size:16px;font-weight:bold;}
tr.group-row td{background:#003366;color:#fff;font-weight:bold;padding:6px 8px;}
.overview tbody tr:hover { background:#8ecdfa; cursor:pointer; }
.footer{margin-top:40px;padding:15px;color:#777;font-size:11px;text-align:center;border-top:1px solid #ddd;}
</style>
"@
        # Dashboard-Zaehler (nur ausgewaehlte Checks)
        $cOK=0; $cW=0; $cC=0; $cI=0; $cN=0
        foreach ($k in Get-ReportKeys) {
            $a = $Global:Assessments[$k]; if (-not $a) { continue }
            switch ($a.OverallStatus) { 'OK'{$cOK++} 'WARN'{$cW++} 'CRITICAL'{$cC++} 'INFO'{$cI++} 'NODATA'{$cN++} }
        }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<!DOCTYPE html><html lang='$Global:Lang'><head><title>AD Health Check Report - $Global:Timestamp</title>$head</head><body>")
        [void]$sb.AppendLine("<h1>Active Directory Health Check Report</h1>")
        [void]$sb.AppendLine("<p><b>$(Format-L10n -Text 'Erstellt:')</b> $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') &nbsp;|&nbsp; <b>Version:</b> $Global:ScriptVersion &nbsp;|&nbsp; <b>$(Format-L10n -Text 'Modus:')</b> $Global:RunMode &nbsp;|&nbsp; <b>$(Format-L10n -Text 'Sprache:')</b> $($Global:Lang.ToUpper())</p>")

        # --- Executive Dashboard ---
        [void]$sb.AppendLine("<div class='dashboard'><h2 style='margin-top:0;border:none;background:none;'>Executive Dashboard</h2><div class='dash-grid'>")
        [void]$sb.AppendLine("<div class='dash-tile dash-ok'><span class='n'>$cOK</span><span class='l'>OK</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-warn'><span class='n'>$cW</span><span class='l'>$(Format-L10n -Text 'WARNUNGEN')</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-crit'><span class='n'>$cC</span><span class='l'>$(Format-L10n -Text 'KRITISCH')</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-info'><span class='n'>$($cI+$cN)</span><span class='l'>INFO</span></div>")
        [void]$sb.AppendLine("</div></div>")

        # --- Uebersichts-Tabelle (gruppiert nach GUI-Kategorien) ---
        [void]$sb.AppendLine("<h2>$(Format-L10n -Text 'Uebersicht aller Checks')</h2>")
        [void]$sb.AppendLine("<table class='overview'><thead><tr><th style='width:40px;'>#</th><th>$(Format-L10n -Text 'Check')</th><th class='status-cell'>$(Format-L10n -Text 'Status')</th><th>$(Format-L10n -Text 'Zusammenfassung')</th></tr></thead><tbody>")
        $i = 0
        foreach ($cat in (Get-GroupedReportKeys).Keys) {
            $catKeys = (Get-GroupedReportKeys)[$cat]
            [void]$sb.AppendLine("<tr class='group-row'><td colspan='4'>$(Format-L10n -Text $cat)</td></tr>")
            foreach ($k in $catKeys) {
                $t = Format-L10n -Text $Global:ReportTitles[$k]
                $a = $Global:Assessments[$k]
                if (-not $a) { continue }
                $i++
                $b = Get-StatusBadgeHtml -Status $a.OverallStatus
                $s = if ($a.Summary) { Format-L10n -Text $a.Summary } else { '-' }
                [void]$sb.AppendLine("<tr><td>$i</td><td><a href='#$k'>$t</a></td><td>$b</td><td>$s</td></tr>")
            }
        }
        [void]$sb.AppendLine("</tbody></table>")

                # --- Detail-Abschnitte (gruppiert nach GUI-Kategorien) ---
        $j = 0
        foreach ($cat in (Get-GroupedReportKeys).Keys) {
        [void]$sb.AppendLine("<div class='group-banner'>$(Format-L10n -Text $cat)</div>")
        foreach ($k in (Get-GroupedReportKeys)[$cat]) {
            $t = Format-L10n -Text $Global:ReportTitles[$k]
            $a = $Global:Assessments[$k]
            if (-not $a) { continue }
            $j++
            $b = Get-StatusBadgeHtml -Status $a.OverallStatus
            [void]$sb.AppendLine("<h2 id='$k'>$j. $t $b</h2>")

            if ($a.Summary) { [void]$sb.AppendLine("<p><b>$(Format-L10n -Text 'Zusammenfassung:')</b> $(Format-L10n -Text $a.Summary)</p>") }
            if ($a.Findings -and @($a.Findings).Count -gt 0) {
                $fc = if ($a.OverallStatus -eq 'CRITICAL') { 'findings crit' } else { 'findings' }
                [void]$sb.AppendLine("<div class='$fc'><b>$(Format-L10n -Text 'Auffaelligkeiten / Handlungsempfehlungen:')</b><ul>")
                foreach ($x in $a.Findings) {
                    $e = Format-L10n -Text "$x"
                    $e = $e -replace '<','&lt;' -replace '>','&gt;'
                    [void]$sb.AppendLine("<li>$e</li>")
                }
                [void]$sb.AppendLine("</ul></div>")
            }

            $items = $Global:Results[$k]
            if ($null -eq $items -or @($items).Count -eq 0) {
                [void]$sb.AppendLine("<p><i>$(Format-L10n -Text 'Keine Daten.')</i></p>")
                Write-Host ("  [-] {0,-32} -> leer" -f $k) -ForegroundColor DarkGray
                continue
            }
            try {
                if ($a.RowFlags -and $a.RowFlags.Count -gt 0) {
                    # Spalten-Reihenfolge aus erstem Objekt uebernehmen + '_'-Felder ausblenden
                    $firstItem = @($items) | Select-Object -First 1
                    $props = $firstItem.PSObject.Properties |
                                Where-Object { $_.Name -notlike '_*' } |
                                Select-Object -ExpandProperty Name

                    [void]$sb.AppendLine("<table><thead><tr>")
                    foreach ($p in $props) { [void]$sb.AppendLine("<th>$(Format-L10n -Text $p)</th>") }
                    [void]$sb.AppendLine("</tr></thead><tbody>")

                    foreach ($row in $items) {
                        # Row-ID je nach Check-Typ ermitteln (fuer Zeilenfaerbung)
                        $rid = switch ($k) {
                            '02_Services'                { "$($row.DCName)|$($row.Service)" }
                            '03_DCDiag'                  { "$($row.DCName)|$($row.Category)|$($row.PartitionOrScope)|$($row.TestName)" }
                            '04_Replication'             { "$($row.Server)|$($row.Partner)" }
                            '06_DNS'                     { "$($row.DCName)|$($row.ZoneName)" }
                            '07_SYSVOL'                  { $row.DCName }
                            '08_Database'                { $row.DCName }
                            '09_TLS'                     { "$($row.DCName)|$($row.Protocol)|$($row.Side)" }
                            '10_Cipher'                  { "$($row.DCName)|$($row.Cipher)" }
                            '11_SMB'                     { $row.DCName }
                            '12_NTLMAuth'                { $row.DCName }
                            '13_LLMNR'                   { $row.DCName }
                            '14_LDAPSecurity'            { $row.DCName }
                            '15_WindowsFirewall'         { "$($row.DCName)|$($row.Profile)" }
                            '19_UnconstrainedDelegation' { "$($row.Type)|$($row.SamAccount)" }
                            '20_KerberoastingRisk'       { $row.SamAccount }
                            '21_LSAProtection'           { $row.DCName }
                            '22_PrintSpooler'            { $row.DCName }
                            '23_SecureBoot'              { $row.DCName }
                            '24_Certificates'            { "$($row.DCName)|$($row.Store)|$($row.Thumbprint)" }
                            '31_GPO'                     { "$($row.Id)" }
                            '34_TimeSync'                { $row.DCName }
                            '37_WindowsUpdates'          { "$($row.DCName)|$($row.HotFixID)" }
                            '38_SPNDuplicates'           { "$($row.SPN)|$($row.SamAccount)" }
                            '39_ASREPRoasting'           { $row.SamAccount }
                            '40_AdminSDHolderDrift'      { $row.SamAccount }
                            '41_FGPP'                    { $row.Name }
                            '42_DNSHygiene'              { "$($row.Kind)|$($row.Target)" }
                            '45_WindowsFeatures'         { "$($row.DCName)|$($row.Name)" }
                            '46_Shares'                  { "$($row.DCName)|$($row.Name)" }
                            '47_RCAESMigration'          { "$($row.Kind)|$($row.Name)" }
                            '48_DCSyncPermissions'       { "$($row.Kind)|$($row.SID)" }
                            '49_RBCDDelegation'          { "$($row.Kind)|$($row.Name)|$($row.Prinzipal)" }
                            '50_dMSA'                    { "$($row.Kind)|$($row.Name)" }
                            '51_MachineAccountQuota'     { $row.Einstellung }
                            '52_AnonymousLDAP'           { $row.Test }
                            '53_GPPPasswords'            { $row.Datei }
                            '54_ProtectedUsers'          { $row.Account }
                            default                      { '' }
                        }
                        $cls = ''
                        if ($a.RowFlags.ContainsKey($rid)) {
                            $cls = switch ($a.RowFlags[$rid]) { 'CRITICAL'{'row-crit'} 'WARN'{'row-warn'} default{''} }
                        }
                        [void]$sb.AppendLine("<tr class='$cls'>")
                        foreach ($p in $props) {
                            $v = $row.$p
                            if ($v -is [datetime]) { $v = $v.ToString('yyyy-MM-dd HH:mm:ss') }
                            $v = Format-L10n -Text $v
                            $ve = "$v" -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
                            [void]$sb.AppendLine("<td>$ve</td>")
                        }
                        [void]$sb.AppendLine("</tr>")
                    }
                    [void]$sb.AppendLine("</tbody></table>")
                } else {
                    # Fallback: ConvertTo-Html aber '_'-Felder rausfiltern
                    $firstItem = @($items) | Select-Object -First 1
                    $props = $firstItem.PSObject.Properties |
                                Where-Object { $_.Name -notlike '_*' } |
                                Select-Object -ExpandProperty Name
                    $localized = foreach ($row in $items) {
                        $h = [ordered]@{}
                        foreach ($p in $props) { $h[(Format-L10n -Text $p)] = (Format-L10n -Text $row.$p) }
                        [pscustomobject]$h
                    }
                    [void]$sb.AppendLine(($localized | ConvertTo-Html -Fragment))
                }
                Write-Host ("  [+] {0,-32} -> {1,4} Zeilen (Status: {2})" -f $k, @($items).Count, $a.OverallStatus) -ForegroundColor Green
            } catch {
                [void]$sb.AppendLine("<pre>$($items | Out-String)</pre>")
                Write-Host ("  [!] {0,-32} -> Fallback" -f $k) -ForegroundColor Yellow
            }
        }
        }

        [void]$sb.AppendLine((Format-L10n -Text "<div class='footer'>Erzeugt von <b>$Global:ScriptName v$Global:ScriptVersion</b> &nbsp;|&nbsp; $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') &nbsp;|&nbsp; Laufzeit: $((New-TimeSpan -Start $Global:ProgressStats.StartTime -End (Get-Date)).ToString('hh\:mm\:ss'))</div>"))
        [void]$sb.AppendLine("</body></html>")
        $sb.ToString() | Out-File -FilePath $Global:HtmlReport -Encoding UTF8
        Write-Log "HTML-Report erstellt: $Global:HtmlReport" -Level OK
    } catch { Write-Log "HTML-Report Fehler: $_" -Level ERROR }
}

#endregion

#region ======================= RECHTE-ERHOEHUNG =============================

function Test-IsElevated {
    <# Prueft, ob das Skript mit Administratorrechten laeuft. #>
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pri = New-Object Security.Principal.WindowsPrincipal($id)
        return [bool]$pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-ElevationCommand {
    <#
    .SYNOPSIS
        Baut Programm und Argumentliste fuer einen Neustart mit Administratorrechten.
    .NOTES
        Alle uebergebenen Parameter (-FullRun, -OnlyChecks, -OutputPath, -Language ...)
        werden erhalten bleiben, damit der erhoehte Lauf identisch ist.
        -NoElevate wird NICHT mitgegeben - sonst wuerde sich die erhoehte Instanz
        selbst wieder degradieren.
    #>
    param([hashtable]$BoundParameters = @{}, [string]$ScriptPath)
    $exe = $null
    try { $exe = (Get-Process -Id $PID).Path } catch {}
    # ISE oder Editor-Host: lieber die klassische powershell.exe verwenden
    if (-not $exe -or $exe -match '(?i)powershell_ise|Code\.exe|WindowsTerminal|openconsole') {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not (Test-Path -LiteralPath $exe)) { $exe = 'powershell.exe' }

    $a = New-Object System.Collections.Generic.List[string]
    [void]$a.Add('-NoProfile')
    [void]$a.Add('-ExecutionPolicy'); [void]$a.Add('Bypass')
    [void]$a.Add('-File');            [void]$a.Add(('"{0}"' -f $ScriptPath))
    foreach ($k in ($BoundParameters.Keys | Sort-Object)) {
        if ($k -ieq 'NoElevate') { continue }
        $v = $BoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { [void]$a.Add("-$k") }
        }
        elseif ($v -is [System.Array]) {
            foreach ($item in $v) { [void]$a.Add("-$k"); [void]$a.Add(('"{0}"' -f $item)) }
        }
        else { [void]$a.Add("-$k"); [void]$a.Add(('"{0}"' -f $v)) }
    }
    [pscustomobject]@{ Exe = $exe; Arguments = $a }
}

function Start-ElevatedRestart {
    <#
    .SYNOPSIS
        Startet das Skript mit Administratorrechten neu und beendet diese Instanz.
    .NOTES
        Bricht der Benutzer die UAC-Abfrage ab, wird false zurueckgegeben und im
        aktuellen Kontext weitergemacht - einzelne Checks werden dann fehlschlagen.
    #>
    param([hashtable]$BoundParameters)
    if (-not $PSCommandPath) { return $false }
    $cmd = Get-ElevationCommand -BoundParameters $BoundParameters -ScriptPath $PSCommandPath
    Write-Host ''
    Write-Host (Format-L10n -Text '  [i] Administratorrechte fehlen - DNS-/WMI-Abfragen werden ohne erhoehte Rechte abgelehnt.') -ForegroundColor Yellow
    Write-Host (Format-L10n -Text '  [i] Starte das Skript mit Administratorrechten neu (UAC-Bestaetigung erforderlich).') -ForegroundColor Yellow
    Write-Log 'Keine Administratorrechte - Neustart mit erhoehten Rechten.' -Level WARN -NoConsole
    try {
        Start-Process -FilePath $cmd.Exe -ArgumentList $cmd.Arguments -Verb RunAs -ErrorAction Stop
        Write-Host (Format-L10n -Text '  [i] Die erhoehte Instanz wurde gestartet; dieses Fenster kann geschlossen werden.') -ForegroundColor Gray
        return $true
    } catch {
        Write-Host (Format-L10n -Text "  [!] Neustart abgelehnt oder fehlgeschlagen: $_") -ForegroundColor Red
        Write-Host (Format-L10n -Text '  [i] Es wird ohne erhoehte Rechte weitergemacht - einzelne Checks werden fehlschlagen.') -ForegroundColor Yellow
        Write-Log "Elevation abgelehnt: $_" -Level WARN -NoConsole
        return $false
    }
}

#endregion

#region ============= MAIN ===================================================

function Start-ADHealthCheck {
    try {
        Initialize-LogEnvironment
        $Global:ProgressStats.StartTime = Get-Date

        # --- Rechte-Erhoehung ---
        # Ohne Administratorrechte lehnt Windows die DNS-/WMI-Abfragen ab (z.B.
        # root\MicrosoftDNS), sodass Checks 7-9 leer bleiben. Deshalb einmalig
        # neu starten; $Global:ElevationHandled verhindert eine Endlosschleife.
        if (-not $Global:ElevationHandled -and -not $NoElevate -and -not (Test-IsElevated)) {
            $Global:ElevationHandled = $true
            if (Start-ElevatedRestart -BoundParameters $PSBoundParameters) { return }
        }

        $skippedDCs   = @()
        $reachableDCs = @()

        # --- Update-Check (nur Infozeile; GUI zeigt stattdessen das Badge) ---
        # Fehler, Offline und Proxy-Sperren bleiben folgenlos (Timeout 3 s)
        $guiMode = -not ($FullRun -or $NoInteractive -or ($OnlyChecks -and $OnlyChecks.Count -gt 0))
        if (-not $guiMode -and -not $Global:NoUpdateCheck) {
            $upd = Get-RemoteReleaseInfo
            if ($upd.UpdateAvailable) {
                Write-Host "  [i] Update verfügbar: $($upd.LatestTag) (aktuell v$Global:ScriptVersion) - $($upd.Url)" -ForegroundColor Yellow
            }
        }

        # --- Modus-Ermittlung (Parameter oder interaktives Menue) ---
        if ($FullRun) {
            $Global:RunMode = 'Full'
            $Global:SelectedChecks = @($Global:ReportTitles.Keys | Where-Object { $_ -ne '00_SkippedDCs' })
        }
        elseif ($OnlyChecks -and $OnlyChecks.Count -gt 0) {
            $valid = @(); $invalid = @()
            foreach ($c in $OnlyChecks) {
                if ($Global:ReportTitles.Contains($c)) { $valid += $c }
                else {
                    $m = $Global:ReportTitles.Keys | Where-Object { $_ -ilike "*$c*" -and $_ -ne '00_SkippedDCs' }
                    if (@($m).Count -eq 1) { $valid += $m } else { $invalid += $c }
                }
            }
            if ($invalid.Count -gt 0) {
                Write-Host "[X] Ungueltige Check-Keys: $($invalid -join ', ')" -ForegroundColor Red
                Write-Host "[i] Verfuegbar: $($Global:ReportTitles.Keys -join ', ')" -ForegroundColor Yellow
                throw "Ungueltige Checks angegeben."
            }
            $Global:RunMode = if ($valid.Count -eq 1) { 'Single' } else { 'Multi' }
            $Global:SelectedChecks = @($valid)
        }
        elseif ($NoInteractive) {
            $Global:RunMode = 'Full'
            $Global:SelectedChecks = @($Global:ReportTitles.Keys | Where-Object { $_ -ne '00_SkippedDCs' })
        }
        else {
            # GUI starten
            $guiResult = Show-HealthCheckGUI
            if ($guiResult.Cancelled) {
                Write-Host "[!] Abbruch durch Benutzer." -ForegroundColor Yellow
                return
            }
            # Gewaehlte Sprache uebernehmen (GUI-Schalter schlaegt Betriebssystemsprache)
            if ($guiResult.Language) { $Global:Lang = $guiResult.Language }
            $Global:SelectedChecks = @($guiResult.SelectedChecks)
            $Global:RunMode = if ($guiResult.SelectedChecks.Count -eq @($Global:ReportTitles.Keys | Where-Object { $_ -ne '00_SkippedDCs' }).Count) { 'Full' }
                              elseif ($guiResult.SelectedChecks.Count -eq 1) { 'Single' }
                              else { 'Multi' }
            # Ausgabepfad uebernehmen
            if ($guiResult.OutputPath -and $guiResult.OutputPath -ne $Global:LogDirectory) {
                $Global:LogDirectory    = $guiResult.OutputPath
                $Global:ReportDirectory = Join-Path $Global:LogDirectory "AD_HealthCheck_$Global:Timestamp"
                $Global:LogFile         = Join-Path $Global:LogDirectory "$Global:ScriptName`_$Global:Timestamp.log"
                $Global:HtmlReport      = Join-Path $Global:ReportDirectory "AD_HealthCheck_Report_$Global:Timestamp.html"
                $Global:CsvDirectory    = Join-Path $Global:ReportDirectory "CSV"
            }
        }

        # --- Banner ---
        Clear-Host
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host "    AD HEALTH CHECK v$Global:ScriptVersion - Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        Write-Host ("    Modus: {0} ({1} Check(s))" -f $Global:RunMode, $Global:SelectedChecks.Count) -ForegroundColor Yellow
        Write-Host "    Report: $Global:ReportDirectory" -ForegroundColor DarkCyan
        if ($Global:RunMode -ne 'Full') {
            Write-Host "    Ausgewaehlte Checks:" -ForegroundColor Yellow
            foreach ($k in $Global:SelectedChecks) {
                Write-Host ("      - {0}" -f $Global:ReportTitles[$k]) -ForegroundColor Gray
            }
        }
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host ""

        Write-Log "==================== AD HEALTH CHECK START ====================" -Level INFO -NoConsole
        Write-Log ("Modus: {0} | Checks: {1}" -f $Global:RunMode, ($Global:SelectedChecks -join ', ')) -Level INFO -NoConsole

        Import-RequiredModules
        Initialize-ResultKeys

        # --- DCs abfragen ---
        Write-Host "`n==== DC-ERKENNUNG ====" -ForegroundColor Magenta
        $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
        $dcCount = @($allDCs).Count
        Write-Host ("  [+] Gefundene DCs: {0}" -f $dcCount) -ForegroundColor Green
        foreach ($dc in $allDCs) { Write-Host ("      - {0} (Site: {1})" -f $dc.HostName, $dc.Site) -ForegroundColor Gray }

        $pdcEmulator = ''
        try { $pdcEmulator = (Get-ADDomain -ErrorAction Stop).PDCEmulator } catch {}

        # --- Connectivity-Test ---
        Write-Host "`n==== CONNECTIVITY-TEST ====" -ForegroundColor Magenta
        foreach ($dc in $allDCs) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $conn = Test-DCConnectivity -DCName $dc.HostName
            $sw.Stop()
            $Global:DCConnectivity[$dc.HostName] = $conn

            $skip = ($Global:SkipUnreachableDCs -and -not $conn.Reachable)
            if ($skip) {
                $skippedDCs += $conn
                Write-Host ("  [X] {0,-30} -> UEBERSPRUNGEN: {1}" -f $dc.HostName, $conn.SkipReason) -ForegroundColor Red
                Write-Log ("DC '{0}' uebersprungen: {1}" -f $dc.HostName, $conn.SkipReason) -Level WARN -NoConsole
            } else {
                $reachableDCs += $dc
                $icon  = if ($conn.Method -ne 'None') { '[+]' } else { '[!]' }
                $color = if ($conn.Method -ne 'None') { 'Green' } else { 'Yellow' }
                $extra = ''
                if ($conn.IsLocalComputer) { $extra += ' [LOKAL]' }
                if ($conn.WinRM_Loopback)  { $extra += ' [via localhost]' }
                if (-not $conn.Ping -and $conn.Reachable) { $extra += ' [kein Ping, aber WinRM OK]' }
                Write-Host ("  {0} {1,-30} -> Methode: {2}{3}  ({4:N2}s)" -f `
                    $icon, $dc.HostName, $conn.Method, $extra, $sw.Elapsed.TotalSeconds) -ForegroundColor $color
            }
            $Global:ProgressStats.CompletedChecks++
        }
        Write-Host ""
        Write-Host ("  Gesamt: {0} DCs | Erreichbar: {1} | Uebersprungen: {2}" -f `
            $dcCount, @($reachableDCs).Count, @($skippedDCs).Count) `
            -ForegroundColor $(if (@($skippedDCs).Count -gt 0) { 'Yellow' } else { 'Green' })

        if (@($skippedDCs).Count -gt 0) {
            $Global:Results['00_SkippedDCs'] = @($skippedDCs | Select-Object DCName, IsLocalComputer, Ping, WinRM, CIM_DCOM, WMI, Reachable, SkipReason, ErrorMsg)
        }

        # --- TotalChecks dynamisch berechnen ---
        $dcCountReachable = @($reachableDCs).Count
        $selPerDC  = @('01_DCSystemInfo','02_Services','03_DCDiag','04_Replication','06_DNS','07_SYSVOL','08_Database',
                       '09_TLS','10_Cipher','11_SMB','12_NTLMAuth','13_LLMNR','14_LDAPSecurity','15_WindowsFirewall',
                       '21_LSAProtection','22_PrintSpooler','23_SecureBoot','24_Certificates',
                       '33_EventLog','34_TimeSync','36_InstalledPrograms','37_WindowsUpdates',
               '45_WindowsFeatures','46_Shares') |
                     Where-Object { $Global:SelectedChecks -contains $_ }
        $selForest = @('04b_ReplicationFailures','05_FSMO','16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos',
                       '19_UnconstrainedDelegation','20_KerberoastingRisk','25_Sites','26_Subnets','27_Trusts',
                                             '28_ADRecycleBin','29_TombstoneLifetime','30_Levels','31_GPO','35_Backup',
                                             '38_SPNDuplicates','39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','42_DNSHygiene','43_LAPS','44_AccountsWithoutAES',
                                             '47_RCAESMigration','48_DCSyncPermissions','49_RBCDDelegation','50_dMSA',
                                             '51_MachineAccountQuota','52_AnonymousLDAP','53_GPPPasswords','54_ProtectedUsers') |
                     Where-Object { $Global:SelectedChecks -contains $_ }
        $selInact = if ((Test-IsCheckSelected '32a_InactiveUsers') -or (Test-IsCheckSelected '32b_InactiveComputers') -or (Test-IsCheckSelected '32c_PasswordNeverExpires')) { 1 } else { 0 }
        $Global:ProgressStats.TotalChecks = ($selPerDC.Count * $dcCountReachable) + $selForest.Count + $selInact + $dcCount

        # --- Pro-DC-Checks ---
        Write-Host "`n==== PRO-DC-CHECKS ====" -ForegroundColor Magenta
        if ($dcCountReachable -eq 0) {
            Write-Host "  [!] Keine erreichbaren DCs - uebersprungen" -ForegroundColor Yellow
        } else {
            foreach ($dc in $reachableDCs) {
                $dcName = $dc.HostName
                $Global:ProgressStats.CurrentDC = $dcName
                Write-Host "`n  ------- DC: $dcName -------" -ForegroundColor White

                if (Test-IsCheckSelected '01_DCSystemInfo')     { $r = Invoke-TimedCheck -CheckKey '01_DCSystemInfo'     -DCName $dcName -ScriptBlock { Get-DCSystemInfo          -DC $dcName }; if ($r) { $Global:Results['01_DCSystemInfo']    += $r } }
                if (Test-IsCheckSelected '02_Services')         { $r = Invoke-TimedCheck -CheckKey '02_Services'         -DCName $dcName -ScriptBlock { Get-DCServiceStatus       -DC $dcName }; if ($r) { $Global:Results['02_Services']        += $r } }
                if (Test-IsCheckSelected '03_DCDiag')           { $r = Invoke-TimedCheck -CheckKey '03_DCDiag'           -DCName $dcName -ScriptBlock { Invoke-DCDiag             -DC $dcName }; if ($r) { $Global:Results['03_DCDiag']          += $r } }
                if (Test-IsCheckSelected '04_Replication')      { $r = Invoke-TimedCheck -CheckKey '04_Replication'      -DCName $dcName -ScriptBlock { Get-ReplicationPartners   -DC $dcName }; if ($r) { $Global:Results['04_Replication']     += $r } }
                if (Test-IsCheckSelected '06_DNS')              { $r = Invoke-TimedCheck -CheckKey '06_DNS'              -DCName $dcName -ScriptBlock { Get-DNSConfiguration      -DC $dcName }; if ($r) { $Global:Results['06_DNS']             += $r } }
                if (Test-IsCheckSelected '07_SYSVOL')           { $r = Invoke-TimedCheck -CheckKey '07_SYSVOL'           -DCName $dcName -ScriptBlock { Get-SysvolStatus          -DC $dcName }; if ($r) { $Global:Results['07_SYSVOL']          += $r } }
                if (Test-IsCheckSelected '08_Database')         { $r = Invoke-TimedCheck -CheckKey '08_Database'         -DCName $dcName -ScriptBlock { Get-NTDSDatabase          -DC $dcName }; if ($r) { $Global:Results['08_Database']        += $r } }
                if (Test-IsCheckSelected '09_TLS')              { $r = Invoke-TimedCheck -CheckKey '09_TLS'              -DCName $dcName -ScriptBlock { Get-TLSConfiguration      -DC $dcName }; if ($r) { $Global:Results['09_TLS']             += $r } }
                if (Test-IsCheckSelected '10_Cipher')           { $r = Invoke-TimedCheck -CheckKey '10_Cipher'           -DCName $dcName -ScriptBlock { Get-CipherConfiguration   -DC $dcName }; if ($r) { $Global:Results['10_Cipher']          += $r } }
                if (Test-IsCheckSelected '11_SMB')              { $r = Invoke-TimedCheck -CheckKey '11_SMB'              -DCName $dcName -ScriptBlock { Get-SMBConfiguration      -DC $dcName }; if ($r) { $Global:Results['11_SMB']             += $r } }
                if (Test-IsCheckSelected '12_NTLMAuth')         { $r = Invoke-TimedCheck -CheckKey '12_NTLMAuth'         -DCName $dcName -ScriptBlock { Get-NTLMAuthLevel         -DC $dcName }; if ($r) { $Global:Results['12_NTLMAuth']        += $r } }
                if (Test-IsCheckSelected '13_LLMNR')            { $r = Invoke-TimedCheck -CheckKey '13_LLMNR'            -DCName $dcName -ScriptBlock { Get-LLMNRConfiguration    -DC $dcName }; if ($r) { $Global:Results['13_LLMNR']           += $r } }
                if (Test-IsCheckSelected '14_LDAPSecurity')     { $r = Invoke-TimedCheck -CheckKey '14_LDAPSecurity'     -DCName $dcName -ScriptBlock { Get-LDAPSecurity          -DC $dcName }; if ($r) { $Global:Results['14_LDAPSecurity']    += $r } }
                if (Test-IsCheckSelected '15_WindowsFirewall')  { $r = Invoke-TimedCheck -CheckKey '15_WindowsFirewall'  -DCName $dcName -ScriptBlock { Get-WindowsFirewallStatus -DC $dcName }; if ($r) { $Global:Results['15_WindowsFirewall'] += $r } }
                if (Test-IsCheckSelected '21_LSAProtection')    { $r = Invoke-TimedCheck -CheckKey '21_LSAProtection'    -DCName $dcName -ScriptBlock { Get-LSAProtectionStatus   -DC $dcName }; if ($r) { $Global:Results['21_LSAProtection']   += $r } }
                if (Test-IsCheckSelected '22_PrintSpooler')     { $r = Invoke-TimedCheck -CheckKey '22_PrintSpooler'     -DCName $dcName -ScriptBlock { Get-PrintSpoolerStatus    -DC $dcName }; if ($r) { $Global:Results['22_PrintSpooler']    += $r } }
                if (Test-IsCheckSelected '23_SecureBoot')       { $r = Invoke-TimedCheck -CheckKey '23_SecureBoot'       -DCName $dcName -ScriptBlock { Get-SecureBootStatus      -DC $dcName }; if ($r) { $Global:Results['23_SecureBoot']      += $r } }
                if (Test-IsCheckSelected '24_Certificates')     { $r = Invoke-TimedCheck -CheckKey '24_Certificates'     -DCName $dcName -ScriptBlock { Get-DCCertificates        -DC $dcName }; if ($r) { $Global:Results['24_Certificates']    += $r } }
                if (Test-IsCheckSelected '33_EventLog')         { $r = Invoke-TimedCheck -CheckKey '33_EventLog'         -DCName $dcName -ScriptBlock { Get-DCEventLog            -DC $dcName }; if ($r) { $Global:Results['33_EventLog']        += $r } }
                if (Test-IsCheckSelected '34_TimeSync')         { $r = Invoke-TimedCheck -CheckKey '34_TimeSync'         -DCName $dcName -ScriptBlock { Get-TimeSyncStatus        -DC $dcName -PDCEmulator $pdcEmulator }; if ($r) { $Global:Results['34_TimeSync'] += $r } }
                if (Test-IsCheckSelected '36_InstalledPrograms'){ $r = Invoke-TimedCheck -CheckKey '36_InstalledPrograms'-DCName $dcName -ScriptBlock { Get-InstalledPrograms     -DC $dcName }; if ($r) { $Global:Results['36_InstalledPrograms'] += $r } }
                if (Test-IsCheckSelected '37_WindowsUpdates')   { $r = Invoke-TimedCheck -CheckKey '37_WindowsUpdates'   -DCName $dcName -ScriptBlock { Get-WindowsUpdates        -DC $dcName }; if ($r) { $Global:Results['37_WindowsUpdates']  += $r } }
                if (Test-IsCheckSelected '45_WindowsFeatures')  { $r = Invoke-TimedCheck -CheckKey '45_WindowsFeatures'  -DCName $dcName -ScriptBlock { Get-WindowsFeatures       -DC $dcName }; if ($r) { $Global:Results['45_WindowsFeatures'] += $r } }
                if (Test-IsCheckSelected '46_Shares')           { $r = Invoke-TimedCheck -CheckKey '46_Shares'           -DCName $dcName -ScriptBlock { Get-Shares                -DC $dcName }; if ($r) { $Global:Results['46_Shares']          += $r } }
            }
        }

        # --- Forest-weite Checks ---
        Write-Host "`n==== FOREST-WEITE CHECKS ====" -ForegroundColor Magenta
        $Global:ProgressStats.CurrentDC = '<Forest>'

        if (Test-IsCheckSelected '04b_ReplicationFailures')    { $r = Invoke-TimedCheck -CheckKey '04b_ReplicationFailures'    -ScriptBlock { Get-ReplicationFailures };     $Global:Results['04b_ReplicationFailures']    = @($r) }
        if (Test-IsCheckSelected '05_FSMO')                    { $r = Invoke-TimedCheck -CheckKey '05_FSMO'                    -ScriptBlock { Get-FSMORoles };               $Global:Results['05_FSMO']                    = @($r) }
        if (Test-IsCheckSelected '16_PrivilegedAccounts')      { $r = Invoke-TimedCheck -CheckKey '16_PrivilegedAccounts'      -ScriptBlock { Get-PrivilegedAccounts };      $Global:Results['16_PrivilegedAccounts']      = @($r) }
        if (Test-IsCheckSelected '17_PasswordPolicy')          { $r = Invoke-TimedCheck -CheckKey '17_PasswordPolicy'          -ScriptBlock { Get-PasswordPolicy };          $Global:Results['17_PasswordPolicy']          = @($r) }
        if (Test-IsCheckSelected '18_Kerberos')                { $r = Invoke-TimedCheck -CheckKey '18_Kerberos'                -ScriptBlock { Get-KerberosInfo };            $Global:Results['18_Kerberos']                = @($r) }
        if (Test-IsCheckSelected '19_UnconstrainedDelegation') { $r = Invoke-TimedCheck -CheckKey '19_UnconstrainedDelegation' -ScriptBlock { Get-UnconstrainedDelegation }; $Global:Results['19_UnconstrainedDelegation'] = @($r) }
        if (Test-IsCheckSelected '20_KerberoastingRisk')       { $r = Invoke-TimedCheck -CheckKey '20_KerberoastingRisk'       -ScriptBlock { Get-KerberoastingRisk };       $Global:Results['20_KerberoastingRisk']       = @($r) }
        if (Test-IsCheckSelected '25_Sites')                   { $r = Invoke-TimedCheck -CheckKey '25_Sites'                   -ScriptBlock { Get-ADSitesInfo };             $Global:Results['25_Sites']                   = @($r) }
        if (Test-IsCheckSelected '26_Subnets')                 { $r = Invoke-TimedCheck -CheckKey '26_Subnets'                 -ScriptBlock { Get-ADSubnetsInfo };           $Global:Results['26_Subnets']                 = @($r) }
        if (Test-IsCheckSelected '27_Trusts')                  { $r = Invoke-TimedCheck -CheckKey '27_Trusts'                  -ScriptBlock { Get-ADTrusts };                $Global:Results['27_Trusts']                  = @($r) }
        if (Test-IsCheckSelected '28_ADRecycleBin')            { $r = Invoke-TimedCheck -CheckKey '28_ADRecycleBin'            -ScriptBlock { Get-ADRecycleBinStatus };      $Global:Results['28_ADRecycleBin']            = @($r) }
        if (Test-IsCheckSelected '29_TombstoneLifetime')       { $r = Invoke-TimedCheck -CheckKey '29_TombstoneLifetime'       -ScriptBlock { Get-TombstoneLifetime };       $Global:Results['29_TombstoneLifetime']       = @($r) }
        if (Test-IsCheckSelected '30_Levels')                  { $r = Invoke-TimedCheck -CheckKey '30_Levels'                  -ScriptBlock { Get-ADLevels };                $Global:Results['30_Levels']                  = @($r) }
        if (Test-IsCheckSelected '31_GPO')                     { $r = Invoke-TimedCheck -CheckKey '31_GPO'                     -ScriptBlock { Get-GPOHealth };               $Global:Results['31_GPO']                     = @($r) }
        if (Test-IsCheckSelected '38_SPNDuplicates')           { $r = Invoke-TimedCheck -CheckKey '38_SPNDuplicates'           -ScriptBlock { Get-SPNDuplicateReport };      $Global:Results['38_SPNDuplicates']           = @($r) }
        if (Test-IsCheckSelected '39_ASREPRoasting')           { $r = Invoke-TimedCheck -CheckKey '39_ASREPRoasting'           -ScriptBlock { Get-ASREPRoastingRisk };       $Global:Results['39_ASREPRoasting']           = @($r) }
        if (Test-IsCheckSelected '40_AdminSDHolderDrift')      { $r = Invoke-TimedCheck -CheckKey '40_AdminSDHolderDrift'      -ScriptBlock { Get-AdminSDHolderDrift };      $Global:Results['40_AdminSDHolderDrift']      = @($r) }
        if (Test-IsCheckSelected '41_FGPP')                    { $r = Invoke-TimedCheck -CheckKey '41_FGPP'                    -ScriptBlock { Get-FGPPOverview };            $Global:Results['41_FGPP']                    = @($r) }
        if (Test-IsCheckSelected '42_DNSHygiene')              { $r = Invoke-TimedCheck -CheckKey '42_DNSHygiene'              -ScriptBlock { Get-DNSHygiene };              $Global:Results['42_DNSHygiene']              = @($r) }
        if (Test-IsCheckSelected '43_LAPS')                    { $r = Invoke-TimedCheck -CheckKey '43_LAPS'                    -ScriptBlock { Get-LAPSConfiguration };       $Global:Results['43_LAPS']                    = @($r) }
        if (Test-IsCheckSelected '44_AccountsWithoutAES')      { $r = Invoke-TimedCheck -CheckKey '44_AccountsWithoutAES'      -ScriptBlock { Get-AccountsWithoutAES };      $Global:Results['44_AccountsWithoutAES']      = @($r) }
        if (Test-IsCheckSelected '47_RCAESMigration')          { $r = Invoke-TimedCheck -CheckKey '47_RCAESMigration'          -ScriptBlock { Get-RCAESMigration };          $Global:Results['47_RCAESMigration']          = @($r) }
        if (Test-IsCheckSelected '48_DCSyncPermissions')       { $r = Invoke-TimedCheck -CheckKey '48_DCSyncPermissions'       -ScriptBlock { Get-DCSyncPermissions };       $Global:Results['48_DCSyncPermissions']       = @($r) }
        if (Test-IsCheckSelected '49_RBCDDelegation')          { $r = Invoke-TimedCheck -CheckKey '49_RBCDDelegation'          -ScriptBlock { Get-RBCDDelegation };          $Global:Results['49_RBCDDelegation']          = @($r) }
        if (Test-IsCheckSelected '50_dMSA')                    { $r = Invoke-TimedCheck -CheckKey '50_dMSA'                    -ScriptBlock { Get-dMSAObjects };             $Global:Results['50_dMSA']                    = @($r) }
        if (Test-IsCheckSelected '51_MachineAccountQuota')     { $r = Invoke-TimedCheck -CheckKey '51_MachineAccountQuota'     -ScriptBlock { Get-MachineAccountQuota };     $Global:Results['51_MachineAccountQuota']     = @($r) }
        if (Test-IsCheckSelected '52_AnonymousLDAP')           { $r = Invoke-TimedCheck -CheckKey '52_AnonymousLDAP'           -ScriptBlock { Get-AnonymousLDAP };           $Global:Results['52_AnonymousLDAP']           = @($r) }
        if (Test-IsCheckSelected '53_GPPPasswords')            { $r = Invoke-TimedCheck -CheckKey '53_GPPPasswords'            -ScriptBlock { Get-GPPPasswords };            $Global:Results['53_GPPPasswords']            = @($r) }
        if (Test-IsCheckSelected '54_ProtectedUsers')          { $r = Invoke-TimedCheck -CheckKey '54_ProtectedUsers'          -ScriptBlock { Get-ProtectedUsersAudit };     $Global:Results['54_ProtectedUsers']          = @($r) }
        if (Test-IsCheckSelected '61_Forwarder')               { $r = Invoke-TimedCheck -CheckKey '61_Forwarder'               -ScriptBlock { Get-ConditionalForwarding };      $Global:Results['61_Forwarder']               = @($r) }
        if (Test-IsCheckSelected '62_ReverseLookup')           { $r = Invoke-TimedCheck -CheckKey '62_ReverseLookup'           -ScriptBlock { Get-ReverseLookupCompleteness };    $Global:Results['62_ReverseLookup']           = @($r) }

        # Inaktive Accounts - einmaliger Aufruf fuer 3 Check-Keys
        $wantInact = (Test-IsCheckSelected '32a_InactiveUsers') -or (Test-IsCheckSelected '32b_InactiveComputers') -or (Test-IsCheckSelected '32c_PasswordNeverExpires')
        if ($wantInact) {
            Write-CheckProgress -CheckKey '32a_InactiveUsers' -Status Start -Message "Einmalige AD-Abfrage"
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $ina = Get-InactiveAccounts
                $sw.Stop()
                if (Test-IsCheckSelected '32a_InactiveUsers')        { $Global:Results['32a_InactiveUsers']        = @($ina.InactiveUsers) }
                if (Test-IsCheckSelected '32b_InactiveComputers')    { $Global:Results['32b_InactiveComputers']    = @($ina.InactiveComputers) }
                if (Test-IsCheckSelected '32c_PasswordNeverExpires') { $Global:Results['32c_PasswordNeverExpires'] = @($ina.PasswordNeverExpires) }
                Write-CheckProgress -CheckKey '32a_InactiveUsers' -Status OK -Duration $sw.Elapsed.TotalSeconds `
                    -Message ("User:{0}/Comp:{1}/PwdNeverExp:{2}" -f @($ina.InactiveUsers).Count, @($ina.InactiveComputers).Count, @($ina.PasswordNeverExpires).Count)
                $Global:ProgressStats.CompletedChecks++
            } catch {
                $sw.Stop()
                Write-CheckProgress -CheckKey '32a_InactiveUsers' -Status Error -Duration $sw.Elapsed.TotalSeconds -Message "$_"
                $Global:ProgressStats.CompletedChecks++
                $Global:ProgressStats.FailedChecks++
            }
        }

        if (Test-IsCheckSelected '35_Backup') { $r = Invoke-TimedCheck -CheckKey '35_Backup' -ScriptBlock { Get-ADBackupStatus }; $Global:Results['35_Backup'] = @($r) }

        Write-Progress -Activity "AD Health Check" -Completed

        Invoke-AllAssessments
        Export-ResultsToCsv
        New-HtmlReport

        # --- Abschluss-Summary ---
        $totalTime = New-TimeSpan -Start $Global:ProgressStats.StartTime -End (Get-Date)
        $sOK=0; $sW=0; $sC=0; $sI=0; $sN=0
        foreach ($a in $Global:Assessments.Values) {
            switch ($a.OverallStatus) { 'OK'{$sOK++} 'WARN'{$sW++} 'CRITICAL'{$sC++} 'INFO'{$sI++} 'NODATA'{$sN++} }
        }

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host "    AD HEALTH CHECK ABGESCHLOSSEN" -ForegroundColor White
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host ("  Gesamtdauer         : {0:D2}:{1:D2}:{2:D2}" -f $totalTime.Hours,$totalTime.Minutes,$totalTime.Seconds) -ForegroundColor White
        Write-Host ("  Ausgefuehrte Checks : {0}" -f $Global:ProgressStats.CompletedChecks) -ForegroundColor White
        Write-Host ("  Davon Fehler        : {0}" -f $Global:ProgressStats.FailedChecks) -ForegroundColor $(if($Global:ProgressStats.FailedChecks -gt 0){'Yellow'}else{'Green'})
        Write-Host ""
        Write-Host "  -------- Best-Practice-Bewertung --------" -ForegroundColor White
        Write-Host ("    [OK]       OK / Best Practice : {0}" -f $sOK) -ForegroundColor Green
        Write-Host ("    [WARN]     Warnungen          : {0}" -f $sW)  -ForegroundColor Yellow
        Write-Host ("    [KRITISCH] Kritisch           : {0}" -f $sC)  -ForegroundColor Red
        Write-Host ("    [INFO]     Info               : {0}" -f $sI)  -ForegroundColor Cyan
        Write-Host ("    [--]       Keine Daten        : {0}" -f $sN)  -ForegroundColor DarkGray

        if (@($skippedDCs).Count -gt 0) {
            Write-Host ""
            Write-Host "  -------- UEBERSPRUNGENE DCs --------" -ForegroundColor Yellow
            foreach ($s in $skippedDCs) {
                Write-Host ("    [X] {0,-30} -> {1}" -f $s.DCName, $s.SkipReason) -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "  HTML-Report : $Global:HtmlReport"  -ForegroundColor Green
        Write-Host "  CSV-Ordner  : $Global:CsvDirectory" -ForegroundColor Green
        Write-Host "  Log-Datei   : $Global:LogFile"     -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor DarkCyan
        Write-Host ""

        Write-Log "==================== AD HEALTH CHECK ENDE ====================" -Level OK -NoConsole

        # Optional: HTML-Report automatisch oeffnen
        # Start-Process $Global:HtmlReport

    } catch {
        Write-Progress -Activity "AD Health Check" -Completed
        Write-Log "FATAL: $_" -Level ERROR
        throw
    }
}

# --- Script ausfuehren ---
Start-ADHealthCheck

#endregion
