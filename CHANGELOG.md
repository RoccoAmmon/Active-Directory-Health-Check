# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.

---

## [2.5] – 2026-10-12

### Hinzugefügt
- **Check 47: RC4 → AES Migrations-Audit (CVE-2026-20833)** – Microsoft deaktiviert RC4 im Kerberos ab 2026 (Juli-Updates); dieser Check zeigt vorab, was bei der Abschaltung ausfällt
  - Alle User/Computer mit `msDS-SupportedEncryptionTypes`: DES → RC4-only → RC4+AES → AES-ready klassifiziert
  - SPN-Dienstkonten OHNE Attribut werden gelistet (KDC stellt derzeit RC4-TGS aus → Ausfall nach RC4-Ende)
  - KDC-Registry `SupportedEncryptionTypes` wird auf allen erreichbaren DCs ausgelesen (WinRM/lokal)
- **Check 48: DCSync-Berechtigungen** – ACL-Auswertung des Domain-NC auf `DS-Replication-Get-Changes(-All/-FilteredSet)`
  - Standard-Träger (SYSTEM, BUILTIN\Administrators, Domain Controllers RID 516, Enterprise DCs) werden per SID erkannt und nicht beanstandet
  - Jeder andere Träger mit `Get-Changes-All` = CRITICAL (volle Hash-Extraktion möglich)
- **Check 49: RBCD & Constrained Delegation** – `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) und `msDS-AllowedToDelegateTo` (Constrained Delegation)
  - RBCD-Prinzipale nach Objektklasse bewertet (User-Prinzipal = CRITICAL/PrivEsc-Pfad, Computer/gMSA = WARN)
  - Constrained Delegation mit Kennzeichnung von Protokollwechsel (`TrustedToAuthForDelegation` / S4U2Self)
- **Check 50: dMSA / BadSuccessor** – Findet Delegated Managed Service Accounts (`msDS-DelegatedManagedServiceAccount`, Server 2025 Schema)
  - `msDS-DelegatedMSAState=2` (Superseding aktiv) wird als Takeover-Pfad bewertet; übernimmt das dMSA ein privilegiertes Konto (adminCount=1), ist der Befund CRITICAL
  - Fehlendes Schema = grün (BadSuccessor nicht anwendbar)
- **Check 51: MachineAccountQuota** – `ms-DS-MachineAccountQuota` muss 0 sein (Default 10 erlaubt Angreifern eigene Computerkonten)
- **Check 52: Anonymer LDAP-Zugriff** – funktionaler anonymer RootDSE-Bind gegen den PDC (NC-Informationen lesbar = WARN) plus Anzeige der `dSHeuristics`
- **Check 53: GPP/cpassword in SYSVOL** – durchsucht alle GPP-XMLs im SYSVOL nach `cpassword`-Attributen (MS14-025: AES-Klartextschlüssel öffentlich → Passwörter für jedes Domänenmitglied entschlüsselbar)
- **Check 54: Protected Users Audit** – Domain/Enterprise/Schema Admins, BUILTIN\Administrators und Built-in Administrator (RID 500) auf Mitgliedschaft in „Protected Users" (RID 525, sprachunabhängig) geprüft; Break-Glass-Konto wird als oft beabsichtigte Ausnahme kommentiert

### Behoben
- **NTDS-Dienst auf lokalen DCs wird jetzt zuverlässig erkannt** – vierstufiges Matching in Check 02:
  1. Service-Name (sprachunabhängig), 2. DE/EN-Anzeigename, 3. ASCII-sichere Regex-Patterns (z. B. `^Active Directory`), 4. direkte CIM-Einzelabfrage per Name-Filter sowie lokaler `Get-Service` als letzte Instanz
  - Korrigierte deutsche Anzeigenamen in der Service-Map (u. a. „Kerberos-Schlüsselverteilungscenter", „Windows-Zeitgeber", „Anmeldedienst") und englischer NTDS-Name mit Leerzeichen statt Bindestrich
- **Datei-Speicherung jetzt UTF-8 MIT BOM**: PowerShell 5.1 las die Datei ohne BOM als ANSI und zerschoss damit alle Umlaut-Strings (DE-Dienstnamen, „ändern"-Regex im Shares-Check) – Matching-Fehler waren die Folge
- **Check 44 (Konten ohne AES): Bitmasken korrigiert**: RC4 war fälschlich mit `0x2` (ist DES-CBC-MD5) und AES mit `0x30` (AES256+CompoundId) definiert. Korrekt: RC4=`0x04`, AES128=`0x08`, AES256=`0x10` (AES gesamt=`0x18`), DES=`0x03`. Folge: AES128-only-Konten wurden vorher fälschlich als „ohne AES" (CRITICAL) gemeldet, DES-CBC-MD5 als RC4 gelabelt
- **Shell-Menü**: Die Punkte „Forest" und „Security" enthielten die Checks 43 (LAPS) und 44 (Konten ohne AES) nicht – jetzt ergänzt

### Geändert
- Version auf 2.5 erhöht (54 Checks)
- Neue Checks in den GUI-Gruppen „Identity & Kerberos" (47–50, 54) und „Security & Hardening" (51–53) – wirken sich auf GUI, Konsolen-Menü und gruppierten HTML-Report aus

---

## [2.4] – 2026-10-12

### Hinzugefügt
- **Check 45: Installierte Windows Features** – liest alle installierten Rollen & Features pro DC aus
  - Abfrage via `Get-WindowsFeature` (ServerManager-Modul), Fallback `Get-WindowsOptionalFeature`
  - Ausgabe: Name, DisplayName, FeatureType, InstallState
- **Check 46: SMB-Freigaben (Shares)** – listet alle Freigaben auf jedem DC auf
  - Abfrage via `Get-SmbShare`, Fallback `Win32_Share` (CIM)
  - Enthält Pfad, Beschreibung, Scope, CachingMode, Verschlüsselung, aktive Nutzer und Freigabeberechtigungen (`Get-SmbShareAccess`)
  - Warnung bei „Everyone" mit Full/Change-Berechtigung – Standard-Freigaben (SYSVOL, NETLOGON, ADMIN$, IPC$ etc.) werden NICHT beanstandet, da „Everyone" dort Default ist (NTFS regelt den eigentlichen Zugriff)
- **HTML-Report jetzt nach GUI-Kategorien gruppiert** – Übersichtstabelle und Detail-Abschnitte werden nun in denselben 5 Kategorien dargestellt wie in der WPF-GUI (DC-Infrastruktur, Security & Hardening, Identity & Kerberos, AD-Topologie & Objekte, System & Updates), inkl. farbiger Kategorie-Banner
- Gemeinsame Gruppen-Definition `$Global:CheckGroups` für GUI und HTML-Report (Single Source of Truth)

### Behoben
- **Dienste-Check findet NTDS auf deutschen Systemen nun korrekt**: Abfrage via CIM (`Win32_Service`) über WinRM statt `Get-Service -ComputerName` (RPC); Matching per Service-Name UND Anzeigename (z. B. „Active Directory-Domänendienste", „Kerberos-Key-Verteilungsdienst", „DFS-Replikation")
- **NTFRS-Bewertung korrigiert**: Gestoppt/Disabled/NTFRS = Best Practice und wird jetzt GRÜN bewertet (DFSR repliziert SYSVOL). Nur wenn NTFRS aktiv läuft, erscheint eine Warnung (Legacy-Replikation)
- DFSR-Gestoppt wird als Warnung markiert (SYSVOL-Replizierung betroffen)

### Geändert
- Version auf 2.4 erhöht (46 Checks)
- Dienste-Ausgabe enthält zusätzlich den Anzeigenamen (`DisplayName`) der Dienste

---

## [2.2] – 2026-05-29

### Hinzugefügt
- **WPF-GUI** (Light Theme) ersetzt das interaktive Shell-Menü
  - Moderne Oberfläche mit Segoe UI, abgerundeten Buttons, Hover-Effekten
  - Ausgabepfad-Wahl per FolderBrowserDialog
  - 5 Check-Gruppen als aufklappbare Expander mit Gruppen-Checkboxen
  - Suite-Buttons: DC-Infrastruktur, Security & Hardening, Identity & Kerberos, AD-Topologie & Objekte, System & Updates
  - Schnellauswahl: Alle / Keine
  - Echtzeit-Zähler "X / Y Checks ausgewählt"
- Neuer Parameter `-OutputPath` zur Angabe des Ausgabepfads per Kommandozeile

### Geändert
- Version auf 2.2 erhöht
- Shell-Menü bleibt als Fallback für `-NoInteractive` / `-FullRun` erhalten

---

## [2.1] – 2026-05-29

### Verbessert
- Loopback-Handling für lokale DCs optimiert
- Ping-Skip-Logik erweitert mit WinRM-Fallback
- Performance-Optimierungen bei der DC-Discovery
- HTML-Report-Rendering Bugfixes

### Hinzugefügt
- Vollständige Wiki-Dokumentation (16 strukturierte Seiten)
- README komplett überarbeitet mit allen Abschnitten
- CHANGELOG.md erstellt

---

## [2.0] – 2025-12-01

### Hinzugefügt
- **5 neue Checks** (38–42):
  - Check 38: SPN-Dubletten-Erkennung
  - Check 39: AS-REP-Roasting-Risiko
  - Check 40: AdminSDHolder / AdminCount-Drift
  - Check 41: Fine-Grained Password Policies (FGPP)
  - Check 42: DNS-Hygiene (Aging / Scavenging)
- Executive Dashboard im HTML-Report
- Interaktives Startmenü mit 7 Optionen
- Parameter-basierte Ausführung (`-FullRun`, `-OnlyChecks`, `-NoInteractive`)
- CSV-Export aller Check-Ergebnisse
- Progress-Tracking während der Ausführung
- Sprachunabhängigkeit via Well-Known SIDs

---

## [1.0] – 2025-06-01

### Initiale Version
- 37 Prüfpunkte für AD-Gesundheit und -Sicherheit
- Basis-HTML-Report mit Farbcodierung
- Logging nach `C:\ScriptLog`
- Forest-weite DC-Discovery
- WinRM-basierte Remote-Abfragen
