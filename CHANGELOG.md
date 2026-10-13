# Changelog

> 🇩🇪 [Deutsch](#-deutsch) | 🇬🇧 [English](#-english)

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.
All notable changes to this project are documented here.

---

## 🇩🇪 Deutsch

### [2.7] - 2026-10-14

#### Hinzugefügt
- **Update-Anzeige gegen GitLab-Releases** – beim Start wird das neueste Release dieses Projekts abgefragt (Timeout 3 s, Sortierung `released_at` absteigend)
  - **GUI**: neben der Versionsnummer erscheint ein klickbares Badge („🔄 Update verfügbar: v2.8"); ein Klick öffnet die Release-Seite im Browser
  - **Konsole/Skriptbetrieb**: zusätzliche Infozeile `[i] Update verfügbar: v2.8 (aktuell v2.7) - <URL>`
  - **Neuer Parameter `-NoUpdateCheck`** unterdrückt die Abfrage (Airgap-/Luftschacht-Umgebungen, streng firewalled Server)
- **Versionsnummer im GUI-Kopf sichtbar** (`v2.7` steht jetzt neben dem Titel, nicht mehr nur im Fenster-Titel)

#### Geändert
- Version auf 2.7 erhöht (54 Checks, Check-Logik unverändert)
- Die Release-Abfrage erzwingt für Windows PowerShell 5.1 TLS 1.2 (sonst schlägt der HTTPS-Handshake auf älteren Systemen fehl)

#### Behoben
- **Update-Check stört nie einen Health Check**: ohne Internet, bei Proxy-Sperren oder Timeouts bleibt die Anzeige aus, und in der GUI läuft die Abfrage in einem eigenen Runspace (DispatcherTimer pollt das Ergebnis) – das Fenster öffnet sich auch bei langsamem Netz sofort

### [2.6] - 2026-10-13

#### Hinzugefügt
- **Internationalisierung Deutsch/Englisch** – das gesamte Projekt ist jetzt zweisprachig
  - **Automatische Spracherkennung**: Die Ausgabesprache wird beim Start aus der Betriebssystemsprache ermittelt (`Get-UICulture`); deutsche Windows-Oberfläche => Deutsch, englische => Englisch, alles andere => Deutsch
  - **Sprachumschalter in der GUI**: neue DE/EN-Schaltflächen in der WPF-GUI, Umschalten zur Laufzeit aktualisiert alle GUI-Texte, Check-Titel und Gruppennamen
  - **Neuer Parameter `-Language de|en`** überschreibt die Erkennung (für Scheduled Tasks/Automatisierung)
  - **HTML-Report zweisprachig**: Kopfbereich, Dashboard, Übersichts- und Detailabschnitte, Status-Badges, Spaltenüberschriften und Zellwerte erscheinen in der gewählten Sprache (`lang`-Attribut der HTML-Datei folgt der Auswahl)
  - **Konsolenausgabe und Menüs** in der gewählten Sprache (Fortschritt, Auswertungs-Bewertung, Export- und Abschluss-Meldungen)
- **Zweisprachige Dokumentation**: README, CHANGELOG und Wiki sind jetzt je Datei deutsch und englisch mit Sprachumschalter am Kopf der Seite
- **GitLab-Projektbeschreibung und Topics** zweisprachig gepflegt

### [2.5] - 2026-10-12

#### Hinzugefügt
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

#### Behoben
- **NTDS-Dienst auf lokalen DCs wird jetzt zuverlässig erkannt** – vierstufiges Matching in Check 02:
  1. Service-Name (sprachunabhängig), 2. DE/EN-Anzeigename, 3. ASCII-sichere Regex-Patterns (z. B. `^Active Directory`), 4. direkte CIM-Einzelabfrage per Name-Filter sowie lokaler `Get-Service` als letzte Instanz
  - Korrigierte deutsche Anzeigenamen in der Service-Map (u. a. „Kerberos-Schlüsselverteilungscenter", „Windows-Zeitgeber", „Anmeldedienst") und englischer NTDS-Name mit Leerzeichen statt Bindestrich
- **Datei-Speicherung jetzt UTF-8 MIT BOM**: PowerShell 5.1 las die Datei ohne BOM als ANSI und zerschoss damit alle Umlaut-Strings (DE-Dienstnamen, „ändern"-Regex im Shares-Check) – Matching-Fehler waren die Folge
- **Check 44 (Konten ohne AES): Bitmasken korrigiert**: RC4 war fälschlich mit `0x2` (ist DES-CBC-MD5) und AES mit `0x30` (AES256+CompoundId) definiert. Korrekt: RC4=`0x04`, AES128=`0x08`, AES256=`0x10` (AES gesamt=`0x18`), DES=`0x03`. Folge: AES128-only-Konten wurden vorher fälschlich als „ohne AES" (CRITICAL) gemeldet, DES-CBC-MD5 als RC4 gelabelt
- **Shell-Menü**: Die Punkte „Forest" und „Security" enthielten die Checks 43 (LAPS) und 44 (Konten ohne AES) nicht – jetzt ergänzt

#### Geändert
- Version auf 2.5 erhöht (54 Checks)
- Neue Checks in den GUI-Gruppen „Identity & Kerberos" (47–50, 54) und „Security & Hardening" (51–53) – wirken sich auf GUI, Konsolen-Menü und gruppierten HTML-Report aus

### [2.4] - 2026-10-12

#### Hinzugefügt
- **Check 45: Installierte Windows Features** – liest alle installierten Rollen & Features pro DC aus
  - Abfrage via `Get-WindowsFeature` (ServerManager-Modul), Fallback `Get-WindowsOptionalFeature`
  - Ausgabe: Name, DisplayName, FeatureType, InstallState
- **Check 46: SMB-Freigaben (Shares)** – listet alle Freigaben auf jedem DC auf
  - Abfrage via `Get-SmbShare`, Fallback `Win32_Share` (CIM)
  - Enthält Pfad, Beschreibung, Scope, CachingMode, Verschlüsselung, aktive Nutzer und Freigabeberechtigungen (`Get-SmbShareAccess`)
  - Warnung bei „Everyone" mit Full/Change-Berechtigung – Standard-Freigaben (SYSVOL, NETLOGON, ADMIN$, IPC$ etc.) werden NICHT beanstandet, da „Everyone" dort Default ist (NTFS regelt den eigentlichen Zugriff)
- **HTML-Report jetzt nach GUI-Kategorien gruppiert** – Übersichtstabelle und Detail-Abschnitte werden nun in denselben 5 Kategorien dargestellt wie in der WPF-GUI (DC-Infrastruktur, Security & Hardening, Identity & Kerberos, AD-Topologie & Objekte, System & Updates), inkl. farbiger Kategorie-Banner
- Gemeinsame Gruppen-Definition `$Global:CheckGroups` für GUI und HTML-Report (Single Source of Truth)

#### Behoben
- **Dienste-Check findet NTDS auf deutschen Systemen nun korrekt**: Abfrage via CIM (`Win32_Service`) über WinRM statt `Get-Service -ComputerName` (RPC); Matching per Service-Name UND Anzeigename (z. B. „Active Directory-Domänendienste", „Kerberos-Key-Verteilungsdienst", „DFS-Replikation")
- **NTFRS-Bewertung korrigiert**: Gestoppt/Disabled/NTFRS = Best Practice und wird jetzt GRÜN bewertet (DFSR repliziert SYSVOL). Nur wenn NTFRS aktiv läuft, erscheint eine Warnung (Legacy-Replikation)
- DFSR-Gestoppt wird als Warnung markiert (SYSVOL-Replizierung betroffen)

#### Geändert
- Version auf 2.4 erhöht (46 Checks)
- Dienste-Ausgabe enthält zusätzlich den Anzeigenamen (`DisplayName`) der Dienste

### [2.2] - 2026-05-29

#### Hinzugefügt
- **WPF-GUI** (Light Theme) ersetzt das interaktive Shell-Menü
  - Moderne Oberfläche mit Segoe UI, abgerundeten Buttons, Hover-Effekten
  - Ausgabepfad-Wahl per FolderBrowserDialog
  - 5 Check-Gruppen als aufklappbare Expander mit Gruppen-Checkboxen
  - Suite-Buttons: DC-Infrastruktur, Security & Hardening, Identity & Kerberos, AD-Topologie & Objekte, System & Updates
  - Schnellauswahl: Alle / Keine
  - Echtzeit-Zähler "X / Y Checks ausgewählt"
- Neuer Parameter `-OutputPath` zur Angabe des Ausgabepfads per Kommandozeile

#### Geändert
- Version auf 2.2 erhöht
- Shell-Menü bleibt als Fallback für `-NoInteractive` / `-FullRun` erhalten

### [2.1] - 2026-05-29

#### Verbessert
- Loopback-Handling für lokale DCs optimiert
- Ping-Skip-Logik erweitert mit WinRM-Fallback
- Performance-Optimierungen bei der DC-Discovery
- HTML-Report-Rendering Bugfixes

#### Hinzugefügt
- Vollständige Wiki-Dokumentation (16 strukturierte Seiten)
- README komplett überarbeitet mit allen Abschnitten
- CHANGELOG.md erstellt

### [2.0] - 2025-12-01

#### Hinzugefügt
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

### [1.0] - 2025-06-01

#### Initiale Version
- 37 Prüfpunkte für AD-Gesundheit und -Sicherheit
- Basis-HTML-Report mit Farbcodierung
- Logging nach `C:\ScriptLog`
- Forest-weite DC-Discovery
- WinRM-basierte Remote-Abfragen

---

## 🇬🇧 English

### [2.7] - 2026-10-14

#### Added
- **Update indicator backed by GitLab releases** – on startup the script queries this project's latest release (3 s timeout, sorted by `released_at` descending)
  - **GUI**: a clickable badge appears next to the version number ("🔄 Update available: v2.8"); clicking it opens the release page in your browser
  - **Console/script mode**: an extra info line `[i] Update available: v2.8 (currently v2.7) - <URL>`
  - **New `-NoUpdateCheck` parameter** disables the query (air-gapped environments, strictly firewalled servers)
- **Version number now visible in the GUI header** (`v2.7` sits next to the title instead of only in the window title bar)

#### Changed
- Version bumped to 2.7 (54 checks, check logic unchanged)
- The release query enforces TLS 1.2 for Windows PowerShell 5.1 (otherwise the HTTPS handshake fails on older systems)

#### Fixed
- **The update check never interferes with a health check**: without internet access, behind proxy blocks or on timeouts the indicator simply stays hidden, and in the GUI the query runs in its own runspace (a DispatcherTimer polls the result) – the window opens immediately even on slow networks

### [2.6] - 2026-10-13

#### Added
- **German/English internationalization** – the whole project is now bilingual
  - **Automatic language detection**: the output language is determined at startup from the operating system language (`Get-UICulture`); German Windows UI => German, English UI => English, anything else => German
  - **Language switch in the GUI**: new DE/EN buttons in the WPF GUI; switching updates all GUI texts, check titles and group names live
  - **New parameter `-Language de|en`** overrides detection (for scheduled tasks/automation)
  - **Bilingual HTML report**: header, dashboard, overview and detail sections, status badges, column headers and cell values are rendered in the selected language (the HTML `lang` attribute follows the selection)
  - **Console output and menus** in the selected language (progress, best-practice assessment, export and completion messages)
- **Bilingual documentation**: README, CHANGELOG and wiki are now German and English per file with a language switch at the top of each page
- **GitLab project description and topics** maintained in both languages

### [2.5] - 2026-10-12

#### Added
- **Check 47: RC4 → AES migration audit (CVE-2026-20833)** – Microsoft disables RC4 in Kerberos starting 2026 (July updates); this check shows in advance what will break when RC4 is turned off
  - All users/computers with `msDS-SupportedEncryptionTypes` are classified: DES → RC4-only → RC4+AES → AES-ready
  - SPN service accounts WITHOUT the attribute are listed (the KDC currently issues RC4 TGS tickets → outage after RC4 end-of-life)
  - KDC registry `SupportedEncryptionTypes` is read from all reachable DCs (WinRM/local)
- **Check 48: DCSync permissions** – ACL evaluation of the domain NC for `DS-Replication-Get-Changes(-All/-FilteredSet)`
  - Default holders (SYSTEM, BUILTIN\Administrators, Domain Controllers RID 516, Enterprise DCs) are recognized by SID and not flagged
  - Any other holder with `Get-Changes-All` = CRITICAL (full hash extraction possible)
- **Check 49: RBCD & constrained delegation** – `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) and `msDS-AllowedToDelegateTo` (constrained delegation)
  - RBCD principals evaluated by object class (user principal = CRITICAL/priv-esc path, computer/gMSA = WARN)
  - Constrained delegation with indication of protocol transition (`TrustedToAuthForDelegation` / S4U2Self)
- **Check 50: dMSA / BadSuccessor** – finds Delegated Managed Service Accounts (`msDS-DelegatedManagedServiceAccount`, Server 2025 schema)
  - `msDS-DelegatedMSAState=2` (superseding active) is evaluated as a takeover path; if the dMSA supersedes a privileged account (adminCount=1), the finding is CRITICAL
  - Missing schema = green (BadSuccessor not applicable)
- **Check 51: MachineAccountQuota** – `ms-DS-MachineAccountQuota` must be 0 (the default of 10 allows attackers to create their own computer accounts)
- **Check 52: Anonymous LDAP access** – functional anonymous RootDSE bind against the PDC (NC information readable = WARN) plus display of `dSHeuristics`
- **Check 53: GPP/cpassword in SYSVOL** – searches all GPP XMLs in SYSVOL for `cpassword` attributes (MS14-025: AES keys stored in cleartext publicly → passwords of every domain member can be decrypted)
- **Check 54: Protected Users audit** – Domain/Enterprise/Schema Admins, BUILTIN\Administrators and the built-in Administrator (RID 500) checked for membership in "Protected Users" (RID 525, language-independent); the break-glass account is commented as an often intentional exception

#### Fixed
- **NTDS service on local DCs is now detected reliably** – four-stage matching in check 02:
  1. Service name (language-independent), 2. DE/EN display name, 3. ASCII-safe regex patterns (e.g. `^Active Directory`), 4. direct CIM single query via name filter as well as local `Get-Service` as a last resort
  - Corrected German display names in the service map (among others "Kerberos-Schlüsselverteilungscenter", "Windows-Zeitgeber", "Anmeldedienst") and the English NTDS name with a space instead of a hyphen
- **File saving now UTF-8 with BOM**: PowerShell 5.1 read the file without a BOM as ANSI and thus mangled all umlaut strings (German service names, the "ändern" regex in the shares check) – resulting in matching failures
- **Check 44 (accounts without AES): bit masks corrected**: RC4 was incorrectly defined as `0x2` (which is DES-CBC-MD5) and AES as `0x30` (AES256+CompoundId). Correct: RC4=`0x04`, AES128=`0x08`, AES256=`0x10` (AES total=`0x18`), DES=`0x03`. Consequence: AES128-only accounts were previously reported incorrectly as "without AES" (CRITICAL), and DES-CBC-MD5 was labeled as RC4
- **Shell menu**: The items "Forest" and "Security" did not include checks 43 (LAPS) and 44 (accounts without AES) – now added

#### Changed
- Version increased to 2.5 (54 checks)
- New checks in the GUI groups "Identity & Kerberos" (47–50, 54) and "Security & Hardening" (51–53) – affecting the GUI, console menu and grouped HTML report

### [2.4] - 2026-10-12

#### Added
- **Check 45: Installed Windows features** – reads all installed roles & features per DC
  - Query via `Get-WindowsFeature` (ServerManager module), fallback `Get-WindowsOptionalFeature`
  - Output: Name, DisplayName, FeatureType, InstallState
- **Check 46: SMB shares** – lists all shares on every DC
  - Query via `Get-SmbShare`, fallback `Win32_Share` (CIM)
  - Includes path, description, scope, CachingMode, encryption, active users and share permissions (`Get-SmbShareAccess`)
  - Warning for "Everyone" with Full/Change permissions – default shares (SYSVOL, NETLOGON, ADMIN$, IPC$ etc.) are NOT flagged, because "Everyone" is the default there (NTFS governs the actual access)
- **HTML report now grouped by GUI categories** – the overview table and detail sections are now rendered in the same 5 categories as in the WPF GUI (DC Infrastructure, Security & Hardening, Identity & Kerberos, AD Topology & Objects, System & Updates), including colored category banners
- Shared group definition `$Global:CheckGroups` for GUI and HTML report (single source of truth)

#### Fixed
- **Services check now finds NTDS on German systems correctly**: query via CIM (`Win32_Service`) over WinRM instead of `Get-Service -ComputerName` (RPC); matching by service name AND display name (e.g. "Active Directory-Domänendienste", "Kerberos-Key-Verteilungsdienst", "DFS-Replikation")
- **NTFRS assessment corrected**: stopped/disabled/NTFRS = best practice and is now rated GREEN (DFSR replicates SYSVOL). Only if NTFRS is actively running is a warning shown (legacy replication)
- DFSR stopped is marked as a warning (SYSVOL replication affected)

#### Changed
- Version increased to 2.4 (46 checks)
- Services output additionally includes the display name (`DisplayName`) of the services

### [2.2] - 2026-05-29

#### Added
- **WPF GUI** (light theme) replaces the interactive shell menu
  - Modern interface with Segoe UI, rounded buttons, hover effects
  - Output path selection via FolderBrowserDialog
  - 5 check groups as expandable expanders with group checkboxes
  - Suite buttons: DC Infrastructure, Security & Hardening, Identity & Kerberos, AD Topology & Objects, System & Updates
  - Quick selection: All / None
  - Real-time counter "X / Y checks selected"
- New parameter `-OutputPath` to specify the output path from the command line

#### Changed
- Version increased to 2.2
- Shell menu is retained as a fallback for `-NoInteractive` / `-FullRun`

### [2.1] - 2026-05-29

#### Improved
- Loopback handling for local DCs optimized
- Ping skip logic extended with WinRM fallback
- Performance optimizations in DC discovery
- HTML report rendering bug fixes

#### Added
- Complete wiki documentation (16 structured pages)
- README fully revised with all sections
- CHANGELOG.md created

### [2.0] - 2025-12-01

#### Added
- **5 new checks** (38–42):
  - Check 38: SPN duplicate detection
  - Check 39: AS-REP-Roasting risk
  - Check 40: AdminSDHolder / AdminCount drift
  - Check 41: Fine-Grained Password Policies (FGPP)
  - Check 42: DNS hygiene (aging / scavenging)
- Executive dashboard in the HTML report
- Interactive start menu with 7 options
- Parameter-based execution (`-FullRun`, `-OnlyChecks`, `-NoInteractive`)
- CSV export of all check results
- Progress tracking during execution
- Language independence via well-known SIDs

### [1.0] - 2025-06-01

#### Initial version
- 37 checks for AD health and security
- Basic HTML report with color coding
- Logging to `C:\ScriptLog`
- Forest-wide DC discovery
- WinRM-based remote queries
