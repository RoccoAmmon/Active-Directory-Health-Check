# Changelog

> 🇩🇪 [Deutsch](#-deutsch) | 🇬🇧 [English](#-english)

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.
All notable changes to this project are documented here.

---

## 🇩🇪 Deutsch

### [2.13] - 2026-10-19

#### Geändert
- **Check 55 vollständig neu aufgebaut** (bisherige Abfragen liefen ins Leere):
  - **Discovery** über die DNS-SRV-Einträge `_vlmcs._tcp.<ForestRoot>`, `_vlmcs._tcp.<Domain>` und je Site `_vlmcs._tcp.<Site>._sites.<Domain>`; alle Treffer werden je Host zusammengeführt
  - **Je Host:** TCP-Erreichbarkeit des veröffentlichten Ports, Software Protection (`sppsvc`) inkl. Starttyp, KMS-Host-Key (CSVLK) und Zähler aus `SoftwareLicensingProduct` (`IsKeyManagementServiceMachine`, `KeyManagementServiceCurrentCount`, `RequiredClientCount`, `...TotalRequests`, `...FailedRequests`)
  - **Behoben:** falscher Dienstname (`KeyManagementService` existiert nicht – KMS läuft im Dienst `sppsvc`), falsche CIM-Klasse für die Zähler (`SoftwareLicensingService` statt `SoftwareLicensingProduct`) und ein Registry-Zugriff, der den lokalen statt des entfernten Rechners gelesen hat
  - **CIM** zuerst per WinRM, dann per DCOM. Ist beides gesperrt, werden die Details als nicht auslesbar benannt (INFO) – der Host wird nicht mehr pauschal als CRITICAL gemeldet
  - **AD-KMS:** Ist kein SRV-Eintrag vorhanden, prüft der Check alle DCs auf TCP 1688. Die Spalte `AufDC` beantwortet damit die Frage, ob ein KMS auf einem Domaincontroller läuft
  - **Bewertung:** veröffentlichter Host nicht erreichbar = CRITICAL; Host ohne CSVLK oder ohne DNS-Veröffentlichung = WARN; fehlende Detaildaten oder noch nicht erreichte Aktivierungsschwelle = INFO
  - Row-Kinds `Host`, `Hinweis`, `Summary`, `Fehler`

#### Hinzugefügt
- **Check 55b: AD-basierte Aktivierung (ADBA)** – liest die Aktivierungsobjekte (`msSPP-ActivationObject`) unter `CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration` inkl. Anzeigename, CSVLK-Teilkey (`msSPP-CSVLKPartialProductKey`), Lizenzblob (`msSPP-OnlineLicense`), Erstellungs- und Änderungsdatum. Fehlt der Container oder ist er leer, wird das als INFO („nicht eingerichtet"/„nicht aktiv") ausgewiesen – nicht als Fehler
  - Row-Kinds `Objekt`, `Summary`, `Fehler`
- Neue Schwellwerte `$Global:KMSProbeTimeoutMs` (1500 ms, TCP-Test) und `$Global:KMSCimTimeoutSec` (6 s, CIM-Verbindung)
- Neues Testskript `test-55-kms-adba.ps1` in die Test-Suite aufgenommen

#### Version
- Version auf 2.13 erhöht (74 nummerierte Checks, zusätzlich die Teilprüfungen 04b, 32a–c und 55b); Skript-Header, README und Wiki angeglichen

### [2.12] - 2026-10-19

#### Hinzugefügt
- **Neue GUI-Gruppe „Hybrid & Cloud (Entra)"** – rein lokal prüfbare Checks der Cloud-Anbindung; es wird ausschließlich das AD gelesen, keine Cloud-API kontaktiert und nichts geändert
- **Check 72: Entra-Sync-Dienstkonten** – inventarisiert die Dienstkonten der Entra-Synchronisierung (`MSOL_*` = Entra Connect Sync, `AAD_*` = altes DirSync) mit Kennwortalter (`PasswordLastSet`), „Kennwort läuft nie ab", Aktivstatus, Erstellungsdatum und Gruppenmitgliedschaften; privilegierte Gruppen werden über die Well-Known-SID erkannt (sprachunabhängig). Mehr als ein Konto, ein deaktiviertes Konto, ein zu altes Kennwort (`$Global:EntraSyncAccountPwdWarnDays`, 365 Tage) oder eine privilegierte Gruppe werden als WARN geführt
  - Row-Kinds `Konto`, `Summary`, `Fehler`
- **Check 73: Seamless SSO (AZUREADSSOACC)** – prüft das Computerkonto `AZUREADSSOACC` und das Alter seines Kerberos-Entschlüsselungsschlüssels (`PasswordLastSet`); bei Überschreitung von `$Global:SeamlessSSOKeyWarnDays` (30 Tage) wird ein Rollover empfohlen. Existiert kein Konto, ist Seamless SSO nicht eingerichtet – das wird als INFO und nicht als Fehler ausgewiesen
  - Row-Kinds `Objekt`, `Summary`, `Fehler`
- **Check 74: Cloud-Anbindung (Inventar)** – dokumentiert die im AD sichtbare Cloud-Anbindung: Hybrid-Join-SCP (`CN=Device Registration Configuration` inkl. `azureADId`/`azureADName`), Kerberos-Cloud-Trust-Objekt (`AzureADKerberos`), Hybrid-Join-Geräte (`msDS-DeviceID`), Synchronisierungs-Konten und alternative UPN-Suffixe des Forests. Ausdrücklich ein Doku-Inventar (Bewertung INFO); nicht auslesbare Bereiche werden als solche benannt und nicht als „nicht konfiguriert" behauptet
  - Row-Kinds `Bereich`, `Summary`
- Neue Schwellwerte `$Global:EntraSyncAccountPwdWarnDays` (365 Tage) und `$Global:SeamlessSSOKeyWarnDays` (30 Tage)

#### Geändert
- Version auf 2.12 erhöht (74 Checks); Skript-Header, README und Wiki angeglichen
- Neues Testskript `test-72-74-cloud.ps1` in die Test-Suite aufgenommen

### [2.11] - 2026-10-18

#### Hinzugefügt
- **Check 64: IPv6-Status je DC** – Computername, IPv6-Bindungsstatus aller Adapter und der Registry-Wert `DisabledComponents` (`HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`) als Rohwert plus Klartext-Interpretation (MS KB929852); eine Ergebniszeile je DC, Abweichungen zwischen Adapterbindung und Registry als WARN
- **Check 65: Computer-SPNs** – SPN-Export mit **einer Zeile je SPN** für Computerkonten: Computername, DNS-Hostname, DN, aktiviert/deaktiviert, Betriebssystem, vollständiger SPN, extrahierte Serviceklasse und Dublettenkennzeichnung (gleiche Regel wie Check 38)
- **Check 66: Benutzer-, MSA- und gMSA-SPNs** – gleiche Datenstruktur wie Check 65, zusätzlich sAMAccountName, UPN und "Kennwort läuft nie ab"; klassische Benutzerkonten, MSA und gMSA werden nicht stillschweigend vermischt, sondern in der Spalte `ObjektTyp` getrennt ausgewiesen (per `-ObjectType` filterbar)
- **Check 67: PKI – Enterprise-CA-Inventar** – CA-Objekte aus `CN=Enrollment Services` (`pKIEnrollmentService`) mit ihren CA-Zertifikaten (eine Zeile je Zertifikat), Restlaufzeit, Anzahl veröffentlichter Vorlagen, Veröffentlichung des Ausstellers in `CN=Certification Authorities` und lesende Erreichbarkeitsprüfung der `CertEnroll`-Freigabe
- **Check 68: PKI – Vertrauenswürdige Stamm- und Zwischenzertifikate** – Zertifikate aus `CN=Certification Authorities`, `CN=NTAuthCertificates` und den Public-Key-Richtlinien der GPOs (hex-kodierter Inhalt), Quellen getrennt ausgewiesen, Duplikaterkennung über den Fingerabdruck
- **Check 69: PKI – Zertifikatvorlagen & Veröffentlichung** – Vorlageninventar (`pKICertificateTemplate`) mit EKU-Klartext, Gültigkeitsdauer, Autoenrollment, tatsächlicher CA-Veröffentlichung und Schema-Version; CA-Referenzen ohne Vorlagenobjekt und eine Heuristik für zu offene Vorlagen
- **Check 70: PKI – Bezüge zu WLAN und Mailverschlüsselung** – Zuordnung über EKUs (Client Authentication, Secure Email, EFS) sowie die Public-Key- und WLAN-Richtlinien; ausdrücklich als Plausibilitätsprüfung gekennzeichnet, fehlende Zuordnung als WARN
- **Check 71: PKI – Sperrlisten- und Veröffentlichungsendpunkte** – CDP-/AIA-Adressen aus den CA-Zertifikaten inklusive lesender Erreichbarkeitsprüfung sowie die im AD veröffentlichten Sperrlisten (`CN=<CA>,CN=CDP`); nicht prüfbare Endpunkte bleiben sichtbar und werden nie als OK geführt
- **Neue GUI-Gruppe "PKI & Zertifikate"** – die fünf Teilprüfungen bewerten jeweils nur ihre eigene Ebene; eine zusammenfassende "PKI OK"-Aussage gibt es bewusst nicht
- Neue Schwellwerte `$Global:PkiCertWarnDays` (90 Tage Restlaufzeit) und `$Global:PkiEndpointTimeoutSec` (10 s Endpunkttest)

#### Behoben
- **Check 62** meldete als Befund nur "Summary", auch wenn die Ursache eine fehlende Reverse-Zone war; der Befund benennt jetzt die fehlende Reverse-Zone, und Fehlerzeilen ohne Zusammenfassung werden als WARN statt NODATA geführt
- **Mehrwertige Binärattribute** (`cACertificate`, `certificateRevocationList`) wurden durch `@()` in einzelne Bytes zerlegt; der neue Helfer `Get-PkiBinaryValues` behandelt sowohl ein Bytearray als auch eine Liste von Bytearrays korrekt
- **CDP-/AIA-Adressen** werden direkt aus den Erweiterungs-Rohbytes gelesen, da das .NET Framework diese Erweiterungen in `Format()` nicht dekodiert
- **GPO-Zertifikatssuche** nutzt jetzt relative XPath-Ausdrücke (`.//`), sonst hätte jede Richtlinie die Zertifikate des gesamten Reports gemeldet

#### Geändert
- Version auf 2.11 erhöht (71 Checks); Skript-Header, README und Wiki angeglichen
- Neues Testskript `test-67-71-pki.ps1` (60 Assertions) in die Test-Suite aufgenommen
### [2.10] - 2026-10-16

#### Hinzugefügt
- **Check 62: DNS-Reverse-Lookup-Vollständigkeit** – sammelt alle A- und AAAA-Records aller Primary-Forward-Zonen und prüft je IP, ob eine passende Reverse-Zone (`in-addr.arpa` / `ip6.arpa`) existiert; fehlende Reverse-Zonen werden mit betroffenen IPs und Hosts gemeldet. Geprüft wird nur die Zone, nicht ob ein PTR-Record existiert
  - Row-Kinds `Summary`, `MissingReverseZone`, `Fehler`
- **Check 63: AD-Subnetze vs. Reverse-Lookup-Zonen** – listet alle AD-Subnetze mit zugeordneter Site und prüft die passende Reverse-Zone; zusätzlich werden DNS-Netze mit A-Records aus allen Primary-Forward-Zonen gemeldet, die kein AD-Subnetz haben, sowie Reverse-Zonen ohne Subnetz (INFO)
  - WARN bei Subnetzen ohne Reverse-Zone oder Site, bei DNS-Netzen ohne AD-Subnetz und wenn gar keine Subnetze definiert sind
  - Row-Kinds `Subnet`, `ZoneOhneSubnet`, `DNSNetzOhneSubnet`, `Fehler`, `Summary`
  - Registriert in der GUI-Gruppe „AD-Topologie & Objekte“, im Forest-Bereich des Shell-Menüs und in den Auswahl-Listen

#### Behoben
- **Versionsvariable**: `$Global:ScriptVersion` stand noch auf 2.7 und wurde im Report-Kopf, im Update-Check und im Fenstertitel falsch angezeigt; Skript-Header (54 → 63 Checks) ebenfalls angeglichen

#### Geändert
- Version auf 2.10 erhöht (63 Checks)
- README und Wiki auf 63 Checks und Version 2.10 aktualisiert

### [2.9] - 2026-10-15

#### Hinzugefügt
- **Check 56: Tote DCs & DC-Verfügbarkeit** – gleicht sieben unabhängige Quellen für „welche DCs gibt es" gegeneinander ab (Live-Bestand, Computerobjekte in `OU=Domain Controllers`, Serverobjekte samt NTDS-Settings im Config-NC, Replikationspartner aller Domänen u. a.) und listet jeden DC mit Live-/Verwaist-Status und DNS-Existenz
  - Row-Kinds `DC` und `Quelle` (RowKey `Kind|Name`): jede Quelle wird separat bewertet, abweichende oder nicht auswertbare Quellen nennen die betroffenen Namen
  - Neuer Schwellwert `$Global:StaleDCWarnAgeDays` (0 = jedes verwaiste DC-Objekt ist auffällig, ab 1 nur ältere)
  - Registriert in der GUI-Gruppe „AD-Topologie & Objekte" und im Forest-Bereich des Shell-Menüs
- **Check 57: RC4 / LM Belege je DC** – sammelt echte Belege, dass RC4/LM noch verwendet wird, statt nur die Konfiguration zu lesen: `AllowableEncryptionTypes` der Computer- und Benutzerkonten, `NoLMHash`-Kennzeichnung und ausgewertete Kerberos-Tickets 4768/4769 aus dem Security-Log
  - Row-Kinds `Netlogon`, `NoLMHash`, `RC4-Tickets` (RowKey `Kind|DCName`)
  - Zeitfenster und Stichprobengröße per `$Global:RC4EventDays` (7 Tage) und `$Global:RC4EventSampleLimit` (5000 Tickets je DC); ein nicht lesbares Security-Log wird als eigener Befund ausgewiesen, statt den Teil stillschweigend auszulassen
  - Registriert in der GUI-Gruppe „Identity & Kerberos", im Pro-DC-Bereich des Shell-Menüs und in der Security-Suite
- **Check 58: SPN-Inventar & Verwaiste SPNs** – inventarisiert alle SPNs nach Dienstklasse und Objekt und ergänzt Check 38 (prüft nur Dubletten)
  - Row-Kinds `Zusammenfassung`, `Objekt`, `Klasse`, `Host`, `Fehler` (RowKey `Kind|Name`); RowFlags der Zusammenfassung werden nicht doppelt als Befund gezählt
  - Meldet Objekte mit ungewöhnlich vielen SPNs (`$Global:SPNMaxObjSpns`, 20), SPNs auf deaktivierten Konten, unerwartete SPN-Klassen auf Benutzerkonten (`$Global:SPNUserAccountClassWarn`) und SPN-Hostnamen ohne DNS-Auflösung (max. `$Global:SPNMaxDnsProbe` = 200 Abfragen, Anzeige je Row-Kind auf `$Global:SPNInventoryMaxRows` = 200 begrenzt)
  - Neue Spalte `DeaktKonten` (siehe „Behoben")
  - Registriert in der GUI-Gruppe „Identity & Kerberos", im Forest-Bereich des Shell-Menüs und in der Security-Suite
- **Check 59: Encryption-Types: Verteilung & AES-Abdeckung** – verteilt alle Konten nach EncType-Kombination, prüft die AES-Abdeckung gegen `$Global:EncTypesAesCoverageMin` (90 %) und korreliert die OS-Gruppe mit dem tatsächlich gesetzten EncType
  - Row-Kinds `Verteilung`, `OS`, `Fazit` (Fazit-Row `AES-Abdeckung`) und `Fehler` (RowKey `Kind|Name`)
  - Eine moderne OS-Gruppe ohne vollständige AES-Abdeckung wird gesondert gemeldet
  - Registriert in der GUI-Gruppe „Identity & Kerberos", im Forest-Bereich des Shell-Menüs und in der Security-Suite
- **Check 60: DNS-Zonen: SOA & Replikation** (Forest) – wertet die SOA-Refresh/-Expire-Werte aus und nutzt dafür die bislang ungenutzten Schwellwerte `$Global:DNSZoneRefreshMaxHours` (24) und `$Global:DNSZoneExpireMinDays` (7); zusätzlich werden pro Zone geprüft
  - `ReplicationScope='Server'` (Zone nur auf einem Server, nicht repliziert) bzw. eine zwischen den DCs variierende Scope-Zuordnung
  - `DynamicUpdate='None'` auf AD-integrierten Zonen (`NonsecureAndSecure` bleibt Check 6 vorbehalten)
  - abweichende SOA-Seriennummern derselben Zone zwischen den DCs
  - Row-Kinds `Zusammenfassung`, `Zone`, `Fehler` (RowKey `Kind|Name`); liefert die bisher ungenutzten Schwellwerte und ersetzt weder Check 6 noch Check 42
  - Registriert in der GUI-Gruppe „DC-Infrastruktur" und im Forest-Bereich des Shell-Menüs
- **Check 61: DNS-Forwarder & Conditional Forwarder** (Forest) – globale Forwarder inkl. Verfügbarkeit der Root-Hints sowie Conditional Forwarder mit Ziel-IP je DNS-Server
  - Erkennt nur teilweise verteilte CF (registry-basiert, **nicht** repliziert), CF ohne MasterServer (keine Auflösung möglich) und Weiterleitungsschleifen, deren Ziel ein eigener DNS-Server ist
  - Die Erreichbarkeit der Forwarder-IPs bleibt bewusst bei `dcdiag /test:DnsForwarders` in Check 3 (keine Doppelung); Row-Kinds `Zusammenfassung`, `ConditionalForwarder`, `Forwarder` (RowKey `Kind|Name`)
  - Registriert in der GUI-Gruppe „DC-Infrastruktur" und im Forest-Bereich des Shell-Menüs
- **Gesamtübersicht der Auffälligkeiten im HTML-Report** – eine Tabelle direkt hinter dem Executive Dashboard mit allen auffälligen Checks, nach Schwere sortiert; die Befunde je Check werden auf `$Global:ReportOverviewFindingsMax` (5) gekürzt, dahinter folgt „... und n weitere Befunde". Kein eigener Check, sondern ein Bestandteil des Reports
- **Automatische Rechte-Erhöhung** – Windows verlangt Administratorrechte für DNS- und WMI-Abfragen (z. B. `root\MicrosoftDNS`); liefen die DNS-Checks ohne diese Rechte, meldeten sie trotz installiertem DNS-Modul „keine Zonen" bzw. „DNS-Abfrage fehlgeschlagen". Ohne Adminrechte startet sich das Skript jetzt selbst mit einer UAC-Abfrage neu; alle übergebenen Parameter bleiben erhalten (betrifft `-FullRun`, `-OnlyChecks`, `-OutputPath`, `-Language`, `-NoInteractive`, `-NoUpdateCheck`)
  - Neue Funktionen `Test-IsElevated`, `Get-ElevationCommand` und `Start-ElevatedRestart`; ein Global-Flag (`ElevationHandled`) verhindert eine Endlosschleife
  - Abbruch der UAC-Abfrage führt nicht zum Abbruch: es wird im aktuellen Kontext weitergemacht, die fehlenden Rechte werden dabei ausdrücklich benannt
  - Neuer Parameter `-NoElevate` unterdrückt den Neustart (nützlich, wenn bewusst ohne Adminrechte getestet werden soll)

#### Behoben
- **Spaltenkopf `Deaktiviert` (Check 58)** wurde in englischen Berichten als `disabled` ausgegeben: der L10n-Schlüsselvergleich ist case-insensitiv und behält den ersten Eintrag (`deaktiviert=>disabled`), sodass der neu angelegte Eintrag `Deaktiviert=>Disabled` wirkungslos blieb. Die Spalte heißt jetzt `DeaktKonten` (=> `Disabled accounts`); die Klein-/Großschreibweise deutscher Fließtexte (`deaktiviert` => `disabled`) bleibt unverändert korrekt
- **README-Changelog**: der v2.7-Eintrag „weiterhin 55 Checks" (DE) bzw. „still 55 checks" (EN) war durch einen globalen Ersetzungsvorgang bei 2.8 mit hochgezogen worden und lautet jetzt wieder 54
- **README-Titel und Version-Badge** standen noch auf v2.7 (bei 2.8 nicht mitgeführt) und sind jetzt auf 2.9 gesetzt
- **Check 56 hing bei ausführbaren Läufen kommentarlos in der Warteschlange**: `Get-ADComputer` in `Get-StaleDCObjects` (Quelle „Computerobjekte in `OU=Domain Controllers`") wurde ohne `-Filter` aufgerufen, wodurch PowerShell den fehlenden Parameter interaktiv abfragt – bei `-FullRun` oder als Scheduled-Task blieb der Lauf hier stehen. Aufruf mit `-Filter *` ergänzt
- **Checks 7, 8 und 9 meldeten auf dem lokalen DNS-DC „keine Zonen" bzw. „nicht erreichbar"**: die DnsServer-Cmdlets wurden durchgehend mit `-ComputerName <DC>` aufgerufen, also auch gegen den **eigenen** Rechner. Ein `-ComputerName` auf sich selbst erzwingt einen CIM/WMI-Remoting-Umweg; ist WinRM-Loopback oder DCOM gesperrt, schlägt auch die Abfrage auf dem EIGENEN DC fehl, obwohl DNS installiert ist und der DC über Ping/AD/Replikation einwandfrei erreichbar bleibt. Check 42 war nicht betroffen, weil er bereits ohne `-ComputerName` abfragt. Neue Funktion `Get-DnsServerTargets` liefert eine Prüfreihenfolge: lokal zuerst **ohne** `-ComputerName` (in-process), dann `localhost`, dann der übergebene Name; remote nur der Name. Genutzt in `Get-DNSConfiguration`, `Get-DNSZoneConfiguration` und `Get-ConditionalForwarding`
- **`Test-IsLocalComputer` erkannte den lokalen DC nicht in FQDN-Form**: Check 7 erhält den DC als FQDN (`dc.HostName`), Checks 8/9 als NetBIOS-Namen (`.Name`); der Vergleich war rein exakt, sodass Check 7 den lokalen DC stets als „remote" behandelte. Jetzt wird zusätzlich der Kurzname vor dem ersten Punkt verglichen
- **Fehlermeldung von Check 8 war irreführend**: „kein DC mit auswertbaren DNS-Zonen (nicht erreichbar: ...)" behauptete eine Nichterreichbarkeit, obwohl nur die DNS-Abfrage scheiterte. Sie heißt jetzt „... (DNS-Abfrage fehlgeschlagen: ...)" und nennt zusätzlich die tatsächliche Ursache je DC; Check 9 nennt die Ursache ebenfalls
- **Check 7 meldete `0.in-addr.arpa`, `127.in-addr.arpa` und `255.in-addr.arpa` als „nicht AD-integriert"**: diese drei Reverse-Lookup-Zonen legt der Windows-DNS-Dienst automatisch selbst an; sie sind korrekt **nicht** AD-integriert und auf jedem Windows-DNS-Server identisch vorhanden. Als Befund gemeldet war das reines Rauschen und lenkte von echten Problemen ab. Neue Liste `$Global:DNSDefaultReverseZones` wird in `Test-Check-DNS` von der Prüfung ausgenommen; eine **echte** Primary-Zone ohne AD-Integration und `NonsecureAndSecure`-Updates werden weiterhin gemeldet
- **Check 8 meldete bei 8 von 9 Zonen „SOA-Expire 0 Tage unterschreitet die Schwelle"** – ein reiner Lesefehler: `[double]$rd.ExpireInterval.TotalDays` ergibt bei fehlender/anders benannter Eigenschaft `$null`, und `[double]$null` ist `0`. Der Wert flog also stillschweigend auf 0 und verletzte immer die Schwelle, obwohl er schlicht nicht lesbar war; eine Zone mit 0 Tagen Ablaufzeit wäre sofort defunkt. Neue Funktion `ConvertFrom-SOAInterval` wertet `[timespan]` **und** Sekunden-Zahlen (WMI-Abbild) korrekt aus, gibt bei nicht auslesbaren Werten `$null` zurück und lässt diese Werte unberücksichtigt – in den Spalten `Refresh`/`Expire` erscheint dann `-`. Wenn auf **allen** DCs einer Zone die Intervalle nicht lesbar sind, meldet der Check das jetzt ausdrücklich („SOA-Intervalle (Refresh/Expire) nicht auslesbar"), statt eine erfundene Schwellenverletzung zu behaupten. Zusätzlich wird mit zwei Nachkommastellen gerechnet, damit kleine echte Werte nicht mehr auf `0 d` abgerundet werden

- **Check 8 fragte bei Forwarder-Zonen (z. B. 	est.de) unnotigerweise SOA ab**: Forwarder-Zonen enthalten per Definition keine Ressourcenrekorde und damit keine SOA. Die Abfrage schlug immer fehl („SOA-Abfrage fehlgeschlagen auf …") und war ein reiner Fehlalarm. Forwarder-Zonen werden jetzt vor der SOA-Lesung ausgelassen; sie erscheinen im Report mit - bei Refresh/Expire und ohne Befund
- **Check 8 meldete TrustAnchors als „DynamicUpdate='None' auf AD-Zone"**: TrustAnchors ist die von Windows selbst angelegte DNSSEC-Trust-Anchor-Zone; dort sind statische Einträge korrekt und dynamische Registrierung unerwuenscht. Neue Liste $Global:DNSSystemZones wird von der DynamicUpdate-Pruefung ausgenommen

#### Geändert
- Version auf 2.9 erhöht (61 Checks)
- 11 neue konfigurierbare Werte im Variablenblock: `RC4EventDays` (7), `RC4EventSampleLimit` (5000), `EncTypesAesCoverageMin` (90), `DNSZoneExpireMinDays` (7), `DNSZoneRefreshMaxHours` (24), `StaleDCWarnAgeDays` (0), `ReportOverviewFindingsMax` (5), `SPNMaxObjSpns` (20), `SPNMaxDnsProbe` (200), `SPNInventoryMaxRows` (200), `SPNUserAccountClassWarn`
- L10n-Tabelle auf 717 DE/EN-Einträge erweitert (Glue 0/0); dublette DE-Schlüssel mit abweichender Übersetzung 11 → 10
- Neuer Parameter `-NoElevate` in der Wiki-Parameterseite dokumentiert; `-OutputPath` (vorbestehender Skriptparameter) war dort nie aufgeführt und ist jetzt ebenfalls erfasst
- README (Titel, Version-/Checks-Badge, Feature-Liste, beide Check-Tabellen, Changelog) und Wiki auf 61 Checks und Version 2.9 aktualisiert
- Skript-Header: „54 thematisch sortierte Pruefpunkte" → 61, Versionshinweis „Version : 2.8 (55 Checks ...)" → „2.9 (61 Checks ...)"

### [2.8] - 2026-10-14

#### Hinzugefügt
- **Check 55: KMS-Server & Konfiguration** – sucht KMS-Hosts per DNS-SRV (`_vlmcs._tcp.<ForestRoot>` bzw. `<Domain>`) und liest deren Konfiguration aus
  - **Discovery**: `Resolve-DnsName -Type SRV` auf `_vlmcs._tcp.*` – eintraglose Zone wird als CRITICAL gemeldet (Clients finden keinen KMS-Host)
  - **Konfiguration je Host** (WinRM oder lokal; nicht erreichbare Hosts werden als WARN mit Grund gemeldet): Dienst `KeyManagementService` inkl. StartTyp – **mehrstufig** erkannt (`Get-Service -Name`, `-DisplayName` EN/DE, die **vollständige** CIM-`Win32_Service`-Liste, zuletzt der Service-Registry-Schlüssel), Port aus `...\KeyManagementService\Parameters`, Port-Erreichbarkeit per TCP-Test auf localhost und der **laufende Prozess auf dem KMS-Port** (`Get-NetTCPConnection`), Aktivierungs-Zähler (`KeyManagementServiceCurrentCount/TotalRequests/FailedRequests`), Zeitraum und Retry-Intervall aus `...\SoftwareProtectionPlatform`, Host-Key (`PartialProductKey`) und Kanal aus `SoftwareLicensingService` (CIM, sonst WMI)
  - **Robustes Registry-Lesen**: explizite 64-Bit-Registryansicht (überlebt 32-Bit-Umleitung) mit Fallback auf den PowerShell-Provider; ein lesbarer Schlüssel ohne KMS-Werte gilt als „keine KMS-Konfiguration", nicht als „kein Zugriff"
  - **Bewertung**: CRITICAL bei fehlendem SRV-Eintrag, wenn der befragte Host **kein Windows-KMS** betreibt (Dienst nicht registriert), bei gestopptem Dienst, unerreichbarem Port oder Aktivierungs-Anzahl unter 5 (Server/Office); WARN unter 25 (Client-Schwelle), bei abweichendem Port ≠ 1688, ohne Host-Key, bei Retail-Kanal, >50 % fehlgeschlagenen Anfragen, nicht auslesbarem Dienst-Status oder nur einem Host (kein Failover)
  - **Zusatz-Signale**: gesetztes `KeyManagementServiceName` auf einen fremden Rechner weist die Maschine als KMS-**Client** aus; installierte Rolle *Volume Activation Services* ohne Host-Key deutet auf einen entfernten oder nie installierten Host-Key hin (prüfen mit `slmgr /dlv`); ähnlich benannte Dienste (`KMS`/`KeyManagement`/`VolumeActivation`) werden aus derselben CIM-Abfrage erfasst und im `Detail` genannt
  - **Hinweis-Zeile**: liegt kein SRV-Eintrag vor, werden zusätzlich alle erreichbaren DCs nach installiertem KMS-Dienst abgesucht
  - Registriert in GUI-Gruppe „System & Updates", Shell-Menü (Bereich Forest) und gruppiertem HTML-Report; 20 Spalten inkl. neuer Spalte `Method` (Zugriffsweg: WinRM/Lokal/None), DE/EN übersetzt

#### Behoben
- **Check 55**: der unbelegte Platzhalter `-` im Key-Kanal wird nicht mehr als echter Wert gewertet – vorher meldete jeder Host ohne auslesbaren Kanal fälschlich „Key-Kanal '-' statt 'Volume' – ggf. Retail-Key statt Host-Key installiert"
- **Check 55**: Fehlen Aktivierungs-Zähler wird bei fehlendem KMS-Dienst nicht mehr als separater Fund gemeldet (ist dort Selbstverständlichkeit)
- **Check 55**: ein L10n-Eintrag (`) - Konfiguration konnte nicht gelesen werden`) griff mangels passender Umgebung nie und wurde korrigiert
- **Check 55**: widersprüchliche Meldung bei Hosts mit installierter Rolle und antwortendem Port behoben – vorher hieß es pauschal „der Host ist KEIN KMS-Host!" und verwies zugleich auf den DNS-SRV-Eintrag, obwohl Rolle und Port dafür zu wenig Belege sind. Jetzt wird der Befund benannt (Dienst nicht registriert), die Indizien getrennt aufgeführt und der DNS-Hinweis nur noch gegeben, wenn für den Host **keinerlei** KMS-Spur existiert
- **Check 55**: der Dienst wird auch gefunden, wenn er unter abweichendem Namen registriert ist – ausgewertet wird jetzt die vollständige `Win32_Service`-Liste statt nur nach dem exakten Namen zu filtern

#### Geändert
- Version auf 2.8 erhöht (55 Checks)
- Neue konfigurierbare Schwellwerte `$Global:KMSMinCountServer` (5) und `$Global:KMSMinCountClient` (25) im Variablenblock
- README (Badge, Feature-Liste, beide Check-Tabellen) und Wiki auf 55 Checks aktualisiert

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

### [2.13] - 2026-10-19

#### Changed
- **Check 55 completely rebuilt** (the previous queries came back empty):
  - **Discovery** via the DNS SRV records `_vlmcs._tcp.<ForestRoot>`, `_vlmcs._tcp.<Domain>` and per site `_vlmcs._tcp.<Site>._sites.<Domain>`; all hits are merged per host
  - **Per host:** TCP reachability of the published port, Software Protection (`sppsvc`) incl. start type, KMS host key (CSVLK) and counters from `SoftwareLicensingProduct` (`IsKeyManagementServiceMachine`, `KeyManagementServiceCurrentCount`, `RequiredClientCount`, `...TotalRequests`, `...FailedRequests`)
  - **Fixed:** wrong service name (`KeyManagementService` does not exist – KMS runs inside the `sppsvc` service), wrong CIM class for the counters (`SoftwareLicensingService` instead of `SoftwareLicensingProduct`) and a registry read that targeted the local instead of the remote machine
  - **CIM** via WinRM first, then via DCOM. If both are blocked, the details are reported as unreadable (INFO) – the host is no longer flagged as CRITICAL across the board
  - **AD KMS:** if no SRV record exists, the check probes all DCs on TCP 1688. The `AufDC` column thereby answers whether a KMS runs on a domain controller
  - **Assessment:** published host unreachable = CRITICAL; host without CSVLK or without DNS publication = WARN; missing detail data or activation threshold not yet reached = INFO
  - Row kinds `Host`, `Hinweis`, `Summary`, `Fehler`

#### Added
- **Check 55b: Active Directory-based activation (ADBA)** – reads the activation objects (`msSPP-ActivationObject`) under `CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration` incl. display name, CSVLK partial key (`msSPP-CSVLKPartialProductKey`), license blob (`msSPP-OnlineLicense`), creation and change date. If the container is missing or empty, this is reported as INFO ("not configured"/"not active") – not as an error
  - Row kinds `Objekt`, `Summary`, `Fehler`
- New thresholds `$Global:KMSProbeTimeoutMs` (1500 ms, TCP test) and `$Global:KMSCimTimeoutSec` (6 s, CIM connection)
- New test script `test-55-kms-adba.ps1` added to the test suite

#### Version
- Version bumped to 2.13 (74 numbered checks, plus sub-checks 04b, 32a–c and 55b); script header, README and wiki aligned

### [2.12] - 2026-10-19

#### Added
- **New GUI group "Hybrid & Cloud (Entra)"** – purely local checks of the cloud connection; only AD is read, no cloud API is contacted and nothing is changed
- **Check 72: Entra sync service accounts** – inventories the service accounts of the Entra synchronization (`MSOL_*` = Entra Connect Sync, `AAD_*` = legacy DirSync) with password age (`PasswordLastSet`), "password never expires", enabled state, creation date and group memberships; privileged groups are detected via well-known SID (language-independent). More than one account, a disabled account, an outdated password (`$Global:EntraSyncAccountPwdWarnDays`, 365 days) or a privileged group are reported as WARN
  - Row kinds `Konto`, `Summary`, `Fehler`
- **Check 73: Seamless SSO (AZUREADSSOACC)** – checks the computer account `AZUREADSSOACC` and the age of its Kerberos decryption key (`PasswordLastSet`); if `$Global:SeamlessSSOKeyWarnDays` (30 days) is exceeded, a rollover is recommended. If no account exists, Seamless SSO is not set up – reported as INFO and not as an error
  - Row kinds `Objekt`, `Summary`, `Fehler`
- **Check 74: Cloud connectivity (inventory)** – documents the cloud connection visible in AD: hybrid join SCP (`CN=Device Registration Configuration` incl. `azureADId`/`azureADName`), Kerberos cloud trust object (`AzureADKerberos`), hybrid join devices (`msDS-DeviceID`), synchronization accounts and alternative UPN suffixes of the forest. Explicitly a documentation inventory (assessment INFO); areas that cannot be read are named as such and not claimed to be "not configured"
  - Row kinds `Bereich`, `Summary`
- New thresholds `$Global:EntraSyncAccountPwdWarnDays` (365 days) and `$Global:SeamlessSSOKeyWarnDays` (30 days)

#### Changed
- Version bumped to 2.12 (74 checks); script header, README and wiki aligned
- New test script `test-72-74-cloud.ps1` added to the test suite

### [2.11] - 2026-10-18

#### Added
- **Check 64: IPv6 status per DC** – computer name, IPv6 binding state of all adapters and the registry value `DisabledComponents` (`HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`) as raw value plus plain-text interpretation (MS KB929852); one result row per DC, deviations between adapter binding and registry reported as WARN
- **Check 65: Computer SPNs** – SPN export with **one row per SPN** for computer accounts: computer name, DNS host name, DN, enabled/disabled, operating system, full SPN, extracted service class and duplicate flag (same rule as check 38)
- **Check 66: User, MSA and gMSA SPNs** – same data structure as check 65 plus sAMAccountName, UPN and "password never expires"; classic user accounts, MSA and gMSA are not silently mixed but shown separately in the `ObjektTyp` column (filterable via `-ObjectType`)
- **Check 67: PKI – Enterprise CA inventory** – CA objects from `CN=Enrollment Services` (`pKIEnrollmentService`) with their CA certificates (one row per certificate), remaining lifetime, number of published templates, publication of the issuer in `CN=Certification Authorities` and a read-only reachability check of the `CertEnroll` share
- **Check 68: PKI – Trusted root and intermediate certificates** – certificates from `CN=Certification Authorities`, `CN=NTAuthCertificates` and the public key policies of the GPOs (hex-encoded content), sources reported separately, duplicate detection by thumbprint
- **Check 69: PKI – Certificate templates & publication** – template inventory (`pKICertificateTemplate`) with EKU plain text, validity, autoenrollment, actual CA publication and schema version; CA references without a template object and a heuristic for overly open templates
- **Check 70: PKI – References to WLAN and mail encryption** – mapping via EKUs (client authentication, secure email, EFS) as well as the public key and WLAN policies; explicitly marked as a plausibility check, missing mapping reported as WARN
- **Check 71: PKI – Revocation and publication endpoints** – CDP/AIA addresses from the CA certificates including a read-only reachability check as well as the revocation lists published in AD (`CN=<CA>,CN=CDP`); endpoints that cannot be tested remain visible and are never reported as OK
- **New GUI group "PKI & Zertifikate"** – the five sub-checks each assess only their own layer; a summarizing "PKI OK" statement is deliberately omitted
- New thresholds `$Global:PkiCertWarnDays` (90 days remaining lifetime) and `$Global:PkiEndpointTimeoutSec` (10 s endpoint test)

#### Fixed
- **Check 62** reported only "Summary" as its finding even when the cause was a missing reverse zone; the finding now names the missing reverse zone, and error rows without a summary are reported as WARN instead of NODATA
- **Multi-valued binary attributes** (`cACertificate`, `certificateRevocationList`) were split into single bytes by `@()`; the new helper `Get-PkiBinaryValues` handles both a byte array and a list of byte arrays correctly
- **CDP/AIA addresses** are now read directly from the raw extension bytes, because the .NET Framework does not decode these extensions in `Format()`
- **GPO certificate lookup** now uses relative XPath expressions (`.//`), otherwise every policy would have reported the certificates of the entire report

#### Changed
- Version bumped to 2.11 (71 checks); script header, README and wiki aligned
- New test script `test-67-71-pki.ps1` (60 assertions) added to the test suite
### [2.10] - 2026-10-16

#### Added
- **Check 62: DNS reverse lookup completeness** – collects all A and AAAA records of all primary forward zones and checks per IP whether a matching reverse zone (`in-addr.arpa` / `ip6.arpa`) exists; missing reverse zones are reported with the affected IPs and hosts. Only the zone is checked, not whether a PTR record exists
  - Row kinds `Summary`, `MissingReverseZone`, `Fehler`
- **Check 63: AD subnets vs. reverse lookup zones** – lists all AD subnets with their assigned site and checks the matching reverse zone; additionally reports DNS networks with A records from all primary forward zones that have no AD subnet, as well as reverse zones without a subnet (INFO)
  - WARN for subnets without a reverse zone or site, for DNS networks without an AD subnet and when no subnets are defined at all
  - Row kinds `Subnet`, `ZoneOhneSubnet`, `DNSNetzOhneSubnet`, `Fehler`, `Summary`
  - Registered in the GUI group "AD topology & objects", in the forest section of the shell menu and in the selection lists

#### Fixed
- **Version variable**: `$Global:ScriptVersion` was still 2.7 and was shown incorrectly in the report header, the update check and the window title; script header (54 → 63 checks) aligned as well

#### Changed
- Version bumped to 2.10 (63 checks)
- README and wiki updated to 63 checks and version 2.10

### [2.9] - 2026-10-15

#### Added
- **Check 56: Dead DCs & DC availability** – cross-checks seven independent sources of "which DCs exist" (live inventory, computer objects in `OU=Domain Controllers`, server objects plus NTDS settings in the Config NC, replication partners of all domains, among others) and lists every DC with its live/orphaned status and DNS existence
  - Row kinds `DC` and `Quelle` (row key `Kind|Name`): each source is assessed separately, diverging or unreadable sources name the affected objects
  - New threshold `$Global:StaleDCWarnAgeDays` (0 = every orphaned DC object is flagged, 1 or more only older ones)
  - Registered in the GUI group "AD topology & objects" and the forest section of the console menu
- **Check 57: RC4 / LM evidence per DC** – collects actual evidence that RC4/LM is still in use instead of only reading configuration: `AllowableEncryptionTypes` of computer and user accounts, the `NoLMHash` flag and evaluated Kerberos tickets 4768/4769 from the security log
  - Row kinds `Netlogon`, `NoLMHash`, `RC4-Tickets` (row key `Kind|DCName`)
  - Time window and sample size via `$Global:RC4EventDays` (7 days) and `$Global:RC4EventSampleLimit` (5000 tickets per DC); an unreadable security log is reported as its own finding instead of silently skipping that part
  - Registered in the GUI group "Identity & Kerberos", the per-DC section of the console menu and the security suite
- **Check 58: SPN inventory & stale SPNs** – inventories all SPNs by service class and object, complementing check 38 (duplicate detection only)
  - Row kinds `Zusammenfassung`, `Objekt`, `Klasse`, `Host`, `Fehler` (row key `Kind|Name`); summary row flags are not counted twice as findings
  - Flags objects with an unusual number of SPNs (`$Global:SPNMaxObjSpns`, 20), SPNs on disabled accounts, unexpected SPN classes on user accounts (`$Global:SPNUserAccountClassWarn`) and SPN host names that do not resolve (max. `$Global:SPNMaxDnsProbe` = 200 lookups, output per row kind capped at `$Global:SPNInventoryMaxRows` = 200)
  - New column `DeaktKonten` (see "Fixed")
  - Registered in the GUI group "Identity & Kerberos", the forest section of the console menu and the security suite
- **Check 59: Encryption types: distribution & AES coverage** – distributes all accounts by encryption type combination, checks AES coverage against `$Global:EncTypesAesCoverageMin` (90%) and correlates the OS group with the encryption type actually set
  - Row kinds `Verteilung`, `OS`, `Fazit` (summary row `AES-Abdeckung`) and `Fehler` (row key `Kind|Name`)
  - A modern OS group without full AES coverage is reported separately
  - Registered in the GUI group "Identity & Kerberos", the forest section of the console menu and the security suite
- **Check 60: DNS zones: SOA & replication** (forest) – evaluates the SOA refresh/expire values using the previously unused thresholds `$Global:DNSZoneRefreshMaxHours` (24) and `$Global:DNSZoneExpireMinDays` (7); additionally each zone is checked for
  - `ReplicationScope='Server'` (zone on a single server, not replicated) or a scope assignment varying between the DCs
  - `DynamicUpdate='None'` on AD-integrated zones (`NonsecureAndSecure` remains reserved for check 6)
  - differing SOA serial numbers of the same zone between the DCs
  - Row kinds `Zusammenfassung`, `Zone`, `Fehler` (row key `Kind|Name`); puts the previously unused thresholds to work and replaces neither check 6 nor check 42
  - Registered in the GUI group "DC infrastructure" and the forest section of the console menu
- **Check 61: DNS forwarders & conditional forwarders** (forest) – global forwarders including root hint availability as well as conditional forwarders with their target IP per DNS server
  - Detects only partially distributed CFs (registry-based, **not** replicated), CFs without a master server (cannot resolve at all) and forwarding loops whose target is one of our own DNS servers
  - The reachability of the forwarder IPs intentionally stays with `dcdiag /test:DnsForwarders` in check 3 (no duplication); row kinds `Zusammenfassung`, `ConditionalForwarder`, `Forwarder` (row key `Kind|Name`)
  - Registered in the GUI group "DC infrastructure" and the forest section of the console menu
- **Overall summary of findings in the HTML report** – a single table right behind the executive dashboard listing all flagged checks, sorted by severity; findings per check are capped at `$Global:ReportOverviewFindingsMax` (5), followed by "... and n more findings". Not a check of its own, but part of the report
- **Automatic elevation** – Windows requires administrator rights for DNS and WMI queries (e.g. `root\MicrosoftDNS`); without those rights the DNS checks reported "no zones" or "DNS query failed" even though the DNS module was installed. If the script is not running with admin rights it now relaunches itself with a UAC prompt; all passed parameters are preserved (`-FullRun`, `-OnlyChecks`, `-OutputPath`, `-Language`, `-NoInteractive`, `-NoUpdateCheck`)
  - New functions `Test-IsElevated`, `Get-ElevationCommand` and `Start-ElevatedRestart`; a global flag (`ElevationHandled`) prevents an infinite loop
  - Cancelling the UAC prompt does not abort the run: it continues in the current context and explicitly names the missing rights
  - New parameter `-NoElevate` suppresses the restart (useful when testing without admin rights on purpose)

#### Fixed
- **The column header `Deaktiviert` (check 58)** was rendered as `disabled` in English reports: the L10n key comparison is case-insensitive and keeps the first entry (`deaktiviert=>disabled`), which made the added entry `Deaktiviert=>Disabled` a no-op. The column is now called `DeaktKonten` (=> `Disabled accounts`); the case of German body text (`deaktiviert` => `disabled`) remains correct as before
- **README changelog**: the v2.7 entry "still 55 checks" (EN) / "weiterhin 55 Checks" (DE) had been bumped along by a global replace when v2.8 was written and now reads 54 again
- **README title and version badge** were still at v2.7 (not carried along in 2.8) and are now set to 2.9
- **Check 56 hung silently in the queue during runs**: `Get-ADComputer` in `Get-StaleDCObjects` (source "computer objects in `OU=Domain Controllers`") was called without `-Filter`, making PowerShell prompt for the missing parameter interactively – with `-FullRun` or as a scheduled task the run stalled here. The call now includes `-Filter *`
- **Checks 7, 8 and 9 reported "no zones" or "not reachable" on the local DNS DC**: the DnsServer cmdlets were called with `-ComputerName <DC>` throughout, including against the **local** machine. Passing `-ComputerName` for yourself forces a CIM/WMI remoting detour; if WinRM loopback or DCOM is blocked, the query fails even though DNS is installed and the DC is fully reachable via ping/AD/replication. Check 42 was not affected because it already queries without `-ComputerName`. The new function `Get-DnsServerTargets` returns an ordered list of targets to try: locally **without** `-ComputerName` (in-process) first, then `localhost`, then the given name; remotely just the name. Used in `Get-DNSConfiguration`, `Get-DNSZoneConfiguration` and `Get-ConditionalForwarding`
- **`Test-IsLocalComputer` did not recognise the local DC in FQDN form**: check 7 receives the DC as an FQDN (`dc.HostName`) while checks 8/9 use the NetBIOS name (`.Name`); the comparison was strictly exact, so check 7 always treated the local DC as "remote". The first label before the dot is now compared as well
- **Check 8's error message was misleading**: "no DC with evaluable DNS zones (not reachable: ...)" claimed unreachability when only the DNS query had failed. It now reads "... (DNS query failed: ...)" and additionally names the actual cause per DC; check 9 names the cause as well
- **Check 7 flagged `0.in-addr.arpa`, `127.in-addr.arpa` and `255.in-addr.arpa` as "not AD-integrated"**: the Windows DNS server role creates these three reverse lookup zones automatically; they are correctly **not** AD-integrated and present on every Windows DNS server. Reporting them as a finding was pure noise that distracted from real problems. The new list `$Global:DNSDefaultReverseZones` is excluded from the check in `Test-Check-DNS`; a **genuine** primary zone without AD integration and `NonsecureAndSecure` updates are still reported
- **Check 8 reported "SOA-Expire 0 days below threshold" for 8 of 9 zones** – a pure read error: `[double]$rd.ExpireInterval.TotalDays` yields `$null` when the property is missing or named differently, and `[double]$null` is `0`. The value silently became 0 and therefore always violated the threshold, even though it was simply unreadable; a zone with 0 days expiry would be broken immediately. The new function `ConvertFrom-SOAInterval` evaluates `[timespan]` **and** plain numbers (WMI representation) correctly, returns `$null` for unreadable values and leaves them out of the assessment – the `Refresh`/`Expire` columns then show `-`. If the intervals are unreadable on **all** DCs of a zone, the check now says so explicitly ("SOA intervals (refresh/expire) not readable") instead of claiming a fabricated threshold violation. Two decimal places are used as well so that small genuine values are no longer rounded down to `0 d`
- **Check 8 queried SOA on Forwarder zones unnecessarily (e.g. 	est.de)**: Forwarder zones contain no resource records by definition and therefore no SOA. The query always failed ("SOA query failed on …") and was a pure false positive. Forwarder zones are now skipped before the SOA read; they appear in the report with - for Refresh/Expire and no finding
- **Check 8 flagged TrustAnchors as "DynamicUpdate='None' on an AD zone"**: TrustAnchors is the DNSSEC trust anchor zone created by Windows itself; static entries are correct there and dynamic registration is undesirable. The new list $Global:DNSSystemZones is excluded from the DynamicUpdate check


#### Changed
- Version bumped to 2.9 (61 checks)
- 11 new configurable values in the variables block: `RC4EventDays` (7), `RC4EventSampleLimit` (5000), `EncTypesAesCoverageMin` (90), `DNSZoneExpireMinDays` (7), `DNSZoneRefreshMaxHours` (24), `StaleDCWarnAgeDays` (0), `ReportOverviewFindingsMax` (5), `SPNMaxObjSpns` (20), `SPNMaxDnsProbe` (200), `SPNInventoryMaxRows` (200), `SPNUserAccountClassWarn`
- L10n tables extended to 717 DE/EN entries (glue 0/0); duplicated German keys with conflicting translations 11 → 10
- New parameter `-NoElevate` documented on the wiki parameter page; `-OutputPath` (pre-existing script parameter) had never been listed there and is now covered as well
- README (title, version/checks badges, feature list, both check tables, changelog) and wiki updated to 61 checks and version 2.9
- Script header: "54 thematisch sortierte Pruefpunkte" → 61, version note "Version : 2.8 (55 Checks ...)" → "2.9 (61 Checks ...)"

### [2.8] - 2026-10-14

#### Added
- **Check 55: KMS servers & configuration** – locates KMS hosts via DNS SRV (`_vlmcs._tcp.<ForestRoot>` or `<Domain>`) and reads their configuration
  - **Discovery**: `Resolve-DnsName -Type SRV` against `_vlmcs._tcp.*` – an empty zone is reported as CRITICAL (clients find no KMS host)
  - **Per-host configuration** (WinRM or local; unreachable hosts are reported as WARN with the reason): the `KeyManagementService` service including start type – detected **in several stages** (`Get-Service -Name`, `-DisplayName` EN/DE, the **complete** CIM `Win32_Service` list, and finally the service registry key), the port from `...\KeyManagementService\Parameters`, a TCP reachability test of that port on localhost plus the **process listening on the KMS port** (`Get-NetTCPConnection`), the activation counters (`KeyManagementServiceCurrentCount/TotalRequests/FailedRequests`), the collection period and retry interval from `...\SoftwareProtectionPlatform`, and the host key (`PartialProductKey`) plus channel from `SoftwareLicensingService` (CIM, otherwise WMI)
  - **Robust registry reading**: explicit 64-bit registry view (survives 32-bit redirection) with a PowerShell provider fallback; a readable key without KMS values counts as “no KMS configuration”, not as “no access”
  - **Assessment**: CRITICAL for a missing SRV record, when the queried host does **not run Windows KMS** (service not registered), for a stopped service, an unreachable port or an activation count below 5 (server/office); WARN below 25 (client threshold), for a non-default port ≠ 1688, a missing host key, a retail channel, more than 50 % failed requests, an unreadable service status, or a single host (no failover)
  - **Additional signals**: a set `KeyManagementServiceName` pointing at a foreign machine marks it as a KMS **client**; an installed *Volume Activation Services* role without a host key indicates a removed or never installed host key (check with `slmgr /dlv`); similarly named services (`KMS`/`KeyManagement`/`VolumeActivation`) are collected from the same CIM query and named in `Detail`
  - **Note row**: when no SRV record exists, all reachable DCs are additionally scanned for an installed KMS service
  - Registered in the GUI group "System & Updates", the shell menu (forest section) and the grouped HTML report; 20 columns including the new `Method` column (access path: WinRM/local/None), translated DE/EN

#### Fixed
- **Check 55**: the empty placeholder `-` for the key channel is no longer treated as a real value – previously every host without a readable channel falsely reported “key channel '-' instead of 'Volume' – possibly a retail key instead of a host key”
- **Check 55**: a missing activation counter is no longer reported as a separate finding when the KMS service is absent (that is self-evident there)
- **Check 55**: one L10n entry (`) - Konfiguration konnte nicht gelesen werden`) never matched due to a missing context and has been corrected
- **Check 55**: contradictory output for hosts with an installed role and an answering port has been fixed – previously the check stated “the host is NOT a KMS host!” while simultaneously pointing at the DNS SRV record, even though a role and an open port are not enough evidence for that. The finding is now stated precisely (service not registered), the individual indicators are listed separately, and the DNS hint is only given when the host shows **no** KMS trace at all
- **Check 55**: the service is now also found when it is registered under a diverging name – the complete `Win32_Service` list is evaluated instead of filtering only for the exact name

#### Changed
- Version bumped to 2.8 (55 checks)
- New configurable thresholds `$Global:KMSMinCountServer` (5) and `$Global:KMSMinCountClient` (25) in the variables block
- README (badge, feature list, both check tables) and wiki updated to 55 checks

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
