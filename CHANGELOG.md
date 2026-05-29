# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.

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
