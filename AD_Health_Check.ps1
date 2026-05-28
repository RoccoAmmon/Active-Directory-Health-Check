<#
.SYNOPSIS
    Umfassender Active Directory Health Check v2.1 mit Best-Practice-Bewertung.
.DESCRIPTION
    42 thematisch sortierte Pruefpunkte auf allen DCs im Forest mit farbcodiertem
    HTML-Report, Executive Dashboard, CSV-Exporten, Loopback-Erkennung und
    interaktivem Startmenue.
.PARAMETER FullRun
    Fuehrt alle Checks ohne Menue aus (fuer Scheduled Tasks).
.PARAMETER OnlyChecks
    Fuehrt nur die angegebenen Checks aus (z.B. '22_PrintSpooler','19_Unconstrained').
.PARAMETER NoInteractive
    Ueberspringt das Menue (= Full Run).
.NOTES
    Autor   : R_Super Entwickler CS4.7
    Version : 2.1 (42 Checks, erweitert um 5 Identity-/DNS-Checks)
    LogPfad : C:\ScriptLog
.EXAMPLE
    .\AD_HealthCheck.ps1
    .\AD_HealthCheck.ps1 -FullRun
    .\AD_HealthCheck.ps1 -OnlyChecks '22_PrintSpooler'
#>

[CmdletBinding()]
param(
    [switch]$FullRun,
    [string[]]$OnlyChecks,
    [switch]$NoInteractive
)

#region ============================ VARIABLEN ================================

$Global:ScriptName      = "AD_Health_Check"
$Global:ScriptVersion   = "2.1"
$Global:Timestamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$Global:LogDirectory    = "C:\ScriptLog"
$Global:ReportDirectory = "C:\ScriptLog\AD_HealthCheck_$Global:Timestamp"
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
$Global:ServiceMap = [ordered]@{
    'NTDS'     = @{ Names=@('NTDS');      Description='Active Directory Domain Services - Kerndienst.' }
    'DNS'      = @{ Names=@('DNS');       Description='DNS Server - Namensaufloesung, SRV-Records.' }
    'Netlogon' = @{ Names=@('Netlogon');  Description='Netlogon - Sicherer Kanal, Authentifizierung.' }
    'KDC'      = @{ Names=@('Kdc','KDC'); Description='Kerberos KDC - Stellt Kerberos-Tickets aus.' }
    'W32Time'  = @{ Names=@('W32Time');   Description='Windows-Zeit - Kerberos-Pflicht.' }
    'DFSR'     = @{ Names=@('DFSR');      Description='DFS Replication - Repliziert SYSVOL.' }
    'NTFRS'    = @{ Names=@('NtFrs');     Description='File Replication (LEGACY).' }
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
        Add-Content -Path $Global:LogFile -Value $line -ErrorAction Stop
        if (-not $NoConsole) {
            $c = switch ($Level) { 'ERROR'{'Red'} 'WARN'{'Yellow'} 'OK'{'Green'} 'DEBUG'{'DarkGray'} default{'Cyan'} }
            Write-Host $line -ForegroundColor $c
        }
    } catch { Write-Host "LOG-FEHLER: $_" -ForegroundColor Red }
}

#endregion

#region ============= INTERAKTIVES MENUE =====================================

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
               '33_EventLog','34_TimeSync','36_InstalledPrograms','37_WindowsUpdates')
    $forest = @('04b_ReplicationFailures','05_FSMO','16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos',
                '19_UnconstrainedDelegation','20_KerberoastingRisk','25_Sites','26_Subnets','27_Trusts',
                '28_ADRecycleBin','29_TombstoneLifetime','30_Levels','31_GPO','32a_InactiveUsers',
                '32b_InactiveComputers','32c_PasswordNeverExpires','35_Backup','38_SPNDuplicates',
                '39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','42_DNSHygiene')
    $sec = @('09_TLS','10_Cipher','11_SMB','12_NTLMAuth','13_LLMNR','14_LDAPSecurity','15_WindowsFirewall',
             '16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos','19_UnconstrainedDelegation',
             '20_KerberoastingRisk','21_LSAProtection','22_PrintSpooler','23_SecureBoot','24_Certificates',
             '38_SPNDuplicates','39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP')

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
    Write-Progress -Activity "AD Health Check (Laufzeit: $elapsed)" `
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
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        if (-not $Global:LocalIdentifiers) {
            $local = @('localhost','127.0.0.1','::1',$env:COMPUTERNAME)
            try { $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; if ($fqdn) { $local += $fqdn } } catch {}
            try { $local += Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress } catch {}
            $Global:LocalIdentifiers = $local | Select-Object -Unique
        }
        foreach ($id in $Global:LocalIdentifiers) { if ($ComputerName -ieq $id) { return $true } }
        return $false
    } catch { return $false }
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
    $res = @()
    foreach ($svc in $Global:ServiceMap.Keys) {
        $cfg = $Global:ServiceMap[$svc]; $ok = $false
        foreach ($n in $cfg.Names) {
            try {
                $s = Get-Service -ComputerName $DC -Name $n -ErrorAction Stop
                $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName=$s.Name; Status=$s.Status; StartType=$s.StartType }
                $ok=$true; break
            } catch {}
        }
        if (-not $ok) { $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName='N/A'; Status='NotFound'; StartType='N/A' } }
    }
    $res
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
    Get-DnsServerZone -ComputerName $DC -ErrorAction Stop |
        Select-Object @{n='DCName';e={$DC}}, ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate
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
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        if (-not $Global:LocalIdentifiers) {
            $local = @('localhost','127.0.0.1','::1',$env:COMPUTERNAME)
            try { $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; if ($fqdn) { $local += $fqdn } } catch {}
            try { $local += Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress } catch {}
            $Global:LocalIdentifiers = $local | Select-Object -Unique
        }
        foreach ($id in $Global:LocalIdentifiers) { if ($ComputerName -ieq $id) { return $true } }
        return $false
    } catch { return $false }
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
    $res = @()
    foreach ($svc in $Global:ServiceMap.Keys) {
        $cfg = $Global:ServiceMap[$svc]; $ok = $false
        foreach ($n in $cfg.Names) {
            try {
                $s = Get-Service -ComputerName $DC -Name $n -ErrorAction Stop
                $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName=$s.Name; Status=$s.Status; StartType=$s.StartType }
                $ok=$true; break
            } catch {}
        }
        if (-not $ok) { $res += [pscustomobject]@{ DCName=$DC; Service=$svc; Description=$cfg.Description; RealName='N/A'; Status='NotFound'; StartType='N/A' } }
    }
    $res
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
    Get-DnsServerZone -ComputerName $DC -ErrorAction Stop |
        Select-Object @{n='DCName';e={$DC}}, ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate
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
        if ($s.Status -eq 'NotFound' -and $s.Service -in 'NTDS','Netlogon','KDC','W32Time','DNS') { $f += "KRIT: $($s.Service) auf $($s.DCName) fehlt"; $rf[$id]='CRITICAL'; $c=$true }
        elseif ($s.Status -ne 'Running' -and $s.Status -ne 'NotFound') { $f += "$($s.Service) auf $($s.DCName): $($s.Status)"; $rf[$id]='WARN' }
        else { $rf[$id]='OK' }
    }
    $st = if ($c) { 'CRITICAL' } elseif ($f.Count) { 'WARN' } else { 'OK' }
    New-Assessment -OverallStatus $st -Summary $(if($st -eq 'OK'){'Alle Dienste OK'}else{"$($f.Count) Problem(e)"}) -Findings $f -RowFlags $rf
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
        if ($z.ZoneType -eq 'Primary' -and -not $z.IsDsIntegrated) { $f += "$($z.ZoneName) nicht AD-integriert"; $rf[$id]='WARN' }
        elseif ($z.DynamicUpdate -eq 'NonsecureAndSecure') { $f += "$($z.ZoneName) erlaubt unsichere Updates!"; $rf[$id]='CRITICAL' }
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
                "Keine Eintraege." | Out-File -FilePath $p -Encoding UTF8 -ErrorAction SilentlyContinue
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
    #>
    param([string]$Status)
    $cfg = switch ($Status) {
        'OK'       { @{ Text='OK';          Class='badge-ok' } }
        'WARN'     { @{ Text='WARNUNG';     Class='badge-warn' } }
        'CRITICAL' { @{ Text='KRITISCH';    Class='badge-critical' } }
        'INFO'     { @{ Text='INFO';        Class='badge-info' } }
        'NODATA'   { @{ Text='KEINE DATEN'; Class='badge-nodata' } }
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
        [void]$sb.AppendLine("<!DOCTYPE html><html lang='de'><head><title>AD Health Check Report - $Global:Timestamp</title>$head</head><body>")
        [void]$sb.AppendLine("<h1>Active Directory Health Check Report</h1>")
        [void]$sb.AppendLine("<p><b>Erstellt:</b> $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') &nbsp;|&nbsp; <b>Version:</b> $Global:ScriptVersion &nbsp;|&nbsp; <b>Modus:</b> $Global:RunMode</p>")

        # --- Executive Dashboard ---
        [void]$sb.AppendLine("<div class='dashboard'><h2 style='margin-top:0;border:none;background:none;'>Executive Dashboard</h2><div class='dash-grid'>")
        [void]$sb.AppendLine("<div class='dash-tile dash-ok'><span class='n'>$cOK</span><span class='l'>OK</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-warn'><span class='n'>$cW</span><span class='l'>WARNUNGEN</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-crit'><span class='n'>$cC</span><span class='l'>KRITISCH</span></div>")
        [void]$sb.AppendLine("<div class='dash-tile dash-info'><span class='n'>$($cI+$cN)</span><span class='l'>INFO</span></div>")
        [void]$sb.AppendLine("</div></div>")

        # --- Uebersichts-Tabelle (# = laufende Nummer) ---
        [void]$sb.AppendLine("<h2>Uebersicht aller Checks</h2>")
        [void]$sb.AppendLine("<table class='overview'><thead><tr><th style='width:40px;'>#</th><th>Check</th><th class='status-cell'>Status</th><th>Zusammenfassung</th></tr></thead><tbody>")
        $i = 0
        foreach ($k in Get-ReportKeys) {
            $t = $Global:ReportTitles[$k]
            $a = $Global:Assessments[$k]
            if (-not $a) { continue }
            $i++
            $b = Get-StatusBadgeHtml -Status $a.OverallStatus
            $s = if ($a.Summary) { $a.Summary } else { '-' }
            [void]$sb.AppendLine("<tr><td>$i</td><td><a href='#$k'>$t</a></td><td>$b</td><td>$s</td></tr>")
        }
        [void]$sb.AppendLine("</tbody></table>")

                # --- Detail-Abschnitte ---
        $j = 0
        foreach ($k in Get-ReportKeys) {
            $t = $Global:ReportTitles[$k]
            $a = $Global:Assessments[$k]
            if (-not $a) { continue }
            $j++
            $b = Get-StatusBadgeHtml -Status $a.OverallStatus
            [void]$sb.AppendLine("<h2 id='$k'>$j. $t $b</h2>")

            if ($a.Summary) { [void]$sb.AppendLine("<p><b>Zusammenfassung:</b> $($a.Summary)</p>") }
            if ($a.Findings -and @($a.Findings).Count -gt 0) {
                $fc = if ($a.OverallStatus -eq 'CRITICAL') { 'findings crit' } else { 'findings' }
                [void]$sb.AppendLine("<div class='$fc'><b>Auffaelligkeiten / Handlungsempfehlungen:</b><ul>")
                foreach ($x in $a.Findings) {
                    $e = "$x" -replace '<','&lt;' -replace '>','&gt;'
                    [void]$sb.AppendLine("<li>$e</li>")
                }
                [void]$sb.AppendLine("</ul></div>")
            }

            $items = $Global:Results[$k]
            if ($null -eq $items -or @($items).Count -eq 0) {
                [void]$sb.AppendLine("<p><i>Keine Daten.</i></p>")
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
                    foreach ($p in $props) { [void]$sb.AppendLine("<th>$p</th>") }
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
                    [void]$sb.AppendLine(($items | Select-Object $props | ConvertTo-Html -Fragment))
                }
                Write-Host ("  [+] {0,-32} -> {1,4} Zeilen (Status: {2})" -f $k, @($items).Count, $a.OverallStatus) -ForegroundColor Green
            } catch {
                [void]$sb.AppendLine("<pre>$($items | Out-String)</pre>")
                Write-Host ("  [!] {0,-32} -> Fallback" -f $k) -ForegroundColor Yellow
            }
        }

        [void]$sb.AppendLine("<div class='footer'>Erzeugt von <b>$Global:ScriptName v$Global:ScriptVersion</b> &nbsp;|&nbsp; $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') &nbsp;|&nbsp; Laufzeit: $((New-TimeSpan -Start $Global:ProgressStats.StartTime -End (Get-Date)).ToString('hh\:mm\:ss'))</div>")
        [void]$sb.AppendLine("</body></html>")
        $sb.ToString() | Out-File -FilePath $Global:HtmlReport -Encoding UTF8
        Write-Log "HTML-Report erstellt: $Global:HtmlReport" -Level OK
    } catch { Write-Log "HTML-Report Fehler: $_" -Level ERROR }
}

#endregion

#region ============= MAIN ===================================================

function Start-ADHealthCheck {
    try {
        Initialize-LogEnvironment
        $Global:ProgressStats.StartTime = Get-Date
        $skippedDCs   = @()
        $reachableDCs = @()

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
            Show-ScriptMenu
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
                       '33_EventLog','34_TimeSync','36_InstalledPrograms','37_WindowsUpdates') |
                     Where-Object { $Global:SelectedChecks -contains $_ }
        $selForest = @('04b_ReplicationFailures','05_FSMO','16_PrivilegedAccounts','17_PasswordPolicy','18_Kerberos',
                       '19_UnconstrainedDelegation','20_KerberoastingRisk','25_Sites','26_Subnets','27_Trusts',
                                             '28_ADRecycleBin','29_TombstoneLifetime','30_Levels','31_GPO','35_Backup',
                                             '38_SPNDuplicates','39_ASREPRoasting','40_AdminSDHolderDrift','41_FGPP','42_DNSHygiene') |
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
