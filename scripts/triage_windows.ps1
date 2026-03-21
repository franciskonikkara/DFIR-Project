# ============================================================================
# Windows Live Triage Script for Incident Response
# Version: 1.0
# Usage: Run as Administrator on the suspected compromised host
#        .\triage_windows.ps1 -CaseID "IR-2024-001" -Analyst "Jane Smith"
#
# Collects:
#   - Running processes (full command lines + hashes)
#   - Active network connections with process mapping
#   - Logged in users and recent logons
#   - Scheduled tasks
#   - Active services
#   - Autorun registry entries
#   - Prefetch files list
#   - Recent file system changes
#   - DNS cache
#   - ARP cache
#   - Windows event log summaries (Security, System, Application)
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$CaseID,

    [Parameter(Mandatory=$false)]
    [string]$Analyst = "Unknown",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\Triage_$CaseID"
)

$ErrorActionPreference = "SilentlyContinue"
$TriageStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC

Write-Host "[*] DFIR Triage Script - Case: $CaseID" -ForegroundColor Cyan
Write-Host "[*] Analyst: $Analyst" -ForegroundColor Cyan
Write-Host "[*] Started: $TriageStart" -ForegroundColor Cyan
Write-Host "[*] Output: $OutputPath" -ForegroundColor Cyan

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# ============================================================
# METADATA
# ============================================================
$metadata = @{
    case_id = $CaseID
    analyst = $Analyst
    hostname = $env:COMPUTERNAME
    triage_start = $TriageStart
    os = (Get-WmiObject Win32_OperatingSystem).Caption
    architecture = $env:PROCESSOR_ARCHITECTURE
    current_user = $env:USERNAME
    domain = $env:USERDOMAIN
    ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -ExpandProperty IPAddress) -join ", "
}
$metadata | ConvertTo-Json | Out-File "$OutputPath\00_metadata.json" -Encoding UTF8

Write-Host "[+] Metadata collected" -ForegroundColor Green

# ============================================================
# RUNNING PROCESSES
# ============================================================
Write-Host "[*] Collecting processes..." -ForegroundColor Yellow

$processes = Get-Process -IncludeUserName | Select-Object `
    PID, ProcessName, UserName, CPU, WorkingSet, Path, `
    @{N='CommandLine';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}, `
    @{N='ParentPID';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}, `
    @{N='StartTime';E={$_.StartTime}}, `
    @{N='MD5';E={if($_.Path -and (Test-Path $_.Path)){(Get-FileHash -Path $_.Path -Algorithm MD5 -ErrorAction SilentlyContinue).Hash}else{"N/A"}}}, `
    @{N='SHA256';E={if($_.Path -and (Test-Path $_.Path)){(Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}else{"N/A"}}}

$processes | Export-Csv "$OutputPath\01_processes.csv" -NoTypeInformation -Encoding UTF8
$processes | ConvertTo-Json | Out-File "$OutputPath\01_processes.json" -Encoding UTF8
Write-Host "[+] Processes: $($processes.Count) captured" -ForegroundColor Green

# ============================================================
# NETWORK CONNECTIONS
# ============================================================
Write-Host "[*] Collecting network connections..." -ForegroundColor Yellow

$netstat = netstat -ano
$netstat | Out-File "$OutputPath\02_netstat.txt" -Encoding UTF8

$connections = Get-NetTCPConnection | Select-Object `
    LocalAddress, LocalPort, RemoteAddress, RemotePort, State, `
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, `
    OwningProcess, CreationTime

$connections | Export-Csv "$OutputPath\02_network_connections.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Network connections: $($connections.Count) captured" -ForegroundColor Green

# DNS Cache
Write-Host "[*] Collecting DNS cache..." -ForegroundColor Yellow
Get-DnsClientCache | Export-Csv "$OutputPath\02_dns_cache.csv" -NoTypeInformation -Encoding UTF8

# ARP cache
arp -a | Out-File "$OutputPath\02_arp_cache.txt" -Encoding UTF8
Write-Host "[+] DNS and ARP cache captured" -ForegroundColor Green

# ============================================================
# LOGGED IN USERS
# ============================================================
Write-Host "[*] Collecting user sessions..." -ForegroundColor Yellow

query user 2>&1 | Out-File "$OutputPath\03_logged_in_users.txt" -Encoding UTF8

# Recent logons from event log
$logonEvents = Get-WinEvent -FilterHashtable @{
    LogName='Security';
    Id=4624;
    StartTime=(Get-Date).AddDays(-7)
} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object `
    TimeCreated,
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='AccountName';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}},
    @{N='ProcessName';E={$_.Properties[17].Value}}

$logonEvents | Export-Csv "$OutputPath\03_recent_logons.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] User sessions captured" -ForegroundColor Green

# ============================================================
# SCHEDULED TASKS
# ============================================================
Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Yellow

$tasks = Get-ScheduledTask | Select-Object `
    TaskName, TaskPath, State,
    @{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute + " " + $_.Arguments}) -join "; "}},
    @{N='Triggers';E={($_.Triggers | ForEach-Object {$_.GetType().Name}) -join "; "}},
    @{N='Principal';E={$_.Principal.UserId}},
    @{N='LastRunTime';E={(Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue).LastRunTime}},
    @{N='LastTaskResult';E={(Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue).LastTaskResult}}

$tasks | Export-Csv "$OutputPath\04_scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Scheduled tasks: $($tasks.Count) captured" -ForegroundColor Green

# ============================================================
# SERVICES
# ============================================================
Write-Host "[*] Collecting services..." -ForegroundColor Yellow

$services = Get-WmiObject Win32_Service | Select-Object `
    Name, DisplayName, State, StartMode, StartName,
    @{N='Path';E={$_.PathName}},
    @{N='MD5';E={
        $path = $_.PathName -replace '"','' -replace ' .*',''
        if($path -and (Test-Path $path)){(Get-FileHash -Path $path -Algorithm MD5 -ErrorAction SilentlyContinue).Hash}else{"N/A"}
    }}

$services | Export-Csv "$OutputPath\05_services.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Services: $($services.Count) captured" -ForegroundColor Green

# ============================================================
# AUTORUN / PERSISTENCE
# ============================================================
Write-Host "[*] Collecting autorun entries..." -ForegroundColor Yellow

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
)

$autoruns = @()
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notmatch "^PS") {
                $autoruns += [PSCustomObject]@{
                    RegistryKey = $key
                    Name = $prop.Name
                    Value = $prop.Value
                }
            }
        }
    }
}
$autoruns | Export-Csv "$OutputPath\06_autoruns.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Autorun entries: $($autoruns.Count) captured" -ForegroundColor Green

# ============================================================
# PREFETCH FILES
# ============================================================
Write-Host "[*] Collecting prefetch..." -ForegroundColor Yellow

if (Test-Path "C:\Windows\Prefetch") {
    Get-ChildItem "C:\Windows\Prefetch\*.pf" |
        Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, Length |
        Sort-Object LastWriteTime -Descending |
        Export-Csv "$OutputPath\07_prefetch.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Prefetch files: $($(Get-ChildItem 'C:\Windows\Prefetch\*.pf').Count) captured" -ForegroundColor Green
}

# ============================================================
# RECENT FILES
# ============================================================
Write-Host "[*] Collecting recently modified files..." -ForegroundColor Yellow

$suspiciousPaths = @(
    $env:TEMP, $env:TMP,
    "$env:APPDATA\Microsoft\Windows\Recent",
    "C:\Windows\Temp",
    "C:\Users\Public"
)

$recentFiles = @()
foreach ($path in $suspiciousPaths) {
    if (Test-Path $path) {
        $recentFiles += Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-2)} |
            Select-Object FullName, Length, LastWriteTime, Attributes
    }
}
$recentFiles | Export-Csv "$OutputPath\08_recent_files.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Recent files: $($recentFiles.Count) captured" -ForegroundColor Green

# ============================================================
# WINDOWS EVENT LOGS (KEY EVENTS)
# ============================================================
Write-Host "[*] Collecting security events..." -ForegroundColor Yellow

$eventIds = @(4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 7045, 1102)

$secEvents = @()
foreach ($id in $eventIds) {
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=$id;
        StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    foreach ($evt in $events) {
        $secEvents += [PSCustomObject]@{
            TimeCreated = $evt.TimeCreated
            EventID = $evt.Id
            Message = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length))
        }
    }
}
$secEvents | Sort-Object TimeCreated -Descending |
    Export-Csv "$OutputPath\09_security_events.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[+] Security events: $($secEvents.Count) captured" -ForegroundColor Green

# ============================================================
# COMPUTE HASHES OF COLLECTED ARTIFACTS
# ============================================================
Write-Host "[*] Computing artifact hashes..." -ForegroundColor Yellow

$manifest = @()
Get-ChildItem -Path $OutputPath -File | ForEach-Object {
    $manifest += [PSCustomObject]@{
        FileName = $_.Name
        Size = $_.Length
        MD5 = (Get-FileHash -Path $_.FullName -Algorithm MD5).Hash
        SHA256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        CollectedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)
    }
}
$manifest | Export-Csv "$OutputPath\00_manifest.csv" -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " TRIAGE COMPLETE" -ForegroundColor Cyan
Write-Host " Case ID : $CaseID" -ForegroundColor Cyan
Write-Host " Output  : $OutputPath" -ForegroundColor Cyan
Write-Host " Files   : $($manifest.Count) artifacts collected" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
