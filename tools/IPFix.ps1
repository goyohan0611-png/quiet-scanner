<#
.SYNOPSIS
    Walk through devices sharing one IP and change them one at a time.
    Stock Windows PowerShell; nothing to install.

.DESCRIPTION
    Several devices shipped with the same factory IP are all connected to one
    switch. This changes their addresses in place, one after another, without
    unplugging anything.

    Copyright (C) 2026 Goyohan.  GPLv2 or later; see LICENSE.

    How it works:
      1) Clear the ARP cache and call the target IP repeatedly. The conflicting
         devices answer in turn, so different MACs land in the cache. Collecting
         those tells you, MAC by MAC, how many devices are on that IP.
      2) Pin one of those MACs as a static (Permanent) ARP entry and packets to
         that IP reach only that device. The rest go quiet -> open its web page
         and change its IP.
      3) Once changed, that device leaves the target IP, so drop the entry and
         repeat with the next MAC.

.PARAMETER Ip
    The factory IP the devices are sharing. (e.g. 192.168.1.64)

.PARAMETER Rounds
    How many collection passes to run. Default 40; raise it when there are many
    devices.

.PARAMETER Macs
    Skip the scan and go straight to processing when the MAC list is already
    known. (Paste the ArpDupScan.py results here.)

.PARAMETER NewIpStart
    First address of the new range. Each device is planned one higher than the
    last.

.PARAMETER InterfaceAlias
    Network adapter to use. Omitted, the adapter on the target IP's subnet is
    chosen automatically.

.PARAMETER TempIp
    When the PC is on a different subnet, temporarily add this address to the
    adapter so it can talk to the devices. Removed automatically on exit.
    (e.g. 192.168.1.250)

.PARAMETER ScanOnly
    Collect MACs and stop - just to see how many devices are out there.

.PARAMETER NoBrowser
    Do not open each device's web page automatically.

.EXAMPLE
    # Step 1: see how many devices are in the conflict
    .\IPFix.ps1 -Ip 192.168.1.64 -ScanOnly

.EXAMPLE
    # Step 2: assign from 192.168.10.101 upwards, one device at a time
    .\IPFix.ps1 -Ip 192.168.1.64 -NewIpStart 192.168.10.101

.EXAMPLE
    # PC on another subnet: attach a temporary address first
    .\IPFix.ps1 -Ip 192.168.1.64 -TempIp 192.168.1.250 -NewIpStart 192.168.10.101

.NOTES
    Must be run from an ADMINISTRATOR PowerShell.
    If execution is blocked: Set-ExecutionPolicy -Scope Process Bypass
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Ip,

    [int]$Rounds = 40,

    [string[]]$Macs,

    [string]$NewIpStart,

    [string]$InterfaceAlias,

    [string]$TempIp,

    [string]$Report,

    [switch]$ScanOnly,

    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# A small vendor OUI table - only what turns up often on site
# ---------------------------------------------------------------------------
$script:OuiTable = @{
    # CCTV
    '44-47-CC' = 'Hikvision'; 'BC-AD-28' = 'Hikvision'; 'C0-56-E3' = 'Hikvision'
    '4C-BD-8F' = 'Hikvision'; '28-57-BE' = 'Hikvision'; '58-03-FB' = 'Hikvision'
    'A4-14-37' = 'Hikvision'; 'E0-CA-3C' = 'Hikvision'; '54-C4-15' = 'Hikvision'
    '90-02-A9' = 'Dahua';     '3C-EF-8C' = 'Dahua';     '4C-11-BF' = 'Dahua'
    'E0-50-8B' = 'Dahua';     '08-ED-ED' = 'Dahua';     '14-A7-8B' = 'Dahua'
    '24-52-6A' = 'Dahua';     'BC-32-5F' = 'Dahua'
    '00-09-18' = 'Hanwha';    'E4-30-22' = 'Hanwha';    '00-16-6C' = 'Hanwha'
    '34-E6-D7' = 'Hanwha'
    '00-03-C5' = 'IDIS'
    '00-40-8C' = 'Axis';      'AC-CC-8E' = 'Axis';      'B8-A4-4F' = 'Axis'
    '48-EA-63' = 'Uniview';   '6C-F1-7E' = 'Uniview'
    '00-07-5F' = 'Bosch';     '00-1C-44' = 'Bosch'
    '00-80-45' = 'Panasonic'; '08-00-23' = 'Panasonic'
    '30-F9-ED' = 'Sony';      '54-42-49' = 'Sony'
    # AV / broadcast
    '00-05-A6' = 'Extron';    '00-10-7F' = 'Crestron';  '00-60-9F' = 'AMX'
    '00-1D-56' = 'Kramer';    '7C-2E-0D' = 'Blackmagic';'00-04-A5' = 'Barco'
    # Networking
    '24-A4-3C' = 'Ubiquiti';  '78-8A-20' = 'Ubiquiti';  '74-AC-B9' = 'Ubiquiti'
    'FC-EC-DA' = 'Ubiquiti';  '68-D7-9A' = 'Ubiquiti'
    '50-C7-BF' = 'TP-Link';   'EC-08-6B' = 'TP-Link';   'A4-2B-B0' = 'TP-Link'
    '60-A4-B7' = 'TP-Link'
    '00-1B-D4' = 'Cisco';     '00-23-04' = 'Cisco';     '6C-41-6A' = 'Cisco'
    '20-4E-7F' = 'Netgear';   'A0-40-A0' = 'Netgear'
    '24-DE-C6' = 'Aruba';     '6C-F3-7F' = 'Aruba'
    # Virtual machines - labelled so they are not mistaken for hardware
    '00-50-56' = 'VMware';    '00-0C-29' = 'VMware';    '00-15-5D' = 'Hyper-V'
}

function Get-Vendor {
    param([string]$Mac)
    $prefix = $Mac.Substring(0, 8).ToUpper()
    if ($script:OuiTable.ContainsKey($prefix)) { return $script:OuiTable[$prefix] }
    return 'Unknown'
}

function Format-Mac {
    param([string]$Mac)
    $clean = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -ne 12) { throw "Malformed MAC: $Mac" }
    return ($clean -split '(.{2})' | Where-Object { $_ }) -join '-'
}

function Write-Step   { param([string]$m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok     { param([string]$m) Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn2  { param([string]$m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Err2   { param([string]$m) Write-Host "    [X] $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err2 "Administrator rights are required."
        Write-Host  "    Right-click the PowerShell icon -> 'Run as administrator', then try again." -ForegroundColor Yellow
        exit 1
    }
}

function Test-SameSubnet {
    param([byte[]]$A, [byte[]]$B, [int]$Prefix)
    $bits = $Prefix
    for ($i = 0; $i -lt 4; $i++) {
        if ($bits -le 0) { break }
        $take = [Math]::Min(8, $bits)
        $mask = [byte](((0xFF -shl (8 - $take)) -band 0xFF))
        if (($A[$i] -band $mask) -ne ($B[$i] -band $mask)) { return $false }
        $bits -= 8
    }
    return $true
}

function Resolve-TargetInterface {
    param([string]$TargetIp, [string]$Alias)

    if ($Alias) {
        $cfg = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $Alias -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if (-not $cfg) { throw "No adapter named '$Alias'." }
        return $cfg
    }

    $targetBytes = ([System.Net.IPAddress]::Parse($TargetIp)).GetAddressBytes()
    $candidates = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike '127.*' -and
            $_.IPAddress -notlike '169.254.*' -and
            (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Status -eq 'Up'
        }

    foreach ($c in $candidates) {
        $b = ([System.Net.IPAddress]::Parse($c.IPAddress)).GetAddressBytes()
        if (Test-SameSubnet -A $b -B $targetBytes -Prefix $c.PrefixLength) { return $c }
    }
    return $null
}

function Get-NextIp {
    param([string]$BaseIp, [int]$Offset)
    $b = ([System.Net.IPAddress]::Parse($BaseIp)).GetAddressBytes()
    [array]::Reverse($b)
    $val = [System.BitConverter]::ToUInt32($b, 0) + $Offset
    $nb = [System.BitConverter]::GetBytes([uint32]$val)
    [array]::Reverse($nb)
    return ([System.Net.IPAddress]::new($nb)).IPAddressToString
}

# ---------------------------------------------------------------------------
# ARP manipulation
# ---------------------------------------------------------------------------
function Clear-Neighbor {
    param([int]$IfIndex, [string]$Address)
    Remove-NetNeighbor -InterfaceIndex $IfIndex -IPAddress $Address -Confirm:$false -ErrorAction SilentlyContinue
}

function Get-NeighborMac {
    param([int]$IfIndex, [string]$Address)
    $n = Get-NetNeighbor -InterfaceIndex $IfIndex -IPAddress $Address -ErrorAction SilentlyContinue |
         Where-Object {
             $_.LinkLayerAddress -and
             $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
             $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF'
         } | Select-Object -First 1
    if ($n) { return $n.LinkLayerAddress.ToUpper() }
    return $null
}

function Invoke-MacHarvest {
    param([int]$IfIndex, [string]$Address, [int]$Times)

    $found = New-Object System.Collections.Specialized.OrderedDictionary
    $lastNewAt = 0

    for ($i = 1; $i -le $Times; $i++) {
        Clear-Neighbor -IfIndex $IfIndex -Address $Address
        Start-Sleep -Milliseconds (Get-Random -Minimum 40 -Maximum 220)

        # The ping itself may well fail. Sending the ARP request is the point.
        & ping.exe -n 1 -w 400 $Address 2>&1 | Out-Null

        $mac = Get-NeighborMac -IfIndex $IfIndex -Address $Address
        if ($mac -and -not $found.Contains($mac)) {
            $found.Add($mac, $true)
            $lastNewAt = $i
            Write-Host ("    + new device: {0}  ({1})" -f $mac, (Get-Vendor $mac)) -ForegroundColor Green
        }

        $pct = [int](($i / $Times) * 100)
        Write-Progress -Activity "Collecting MACs" `
                       -Status ("pass $i of $Times  |  " + $found.Count + " found so far") `
                       -PercentComplete $pct
    }
    Write-Progress -Activity "Collecting MACs" -Completed

    if ($found.Count -gt 0 -and ($Times - $lastNewAt) -lt 10) {
        Write-Warn2 "The last device turned up right at the end. Raise -Rounds and run it again."
    }

    return @($found.Keys)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Assert-Admin

Write-Host ""
Write-Host "===============================================" -ForegroundColor White
Write-Host "  Duplicate-IP walkthrough" -ForegroundColor White
Write-Host "  Target IP : $Ip" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor White

$tempIpAdded = $false
$ifIndex = $null
$results = @()

try {
    # --- Choose the adapter ------------------------------------------------
    Write-Step "Checking the network adapter"
    $cfg = Resolve-TargetInterface -TargetIp $Ip -Alias $InterfaceAlias

    if (-not $cfg) {
        if (-not $TempIp) {
            Write-Err2 "No adapter is on the same subnet as $Ip."
            Write-Host ""
            Write-Host "    Adapters found:" -ForegroundColor Yellow
            Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike '127.*' } |
                Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize |
                Out-String | Write-Host
            Write-Host "    Fix: attach a temporary address with -TempIp." -ForegroundColor Yellow
            Write-Host "    e.g. .\IPFix.ps1 -Ip $Ip -TempIp $((Get-NextIp $Ip 100))" -ForegroundColor Yellow
            exit 1
        }

        # Pick the adapter for the temporary address - connected wired first
        $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                   Where-Object { $_.Status -eq 'Up' } |
                   Sort-Object -Property @{ Expression = { if ($_.MediaType -like '*802.3*') { 0 } else { 1 } } } |
                   Select-Object -First 1
        if (-not $adapter) { throw "No connected network adapter. Check the cable." }

        Write-Warn2 "Adding temporary address $TempIp to '$($adapter.Name)'. (removed on exit)"
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $TempIp -PrefixLength 24 -ErrorAction Stop | Out-Null
        $tempIpAdded = $true
        Start-Sleep -Seconds 2
        $cfg = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $TempIp -ErrorAction Stop | Select-Object -First 1
    }

    $ifIndex = $cfg.InterfaceIndex
    Write-Ok "Using '$($cfg.InterfaceAlias)'  ($($cfg.IPAddress)/$($cfg.PrefixLength))"

    # --- Collect MACs ------------------------------------------------------
    if ($Macs -and $Macs.Count -gt 0) {
        Write-Step "MAC list supplied - skipping the scan."
        $macList = @()
        foreach ($m in $Macs) { $macList += (Format-Mac $m) }
    }
    else {
        Write-Step "Collecting MACs from the devices in conflict ($Rounds passes)"
        Write-Host "    ...coaxing the devices into answering in turn. This takes a moment." -ForegroundColor DarkGray
        $macList = Invoke-MacHarvest -IfIndex $ifIndex -Address $Ip -Times $Rounds
    }

    if (-not $macList -or $macList.Count -eq 0) {
        Write-Err2 "Nothing answered."
        Write-Host "    Check: cable / PoE power / correct subnet / firewall" -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "  --- $($macList.Count) device(s) found ---" -ForegroundColor White
    $idx = 0
    foreach ($m in $macList) {
        $idx++
        $planned = ''
        if ($NewIpStart) { $planned = '  ->  ' + (Get-NextIp $NewIpStart ($idx - 1)) }
        Write-Host ("   {0,2}. {1}   {2,-12}{3}" -f $idx, $m, (Get-Vendor $m), $planned)
    }
    Write-Host ""

    if ($macList.Count -eq 1) {
        Write-Warn2 "Only one device answered. If there should be more, raise -Rounds to 80 or higher and retry."
    }

    if ($ScanOnly) {
        Write-Ok "Scan only - stopping here."
        return
    }

    # --- Work through them one at a time -----------------------------------
    Write-Step "Starting the device-by-device walkthrough"
    Write-Host "    When the browser opens, change the device IP, save, then press Enter." -ForegroundColor DarkGray
    Write-Host "    (Use a private browsing window - you hit the same IP for several devices)" -ForegroundColor DarkGray

    $i = 0
    foreach ($mac in $macList) {
        $i++
        $target = ''
        if ($NewIpStart) { $target = Get-NextIp $NewIpStart ($i - 1) }

        Write-Host ""
        Write-Host ("--- [{0}/{1}] {2}  ({3})" -f $i, $macList.Count, $mac, (Get-Vendor $mac)) -ForegroundColor Cyan
        if ($target) { Write-Host ("    IP to assign: {0}" -f $target) -ForegroundColor Yellow }

        # Pin the IP to this one MAC
        Clear-Neighbor -IfIndex $ifIndex -Address $Ip
        try {
            New-NetNeighbor -InterfaceIndex $ifIndex -IPAddress $Ip `
                            -LinkLayerAddress $mac -State Permanent -ErrorAction Stop | Out-Null
            Write-Ok "ARP entry pinned. $Ip now reaches this device only."
        }
        catch {
            Write-Err2 "Could not pin the ARP entry: $($_.Exception.Message)"
            $results += [pscustomobject]@{
                No = $i; MAC = $mac; Vendor = (Get-Vendor $mac)
                NewIp = $target; Result = 'ARP pin failed'; Time = (Get-Date -Format 'HH:mm:ss')
            }
            continue
        }

        if (-not $NoBrowser) { Start-Process ("http://" + $Ip) | Out-Null }

        Write-Host ""
        $answer = Read-Host "    Enter when the IP is changed / s to skip / q to stop"
        if ($answer -eq 'q') {
            Clear-Neighbor -IfIndex $ifIndex -Address $Ip
            Write-Warn2 "Stopped at your request."
            break
        }

        Clear-Neighbor -IfIndex $ifIndex -Address $Ip

        if ($answer -eq 's') {
            Write-Warn2 "Skipped."
            $results += [pscustomobject]@{
                No = $i; MAC = $mac; Vendor = (Get-Vendor $mac)
                NewIp = $target; Result = 'skipped'; Time = (Get-Date -Format 'HH:mm:ss')
            }
            continue
        }

        # Verify the change
        $verdict = 'changed (unverified)'
        if ($target) {
            Start-Sleep -Seconds 2
            $alive = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue
            if ($alive) {
                Write-Ok "$target answered. The change took."
                $verdict = 'ok'
            }
            else {
                Write-Warn2 "$target is not answering yet. (rebooting, or ICMP blocked)"
                $verdict = 'check by hand'
            }
        }

        $results += [pscustomobject]@{
            No = $i; MAC = $mac; Vendor = (Get-Vendor $mac)
            NewIp = $target; Result = $verdict; Time = (Get-Date -Format 'HH:mm:ss')
        }
    }

    # --- Wrap up -----------------------------------------------------------
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor White
    Write-Host "  Summary" -ForegroundColor White
    Write-Host "===============================================" -ForegroundColor White
    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize | Out-String | Write-Host

        if (-not $Report) {
            $Report = Join-Path (Get-Location) ("IPFix_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
        }
        $results | Export-Csv -Path $Report -NoTypeInformation -Encoding UTF8
        Write-Ok "Log saved: $Report"
    }
}
catch {
    Write-Err2 $_.Exception.Message
}
finally {
    # Clean up any static ARP entry left behind
    if ($ifIndex) {
        Clear-Neighbor -IfIndex $ifIndex -Address $Ip
    }
    if ($tempIpAdded) {
        Remove-NetIPAddress -IPAddress $TempIp -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "    Temporary address $TempIp removed." -ForegroundColor DarkGray
    }
    Write-Host ""
}
