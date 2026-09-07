<#
.SYNOPSIS
    IP 충돌 장비 순차 세팅 도구 (Windows 순정, 설치 불필요)

.DESCRIPTION
    같은 초기 IP로 출고된 장비 여러 대를 한 스위치에 전부 꽂아둔 상태에서,
    장비를 하나씩 뽑았다 꽂지 않고 자리에서 순차적으로 IP를 바꾸기 위한 도구.

    원리:
      1) ARP 캐시를 지우고 대상 IP를 반복 호출하면, 충돌 중인 장비들이
         번갈아 응답하면서 서로 다른 MAC이 캐시에 잡힌다. 이걸 모아서
         현장에 몇 대가 물려 있는지 MAC 단위로 알아낸다.
      2) 알아낸 MAC 하나를 정적(Permanent) ARP 엔트리로 박아두면,
         해당 IP로 보내는 패킷은 그 MAC 장비에게만 간다.
         나머지 장비는 조용해진다 -> 한 대씩 웹 접속해서 IP 변경.
      3) IP를 바꾼 장비는 대상 IP에서 빠지므로, 엔트리를 지우고 다음 MAC으로 반복.

.PARAMETER Ip
    충돌 중인 장비들의 초기 IP. (예: 192.168.1.64)

.PARAMETER Rounds
    MAC 수집 반복 횟수. 기본 40. 장비가 많으면 늘린다.

.PARAMETER Macs
    이미 MAC 목록을 알고 있을 때 스캔을 건너뛰고 바로 순차 처리에 들어간다.
    (ArpDupScan.py 결과를 붙여넣을 때 사용)

.PARAMETER NewIpStart
    새로 배정할 IP의 시작 주소. 장비 순서대로 +1씩 배정 계획을 뽑아준다.

.PARAMETER InterfaceAlias
    사용할 네트워크 어댑터 이름. 생략하면 대상 IP와 같은 대역의 어댑터를 자동 선택.

.PARAMETER TempIp
    PC가 대상 IP와 다른 대역일 때, 통신용 임시 IP를 어댑터에 잠시 추가한다.
    스크립트 종료 시 자동으로 제거된다. (예: 192.168.1.250)

.PARAMETER ScanOnly
    MAC 수집만 하고 종료. 현장에 몇 대가 물려 있는지 확인용.

.PARAMETER NoBrowser
    장비별 웹 페이지를 자동으로 열지 않는다.

.EXAMPLE
    # 1단계: 몇 대가 충돌 중인지 확인
    .\IPFix.ps1 -Ip 192.168.1.64 -ScanOnly

.EXAMPLE
    # 2단계: 192.168.10.101 부터 순서대로 배정하며 한 대씩 처리
    .\IPFix.ps1 -Ip 192.168.1.64 -NewIpStart 192.168.10.101

.EXAMPLE
    # PC가 다른 대역일 때 임시 IP를 붙여서 실행
    .\IPFix.ps1 -Ip 192.168.1.64 -TempIp 192.168.1.250 -NewIpStart 192.168.10.101

.NOTES
    반드시 "관리자 권한" PowerShell에서 실행할 것.
    실행이 막히면: Set-ExecutionPolicy -Scope Process Bypass
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
# 제조사 OUI 미니 DB (현장에서 자주 보는 것만)
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
    # AV / 방송장비
    '00-05-A6' = 'Extron';    '00-10-7F' = 'Crestron';  '00-60-9F' = 'AMX'
    '00-1D-56' = 'Kramer';    '7C-2E-0D' = 'Blackmagic';'00-04-A5' = 'Barco'
    # 네트워크
    '24-A4-3C' = 'Ubiquiti';  '78-8A-20' = 'Ubiquiti';  '74-AC-B9' = 'Ubiquiti'
    'FC-EC-DA' = 'Ubiquiti';  '68-D7-9A' = 'Ubiquiti'
    '50-C7-BF' = 'TP-Link';   'EC-08-6B' = 'TP-Link';   'A4-2B-B0' = 'TP-Link'
    '60-A4-B7' = 'TP-Link'
    '00-1B-D4' = 'Cisco';     '00-23-04' = 'Cisco';     '6C-41-6A' = 'Cisco'
    '20-4E-7F' = 'Netgear';   'A0-40-A0' = 'Netgear'
    '24-DE-C6' = 'Aruba';     '6C-F3-7F' = 'Aruba'
    # 가상머신 (오탐 방지용 라벨)
    '00-50-56' = 'VMware';    '00-0C-29' = 'VMware';    '00-15-5D' = 'Hyper-V'
}

function Get-Vendor {
    param([string]$Mac)
    $prefix = $Mac.Substring(0, 8).ToUpper()
    if ($script:OuiTable.ContainsKey($prefix)) { return $script:OuiTable[$prefix] }
    return '미상'
}

function Format-Mac {
    param([string]$Mac)
    $clean = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -ne 12) { throw "MAC 형식이 잘못됐습니다: $Mac" }
    return ($clean -split '(.{2})' | Where-Object { $_ }) -join '-'
}

function Write-Step   { param([string]$m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok     { param([string]$m) Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn2  { param([string]$m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Err2   { param([string]$m) Write-Host "    [X] $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# 사전 점검
# ---------------------------------------------------------------------------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err2 "관리자 권한이 필요합니다."
        Write-Host  "    PowerShell 아이콘 우클릭 -> '관리자 권한으로 실행' 후 다시 돌려주십시오." -ForegroundColor Yellow
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
        if (-not $cfg) { throw "'$Alias' 어댑터를 찾을 수 없습니다." }
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
# ARP 조작
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

        # ping 자체는 실패해도 상관없다. ARP 요청이 나가는 게 목적.
        & ping.exe -n 1 -w 400 $Address 2>&1 | Out-Null

        $mac = Get-NeighborMac -IfIndex $IfIndex -Address $Address
        if ($mac -and -not $found.Contains($mac)) {
            $found.Add($mac, $true)
            $lastNewAt = $i
            Write-Host ("    + 새 장비 발견: {0}  ({1})" -f $mac, (Get-Vendor $mac)) -ForegroundColor Green
        }

        $pct = [int](($i / $Times) * 100)
        Write-Progress -Activity "MAC 수집 중" `
                       -Status ("$i / $Times 회  |  현재 " + $found.Count + "대 발견") `
                       -PercentComplete $pct
    }
    Write-Progress -Activity "MAC 수집 중" -Completed

    if ($found.Count -gt 0 -and ($Times - $lastNewAt) -lt 10) {
        Write-Warn2 "마지막 발견이 끝자락이었습니다. -Rounds 를 늘려서 한 번 더 돌려보십시오."
    }

    return @($found.Keys)
}

# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------
Assert-Admin

Write-Host ""
Write-Host "===============================================" -ForegroundColor White
Write-Host "  IP 충돌 장비 순차 세팅 도구" -ForegroundColor White
Write-Host "  대상 IP : $Ip" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor White

$tempIpAdded = $false
$ifIndex = $null
$results = @()

try {
    # --- 어댑터 결정 -------------------------------------------------------
    Write-Step "네트워크 어댑터 확인"
    $cfg = Resolve-TargetInterface -TargetIp $Ip -Alias $InterfaceAlias

    if (-not $cfg) {
        if (-not $TempIp) {
            Write-Err2 "$Ip 와 같은 대역을 쓰는 어댑터가 없습니다."
            Write-Host ""
            Write-Host "    현재 어댑터 목록:" -ForegroundColor Yellow
            Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike '127.*' } |
                Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize |
                Out-String | Write-Host
            Write-Host "    해결: -TempIp 옵션으로 임시 IP를 붙이십시오." -ForegroundColor Yellow
            Write-Host "    예)  .\IPFix.ps1 -Ip $Ip -TempIp $((Get-NextIp $Ip 100))" -ForegroundColor Yellow
            exit 1
        }

        # 임시 IP를 붙일 어댑터 선택 (연결된 유선 우선)
        $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                   Where-Object { $_.Status -eq 'Up' } |
                   Sort-Object -Property @{ Expression = { if ($_.MediaType -like '*802.3*') { 0 } else { 1 } } } |
                   Select-Object -First 1
        if (-not $adapter) { throw "연결된 네트워크 어댑터가 없습니다. 랜선을 확인해 주십시오." }

        Write-Warn2 "임시 IP $TempIp 를 '$($adapter.Name)' 에 추가합니다. (종료 시 자동 제거)"
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $TempIp -PrefixLength 24 -ErrorAction Stop | Out-Null
        $tempIpAdded = $true
        Start-Sleep -Seconds 2
        $cfg = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $TempIp -ErrorAction Stop | Select-Object -First 1
    }

    $ifIndex = $cfg.InterfaceIndex
    Write-Ok "'$($cfg.InterfaceAlias)'  ($($cfg.IPAddress)/$($cfg.PrefixLength))  사용"

    # --- MAC 수집 ----------------------------------------------------------
    if ($Macs -and $Macs.Count -gt 0) {
        Write-Step "MAC 목록을 직접 받았습니다. 스캔을 건너뜁니다."
        $macList = @()
        foreach ($m in $Macs) { $macList += (Format-Mac $m) }
    }
    else {
        Write-Step "충돌 중인 장비 MAC 수집 (총 $Rounds 회 시도)"
        Write-Host "    ...장비가 서로 번갈아 응답하도록 유도하는 중입니다. 잠시만." -ForegroundColor DarkGray
        $macList = Invoke-MacHarvest -IfIndex $ifIndex -Address $Ip -Times $Rounds
    }

    if (-not $macList -or $macList.Count -eq 0) {
        Write-Err2 "응답한 장비가 없습니다."
        Write-Host "    확인할 것: 랜선 연결 / PoE 전원 / 대역이 맞는지 / 방화벽" -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "  --- 발견된 장비 $($macList.Count) 대 ---" -ForegroundColor White
    $idx = 0
    foreach ($m in $macList) {
        $idx++
        $planned = ''
        if ($NewIpStart) { $planned = '  ->  ' + (Get-NextIp $NewIpStart ($idx - 1)) }
        Write-Host ("   {0,2}. {1}   {2,-12}{3}" -f $idx, $m, (Get-Vendor $m), $planned)
    }
    Write-Host ""

    if ($macList.Count -eq 1) {
        Write-Warn2 "1대만 잡혔습니다. 실제로 여러 대라면 -Rounds 를 80 이상으로 올려 재시도하십시오."
    }

    if ($ScanOnly) {
        Write-Ok "스캔만 수행하고 종료합니다."
        return
    }

    # --- 순차 처리 ---------------------------------------------------------
    Write-Step "장비별 순차 처리 시작"
    Write-Host "    각 단계에서 브라우저가 열리면 장비 IP를 바꾸고 저장한 뒤 Enter를 누르십시오." -ForegroundColor DarkGray
    Write-Host "    (같은 IP로 여러 장비에 붙으므로 브라우저는 '시크릿 모드'를 권장합니다)" -ForegroundColor DarkGray

    $i = 0
    foreach ($mac in $macList) {
        $i++
        $target = ''
        if ($NewIpStart) { $target = Get-NextIp $NewIpStart ($i - 1) }

        Write-Host ""
        Write-Host ("--- [{0}/{1}] {2}  ({3})" -f $i, $macList.Count, $mac, (Get-Vendor $mac)) -ForegroundColor Cyan
        if ($target) { Write-Host ("    배정할 IP: {0}" -f $target) -ForegroundColor Yellow }

        # 이 MAC 하나만 보이도록 고정
        Clear-Neighbor -IfIndex $ifIndex -Address $Ip
        try {
            New-NetNeighbor -InterfaceIndex $ifIndex -IPAddress $Ip `
                            -LinkLayerAddress $mac -State Permanent -ErrorAction Stop | Out-Null
            Write-Ok "ARP 고정 완료. 이제 $Ip 는 이 장비 한 대만 가리킵니다."
        }
        catch {
            Write-Err2 "ARP 고정 실패: $($_.Exception.Message)"
            $results += [pscustomobject]@{
                순번 = $i; MAC = $mac; 제조사 = (Get-Vendor $mac)
                배정IP = $target; 결과 = 'ARP 고정 실패'; 시각 = (Get-Date -Format 'HH:mm:ss')
            }
            continue
        }

        if (-not $NoBrowser) { Start-Process ("http://" + $Ip) | Out-Null }

        Write-Host ""
        $answer = Read-Host "    IP 변경을 마쳤으면 Enter / 건너뛰려면 s / 전체 중단은 q"
        if ($answer -eq 'q') {
            Clear-Neighbor -IfIndex $ifIndex -Address $Ip
            Write-Warn2 "사용자 요청으로 중단합니다."
            break
        }

        Clear-Neighbor -IfIndex $ifIndex -Address $Ip

        if ($answer -eq 's') {
            Write-Warn2 "건너뜀."
            $results += [pscustomobject]@{
                순번 = $i; MAC = $mac; 제조사 = (Get-Vendor $mac)
                배정IP = $target; 결과 = '건너뜀'; 시각 = (Get-Date -Format 'HH:mm:ss')
            }
            continue
        }

        # 변경 검증
        $verdict = '변경됨(미검증)'
        if ($target) {
            Start-Sleep -Seconds 2
            $alive = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue
            if ($alive) {
                Write-Ok "$target 응답 확인. 정상 반영됐습니다."
                $verdict = '성공'
            }
            else {
                Write-Warn2 "$target 가 아직 응답하지 않습니다. (재부팅 중이거나 ICMP 차단일 수 있음)"
                $verdict = '확인 필요'
            }
        }

        $results += [pscustomobject]@{
            순번 = $i; MAC = $mac; 제조사 = (Get-Vendor $mac)
            배정IP = $target; 결과 = $verdict; 시각 = (Get-Date -Format 'HH:mm:ss')
        }
    }

    # --- 마무리 ------------------------------------------------------------
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor White
    Write-Host "  작업 요약" -ForegroundColor White
    Write-Host "===============================================" -ForegroundColor White
    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize | Out-String | Write-Host

        if (-not $Report) {
            $Report = Join-Path (Get-Location) ("IPFix_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
        }
        $results | Export-Csv -Path $Report -NoTypeInformation -Encoding UTF8
        Write-Ok "작업 내역 저장: $Report"
    }
}
catch {
    Write-Err2 $_.Exception.Message
}
finally {
    # 남은 정적 ARP 엔트리 정리
    if ($ifIndex) {
        Clear-Neighbor -IfIndex $ifIndex -Address $Ip
    }
    if ($tempIpAdded) {
        Remove-NetIPAddress -IPAddress $TempIp -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "    임시 IP $TempIp 제거 완료." -ForegroundColor DarkGray
    }
    Write-Host ""
}
