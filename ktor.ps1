# Maptnh@S-H4CK13 KTOR

[CmdletBinding()]
param(
    [int]   $Threads    = 50,
    [switch]$Local,
    [string]$Targets    = "",
    [string[]]$Ports    = @("80","443","8080"),
    [switch]$Help
)

function Show-Usage {
    Write-Output @"
Usage: .\ktor.ps1 [-Threads <int>] [-Local] [-Targets <CIDR|IP|IP,IP,...>] [-Ports <int,int,...>] [-Help]

  -Threads    Maximum parallel threads (default: 50)
  -Local      Scan only localhost (127.0.0.1)
  -Targets    CIDR (e.g. 192.168.0.0/24 or /16), single IP (e.g. 192.168.0.1) or comma-separated list
  -Ports      Comma-separated list of ports to scan (default: 80,443,8080)
  -Help       Show this help message
"@
}

if ($Help) { Show-Usage; exit }

 
$timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$logFile   = Join-Path $env:TEMP "http-$timestamp.txt"
$Results   = @()

$header = @'
      ___                       ___           ___     
     /__/|          ___        / :/          /  /\    
    |  |:|         /  /\      /  /:/_        /  /::\   
    |  |:|        /  /:/     /  /:/ /\      /  /:/\:\  
  __|  |:|       /  /:/     /  /:/_/::\    /  /:/~/:/  
 /__\/\_|:|____ /  /::\    /__/:/__\/\:\  /__/:/ /:/___
 \  \:/:::::/ /__/:/\:\   \  \:\ /~~/:/  \  \:\/:/:::::/
  \  \::/~~~~  \__\/  \:\   \  \:\  /:/    \  \::/~~~~ 
   \  \:\           \  \:\   \  \:\/:/      \  \:\     
    \  \:\           \__\/    \  \::/        \  \:\    
     \__\/                     \__\/          \__\/    
'@
Write-Output $header
Write-Output "Maptnh@S-H4CK13   https://github.com/MartinxMax  KTOR"
Write-Output "For Windows"

function Get-Title {
    param([string]$Html)
    if ($Html -match '(?is)<title>(.*?)</title>') { return $Matches[1].Trim() }
    return ''
}

function Scan-Local {
    if ($Local -and -not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Ports')) {
        Write-Output "[*] No ports specified. Auto-detecting listening ports via netstat..."
        $Ports = netstat -ano |
                 Select-String 'LISTENING' |
                 ForEach-Object { if ($_ -match '^\s*TCP\s+\S+:(\d+)\s') { $matches[1] } } |
                 Sort-Object -Unique
        if (-not $Ports.Count) {
            Write-Output "[-] No listening TCP ports found."
            return
        }
    }

    Write-Output "[*] Scanning localhost ports: $($Ports -join ',')"

    foreach ($port in $Ports) {
        try {
            if (Test-NetConnection -ComputerName '127.0.0.1' -Port $port -InformationLevel Quiet) {
                $url = "http://127.0.0.1:$port/"
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                if ($resp.Content -match '(?is)<title>(.*?)</title>') {
                    $title = $Matches[1].Trim()
                } else { $title = '' }
                $line = "127.0.0.1:$port - HTTP detected - Title: $title"
                Add-Content -Path $logFile -Value $line
                Write-Output "[+] $line"
            }
        } catch {}
    }
}

function Expand-CIDR {
    param([string]$cidr)
    $result = @()
    if ($cidr -match '^(.+)/(\d{1,2})$') {
        $network = $Matches[1]
        $mask = [int]$Matches[2]
        $octets = $network -split '\.'
        switch ($mask) {
            24 {
                $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
                $result = 1..254 | ForEach-Object { "$prefix.$_" }
            }
            16 {
                $prefix2 = "$($octets[0]).$($octets[1])"
                foreach ($i in 1..16) { foreach ($j in 1..16) { $result += "$prefix2.$i.$j" } }
            }
            default {
                Write-Output "[-] Unsupported mask /$mask"
            }
        }
    } else {
        $result += $cidr
    }
    return $result
}

function Scan-Network {
    param([string[]]$Hosts)

    $total = $Hosts.Count * $Ports.Count
    Write-Output "[*] Scanning ..."

    $queue = foreach ($targetHost in $Hosts) {
        foreach ($targetPort in $Ports) {
            [PSCustomObject]@{IP = $targetHost; Port = $targetPort}
        }
    }

    foreach ($entry in $queue) {
        try {
            if (Test-NetConnection -ComputerName $entry.IP -Port $entry.Port -InformationLevel Quiet) {
                $url = "http://$($entry.IP):$($entry.Port)/"
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                if ($resp.Content -match '(?is)<title>(.*?)</title>') {
                    $title = $Matches[1].Trim()
                } else { $title = '' }
                $line = "$($entry.IP):$($entry.Port) - HTTP detected - Title: $title"
                Add-Content -Path $logFile -Value $line
                Write-Output "[+] $line"
            }
        } catch {}
    }
}

if ($Local) {
    Scan-Local
} elseif ($Targets) {
    $targetsList = @()
    foreach ($t in $Targets -split ',') {
        $targetsList += Expand-CIDR -cidr $t
    }
 
    if ($targetsList.Count -gt 4096) {
        Write-Output "[-] Too many targets ($($targetsList.Count)). Limit to 4096 IPs."
        exit 1
    }

    Scan-Network -Hosts $targetsList
} else {
    Write-Output "Error: Specify -Targets or -Local."
    Show-Usage; exit 1
}

Write-Output "[+] Scan complete. Results saved to: $logFile"
