#!/usr/bin/env pwsh
# Maptnh@S-H4CK13 —  KTOR

[CmdletBinding()]
param(
    [int]   $Threads   = 50,
    [string]$Interface = "",
    [switch]$Local,
    [string[]]$Ports   = @("80","443","8080"),
    [switch]$Help
)

function Show-Usage {
    Write-Output @"
Usage: .\ktor.ps1 [-Threads <int>] [-Interface <string>] [-Local] [-Ports <int,int,...>] [-Help]

  -Threads    Maximum parallel threads (default: 50)
  -Interface  Network interface to scan (e.g. Ethernet)
  -Local      Scan only localhost (127.0.0.1)
  -Ports      Comma-separated list of ports to scan (default: 80,443,8080)
  -Help       Show this help message
"@
}

if ($Help) { Show-Usage; exit }

$timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$logFile   = Join-Path $env:TEMP "http-$timestamp.txt"
$Results   = @()

# Header
$header = @"
      ___                       ___           ___     
     /__/|          ___        /  /\         /  /\    
    |  |:|         /  /\      /  /::\       /  /::\   
    |  |:|        /  /:/     /  /:/\:\     /  /:/\:\  
  __|  |:|       /  /:/     /  /:/  \:\   /  /:/~/:/  
 /__/\_|:|____  /  /::\    /__/:/ \__\:\ /__/:/ /:/___
 \  \:\/:::::/ /__/:/\:\   \  \:\ /  /:/ \  \:\/:::::/
  \  \::/~~~~  \__\/  \:\   \  \:\  /:/   \  \::/~~~~ 
   \  \:\           \  \:\   \  \:\/:/     \  \:\     
    \  \:\           \__\/    \  \::/       \  \:\    
     \__\/                     \__\/         \__\/    
"@
Write-Output $header
Write-Output "Maptnh@S-H4CK13   https://github.com/MartinxMax  KTOR"
Write-Output "For Windows"

function Get-SubnetPrefix {
    param([string]$IfAlias)
    $ip = Get-NetIPAddress -InterfaceAlias $IfAlias -AddressFamily IPv4 |
          Where-Object { $_.IPAddress -notlike '169.*' } |
          Select-Object -First 1 -ExpandProperty IPAddress
    if (-not $ip) { throw "Interface '$IfAlias' has no valid IPv4 address." }
    return ($ip -split '\.')[0..2] -join '.'
}

function Get-Title {
    param([string]$Html)
    if ($Html -match '(?is)<title>(.*?)</title>') { return $Matches[1].Trim() }
    return ''
}

function Scan-Local {
    Write-Output "[*] Scanning localhost ports: $($Ports -join ', ')"
    foreach ($p in $Ports) {
        if (Test-NetConnection -ComputerName '127.0.0.1' -Port $p -InformationLevel Quiet) {
            $url = "http://127.0.0.1:${p}/"
            try {
                $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction Stop
                $status = $resp.StatusCode
            } catch {
                $status = $null
                Write-Output "[-] Error accessing ${url}: $($_.Exception.Message)"
            }
            if ($status -match '^[1-5]\d\d$') {
                $title = Get-Title -Html $resp.Content
                $line = "127.0.0.1:${p} - ${title}"
                Write-Output "[+] ${line}"
                $Results += $line
                Add-Content -Path $logFile -Value $line
            } else {
                Write-Output "[-] ${url} did not return HTTP (status: ${status})"
            }
        } else {
            Write-Output "[-] TCP port ${p} is closed on localhost"
        }
    }
}

function Scan-Network {
    param([string]$Prefix)
    Write-Output "[*] Pinging hosts in subnet ${Prefix}.1-254..."
    $alive = 1..254 | ForEach-Object -Parallel -ThrottleLimit $Threads {
        $ip = "${using:Prefix}.$_"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
            Write-Output "[+] ${ip} is alive"
            $ip
        }
    }
    if (-not $alive) {
        Write-Output "[-] No live hosts found."
        return
    }
    $alive | ForEach-Object -Parallel -ThrottleLimit $Threads {
        $ip = $_
        foreach ($p in $using:Ports) {
            if (Test-NetConnection -ComputerName $ip -Port $p -InformationLevel Quiet) {
                $url = "http://${ip}:${p}/"
                try {
                    $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction Stop
                    $status = $resp.StatusCode
                } catch {
                    $status = $null
                    Write-Output "[-] Error accessing ${url}: $($_.Exception.Message)"
                }
                if ($status -match '^[1-5]\d\d$') {
                    $title = Get-Title -Html $resp.Content
                    $line = "${ip}:${p} - ${title}"
                    Write-Output "[+] ${line}"
                    $Results += $line
                    Add-Content -Path $logFile -Value $line
                } else {
                    Write-Output "[-] ${url} did not return HTTP (status: ${status})"
                }
            } else {
                Write-Output "[-] TCP port ${p} closed on ${ip}"
            }
        }
    }
}

if ($Local) { Scan-Local } else {
    if (-not $Interface) { Write-Output "Error: Specify -Interface."; Show-Usage; exit 1 }
    try { $prefix = Get-SubnetPrefix -IfAlias $Interface } catch { Write-Output "Error: $_"; exit 1 }
    Scan-Network -Prefix $prefix
}

Write-Output "`n[+] Scan complete. Results saved to: ${logFile}"
