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
    Write-Host @"
Usage: .\ktor.ps1 [-Threads <int>] [-Interface <string>] [-Local] [-Ports <int,int,...>] [-Help]

  -Threads    Maximum parallel threads (default: 50)
  -Interface  Network interface to scan (e.g. Ethernet)
  -Local      Scan only localhost (127.0.0.1)
  -Ports      Comma-separated list of ports to scan (default: 80,443,8080)
  -Help       Show this help message
"@ -ForegroundColor Cyan
}

if ($Help) { Show-Usage; exit }

 
$timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$logFile   = Join-Path $env:TEMP "http-$timestamp.txt"
$Results   = @()

 
Write-Host @"
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
"@ -ForegroundColor Green
Write-Host "Maptnh@S-H4CK13   https://github.com/MartinxMax  KTOR  " -ForegroundColor Green
Write-Host "                    For Windows" -ForegroundColor Green
 
function Get-SubnetPrefix {
    param([string]$IfAlias)
    $ip = Get-NetIPAddress -InterfaceAlias $IfAlias -AddressFamily IPv4 |
          Where-Object { $_.IPAddress -notlike '169.*' } |
          Select-Object -First 1 -ExpandProperty IPAddress
    if (-not $ip) { Throw "Interface '$IfAlias' has no valid IPv4 address." }
    return ($ip -split '\.')[0..2] -join '.'
}

 
function Get-Title {
    param([string]$Html)
    if ($Html -match '(?is)<title>(.*?)</title>') { return $Matches[1].Trim() }
    return ''
}

 
function Scan-Local {
    Write-Host "[*] Scanning localhost ports: $($Ports -join ', ')" -ForegroundColor Cyan
    foreach ($p in $Ports) {
        if (Test-NetConnection -ComputerName '127.0.0.1' -Port $p -InformationLevel Quiet) {
            $url = "http://127.0.0.1:${p}"
            try {
                $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2
                $html = $resp.Content
                $title = Get-Title -Html $html
            } catch {
                $title = ''
            }
            if ($resp.StatusCode -match '^[1-5]\d\d$') {
                $line = "127.0.0.1:${p} - $title"
                Write-Host "[+] $line" -ForegroundColor Green
                $Results += $line
                Add-Content -Path $logFile -Value $line
            } else {
                Write-Host "[-] $url did not return HTTP" -ForegroundColor Red
            }
        }
    }
}

 
function Scan-Network {
    param([string]$Prefix)
    Write-Host "[*] Pinging hosts in subnet ${Prefix}.1-254..." -ForegroundColor Cyan

 
    $alive = 1..254 | ForEach-Object -Parallel -ThrottleLimit $Threads {
        $ip = "${using:Prefix}.$_"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
            Write-Host "[+] $ip is alive" -ForegroundColor Green
            $ip
        }
    }

    if (-not $alive) {
        Write-Host "[-] No live hosts found." -ForegroundColor Red
        return
    }

 
    $alive | ForEach-Object -Parallel -ThrottleLimit $Threads {
        $ip = $_
        foreach ($p in $using:Ports) {
            if (Test-NetConnection -ComputerName $ip -Port $p -InformationLevel Quiet) {
                $url = "http://${ip}:${p}"
                try {
                    $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2
                    $html = $resp.Content
                    $title = Get-Title -Html $html
                } catch {
                    $title = ''
                }
                if ($resp.StatusCode -match '^[1-5]\d\d$') {
                    $line = "${ip}:${p} - $title"
                    Write-Host "[+] $line" -ForegroundColor Green
                    $Results += $line
                    Add-Content -Path $logFile -Value $line
                } else {
                    Write-Host "[-] $url did not return HTTP" -ForegroundColor Red
                }
            }
        }
    }
}

 
if ($Local) {
    Scan-Local
} else {
    if (-not $Interface) {
        Write-Host "Error: Please specify a network interface with -Interface." -ForegroundColor Yellow
        Show-Usage; exit 1
    }
    try {
        $prefix = Get-SubnetPrefix -IfAlias $Interface
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red; exit 1
    }
    Scan-Network -Prefix $prefix
}

Write-Host "`n[+] Scan complete. Results saved to: $logFile" -ForegroundColor Cyan
 
