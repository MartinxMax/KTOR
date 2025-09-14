# KTOR - improved HTTP detection using Invoke-WebRequest + concurrency
# Usage: .\ktor-invoke-http.ps1 [-Threads <int>] [-Local] [-Targets <CIDR|IP|IP,IP,...>] [-Ports <int,int,...>] [-Help]

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
Usage: .\ktor-invoke-http.ps1 [-Threads <int>] [-Local] [-Targets <CIDR|IP|IP,IP,...>] [-Ports <int,int,...>] [-Help]

  -Threads    Maximum parallel jobs (default: 50)
  -Local      Scan only localhost (127.0.0.1)
  -Targets    CIDR (e.g. 192.168.0.0/24 or /16), single IP (e.g. 192.168.0.1) or comma-separated list
  -Ports      Comma-separated list of ports to scan (default: 80,443,8080)
  -Help       Show this help message
"@
}

if ($Help) { Show-Usage; exit }

$timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$logFile   = Join-Path $env:TEMP "http-$timestamp.txt"
$Results   = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()

$header = @'
      ___                       ___           ___     
     /__/|          ___        / :/          /  /\    
    |  |:|         /  /:\      /  /:/_        /  /::\   
    |  |:|        /  /:/     /  /:/ /\      /  /:/\:\  
  __|  |:|       /  /:/     /  /:/_/::\    /  /:/~/:/  
 /__\/\_|:|____ /  /::\    /__/:/__\/\:\  /__/:/ /:/___
 \  \:/:::::/ /__/:/\:\   \  \:\ /~~/:/  \  \:/:/:::::/
  \  \::/~~~~  \__\/  \:\   \  \:\  /:/    \  \::/~~~~ 
   \  \:\           \  \:\   \  \:\/:/      \  \:\     
    \  \:\           \__\/    \  \::/        \  \:\    
     \__\/                     \__\/          \__\/    
'@
Write-Output $header
Write-Output "Maptnh@S-H4CK13   https://github.com/MartinxMax  KTOR  (modified)"
Write-Output "For Windows - improved HTTP detection (Invoke-WebRequest)"

function Get-Title {
    param([string]$Html)
    if ($Html -match '(?is)<title>(.*?)</title>') { return $Matches[1].Trim() }
    return ''
}

function Expand-CIDR {
    param([string]$cidr)
    $result = @()
    if ($cidr -match '^(.+)/([0-9]{1,2})$') {
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

function Probe-Http {
    param(
        [string]$IP,
        [int]$Port
    )

    # Try both http and https heuristically
    $schemes = @('http')
    if ($Port -eq 443) { $schemes = @('https') } else { $schemes += 'https' }

    foreach ($s in $schemes) {
        $url = "{0}://{1}:{2}/" -f $s, $IP, $Port
        try {
            # Use -UseBasicParsing to avoid IE DOM dependency on older PowerShell
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop

            $title = Get-Title -Html $resp.Content
            $server = $resp.Headers['Server'] -as [string]
            $ct = $resp.Headers['Content-Type'] -as [string]
            $line = [PSCustomObject]@{
                IP = $IP
                Port = $Port
                Scheme = $s
                StatusCode = $resp.StatusCode
                Server = $server
                ContentType = $ct
                Title = $title
                Length = ($resp.Content | Measure-Object -Character).Characters
            }
            return $line
        } catch {
            # swallow and try next scheme
        }
    }
    return $null
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

    $queue = foreach ($p in $Ports) { [PSCustomObject]@{IP='127.0.0.1'; Port=[int]$p} }
    Start-Scan -Queue $queue
}

function Scan-Network {
    param([string[]]$Hosts)
    $total = $Hosts.Count * $Ports.Count
    Write-Output "[*] Scanning $($Hosts.Count) hosts x $($Ports.Count) ports = $total checks"

    $queue = foreach ($targetHost in $Hosts) {
        foreach ($targetPort in $Ports) {
            [PSCustomObject]@{IP = $targetHost; Port = [int]$targetPort}
        }
    }

    Start-Scan -Queue $queue
}

function Start-Scan {
    param([Parameter(Mandatory = $true)][object[]]$Queue)

    $jobs = @()
    foreach ($entry in $Queue) {
        # throttle
        while ($jobs.Where({ $_.State -eq 'Running' }).Count -ge $Threads) {
            Start-Sleep -Milliseconds 200
            $jobs = $jobs | Where-Object { $_.State -ne 'Completed' -and $_.State -ne 'Failed' -and $_.State -ne 'Stopped' } +
                    (Get-Job | Where-Object { $_.State -eq 'Running' })
        }

        $j = Start-Job -ArgumentList $entry.IP, $entry.Port -ScriptBlock {
            param($ip,$port)
            # quick TCP check
            $tcp = $false
            try { $tcp = Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet } catch { $tcp = $false }
            if (-not $tcp) { return @{Found=$false; IP=$ip; Port=$port} }

            # Probe http(s)
            try {
                # Import the Get-Title and Probe-Http functions into the job session
                $GetTitle = Get-Command -Name Get-Title -ErrorAction SilentlyContinue
                if ($GetTitle) { . ($GetTitle.Source) } 2>$null
            } catch {}

            # replicate Probe-Http inline to avoid missing function context
            $schemes = @('http')
            if ($port -eq 443) { $schemes = @('https') } else { $schemes += 'https' }
            foreach ($s in $schemes) {
                $url = "{0}://{1}:{2}/" -f $s, $ip, $port
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $title = ''
                    if ($resp.Content -match '(?is)<title>(.*?)</title>') { $title = $Matches[1].Trim() }
                    return @{Found=$true; IP=$ip; Port=$port; Scheme=$s; StatusCode=$resp.StatusCode; Server=$resp.Headers['Server']; ContentType=$resp.Headers['Content-Type']; Title=$title; Length = ($resp.Content | Measure-Object -Character).Characters }
                } catch {}
            }
            return @{Found=$false; IP=$ip; Port=$port}
        }
        $jobs += $j
    }

    # wait for all jobs
    while (Get-Job -State 'Running') { Start-Sleep -Milliseconds 200 }

    # collect
    foreach ($j in Get-Job) {
        $r = Receive-Job -Job $j -ErrorAction SilentlyContinue
        if ($r -and $r.Found) {
            $obj = [PSCustomObject]@{
                IP = $r.IP
                Port = $r.Port
                Scheme = $r.Scheme
                StatusCode = $r.StatusCode
                Server = $r.Server
                ContentType = $r.ContentType
                Title = $r.Title
                Length = $r.Length
            }
            $Results.Add($obj)
            $line = "{0}:{1} ({2}) - {3} - Title: {4}" -f $r.IP, $r.Port, $r.Scheme, ($r.StatusCode -or '200'), ($r.Title -or '')
            Add-Content -Path $logFile -Value $line
            Write-Output "[+] $line"
        }
        Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
    }
}

if ($Local) {
    Scan-Local
} elseif ($Targets) {
    $targetsList = @()
    foreach ($t in $Targets -split ',') { $targetsList += Expand-CIDR -cidr $t }
    if ($targetsList.Count -gt 4096) { Write-Output "[-] Too many targets ($($targetsList.Count)). Limit to 4096 IPs."; exit 1 }
    Scan-Network -Hosts $targetsList
} else {
    Write-Output "Error: Specify -Targets or -Local."; Show-Usage; exit 1
}

Write-Output "[+] Scan complete. Results saved to: $logFile"
