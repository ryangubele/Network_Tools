function Get-ArpTable {
    [CmdletBinding()]
    param ()

    $arpTable = @{}

    if ($IsWindows) {
        $getNetNeighbor = Get-Command -Name Get-NetNeighbor -ErrorAction SilentlyContinue
        if ($null -ne $getNetNeighbor) {
            try {
                Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object State -ne 'Unreachable' |
                    ForEach-Object {
                        $arpTable[$_.IPAddress] = $_.LinkLayerAddress -replace '-', ':'
                    }
            }
            catch {
            }
        }
    } elseif ($IsLinux) {
        $ipCommand = Get-Command -Name ip -ErrorAction SilentlyContinue
        if ($null -ne $ipCommand) {
            try {
                (ip neigh show) | ForEach-Object {
                    if ($_ -match '(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([a-fA-F0-9:]+)') {
                        $arpTable[$matches[1]] = $matches[2]
                    }
                }
            }
            catch {
            }
        }
    }

    return $arpTable
}

if ($null -eq $script:OuiLookupCache) {
    $script:OuiLookupCache = @{}
}

function Get-OuiLookupData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$MapPath
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($MapPath)
    if (-not (Test-Path -Path $resolvedPath)) {
        throw "OUI map file not found: $resolvedPath"
    }

    $lastWriteTicks = (Get-Item -Path $resolvedPath).LastWriteTimeUtc.Ticks
    if ($script:OuiLookupCache.ContainsKey($resolvedPath)) {
        $cached = $script:OuiLookupCache[$resolvedPath]
        if ($cached.LastWriteTicks -eq $lastWriteTicks) {
            return $cached
        }
    }

    $ouiMap = @{}
    $prefixLengths = [System.Collections.Generic.HashSet[int]]::new()

    $rows = Import-Csv -Path $resolvedPath -ErrorAction Stop
    foreach ($row in $rows) {
        if ($null -eq $row.Prefix -or $null -eq $row.Vendor) {
            continue
        }

        $prefix = (($row.Prefix -replace '[^0-9A-Fa-f]', '').ToUpper())
        if ($prefix.Length -ge 6) {
            $ouiMap[$prefix] = [string]$row.Vendor
            [void]$prefixLengths.Add($prefix.Length)
        }
    }

    $cacheEntry = [PSCustomObject]@{
        Map                = $ouiMap
        OrderedPrefixLengths = ($prefixLengths | Sort-Object -Descending)
        LastWriteTicks     = $lastWriteTicks
    }

    $script:OuiLookupCache[$resolvedPath] = $cacheEntry
    return $cacheEntry
}

function Send-Stimulus {
    <#
    .SYNOPSIS
    Sends UDP broadcast stimulus frames from a specific local interface and optional local port.

    .DESCRIPTION
    Binds a UDP socket to the local interface IP address and sends a configurable number of
    broadcast UDP frames. This is useful for generating deterministic traffic for
    switch port tests, capture validation, and basic path stimulation in lab or field networks.

    .PARAMETER InterfaceIP
    IPv4 address of the local interface to bind for outbound stimulus traffic.

    .PARAMETER LocalPort
    Local UDP source port used when binding the socket. Use 0 for an ephemeral OS-assigned port.

    .PARAMETER Count
    Number of stimulus frames to send.

    .PARAMETER DelayMs
    Delay in milliseconds between each transmitted frame.

    .EXAMPLE
    Send-Stimulus -InterfaceIP 192.168.1.10 -LocalPort 40000 -Count 50 -DelayMs 10
    Sends 50 broadcast frames from interface 192.168.1.10 using source port 40000.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceIP,

        [ValidateRange(0, 65535)]
        [int]$LocalPort = 0,

        [ValidateRange(1, 1000000)]
        [int]$Count = 100,

        [ValidateRange(0, 60000)]
        [int]$DelayMs = 50
    )

    $target = [System.Net.IPAddress]::Broadcast
    $port = 9
    $payload = [System.Text.Encoding]::ASCII.GetBytes("STIMULUS")

    $client = $null
    try {
        $localEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($InterfaceIP), $LocalPort)
        $client = [System.Net.Sockets.UdpClient]::new($localEndPoint)
        $targetEndPoint = [System.Net.IPEndPoint]::new($target, $port)

        1..$Count | ForEach-Object {
            [void]$client.Send($payload, $payload.Length, $targetEndPoint)
            Write-Verbose "Frame $_ sent from $InterfaceIP"
            if ($DelayMs -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }

        [PSCustomObject]@{
            InterfaceIP = $InterfaceIP
            LocalPort   = $localEndPoint.Port
            Count       = $Count
            Target      = $target.IPAddressToString
            Port        = $port
            PayloadSize = $payload.Length
        }
    }
    catch {
        Write-Error $_.Exception.Message
    }
    finally {
        if ($null -ne $client) {
            $client.Close()
        }
    }
}

function Test-TcpPort {
    <#
    .SYNOPSIS
    Tests TCP connectivity to one or more ports on a target host.

    .DESCRIPTION
    Attempts a TCP connection using .NET sockets so behavior is consistent across Windows and Linux.
    Returns reachability and latency details for each tested port.

    .PARAMETER ComputerName
    Hostname or IP address of the remote target.

    .PARAMETER Port
    One or more TCP ports to test.

    .PARAMETER TimeoutMs
    Connection timeout in milliseconds for each TCP probe.

    .PARAMETER Quiet
    Returns only boolean reachability values instead of detailed objects.

    .PARAMETER ResolveDns
    Attempts DNS resolution and includes the first IPv4 address in the output.

    .EXAMPLE
    Test-TcpPort -ComputerName 192.168.1.20 -Port 22,443 -TimeoutMs 800
    Tests SSH and HTTPS reachability and returns latency details.

    .EXAMPLE
    'server01' | Test-TcpPort -Port 3389 -Quiet
    Returns True or False for TCP 3389 reachability on server01.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host', 'IPAddress')]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateRange(1, 65535)]
        [int[]]$Port,

        [ValidateRange(50, 60000)]
        [int]$TimeoutMs = 1000,

        [switch]$Quiet,

        [switch]$ResolveDns
    )

    process {
        foreach ($targetPort in $Port) {
            $client = [System.Net.Sockets.TcpClient]::new()
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $reachable = $false
            $errorMessage = $null
            $resolvedAddress = $null

            if ($ResolveDns) {
                try {
                    $resolvedAddress = [System.Net.Dns]::GetHostAddresses($ComputerName) |
                        Where-Object AddressFamily -eq ([System.Net.Sockets.AddressFamily]::InterNetwork) |
                        Select-Object -ExpandProperty IPAddressToString -First 1
                }
                catch {
                }
            }

            try {
                $connectTask = $client.ConnectAsync($ComputerName, $targetPort)
                if ($connectTask.Wait($TimeoutMs) -and $client.Connected) {
                    $reachable = $true
                } else {
                    $errorMessage = 'Timed out'
                }
            }
            catch {
                $errorMessage = $_.Exception.Message
            }
            finally {
                $stopwatch.Stop()
                $client.Dispose()
            }

            if ($Quiet) {
                $reachable
            } else {
                [PSCustomObject]@{
                    ComputerName    = $ComputerName
                    Port            = $targetPort
                    Reachable       = $reachable
                    LatencyMs       = [int]$stopwatch.ElapsedMilliseconds
                    ResolvedAddress = $resolvedAddress
                    Error           = if ($reachable) { $null } else { $errorMessage }
                }
            }
        }
    }
}

function Resolve-MacVendor {
    <#
    .SYNOPSIS
    Resolves a MAC address to a likely hardware vendor based on OUI prefix.

    .DESCRIPTION
    Normalizes MAC address input and matches its OUI prefix against a local CSV database.
    You can also supply a custom CSV map file with Prefix and Vendor columns.
    If enabled, optional online lookup is used when no local match is found.

    .PARAMETER MacAddress
    One or more MAC addresses to resolve. Supports common formats with colons, hyphens, or dots.

    .PARAMETER OuiMapPath
    Optional path to a CSV file containing Prefix and Vendor columns.

    .PARAMETER UseOnlineApi
    If set, attempts an online lookup for unknown OUIs.

    .PARAMETER ApiBaseUri
    Base URI for online lookup requests. Default uses api.macvendors.com.

    .EXAMPLE
    Resolve-MacVendor -MacAddress '00:1A:2B:AA:BB:CC'
    Resolves the vendor for a single MAC address.

    .EXAMPLE
    '00-50-56-11-22-33','AA:BB:CC:00:11:22' | Resolve-MacVendor
    Resolves vendor names for multiple MAC addresses from pipeline input.

    .EXAMPLE
    Resolve-MacVendor -MacAddress '40:b0:34:00:11:22' -UseOnlineApi
    Uses local database first, then online lookup if no local match is found.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MAC', 'Address')]
        [ValidateNotNullOrEmpty()]
        [string[]]$MacAddress,

        [Parameter()]
        [string]$OuiMapPath,

        [Parameter()]
        [switch]$UseOnlineApi,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiBaseUri = 'https://api.macvendors.com'
    )

    begin {
        $defaultMapPath = Join-Path -Path $PSScriptRoot -ChildPath 'data\\oui-map.csv'
        $selectedMapPath = if ($OuiMapPath) { $OuiMapPath } else { $defaultMapPath }

        try {
            $lookupData = Get-OuiLookupData -MapPath $selectedMapPath
        }
        catch {
            throw "Failed to read OUI map file '$selectedMapPath': $($_.Exception.Message)"
        }

        $ouiMap = $lookupData.Map
        $orderedPrefixLengths = $lookupData.OrderedPrefixLengths
    }

    process {
        foreach ($mac in $MacAddress) {
            $hex = ($mac -replace '[^0-9A-Fa-f]', '').ToUpper()
            if ($hex.Length -ne 12) {
                throw "Invalid MAC address format: $mac"
            }

            $normalized = '{0}:{1}:{2}:{3}:{4}:{5}' -f $hex.Substring(0, 2), $hex.Substring(2, 2), $hex.Substring(4, 2), $hex.Substring(6, 2), $hex.Substring(8, 2), $hex.Substring(10, 2)
            $prefix = $hex.Substring(0, 6)

            $vendor = 'Unknown'
            $source = 'None'

            foreach ($length in $orderedPrefixLengths) {
                if ($length -le $hex.Length) {
                    $candidate = $hex.Substring(0, $length)
                    if ($ouiMap.ContainsKey($candidate)) {
                        $vendor = $ouiMap[$candidate]
                        $source = if ($OuiMapPath) { 'CustomMap' } else { 'FileMap' }
                        break
                    }
                }
            }

            if ($source -eq 'None' -and $UseOnlineApi) {
                try {
                    $uri = ('{0}/{1}' -f $ApiBaseUri.TrimEnd('/'), $normalized)
                    $onlineResult = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 5 -ErrorAction Stop
                    $onlineVendor = [string]$onlineResult
                    if (-not [string]::IsNullOrWhiteSpace($onlineVendor)) {
                        $vendor = $onlineVendor.Trim()
                        $source = 'OnlineApi'
                    }
                }
                catch {
                }
            }

            [PSCustomObject]@{
                InputMac      = $mac
                NormalizedMac = $normalized
                OuiPrefix     = '{0}:{1}:{2}' -f $hex.Substring(0, 2), $hex.Substring(2, 2), $hex.Substring(4, 2)
                Vendor        = $vendor
                Source        = $source
            }
        }
    }
}

function Convert-FromCidr {
    <#
    .SYNOPSIS
    Converts CIDR notation into an IPv4 subnet mask.

    .DESCRIPTION
    Accepts an IPv4 CIDR string such as 192.168.10.0/24 and returns the source network address,
    prefix length, and dotted-decimal subnet mask. This helps network engineers translate between
    prefix and mask formats when documenting or validating network configurations.

    .PARAMETER Cidr
    IPv4 CIDR input in address/prefix format, such as 192.168.10.0/24.

    .EXAMPLE
    Convert-FromCidr -Cidr 10.10.0.0/16
    Returns IPAddress, PrefixLength, and SubnetMask for the specified CIDR block.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidatePattern('^(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[12][0-9]|3[0-2])$')]
        [Alias('InputObject')]
        [string]$Cidr
    )

    process {
        $ip, $prefixLength = $Cidr.Split('/')

        $parsedIp = $null
        if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp) -or
            $parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Invalid IPv4 address in CIDR input: $ip"
        }

        $maskInt = if ([int]$prefixLength -eq 0) {
            [uint32]0
        } else {
            [uint32]((0xFFFFFFFFL -shl (32 - [int]$prefixLength)) -band 0xFFFFFFFFL)
        }

        $maskBytes = [System.BitConverter]::GetBytes($maskInt)
        [array]::Reverse($maskBytes)

        [PSCustomObject]@{
            IPAddress    = $parsedIp.IPAddressToString
            PrefixLength = [int]$prefixLength
            SubnetMask   = ([ipaddress]$maskBytes).IPAddressToString
        }
    }
}

function Invoke-NetworkScan {
    <#
    .SYNOPSIS
    Performs a parallel ping sweep and attempts to retrieve MAC addresses from the local ARP cache.

    .DESCRIPTION
    Accepts CIDR (e.g., 192.168.1.0/24) or standard mask (e.g., 192.168.1.0 255.255.255.0).
    Requires PowerShell 7+ for the ForEach-Object -Parallel switch.
    Emits result objects as hosts are discovered instead of waiting for full scan completion.

    .PARAMETER Target
    Target network expressed as CIDR (192.168.1.0/24) or address plus subnet mask.

    .PARAMETER TimeoutMs
    ICMP timeout in milliseconds for each host probe.

    .PARAMETER ThrottleLimit
    Maximum number of concurrent ping operations.

    .PARAMETER ResolveMacVendor
    When set, resolves discovered MAC addresses to likely vendors using Resolve-MacVendor.

    .PARAMETER ResolveDns
    When set, performs a reverse DNS (PTR) lookup for each discovered host and includes its hostname.

    .PARAMETER DnsTimeout
    Timeout in seconds for each reverse DNS lookup. Increase if hostnames are being missed on slow DNS.

    .EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.0/24 -TimeoutMs 300 -ThrottleLimit 50
    Scans the target subnet for reachable hosts and returns IP, MAC, and latency details.

    .EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.0/24 -ResolveMacVendor
    Scans the target subnet and includes vendor lookups for discovered MAC addresses.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Target,

        [int]$TimeoutMs = 300,
        [int]$ThrottleLimit = 50,
        [int]$DnsTimeout = 5,
        [switch]$ResolveMacVendor,
        [switch]$ResolveDns
    )

    $ipStr = ""
    $maskBits = 0
    $maskInt = 0

    if ($Target -match '/') {
        $ipStr, $maskStr = $Target.Split('/')
        $maskBits = [int]$maskStr
        # Shift, mask the upper 32 bits to prevent overflow, then cast.
        $maskInt = [uint32]((0xFFFFFFFFL -shl (32 - $maskBits)) -band 0xFFFFFFFFL)
    } else {
        $ipStr, $maskStr = $Target -split '\s+|,', 2
        $maskBytes = [System.Net.IPAddress]::Parse($maskStr).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($maskBytes)
        }

        $maskInt = [BitConverter]::ToUInt32($maskBytes, 0)

        # Calculate CIDR bits by counting 1 bits in the mask.
        $maskBits = [Convert]::ToString($maskInt, 2).Replace("0", "").Length
    }

    $ipBytes = [System.Net.IPAddress]::Parse($ipStr).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($ipBytes)
    }
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    # Base network and broadcast addresses as 32-bit integers.
    $networkInt = $ipInt -band $maskInt
    $broadcastInt = $networkInt -bor (-bnot $maskInt)

    $ipList = [System.Collections.Generic.List[string]]::new()
    for ($i = $networkInt + 1; $i -lt $broadcastInt; $i++) {
        $bytes = [BitConverter]::GetBytes([uint32]$i)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($bytes)
        }
        $ipList.Add([System.Net.IPAddress]::new($bytes).IPAddressToString)
    }

    Write-Verbose "Pinging $($ipList.Count) IPs..."

    $arpTable = Get-ArpTable
    $vendorCache = @{}
    $ouiMap = $null
    $orderedPrefixLengths = @()

    if ($ResolveMacVendor) {
        try {
            $lookupData = Get-OuiLookupData -MapPath (Join-Path -Path $PSScriptRoot -ChildPath 'data\\oui-map.csv')
            $ouiMap = $lookupData.Map
            $orderedPrefixLengths = $lookupData.OrderedPrefixLengths
        }
        catch {
            Write-Verbose "OUI map load failed. MAC vendor lookup will fall back to Unknown."
        }
    }

    $ipList |
        ForEach-Object -Parallel {
            $ping = [System.Net.NetworkInformation.Ping]::new()
            try {
                $reply = $ping.Send($_, $using:TimeoutMs)
                if ($reply.Status -eq 'Success') {
                    [PSCustomObject]@{
                        IPAddress = $_
                        LatencyMs = $reply.RoundtripTime
                    }
                }
            }
            catch {
            }
            finally {
                $ping.Dispose()
            }
        } -ThrottleLimit $ThrottleLimit |
        ForEach-Object {
            $mac = if ($arpTable.ContainsKey($_.IPAddress)) {
                $arpTable[$_.IPAddress]
            } else {
                'Unknown'
            }

            $vendor = $null
            if ($ResolveMacVendor -and $mac -ne 'Unknown') {                if ($vendorCache.ContainsKey($mac)) {
                    $vendor = $vendorCache[$mac]
                }
                else {
                    $vendor = 'Unknown'
                    if ($null -ne $ouiMap) {
                        $macHex = ($mac -replace '[^0-9A-Fa-f]', '').ToUpper()
                        foreach ($length in $orderedPrefixLengths) {
                            if ($length -le $macHex.Length) {
                                $candidate = $macHex.Substring(0, $length)
                                if ($ouiMap.ContainsKey($candidate)) {
                                    $vendor = $ouiMap[$candidate]
                                    break
                                }
                            }
                        }
                    }

                    $vendorCache[$mac] = $vendor
                }
            }

            [PSCustomObject]@{
                IPAddress  = $_.IPAddress
                MACAddress = $mac
                MACVendor  = $vendor
                Hostname   = $null
                LatencyMs  = $_.LatencyMs
            }
        } |
        ForEach-Object -Parallel {
            if ($using:ResolveDns) {
                $dnsTimeout = $using:DnsTimeout * 1000
                try {
                    $result = [System.Net.Dns]::BeginGetHostEntry($_.IPAddress, $null, $null)
                    if ($result.AsyncWaitHandle.WaitOne($dnsTimeout)) {
                        $entry = [System.Net.Dns]::EndGetHostEntry($result)
                        if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace($entry.HostName)) {
                            $_.Hostname = $entry.HostName
                        }
                    }
                }
                catch {
                }
            }
            $_.PSObject.TypeNames.Insert(0, 'NetworkTools.ScanResult')
            $_
        } -ThrottleLimit $ThrottleLimit
}

Set-Alias -Name Send-InterfaceStimulus -Value Send-Stimulus

Export-ModuleMember -Function Send-Stimulus, Test-TcpPort, Resolve-MacVendor, Convert-FromCidr, Invoke-NetworkScan -Alias Send-InterfaceStimulus
