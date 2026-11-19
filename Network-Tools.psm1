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

function Invoke-NetworkScanProbe {
    param (
        [System.Collections.Generic.IEnumerable[string]]$Addresses,
        [int]$TimeoutMs,
        [int]$ThrottleLimit
    )

    $Addresses |
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
        } -ThrottleLimit $ThrottleLimit
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

    Invoke-NetworkScanProbe -Addresses $ipList -TimeoutMs $TimeoutMs -ThrottleLimit $ThrottleLimit |
        ForEach-Object {
            $mac = if ($arpTable.ContainsKey($_.IPAddress)) {
                $arpTable[$_.IPAddress]
            } else {
                'Unknown'
            }

            if ($mac -eq 'Unknown') {
                foreach ($retry in 1..3) {
                    Start-Sleep -Milliseconds 100
                    $freshArp = Get-ArpTable
                    if ($freshArp.ContainsKey($_.IPAddress)) {
                        $mac = $freshArp[$_.IPAddress]
                        break
                    }
                }
            }

            $vendor = $null
            if ($ResolveMacVendor -and $mac -ne 'Unknown') {
                if ($vendorCache.ContainsKey($mac)) {
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
                Hostname   = $null
                IPAddress  = $_.IPAddress
                MACAddress = $mac
                MACVendor  = $vendor
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

#region SNMP protocol (v1 / v2c / v3 USM) -------------------------------------
#
# A small, dependency-free SNMP manager: BER encoding, community (v1/v2c) and
# USM (v3) message security, and a pipelined UDP request engine. Only what the
# interface-counter tooling needs (Get, GetNext, GetBulk) is implemented.

$script:SnmpTypeTags = @{
    Integer          = 0x02
    OctetString      = 0x04
    Null             = 0x05
    ObjectIdentifier = 0x06
    Sequence         = 0x30
    IpAddress        = 0x40
    Counter32        = 0x41
    Gauge32          = 0x42
    TimeTicks        = 0x43
    Opaque           = 0x44
    Counter64        = 0x46
    NoSuchObject     = 0x80
    NoSuchInstance   = 0x81
    EndOfMibView     = 0x82
}
$script:SnmpTagNames = @{}
foreach ($snmpTypeEntry in $script:SnmpTypeTags.GetEnumerator()) {
    $script:SnmpTagNames[[int]$snmpTypeEntry.Value] = $snmpTypeEntry.Key
}

$script:SnmpPduTypes = @{
    Get      = 0xA0
    GetNext  = 0xA1
    Response = 0xA2
    GetBulk  = 0xA5
    Report   = 0xA8
}

$script:SnmpErrorNames = @(
    'noError', 'tooBig', 'noSuchName', 'badValue', 'readOnly', 'genErr', 'noAccess', 'wrongType',
    'wrongLength', 'wrongEncoding', 'wrongValue', 'noCreation', 'inconsistentValue',
    'resourceUnavailable', 'commitFailed', 'undoFailed', 'authorizationError', 'notWritable',
    'inconsistentName'
)

$script:SnmpUsmReports = @{
    '1.3.6.1.6.3.15.1.1.1.0' = 'unsupportedSecLevels'
    '1.3.6.1.6.3.15.1.1.2.0' = 'notInTimeWindows'
    '1.3.6.1.6.3.15.1.1.3.0' = 'unknownUserNames'
    '1.3.6.1.6.3.15.1.1.4.0' = 'unknownEngineIDs'
    '1.3.6.1.6.3.15.1.1.5.0' = 'wrongDigests'
    '1.3.6.1.6.3.15.1.1.6.0' = 'decryptionErrors'
}

# RFC 3414 (MD5/SHA-1) and RFC 7860 (SHA-2) HMAC authentication protocols.
$script:SnmpAuthProtocols = @{
    MD5    = @{ Hash = 'MD5';    MacLength = 12 }
    SHA    = @{ Hash = 'SHA1';   MacLength = 12 }
    SHA256 = @{ Hash = 'SHA256'; MacLength = 24 }
    SHA384 = @{ Hash = 'SHA384'; MacLength = 32 }
    SHA512 = @{ Hash = 'SHA512'; MacLength = 48 }
}

# RFC 3414 DES-CBC, RFC 3826 AES-CFB128. AES192/AES256 use the Blumenthal key
# extension (net-snmp "AES192"/"AES256"); the C variants use the Reeder
# extension used by Cisco (net-snmp "AES192C"/"AES256C").
$script:SnmpPrivProtocols = @{
    DES     = @{ Cipher = 'DES'; KeyLength = 16; Extend = 'None' }
    AES     = @{ Cipher = 'AES'; KeyLength = 16; Extend = 'None' }
    AES192  = @{ Cipher = 'AES'; KeyLength = 24; Extend = 'Blumenthal' }
    AES256  = @{ Cipher = 'AES'; KeyLength = 32; Extend = 'Blumenthal' }
    AES192C = @{ Cipher = 'AES'; KeyLength = 24; Extend = 'Reeder' }
    AES256C = @{ Cipher = 'AES'; KeyLength = 32; Extend = 'Reeder' }
}

function Join-SnmpBytes {
    $list = [System.Collections.Generic.List[byte]]::new()
    foreach ($part in $args) {
        if ($null -ne $part) {
            $list.AddRange([byte[]]$part)
        }
    }
    return , $list.ToArray()
}

function Get-SnmpByteSlice {
    param ([byte[]]$Data, [int]$Start, [int]$Length)

    $slice = [byte[]]::new([Math]::Max(0, $Length))
    if ($Length -gt 0) {
        [Array]::Copy($Data, $Start, $slice, 0, $Length)
    }
    return , $slice
}

function ConvertTo-SnmpBerTlv {
    param ([int]$Tag, [byte[]]$Content)

    if ($null -eq $Content) {
        $Content = [byte[]]::new(0)
    }

    $length = $Content.Length
    $list = [System.Collections.Generic.List[byte]]::new($length + 6)
    $list.Add([byte]$Tag)
    if ($length -lt 0x80) {
        $list.Add([byte]$length)
    } else {
        $lengthBytes = [System.Collections.Generic.List[byte]]::new()
        $remaining = $length
        while ($remaining -gt 0) {
            $lengthBytes.Insert(0, [byte]($remaining -band 0xFF))
            $remaining = $remaining -shr 8
        }
        $list.Add([byte](0x80 -bor $lengthBytes.Count))
        $list.AddRange($lengthBytes)
    }
    $list.AddRange($Content)
    return , $list.ToArray()
}

function ConvertTo-SnmpBerIntegerTlv {
    param ([int]$Tag = 0x02, [System.Numerics.BigInteger]$Value)

    # BigInteger produces minimal two's complement (little-endian), which is
    # exactly BER for signed values and adds the leading 0x00 unsigned types need.
    $content = $Value.ToByteArray()
    [Array]::Reverse($content)
    return , (ConvertTo-SnmpBerTlv -Tag $Tag -Content $content)
}

function ConvertTo-SnmpBerOctetStringTlv {
    param ($Value)

    $bytes = if ($null -eq $Value) {
        [byte[]]::new(0)
    } elseif ($Value -is [byte[]]) {
        $Value
    } else {
        [System.Text.Encoding]::UTF8.GetBytes([string]$Value)
    }
    return , (ConvertTo-SnmpBerTlv -Tag 0x04 -Content $bytes)
}

function ConvertTo-SnmpBerOidTlv {
    param ([Parameter(Mandatory = $true)][string]$Oid)

    $parts = $Oid.Trim().TrimStart('.').Split('.')
    if ($parts.Count -lt 2) {
        throw "Invalid OID '$Oid'"
    }

    try {
        [uint64[]]$arcs = $parts
    }
    catch {
        throw "Invalid OID '$Oid'"
    }

    $values = [System.Collections.Generic.List[uint64]]::new()
    $values.Add([uint64]($arcs[0] * 40 + $arcs[1]))
    for ($i = 2; $i -lt $arcs.Count; $i++) {
        $values.Add($arcs[$i])
    }

    $content = [System.Collections.Generic.List[byte]]::new()
    foreach ($value in $values) {
        $chunk = [System.Collections.Generic.List[byte]]::new()
        $remaining = $value
        $chunk.Add([byte]($remaining -band 0x7F))
        $remaining = $remaining -shr 7
        while ($remaining -gt 0) {
            $chunk.Insert(0, [byte](($remaining -band 0x7F) -bor 0x80))
            $remaining = $remaining -shr 7
        }
        $content.AddRange($chunk)
    }
    return , (ConvertTo-SnmpBerTlv -Tag 0x06 -Content $content.ToArray())
}

function Read-SnmpBerHeader {
    # Returns @(tag, contentStart, contentLength) for the TLV at $Offset.
    param ([byte[]]$Data, [int]$Offset, [int]$Limit)

    if ($Offset + 2 -gt $Limit) {
        throw 'Malformed SNMP packet: truncated BER header.'
    }

    $tag = [int]$Data[$Offset]
    $length = [int]$Data[$Offset + 1]
    $position = $Offset + 2
    if ($length -band 0x80) {
        $count = $length -band 0x7F
        if ($count -lt 1 -or $count -gt 4 -or $position + $count -gt $Limit) {
            throw 'Malformed SNMP packet: invalid BER length.'
        }
        $length = 0
        for ($i = 0; $i -lt $count; $i++) {
            $length = ($length -shl 8) -bor $Data[$position + $i]
        }
        $position += $count
    }

    if ($length -lt 0 -or $position + $length -gt $Limit) {
        throw 'Malformed SNMP packet: BER length exceeds packet.'
    }

    return [int[]]@($tag, $position, $length)
}

function ConvertFrom-SnmpBerSigned {
    param ([byte[]]$Data, [int]$Start, [int]$Length)

    [long]$value = 0
    if ($Length -gt 0 -and ($Data[$Start] -band 0x80)) {
        $value = -1
    }
    for ($i = $Start; $i -lt $Start + $Length; $i++) {
        $value = ($value -shl 8) -bor [long]$Data[$i]
    }
    return $value
}

function ConvertFrom-SnmpBerUnsigned {
    param ([byte[]]$Data, [int]$Start, [int]$Length)

    [uint64]$value = 0
    for ($i = $Start; $i -lt $Start + $Length; $i++) {
        $value = ($value -shl 8) -bor [uint64]$Data[$i]
    }
    return $value
}

function ConvertFrom-SnmpBerOid {
    param ([byte[]]$Data, [int]$Start, [int]$Length)

    $builder = [System.Text.StringBuilder]::new()
    [uint64]$current = 0
    $first = $true
    for ($i = $Start; $i -lt $Start + $Length; $i++) {
        $byte = $Data[$i]
        $current = ($current -shl 7) -bor [uint64]($byte -band 0x7F)
        if (-not ($byte -band 0x80)) {
            if ($first) {
                if ($current -lt 40) {
                    [void]$builder.Append('0.').Append($current)
                } elseif ($current -lt 80) {
                    [void]$builder.Append('1.').Append($current - 40)
                } else {
                    [void]$builder.Append('2.').Append($current - 80)
                }
                $first = $false
            } else {
                [void]$builder.Append('.').Append($current)
            }
            $current = 0
        }
    }
    return $builder.ToString()
}

function ConvertFrom-SnmpBerValue {
    param ([byte[]]$Data, [int]$Tag, [int]$Start, [int]$Length)

    switch ($Tag) {
        0x02 { return ConvertFrom-SnmpBerSigned -Data $Data -Start $Start -Length $Length }
        0x04 { return , (Get-SnmpByteSlice -Data $Data -Start $Start -Length $Length) }
        0x06 { return ConvertFrom-SnmpBerOid -Data $Data -Start $Start -Length $Length }
        0x40 {
            if ($Length -eq 4) {
                return ('{0}.{1}.{2}.{3}' -f $Data[$Start], $Data[$Start + 1], $Data[$Start + 2], $Data[$Start + 3])
            }
            return , (Get-SnmpByteSlice -Data $Data -Start $Start -Length $Length)
        }
        { $_ -in 0x41, 0x42, 0x43, 0x46 } { return ConvertFrom-SnmpBerUnsigned -Data $Data -Start $Start -Length $Length }
        0x44 { return , (Get-SnmpByteSlice -Data $Data -Start $Start -Length $Length) }
    }
    return $null
}

function ConvertTo-SnmpDisplayString {
    param ($Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [byte[]]) {
        return ([System.Text.Encoding]::UTF8.GetString($Value) -replace '[\x00-\x1F\x7F]', ' ').Trim()
    }
    return ([string]$Value).Trim()
}

function ConvertTo-SnmpValueTlv {
    param ([string]$Type = 'Null', $Value)

    switch ($Type) {
        'Null' { return , [byte[]]@(0x05, 0x00) }
        'Integer' { return , (ConvertTo-SnmpBerIntegerTlv -Tag 0x02 -Value $Value) }
        'OctetString' { return , (ConvertTo-SnmpBerOctetStringTlv -Value $Value) }
        'ObjectIdentifier' { return , (ConvertTo-SnmpBerOidTlv -Oid $Value) }
        'IpAddress' { return , (ConvertTo-SnmpBerTlv -Tag 0x40 -Content ([System.Net.IPAddress]::Parse([string]$Value).GetAddressBytes())) }
        { $_ -in 'Counter32', 'Gauge32', 'TimeTicks', 'Counter64' } {
            return , (ConvertTo-SnmpBerIntegerTlv -Tag $script:SnmpTypeTags[$Type] -Value $Value)
        }
        { $_ -in 'NoSuchObject', 'NoSuchInstance', 'EndOfMibView' } {
            return , [byte[]]@([byte]$script:SnmpTypeTags[$Type], 0x00)
        }
    }
    throw "Unsupported SNMP value type '$Type'"
}

function ConvertTo-SnmpPduBytes {
    # Varbinds are OID strings (encoded with a NULL value) or objects with Oid/Type/Value.
    # For GetBulk, ErrorStatus/ErrorIndex carry non-repeaters/max-repetitions.
    param (
        [int]$PduType,
        [int]$RequestId,
        [int]$ErrorStatus = 0,
        [int]$ErrorIndex = 0,
        [object[]]$Varbinds = @(),
        # Pre-encoded varbind SEQUENCE (from ConvertTo-SnmpVarbindListTlv); skips re-encoding repeated polls.
        [byte[]]$VarbindList
    )

    if ($null -eq $VarbindList) {
        $VarbindList = ConvertTo-SnmpVarbindListTlv -Varbinds $Varbinds
    }
    $body = Join-SnmpBytes `
        (ConvertTo-SnmpBerIntegerTlv -Value $RequestId) `
        (ConvertTo-SnmpBerIntegerTlv -Value $ErrorStatus) `
        (ConvertTo-SnmpBerIntegerTlv -Value $ErrorIndex) `
        $VarbindList
    return , (ConvertTo-SnmpBerTlv -Tag $PduType -Content $body)
}

function ConvertTo-SnmpVarbindListTlv {
    param ([object[]]$Varbinds = @())

    $varbindBytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($varbind in $Varbinds) {
        if ($varbind -is [string]) {
            $oid = $varbind
            $type = 'Null'
            $value = $null
        } else {
            $oid = $varbind.Oid
            $type = $varbind.Type ?? 'Null'
            $value = $varbind.Value
        }
        $pair = Join-SnmpBytes (ConvertTo-SnmpBerOidTlv -Oid $oid) (ConvertTo-SnmpValueTlv -Type $type -Value $value)
        $varbindBytes.AddRange((ConvertTo-SnmpBerTlv -Tag 0x30 -Content $pair))
    }
    return , (ConvertTo-SnmpBerTlv -Tag 0x30 -Content $varbindBytes.ToArray())
}

function ConvertFrom-SnmpPdu {
    param ([byte[]]$Data, [int]$Offset, [int]$Limit)

    $header = Read-SnmpBerHeader -Data $Data -Offset $Offset -Limit $Limit
    $pduType = $header[0]
    $position = $header[1]
    $end = $header[1] + $header[2]

    $numbers = [long[]]::new(3)
    for ($i = 0; $i -lt 3; $i++) {
        $field = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
        if ($field[0] -ne 0x02) {
            throw 'Malformed SNMP PDU: expected INTEGER.'
        }
        $numbers[$i] = ConvertFrom-SnmpBerSigned -Data $Data -Start $field[1] -Length $field[2]
        $position = $field[1] + $field[2]
    }

    $listHeader = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
    $cursor = $listHeader[1]
    $listEnd = $listHeader[1] + $listHeader[2]
    $varbinds = [System.Collections.Generic.List[object]]::new()
    while ($cursor -lt $listEnd) {
        $pairHeader = Read-SnmpBerHeader -Data $Data -Offset $cursor -Limit $listEnd
        $pairEnd = $pairHeader[1] + $pairHeader[2]
        $oidHeader = Read-SnmpBerHeader -Data $Data -Offset $pairHeader[1] -Limit $pairEnd
        $oid = ConvertFrom-SnmpBerOid -Data $Data -Start $oidHeader[1] -Length $oidHeader[2]
        $valueHeader = Read-SnmpBerHeader -Data $Data -Offset ($oidHeader[1] + $oidHeader[2]) -Limit $pairEnd
        $value = ConvertFrom-SnmpBerValue -Data $Data -Tag $valueHeader[0] -Start $valueHeader[1] -Length $valueHeader[2]
        $typeName = $script:SnmpTagNames[[int]$valueHeader[0]] ?? ('0x{0:X2}' -f $valueHeader[0])
        $varbinds.Add([PSCustomObject]@{
            Oid   = $oid
            Type  = $typeName
            Value = $value
        })
        $cursor = $pairEnd
    }

    [PSCustomObject]@{
        PduType     = $pduType
        RequestId   = [int]$numbers[0]
        ErrorStatus = [int]$numbers[1]
        ErrorIndex  = [int]$numbers[2]
        Varbinds    = $varbinds.ToArray()
    }
}

function ConvertFrom-SnmpScopedPdu {
    param ([byte[]]$Data, [int]$Offset, [int]$Limit)

    $header = Read-SnmpBerHeader -Data $Data -Offset $Offset -Limit $Limit
    if ($header[0] -ne 0x30) {
        throw 'Malformed SNMPv3 scoped PDU.'
    }
    $end = $header[1] + $header[2]
    $engineHeader = Read-SnmpBerHeader -Data $Data -Offset $header[1] -Limit $end
    $nameHeader = Read-SnmpBerHeader -Data $Data -Offset ($engineHeader[1] + $engineHeader[2]) -Limit $end

    [PSCustomObject]@{
        ContextEngineId = Get-SnmpByteSlice -Data $Data -Start $engineHeader[1] -Length $engineHeader[2]
        ContextName     = [System.Text.Encoding]::UTF8.GetString($Data, $nameHeader[1], $nameHeader[2])
        Pdu             = ConvertFrom-SnmpPdu -Data $Data -Offset ($nameHeader[1] + $nameHeader[2]) -Limit $end
    }
}

function ConvertFrom-SnmpMessage {
    param ([byte[]]$Data)

    $outer = Read-SnmpBerHeader -Data $Data -Offset 0 -Limit $Data.Length
    if ($outer[0] -ne 0x30) {
        throw 'Not an SNMP message.'
    }
    $end = $outer[1] + $outer[2]
    $versionHeader = Read-SnmpBerHeader -Data $Data -Offset $outer[1] -Limit $end
    $version = [int](ConvertFrom-SnmpBerSigned -Data $Data -Start $versionHeader[1] -Length $versionHeader[2])
    $position = $versionHeader[1] + $versionHeader[2]

    if ($version -in 0, 1) {
        $communityHeader = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
        $pdu = ConvertFrom-SnmpPdu -Data $Data -Offset ($communityHeader[1] + $communityHeader[2]) -Limit $end
        return [PSCustomObject]@{
            Version   = $version
            Community = [System.Text.Encoding]::UTF8.GetString($Data, $communityHeader[1], $communityHeader[2])
            MsgId     = $pdu.RequestId
            Pdu       = $pdu
        }
    }

    if ($version -ne 3) {
        throw "Unsupported SNMP version $version."
    }

    # msgGlobalData
    $globalHeader = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
    $globalEnd = $globalHeader[1] + $globalHeader[2]
    $msgIdHeader = Read-SnmpBerHeader -Data $Data -Offset $globalHeader[1] -Limit $globalEnd
    $maxSizeHeader = Read-SnmpBerHeader -Data $Data -Offset ($msgIdHeader[1] + $msgIdHeader[2]) -Limit $globalEnd
    $flagsHeader = Read-SnmpBerHeader -Data $Data -Offset ($maxSizeHeader[1] + $maxSizeHeader[2]) -Limit $globalEnd
    $flags = if ($flagsHeader[2] -gt 0) { [int]$Data[$flagsHeader[1]] } else { 0 }
    $position = $globalEnd

    # msgSecurityParameters (OCTET STRING wrapping UsmSecurityParameters)
    $securityHeader = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
    $securityEnd = $securityHeader[1] + $securityHeader[2]
    $usmHeader = Read-SnmpBerHeader -Data $Data -Offset $securityHeader[1] -Limit $securityEnd
    $usmEnd = $usmHeader[1] + $usmHeader[2]
    $engineHeader = Read-SnmpBerHeader -Data $Data -Offset $usmHeader[1] -Limit $usmEnd
    $bootsHeader = Read-SnmpBerHeader -Data $Data -Offset ($engineHeader[1] + $engineHeader[2]) -Limit $usmEnd
    $timeHeader = Read-SnmpBerHeader -Data $Data -Offset ($bootsHeader[1] + $bootsHeader[2]) -Limit $usmEnd
    $userHeader = Read-SnmpBerHeader -Data $Data -Offset ($timeHeader[1] + $timeHeader[2]) -Limit $usmEnd
    $authHeader = Read-SnmpBerHeader -Data $Data -Offset ($userHeader[1] + $userHeader[2]) -Limit $usmEnd
    $privHeader = Read-SnmpBerHeader -Data $Data -Offset ($authHeader[1] + $authHeader[2]) -Limit $usmEnd
    $position = $securityEnd

    $dataHeader = Read-SnmpBerHeader -Data $Data -Offset $position -Limit $end
    $scopedPdu = $null
    $encryptedPdu = $null
    if ($dataHeader[0] -eq 0x30) {
        $scopedPdu = ConvertFrom-SnmpScopedPdu -Data $Data -Offset $position -Limit $end
    } elseif ($dataHeader[0] -eq 0x04) {
        $encryptedPdu = Get-SnmpByteSlice -Data $Data -Start $dataHeader[1] -Length $dataHeader[2]
    } else {
        throw 'Malformed SNMPv3 message data.'
    }

    [PSCustomObject]@{
        Version      = 3
        MsgId        = [int](ConvertFrom-SnmpBerSigned -Data $Data -Start $msgIdHeader[1] -Length $msgIdHeader[2])
        Flags        = $flags
        EngineId     = Get-SnmpByteSlice -Data $Data -Start $engineHeader[1] -Length $engineHeader[2]
        EngineBoots  = ConvertFrom-SnmpBerSigned -Data $Data -Start $bootsHeader[1] -Length $bootsHeader[2]
        EngineTime   = ConvertFrom-SnmpBerSigned -Data $Data -Start $timeHeader[1] -Length $timeHeader[2]
        UserName     = [System.Text.Encoding]::UTF8.GetString($Data, $userHeader[1], $userHeader[2])
        AuthParams   = Get-SnmpByteSlice -Data $Data -Start $authHeader[1] -Length $authHeader[2]
        AuthOffset   = $authHeader[1]
        PrivParams   = Get-SnmpByteSlice -Data $Data -Start $privHeader[1] -Length $privHeader[2]
        ScopedPdu    = $scopedPdu
        EncryptedPdu = $encryptedPdu
        Pdu          = $scopedPdu?.Pdu
    }
}

function ConvertTo-SnmpCommunityMessage {
    param ([int]$Version, [string]$Community, [byte[]]$Pdu)

    $content = Join-SnmpBytes (ConvertTo-SnmpBerIntegerTlv -Value $Version) (ConvertTo-SnmpBerOctetStringTlv -Value $Community) $Pdu
    return , (ConvertTo-SnmpBerTlv -Tag 0x30 -Content $content)
}

#region SNMPv3 USM crypto

function New-SnmpHashAlgorithm {
    param ([string]$Name)

    switch ($Name) {
        'MD5' { return [System.Security.Cryptography.MD5]::Create() }
        'SHA1' { return [System.Security.Cryptography.SHA1]::Create() }
        'SHA256' { return [System.Security.Cryptography.SHA256]::Create() }
        'SHA384' { return [System.Security.Cryptography.SHA384]::Create() }
        'SHA512' { return [System.Security.Cryptography.SHA512]::Create() }
    }
    throw "Unsupported hash algorithm '$Name'"
}

function Get-SnmpHash {
    param ([string]$HashName, [byte[]]$Data)

    $hash = New-SnmpHashAlgorithm -Name $HashName
    try {
        return , $hash.ComputeHash($Data)
    }
    finally {
        $hash.Dispose()
    }
}

function Get-SnmpHmac {
    param ([string]$HashName, [byte[]]$Key, [byte[]]$Data, [int]$Length)

    $hmac = switch ($HashName) {
        'MD5' { [System.Security.Cryptography.HMACMD5]::new($Key) }
        'SHA1' { [System.Security.Cryptography.HMACSHA1]::new($Key) }
        'SHA256' { [System.Security.Cryptography.HMACSHA256]::new($Key) }
        'SHA384' { [System.Security.Cryptography.HMACSHA384]::new($Key) }
        'SHA512' { [System.Security.Cryptography.HMACSHA512]::new($Key) }
        default { throw "Unsupported HMAC algorithm '$HashName'" }
    }
    try {
        $mac = $hmac.ComputeHash($Data)
        return , (Get-SnmpByteSlice -Data $mac -Start 0 -Length $Length)
    }
    finally {
        $hmac.Dispose()
    }
}

function ConvertTo-SnmpUsmKey {
    # RFC 3414 A.2 password-to-key: hash 1 MiB of the repeated password.
    param ([string]$HashName, [byte[]]$Password)

    if ($null -eq $Password -or $Password.Length -eq 0) {
        throw 'SNMPv3 passwords cannot be empty.'
    }

    $total = 1048576
    $buffer = [byte[]]::new($total)
    $filled = [Math]::Min($Password.Length, $total)
    [Array]::Copy($Password, 0, $buffer, 0, $filled)
    while ($filled -lt $total) {
        # $filled is always a multiple of the password length here, so the copy keeps the repetition aligned.
        $count = [Math]::Min($filled, $total - $filled)
        [Array]::Copy($buffer, 0, $buffer, $filled, $count)
        $filled += $count
    }
    return , (Get-SnmpHash -HashName $HashName -Data $buffer)
}

function Get-SnmpLocalizedKey {
    # RFC 3414 A.2 key localization: H(Ku || engineID || Ku).
    param ([string]$HashName, [byte[]]$Key, [byte[]]$EngineId)

    return , (Get-SnmpHash -HashName $HashName -Data (Join-SnmpBytes $Key $EngineId $Key))
}

function Get-SnmpPrivacyKey {
    param ([string]$HashName, [byte[]]$MasterKey, [byte[]]$EngineId, [string]$PrivProtocol)

    $spec = $script:SnmpPrivProtocols[$PrivProtocol]
    $key = Get-SnmpLocalizedKey -HashName $HashName -Key $MasterKey -EngineId $EngineId
    while ($key.Length -lt $spec.KeyLength) {
        switch ($spec.Extend) {
            'Blumenthal' {
                $key = Join-SnmpBytes $key (Get-SnmpHash -HashName $HashName -Data $key)
            }
            'Reeder' {
                $extension = Get-SnmpLocalizedKey -HashName $HashName -Key (ConvertTo-SnmpUsmKey -HashName $HashName -Password $key) -EngineId $EngineId
                $key = Join-SnmpBytes $key $extension
            }
            default {
                throw "The auth protocol hash is too short to derive a $PrivProtocol privacy key."
            }
        }
    }
    return , (Get-SnmpByteSlice -Data $key -Start 0 -Length $spec.KeyLength)
}

function ConvertTo-SnmpUInt32Bytes {
    param ([uint64]$Value)

    # Note: the literal 0xFFFFFFFF is [int] -1 in PowerShell, so mask with an explicit uint64.
    $bytes = [BitConverter]::GetBytes([uint32]($Value -band [uint64][uint32]::MaxValue))
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return , $bytes
}

function Invoke-SnmpAesCfb {
    # AES-CFB128 built from an ECB block encryptor so it works on every .NET runtime PowerShell 7 ships on.
    param ([byte[]]$Key, [byte[]]$Iv, [byte[]]$Data, [switch]$Decrypt)

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.Key = $Key
        $encryptor = $aes.CreateEncryptor()
        try {
            $output = [byte[]]::new($Data.Length)
            $feedback = [byte[]]$Iv.Clone()
            $keystream = [byte[]]::new(16)
            for ($offset = 0; $offset -lt $Data.Length; $offset += 16) {
                [void]$encryptor.TransformBlock($feedback, 0, 16, $keystream, 0)
                $count = [Math]::Min(16, $Data.Length - $offset)
                for ($i = 0; $i -lt $count; $i++) {
                    $output[$offset + $i] = $Data[$offset + $i] -bxor $keystream[$i]
                }
                if ($count -eq 16) {
                    $source = if ($Decrypt) { $Data } else { $output }
                    [Array]::Copy($source, $offset, $feedback, 0, 16)
                }
            }
            return , $output
        }
        finally {
            $encryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }
}

function Invoke-SnmpDesCbc {
    param ([byte[]]$Key, [byte[]]$Iv, [byte[]]$Data, [switch]$Decrypt)

    $des = [System.Security.Cryptography.DES]::Create()
    try {
        $des.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $transform = if ($Decrypt) { $des.CreateDecryptor($Key, $Iv) } else { $des.CreateEncryptor($Key, $Iv) }
        try {
            return , $transform.TransformFinalBlock($Data, 0, $Data.Length)
        }
        finally {
            $transform.Dispose()
        }
    }
    catch [System.Security.Cryptography.CryptographicException] {
        throw "SNMPv3 DES privacy failed: $($_.Exception.Message). DES may be unavailable on this platform; use AES if the agent supports it."
    }
    finally {
        $des.Dispose()
    }
}

function Protect-SnmpScopedPdu {
    param ([hashtable]$Session, [byte[]]$Plain, [long]$Boots, [long]$Time)

    $spec = $script:SnmpPrivProtocols[$Session.PrivProtocol]
    $Session.SaltCounter = if ($Session.SaltCounter -eq [uint64]::MaxValue) { [uint64]0 } else { [uint64]($Session.SaltCounter + 1) }
    $counter = [uint64]$Session.SaltCounter

    if ($spec.Cipher -eq 'DES') {
        $salt = Join-SnmpBytes (ConvertTo-SnmpUInt32Bytes $Boots) (ConvertTo-SnmpUInt32Bytes $counter)
        $iv = [byte[]]::new(8)
        for ($i = 0; $i -lt 8; $i++) {
            $iv[$i] = $Session.PrivKey[8 + $i] -bxor $salt[$i]
        }
        $padded = $Plain
        if ($Plain.Length % 8 -ne 0) {
            $padded = [byte[]]::new($Plain.Length + (8 - $Plain.Length % 8))
            [Array]::Copy($Plain, $padded, $Plain.Length)
        }
        $cipher = Invoke-SnmpDesCbc -Key (Get-SnmpByteSlice $Session.PrivKey 0 8) -Iv $iv -Data $padded
    } else {
        $salt = Join-SnmpBytes (ConvertTo-SnmpUInt32Bytes ($counter -shr 32)) (ConvertTo-SnmpUInt32Bytes $counter)
        $iv = Join-SnmpBytes (ConvertTo-SnmpUInt32Bytes $Boots) (ConvertTo-SnmpUInt32Bytes $Time) $salt
        $cipher = Invoke-SnmpAesCfb -Key $Session.PrivKey -Iv $iv -Data $Plain
    }

    [PSCustomObject]@{
        Cipher = $cipher
        Salt   = $salt
    }
}

function Unprotect-SnmpScopedPdu {
    param ([hashtable]$Session, [byte[]]$Cipher, [byte[]]$Salt, [long]$Boots, [long]$Time)

    $spec = $script:SnmpPrivProtocols[$Session.PrivProtocol]
    if ($Salt.Length -ne 8) {
        throw 'SNMPv3 decryption failed: invalid privacy parameters.'
    }

    if ($spec.Cipher -eq 'DES') {
        if ($Cipher.Length % 8 -ne 0) {
            throw 'SNMPv3 decryption failed: DES ciphertext is not block aligned.'
        }
        $iv = [byte[]]::new(8)
        for ($i = 0; $i -lt 8; $i++) {
            $iv[$i] = $Session.PrivKey[8 + $i] -bxor $Salt[$i]
        }
        return , (Invoke-SnmpDesCbc -Key (Get-SnmpByteSlice $Session.PrivKey 0 8) -Iv $iv -Data $Cipher -Decrypt)
    }

    $iv = Join-SnmpBytes (ConvertTo-SnmpUInt32Bytes $Boots) (ConvertTo-SnmpUInt32Bytes $Time) $Salt
    return , (Invoke-SnmpAesCfb -Key $Session.PrivKey -Iv $iv -Data $Cipher -Decrypt)
}

function Get-SnmpEngineTime {
    param ([hashtable]$Session)

    return [long]($Session.EngineTime + [Math]::Floor($Session.Clock.Elapsed.TotalSeconds - $Session.EngineTimeSyncedAt))
}

function ConvertTo-SnmpV3Message {
    param (
        [hashtable]$Session,
        [int]$MsgId,
        [byte[]]$Pdu,
        [string]$SecurityLevel,
        [bool]$Reportable = $true,
        [switch]$Discovery,
        [string]$UserName
    )

    if (-not $SecurityLevel) {
        $SecurityLevel = $Session.SecurityLevel
    }
    if (-not $PSBoundParameters.ContainsKey('UserName')) {
        $UserName = $Session.UserName
    }

    if ($Discovery) {
        $engineId = [byte[]]::new(0)
        $boots = 0
        $time = 0
        $UserName = ''
        $SecurityLevel = 'NoAuthNoPriv'
    } else {
        $engineId = $Session.EngineId
        $boots = $Session.EngineBoots
        $time = Get-SnmpEngineTime -Session $Session
    }

    $useAuth = $SecurityLevel -ne 'NoAuthNoPriv'
    $usePriv = $SecurityLevel -eq 'AuthPriv'
    $flags = 0
    if ($useAuth) { $flags = $flags -bor 0x01 }
    if ($usePriv) { $flags = $flags -bor 0x02 }
    if ($Reportable) { $flags = $flags -bor 0x04 }

    $scoped = ConvertTo-SnmpBerTlv -Tag 0x30 -Content (Join-SnmpBytes `
        (ConvertTo-SnmpBerOctetStringTlv -Value $engineId) `
        (ConvertTo-SnmpBerOctetStringTlv -Value ($Session.Context ?? '')) `
        $Pdu)

    $privParams = [byte[]]::new(0)
    if ($usePriv) {
        $protected = Protect-SnmpScopedPdu -Session $Session -Plain $scoped -Boots $boots -Time $time
        $msgData = ConvertTo-SnmpBerOctetStringTlv -Value $protected.Cipher
        $privParams = $protected.Salt
    } else {
        $msgData = $scoped
    }

    $authSpec = $script:SnmpAuthProtocols[$Session.AuthProtocol ?? 'SHA']
    $macLength = if ($useAuth) { $authSpec.MacLength } else { 0 }
    $authField = ConvertTo-SnmpBerOctetStringTlv -Value ([byte[]]::new($macLength))
    $beforeAuth = Join-SnmpBytes `
        (ConvertTo-SnmpBerOctetStringTlv -Value $engineId) `
        (ConvertTo-SnmpBerIntegerTlv -Value $boots) `
        (ConvertTo-SnmpBerIntegerTlv -Value $time) `
        (ConvertTo-SnmpBerOctetStringTlv -Value $UserName)
    $usmContent = Join-SnmpBytes $beforeAuth $authField (ConvertTo-SnmpBerOctetStringTlv -Value $privParams)
    $usm = ConvertTo-SnmpBerTlv -Tag 0x30 -Content $usmContent
    $securityParams = ConvertTo-SnmpBerOctetStringTlv -Value $usm

    $globalData = ConvertTo-SnmpBerTlv -Tag 0x30 -Content (Join-SnmpBytes `
        (ConvertTo-SnmpBerIntegerTlv -Value $MsgId) `
        (ConvertTo-SnmpBerIntegerTlv -Value 65507) `
        (ConvertTo-SnmpBerOctetStringTlv -Value ([byte[]]@([byte]$flags))) `
        (ConvertTo-SnmpBerIntegerTlv -Value 3))

    $message = ConvertTo-SnmpBerTlv -Tag 0x30 -Content (Join-SnmpBytes `
        (ConvertTo-SnmpBerIntegerTlv -Value 3) $globalData $securityParams $msgData)

    if ($useAuth) {
        # Locate the zeroed msgAuthenticationParameters by walking back from the end of the message.
        $offset = $message.Length - $msgData.Length - $securityParams.Length +
            ($securityParams.Length - $usm.Length) +
            ($usm.Length - $usmContent.Length) +
            $beforeAuth.Length +
            ($authField.Length - $macLength)
        $mac = Get-SnmpHmac -HashName $authSpec.Hash -Key $Session.AuthKey -Data $message -Length $macLength
        [Array]::Copy($mac, 0, $message, $offset, $macLength)
    }

    return , $message
}

function Resolve-SnmpV3Message {
    # Verifies authentication and decrypts an incoming v3 message; returns the scoped PDU.
    param ([hashtable]$Session, [byte[]]$Data, $Message)

    if ($Message.Flags -band 0x01) {
        if ($null -eq $Session.AuthKey) {
            throw 'Received an authenticated SNMPv3 message but no authentication key is configured.'
        }
        $authSpec = $script:SnmpAuthProtocols[$Session.AuthProtocol]
        if ($Message.AuthParams.Length -ne $authSpec.MacLength) {
            throw 'SNMPv3 authentication failed: unexpected digest length.'
        }
        $copy = [byte[]]$Data.Clone()
        [Array]::Clear($copy, $Message.AuthOffset, $Message.AuthParams.Length)
        $expected = Get-SnmpHmac -HashName $authSpec.Hash -Key $Session.AuthKey -Data $copy -Length $authSpec.MacLength
        if ([BitConverter]::ToString($expected) -ne [BitConverter]::ToString($Message.AuthParams)) {
            throw 'SNMPv3 authentication failed: message digest mismatch.'
        }
    }

    if ($Message.Flags -band 0x02) {
        if ($null -eq $Session.PrivKey) {
            throw 'Received an encrypted SNMPv3 message but no privacy key is configured.'
        }
        if ($null -eq $Message.EncryptedPdu) {
            throw 'SNMPv3 message is flagged as encrypted but carries a plaintext PDU.'
        }
        $plain = Unprotect-SnmpScopedPdu -Session $Session -Cipher $Message.EncryptedPdu -Salt $Message.PrivParams -Boots $Message.EngineBoots -Time $Message.EngineTime
        return ConvertFrom-SnmpScopedPdu -Data $plain -Offset 0 -Limit $plain.Length
    }

    if ($null -eq $Message.ScopedPdu) {
        throw 'SNMPv3 message is encrypted but privacy is not configured.'
    }
    return $Message.ScopedPdu
}

function Set-SnmpV3Engine {
    param ([hashtable]$Session, [byte[]]$EngineId, [long]$Boots, [long]$Time)

    $changed = $null -eq $Session.EngineId -or
        [BitConverter]::ToString($Session.EngineId) -ne [BitConverter]::ToString($EngineId)

    $Session.EngineId = $EngineId
    $Session.EngineBoots = $Boots
    $Session.EngineTime = $Time
    $Session.EngineTimeSyncedAt = $Session.Clock.Elapsed.TotalSeconds

    if ($changed -and $EngineId.Length -gt 0) {
        if ($Session.AuthMasterKey) {
            $hashName = $script:SnmpAuthProtocols[$Session.AuthProtocol].Hash
            $Session.AuthKey = Get-SnmpLocalizedKey -HashName $hashName -Key $Session.AuthMasterKey -EngineId $EngineId
            if ($Session.PrivMasterKey) {
                $Session.PrivKey = Get-SnmpPrivacyKey -HashName $hashName -MasterKey $Session.PrivMasterKey -EngineId $EngineId -PrivProtocol $Session.PrivProtocol
            }
        }
    }
}

#endregion SNMPv3 USM crypto

#region SNMP transport and request engine

function ConvertTo-SnmpPasswordBytes {
    param ($Value)

    if ($null -eq $Value) {
        return $null
    }
    $plain = if ($Value -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $Value).Password
    } elseif ($Value -is [System.Management.Automation.PSCredential]) {
        $Value.GetNetworkCredential().Password
    } else {
        [string]$Value
    }
    if ([string]::IsNullOrEmpty($plain)) {
        return $null
    }
    return , [System.Text.Encoding]::UTF8.GetBytes($plain)
}

function New-SnmpSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [string]$Community = 'public',
        [string]$Version,
        [switch]$V1,
        [switch]$V2c,
        [switch]$V3,
        [string]$UserName,
        [string]$AuthProtocol,
        $AuthPassword,
        [string]$PrivProtocol,
        $PrivPassword,
        [string]$Context = '',
        [int]$Port = 161,
        [int]$TimeoutMs = 2000,
        [int]$Retries = 2
    )

    $switches = @()
    if ($V1) { $switches += '1' }
    if ($V2c) { $switches += '2c' }
    if ($V3) { $switches += '3' }
    if ($switches.Count -gt 1) {
        throw 'Specify only one of -V1, -V2c, or -V3.'
    }
    if ($switches.Count -eq 1) {
        if ($Version -and ($Version -replace '^2$', '2c') -ne $switches[0]) {
            throw "-Version $Version conflicts with -V$($switches[0])."
        }
        $Version = $switches[0]
    }
    if (-not $Version) {
        $Version = if ($UserName) { '3' } else { '2c' }
    }

    $versionNumber = switch ($Version) {
        '1' { 0 }
        '2' { 1 }
        '2c' { 1 }
        '3' { 3 }
        default { throw "Unsupported SNMP version '$Version'." }
    }

    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($ComputerName, [ref]$address)) {
        $candidates = @([System.Net.Dns]::GetHostAddresses($ComputerName))
        $address = ($candidates | Where-Object AddressFamily -eq ([System.Net.Sockets.AddressFamily]::InterNetwork) | Select-Object -First 1) ?? $candidates[0]
        if ($null -eq $address) {
            throw "Could not resolve '$ComputerName'."
        }
    }

    $session = @{
        ComputerName   = $ComputerName
        Endpoint       = [System.Net.IPEndPoint]::new($address, $Port)
        Version        = $versionNumber
        VersionLabel   = @{ 0 = 'v1'; 1 = 'v2c'; 3 = 'v3' }[$versionNumber]
        Community      = $Community
        Context        = $Context
        TimeoutMs      = $TimeoutMs
        Retries        = $Retries
        Window         = 8
        MaxVarbinds    = 24
        MaxRepetitions = 25
        NextId         = [System.Random]::new().Next(1, 0x3FFFFFFF)
        Clock          = [System.Diagnostics.Stopwatch]::StartNew()
        Socket         = $null
    }

    if ($versionNumber -eq 3) {
        if (-not $UserName) {
            throw 'SNMPv3 requires -UserName.'
        }
        $authBytes = ConvertTo-SnmpPasswordBytes $AuthPassword
        $privBytes = ConvertTo-SnmpPasswordBytes $PrivPassword
        if ($privBytes -and -not $authBytes) {
            throw 'SNMPv3 privacy (-PrivPassword) requires authentication (-AuthPassword).'
        }
        if ($AuthProtocol -and -not $authBytes) {
            throw '-AuthProtocol was given without -AuthPassword.'
        }
        if ($PrivProtocol -and -not $privBytes) {
            throw '-PrivProtocol was given without -PrivPassword.'
        }

        $session.UserName = $UserName
        $session.SecurityLevel = 'NoAuthNoPriv'
        $session.EngineId = $null
        $session.EngineBoots = 0
        $session.EngineTime = 0
        $session.EngineTimeSyncedAt = 0.0
        $saltSeed = [byte[]]::new(8)
        [System.Random]::new().NextBytes($saltSeed)
        $session.SaltCounter = [BitConverter]::ToUInt64($saltSeed, 0)

        if ($authBytes) {
            # [string] parameters default to '' rather than $null, so ?? would never apply here.
            $authName = $(if ($AuthProtocol) { $AuthProtocol } else { 'SHA' }).ToUpperInvariant() -replace '^SHA1$', 'SHA'
            if (-not $script:SnmpAuthProtocols.ContainsKey($authName)) {
                throw "Unsupported SNMPv3 auth protocol '$AuthProtocol'."
            }
            if ($authBytes.Length -lt 8) {
                Write-Warning 'SNMPv3 auth password is shorter than 8 characters; most agents will reject it.'
            }
            $session.AuthProtocol = $authName
            $session.AuthMasterKey = ConvertTo-SnmpUsmKey -HashName $script:SnmpAuthProtocols[$authName].Hash -Password $authBytes
            $session.SecurityLevel = 'AuthNoPriv'
        }
        if ($privBytes) {
            $privName = $(if ($PrivProtocol) { $PrivProtocol } else { 'AES' }).ToUpperInvariant() -replace '^AES128$', 'AES'
            if (-not $script:SnmpPrivProtocols.ContainsKey($privName)) {
                throw "Unsupported SNMPv3 privacy protocol '$PrivProtocol'."
            }
            if ($privBytes.Length -lt 8) {
                Write-Warning 'SNMPv3 privacy password is shorter than 8 characters; most agents will reject it.'
            }
            $session.PrivProtocol = $privName
            $session.PrivMasterKey = ConvertTo-SnmpUsmKey -HashName $script:SnmpAuthProtocols[$session.AuthProtocol].Hash -Password $privBytes
            $session.SecurityLevel = 'AuthPriv'
        }
        $session.VersionLabel = "v3 $($session.SecurityLevel)"
    }

    $socket = [System.Net.Sockets.UdpClient]::new($address.AddressFamily)
    if ($IsWindows) {
        # Stop ICMP port-unreachable from surfacing as ConnectionReset on later receives (SIO_UDP_CONNRESET).
        try {
            [void]$socket.Client.IOControl(-1744830452, [byte[]]@(0, 0, 0, 0), $null)
        }
        catch {
        }
    }
    $session.Socket = $socket
    return $session
}

function Close-SnmpSession {
    param ([hashtable]$Session)

    if ($null -ne $Session -and $null -ne $Session.Socket) {
        $Session.Socket.Dispose()
        $Session.Socket = $null
    }
}

function New-SnmpRequestId {
    param ([hashtable]$Session)

    $Session.NextId = if ($Session.NextId -ge 0x7FFFFFF0) { 1 } else { $Session.NextId + 1 }
    return $Session.NextId
}

function Send-SnmpDatagram {
    param ([hashtable]$Session, [byte[]]$Bytes)

    [void]$Session.Socket.Send($Bytes, $Bytes.Length, $Session.Endpoint)
}

function Receive-SnmpDatagram {
    param ([hashtable]$Session, [long]$TimeoutMs)

    $deadline = $Session.Clock.ElapsedMilliseconds + [Math]::Max(0, $TimeoutMs)
    $anyAddress = if ($Session.Endpoint.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        [System.Net.IPAddress]::IPv6Any
    } else {
        [System.Net.IPAddress]::Any
    }

    while ($true) {
        $remaining = [Math]::Max(0, $deadline - $Session.Clock.ElapsedMilliseconds)
        if (-not $Session.Socket.Client.Poll([int]($remaining * 1000), [System.Net.Sockets.SelectMode]::SelectRead)) {
            return $null
        }
        try {
            $remote = [System.Net.IPEndPoint]::new($anyAddress, 0)
            return , $Session.Socket.Receive([ref]$remote)
        }
        catch [System.Net.Sockets.SocketException] {
            if ($remaining -le 0) {
                return $null
            }
        }
    }
}

function ConvertTo-SnmpRequestMessage {
    param ([hashtable]$Session, $Request, [int]$Id)

    $errorStatus = 0
    $errorIndex = 0
    if ($Request.PduType -eq $script:SnmpPduTypes.GetBulk) {
        $errorStatus = $Request.NonRepeaters ?? 0
        $errorIndex = $Request.MaxRepetitions ?? $Session.MaxRepetitions
    }
    # Polls repeat the same OID batches, so cache their encoded varbind lists; only the
    # request ID (and, for v3, the security wrapper) changes between polls.
    if ($null -eq $Session.VarbindCache) {
        $Session.VarbindCache = @{}
    }
    $cacheKey = @($Request.Oids) -join ' '
    $varbindList = $Session.VarbindCache[$cacheKey]
    if ($null -eq $varbindList) {
        if ($Session.VarbindCache.Count -ge 512) {
            $Session.VarbindCache.Clear()
        }
        $varbindList = ConvertTo-SnmpVarbindListTlv -Varbinds @($Request.Oids)
        $Session.VarbindCache[$cacheKey] = $varbindList
    }
    $pdu = ConvertTo-SnmpPduBytes -PduType $Request.PduType -RequestId $Id -ErrorStatus $errorStatus -ErrorIndex $errorIndex -VarbindList $varbindList

    if ($Session.Version -eq 3) {
        return , (ConvertTo-SnmpV3Message -Session $Session -MsgId $Id -Pdu $pdu)
    }
    return , (ConvertTo-SnmpCommunityMessage -Version $Session.Version -Community $Session.Community -Pdu $pdu)
}

function ConvertFrom-SnmpResponse {
    param ([hashtable]$Session, [byte[]]$Data)

    $message = ConvertFrom-SnmpMessage -Data $Data
    if ($message.Version -ne $Session.Version) {
        return $null
    }
    if ($Session.Version -ne 3) {
        return [PSCustomObject]@{ Id = $message.MsgId; Pdu = $message.Pdu; Message = $message }
    }
    $scoped = Resolve-SnmpV3Message -Session $Session -Data $Data -Message $message
    return [PSCustomObject]@{ Id = $message.MsgId; Pdu = $scoped.Pdu; Message = $message }
}

function Resolve-SnmpReport {
    # Handles a v3 Report PDU. Returns when the request should be resent; throws otherwise.
    param ([hashtable]$Session, $Response)

    $varbind = @($Response.Pdu.Varbinds)[0]
    $report = if ($varbind) { $script:SnmpUsmReports[$varbind.Oid] } else { $null }
    $target = $Session.ComputerName

    switch ($report) {
        'notInTimeWindows' {
            Set-SnmpV3Engine -Session $Session -EngineId $Response.Message.EngineId -Boots $Response.Message.EngineBoots -Time $Response.Message.EngineTime
            return
        }
        'unknownEngineIDs' {
            Set-SnmpV3Engine -Session $Session -EngineId $Response.Message.EngineId -Boots $Response.Message.EngineBoots -Time $Response.Message.EngineTime
            return
        }
        'unknownUserNames' { throw "SNMPv3 user '$($Session.UserName)' is not known to $target." }
        'wrongDigests' { throw "SNMPv3 authentication failed on $target (wrong auth password or auth protocol)." }
        'decryptionErrors' { throw "SNMPv3 decryption failed on $target (wrong privacy password or privacy protocol)." }
        'unsupportedSecLevels' { throw "$target does not allow security level $($Session.SecurityLevel) for user '$($Session.UserName)'." }
    }
    throw "SNMP agent $target returned report $($varbind.Oid)."
}

function Initialize-SnmpV3Engine {
    # RFC 3414 4: discover the authoritative engine ID (plus boots/time) with an empty noAuthNoPriv request.
    param ([hashtable]$Session)

    for ($attempt = 0; $attempt -le $Session.Retries; $attempt++) {
        $id = New-SnmpRequestId -Session $Session
        $pdu = ConvertTo-SnmpPduBytes -PduType $script:SnmpPduTypes.Get -RequestId $id -Varbinds @()
        Send-SnmpDatagram -Session $Session -Bytes (ConvertTo-SnmpV3Message -Session $Session -MsgId $id -Pdu $pdu -Discovery)

        $deadline = $Session.Clock.ElapsedMilliseconds + $Session.TimeoutMs
        while ($Session.Clock.ElapsedMilliseconds -lt $deadline) {
            $data = Receive-SnmpDatagram -Session $Session -TimeoutMs ($deadline - $Session.Clock.ElapsedMilliseconds)
            if ($null -eq $data) {
                break
            }
            try {
                $message = ConvertFrom-SnmpMessage -Data $data
            }
            catch {
                Write-Verbose "Ignoring malformed SNMP datagram: $($_.Exception.Message)"
                continue
            }
            if ($message.Version -eq 3 -and $message.MsgId -eq $id -and $message.EngineId.Length -gt 0) {
                Set-SnmpV3Engine -Session $Session -EngineId $message.EngineId -Boots $message.EngineBoots -Time $message.EngineTime
                return
            }
        }
    }
    throw "No SNMPv3 response from $($Session.ComputerName):$($Session.Endpoint.Port) (engine discovery timed out)."
}

function Invoke-SnmpExchange {
    # Sends a set of requests with up to $Session.Window outstanding at once and returns the
    # response PDUs in request order. Each request is @{ PduType; Oids; [NonRepeaters]; [MaxRepetitions] }.
    param ([hashtable]$Session, [object[]]$Requests)

    if ($Session.Version -eq 3 -and $null -eq $Session.EngineId) {
        Initialize-SnmpV3Engine -Session $Session
    }

    $count = $Requests.Count
    $results = [object[]]::new($count)
    $inflight = @{}
    $next = 0
    $completed = 0

    while ($completed -lt $count) {
        while ($inflight.Count -lt $Session.Window -and $next -lt $count) {
            $id = New-SnmpRequestId -Session $Session
            Send-SnmpDatagram -Session $Session -Bytes (ConvertTo-SnmpRequestMessage -Session $Session -Request $Requests[$next] -Id $id)
            $inflight[$id] = @{
                Index    = $next
                Attempts = 1
                Reports  = 0
                Deadline = $Session.Clock.ElapsedMilliseconds + $Session.TimeoutMs
            }
            $next++
        }

        $nearest = ($inflight.Values | Measure-Object -Property Deadline -Minimum).Minimum
        $data = Receive-SnmpDatagram -Session $Session -TimeoutMs ($nearest - $Session.Clock.ElapsedMilliseconds)
        if ($null -ne $data) {
            $response = $null
            try {
                $response = ConvertFrom-SnmpResponse -Session $Session -Data $data
            }
            catch {
                Write-Verbose "Ignoring SNMP datagram: $($_.Exception.Message)"
            }

            if ($null -ne $response -and $inflight.ContainsKey($response.Id)) {
                $entry = $inflight[$response.Id]
                if ($response.Pdu.PduType -eq $script:SnmpPduTypes.Report) {
                    Resolve-SnmpReport -Session $Session -Response $response
                    $entry.Reports++
                    if ($entry.Reports -gt 3) {
                        throw "SNMPv3 agent $($Session.ComputerName) keeps rejecting requests (time window / engine ID never converged)."
                    }
                    Send-SnmpDatagram -Session $Session -Bytes (ConvertTo-SnmpRequestMessage -Session $Session -Request $Requests[$entry.Index] -Id $response.Id)
                    $entry.Deadline = $Session.Clock.ElapsedMilliseconds + $Session.TimeoutMs
                } else {
                    $results[$entry.Index] = $response.Pdu
                    $inflight.Remove($response.Id)
                    $completed++
                }
            }
        }

        $now = $Session.Clock.ElapsedMilliseconds
        foreach ($id in @($inflight.Keys)) {
            $entry = $inflight[$id]
            if ($now -ge $entry.Deadline) {
                if ($entry.Attempts -gt $Session.Retries) {
                    throw "No SNMP response from $($Session.ComputerName):$($Session.Endpoint.Port) after $($entry.Attempts) attempts (check reachability, version, and credentials)."
                }
                Send-SnmpDatagram -Session $Session -Bytes (ConvertTo-SnmpRequestMessage -Session $Session -Request $Requests[$entry.Index] -Id $id)
                $entry.Attempts++
                $entry.Deadline = $now + $Session.TimeoutMs
            }
        }
    }

    return , $results
}

function Get-SnmpErrorName {
    param ([int]$Status)

    if ($Status -ge 0 -and $Status -lt $script:SnmpErrorNames.Count) {
        return $script:SnmpErrorNames[$Status]
    }
    return "error $Status"
}

function Invoke-SnmpGet {
    # Fetches many OIDs, batching varbinds per request. Returns a hashtable of OID -> varbind.
    param ([hashtable]$Session, [string[]]$Oid)

    $results = @{}
    $queue = [System.Collections.Generic.List[object]]::new()
    $size = [Math]::Max(1, $Session.MaxVarbinds)
    for ($i = 0; $i -lt $Oid.Count; $i += $size) {
        $last = [Math]::Min($i + $size, $Oid.Count) - 1
        $queue.Add([string[]]@($Oid[$i..$last]))
    }

    while ($queue.Count -gt 0) {
        $batches = $queue.ToArray()
        $queue.Clear()
        $requests = foreach ($batch in $batches) {
            @{ PduType = $script:SnmpPduTypes.Get; Oids = $batch }
        }
        $responses = Invoke-SnmpExchange -Session $Session -Requests @($requests)

        for ($i = 0; $i -lt $batches.Count; $i++) {
            $batch = $batches[$i]
            $pdu = $responses[$i]
            switch ($pdu.ErrorStatus) {
                0 {
                    foreach ($varbind in $pdu.Varbinds) {
                        $results[$varbind.Oid] = $varbind
                    }
                }
                1 {
                    if ($batch.Count -le 1) {
                        throw "SNMP agent $($Session.ComputerName) reported tooBig for a single varbind."
                    }
                    $half = [int][Math]::Floor($batch.Count / 2)
                    $Session.MaxVarbinds = [Math]::Max(1, $half)
                    $queue.Add([string[]]@($batch[0..($half - 1)]))
                    $queue.Add([string[]]@($batch[$half..($batch.Count - 1)]))
                }
                2 {
                    # SNMPv1 fails the whole request for one missing OID; drop it and retry the rest.
                    $bad = $pdu.ErrorIndex - 1
                    if ($bad -lt 0 -or $bad -ge $batch.Count) {
                        throw "SNMP agent $($Session.ComputerName) returned noSuchName without a valid error index."
                    }
                    $results[$batch[$bad]] = [PSCustomObject]@{ Oid = $batch[$bad]; Type = 'NoSuchName'; Value = $null }
                    $rest = @(for ($j = 0; $j -lt $batch.Count; $j++) { if ($j -ne $bad) { $batch[$j] } })
                    if ($rest.Count -gt 0) {
                        $queue.Add([string[]]$rest)
                    }
                }
                default {
                    throw "SNMP agent $($Session.ComputerName) returned error '$(Get-SnmpErrorName $pdu.ErrorStatus)'."
                }
            }
        }
    }

    return $results
}

function Invoke-SnmpWalk {
    param ([hashtable]$Session, [string]$RootOid)

    $root = $RootOid.TrimStart('.')
    $prefix = "$root."
    $results = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $current = $root

    while ($true) {
        $request = if ($Session.Version -eq 0) {
            @{ PduType = $script:SnmpPduTypes.GetNext; Oids = @($current) }
        } else {
            @{ PduType = $script:SnmpPduTypes.GetBulk; Oids = @($current); NonRepeaters = 0; MaxRepetitions = $Session.MaxRepetitions }
        }
        $pdu = (Invoke-SnmpExchange -Session $Session -Requests @($request))[0]

        if ($pdu.ErrorStatus -eq 2) {
            break
        }
        if ($pdu.ErrorStatus -eq 1 -and $Session.Version -ne 0 -and $Session.MaxRepetitions -gt 1) {
            $Session.MaxRepetitions = [Math]::Max(1, [int][Math]::Floor($Session.MaxRepetitions / 2))
            continue
        }
        if ($pdu.ErrorStatus -ne 0) {
            throw "SNMP agent $($Session.ComputerName) returned error '$(Get-SnmpErrorName $pdu.ErrorStatus)' walking $root."
        }
        if ($pdu.Varbinds.Count -eq 0) {
            break
        }

        $finished = $false
        foreach ($varbind in $pdu.Varbinds) {
            if ($varbind.Type -in 'EndOfMibView', 'NoSuchObject', 'NoSuchInstance' -or
                -not $varbind.Oid.StartsWith($prefix, [System.StringComparison]::Ordinal) -or
                -not $seen.Add($varbind.Oid)) {
                $finished = $true
                break
            }
            $results.Add($varbind)
            $current = $varbind.Oid
        }
        if ($finished) {
            break
        }
    }

    return , $results.ToArray()
}

#endregion SNMP transport and request engine

#endregion SNMP protocol

#region Interface counters ----------------------------------------------------

$script:IfMib = @{
    SysDescr     = '1.3.6.1.2.1.1.1.0'
    SysUpTime    = '1.3.6.1.2.1.1.3.0'
    SysName      = '1.3.6.1.2.1.1.5.0'
    IfDescr      = '1.3.6.1.2.1.2.2.1.2'
    IfType       = '1.3.6.1.2.1.2.2.1.3'
    IfSpeed      = '1.3.6.1.2.1.2.2.1.5'
    IfAdmin      = '1.3.6.1.2.1.2.2.1.7'
    IfOper       = '1.3.6.1.2.1.2.2.1.8'
    InOctets     = '1.3.6.1.2.1.2.2.1.10'
    InDiscards   = '1.3.6.1.2.1.2.2.1.13'
    InErrors     = '1.3.6.1.2.1.2.2.1.14'
    OutOctets    = '1.3.6.1.2.1.2.2.1.16'
    OutDiscards  = '1.3.6.1.2.1.2.2.1.19'
    OutErrors    = '1.3.6.1.2.1.2.2.1.20'
    IfName       = '1.3.6.1.2.1.31.1.1.1.1'
    HCInOctets   = '1.3.6.1.2.1.31.1.1.1.6'
    HCOutOctets  = '1.3.6.1.2.1.31.1.1.1.10'
    IfHighSpeed  = '1.3.6.1.2.1.31.1.1.1.15'
    IfAlias      = '1.3.6.1.2.1.31.1.1.1.18'
}

$script:IfStatusNames = @{
    1 = 'up'; 2 = 'down'; 3 = 'testing'; 4 = 'unknown'; 5 = 'dormant'; 6 = 'notPresent'; 7 = 'lowerLayerDown'
}

$script:IfTypeNames = @{
    1 = 'other'; 6 = 'ethernetCsmacd'; 23 = 'ppp'; 24 = 'softwareLoopback'; 53 = 'propVirtual'; 71 = 'ieee80211'
    117 = 'gigabitEthernet'; 131 = 'tunnel'; 135 = 'l2vlan'; 136 = 'l3ipvlan'; 161 = 'ieee8023adLag'; 209 = 'bridge'
}

$script:SnmpSessionParameterNames = @(
    'ComputerName', 'Community', 'Version', 'V1', 'V2c', 'V3', 'UserName', 'AuthProtocol', 'AuthPassword',
    'PrivProtocol', 'PrivPassword', 'Context', 'Port', 'TimeoutMs', 'Retries'
)

function Get-SnmpSessionParameter {
    param ([hashtable]$BoundParameters)

    $selected = @{}
    foreach ($name in $script:SnmpSessionParameterNames) {
        if ($BoundParameters.ContainsKey($name)) {
            $selected[$name] = $BoundParameters[$name]
        }
    }
    return $selected
}

function Get-SnmpColumn {
    # Walks a table column and returns a hashtable of ifIndex -> value.
    param ([hashtable]$Session, [string]$ColumnOid)

    $map = @{}
    foreach ($varbind in (Invoke-SnmpWalk -Session $Session -RootOid $ColumnOid)) {
        $index = 0
        if ([int]::TryParse($varbind.Oid.Substring($ColumnOid.Length + 1), [ref]$index)) {
            $map[$index] = $varbind.Value
        }
    }
    return $map
}

function Get-SnmpInterfaceInventory {
    param ([hashtable]$Session)

    $system = Invoke-SnmpGet -Session $Session -Oid @($script:IfMib.SysDescr, $script:IfMib.SysUpTime, $script:IfMib.SysName)

    $descr = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfDescr
    $type = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfType
    $speed = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfSpeed
    $admin = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfAdmin
    $oper = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfOper
    $name = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfName
    $alias = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfAlias
    $highSpeed = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.IfHighSpeed

    # Counter64 needs v2c or v3; prefer the 64-bit counters wherever the agent has them.
    $hcIn = if ($Session.Version -ne 0) { Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.HCInOctets } else { @{} }
    $in32 = @{}
    $allIndexes = @($descr.Keys) + @($name.Keys) | Sort-Object -Unique
    if (@($allIndexes | Where-Object { -not $hcIn.ContainsKey($_) }).Count -gt 0) {
        $in32 = Get-SnmpColumn -Session $Session -ColumnOid $script:IfMib.InOctets
    }

    $interfaces = foreach ($index in $allIndexes) {
        $highCapacity = $hcIn.ContainsKey($index)
        if (-not $highCapacity -and -not $in32.ContainsKey($index)) {
            continue
        }

        $description = ConvertTo-SnmpDisplayString $descr[$index]
        $ifName = ConvertTo-SnmpDisplayString $name[$index]
        $speedBps = if ($highSpeed[$index] -gt 0) {
            [double]$highSpeed[$index] * 1e6
        } elseif ($null -ne $speed[$index]) {
            [double]$speed[$index]
        } else {
            0.0
        }
        $typeNumber = [int]($type[$index] ?? 0)

        [PSCustomObject]@{
            Index        = [int]$index
            Name         = if ($ifName) { $ifName } elseif ($description) { $description } else { "if$index" }
            Description  = $description
            Alias        = ConvertTo-SnmpDisplayString $alias[$index]
            Type         = $script:IfTypeNames[$typeNumber] ?? [string]$typeNumber
            TypeId       = $typeNumber
            SpeedBps     = $speedBps
            AdminStatus  = [int]($admin[$index] ?? 0)
            OperStatus   = [int]($oper[$index] ?? 0)
            HighCapacity = $highCapacity
        }
    }

    [PSCustomObject]@{
        SysName    = ConvertTo-SnmpDisplayString $system[$script:IfMib.SysName].Value
        SysDescr   = ConvertTo-SnmpDisplayString $system[$script:IfMib.SysDescr].Value
        SysUpTime  = $system[$script:IfMib.SysUpTime].Value
        Interfaces = @($interfaces)
    }
}

function Get-SnmpNumericValue {
    param ($Varbind)

    if ($null -eq $Varbind -or $Varbind.Type -notin 'Counter32', 'Counter64', 'Gauge32', 'TimeTicks', 'Integer') {
        return $null
    }
    return $Varbind.Value
}

function Get-SnmpInterfaceSample {
    param ([hashtable]$Session, [object[]]$Interfaces)

    $oids = [System.Collections.Generic.List[string]]::new()
    $oids.Add($script:IfMib.SysUpTime)
    foreach ($interface in $Interfaces) {
        $i = $interface.Index
        if ($interface.HighCapacity) {
            $oids.Add("$($script:IfMib.HCInOctets).$i")
            $oids.Add("$($script:IfMib.HCOutOctets).$i")
        } else {
            $oids.Add("$($script:IfMib.InOctets).$i")
            $oids.Add("$($script:IfMib.OutOctets).$i")
        }
        $oids.Add("$($script:IfMib.InErrors).$i")
        $oids.Add("$($script:IfMib.OutErrors).$i")
        $oids.Add("$($script:IfMib.InDiscards).$i")
        $oids.Add("$($script:IfMib.OutDiscards).$i")
        $oids.Add("$($script:IfMib.IfOper).$i")
    }

    $values = Invoke-SnmpGet -Session $Session -Oid $oids.ToArray()
    $time = $Session.Clock.Elapsed.TotalSeconds

    $counters = @{}
    foreach ($interface in $Interfaces) {
        $i = $interface.Index
        $inOid = if ($interface.HighCapacity) { "$($script:IfMib.HCInOctets).$i" } else { "$($script:IfMib.InOctets).$i" }
        $outOid = if ($interface.HighCapacity) { "$($script:IfMib.HCOutOctets).$i" } else { "$($script:IfMib.OutOctets).$i" }
        $counters[$i] = [PSCustomObject]@{
            InOctets    = Get-SnmpNumericValue $values[$inOid]
            OutOctets   = Get-SnmpNumericValue $values[$outOid]
            InErrors    = Get-SnmpNumericValue $values["$($script:IfMib.InErrors).$i"]
            OutErrors   = Get-SnmpNumericValue $values["$($script:IfMib.OutErrors).$i"]
            InDiscards  = Get-SnmpNumericValue $values["$($script:IfMib.InDiscards).$i"]
            OutDiscards = Get-SnmpNumericValue $values["$($script:IfMib.OutDiscards).$i"]
            OperStatus  = Get-SnmpNumericValue $values["$($script:IfMib.IfOper).$i"]
        }
    }

    [PSCustomObject]@{
        Time     = $time
        UpTime   = Get-SnmpNumericValue $values[$script:IfMib.SysUpTime]
        Counters = $counters
    }
}

function Get-SnmpCounterDelta {
    # Difference between two counter readings, handling Counter32 wrap. A Counter64 that
    # goes backwards is treated as a discontinuity (agent/interface reset) and yields $null.
    param ($Previous, $Current, [switch]$Counter64)

    if ($null -eq $Previous -or $null -eq $Current) {
        return $null
    }
    $p = [uint64]$Previous
    $c = [uint64]$Current
    if ($c -ge $p) {
        return [uint64]($c - $p)
    }
    if ($Counter64 -or $p -gt [uint32]::MaxValue) {
        return $null
    }
    return [uint64]([decimal]4294967296 - $p + $c)
}

function Test-SnmpInterfaceMatch {
    param ($Interface, [string[]]$Pattern)

    if (-not $Pattern) {
        return $true
    }
    foreach ($item in $Pattern) {
        if ([string]$Interface.Index -eq $item -or
            $Interface.Name -like $item -or
            $Interface.Description -like $item -or
            ($Interface.Alias -and $Interface.Alias -like $item)) {
            return $true
        }
    }
    return $false
}

function Format-SnmpBitRate {
    param ([double]$BitsPerSecond, [switch]$Compact)

    $long = 'bps', 'kbps', 'Mbps', 'Gbps', 'Tbps'
    $short = '', 'k', 'M', 'G', 'T'
    $value = [Math]::Max(0.0, $BitsPerSecond)
    $unit = 0
    while ($value -ge 999.5 -and $unit -lt 4) {
        $value /= 1000
        $unit++
    }
    $number = if ($unit -eq 0) {
        '{0:0}' -f $value
    } elseif ($value -lt 9.995) {
        '{0:0.00}' -f $value
    } elseif ($value -lt 99.95) {
        '{0:0.0}' -f $value
    } else {
        '{0:0}' -f $value
    }
    if ($Compact) {
        return "$number$($short[$unit])"
    }
    return "$number $($long[$unit])"
}

function Format-SnmpSpeed {
    param ([double]$BitsPerSecond)

    if ($BitsPerSecond -le 0) { return '?' }
    if ($BitsPerSecond -ge 1e12) { return ('{0:0.#}T' -f ($BitsPerSecond / 1e12)) }
    if ($BitsPerSecond -ge 1e9) { return ('{0:0.#}G' -f ($BitsPerSecond / 1e9)) }
    if ($BitsPerSecond -ge 1e6) { return ('{0:0.#}M' -f ($BitsPerSecond / 1e6)) }
    if ($BitsPerSecond -ge 1e3) { return ('{0:0.#}k' -f ($BitsPerSecond / 1e3)) }
    return ('{0:0}' -f $BitsPerSecond)
}

function Format-SnmpUpTime {
    param ($TimeTicks)

    if ($null -eq $TimeTicks) {
        return '?'
    }
    $span = [TimeSpan]::FromSeconds([double]$TimeTicks / 100)
    return ('{0}d {1:hh\:mm\:ss}' -f [int][Math]::Floor($span.TotalDays), $span)
}

function Format-SnmpCount {
    param ([double]$Value)

    if ($Value -lt 100000) { return ('{0:0}' -f $Value) }
    if ($Value -lt 1e7) { return ('{0:0}k' -f ($Value / 1e3)) }
    if ($Value -lt 1e10) { return ('{0:0}M' -f ($Value / 1e6)) }
    return ('{0:0}G' -f ($Value / 1e9))
}

#endregion Interface counters

#region Bandwidth monitor TUI -------------------------------------------------

$script:BandwidthBarGlyphs = @{
    # Index = filled fraction of a cell in steps of 1/(Count-1); the last entry is a full cell.
    Block = @(' ', [char]0x2591, [char]0x2592, [char]0x2593, [char]0x2588)   # ' ' ░ ▒ ▓ █
    Ascii = @(' ', '|', '%', '#')
}

$script:BandwidthViews = @('Grid', 'Errors', 'List')
$script:BandwidthSortOrders = @('Index', 'Name', 'In', 'Out', 'Total', 'Errors')
$script:BandwidthIntervalSteps = @(0.2, 0.25, 0.5, 1, 2, 5, 10, 30, 60)
$script:BandwidthAverageSteps = @(0, 1, 3, 5, 10, 30)
$script:BandwidthErrorFields = @('InErrors', 'OutErrors', 'InDiscards', 'OutDiscards')
$script:BandwidthFlashSeconds = 3.0

# ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet: kept on screen even when down so a
# switch's front-panel ports hold their positions in the grid.
$script:PhysicalIfTypes = @(6, 62, 69, 117)

$script:InterfaceNameAbbreviations = [ordered]@{
    '^HundredGig(abit)?E(thernet)?'    = 'Hu'
    '^FortyGig(abit)?E(thernet)?'      = 'Fo'
    '^TwentyFiveGig(abit)?E(thernet)?' = 'Twe'
    '^TenGig(abit)?E(thernet)?'        = 'Te'
    '^FiveGig(abit)?E(thernet)?'       = 'Fi'
    '^TwoGig(abit)?E(thernet)?'        = 'Tw'
    '^GigabitEthernet'                 = 'Gi'
    '^FastEthernet'                    = 'Fa'
    '^Ethernet'                        = 'Eth'
    '^Port-channel'                    = 'Po'
}

function Format-BandwidthBar {
    <#
    Renders one split bar: inbound grows from the left edge toward the centre (green),
    outbound grows from the right edge toward the centre (red). An optional label is centred
    with the in/out texts beside it; without a label the texts sit either side of the centre.
    Text drawn over a filled part of the bar is inverted so it stays readable.
    #>
    param (
        [double]$InFraction,
        [double]$OutFraction,
        [int]$Width,
        [string]$InText = '',
        [string]$OutText = '',
        [string]$Label = '',
        # Width of the centred slot the label sits in. Giving every cell in a grid the same slot
        # lines the in texts up on their right edge and the out texts on their left edge.
        [int]$LabelWidth = 0,
        # SGR overrides for text that is not over the bar (used by the errors view).
        [string]$InTextCode = '1;92',
        [string]$OutTextCode = '1;91',
        [string]$LabelCode = '1',
        [ValidateSet('Block', 'Ascii')]
        [string]$Style = 'Block',
        [switch]$NoColor
    )

    $Width = [Math]::Max(1, $Width)
    $glyphs = $script:BandwidthBarGlyphs[$Style]
    $levels = $glyphs.Count - 1
    $leftWidth = [int][Math]::Floor($Width / 2)
    $rightWidth = $Width - $leftWidth

    $chars = [char[]]::new($Width)
    $codes = [string[]]::new($Width)
    $onBar = [bool[]]::new($Width)

    foreach ($side in 'In', 'Out') {
        $fraction = if ($side -eq 'In') { $InFraction } else { $OutFraction }
        $sideWidth = if ($side -eq 'In') { $leftWidth } else { $rightWidth }
        if ([double]::IsNaN($fraction)) { $fraction = 0.0 }
        $fraction = [Math]::Max(0.0, [Math]::Min(1.0, [double]$fraction))
        $units = [int][Math]::Round($fraction * $sideWidth * $levels)
        if ($fraction -gt 0 -and $units -eq 0) {
            # Keep any non-zero traffic visible as a sliver at the edge.
            $units = 1
        }

        for ($distance = 0; $distance -lt $sideWidth; $distance++) {
            $cellUnits = [Math]::Max(0, [Math]::Min($levels, $units - $distance * $levels))
            $position = if ($side -eq 'In') { $distance } else { $Width - 1 - $distance }
            $chars[$position] = [char]$glyphs[$cellUnits]
            $onBar[$position] = ($cellUnits * 2) -ge $levels -and $cellUnits -gt 0
            $codes[$position] = if ($cellUnits -gt 0) { if ($side -eq 'In') { '32' } else { '31' } } else { '' }
        }
    }

    if ($Label) {
        if ($Label.Length -gt $Width) { $Label = $Label.Substring(0, $Width) }
        $slot = [Math]::Min($Width, [Math]::Max($LabelWidth, $Label.Length))
        $slotStart = [int][Math]::Floor(($Width - $slot) / 2)
        $labelStart = $slotStart + [int][Math]::Floor(($slot - $Label.Length) / 2)
        $inEnd = $slotStart - 1
        $outStart = $slotStart + $slot + 1
    } else {
        $labelStart = 0
        $inEnd = $leftWidth - 1
        $outStart = $leftWidth + 1
    }

    $inMax = [Math]::Max(0, $inEnd)
    $outMax = [Math]::Max(0, $Width - $outStart)
    if ($InText.Length -gt $inMax) { $InText = $InText.Substring(0, $inMax) }
    if ($OutText.Length -gt $outMax) { $OutText = $OutText.Substring(0, $outMax) }

    for ($i = 0; $i -lt $InText.Length; $i++) {
        $position = $inEnd - $InText.Length + $i
        $chars[$position] = $InText[$i]
        $codes[$position] = if ($onBar[$position]) { '30;42' } else { $InTextCode }
    }
    for ($i = 0; $i -lt $OutText.Length; $i++) {
        $position = $outStart + $i
        $chars[$position] = $OutText[$i]
        $codes[$position] = if ($onBar[$position]) { '1;97;41' } else { $OutTextCode }
    }
    for ($i = 0; $i -lt $Label.Length; $i++) {
        $position = $labelStart + $i
        $chars[$position] = $Label[$i]
        $codes[$position] = if ($onBar[$position]) {
            if ($position -lt $leftWidth) { '30;42' } else { '1;97;41' }
        } else {
            $LabelCode
        }
    }

    if ($NoColor) {
        return [string]::new($chars)
    }

    $escape = [char]27
    $builder = [System.Text.StringBuilder]::new($Width * 4)
    $current = ''
    for ($i = 0; $i -lt $Width; $i++) {
        if ($codes[$i] -ne $current) {
            [void]$builder.Append($(if ($codes[$i]) { "$escape[0;$($codes[$i])m" } else { "$escape[0m" }))
            $current = $codes[$i]
        }
        [void]$builder.Append($chars[$i])
    }
    if ($current) {
        [void]$builder.Append("$escape[0m")
    }
    return $builder.ToString()
}

function Get-BandwidthFraction {
    param ($BitsPerSecond, [double]$ScaleBps, [switch]$LogScale)

    if ($null -eq $BitsPerSecond -or $BitsPerSecond -le 0 -or $ScaleBps -le 0) {
        return 0.0
    }
    if ($LogScale) {
        # 1 kbps sits at the edge, link speed at the centre.
        $floor = [Math]::Log10(1000)
        $top = [Math]::Log10([Math]::Max($ScaleBps, 10000.0))
        return [Math]::Max(0.0, [Math]::Min(1.0, ([Math]::Log10([Math]::Max([double]$BitsPerSecond, 1.0)) - $floor) / ($top - $floor)))
    }
    return [Math]::Min(1.0, [double]$BitsPerSecond / $ScaleBps)
}

function Get-BandwidthScale {
    # Returns @(scaleBps, speedLabel). Interfaces that report no speed (bridges, PPPoE, tunnels)
    # are scaled to the fastest speed the device reports, not to their own peak, which would
    # make any steady trickle look like a saturated link.
    param ($Row, [double]$DeviceSpeed)

    if ($Row.SpeedBps -gt 0) {
        return @([double]$Row.SpeedBps, (Format-SnmpSpeed $Row.SpeedBps))
    }
    if ($DeviceSpeed -gt 0) {
        return @($DeviceSpeed, ('~' + (Format-SnmpSpeed $DeviceSpeed)))
    }
    return @([Math]::Max(1000.0, [Math]::Max([double]$Row.PeakInBps, [double]$Row.PeakOutBps)), 'peak')
}

function Format-SnmpBitRateShort {
    # Compact rate for grid cells: 512b, 5Kb, 8.3Mb, 43Mb, 1Gb.
    param ($BitsPerSecond)

    $units = 'b', 'Kb', 'Mb', 'Gb', 'Tb'
    $value = [Math]::Max(0.0, [double]$BitsPerSecond)
    if ($value -lt 0.5) {
        return '0'
    }
    $unit = 0
    while ($value -ge 999.5 -and $unit -lt 4) {
        $value /= 1000
        $unit++
    }
    $number = if ($value -lt 9.95) { '{0:0.#}' -f $value } else { '{0:0}' -f $value }
    return "$number$($units[$unit])"
}

function Get-SnmpFitText {
    param ([string]$Text, [int]$Width, [switch]$AlignRight)

    $Text = $Text ?? ''
    if ($Width -le 0) {
        return ''
    }
    if ($Text.Length -gt $Width) {
        return $Text.Substring(0, [Math]::Max(0, $Width - 1)) + [char]0x2026
    }
    if ($AlignRight) {
        return $Text.PadLeft($Width)
    }
    return $Text.PadRight($Width)
}

function Format-SnmpInterfaceLabel {
    # Fits an interface name into $Width: first abbreviates well-known prefixes
    # (GigabitEthernet -> Gi, ...), then truncates. 'Start' drops leading characters, keeping
    # the end of the name (Gi1/0/48), which is usually the part that tells ports apart.
    param ([string]$Name, [int]$Width, [ValidateSet('Start', 'End')][string]$Truncate = 'Start', [switch]$Abbreviate)

    $Name = $Name ?? ''
    if ($Width -le 0) {
        return ''
    }
    if ($Name.Length -le $Width -and -not $Abbreviate) {
        return $Name
    }
    foreach ($entry in $script:InterfaceNameAbbreviations.GetEnumerator()) {
        if ($Name -match $entry.Key) {
            $Name = $Name -replace $entry.Key, $entry.Value
            break
        }
    }
    if ($Name.Length -le $Width) {
        return $Name
    }
    if ($Width -eq 1) {
        return [string][char]0x2026
    }
    if ($Truncate -eq 'Start') {
        return [string][char]0x2026 + $Name.Substring($Name.Length - ($Width - 1))
    }
    return $Name.Substring(0, $Width - 1) + [char]0x2026
}

function Get-BandwidthCellText {
    # Decides what fits in a grid cell: a centred label with the in/out texts beside it.
    # The label gets squeezed (abbreviated/truncated) first; if it would drop below 6 chars
    # the side texts are dropped instead so the port stays identifiable.
    param (
        [string]$Name,
        [int]$Width,
        [string]$Truncate = 'Start',
        [string]$InText = '',
        [string]$OutText = '',
        # Minimum room kept for each side text, so cells with and without rates (e.g. down
        # ports) shorten their labels the same way and the grid lines up.
        [int]$Reserve = 0
    )

    $side = [Math]::Max([Math]::Max($InText.Length, $OutText.Length), $Reserve)
    $room = if ($side -gt 0) { $Width - 2 * ($side + 1) } else { $Width }
    if ($side -gt 0 -and $room -lt [Math]::Min(6, $Name.Length)) {
        $InText = ''
        $OutText = ''
        $room = $Width
    }

    [PSCustomObject]@{
        Label   = Format-SnmpInterfaceLabel -Name $Name -Width $room -Truncate $Truncate -Abbreviate
        InText  = $InText
        OutText = $OutText
    }
}

function Update-SnmpRateTracker {
    <#
    Tracks one octet counter and keeps $Tracker.Rate (bits/s) current.

    Agents refresh their counters on their own schedule (about once a second on RouterOS, every
    few seconds on some switches), so a rate taken between two arbitrary polls flickers between
    zero and double. Instead, the tracker records the polls at which the counter actually changed
    and measures between those, averaged over the last $AverageSeconds of changes. A counter that
    stays still for well past its usual update gap is reported as idle (0).
    #>
    param ([hashtable]$Tracker, $Value, [double]$Time, [double]$AverageSeconds = 3, [switch]$Counter64)

    if ($null -eq $Value) {
        $Tracker.Rate = $null
        return
    }

    if ($null -eq $Tracker.Events) {
        # Events are @(time, cumulative octets). The first one is only an anchor: the agent's
        # counter did not necessarily change at that moment, so it is not used as a start point.
        $Tracker.Events = [System.Collections.Generic.List[double[]]]::new()
        $Tracker.Events.Add([double[]]@($Time, 0.0))
        $Tracker.Anchor = $true
        $Tracker.Value = $Value
        $Tracker.Total = 0.0
        $Tracker.Rate = $null
        $Tracker.Started = $Time
        return
    }

    $events = $Tracker.Events
    if ($Value -ne $Tracker.Value) {
        $delta = Get-SnmpCounterDelta $Tracker.Value $Value -Counter64:$Counter64
        $Tracker.Value = $Value
        if ($null -eq $delta) {
            # Discontinuity (counter reset): start over from here.
            $events.Clear()
            $events.Add([double[]]@($Time, 0.0))
            $Tracker.Anchor = $true
            $Tracker.Total = 0.0
            $Tracker.Rate = $null
            return
        }

        $Tracker.Total += [double]$delta
        $events.Add([double[]]@($Time, $Tracker.Total))
        # Keep just enough history to span the averaging window (at least two points).
        while ($events.Count -gt 2 -and ($Time - $events[1][0]) -ge $AverageSeconds) {
            $events.RemoveAt(0)
            $Tracker.Anchor = $false
        }

        $first = if ($Tracker.Anchor) { 1 } else { 0 }
        if ($events.Count - $first -ge 2) {
            $oldest = $events[$first]
            $newest = $events[$events.Count - 1]
            if ($newest[0] -gt $oldest[0]) {
                $Tracker.Rate = ($newest[1] - $oldest[1]) * 8.0 / ($newest[0] - $oldest[0])
            }
        }
        return
    }

    # Unchanged since the last poll.
    $lastChange = $events[$events.Count - 1][0]
    $gap = if ($events.Count -ge 2) { $lastChange - $events[$events.Count - 2][0] } else { 1.0 }
    if (($Time - $lastChange) -gt [Math]::Max(3.0, 2.5 * $gap)) {
        $Tracker.Rate = 0.0
        if ($events.Count -gt 1) {
            # Idle: restart history at the last real change so a burst after a quiet spell is
            # not averaged against the quiet period.
            $last = $events[$events.Count - 1]
            $events.Clear()
            $events.Add($last)
            $Tracker.Anchor = $true
        }
    }
}

function New-BandwidthMonitorRow {
    param ($Interface)

    [PSCustomObject]@{
        Index            = $Interface.Index
        Name             = $Interface.Name
        Alias            = $Interface.Alias
        Description      = $Interface.Description
        SpeedBps         = $Interface.SpeedBps
        OperStatus       = $Interface.OperStatus
        HighCapacity     = $Interface.HighCapacity
        Physical         = [int]($Interface.TypeId ?? 0) -in $script:PhysicalIfTypes
        InBps            = $null
        OutBps           = $null
        PeakInBps        = 0.0
        PeakOutBps       = 0.0
        InTracker        = @{}
        OutTracker       = @{}
        InErrors         = [uint64]0
        OutErrors        = [uint64]0
        InDiscards       = [uint64]0
        OutDiscards      = [uint64]0
        TotalInErrors    = $null
        TotalOutErrors   = $null
        TotalInDiscards  = $null
        TotalOutDiscards = $null
        # Field -> time until which the cell is highlighted after the counter increased.
        ErrorFlash       = @{}
    }
}

function Update-BandwidthMonitorState {
    param ([hashtable]$State, $Sample)

    $previous = $State.LastSample
    $State.LastSample = $Sample
    $State.Now = $Sample.Time
    if ($null -ne $Sample.UpTime) {
        $State.UpTime = $Sample.UpTime
    }
    # sysUpTime going backwards means the agent restarted and its counters reset.
    $restarted = $null -ne $previous -and $null -ne $Sample.UpTime -and $null -ne $previous.UpTime -and $Sample.UpTime -lt $previous.UpTime
    $average = [double]($State.AverageSeconds ?? 3)

    foreach ($row in $State.Rows) {
        $current = $Sample.Counters[$row.Index]
        if ($null -eq $current) { continue }
        if ($null -ne $current.OperStatus) { $row.OperStatus = [int]$current.OperStatus }

        if ($restarted) {
            $row.InTracker = @{}
            $row.OutTracker = @{}
        }
        Update-SnmpRateTracker -Tracker $row.InTracker -Value $current.InOctets -Time $Sample.Time -AverageSeconds $average -Counter64:$row.HighCapacity
        Update-SnmpRateTracker -Tracker $row.OutTracker -Value $current.OutOctets -Time $Sample.Time -AverageSeconds $average -Counter64:$row.HighCapacity
        $row.InBps = $row.InTracker.Rate
        $row.OutBps = $row.OutTracker.Rate
        if ($row.InBps -gt $row.PeakInBps) { $row.PeakInBps = $row.InBps }
        if ($row.OutBps -gt $row.PeakOutBps) { $row.PeakOutBps = $row.OutBps }

        $before = if ($null -ne $previous -and -not $restarted) { $previous.Counters[$row.Index] } else { $null }
        foreach ($field in $script:BandwidthErrorFields) {
            $row."Total$field" = $current.$field
            if ($null -ne $before) {
                $delta = Get-SnmpCounterDelta $before.$field $current.$field
                if ($delta) {
                    $row.$field = [uint64]($row.$field + $delta)
                    $row.ErrorFlash[$field] = $Sample.Time + $script:BandwidthFlashSeconds
                }
            }
        }
    }
    $State.PollCount++
}

function Get-BandwidthErrorValue {
    param ($Row, [string]$Field, [bool]$Totals)

    if ($Totals) {
        return $Row."Total$Field"
    }
    return $Row.$Field
}

function Test-BandwidthFlash {
    param ($Row, [string[]]$Field, [double]$Now)

    foreach ($name in $Field) {
        if ($Row.ErrorFlash[$name] -gt $Now) {
            return $true
        }
    }
    return $false
}

function Get-BandwidthMonitorVisibleRows {
    param ([hashtable]$State)

    $rows = @($State.Rows | Where-Object { $State.ShowAll -or $_.OperStatus -eq 1 -or $_.Physical })
    $totals = [bool]$State.ShowTotals
    switch ($State.Sort) {
        'Name' { return @($rows | Sort-Object -Property Name, Index) }
        'In' { return @($rows | Sort-Object -Property @{ Expression = { $_.InBps ?? 0 }; Descending = $true }, Index) }
        'Out' { return @($rows | Sort-Object -Property @{ Expression = { $_.OutBps ?? 0 }; Descending = $true }, Index) }
        'Total' { return @($rows | Sort-Object -Property @{ Expression = { ($_.InBps ?? 0) + ($_.OutBps ?? 0) }; Descending = $true }, Index) }
        'Errors' {
            $errorSum = {
                $sum = 0.0
                foreach ($field in $script:BandwidthErrorFields) { $sum += [double]((Get-BandwidthErrorValue $_ $field $totals) ?? 0) }
                $sum
            }
            return @($rows | Sort-Object -Property @{ Expression = $errorSum; Descending = $true }, Index)
        }
    }
    return @($rows | Sort-Object -Property Index)
}

function Get-BandwidthErrorTexts {
    # Returns @(inText, outText) for the errors view: "errors/discards" per direction.
    param ($Row, [bool]$Totals)

    $count = {
        param ($Field)
        $value = Get-BandwidthErrorValue $Row $Field $Totals
        if ($null -eq $value) { '-' } else { Format-SnmpCount $value }
    }
    return @("$(& $count 'InErrors')/$(& $count 'InDiscards')", "$(& $count 'OutErrors')/$(& $count 'OutDiscards')")
}

function Format-BandwidthGridCell {
    param (
        [hashtable]$State,
        $Row,
        [int]$CellWidth,
        [double]$DeviceSpeed,
        # Side-text room and label slot shared by every cell in the grid (see Format-BandwidthMonitorGrid).
        [int]$Reserve = 5,
        [int]$LabelWidth = 0,
        [switch]$Errors,
        [switch]$NoColor
    )

    $escape = [char]27
    $inner = [Math]::Max(1, $CellWidth - 2)
    $isUp = $Row.OperStatus -eq 1
    $now = [double]$State.Now
    $totals = [bool]$State.ShowTotals
    $truncate = $State.NameTruncation ?? 'Start'

    $hasErrors = $false
    foreach ($field in $script:BandwidthErrorFields) {
        if ((Get-BandwidthErrorValue $Row $field $totals) -gt 0) { $hasErrors = $true }
    }
    $flashing = Test-BandwidthFlash $Row $script:BandwidthErrorFields $now
    $bracketCode = if ($flashing) { '1;91' } elseif ($hasErrors) { '33' } elseif ($isUp) { '1' } else { '2' }
    $labelCode = if ($isUp) { '1' } else { '2' }

    if ($Errors) {
        $severity = {
            param ([string[]]$Fields)
            if (Test-BandwidthFlash $Row $Fields $now) { return '1;97;41' }
            foreach ($field in $Fields) {
                if ((Get-BandwidthErrorValue $Row $field $totals) -gt 0) { return '1;33' }
            }
            return '2'
        }
        $inText, $outText = Get-BandwidthErrorTexts $Row $totals
        $text = Get-BandwidthCellText -Name $Row.Name -Width $inner -Truncate $truncate -InText $inText -OutText $outText -Reserve $Reserve
        $body = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width $inner -Label $text.Label -LabelWidth $LabelWidth `
            -InText $text.InText -OutText $text.OutText `
            -InTextCode (& $severity @('InErrors', 'InDiscards')) -OutTextCode (& $severity @('OutErrors', 'OutDiscards')) `
            -LabelCode $labelCode -Style $State.BarStyle -NoColor:$NoColor
    } else {
        $scale = (Get-BandwidthScale $Row $DeviceSpeed)[0]
        if ($isUp) {
            $inText = if ($null -ne $Row.InBps) { Format-SnmpBitRateShort $Row.InBps } else { '-' }
            $outText = if ($null -ne $Row.OutBps) { Format-SnmpBitRateShort $Row.OutBps } else { '-' }
        } else {
            $inText = ''
            $outText = ''
        }
        $text = Get-BandwidthCellText -Name $Row.Name -Width $inner -Truncate $truncate -InText $inText -OutText $outText -Reserve $Reserve
        $inFraction = if ($isUp) { Get-BandwidthFraction $Row.InBps $scale -LogScale:$State.LogScale } else { 0.0 }
        $outFraction = if ($isUp) { Get-BandwidthFraction $Row.OutBps $scale -LogScale:$State.LogScale } else { 0.0 }
        $body = Format-BandwidthBar -InFraction $inFraction -OutFraction $outFraction `
            -Width $inner -Label $text.Label -LabelWidth $LabelWidth -InText $text.InText -OutText $text.OutText `
            -LabelCode $labelCode -Style $State.BarStyle -NoColor:$NoColor
    }

    if ($NoColor) {
        return "[$body]"
    }
    $bracket = "$escape[0;${bracketCode}m"
    return "$bracket[$escape[0m$body$bracket]$escape[0m"
}

function Format-BandwidthMonitorGrid {
    # htop-style meter grid, filled column by column. Picks the fewest columns that fit every
    # interface on screen (wider cells = finer bars), within min/max cell widths.
    param (
        [hashtable]$State,
        [object[]]$Rows,
        [int]$Usable,
        [int]$BodyHeight,
        [double]$DeviceSpeed,
        [switch]$Errors,
        [switch]$NoColor
    )

    $count = $Rows.Count
    if ($count -eq 0) {
        return , [string[]]@()
    }
    $minCell = 18
    $maxCell = 100
    $BodyHeight = [Math]::Max(1, $BodyHeight)

    $colsForWidth = [Math]::Max(1, [int][Math]::Floor(($Usable + 1) / ($minCell + 1)))
    $colsForHeight = [int][Math]::Ceiling($count / $BodyHeight)
    $colsForMaxCell = [int][Math]::Ceiling(($Usable + 1) / ($maxCell + 1))
    $columns = [Math]::Min($colsForWidth, [Math]::Max($colsForHeight, $colsForMaxCell))
    $columns = [Math]::Max(1, [Math]::Min($columns, $count))
    $cellWidth = [Math]::Min($maxCell, [int][Math]::Floor(($Usable - ($columns - 1)) / $columns))
    $rowsPerColumn = [int][Math]::Ceiling($count / $columns)

    $maxScroll = [Math]::Max(0, $rowsPerColumn - $BodyHeight)
    $State.Scroll = [Math]::Max(0, [Math]::Min($State.Scroll, $maxScroll))
    $State.PageSize = $BodyHeight
    $State.ScrollInfo = if ($maxScroll -gt 0) { "rows $($State.Scroll + 1)-$([Math]::Min($rowsPerColumn, $State.Scroll + $BodyHeight)) of $rowsPerColumn" } else { '' }

    # Every cell shares one label slot (the longest fitted name) and one side-text reserve, so
    # in readouts line up on their right edge and out readouts on their left edge, grid-wide.
    $inner = [Math]::Max(1, $cellWidth - 2)
    $truncate = $State.NameTruncation ?? 'Start'
    $reserve = 5
    if ($Errors) {
        $reserve = 3
        foreach ($row in $Rows) {
            foreach ($text in (Get-BandwidthErrorTexts $row ([bool]$State.ShowTotals))) {
                $reserve = [Math]::Max($reserve, $text.Length)
            }
        }
    }
    $labelWidth = 0
    foreach ($row in $Rows) {
        $fitted = Get-BandwidthCellText -Name $row.Name -Width $inner -Truncate $truncate -Reserve $reserve
        $labelWidth = [Math]::Max($labelWidth, $fitted.Label.Length)
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $last = [Math]::Min($rowsPerColumn, $State.Scroll + $BodyHeight)
    for ($r = $State.Scroll; $r -lt $last; $r++) {
        $builder = [System.Text.StringBuilder]::new()
        for ($c = 0; $c -lt $columns; $c++) {
            $i = $c * $rowsPerColumn + $r
            if ($i -ge $count) { break }
            if ($c -gt 0) { [void]$builder.Append(' ') }
            [void]$builder.Append((Format-BandwidthGridCell -State $State -Row $Rows[$i] -CellWidth $cellWidth -DeviceSpeed $DeviceSpeed -Reserve $reserve -LabelWidth $labelWidth -Errors:$Errors -NoColor:$NoColor))
        }
        $lines.Add($builder.ToString())
    }
    return , $lines.ToArray()
}

function Format-BandwidthMonitorList {
    # One wide row per interface with name, alias, speed, bar and separate error columns.
    param (
        [hashtable]$State,
        [object[]]$Rows,
        [int]$Usable,
        [int]$BodyHeight,
        [double]$DeviceSpeed,
        [switch]$NoColor
    )

    $escape = [char]27
    $sgr = { param ([string]$Code) if ($NoColor) { '' } else { "$escape[${Code}m" } }
    $reset = & $sgr '0'
    $totals = [bool]$State.ShowTotals
    $now = [double]$State.Now

    $nameWidth = [Math]::Min(24, [Math]::Max(9, (@($Rows | ForEach-Object { $_.Name.Length }) + 9 | Measure-Object -Maximum).Maximum))
    $aliasWidth = [Math]::Min(24, (@($Rows | ForEach-Object { ($_.Alias ?? '').Length }) + 0 | Measure-Object -Maximum).Maximum)
    $errorMode = 'Full'
    $minimumBar = 24
    $layout = {
        $errorWidth = switch ($errorMode) { 'Full' { 32 } 'Combined' { 8 } default { 0 } }
        $aliasPart = if ($aliasWidth -gt 0) { $aliasWidth + 1 } else { 0 }
        $Usable - (1 + $nameWidth + 1 + $aliasPart + 6 + 1 + 2 + $errorWidth)
    }
    $barWidth = & $layout
    if ($barWidth -lt $minimumBar -and $aliasWidth -gt 0) { $aliasWidth = 0; $barWidth = & $layout }
    if ($barWidth -lt $minimumBar) { $errorMode = 'Combined'; $barWidth = & $layout }
    if ($barWidth -lt $minimumBar) { $nameWidth = 9; $barWidth = & $layout }
    if ($barWidth -lt $minimumBar) { $errorMode = 'None'; $barWidth = & $layout }
    $barWidth = [Math]::Max(10, $barWidth)
    $compactRates = ([Math]::Floor($barWidth / 2) - 1) -lt 10

    $lines = [System.Collections.Generic.List[string]]::new()
    $leftWidth = [int][Math]::Floor($barWidth / 2)
    $rightWidth = $barWidth - $leftWidth
    $header = ' ' + (Get-SnmpFitText 'Interface' $nameWidth) + ' '
    if ($aliasWidth -gt 0) { $header += (Get-SnmpFitText 'Alias' $aliasWidth) + ' ' }
    $header += ' Speed [' + (Get-SnmpFitText 'In ' $leftWidth -AlignRight) + (Get-SnmpFitText ' Out' $rightWidth) + ']'
    switch ($errorMode) {
        'Full' { $header += '  InErr  OutErr  InDisc OutDisc' }
        'Combined' { $header += '  Err+Dsc' }
    }
    $lines.Add((& $sgr '7') + (Get-SnmpFitText $header $Usable) + $reset)

    $rowArea = [Math]::Max(1, $BodyHeight - 1)
    $maxScroll = [Math]::Max(0, $Rows.Count - $rowArea)
    $State.Scroll = [Math]::Max(0, [Math]::Min($State.Scroll, $maxScroll))
    $State.PageSize = $rowArea
    $State.ScrollInfo = if ($maxScroll -gt 0) { "rows $($State.Scroll + 1)-$([Math]::Min($Rows.Count, $State.Scroll + $rowArea)) of $($Rows.Count)" } else { '' }

    $errorCell = {
        param ($Value, [bool]$Flash, [int]$CellWidth)
        $text = if ($null -eq $Value) { '-' } else { Format-SnmpCount $Value }
        $text = (' ' + $text.PadLeft($CellWidth - 1))
        $code = if ($Flash) { '1;97;41' } elseif ($null -ne $Value -and $Value -gt 0) { '33' } else { '2' }
        return (& $sgr $code) + $text + $reset
    }

    foreach ($row in @($Rows | Select-Object -Skip $State.Scroll -First $rowArea)) {
        $isUp = $row.OperStatus -eq 1
        $line = ' ' + (& $sgr $(if ($isUp) { '1' } else { '2' })) + (Get-SnmpFitText $row.Name $nameWidth) + $reset + ' '
        if ($aliasWidth -gt 0) {
            $line += (& $sgr '36') + (Get-SnmpFitText $row.Alias $aliasWidth) + $reset + ' '
        }
        $scale, $speedText = Get-BandwidthScale $row $DeviceSpeed
        $line += $speedText.PadLeft(6) + ' ['

        if (-not $isUp) {
            $inText = 'down'
            $outText = ''
        } else {
            $inText = if ($null -ne $row.InBps) { Format-SnmpBitRate $row.InBps -Compact:$compactRates } else { '...' }
            $outText = if ($null -ne $row.OutBps) { Format-SnmpBitRate $row.OutBps -Compact:$compactRates } else { '...' }
        }
        $line += Format-BandwidthBar -InFraction (Get-BandwidthFraction $row.InBps $scale -LogScale:$State.LogScale) `
            -OutFraction (Get-BandwidthFraction $row.OutBps $scale -LogScale:$State.LogScale) `
            -Width $barWidth -InText $inText -OutText $outText -Style $State.BarStyle -NoColor:$NoColor
        $line += ']'

        switch ($errorMode) {
            'Full' {
                $line += ' '
                foreach ($field in $script:BandwidthErrorFields) {
                    $line += & $errorCell (Get-BandwidthErrorValue $row $field $totals) (Test-BandwidthFlash $row $field $now) 7
                }
            }
            'Combined' {
                $sum = 0.0
                foreach ($field in $script:BandwidthErrorFields) { $sum += [double]((Get-BandwidthErrorValue $row $field $totals) ?? 0) }
                $line += ' ' + (& $errorCell $sum (Test-BandwidthFlash $row $script:BandwidthErrorFields $now) 7)
            }
        }
        $lines.Add($line)
    }
    return , $lines.ToArray()
}

function Format-BandwidthMonitorFrame {
    # Returns the screen as an array of lines (ANSI-coloured unless -NoColor), each at most $Width-1 visible chars.
    param ([hashtable]$State, [int]$Width, [int]$Height, [switch]$NoColor)

    $escape = [char]27
    $sgr = { param ([string]$Code) if ($NoColor) { '' } else { "$escape[${Code}m" } }
    $reset = & $sgr '0'
    $usable = [Math]::Max(40, $Width) - 1
    $Height = [Math]::Max(6, $Height)
    $rows = Get-BandwidthMonitorVisibleRows -State $State
    $deviceSpeed = [double](@($State.Rows | ForEach-Object { [double]$_.SpeedBps }) + 0.0 | Measure-Object -Maximum).Maximum
    $view = $State.View ?? 'Grid'

    $lines = [System.Collections.Generic.List[string]]::new()

    $sysLabel = if ($State.SysName) { "$($State.Target) ($($State.SysName))" } else { $State.Target }
    $scaleLabel = if ($State.LogScale) { 'log' } else { 'linear' }
    $errorLabel = if ($State.ShowTotals) { 'errors: totals' } else { 'errors: since start' }
    $averageLabel = if ($State.AverageSeconds -gt 0) { "avg $($State.AverageSeconds)s" } else { 'avg off' }
    $title = " bwmon | $sysLabel | $($State.VersionLabel) | up $(Format-SnmpUpTime $State.UpTime) | $($view.ToLowerInvariant()) | every $($State.IntervalSeconds)s $averageLabel | $scaleLabel | sort $($State.Sort.ToLowerInvariant()) | $errorLabel | $($rows.Count)/$($State.Rows.Count) ifaces"
    $lines.Add((& $sgr '30;46') + (Get-SnmpFitText $title $usable) + $reset)

    $legend = switch ($view) {
        'Errors' { 'cells: in errors/discards  port  out errors/discards  (yellow = non-zero, red = increased in the last few seconds)' }
        'Grid' { 'bars: in (green) from the left edge, out (red) from the right edge, centre = link speed  |  [ ] yellow = port has errors, red = errors increasing' }
        default { '' }
    }
    $descr = (($State.SysDescr ?? '') -split '\r?\n')[0]
    $second = if ($legend) { " $descr  |  $legend" } else { " $descr" }
    $lines.Add((& $sgr '2') + (Get-SnmpFitText $second $usable) + $reset)

    $footerLines = if ($State.LastError) { 2 } else { 1 }
    $bodyHeight = [Math]::Max(1, $Height - $lines.Count - $footerLines)
    $body = switch ($view) {
        'List' { Format-BandwidthMonitorList -State $State -Rows $rows -Usable $usable -BodyHeight $bodyHeight -DeviceSpeed $deviceSpeed -NoColor:$NoColor }
        'Errors' { Format-BandwidthMonitorGrid -State $State -Rows $rows -Usable $usable -BodyHeight $bodyHeight -DeviceSpeed $deviceSpeed -Errors -NoColor:$NoColor }
        default { Format-BandwidthMonitorGrid -State $State -Rows $rows -Usable $usable -BodyHeight $bodyHeight -DeviceSpeed $deviceSpeed -NoColor:$NoColor }
    }
    foreach ($line in @($body)) {
        $lines.Add($line)
    }
    if ($rows.Count -eq 0) {
        $lines.Add((& $sgr '2') + (Get-SnmpFitText '  No interfaces to show (press d to include every interface).' $usable) + $reset)
    }
    while ($lines.Count -lt $Height - $footerLines) {
        $lines.Add('')
    }

    if ($State.LastError) {
        $lines.Add((& $sgr '1;91') + (Get-SnmpFitText (' ! ' + $State.LastError) $usable) + $reset)
    }
    $totalIn = ($rows | ForEach-Object { $_.InBps ?? 0 } | Measure-Object -Sum).Sum
    $totalOut = ($rows | ForEach-Object { $_.OutBps ?? 0 } | Measure-Object -Sum).Sum
    $more = if ($State.ScrollInfo) { " | $($State.ScrollInfo)" } else { '' }
    $footer = " total in $(Format-SnmpBitRate $totalIn) out $(Format-SnmpBitRate $totalOut) | poll $($State.PollMs) ms$more | q quit  v view  s sort  l log  a avg  +/- rate  d all  e err totals  n names  r reset  arrows scroll"
    $lines.Add((& $sgr '7') + (Get-SnmpFitText $footer $usable) + $reset)

    return , $lines.ToArray()
}

function Get-BandwidthNextStep {
    # Next/previous value in a list of steps relative to $Current (which may not be in the list).
    param ([double[]]$Steps, [double]$Current, [switch]$Down)

    if ($Down) {
        $lower = @($Steps | Where-Object { $_ -lt $Current - 1e-9 })
        if ($lower.Count -gt 0) { return $lower[-1] }
        return $Steps[0]
    }
    $higher = @($Steps | Where-Object { $_ -gt $Current + 1e-9 })
    if ($higher.Count -gt 0) { return $higher[0] }
    return $Steps[-1]
}

function Invoke-BandwidthMonitorKey {
    # Applies a keypress to the monitor state. Returns $false when the monitor should exit.
    param ([hashtable]$State, [System.ConsoleKeyInfo]$Key)

    $control = ($Key.Modifiers -band [System.ConsoleModifiers]::Control) -ne 0
    if ($control -and $Key.Key -eq [System.ConsoleKey]::C) {
        return $false
    }

    switch ($Key.Key) {
        'Escape' { return $false }
        'Q' { return $false }
        'UpArrow' { $State.Scroll-- }
        'DownArrow' { $State.Scroll++ }
        'PageUp' { $State.Scroll -= [Math]::Max(1, $State.PageSize) }
        'PageDown' { $State.Scroll += [Math]::Max(1, $State.PageSize) }
        'Home' { $State.Scroll = 0 }
        'End' { $State.Scroll = [int]::MaxValue }
        'V' {
            $views = $script:BandwidthViews
            $State.View = $views[([Array]::IndexOf($views, ($State.View ?? 'Grid')) + 1) % $views.Count]
            $State.Scroll = 0
        }
        'S' {
            $orders = $script:BandwidthSortOrders
            $State.Sort = $orders[([Array]::IndexOf($orders, $State.Sort) + 1) % $orders.Count]
            $State.Scroll = 0
        }
        'L' { $State.LogScale = -not $State.LogScale }
        'D' { $State.ShowAll = -not $State.ShowAll }
        'E' { $State.ShowTotals = -not $State.ShowTotals }
        'N' { $State.NameTruncation = if ($State.NameTruncation -eq 'End') { 'Start' } else { 'End' } }
        'A' {
            $steps = $script:BandwidthAverageSteps
            $index = [Array]::IndexOf($steps, [int]$State.AverageSeconds)
            $State.AverageSeconds = $steps[($index + 1) % $steps.Count]
        }
        'R' {
            foreach ($row in $State.Rows) {
                foreach ($field in $script:BandwidthErrorFields) {
                    $row.$field = [uint64]0
                }
                $row.PeakInBps = 0.0
                $row.PeakOutBps = 0.0
                $row.ErrorFlash = @{}
            }
            $State.LastError = $null
        }
        default {
            if ($Key.KeyChar -in '+', '=') {
                $State.IntervalSeconds = Get-BandwidthNextStep $script:BandwidthIntervalSteps $State.IntervalSeconds
            } elseif ($Key.KeyChar -in '-', '_') {
                $State.IntervalSeconds = Get-BandwidthNextStep $script:BandwidthIntervalSteps $State.IntervalSeconds -Down
            }
        }
    }
    return $true
}

function Get-SnmpInterface {
    <#
    .SYNOPSIS
    Reads interface inventory and traffic/error counters from a device over SNMP.

    .DESCRIPTION
    Walks IF-MIB (ifTable/ifXTable) on the target and returns one object per interface whose
    octet counters are readable: name, alias, speed, admin/oper status, and the raw in/out octet,
    error, and discard counters. 64-bit (ifHC*) counters are used when the agent provides them.

    With -SampleSeconds, the counters are read twice and the result includes bit rates,
    utilization, and how many errors/discards occurred during the sample window.

    Supports SNMP v1, v2c (default), and v3 (USM: MD5/SHA/SHA-2 auth, DES/AES privacy).

    .PARAMETER ComputerName
    Hostname or IP address of the SNMP agent.

    .PARAMETER Community
    Community string for v1/v2c. Defaults to 'public'.

    .PARAMETER Version
    SNMP version: 1, 2c, or 3. Defaults to 2c, or 3 when -UserName is given. -V1/-V2c/-V3 are shorthands.

    .PARAMETER UserName
    SNMPv3 USM user name.

    .PARAMETER AuthProtocol
    SNMPv3 authentication protocol: MD5, SHA (SHA-1), SHA256, SHA384, or SHA512. Defaults to SHA when -AuthPassword is set.

    .PARAMETER AuthPassword
    SNMPv3 authentication password (string or SecureString).

    .PARAMETER PrivProtocol
    SNMPv3 privacy protocol: DES, AES (AES-128), AES192, AES256, or AES192C/AES256C for the
    Cisco-style (Reeder) key extension. Defaults to AES when -PrivPassword is set.

    .PARAMETER PrivPassword
    SNMPv3 privacy password (string or SecureString).

    .PARAMETER Context
    SNMPv3 context name (for example a VLAN or VRF context on some platforms).

    .PARAMETER Interface
    Only return interfaces whose index, name, description, or alias matches one of these (wildcards allowed).

    .PARAMETER SampleSeconds
    Read the counters twice this many seconds apart and include rates and deltas.

    .EXAMPLE
    Get-SnmpInterface 10.0.0.1 -Community public | Where-Object InErrors -gt 0
    Lists interfaces with non-zero input errors since the counters were last cleared.

    .EXAMPLE
    Get-SnmpInterface core1 -V3 -UserName monitor -AuthPassword $auth -PrivPassword $priv -SampleSeconds 5
    Samples rates and error deltas over 5 seconds using SNMPv3 authPriv (SHA/AES).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host', 'IPAddress', 'Target')]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Position = 1)]
        [string]$Community = 'public',

        [ValidateSet('1', '2', '2c', '3')]
        [string]$Version,
        [switch]$V1,
        [switch]$V2c,
        [switch]$V3,

        [string]$UserName,
        [ValidateSet('MD5', 'SHA', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string]$AuthProtocol,
        [object]$AuthPassword,
        [ValidateSet('DES', 'AES', 'AES128', 'AES192', 'AES256', 'AES192C', 'AES256C')]
        [string]$PrivProtocol,
        [object]$PrivPassword,
        [string]$Context = '',

        [string[]]$Interface,

        [ValidateRange(0, 3600)]
        [double]$SampleSeconds = 0,

        [ValidateRange(1, 65535)]
        [int]$Port = 161,
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 2000,
        [ValidateRange(0, 10)]
        [int]$Retries = 2
    )

    process {
        $sessionParameters = Get-SnmpSessionParameter -BoundParameters $PSBoundParameters
        $session = New-SnmpSession @sessionParameters
        try {
            $inventory = Get-SnmpInterfaceInventory -Session $session
            $interfaces = @($inventory.Interfaces | Where-Object { Test-SnmpInterfaceMatch -Interface $_ -Pattern $Interface })
            if ($interfaces.Count -eq 0) {
                Write-Warning "No readable interfaces on $ComputerName matched."
                return
            }

            $first = Get-SnmpInterfaceSample -Session $session -Interfaces $interfaces
            $second = $null
            if ($SampleSeconds -gt 0) {
                Start-Sleep -Milliseconds ([int]($SampleSeconds * 1000))
                $second = Get-SnmpInterfaceSample -Session $session -Interfaces $interfaces
            }
            $latest = $second ?? $first
            $elapsed = if ($second) { $second.Time - $first.Time } else { 0 }

            foreach ($entry in $interfaces) {
                $now = $latest.Counters[$entry.Index]
                $before = $first.Counters[$entry.Index]
                $inBps = $null
                $outBps = $null
                $deltas = @{}
                if ($second -and $elapsed -gt 0) {
                    $inDelta = Get-SnmpCounterDelta $before.InOctets $now.InOctets -Counter64:$entry.HighCapacity
                    $outDelta = Get-SnmpCounterDelta $before.OutOctets $now.OutOctets -Counter64:$entry.HighCapacity
                    if ($null -ne $inDelta) { $inBps = [Math]::Round($inDelta * 8.0 / $elapsed, 1) }
                    if ($null -ne $outDelta) { $outBps = [Math]::Round($outDelta * 8.0 / $elapsed, 1) }
                    foreach ($field in 'InErrors', 'OutErrors', 'InDiscards', 'OutDiscards') {
                        $deltas[$field] = Get-SnmpCounterDelta $before.$field $now.$field
                    }
                }
                $utilization = {
                    param ($Bps)
                    if ($null -eq $Bps -or $entry.SpeedBps -le 0) { return $null }
                    return [Math]::Round(100.0 * $Bps / $entry.SpeedBps, 2)
                }
                $operStatus = [int]($now.OperStatus ?? $entry.OperStatus)

                $result = [PSCustomObject]@{
                    ComputerName      = $ComputerName
                    Index             = $entry.Index
                    Name              = $entry.Name
                    Alias             = $entry.Alias
                    Description       = $entry.Description
                    Type              = $entry.Type
                    OperStatus        = $script:IfStatusNames[$operStatus] ?? [string]$operStatus
                    AdminStatus       = $script:IfStatusNames[$entry.AdminStatus] ?? [string]$entry.AdminStatus
                    SpeedMbps         = [Math]::Round($entry.SpeedBps / 1e6, 3)
                    HighCapacity      = $entry.HighCapacity
                    InOctets          = $now.InOctets
                    OutOctets         = $now.OutOctets
                    InErrors          = $now.InErrors
                    OutErrors         = $now.OutErrors
                    InDiscards        = $now.InDiscards
                    OutDiscards       = $now.OutDiscards
                    SampleSeconds     = if ($second) { [Math]::Round($elapsed, 2) } else { $null }
                    InBitsPerSec      = $inBps
                    OutBitsPerSec     = $outBps
                    InRate            = if ($null -ne $inBps) { Format-SnmpBitRate $inBps } else { $null }
                    OutRate           = if ($null -ne $outBps) { Format-SnmpBitRate $outBps } else { $null }
                    InUtilizationPct  = & $utilization $inBps
                    OutUtilizationPct = & $utilization $outBps
                    InErrorsDelta     = $deltas['InErrors']
                    OutErrorsDelta    = $deltas['OutErrors']
                    InDiscardsDelta   = $deltas['InDiscards']
                    OutDiscardsDelta  = $deltas['OutDiscards']
                }
                $result.PSObject.TypeNames.Insert(0, 'NetworkTools.SnmpInterface')
                $result
            }
        }
        finally {
            Close-SnmpSession -Session $session
        }
    }
}

function Invoke-BandwidthMonitor {
    <#
    .SYNOPSIS
    Live, htop-style SNMP bandwidth and error-counter monitor for every interface on a device.

    .DESCRIPTION
    Discovers the interfaces whose in/out octet counters are readable over SNMP, polls them, and
    draws a full-screen view sized to fit a 48/52-port switch on one screen.

    Grid view (default): one meter per interface, packed into as many columns as needed. Inbound
    (green) grows from the left edge toward the centre and outbound (red) from the right edge
    toward the centre, scaled to the interface speed. The port name is centred in the meter with
    compact rates (5Kb, 8.3Mb, 1Gb) beside it. A meter's brackets turn yellow when the port has
    errors/discards and red while they are increasing.

    Errors view: the same grid showing in and out errors/discards per port.
    List view: one wide row per interface with alias, speed, full rates and error columns.

    Rates are measured between the polls at which each counter actually changed and averaged
    over -AverageSeconds, so fast polling against agents that refresh counters about once a
    second (RouterOS) or less often (many switches) stays steady instead of flickering.

    Keys: q/Esc quit, v cycle view (grid/errors/list), s cycle sort (index/name/in/out/total/errors),
    l toggle log scale, a cycle averaging window, +/- poll faster/slower, d show every interface
    (not just up or physical ones), e toggle error totals vs since-start, n toggle keeping the
    start/end of long names, r reset since-start counts and peaks, arrows/PgUp/PgDn/Home/End scroll.

    Requires an interactive terminal. For scripted output use Get-SnmpInterface -SampleSeconds.

    .PARAMETER ComputerName
    Hostname or IP address of the SNMP agent.

    .PARAMETER Community
    Community string for v1/v2c. Defaults to 'public'.

    .PARAMETER Version
    SNMP version: 1, 2c, or 3. Defaults to 2c, or 3 when -UserName is given. -V1/-V2c/-V3 are shorthands.

    .PARAMETER UserName
    SNMPv3 USM user name.

    .PARAMETER AuthProtocol
    SNMPv3 authentication protocol: MD5, SHA (SHA-1), SHA256, SHA384, or SHA512. Defaults to SHA.

    .PARAMETER AuthPassword
    SNMPv3 authentication password (string or SecureString).

    .PARAMETER PrivProtocol
    SNMPv3 privacy protocol: DES, AES, AES192, AES256, AES192C, or AES256C. Defaults to AES.

    .PARAMETER PrivPassword
    SNMPv3 privacy password (string or SecureString).

    .PARAMETER Interface
    Only monitor interfaces whose index, name, description, or alias matches one of these (wildcards allowed).

    .PARAMETER IntervalSeconds
    Poll interval (0.1 to 3600). Defaults to 0.5. Polling faster than the agent refreshes its
    counters only makes the display react sooner; raise it for switches with weak management CPUs.

    .PARAMETER AverageSeconds
    Window over which rates are averaged. Defaults to 3. Use 0 to turn averaging off (shown as
    "avg off"): each rate then covers only the most recent counter refresh, so it reacts fastest
    but jumps the most. The 'a' key cycles off, 1, 3, 5, 10 and 30 seconds.

    .PARAMETER View
    Starting view: Grid (default), Errors, or List.

    .PARAMETER NameTruncation
    How long interface names are shortened after abbreviation: Start (default) keeps the end of
    the name, e.g. ...1/0/48; End keeps the beginning.

    .PARAMETER ErrorsSinceStart
    Start with error/discard counts since the monitor started instead of the device totals.

    .PARAMETER BarStyle
    Block uses full/shaded block characters; Ascii uses #, % and | for terminals without box glyphs.

    .PARAMETER LogScale
    Start with a logarithmic bar scale (1 kbps at the edge, link speed at the centre).

    .PARAMETER IncludeDown
    Start with every interface shown. By default only interfaces that are up, plus physical
    Ethernet ports (so a switch's ports keep their positions), are shown.

    .PARAMETER NoColor
    Disable ANSI colours.

    .EXAMPLE
    Invoke-BwMon 10.0.0.1 -V2c -Community public
    Monitors every readable interface on 10.0.0.1 using SNMPv2c.

    .EXAMPLE
    Invoke-BandwidthMonitor core1 -V3 -UserName monitor -AuthProtocol SHA256 -AuthPassword $a -PrivProtocol AES -PrivPassword $p -Interface 'Te1/1/*'
    Monitors the TenGig uplinks on core1 over SNMPv3 authPriv.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('Host', 'IPAddress', 'Target')]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Position = 1)]
        [string]$Community = 'public',

        [ValidateSet('1', '2', '2c', '3')]
        [string]$Version,
        [switch]$V1,
        [switch]$V2c,
        [switch]$V3,

        [string]$UserName,
        [ValidateSet('MD5', 'SHA', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string]$AuthProtocol,
        [object]$AuthPassword,
        [ValidateSet('DES', 'AES', 'AES128', 'AES192', 'AES256', 'AES192C', 'AES256C')]
        [string]$PrivProtocol,
        [object]$PrivPassword,
        [string]$Context = '',

        [string[]]$Interface,

        [ValidateRange(0.1, 3600)]
        [double]$IntervalSeconds = 0.5,

        [ValidateRange(0, 300)]
        [double]$AverageSeconds = 3,

        [ValidateSet('Grid', 'Errors', 'List')]
        [string]$View = 'Grid',

        [ValidateSet('Start', 'End')]
        [string]$NameTruncation = 'Start',

        [switch]$ErrorsSinceStart,

        [ValidateSet('Block', 'Ascii')]
        [string]$BarStyle = 'Block',

        [switch]$LogScale,
        [Alias('All')]
        [switch]$IncludeDown,
        [switch]$NoColor,

        [ValidateRange(1, 65535)]
        [int]$Port = 161,
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 2000,
        [ValidateRange(0, 10)]
        [int]$Retries = 1
    )

    if ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected) {
        throw 'Invoke-BandwidthMonitor needs an interactive terminal. Use Get-SnmpInterface -SampleSeconds for scripted output.'
    }

    $sessionParameters = Get-SnmpSessionParameter -BoundParameters $PSBoundParameters
    $sessionParameters['Retries'] = $Retries
    $session = New-SnmpSession @sessionParameters
    $escape = [char]27
    $screenActive = $false
    $savedTreatControlC = [Console]::TreatControlCAsInput
    $savedEncoding = [Console]::OutputEncoding

    try {
        Write-Host "Discovering interfaces on $ComputerName ($($session.VersionLabel))..."
        $inventory = Get-SnmpInterfaceInventory -Session $session
        $interfaces = @($inventory.Interfaces | Where-Object { Test-SnmpInterfaceMatch -Interface $_ -Pattern $Interface })
        if ($interfaces.Count -eq 0) {
            throw "No interfaces with readable octet counters on $ComputerName matched."
        }

        $state = @{
            Target          = $ComputerName
            SysName         = $inventory.SysName
            SysDescr        = $inventory.SysDescr
            UpTime          = $inventory.SysUpTime
            VersionLabel    = $session.VersionLabel
            IntervalSeconds = $IntervalSeconds
            AverageSeconds  = $AverageSeconds
            View            = $View
            NameTruncation  = $NameTruncation
            BarStyle        = $BarStyle
            LogScale        = [bool]$LogScale
            ShowAll         = [bool]$IncludeDown
            ShowTotals      = -not $ErrorsSinceStart
            Sort            = 'Index'
            Scroll          = 0
            PageSize        = 10
            ScrollInfo      = ''
            PollMs          = 0
            PollCount       = 0
            Now             = 0.0
            LastError       = $null
            LastSample      = $null
            Rows            = @($interfaces | ForEach-Object { New-BandwidthMonitorRow $_ })
        }

        $poll = {
            $watch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $sample = Get-SnmpInterfaceSample -Session $session -Interfaces $interfaces
                Update-BandwidthMonitorState -State $state -Sample $sample
                $state.LastError = $null
            }
            catch {
                $state.LastError = "$(Get-Date -Format 'HH:mm:ss') $($_.Exception.Message)"
            }
            $state.PollMs = $watch.ElapsedMilliseconds
        }

        & $poll
        $nextPoll = $session.Clock.Elapsed.TotalSeconds + $state.IntervalSeconds

        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        [Console]::TreatControlCAsInput = $true
        [Console]::Write("$escape[?1049h$escape[?25l$escape[2J")
        $screenActive = $true

        $lastSize = ''
        $dirty = $true
        $running = $true
        while ($running) {
            while ([Console]::KeyAvailable) {
                $running = Invoke-BandwidthMonitorKey -State $state -Key ([Console]::ReadKey($true))
                $dirty = $true
                if (-not $running) { break }
            }
            if (-not $running) { break }

            $now = $session.Clock.Elapsed.TotalSeconds
            if ($now -ge $nextPoll) {
                & $poll
                # If a poll overruns the interval, poll again right away but never fall behind a backlog.
                $nextPoll = [Math]::Max($nextPoll + $state.IntervalSeconds, $session.Clock.Elapsed.TotalSeconds + 0.05)
                $dirty = $true
            }

            $width = [Console]::WindowWidth
            $height = [Console]::WindowHeight
            $size = "$width x $height"
            if ($size -ne $lastSize) {
                [Console]::Write("$escape[2J")
                $lastSize = $size
                $dirty = $true
            }

            if ($dirty) {
                $state.Now = $session.Clock.Elapsed.TotalSeconds
                $lines = Format-BandwidthMonitorFrame -State $state -Width $width -Height $height -NoColor:$NoColor
                $frame = [System.Text.StringBuilder]::new()
                for ($i = 0; $i -lt [Math]::Min($lines.Count, $height); $i++) {
                    [void]$frame.Append("$escape[$($i + 1);1H").Append($lines[$i]).Append("$escape[0m$escape[K")
                }
                [void]$frame.Append("$escape[J")
                [Console]::Write($frame.ToString())
                $dirty = $false
            }

            $wait = [int][Math]::Min(50, [Math]::Max(5, ($nextPoll - $session.Clock.Elapsed.TotalSeconds) * 1000))
            Start-Sleep -Milliseconds $wait
        }
    }
    finally {
        if ($screenActive) {
            [Console]::Write("$escape[0m$escape[?25h$escape[?1049l")
        }
        [Console]::TreatControlCAsInput = $savedTreatControlC
        [Console]::OutputEncoding = $savedEncoding
        Close-SnmpSession -Session $session
    }
}

#endregion Bandwidth monitor TUI

Set-Alias -Name Send-InterfaceStimulus -Value Send-Stimulus
Set-Alias -Name Invoke-BwMon -Value Invoke-BandwidthMonitor

Export-ModuleMember -Function Send-Stimulus, Test-TcpPort, Resolve-MacVendor, Convert-FromCidr, Invoke-NetworkScan, Get-SnmpInterface, Invoke-BandwidthMonitor -Alias Send-InterfaceStimulus, Invoke-BwMon
