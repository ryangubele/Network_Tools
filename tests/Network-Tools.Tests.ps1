$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path -Path $here -ChildPath '..\Network-Tools.psm1'

Remove-Module Network-Tools -ErrorAction SilentlyContinue
Import-Module $modulePath -Force

Describe 'Convert-FromCidr' {
    It 'converts /24 to dotted decimal mask' {
        $result = Convert-FromCidr -Cidr '192.168.10.0/24'

        $result.IPAddress | Should Be '192.168.10.0'
        $result.PrefixLength | Should Be 24
        $result.SubnetMask | Should Be '255.255.255.0'
    }

    It 'converts /0 correctly' {
        $result = Convert-FromCidr -Cidr '10.0.0.0/0'

        $result.PrefixLength | Should Be 0
        $result.SubnetMask | Should Be '0.0.0.0'
    }

    It 'converts /32 correctly' {
        $result = Convert-FromCidr -Cidr '10.0.0.15/32'

        $result.PrefixLength | Should Be 32
        $result.SubnetMask | Should Be '255.255.255.255'
    }

    It 'accepts pipeline input' {
        $result = '172.16.0.0/16' | Convert-FromCidr

        $result.SubnetMask | Should Be '255.255.0.0'
    }

    It 'rejects prefix lengths above 32' {
        $thrown = $false
        try {
            Convert-FromCidr -Cidr '192.168.1.0/33' -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'rejects invalid IPv4 octets above 255' {
        $thrown = $false
        try {
            Convert-FromCidr -Cidr '999.999.999.999/24' -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'rejects mixed valid and invalid octets' {
        $thrown = $false
        try {
            Convert-FromCidr -Cidr '256.1.1.1/24' -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }
}

Describe 'Send-Stimulus' {
    It 'supports selecting a local source port' {
        $result = Send-Stimulus -InterfaceIP '127.0.0.1' -LocalPort 45000 -Count 1 -DelayMs 0

        $result.LocalPort | Should Be 45000
    }

    It 'validates LocalPort lower bound' {
        $thrown = $false
        try {
            Send-Stimulus -InterfaceIP '127.0.0.1' -LocalPort -1 -Count 1 -DelayMs 0 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'validates LocalPort upper bound' {
        $thrown = $false
        try {
            Send-Stimulus -InterfaceIP '127.0.0.1' -LocalPort 70000 -Count 1 -DelayMs 0 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'validates Count lower bound' {
        $thrown = $false
        try {
            Send-Stimulus -InterfaceIP '127.0.0.1' -Count 0 -DelayMs 0 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'validates DelayMs lower bound' {
        $thrown = $false
        try {
            Send-Stimulus -InterfaceIP '127.0.0.1' -Count 1 -DelayMs -1 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'emits a non-terminating error on invalid interface input' {
        $errorRecords = @()
        $result = Send-Stimulus -InterfaceIP 'not-an-ip' -Count 1 -DelayMs 0 -ErrorAction SilentlyContinue -ErrorVariable +errorRecords

        $result | Should BeNullOrEmpty
        $errorRecords.Count | Should BeGreaterThan 0
    }
}

Describe 'Invoke-NetworkScan' {
    BeforeEach {
        Mock Invoke-NetworkScanProbe -ModuleName Network-Tools {
            if ($Addresses -contains '127.0.0.1') {
                [PSCustomObject]@{ IPAddress = '127.0.0.1'; LatencyMs = 0 }
            }
        }

        Mock Get-ArpTable -ModuleName Network-Tools {
            @{ '127.0.0.1' = '00:11:22:33:44:55' }
        }
    }

    It 'runs without platform-specific command failures on a /32 target' {
        $thrown = $false
        $result = $null

        try {
            $result = Invoke-NetworkScan -Target '127.0.0.1/32' -TimeoutMs 50 -ThrottleLimit 4
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $false
        @($result).Count | Should Be 0
    }

    It 'accepts ResolveMacVendor flag without errors' {
        $result = @(Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 50 -ThrottleLimit 4 -ResolveMacVendor)

        $result.Count | Should Be 1
    }

    It 'accepts ResolveDns flag without errors' {
        $result = @(Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 50 -ThrottleLimit 4 -ResolveDns)

        $result.Count | Should Be 1
    }

    It 'accepts DnsTimeout in seconds without errors' {
        $result = @(Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 50 -ThrottleLimit 4 -ResolveDns -DnsTimeout 10)

        $result.Count | Should Be 1
    }

    It 'emits ScanResult objects carrying a Hostname property' {
        $result = Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 100 -ThrottleLimit 4 -ResolveDns

        $hosts = @($result)
        $hosts.Count | Should BeGreaterThan 0
        foreach ($h in $hosts) {
            $h.PSObject.TypeNames[0] | Should Be 'NetworkTools.ScanResult'
            $h.PSObject.Properties.Name -contains 'Hostname' | Should Be $true
        }
    }

    It 'retries ARP lookup when the first snapshot is empty' {
        InModuleScope Network-Tools {
            $script:arpSnapshotCallCount = 0
            Mock Get-ArpTable {
                $script:arpSnapshotCallCount++
                if ($script:arpSnapshotCallCount -eq 1) {
                    @{}
                }
                else {
                    @{ '127.0.0.1' = '00:11:22:33:44:55' }
                }
            }

            Mock Get-OuiLookupData {
                [pscustomobject]@{
                    Map = @{ '001122' = 'Contoso Ltd' }
                    OrderedPrefixLengths = @(6)
                }
            }
        }

        $result = Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 100 -ThrottleLimit 4 -ResolveMacVendor

        $hostResult = @($result) | Where-Object { $_.IPAddress -eq '127.0.0.1' }
        $hostResult.Count | Should Be 1
        Assert-MockCalled Get-ArpTable -ModuleName Network-Tools -Scope It -Times 2 -Exactly
        $hostResult[0].MACAddress | Should Be '00:11:22:33:44:55'
        $hostResult[0].MACVendor | Should Be 'Contoso Ltd'
    }

    It 'places Hostname before IPAddress in the object property order' {
        $result = @(Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 100 -ThrottleLimit 4 -ResolveDns)

        $result.Count | Should Be 1
        $names = @($result[0].PSObject.Properties.Name)
        $names[0] | Should Be 'Hostname'
        $names[1] | Should Be 'IPAddress'
    }

    It 'leaves Hostname null when ResolveDns is not specified' {
        $result = @(Invoke-NetworkScan -Target '127.0.0.1/30' -TimeoutMs 100 -ThrottleLimit 4)

        $result.Count | Should Be 1
        $result[0].PSObject.Properties.Name -contains 'Hostname' | Should Be $true
        $result[0].Hostname | Should BeNullOrEmpty
    }
}

Describe 'Test-TcpPort' {
    It 'returns Reachable true for an open local listener port' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        try {
            $listener.Start()
            $openPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port

            $result = Test-TcpPort -ComputerName '127.0.0.1' -Port $openPort -TimeoutMs 500

            $result.Reachable | Should Be $true
            $result.Port | Should Be $openPort
            $result.ComputerName | Should Be '127.0.0.1'
        }
        finally {
            $listener.Stop()
        }
    }

    It 'returns boolean output when Quiet is used' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        try {
            $listener.Start()
            $openPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port

            $result = Test-TcpPort -ComputerName '127.0.0.1' -Port $openPort -TimeoutMs 500 -Quiet
            $result.GetType().Name | Should Be 'Boolean'
            $result | Should Be $true
        }
        finally {
            $listener.Stop()
        }
    }

    It 'validates Port lower bound' {
        $thrown = $false
        try {
            Test-TcpPort -ComputerName '127.0.0.1' -Port 0 -TimeoutMs 200 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }

    It 'validates Port upper bound' {
        $thrown = $false
        try {
            Test-TcpPort -ComputerName '127.0.0.1' -Port 70000 -TimeoutMs 200 -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }
}

Describe 'Resolve-MacVendor' {
    It 'resolves known vendor from local OUI map file' {
        $result = Resolve-MacVendor -MacAddress '00-50-56-11-22-33'

        $result.Vendor | Should Match 'VMware'
        $result.Source | Should Be 'FileMap'
        $result.NormalizedMac | Should Be '00:50:56:11:22:33'
    }

    It 'returns Unknown for unlisted OUI prefix' {
        $result = Resolve-MacVendor -MacAddress 'AA-BB-CC-11-22-33'

        $result.Vendor | Should Be 'Unknown'
        $result.Source | Should Be 'None'
    }

    It 'supports custom OUI map override' {
        $tempPath = [System.IO.Path]::GetTempFileName()
        try {
            @(
                'Prefix,Vendor'
                'AABBCC,Contoso Labs'
            ) | Set-Content -Path $tempPath

            $result = Resolve-MacVendor -MacAddress 'AA-BB-CC-00-11-22' -OuiMapPath $tempPath

            $result.Vendor | Should Be 'Contoso Labs'
            $result.Source | Should Be 'CustomMap'
        }
        finally {
            if (Test-Path $tempPath) {
                Remove-Item $tempPath -Force
            }
        }
    }

    It 'supports optional online API fallback for unknown OUIs' {
        Mock Invoke-RestMethod {
            'Mock Vendor'
        } -ModuleName Network-Tools

        $result = Resolve-MacVendor -MacAddress 'AA-BB-CC-11-22-33' -UseOnlineApi
        $result.Vendor | Should Be 'Mock Vendor'
        $result.Source | Should Be 'OnlineApi'
    }

    It 'rejects invalid MAC address formats' {
        $thrown = $false
        try {
            Resolve-MacVendor -MacAddress '00:11:22:33:44' -ErrorAction Stop | Out-Null
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $true
    }
}

. (Join-Path -Path $here -ChildPath 'SnmpTestAgent.ps1')

Describe 'SNMP BER encoding' {
    InModuleScope Network-Tools {
        It 'round-trips OIDs including large arcs' {
            foreach ($oid in '1.3.6.1.2.1.31.1.1.1.6.10101', '1.3.6.1.4.1.9.9.4294967295', '2.999.3') {
                $tlv = ConvertTo-SnmpBerOidTlv -Oid $oid
                $header = Read-SnmpBerHeader -Data $tlv -Offset 0 -Limit $tlv.Length
                ConvertFrom-SnmpBerOid -Data $tlv -Start $header[1] -Length $header[2] | Should Be $oid
            }
        }

        It 'encodes the canonical v2c GetRequest bytes' {
            $pdu = ConvertTo-SnmpPduBytes -PduType 0xA0 -RequestId 1234 -Varbinds @('1.3.6.1.2.1.1.1.0')
            $message = ConvertTo-SnmpCommunityMessage -Version 1 -Community 'public' -Pdu $pdu
            [BitConverter]::ToString($message) | Should Be '30-27-02-01-01-04-06-70-75-62-6C-69-63-A0-1A-02-02-04-D2-02-01-00-02-01-00-30-0E-30-0C-06-08-2B-06-01-02-01-01-01-00-05-00'
        }

        It 'round-trips typed varbinds through a response message' {
            $varbinds = @(
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.2.2.1.8.1'; Type = 'Integer'; Value = -42 }
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.31.1.1.1.6.1'; Type = 'Counter64'; Value = [uint64]::MaxValue }
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.2.2.1.10.1'; Type = 'Counter32'; Value = [uint64]4294967295 }
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.1.5.0'; Type = 'OctetString'; Value = 'core-sw1' }
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.4.20.1.1.10.0.0.1'; Type = 'IpAddress'; Value = '10.0.0.1' }
                [PSCustomObject]@{ Oid = '1.3.6.1.2.1.1.9.9'; Type = 'NoSuchInstance'; Value = $null }
            )
            $pdu = ConvertTo-SnmpPduBytes -PduType 0xA2 -RequestId 77 -Varbinds $varbinds
            $decoded = ConvertFrom-SnmpMessage -Data (ConvertTo-SnmpCommunityMessage -Version 1 -Community 'c' -Pdu $pdu)

            $decoded.Pdu.RequestId | Should Be 77
            $decoded.Pdu.Varbinds[0].Value | Should Be -42
            $decoded.Pdu.Varbinds[1].Value | Should Be ([uint64]::MaxValue)
            $decoded.Pdu.Varbinds[1].Type | Should Be 'Counter64'
            $decoded.Pdu.Varbinds[2].Value | Should Be ([uint64]4294967295)
            ConvertTo-SnmpDisplayString $decoded.Pdu.Varbinds[3].Value | Should Be 'core-sw1'
            $decoded.Pdu.Varbinds[4].Value | Should Be '10.0.0.1'
            $decoded.Pdu.Varbinds[5].Type | Should Be 'NoSuchInstance'
        }

        It 'rejects truncated packets' {
            $thrown = $false
            try {
                ConvertFrom-SnmpMessage -Data ([byte[]]@(0x30, 0x27, 0x02, 0x01)) | Out-Null
            }
            catch {
                $thrown = $true
            }
            $thrown | Should Be $true
        }
    }
}

Describe 'SNMPv3 USM keys' {
    InModuleScope Network-Tools {
        # RFC 3414 Appendix A.3 test vectors.
        $password = [System.Text.Encoding]::ASCII.GetBytes('maplesyrup')
        $engineId = [byte[]](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)

        It 'derives the RFC 3414 MD5 localized key' {
            $key = Get-SnmpLocalizedKey -HashName MD5 -Key (ConvertTo-SnmpUsmKey -HashName MD5 -Password $password) -EngineId $engineId
            [BitConverter]::ToString($key) | Should Be '52-6F-5E-ED-9F-CC-E2-6F-89-64-C2-93-07-87-D8-2B'
        }

        It 'derives the RFC 3414 SHA-1 localized key' {
            $key = Get-SnmpLocalizedKey -HashName SHA1 -Key (ConvertTo-SnmpUsmKey -HashName SHA1 -Password $password) -EngineId $engineId
            [BitConverter]::ToString($key) | Should Be '66-95-FE-BC-92-88-E3-62-82-23-5F-C7-15-1F-12-84-97-B3-8F-3F'
        }

        It 'matches independent Blumenthal and Reeder AES-256 key extension values' {
            # Net-SNMP keytools.c extension algorithms applied to the RFC 3414 SHA-1 vector.
            $master = ConvertTo-SnmpUsmKey -HashName SHA1 -Password $password
            $blumenthal = Get-SnmpPrivacyKey -HashName SHA1 -MasterKey $master -EngineId $engineId -PrivProtocol AES256
            $reeder = Get-SnmpPrivacyKey -HashName SHA1 -MasterKey $master -EngineId $engineId -PrivProtocol AES256C
            [BitConverter]::ToString($blumenthal) | Should Be '66-95-FE-BC-92-88-E3-62-82-23-5F-C7-15-1F-12-84-97-B3-8F-3F-50-5E-07-EB-9A-F2-55-68-FA-1F-5D-BE'
            [BitConverter]::ToString($reeder) | Should Be '66-95-FE-BC-92-88-E3-62-82-23-5F-C7-15-1F-12-84-97-B3-8F-3F-9B-8B-6D-78-93-6B-A6-E7-D1-9D-FD-9C'
        }

        It 'round-trips AES-CFB with a partial final block' {
            $key = [byte[]](1..16)
            $iv = [byte[]](101..116)
            $plain = [System.Text.Encoding]::ASCII.GetBytes('scoped pdu that is not a multiple of sixteen bytes')
            $cipher = Invoke-SnmpAesCfb -Key $key -Iv $iv -Data $plain
            $cipher.Length | Should Be $plain.Length
            [System.Text.Encoding]::ASCII.GetString((Invoke-SnmpAesCfb -Key $key -Iv $iv -Data $cipher -Decrypt)) | Should Be 'scoped pdu that is not a multiple of sixteen bytes'
        }
    }
}

Describe 'Interface counter math' {
    InModuleScope Network-Tools {
        It 'handles Counter32 wrap' {
            Get-SnmpCounterDelta ([uint64]4294967000) ([uint64]704) | Should Be 1000
        }

        It 'treats a Counter64 going backwards as a discontinuity' {
            Get-SnmpCounterDelta ([uint64]5000) ([uint64]10) -Counter64 | Should BeNullOrEmpty
        }

        It 'formats bit rates with three significant digits' {
            Format-SnmpBitRate 43210000 | Should Be ('{0:0.0} Mbps' -f 43.2)
            Format-SnmpBitRate 7100000 | Should Be ('{0:0.00} Mbps' -f 7.1)
            Format-SnmpBitRate 950000 -Compact | Should Be '950k'
            Format-SnmpBitRate 0 | Should Be '0 bps'
        }
    }
}

Describe 'Bandwidth bar rendering' {
    InModuleScope Network-Tools {
        It 'renders an idle bar as blanks of the requested width' {
            $bar = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width 40 -NoColor
            $bar.Length | Should Be 40
            $bar.Trim() | Should Be ''
        }

        It 'grows inbound from the left edge and outbound from the right edge' {
            $bar = Format-BandwidthBar -InFraction 0.5 -OutFraction 0.25 -Width 40 -NoColor
            $full = [string][char]0x2588
            $bar.Substring(0, 10) | Should Be ($full * 10)
            $bar.Substring(10, 10).Trim() | Should Be ''
            $bar.Substring(35, 5) | Should Be ($full * 5)
            $bar.Substring(20, 15).Trim() | Should Be ''
        }

        It 'fills the whole bar at full utilization' {
            $bar = Format-BandwidthBar -InFraction 1 -OutFraction 1 -Width 21 -NoColor
            $bar | Should Be ([string][char]0x2588 * 21)
        }

        It 'uses partial glyphs for fractional cells' {
            $bar = Format-BandwidthBar -InFraction 0.05 -OutFraction (1 / 30) -Width 20 -Style Ascii -NoColor
            $bar[0] | Should Be '%'
            $bar[19] | Should Be '|'
        }

        It 'keeps non-zero traffic visible' {
            $bar = Format-BandwidthBar -InFraction 0.0001 -OutFraction 0 -Width 40 -NoColor
            $bar[0] | Should Not Be ' '
        }

        It 'places rate labels on either side of the centre' {
            $bar = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width 40 -InText '43 Mbps' -OutText '7 Mbps' -NoColor
            $bar | Should Be ((' ' * 12) + '43 Mbps' + ' ' + ' ' + '7 Mbps' + (' ' * 13))
        }

        It 'inverts label colours where the bar is underneath' {
            $bar = Format-BandwidthBar -InFraction 1 -OutFraction 0 -Width 20 -InText 'IN' -OutText 'OUT'
            $bar | Should Match ([regex]::Escape("$([char]27)[0;30;42mIN"))
            $bar | Should Match ([regex]::Escape("$([char]27)[0;1;91mOUT"))
        }

        It 'maps rates to the log scale between 1 kbps and link speed' {
            Get-BandwidthFraction 1000 1e9 -LogScale | Should Be 0
            Get-BandwidthFraction 1e6 1e9 -LogScale | Should Be 0.5
            Get-BandwidthFraction 1e9 1e9 -LogScale | Should Be 1
        }
    }
}

Describe 'Bandwidth rate tracking' {
    InModuleScope Network-Tools {
        It 'measures between counter changes so slow agent refreshes do not flicker' {
            # Agent refreshes its counter once per second; we poll every 0.4 s. True rate 100 Mbps.
            $tracker = @{}
            $rates = [System.Collections.Generic.List[double]]::new()
            for ($poll = 0; $poll -le 40; $poll++) {
                $time = $poll * 0.4
                $counter = [uint64](12500000 * [Math]::Floor($time))
                Update-SnmpRateTracker -Tracker $tracker -Value $counter -Time $time -AverageSeconds 3 -Counter64
                if ($time -ge 4 -and $null -ne $tracker.Rate) { $rates.Add($tracker.Rate) }
            }
            $rates.Count | Should BeGreaterThan 20
            ($rates | Measure-Object -Minimum).Minimum | Should BeGreaterThan 85000000
            ($rates | Measure-Object -Maximum).Maximum | Should BeLessThan 115000000
        }

        It 'waits for two real counter changes before reporting a rate' {
            $tracker = @{}
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]0) -Time 0 -Counter64
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]1000) -Time 0.5 -Counter64
            $tracker.Rate | Should BeNullOrEmpty
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]2000) -Time 1.5 -Counter64
            $tracker.Rate | Should Be 8000
        }

        It 'reports an idle counter as zero' {
            $tracker = @{}
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]5) -Time 0 -Counter64
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]5) -Time 4 -Counter64
            $tracker.Rate | Should Be 0
        }

        It 'restarts after a Counter64 discontinuity' {
            $tracker = @{}
            foreach ($step in 0..3) {
                Update-SnmpRateTracker -Tracker $tracker -Value ([uint64](1000 * $step + 100000)) -Time $step -Counter64
            }
            $tracker.Rate | Should Be 8000
            Update-SnmpRateTracker -Tracker $tracker -Value ([uint64]10) -Time 4 -Counter64
            $tracker.Rate | Should BeNullOrEmpty
        }
    }
}

Describe 'Bandwidth monitor state' {
    InModuleScope Network-Tools {
        $interface = [PSCustomObject]@{ Index = 1; Name = 'GigabitEthernet1/0/1'; Alias = 'uplink'; Description = 'GigabitEthernet1/0/1'; SpeedBps = 1e9; OperStatus = 1; HighCapacity = $true; TypeId = 6 }
        $counters = {
            param ($In, $Out, $InErrors)
            [PSCustomObject]@{ InOctets = [uint64]$In; OutOctets = [uint64]$Out; InErrors = [uint64]$InErrors; OutErrors = [uint64]0; InDiscards = [uint64]0; OutDiscards = [uint64]0; OperStatus = 1 }
        }
        $newState = {
            param ([object[]]$Interfaces = @($interface))
            @{
                Target = 'sw'; SysName = 'sw'; SysDescr = ''; UpTime = 100; VersionLabel = 'v2c'; IntervalSeconds = 0.5; AverageSeconds = 3
                View = 'Grid'; NameTruncation = 'Start'; BarStyle = 'Block'; LogScale = $false; ShowAll = $false; ShowTotals = $true
                Sort = 'Index'; Scroll = 0; PageSize = 10; ScrollInfo = ''; PollMs = 0; PollCount = 0; Now = 0.0; LastError = $null; LastSample = $null
                Rows = @($Interfaces | ForEach-Object { New-BandwidthMonitorRow $_ })
            }
        }
        $sample = {
            param ($Time, $UpTime, $Counter)
            [PSCustomObject]@{ Time = $Time; UpTime = $UpTime; Counters = @{ 1 = $Counter } }
        }

        It 'computes rates and tracks device totals plus errors since start' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 1000 (& $counters 0 0 50))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 11.0 1100 (& $counters 12500000 1250000 52))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 12.0 1200 (& $counters 25000000 2500000 53))

            $row = $state.Rows[0]
            $row.InBps | Should Be 100000000
            $row.OutBps | Should Be 10000000
            $row.InErrors | Should Be 3
            $row.TotalInErrors | Should Be 53
            Test-BandwidthFlash $row 'InErrors' 12.5 | Should Be $true
            Test-BandwidthFlash $row 'InErrors' 20.0 | Should Be $false
        }

        It 'resets rates when the agent restarts' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 5000 (& $counters 9000 9000 0))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 11.0 5100 (& $counters 19000 19000 0))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 12.0 10 (& $counters 10 10 0))
            $state.Rows[0].InBps | Should BeNullOrEmpty
        }

        It 'renders a grid frame that fits the terminal' {
            $state = & $newState
            $lines = Format-BandwidthMonitorFrame -State $state -Width 100 -Height 10 -NoColor
            $lines.Count | Should Be 10
            foreach ($line in $lines) {
                $line.Length | Should BeLessThan 100
            }
            ($lines -join "`n") | Should Match 'Gi1/0/1'
        }

        It 'fits a 52-port switch on a 30-line screen' {
            $ports = foreach ($i in 1..52) {
                [PSCustomObject]@{ Index = $i; Name = "GigabitEthernet1/0/$i"; Alias = ''; Description = ''; SpeedBps = 1e9; OperStatus = $(if ($i -eq 7) { 2 } else { 1 }); HighCapacity = $true; TypeId = 6 }
            }
            $state = & $newState $ports
            $lines = Format-BandwidthMonitorFrame -State $state -Width 120 -Height 30 -NoColor
            $cells = @($lines | Where-Object { $_ -match '^\[' })
            $cells.Count | Should Be 26
            ($lines -join "`n") | Should Match 'Gi1/0/52'
            $state.ScrollInfo | Should BeNullOrEmpty
        }

        It 'renders the errors and list views' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 1000 (& $counters 0 0 50))
            $state.View = 'Errors'
            (Format-BandwidthMonitorFrame -State $state -Width 100 -Height 10 -NoColor) -join "`n" | Should Match '50/0 Gi1/0/1 0/0'
            $state.View = 'List'
            (Format-BandwidthMonitorFrame -State $state -Width 120 -Height 10 -NoColor) -join "`n" | Should Match 'InErr'
        }

        It 'handles monitor keys' {
            $state = & $newState
            $key = { param ($Char, $ConsoleKey) [System.ConsoleKeyInfo]::new($Char, $ConsoleKey, $false, $false, $false) }
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 's' ([System.ConsoleKey]::S)) | Should Be $true
            $state.Sort | Should Be 'Name'
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 'v' ([System.ConsoleKey]::V)) | Out-Null
            $state.View | Should Be 'Errors'
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 'l' ([System.ConsoleKey]::L)) | Out-Null
            $state.LogScale | Should Be $true
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 'e' ([System.ConsoleKey]::E)) | Out-Null
            $state.ShowTotals | Should Be $false
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 'a' ([System.ConsoleKey]::A)) | Out-Null
            $state.AverageSeconds | Should Be 5
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[0] | Should Match 'avg 5s'
            foreach ($n in 1..3) { Invoke-BandwidthMonitorKey -State $state -Key (& $key 'a' ([System.ConsoleKey]::A)) | Out-Null }
            $state.AverageSeconds | Should Be 0
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[0] | Should Match 'avg off'
            Invoke-BandwidthMonitorKey -State $state -Key (& $key '+' ([System.ConsoleKey]::OemPlus)) | Out-Null
            $state.IntervalSeconds | Should Be 1
            Invoke-BandwidthMonitorKey -State $state -Key (& $key '-' ([System.ConsoleKey]::OemMinus)) | Out-Null
            Invoke-BandwidthMonitorKey -State $state -Key (& $key '-' ([System.ConsoleKey]::OemMinus)) | Out-Null
            $state.IntervalSeconds | Should Be 0.25
            Invoke-BandwidthMonitorKey -State $state -Key (& $key 'q' ([System.ConsoleKey]::Q)) | Should Be $false
        }

        It 'records link changes and shows them in the header' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 1000 (& $counters 0 0 0))
            $down = & $counters 0 0 0
            $down.OperStatus = 2
            Update-BandwidthMonitorState -State $state -Sample (& $sample 11.0 1100 $down)

            $state.Rows[0].LinkChangedAt | Should Be 11.0
            $state.Events[-1].Text | Should Be 'GigabitEthernet1/0/1 down'
            $state.Now = 23.0
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[1] | Should Match 'GigabitEthernet1/0/1 down 12s ago'
        }

        It 'alerts on ports whose errors are increasing' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 1000 (& $counters 0 0 50))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 11.0 1100 (& $counters 0 0 60))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 12.0 1200 (& $counters 0 0 65))

            $header = (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[1]
            $header | Should Match 'GigabitEthernet1/0/1 \+15'
            $header | Should Match 'err/disc in 65/0 out 0/0'
            $state.Now = 30.0
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[1] | Should Not Match '\+15'
        }

        It 'flags an agent restart and stale data' {
            $state = & $newState
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 5000 (& $counters 0 0 0))
            Update-BandwidthMonitorState -State $state -Sample (& $sample 11.0 10 (& $counters 0 0 0))
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[1] | Should Match 'agent restarted'
            $state.Now = 30.0
            (Format-BandwidthMonitorFrame -State $state -Width 200 -Height 8 -NoColor)[0] | Should Match 'STALE 19s'
        }

        It 'shows CPU and memory and keeps the header inside narrow terminals' {
            $state = & $newState
            $state.CpuLoads = @(10.0, 90.0)
            $state.MemUsedBytes = 128MB
            $state.MemTotalBytes = 256MB
            Update-BandwidthMonitorState -State $state -Sample (& $sample 10.0 1000 (& $counters 0 0 0))

            $wide = Format-BandwidthMonitorFrame -State $state -Width 220 -Height 8 -NoColor
            $wide[1] | Should Match 'CPU \[.*\] +50%'
            $wide[1] | Should Match 'Mem \[.*\] +50% 128M/256M'
            foreach ($width in 60, 80, 120) {
                foreach ($line in (Format-BandwidthMonitorFrame -State $state -Width $width -Height 8 -NoColor)[0..1]) {
                    $line.Length | Should BeLessThan $width
                }
            }
        }
    }
}

Describe 'Grid labels' {
    InModuleScope Network-Tools {
        It 'formats compact rates' {
            Format-SnmpBitRateShort 5000 | Should Be '5Kb'
            Format-SnmpBitRateShort 8300000 | Should Be ('{0:0.#}Mb' -f 8.3)
            Format-SnmpBitRateShort 43210000 | Should Be '43Mb'
            Format-SnmpBitRateShort 1e9 | Should Be '1Gb'
            Format-SnmpBitRateShort 512 | Should Be '512b'
            Format-SnmpBitRateShort 0 | Should Be '0'
        }

        It 'abbreviates well-known interface prefixes' {
            Format-SnmpInterfaceLabel 'TenGigabitEthernet1/1/4' 20 -Abbreviate | Should Be 'Te1/1/4'
            Format-SnmpInterfaceLabel 'GigabitEthernet1/0/12' 10 | Should Be 'Gi1/0/12'
            Format-SnmpInterfaceLabel 'ether1' 20 -Abbreviate | Should Be 'ether1'
        }

        It 'keeps the end of long names by default and the start on request' {
            Format-SnmpInterfaceLabel 'customer-uplink-ae12' 8 | Should Be ([string][char]0x2026 + 'nk-ae12')
            Format-SnmpInterfaceLabel 'customer-uplink-ae12' 8 -Truncate End | Should Be ('custome' + [char]0x2026)
        }

        It 'drops rates before squeezing the port name too far' {
            $text = Get-BandwidthCellText -Name 'Gi1/0/1' -Width 12 -InText '950Kb' -OutText '1.2Gb'
            $text.Label | Should Be 'Gi1/0/1'
            $text.InText | Should Be ''
        }

        It 'aligns readouts across cells that share a label slot' {
            $short = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width 40 -Label 'lo' -LabelWidth 10 -InText '5Kb' -OutText '1Gb' -NoColor
            $long = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width 40 -Label 'vlan2010' -LabelWidth 10 -InText '72Mb' -OutText '936Kb' -NoColor
            # Slot starts at column 15: in texts end at column 14, out texts start at column 26.
            $short.Substring(11, 3) | Should Be '5Kb'
            $long.Substring(10, 4) | Should Be '72Mb'
            $short.Substring(26, 3) | Should Be '1Gb'
            $long.Substring(26, 5) | Should Be '936Kb'
        }

        It 'centres the label with rates beside it' {
            $bar = Format-BandwidthBar -InFraction 0 -OutFraction 0 -Width 30 -Label 'Gi1/0/1' -InText '5Kb' -OutText '8Mb' -NoColor
            $bar | Should Be ((' ' * 7) + '5Kb Gi1/0/1 8Mb' + (' ' * 8))
        }
    }
}

Describe 'Get-SnmpInterface' {
    $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 3)
    try {
        It 'discovers interfaces over v2c with 64-bit counters where available' {
            $result = @(Get-SnmpInterface -ComputerName 127.0.0.1 -Port $agent.Port -V2c -Community public)

            $result.Count | Should Be 4
            $result[0].PSObject.TypeNames[0] | Should Be 'NetworkTools.SnmpInterface'
            $result[0].Name | Should Be 'Gi1/0/1'
            $result[0].Alias | Should Be 'test port 1'
            $result[0].SpeedMbps | Should Be 1000
            $result[0].HighCapacity | Should Be $true
            ($result | Where-Object Name -eq 'Vlan100').HighCapacity | Should Be $false
            ($result | Where-Object Index -eq 3).OperStatus | Should Be 'down'
            ($result | Where-Object Index -eq 2).InErrors | Should BeGreaterThan 199
        }

        It 'filters interfaces by name pattern' {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port -Interface 'Gi1/0/2', 'Vlan*')
            ($result.Name -join ',') | Should Be 'Gi1/0/2,Vlan100'
        }

        It 'samples rates and error deltas' {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port -Interface 'Gi1/0/2' -SampleSeconds 1)
            $result[0].InBitsPerSec | Should BeGreaterThan 15000000
            $result[0].InBitsPerSec | Should BeLessThan 25000000
            $result[0].InErrorsDelta | Should BeGreaterThan 0
            $result[0].InRate | Should Match 'Mbps$'
        }

        It 'works over SNMPv1 with 32-bit counters' {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port -V1)
            $result.Count | Should Be 4
            @($result | Where-Object HighCapacity).Count | Should Be 0
        }

        It 'reads CPU, memory and location for the monitor header' {
            $result = & (Get-Module Network-Tools) {
                param ($Port)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port
                try {
                    $inventory = Get-SnmpInterfaceInventory -Session $session -IncludeHostResources
                    $sample = Get-SnmpInterfaceSample -Session $session -Interfaces $inventory.Interfaces -HostResources $inventory.HostResources
                    [PSCustomObject]@{ Inventory = $inventory; Sample = $sample }
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port

            $result.Inventory.SysLocation | Should Be 'lab rack 3'
            ($result.Inventory.HostResources.CpuIndexes -join ',') | Should Be '1,2'
            $result.Inventory.HostResources.Ram.TotalBytes | Should Be 268435456
            ($result.Sample.CpuLoads -join ',') | Should Be '12,35'
            $result.Sample.MemUsedBytes | Should Be 134217728
        }

        It 'reports a timeout for a wrong community' {
            $message = $null
            try {
                Get-SnmpInterface 127.0.0.1 -Port $agent.Port -Community wrong -TimeoutMs 200 -Retries 0 -ErrorAction Stop | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }
            $message | Should Match 'No SNMP response'
        }

        It 'rejects conflicting version switches' {
            $thrown = $false
            try {
                Get-SnmpInterface 127.0.0.1 -Port $agent.Port -V1 -V2c -ErrorAction Stop | Out-Null
            }
            catch {
                $thrown = $true
            }
            $thrown | Should Be $true
        }
    }
    finally {
        Stop-SnmpTestAgent $agent
    }

    $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 6) -MaxResponseVarbinds 10
    try {
        It 'splits requests when the agent answers tooBig' {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port)
            $result.Count | Should Be 7
            $result[0].InOctets | Should Not BeNullOrEmpty
        }
    }
    finally {
        Stop-SnmpTestAgent $agent
    }
}

Describe 'Get-SnmpInterface over SNMPv3' {
    $user = @{ UserName = 'monitor'; AuthProtocol = 'SHA256'; AuthPassword = 'authpass123'; PrivProtocol = 'AES'; PrivPassword = 'privpass123' }
    $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 2) -V3User $user -HideEngineTime
    try {
        It 'reads counters with authPriv (SHA-256/AES) after a time-window resync' {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port @user)
            $result.Count | Should Be 3
            $result[0].Name | Should Be 'Gi1/0/1'
        }

        It 'recovers when its running clock estimate is ahead of a newer authenticated report' {
            & (Get-Module Network-Tools) {
                param ($Port, $Credentials)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port @Credentials
                try {
                    $oid = $script:IfMib.SysName
                    $null = Invoke-SnmpGet -Session $session -Oid $oid
                    $lastTime = $session.LatestReceivedEngineTime
                    $session.EngineTimeSyncedAt -= 201
                    $estimate = Get-SnmpEngineTime $session
                    Start-Sleep -Milliseconds 1100

                    $values = Invoke-SnmpGet -Session $session -Oid $oid
                    (ConvertTo-SnmpDisplayString $values[$oid].Value) | Should Be 'test-agent'
                    $session.LatestReceivedEngineTime | Should BeGreaterThan $lastTime
                    (Get-SnmpEngineTime $session) | Should BeLessThan ($estimate - 150)
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $user
        }

        It 'accepts SecureString passwords' {
            $secure = @{
                UserName     = 'monitor'
                AuthProtocol = 'SHA256'
                AuthPassword = ConvertTo-SecureString 'authpass123' -AsPlainText -Force
                PrivPassword = ConvertTo-SecureString 'privpass123' -AsPlainText -Force
            }
            @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port @secure).Count | Should Be 3
        }

        It 'reports a wrong auth password clearly' {
            $message = $null
            try {
                Get-SnmpInterface 127.0.0.1 -Port $agent.Port -UserName monitor -AuthProtocol SHA256 -AuthPassword 'wrongpass1' -PrivPassword 'privpass123' -TimeoutMs 1000 -Retries 0 -ErrorAction Stop | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }
            $message | Should Match 'authentication failed'
        }

        It 'reports a wrong privacy password clearly' {
            $message = $null
            try {
                Get-SnmpInterface 127.0.0.1 -Port $agent.Port -UserName monitor -AuthProtocol SHA256 -AuthPassword 'authpass123' -PrivPassword 'wrongpriv1' -TimeoutMs 1000 -Retries 0 -ErrorAction Stop | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }
            $message | Should Match 'decryption failed'
        }

        It 'reports an unknown user' {
            $message = $null
            try {
                Get-SnmpInterface 127.0.0.1 -Port $agent.Port -UserName nobody -AuthPassword 'authpass123' -TimeoutMs 1000 -Retries 0 -ErrorAction Stop | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }
            $message | Should Match "user 'nobody' is not known"
        }

    }
    finally {
        Stop-SnmpTestAgent $agent
    }

    $user = @{ UserName = 'legacy'; AuthProtocol = 'MD5'; AuthPassword = 'authpass123'; PrivProtocol = 'DES'; PrivPassword = 'privpass123' }
    $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1) -V3User $user
    try {
        It 'reads counters with MD5/DES' {
            @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port @user).Count | Should Be 2
        }
    }
    finally {
        Stop-SnmpTestAgent $agent
    }
}

Describe 'Invoke-BandwidthMonitor' {
    It 'is exported with the Invoke-BwMon alias' {
        (Get-Command Invoke-BwMon).ResolvedCommand.Name | Should Be 'Invoke-BandwidthMonitor'
    }

    It 'exposes v1, v2c and v3 options' {
        $parameters = (Get-Command Invoke-BandwidthMonitor).Parameters.Keys
        foreach ($name in 'V1', 'V2c', 'V3', 'Community', 'UserName', 'AuthProtocol', 'PrivProtocol', 'IntervalSeconds', 'BarStyle') {
            $parameters -contains $name | Should Be $true
        }
    }

    It 'requires an interactive terminal before creating an SNMP session' {
        Mock Test-BandwidthMonitorTerminal -ModuleName Network-Tools { $false }
        Mock New-SnmpSession -ModuleName Network-Tools { throw 'Monitor reached session creation.' }

        { Invoke-BandwidthMonitor -ComputerName 127.0.0.1 } | Should Throw 'needs an interactive terminal'
        Assert-MockCalled New-SnmpSession -ModuleName Network-Tools -Times 0 -Exactly -Scope It
    }
}

Describe 'SNMP security diagnostic reports' {
    It 'reads discovery and unknown-user reports without decoding their varbind values' {
        $user = @{ UserName = 'monitor'; AuthPassword = 'authpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1) -V3User $user
        $module = Get-Module Network-Tools
        $session = $null
        try {
            $session = & $module {
                param ($Port)
                New-SnmpSession -ComputerName 127.0.0.1 -Port $Port -UserName nobody -AuthPassword 'authpass123' -TimeoutMs 1000 -Retries 0
            } $agent.Port
            Mock ConvertFrom-SnmpVarbindList -ModuleName Network-Tools { throw 'Diagnostic values were decoded.' }
            & $module { param ($Session) Initialize-SnmpV3Engine $Session } $session
            { & $module { param ($Session) Invoke-SnmpGet -Session $Session -Oid $script:IfMib.SysName } $session } |
                Should Throw "user 'nobody' is not known"
            Assert-MockCalled ConvertFrom-SnmpVarbindList -ModuleName Network-Tools -Times 0 -Exactly -Scope It
        }
        finally {
            & $module { param ($Session) Close-SnmpSession $Session } $session
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security delayed Reports' {
    $credentials = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = 'privpass123' }
    $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials -HideEngineTime -ReportDelayMs 450
    try {
        It 'accepts a discovery reply after a later attempt has been sent' {
            & (Get-Module Network-Tools) {
                param ($Port, $Credentials, $ExpectedEngine)
                $session = New-SnmpSession 127.0.0.1 -Port $Port @Credentials -TimeoutMs 300 -Retries 4
                try {
                    $nextId = $session.NextId
                    Initialize-SnmpV3Engine -Session $session
                    (Test-SnmpBytesEqual $session.EngineId $ExpectedEngine) | Should Be $true
                    ($session.NextId - $nextId) | Should BeGreaterThan 1
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $credentials $agent.Engine.Id
        }

        It 'resynchronizes from an authenticated time Report for an earlier attempt' {
            & (Get-Module Network-Tools) {
                param ($Port, $Credentials)
                $session = New-SnmpSession 127.0.0.1 -Port $Port @Credentials -TimeoutMs 2000 -Retries 6
                try {
                    Initialize-SnmpV3Engine -Session $session
                    $session.TimeoutMs = 300
                    $oid = $script:IfMib.SysName
                    $values = Invoke-SnmpGet -Session $session -Oid $oid
                    (ConvertTo-SnmpDisplayString $values[$oid].Value) | Should Be 'test-agent'
                    $session.TimeTrusted | Should Be $true
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $credentials
        }
    }
    finally {
        Stop-SnmpTestAgent $agent
    }

    It 'reports a stale authenticated clock without retrying' {
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials
        try {
            & (Get-Module Network-Tools) {
                param ($Port, $Credentials)
                $session = New-SnmpSession 127.0.0.1 -Port $Port @Credentials -TimeoutMs 700 -Retries 3
                try {
                    $oid = $script:IfMib.SysName
                    $null = Invoke-SnmpGet -Session $session -Oid $oid
                    $session.EngineTime += 220
                    $session.LatestReceivedEngineTime += 220
                    $nextId = $session.NextId
                    $watch = [System.Diagnostics.Stopwatch]::StartNew()
                    { Invoke-SnmpGet -Session $session -Oid $oid } | Should Throw 'Check the agent clock and engineBoots'
                    ($session.NextId - $nextId) | Should Be 2
                    $watch.ElapsedMilliseconds | Should BeLessThan 1400
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $credentials
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security engine transitions' {
    It 'handles a genuine engine change while the client is <State>' -TestCases @(
        @{ State = 'unconfirmed'; Confirmed = $false }
        @{ State = 'confirmed'; Confirmed = $true }
    ) {
        param ($Confirmed)
        $credentials = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = 'privpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials
        try {
            & (Get-Module Network-Tools) {
                param ($Agent, $Credentials, $Confirmed)
                $session = New-SnmpSession 127.0.0.1 -Port $Agent.Port @Credentials -TimeoutMs 500 -Retries 0
                try {
                    $oid = $script:IfMib.SysName
                    Initialize-SnmpV3Engine -Session $session
                    if ($Confirmed) {
                        $null = Invoke-SnmpGet -Session $session -Oid $oid
                    }
                    $session.TimeTrusted | Should Be $Confirmed
                    $initialEngine = $session.EngineId
                    $initialAuth = $session.AuthKey
                    $initialPriv = $session.PrivKey
                    $lastSync = $session.EngineTimeSyncedAt
                    $Agent.Engine.Id = [byte[]](128, 0, 31, 136, 4, 12, 3)

                    if ($Confirmed) {
                        { Invoke-SnmpGet -Session $session -Oid $oid } | Should Throw 'Start a new session'
                        $Agent.Engine.Discoveries | Should Be 1
                        (Test-SnmpBytesEqual $session.EngineId $initialEngine) | Should Be $true
                        [object]::ReferenceEquals($initialAuth, $session.AuthKey) | Should Be $true
                        [object]::ReferenceEquals($initialPriv, $session.PrivKey) | Should Be $true
                        $session.EngineTimeSyncedAt | Should Be $lastSync
                    } else {
                        $values = Invoke-SnmpGet -Session $session -Oid $oid
                        (ConvertTo-SnmpDisplayString $values[$oid].Value) | Should Be 'test-agent'
                        $session.TimeTrusted | Should Be $true
                        (Test-SnmpBytesEqual $session.EngineId $Agent.Engine.Id) | Should Be $true
                        $Agent.Engine.Discoveries | Should Be 2
                        @($initialAuth | Where-Object { $_ -ne 0 }).Count | Should Be 0
                        @($initialPriv | Where-Object { $_ -ne 0 }).Count | Should Be 0
                    }
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent $credentials $Confirmed
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'advises opening a new session when authentication never confirms discovery' {
        $credentials = @{ UserName = 'monitor'; AuthPassword = 'authpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials
        try {
            { Get-SnmpInterface 127.0.0.1 -Port $agent.Port -UserName unknown -AuthPassword 'authpass123' -TimeoutMs 500 -Retries 0 } |
                Should Throw 'Start a new session'
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'preserves provisional state and clears candidate keys when rediscovery cannot authenticate' {
        $credentials = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = 'privpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials
        Mock Test-SnmpV3Mac -ModuleName Network-Tools -ParameterFilter { $null -ne $Session.TestCandidateKeys } {
            param ($Session)
            $Session.TestCandidateKeys.Auth = $Session.AuthKey
            $Session.TestCandidateKeys.Priv = $Session.PrivKey
            return $false
        }
        try {
            & (Get-Module Network-Tools) {
                param ($Agent, $Credentials)
                $session = New-SnmpSession 127.0.0.1 -Port $Agent.Port @Credentials -TimeoutMs 500 -Retries 0
                try {
                    Initialize-SnmpV3Engine -Session $session
                    $initialEngine = $session.EngineId
                    $initialAuth = $session.AuthKey
                    $initialPriv = $session.PrivKey
                    $lastSync = $session.EngineTimeSyncedAt
                    $session.TestCandidateKeys = @{}
                    $Agent.Engine.Id = [byte[]](128, 0, 31, 136, 4, 12, 4)
                    { Invoke-SnmpGet -Session $session -Oid $script:IfMib.SysName } | Should Throw 'Start a new session'

                    $Agent.Engine.Discoveries | Should Be 2
                    $session.TimeTrusted | Should Be $false
                    (Test-SnmpBytesEqual $session.EngineId $initialEngine) | Should Be $true
                    [object]::ReferenceEquals($initialAuth, $session.AuthKey) | Should Be $true
                    [object]::ReferenceEquals($initialPriv, $session.PrivKey) | Should Be $true
                    $session.EngineTimeSyncedAt | Should Be $lastSync
                    foreach ($buffer in $session.TestCandidateKeys.Auth, $session.TestCandidateKeys.Priv) {
                        $buffer.Length | Should BeGreaterThan 0
                        @($buffer | Where-Object { $_ -ne 0 }).Count | Should Be 0
                    }
                    { Invoke-SnmpGet -Session $session -Oid $script:IfMib.SysName } | Should Throw 'Start a new session'
                    $Agent.Engine.Discoveries | Should Be 2
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent $credentials
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'includes restart advice when rediscovery authenticates but the request times out' {
        $credentials = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = 'privpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib) -V3User $credentials -HideEngineTime -ResponseDelayMs 1100
        try {
            & (Get-Module Network-Tools) {
                param ($Agent, $Credentials)
                $session = New-SnmpSession 127.0.0.1 -Port $Agent.Port @Credentials -TimeoutMs 500 -Retries 0
                try {
                    Initialize-SnmpV3Engine -Session $session
                    $initialEngine = $session.EngineId
                    $nextId = $session.NextId
                    $Agent.Engine.Id = [byte[]](128, 0, 31, 136, 4, 12, 5)
                    { Invoke-SnmpGet -Session $session -Oid $script:IfMib.SysName } | Should Throw 'Start a new session'
                    ($session.NextId - $nextId) | Should Be 6
                    $session.TimeTrusted | Should Be $false
                    (Test-SnmpBytesEqual $session.EngineId $initialEngine) | Should Be $true
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent $credentials
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security credential validation' {
    InModuleScope Network-Tools {
        $invalidOptions = @(
            @{ Scenario = 'an authentication protocol without a user'; Options = @{ AuthProtocol = 'SHA256' }; Parameter = 'UserName' }
            @{ Scenario = 'a privacy protocol without a user'; Options = @{ PrivProtocol = 'AES' }; Parameter = 'UserName' }
            @{ Scenario = 'an authentication password without a user'; Options = @{ AuthPassword = 'authpass123' }; Parameter = 'UserName' }
            @{ Scenario = 'a context without a user'; Options = @{ Context = 'test-context' }; Parameter = 'UserName' }
            @{ Scenario = 'USM options on v1'; Options = @{ V1 = $true; UserName = 'monitor'; AuthPassword = 'authpass123' }; Parameter = 'v1|v3|community' }
            @{ Scenario = 'USM options on v2c'; Options = @{ V2c = $true; UserName = 'monitor'; AuthPassword = 'authpass123' }; Parameter = 'v2c|v3|community' }
            @{ Scenario = 'a bound null authentication password'; Options = @{ UserName = 'monitor'; AuthPassword = $null }; Parameter = 'AuthPassword' }
            @{ Scenario = 'an empty privacy password'; Options = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = '' }; Parameter = 'PrivPassword' }
            @{ Scenario = 'an empty SecureString'; Options = @{ UserName = 'monitor'; AuthPassword = [System.Security.SecureString]::new() }; Parameter = 'AuthPassword' }
            @{ Scenario = 'a short authentication password'; Options = @{ UserName = 'monitor'; AuthPassword = 'seven77' }; Parameter = 'AuthPassword' }
            @{
                Scenario  = 'a short multibyte SecureString'
                Options   = @{
                    UserName     = 'monitor'
                    AuthPassword = 'authpass123'
                    PrivPassword = ConvertTo-SecureString (([string][char]0x00E9) * 4) -AsPlainText -Force
                }
                Parameter = 'PrivPassword'
            }
        )

        It 'rejects <Scenario> before sending a request' -TestCases $invalidOptions {
            param ($Options, $Parameter)

            Mock Send-SnmpDatagram { throw 'Credential validation reached the SNMP transport.' }
            $message = $null
            try {
                Get-SnmpInterface -ComputerName 127.0.0.1 @Options -ErrorAction Stop | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }

            Assert-MockCalled Send-SnmpDatagram -Times 0 -Exactly -Scope It
            $message | Should Match $Parameter
        }

        It 'preserves <VersionLabel> when deliberately selected' -TestCases @(
            @{ Options = @{}; VersionLabel = 'v2c' }
            @{ Options = @{ UserName = 'monitor' }; VersionLabel = 'v3 NoAuthNoPriv' }
            @{ Options = @{ UserName = 'monitor'; AuthPassword = 'authpass' }; VersionLabel = 'v3 AuthNoPriv' }
            @{ Options = @{ UserName = 'monitor'; AuthPassword = 'authpass'; PrivPassword = 'privpass' }; VersionLabel = 'v3 AuthPriv' }
        ) {
            param ($Options, $VersionLabel)

            $session = New-SnmpSession -ComputerName 127.0.0.1 @Options
            try {
                $session.VersionLabel | Should Be $VersionLabel
            }
            finally {
                Close-SnmpSession $session
            }
        }

        It 'rejects a missing authentication password before the monitor sends a request' {
            Mock Test-BandwidthMonitorTerminal { $true }
            Mock Send-SnmpDatagram { throw 'Credential validation reached the SNMP transport.' }

            { Invoke-BandwidthMonitor -ComputerName 127.0.0.1 -UserName monitor -AuthPassword $null } |
                Should Throw 'AuthPassword'
            Assert-MockCalled Send-SnmpDatagram -Times 0 -Exactly -Scope It
        }
    }
}

Describe 'SNMP security outgoing v3 requests' {
    InModuleScope Network-Tools {
        $readPlainScopedPdu = {
            param ([byte[]]$Bytes)

            $message = Read-SnmpBerHeader -Data $Bytes -Offset 0 -Limit $Bytes.Length
            $offset = $message[1]
            $end = $offset + $message[2]
            # Skip the version, header data, and security parameters in the locally encoded request.
            for ($field = 0; $field -lt 3; $field++) {
                $header = Read-SnmpBerHeader -Data $Bytes -Offset $offset -Limit $end
                $offset = $header[1] + $header[2]
            }
            ConvertFrom-SnmpScopedPdu -Data $Bytes -Offset $offset -Limit $end
        }

        It 'omits the configured context from discovery and keeps it in the protected request' {
            $context = 'inventory-test-context'
            $session = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor -AuthPassword 'authpass' -PrivPassword 'privpass' -Context $context
            try {
                $discoveryPdu = ConvertTo-SnmpPduBytes -PduType 0xA0 -RequestId 100 -Varbinds @()
                $discovery = ConvertTo-SnmpV3Message -Session $session -MsgId 100 -Pdu $discoveryPdu -Discovery
                $requestPdu = ConvertTo-SnmpPduBytes -PduType 0xA0 -RequestId 101 -Varbinds @('1.3.6.1.2.1.1.1.0')
                Set-SnmpV3Engine -Session $session -EngineId ([byte[]]@(128, 0, 0, 1, 2)) -Boots 1 -Time 10
                $request = ConvertTo-SnmpV3Message -Session $session -MsgId 101 -Pdu $requestPdu
                $encoded = ConvertFrom-SnmpMessage -Data $request
                $plain = Unprotect-SnmpScopedPdu -Session $session -Cipher $encoded.EncryptedPdu -Salt $encoded.PrivParams -Boots $encoded.EngineBoots -Time $encoded.EngineTime

                (ConvertFrom-SnmpScopedPdu -Data $plain -Offset 0 -Limit $plain.Length).ContextName | Should Be $context
                ((& $readPlainScopedPdu $discovery).ContextName -ceq '') | Should Be $true
            }
            finally {
                Close-SnmpSession $session
            }
        }

        It 'assigns a fresh message ID to a timed-out attempt and keeps the logical request ID' {
            Mock Send-SnmpDatagram -ParameterFilter { $null -ne $Session.TestSentMessages } {
                param ($Session, $Bytes)
                $Session.TestSentMessages.Add($Bytes)
            }
            Mock Receive-SnmpDatagram -ParameterFilter { $null -ne $Session.TestSentMessages } {
                param ($Session, $TimeoutMs)
                Start-Sleep -Milliseconds ([Math]::Max(0, $TimeoutMs))
                return $null
            }

            $session = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor -TimeoutMs 10 -Retries 1
            $session.TestSentMessages = [System.Collections.Generic.List[byte[]]]::new()
            try {
                Set-SnmpV3Engine -Session $session -EngineId ([byte[]]@(128, 0, 0, 1, 2)) -Boots 1 -Time 10
                $request = @{ PduType = 0xA0; Oids = @('1.3.6.1.2.1.1.1.0') }
                { Invoke-SnmpExchange -Session $session -Requests @($request) } | Should Throw 'after 2 attempts'

                $session.TestSentMessages.Count | Should Be 2
                $first = ConvertFrom-SnmpMessage -Data $session.TestSentMessages[0]
                $second = ConvertFrom-SnmpMessage -Data $session.TestSentMessages[1]
                ($first.MsgId -eq $second.MsgId) | Should Be $false
                $firstScoped = & $readPlainScopedPdu $session.TestSentMessages[0]
                $secondScoped = & $readPlainScopedPdu $session.TestSentMessages[1]
                $secondScoped.Pdu.RequestId | Should Be $firstScoped.Pdu.RequestId
            }
            finally {
                Close-SnmpSession $session
            }
        }
    }

    It 'accepts the first authenticated reply after sending a timeout retry' {
        $user = @{ UserName = 'monitor'; AuthPassword = 'authpass123'; PrivPassword = 'privpass123' }
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1) -V3User $user -ResponseDelayMs 500
        try {
            & (Get-Module Network-Tools) {
                param ($Port, $Credentials)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port @Credentials -TimeoutMs 300 -Retries 3
                try {
                    Initialize-SnmpV3Engine -Session $session
                    $firstId = $session.NextId
                    $oid = $script:IfMib.SysName
                    $values = Invoke-SnmpGet -Session $session -Oid $oid
                    (ConvertTo-SnmpDisplayString $values[$oid].Value) | Should Be 'test-agent'
                    ($session.NextId - $firstId) | Should BeGreaterThan 2
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $user
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security table walks' {
    It 'finishes a paged table in numeric order across an OID arc boundary' {
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 10)
        try {
            $bindings = & (Get-Module Network-Tools) {
                param ($Port)

                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port -Retries 0
                $session.MaxRepetitions = 2
                try {
                    Invoke-SnmpWalk -Session $session -RootOid $script:IfMib.IfDescr
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port
            (($bindings.Oid | ForEach-Object { ($_ -split '\.')[-1] }) -join ',') | Should Be '1,2,3,4,5,6,7,8,9,10,100'
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security telemetry and display text' {
    InModuleScope Network-Tools {
        It 'ignores an uptime varbind with the wrong MIB type' {
            Mock Invoke-SnmpGet {
                @{ $script:IfMib.SysUpTime = [PSCustomObject]@{ Type = 'Counter32'; Value = 100 } }
            }
            $session = @{ Clock = [System.Diagnostics.Stopwatch]::StartNew() }
            $sample = Get-SnmpInterfaceSample -Session $session -Interfaces @()
            ($null -eq $sample.UpTime) | Should Be $true
        }

        It 'keeps valid CPU load and ignores an out-of-range reading' {
            Mock Invoke-SnmpGet {
                @{
                    "$($script:IfMib.HrProcessorLoad).1" = [PSCustomObject]@{ Type = 'Integer'; Value = 101 }
                    "$($script:IfMib.HrProcessorLoad).2" = [PSCustomObject]@{ Type = 'Integer'; Value = 100 }
                }
            }
            $session = @{ Clock = [System.Diagnostics.Stopwatch]::StartNew() }
            $sample = Get-SnmpInterfaceSample -Session $session -Interfaces @() -HostResources @{ CpuIndexes = @(1, 2) }
            ($sample.CpuLoads -join ',') | Should Be '100'
        }

        It 'preserves the last good sample when a later row fails validation' {
            $rows = @(1, 2 | ForEach-Object { New-BandwidthMonitorRow @{ Index = $_; Name = "port$_"; OperStatus = 1; HighCapacity = $true } })
            $state = @{ Rows = $rows; PollCount = 0 }
            $readings = {
                param ($Status, [uint64]$Octets)

                [PSCustomObject]@{
                    OperStatus = $Status
                    InOctets = $Octets; OutOctets = $Octets
                    InErrors = [uint64]0; OutErrors = [uint64]0
                    InDiscards = [uint64]0; OutDiscards = [uint64]0
                }
            }
            $good = [PSCustomObject]@{
                Time = 1.0; UpTime = 100
                Counters = @{ 1 = & $readings 1 1000; 2 = & $readings 1 1000 }
            }
            Update-BandwidthMonitorState -State $state -Sample $good

            $incomplete = [PSCustomObject]@{
                Time = 2.0; UpTime = 200
                Counters = @{ 1 = & $readings 2 2000; 2 = & $readings 'unknown' 2000 }
            }
            & {
                $ErrorActionPreference = 'Stop'
                try {
                    Update-BandwidthMonitorState -State $state -Sample $incomplete
                }
                catch {
                    # The test checks committed state whether rejection throws or returns.
                }
            }

            $state.LastSuccess | Should Be 1
            $state.LastSample.Time | Should Be 1
            $state.UpTime | Should Be 100
            $state.PollCount | Should Be 1
            ($state.Rows.OperStatus -join ',') | Should Be '1,1'
            $state.Events.Count | Should Be 0

            $recovered = [PSCustomObject]@{ Time = 3.0; UpTime = 300; Counters = $good.Counters }
            Update-BandwidthMonitorState -State $state -Sample $recovered
            $state.LastSuccess | Should Be 3
            $state.PollCount | Should Be 2
        }

        It 'normalizes label separators and keeps international characters' {
            $name = "r$([char]0x00E9)seau"
            $raw = [System.Text.Encoding]::UTF8.GetBytes("$name$([char]0x2028)port$([char]0x2029)1")
            $label = ConvertTo-SnmpDisplayString $raw
            $label.StartsWith($name, [StringComparison]::Ordinal) | Should Be $true
            $label.Contains('port') | Should Be $true
            ($label -match '[\p{Zl}\p{Zp}]') | Should Be $false
        }
    }
}

Describe 'SNMP security key lifecycle' {
    InModuleScope Network-Tools {
        It 'wipes the community buffer and releases the string reference on close' {
            $session = New-SnmpSession -ComputerName 127.0.0.1 -Community 'test-community'
            $bytes = $session.CommunityBytes
            Close-SnmpSession $session
            ($null -eq $session.Community) | Should Be $true
            @($bytes | Where-Object { $_ -ne 0 }).Count | Should Be 0
        }

        It 'wipes the DES IV if the cipher fails while encrypting or decrypting' -TestCases @(
            @{ Decrypt = $false }
            @{ Decrypt = $true }
        ) {
            param ($Decrypt)

            Mock Invoke-SnmpDesCbc {
                param ($Iv)
                $script:observedTestIv = $Iv
                throw 'Synthetic DES failure'
            }
            $script:observedTestIv = $null
            $session = @{ PrivProtocol = 'DES'; PrivKey = [byte[]](1..16) }
            $block = [byte[]]::new(8)
            try {
                if ($Decrypt) {
                    { Unprotect-SnmpScopedPdu -Session $session -Cipher $block -Salt $block -Boots 1 -Time 1 } |
                        Should Throw 'Synthetic DES failure'
                } else {
                    { Protect-SnmpScopedPdu -Session $session -Plain $block -Boots 1 -Time 1 -Allocator ([uint64[]]@(0)) } |
                        Should Throw 'Synthetic DES failure'
                }
                $script:observedTestIv.Length | Should Be 8
                @($script:observedTestIv | Where-Object { $_ -ne 0 }).Count | Should Be 0
            }
            finally {
                $script:observedTestIv = $null
                Clear-SnmpBytes $session.PrivKey
            }
        }
        It 'wipes the owned master and localized key arrays when the session closes' {
            $session = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor -AuthPassword 'authpass' -PrivPassword 'privpass'
            try {
                Set-SnmpV3Engine -Session $session -EngineId ([byte[]]@(128, 0, 0, 1, 2)) -Boots 1 -Time 10
                $buffers = @($session.AuthMasterKey, $session.PrivMasterKey, $session.AuthKey, $session.PrivKey)
                foreach ($buffer in $buffers) {
                    @($buffer | Where-Object { $_ -ne 0 }).Count | Should BeGreaterThan 0
                }
            }
            finally {
                Close-SnmpSession $session
            }
            foreach ($buffer in $buffers) {
                @($buffer | Where-Object { $_ -ne 0 }).Count | Should Be 0
            }
        }

        It 'wipes replaced localized keys and retains the new keys' {
            $session = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor -AuthPassword 'authpass' -PrivPassword 'privpass'
            try {
                Set-SnmpV3Engine -Session $session -EngineId ([byte[]]@(128, 0, 0, 1, 2)) -Boots 1 -Time 10
                $oldAuth = $session.AuthKey
                $oldPriv = $session.PrivKey
                Set-SnmpV3Engine -Session $session -EngineId ([byte[]]@(128, 0, 0, 1, 3)) -Boots 1 -Time 10

                @($oldAuth | Where-Object { $_ -ne 0 }).Count | Should Be 0
                @($oldPriv | Where-Object { $_ -ne 0 }).Count | Should Be 0
                @($session.AuthKey | Where-Object { $_ -ne 0 }).Count | Should BeGreaterThan 0
                @($session.PrivKey | Where-Object { $_ -ne 0 }).Count | Should BeGreaterThan 0
            }
            finally {
                Close-SnmpSession $session
            }
        }
    }
}

Describe 'SNMP security AES-CFB allocation and correctness' {
    InModuleScope Network-Tools {
        It 'matches the NIST CFB128 vector through a partial second block' {
            # NIST SP 800-38A F.3.13/F.3.14, truncated to 21 bytes.
            $key = [byte[]]@(0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C)
            $iv = [byte[]](0..15)
            $plaintext = [byte[]]@(0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E)
            $ciphertext = [byte[]]@(0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A, 0xC8, 0xA6, 0x45, 0x37, 0xA0)
            $encrypted = Invoke-SnmpAesCfb -Key $key -Iv $iv -Data $plaintext
            $decrypted = Invoke-SnmpAesCfb -Key $key -Iv $iv -Data $ciphertext -Decrypt
            $usmDecrypted = Unprotect-SnmpScopedPdu -Session @{ PrivProtocol = 'AES'; PrivKey = $key } -Cipher $ciphertext -Salt ([byte[]](8..15)) -Boots 0x00010203 -Time 0x04050607

            [BitConverter]::ToString($encrypted) | Should Be ([BitConverter]::ToString($ciphertext))
            [BitConverter]::ToString($decrypted) | Should Be ([BitConverter]::ToString($plaintext))
            [BitConverter]::ToString($usmDecrypted) | Should Be ([BitConverter]::ToString($plaintext))
        }

        It 'allocates less than three times as much when doubling the buffer (<Direction>)' -TestCases @(
            @{ Direction = 'encrypt'; Decrypt = $false }
            @{ Direction = 'decrypt'; Decrypt = $true }
        ) {
            param ($Decrypt)

            $key = [byte[]](1..16)
            $iv = [byte[]](17..32)
            $small = [byte[]]::new(2048)
            $large = [byte[]]::new(4096)
            $measure = {
                param ([byte[]]$Buffer)
                $start = [GC]::GetAllocatedBytesForCurrentThread()
                $null = Invoke-SnmpAesCfb -Key $key -Iv $iv -Data $Buffer -Decrypt:$Decrypt
                [GC]::GetAllocatedBytesForCurrentThread() - $start
            }

            $null = & $measure $small
            $null = & $measure $large
            $smallBytes = & $measure $small
            $largeBytes = & $measure $large
            ($largeBytes / $smallBytes) | Should BeLessThan 3.0
        }
    }
}

Describe 'SNMP security v3 response policy' {
    InModuleScope Network-Tools {
        $engine = [byte[]](0x80, 0x00, 0x1F, 0x88, 0x04, 1, 2, 3)
        $credentials = @{ UserName = 'monitor'; AuthProtocol = 'SHA256'; AuthPassword = 'authpass123'; PrivProtocol = 'AES'; PrivPassword = 'privpass123' }
        $request = @{ PduType = 0xA0; Oids = @('1.3.6.1.2.1.1.5.0') }

        function New-PolicySession {
            param ([byte[]]$EngineId = $engine)
            $session = New-SnmpSession -ComputerName 127.0.0.1 @credentials
            Set-SnmpV3Engine -Session $session -EngineId $EngineId -Boots 7 -Time 1000
            $session
        }
        function New-PolicyReply {
            # A message from $Session (acting as the agent) answering msgID 900 / request-id 500.
            param ($Session, [int]$RequestId = 500, [string]$Level, [int]$PduType = 0xA2, [string]$Oid = '1.3.6.1.2.1.1.5.0', [string]$User, [int]$MsgId = 900)
            $type = if ($PduType -eq 0xA8) { 'Counter32' } else { 'OctetString' }
            $value = if ($PduType -eq 0xA8) { 1 } else { 'sw1' }
            $pdu = ConvertTo-SnmpPduBytes -PduType $PduType -RequestId $RequestId -Varbinds @([PSCustomObject]@{ Oid = $Oid; Type = $type; Value = $value })
            $parameters = @{ Session = $Session; MsgId = $MsgId; Pdu = $pdu; Reportable = $false }
            if ($Level) { $parameters.SecurityLevel = $Level }
            if ($PSBoundParameters.ContainsKey('User')) { $parameters.UserName = $User }
            ConvertTo-SnmpV3Message @parameters
        }
        function Read-PolicyReply {
            param ($Client, [byte[]]$Data)
            Read-SnmpExchangeReply -Session $Client -Data $Data -Pending @{ 900 = @{ Index = 0; Request = $request; RequestId = 500; Key = 900 } }
        }

        It 'completes a genuine AuthPriv response' {
            $client = New-PolicySession
            $agent = New-PolicySession
            try {
                $reply = Read-PolicyReply $client (New-PolicyReply $agent)
                $reply.Action | Should Be 'Complete'
                $reply.Pdu.Varbinds[0].Oid | Should Be '1.3.6.1.2.1.1.5.0'
                $client.TimeTrusted | Should Be $true
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }

        It 'ignores a reply with <Scenario>' -TestCases @(
            @{ Scenario = 'no protection'; Reply = @{ Level = 'NoAuthNoPriv' } }
            @{ Scenario = 'authentication but no privacy'; Reply = @{ Level = 'AuthNoPriv' } }
            @{ Scenario = 'another user'; Reply = @{ User = 'other' } }
            @{ Scenario = 'a different request-id'; Reply = @{ RequestId = 501 } }
            @{ Scenario = 'a non-Response PDU'; Reply = @{ PduType = 0xA0 } }
            @{ Scenario = 'a substituted binding'; Reply = @{ Oid = '1.3.6.1.2.1.1.6.0' } }
        ) {
            param ($Reply)

            $client = New-PolicySession
            $agent = New-PolicySession
            try {
                $bytes = New-PolicyReply $agent @Reply
                Read-PolicyReply $client $bytes | Should BeNullOrEmpty
                $client.TimeTrusted | Should Be $false
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }

        It 'ignores replies from another engine, with another context, or with a bad MAC' {
            $client = New-PolicySession
            $agent = New-PolicySession
            $other = New-PolicySession -EngineId ([byte[]](0x80, 0, 0, 9, 9, 9))
            try {
                Read-PolicyReply $client (New-PolicyReply $other) | Should BeNullOrEmpty

                $agent.Context = 'other-context'
                $agent.ContextBytes = [System.Text.Encoding]::UTF8.GetBytes('other-context')
                Read-PolicyReply $client (New-PolicyReply $agent) | Should BeNullOrEmpty
                $agent.Context = ''
                $agent.ContextBytes = [byte[]]::new(0)

                $tampered = New-PolicyReply $agent
                $parsed = ConvertFrom-SnmpMessage -Data $tampered -Envelope
                $last = $parsed.AuthOffset + $parsed.AuthParams.Length - 1
                $tampered[$last] = $tampered[$last] -bxor 1
                Read-PolicyReply $client $tampered | Should BeNullOrEmpty

                # The genuine reply still completes afterwards.
                (Read-PolicyReply $client (New-PolicyReply $agent)).Action | Should Be 'Complete'
            }
            finally {
                foreach ($session in $client, $agent, $other) { Close-SnmpSession $session }
            }
        }

        It 'enforces the USM time window and follows a reboot without rewinding the clock' {
            $client = New-PolicySession
            $agent = New-PolicySession
            $setAgentTime = { param ($Boots, $Time) $agent.EngineBoots = $Boots; $agent.EngineTime = $Time; $agent.EngineTimeSyncedAt = $agent.Clock.Elapsed.TotalSeconds }
            try {
                [void](Read-PolicyReply $client (New-PolicyReply $agent))
                $now = Get-SnmpEngineTime $client

                & $setAgentTime 6 $now
                Read-PolicyReply $client (New-PolicyReply $agent) | Should BeNullOrEmpty
                & $setAgentTime 7 ($now - 151)
                Read-PolicyReply $client (New-PolicyReply $agent) | Should BeNullOrEmpty
                & $setAgentTime 7 ($now - 150)
                (Read-PolicyReply $client (New-PolicyReply $agent)).Action | Should Be 'Complete'
                (Get-SnmpEngineTime $client) -ge $now | Should Be $true
                & $setAgentTime 2147483647 0
                Read-PolicyReply $client (New-PolicyReply $agent) | Should BeNullOrEmpty
                & $setAgentTime 8 5
                (Read-PolicyReply $client (New-PolicyReply $agent)).Action | Should Be 'Complete'
                $client.EngineBoots | Should Be 8
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }

        It 'treats an unauthenticated Report as a hint that changes no engine, key, or clock state' {
            $client = New-PolicySession
            $rogue = New-PolicySession -EngineId ([byte[]](0x80, 0, 0, 9, 9, 9))
            try {
                $key = [BitConverter]::ToString($client.AuthKey)
                $reply = Read-PolicyReply $client (New-PolicyReply $rogue -PduType 0xA8 -Oid '1.3.6.1.6.3.15.1.1.2.0' -Level NoAuthNoPriv -User 'monitor')
                $reply.Action | Should Be 'Hint'
                $reply.Hint | Should Be 'notInTimeWindows'
                [BitConverter]::ToString($client.AuthKey) | Should Be $key
                (Test-SnmpBytesEqual $client.EngineId $engine) | Should Be $true
                $client.EngineBoots | Should Be 7
                $client.TimeTrusted | Should Be $false
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $rogue
            }
        }

        It 'keeps the confirmed engine and keys when a diagnostic hint survives to timeout' {
            Mock Send-SnmpDatagram -ParameterFilter { $Session.TestDiagnosticTimeout } {}
            Mock Receive-SnmpDatagram -ParameterFilter { $Session.TestDiagnosticTimeout } {
                param ($Session, $TimeoutMs)
                if (-not $Session.TestHintDelivered) {
                    $Session.TestHintDelivered = $true
                    return , ([byte[]]::new(1))
                }
                Start-Sleep -Milliseconds ([Math]::Max(0, $TimeoutMs))
                return $null
            }
            Mock Read-SnmpExchangeReply -ParameterFilter { $Session.TestDiagnosticTimeout } {
                param ($Pending)
                [PSCustomObject]@{ Action = 'Hint'; Hint = 'unknownEngineIDs'; Entry = @($Pending.Values)[0] }
            }
            Mock Find-SnmpV3Engine -ParameterFilter { $Session.TestDiagnosticTimeout } { throw 'Unexpected rediscovery' }
            $client = New-PolicySession
            $client.TestDiagnosticTimeout = $true
            $client.TimeoutMs = 250
            $client.Retries = 0
            try {
                Update-SnmpV3Clock -Session $client -Boots 7 -Time 1000
                $key = $client.AuthKey
                $lastSync = $client.EngineTimeSyncedAt
                { Invoke-SnmpExchange -Session $client -Requests @($request) } | Should Throw 'Start a new session'
                Assert-MockCalled Find-SnmpV3Engine -Times 0 -Exactly -Scope It
                (Test-SnmpBytesEqual $client.EngineId $engine) | Should Be $true
                [object]::ReferenceEquals($key, $client.AuthKey) | Should Be $true
                $client.EngineTimeSyncedAt | Should Be $lastSync
            }
            finally {
                Close-SnmpSession $client
            }
        }

        It 'resynchronizes an AuthPriv session from a signed AuthNoPriv time Report' {
            $client = New-PolicySession
            $agent = New-PolicySession
            try {
                $agent.EngineBoots = 9
                $agent.EngineTime = 77
                $agent.EngineTimeSyncedAt = $agent.Clock.Elapsed.TotalSeconds
                $reply = Read-PolicyReply $client (New-PolicyReply $agent -PduType 0xA8 -Oid '1.3.6.1.6.3.15.1.1.2.0' -Level AuthNoPriv)
                $reply.Action | Should Be 'Resend'
                $client.EngineBoots | Should Be 9
                $client.TimeTrusted | Should Be $true
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }

        It 'resends each pending request only until it has used the corrected clock' {
            $client = New-PolicySession
            $agent = New-PolicySession
            try {
                Update-SnmpV3Clock -Session $client -Boots 7 -Time 1000
                $originalClock = $client.ClockVersion
                $first = @{ Key = 900; RequestId = 500; Request = $request; AttemptClocks = @{ 900 = $originalClock } }
                $second = @{ Key = 901; RequestId = 501; Request = $request; AttemptClocks = @{ 901 = $originalClock } }
                $other = @{ Key = 902; RequestId = 502; Request = $request; AttemptClocks = @{ 902 = $originalClock } }
                $pending = @{ 900 = $first; 901 = $second; 902 = $other }
                $timeReport = @{ Session = $agent; PduType = 0xA8; Oid = '1.3.6.1.6.3.15.1.1.2.0'; Level = 'AuthNoPriv' }

                $agent.EngineTime = 1010
                $reply = Read-SnmpExchangeReply -Session $client -Data (New-PolicyReply $agent -MsgId 902 -RequestId 502) -Pending $pending
                $reply.Action | Should Be 'Complete'
                $client.ClockVersion | Should Be $originalClock
                $reply = Read-SnmpExchangeReply -Session $client -Data (New-PolicyReply @timeReport -MsgId 900 -RequestId 500) -Pending $pending
                $reply.Action | Should Be 'Resend'
                $correctedClock = $client.ClockVersion
                $correctedClock | Should BeGreaterThan $originalClock

                $first.Key = 903
                $first.AttemptClocks[903] = $correctedClock
                $agent.EngineTime += 2
                Read-SnmpExchangeReply -Session $client -Data (New-PolicyReply @timeReport -MsgId 900 -RequestId 500) -Pending $pending |
                    Should BeNullOrEmpty
                $reply = Read-SnmpExchangeReply -Session $client -Data (New-PolicyReply @timeReport -MsgId 901 -RequestId 501) -Pending $pending
                $reply.Action | Should Be 'Resend'
                $client.ClockVersion | Should Be $correctedClock
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }

        It 'does not decode varbinds for an unmatched or badly authenticated message' {
            Mock ConvertFrom-SnmpVarbindList { throw 'varbinds were decoded' }
            $client = New-PolicySession
            $agent = New-PolicySession
            try {
                Read-SnmpExchangeReply -Session $client -Data (New-PolicyReply $agent) -Pending @{} | Should BeNullOrEmpty
                $tampered = New-PolicyReply $agent
                $parsed = ConvertFrom-SnmpMessage -Data $tampered -Envelope
                $tampered[$parsed.AuthOffset] = $tampered[$parsed.AuthOffset] -bxor 1
                Read-PolicyReply $client $tampered | Should BeNullOrEmpty
                Assert-MockCalled ConvertFrom-SnmpVarbindList -Times 0 -Exactly -Scope It
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }
    }
}

Describe 'SNMP security community replies and peer binding' {
    InModuleScope Network-Tools {
        $request = @{ PduType = 0xA0; Oids = @('1.3.6.1.2.1.1.5.0') }
        $binding = [PSCustomObject]@{ Oid = '1.3.6.1.2.1.1.5.0'; Type = 'OctetString'; Value = 'sw1' }
        function Read-CommunityReply {
            param ($Session, [string]$Community, [int]$PduType = 0xA2, [object[]]$Varbinds = @($binding))
            $bytes = ConvertTo-SnmpCommunityMessage 1 $Community (ConvertTo-SnmpPduBytes -PduType $PduType -RequestId 500 -Varbinds $Varbinds)
            Read-SnmpExchangeReply -Session $Session -Data $bytes -Pending @{ 500 = @{ Index = 0; Request = $request; RequestId = 500; Key = 500 } }
        }

        It 'accepts only a Response with the exact community and the requested bindings' {
            $session = New-SnmpSession -ComputerName 127.0.0.1 -Community 'Secret'
            try {
                (Read-CommunityReply $session 'Secret').Action | Should Be 'Complete'
                Read-CommunityReply $session 'secret' | Should BeNullOrEmpty
                Read-CommunityReply $session 'Secret' -PduType 0xA8 | Should BeNullOrEmpty
                Read-CommunityReply $session 'Secret' -Varbinds @() | Should BeNullOrEmpty
            }
            finally {
                Close-SnmpSession $session
            }
        }

        It 'ignores a datagram from another port and still receives the agent reply' {
            $fakeAgent = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
            $rogue = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
            $session = New-SnmpSession -ComputerName 127.0.0.1 -Port ([System.Net.IPEndPoint]$fakeAgent.Client.LocalEndPoint).Port
            try {
                Send-SnmpDatagram $session ([byte[]](1, 2, 3))
                $client = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, ([System.Net.IPEndPoint]$session.Socket.Client.LocalEndPoint).Port)
                [void]$rogue.Send([byte[]](9, 9, 9), 3, $client)
                Receive-SnmpDatagram $session 300 | Should BeNullOrEmpty
                [void]$rogue.Send([byte[]](9, 9, 9), 3, $client)
                [void]$fakeAgent.Send([byte[]](7, 7, 7), 3, $client)
                $received = Receive-SnmpDatagram $session 1000
                $received[0] | Should Be 7
            }
            finally {
                Close-SnmpSession $session
                $fakeAgent.Dispose()
                $rogue.Dispose()
            }
        }
    }
}

Describe 'SNMP security engine discovery' {
    InModuleScope Network-Tools {
        $engine = [byte[]](0x80, 0x00, 0x1F, 0x88, 0x04, 1, 2, 3)

        It 'accepts only the unknownEngineIDs Report and leaves the engine unset otherwise' {
            Mock Send-SnmpDatagram {
                param ($Session, $Bytes)
                $Session.TestLastMsgId = (ConvertFrom-SnmpMessage -Data $Bytes).MsgId
            }
            Mock Receive-SnmpDatagram {
                param ($Session, $TimeoutMs)
                if ($Session.TestReplies.Count -eq 0) { return $null }
                $next = $Session.TestReplies.Dequeue()
                $pdu = ConvertTo-SnmpPduBytes -PduType $next.PduType -RequestId 1 -Varbinds @([PSCustomObject]@{ Oid = $next.Oid; Type = 'Counter32'; Value = 1 })
                return , (ConvertTo-SnmpV3Message -Session $Session.TestAgent -MsgId $Session.TestLastMsgId -Pdu $pdu -SecurityLevel NoAuthNoPriv -Reportable $false -UserName '')
            }

            $agent = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor
            Set-SnmpV3Engine -Session $agent -EngineId $engine -Boots 3 -Time 30
            $client = New-SnmpSession -ComputerName 127.0.0.1 -UserName monitor -TimeoutMs 200 -Retries 0
            $client.TestAgent = $agent
            $client.TestReplies = [System.Collections.Generic.Queue[object]]::new()
            try {
                $client.TestReplies.Enqueue(@{ PduType = 0xA2; Oid = '1.3.6.1.2.1.1.5.0' })
                $client.TestReplies.Enqueue(@{ PduType = 0xA8; Oid = '1.3.6.1.6.3.15.1.1.2.0' })
                $client.TestReplies.Enqueue(@{ PduType = 0xA8; Oid = '1.3.6.1.6.3.15.1.1.4.0' })
                $found = Find-SnmpV3Engine -Session $client
                (Test-SnmpBytesEqual $found.EngineId $engine) | Should Be $true
                $client.TestReplies.Count | Should Be 0

                $client.TestReplies.Enqueue(@{ PduType = 0xA2; Oid = '1.3.6.1.2.1.1.5.0' })
                { Initialize-SnmpV3Engine -Session $client } | Should Throw 'engine discovery timed out'
                $client.EngineId | Should BeNullOrEmpty
            }
            finally {
                Close-SnmpSession $client
                Close-SnmpSession $agent
            }
        }
    }
}

Describe 'SNMP security walk limits' {
    InModuleScope Network-Tools {
        $column = '1.3.6.1.2.1.2.2.1.2'
        function New-WalkSession {
            # Each page is a comma-separated list of the OID suffixes one GetBulk reply returns.
            param ([string[]]$Pages)
            $session = @{
                Version = 1
                MaxRepetitions = 25
                ComputerName = 'fake'
                WalkLimits = @{ Seconds = 60; Rows = 5; Bytes = 16MB }
                Clock = [System.Diagnostics.Stopwatch]::StartNew()
            }
            $session.TestPages = [System.Collections.Generic.Queue[string[]]]::new()
            foreach ($page in $Pages) {
                $session.TestPages.Enqueue([string[]]@($page.Split(',') | ForEach-Object { "$column.$_" }))
            }
            $session
        }
        Mock Invoke-SnmpExchange -ParameterFilter { $null -ne $Session.TestPages } {
            param ($Session, $Requests)
            $page = $Session.TestPages.Dequeue()
            $bindings = @($page | ForEach-Object { [PSCustomObject]@{ Oid = $_; Type = 'OctetString'; Value = [byte[]](65) } })
            return , @([PSCustomObject]@{ ErrorStatus = 0; ErrorIndex = 0; Varbinds = $bindings })
        }

        It 'rejects an OID that goes backwards after a numeric 9 to 10 step' {
            $session = New-WalkSession -Pages '9,10,2'
            { Invoke-SnmpWalk -Session $session -RootOid $column -Name ifDescr } | Should Throw 'out of order'
        }

        It 'stops with an incomplete-table error when the row budget is exhausted' {
            $session = New-WalkSession -Pages '1,2,3,4', '5,6,7,8'
            { Invoke-SnmpWalk -Session $session -RootOid $column -Name ifDescr } | Should Throw '5-row limit'
        }

        It 'ends normally at the subtree boundary within budget' {
            $session = New-WalkSession -Pages '1,2'
            $session.TestPages.Clear()
            $session.TestPages.Enqueue([string[]]@("$column.1", "$column.2", '1.3.6.1.2.1.2.2.1.3.1'))
            (Invoke-SnmpWalk -Session $session -RootOid $column).Count | Should Be 2
        }

        It 'rejects an empty page after retaining earlier rows' {
            $session = New-WalkSession -Pages '1'
            $session.TestPages.Enqueue([string[]]@())
            { Invoke-SnmpWalk -Session $session -RootOid $column -Name ifDescr } | Should Throw 'empty page'
        }
    }

    It 'applies one inventory <Limit> budget across columns' -TestCases @(
        @{ Limit = 'Rows'; Value = 3; Diagnostic = '3-row' }
        @{ Limit = 'Bytes'; Value = 350; Diagnostic = '350-byte' }
    ) {
        param ($Limit, $Value, $Diagnostic)
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1)
        try {
            & (Get-Module Network-Tools) {
                param ($Port, $Limit, $Value, $Diagnostic)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port
                try {
                    $session.InventoryLimits[$Limit] = $Value
                    { Get-SnmpInterfaceInventory -Session $session } | Should Throw "$Diagnostic limit walking IfType"
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port $Limit $Value $Diagnostic
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'bounds the initial inventory request by the shared deadline' {
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1) -ResponseDelayMs 1500
        try {
            & (Get-Module Network-Tools) {
                param ($Port)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port
                try {
                    $session.InventoryLimits.Seconds = 0.1
                    $watch = [System.Diagnostics.Stopwatch]::StartNew()
                    { Get-SnmpInterfaceInventory -Session $session } | Should Throw 'the inventory is incomplete'
                    $watch.ElapsedMilliseconds | Should BeLessThan 1250
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'propagates the shared limit when an optional host-resource column exceeds both limits' {
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 1)
        try {
            & (Get-Module Network-Tools) {
                param ($Port)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port
                try {
                    $session.WalkLimits.Rows = 1
                    $budget = @{
                        Limits = @{ Rows = 1; Bytes = 16MB }
                        Deadline = @{ AtMs = $session.Clock.ElapsedMilliseconds + 5000; Message = 'Inventory deadline exceeded.' }
                        Rows = 0; Bytes = 0; Exhausted = $false
                    }
                    { Get-SnmpHostResources -Session $session -Budget $budget } |
                        Should Throw '1-row limit walking hrProcessorLoad'
                    $budget.Exhausted | Should Be $true
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }
}

Describe 'SNMP security strict BER decoding' {
    InModuleScope Network-Tools {
        It 'rejects malformed OIDs' {
            { ConvertFrom-SnmpBerOid ([byte[]](0x2B, 0x86)) 0 2 } | Should Throw 'unterminated'
            { ConvertFrom-SnmpBerOid ([byte[]](0x2B, 0x80, 0x01)) 0 3 } | Should Throw 'non-minimal'
            { ConvertFrom-SnmpBerOid ([byte[]](0x2B, 0x90, 0x80, 0x80, 0x80, 0x00)) 0 6 } | Should Throw 'out of range'
            $long = [byte[]](@(0x2B) + @(1) * 130)
            { ConvertFrom-SnmpBerOid $long 0 $long.Length } | Should Throw '128'
        }

        It 'rejects integers and counters of the wrong width' {
            { ConvertFrom-SnmpBerSigned ([byte[]](0, 0, 0, 0, 1)) 0 5 } | Should Throw 'INTEGER'
            { ConvertFrom-SnmpBerSigned ([byte[]]@(0)) 0 0 } | Should Throw 'INTEGER'
            { ConvertFrom-SnmpBerUnsigned ([byte[]](0, 0, 0, 0, 0, 1)) 0 6 -Bits 32 } | Should Throw '32-bit'
            { ConvertFrom-SnmpBerUnsigned ([byte[]](1, 0, 0, 0, 0, 0, 0, 0, 0)) 0 9 -Bits 64 } | Should Throw '64-bit'
        }

        It 'rejects malformed varbinds and trailing message data' {
            $trailing = [byte[]](0x30, 0x07, 0x06, 0x01, 0x2B, 0x05, 0x00, 0x05, 0x00)
            { ConvertFrom-SnmpVarbindList $trailing 0 $trailing.Length } | Should Throw 'inside a varbind'
            $wrongTag = [byte[]](0x30, 0x05, 0x04, 0x01, 0x2B, 0x05, 0x00)
            { ConvertFrom-SnmpVarbindList $wrongTag 0 $wrongTag.Length } | Should Throw 'varbind name'
            $message = ConvertTo-SnmpCommunityMessage 1 'public' (ConvertTo-SnmpPduBytes -PduType 0xA2 -RequestId 1 -Varbinds @())
            { ConvertFrom-SnmpMessage ([byte[]]($message + 0)) } | Should Throw 'trailing data'
        }

        It 'still reads maximum counters encoded with a leading zero octet' {
            ConvertFrom-SnmpBerUnsigned ([byte[]](0, 255, 255, 255, 255)) 0 5 -Bits 32 | Should Be ([uint64][uint32]::MaxValue)
            ConvertFrom-SnmpBerUnsigned ([byte[]](0, 255, 255, 255, 255, 255, 255, 255, 255)) 0 9 -Bits 64 | Should Be ([uint64]::MaxValue)
        }
    }
}

Describe 'SNMP security display text controls' {
    It 'strips bidirectional, C1 and escape controls from returned interface text' {
        $mib = New-SnmpTestMib -InterfaceCount 1
        $mib['1.3.6.1.2.1.31.1.1.1.18.1'].Value = "uplink$([char]0x202E)evil$([char]0x0085)x$([char]0x2066)y$([char]0x1B)[31mz Z$([char]0x00FC)rich"
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib $mib
        try {
            $result = @(Get-SnmpInterface 127.0.0.1 -Port $agent.Port -Interface 'Gi1/0/1')
            ($result[0].Alias -match '[\p{Cc}\u202E\u2066]') | Should Be $false
            $result[0].Alias.EndsWith("Z$([char]0x00FC)rich") | Should Be $true
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'preserves supplementary text while normalizing formatting marks and unpaired surrogates' {
        & (Get-Module Network-Tools) {
            $symbol = [char]::ConvertFromUtf32(0x1F4E1)
            $tag = [char]::ConvertFromUtf32(0xE0020)
            $inputLabel = "A$([char]0x200B)B$tag$symbol$([char]0xD800)C"
            ConvertTo-SnmpDisplayString $inputLabel | Should Be "AB$symbol C"
        }
    }
}

Describe 'SNMP display label normalization' {
    It 'removes invisible formatting marks without inserting spaces into labels' {
        & (Get-Module Network-Tools) {
            foreach ($codePoint in 0x200B, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF) {
                $mark = [char]::ConvertFromUtf32($codePoint)
                ConvertTo-SnmpDisplayString "label$($mark)1" | Should Be (ConvertTo-SnmpDisplayString 'label1')
            }
            $letter = [char]0x0645
            ConvertTo-SnmpDisplayString "$letter$([char]0x200C)$letter" | Should Be "$letter$letter"
            $symbol = [char]::ConvertFromUtf32(0x1F4E1)
            ConvertTo-SnmpDisplayString "$symbol$([char]0x200D)$symbol" | Should Be "$symbol$symbol"
        }
    }

    It 'normalizes Unicode spaces to ASCII and collapses runs' {
        & (Get-Module Network-Tools) {
            ConvertTo-SnmpDisplayString "alpha$([char]0x00A0)$([char]0x2009) beta$([char]0x3000)gamma" |
                Should Be 'alpha beta gamma'
        }
    }
}

Describe 'SNMP security privacy salts and MAC comparison' {
    InModuleScope Network-Tools {
        It 'rolls the salt counter over from 2^64-1 to 0' {
            $allocator = [uint64[]]@([uint64]::MaxValue)
            [BitConverter]::ToString((New-SnmpPrivacySalt -Allocator $allocator)) | Should Be 'FF-FF-FF-FF-FF-FF-FF-FF'
            [BitConverter]::ToString((New-SnmpPrivacySalt -Allocator $allocator)) | Should Be '00-00-00-00-00-00-00-00'
        }

        It 'never repeats a salt across interleaved sessions sharing the process allocator' {
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            $repeated = $false
            foreach ($n in 1..300) {
                if (-not $seen.Add([BitConverter]::ToString((New-SnmpPrivacySalt)))) { $repeated = $true }
            }
            $repeated | Should Be $false
            [object]::ReferenceEquals((Get-SnmpSaltAllocator), [System.AppDomain]::CurrentDomain.GetData('NetworkTools.Snmp.SaltAllocator')) | Should Be $true
        }

        It 'compares tags without regard to where they differ' {
            $tag = [byte[]](1..24)
            $first = [byte[]]$tag.Clone(); $first[0] = 0
            $last = [byte[]]$tag.Clone(); $last[23] = 0
            Test-SnmpBytesEqual $tag ([byte[]]$tag.Clone()) | Should Be $true
            Test-SnmpBytesEqual $tag $first | Should Be $false
            Test-SnmpBytesEqual $tag $last | Should Be $false
        }
    }
}

Describe 'SNMP security loopback agent bulk limit' {
    It 'caps a huge GetBulk reply and keeps answering' {
        $agent = Start-SnmpTestAgent -ModulePath $modulePath -Mib (New-SnmpTestMib -InterfaceCount 10) -MaxBulkVarbinds 5
        try {
            $result = & (Get-Module Network-Tools) {
                param ($Port)
                $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port -Retries 0
                try {
                    $bulk = (Invoke-SnmpExchange -Session $session -Requests @(@{ PduType = 0xA5; Oids = @('1.3.6.1.2.1.2.2.1.2'); NonRepeaters = 0; MaxRepetitions = 100000 }))[0]
                    $next = Invoke-SnmpGet -Session $session -Oid @('1.3.6.1.2.1.1.5.0')
                    [PSCustomObject]@{ Count = @($bulk.Varbinds).Count; Name = ConvertTo-SnmpDisplayString $next['1.3.6.1.2.1.1.5.0'].Value }
                }
                finally {
                    Close-SnmpSession $session
                }
            } $agent.Port
            $result.Count | Should Be 5
            $result.Name | Should Be 'test-agent'
        }
        finally {
            Stop-SnmpTestAgent $agent
        }
    }

    It 'trims a two-binding bulk page and still answers the next request' {
        # A regression can hang inside the agent's cleanup as well as the exchange.
        $testScript = {
            $ErrorActionPreference = 'Stop'
            $module = Import-Module $env:NETWORKTOOLS_TEST_MODULE -PassThru
            . $env:NETWORKTOOLS_TEST_AGENT
            $mib = New-SnmpTestMib -InterfaceCount 2
            $column = '1.3.6.1.2.1.2.2.1.2'
            $mib["$column.1"].Value = 'a' * 30
            $mib["$column.2"].Value = 'b' * 30
            $agent = Start-SnmpTestAgent -ModulePath $env:NETWORKTOOLS_TEST_MODULE -Mib $mib -MaxBulkBytes 64
            try {
                & $module {
                    param ($Port, $Column)
                    $session = New-SnmpSession -ComputerName 127.0.0.1 -Port $Port -TimeoutMs 1000 -Retries 0
                    try {
                        $reply = (Invoke-SnmpExchange -Session $session -Requests @(@{
                            PduType = $script:SnmpPduTypes.GetBulk; Oids = @($Column); NonRepeaters = 0; MaxRepetitions = 2
                        }))[0]
                        if ($reply.Varbinds.Count -ne 1 -or $reply.Varbinds[0].Oid -ne "$Column.1") {
                            throw 'The trimmed bulk page did not return its first binding.'
                        }
                        $values = Invoke-SnmpGet -Session $session -Oid $script:IfMib.SysName
                        if ((ConvertTo-SnmpDisplayString $values[$script:IfMib.SysName].Value) -ne 'test-agent') {
                            throw 'The fixture did not answer the next request.'
                        }
                    }
                    finally {
                        Close-SnmpSession $session
                    }
                } $agent.Port $column
            }
            finally {
                Stop-SnmpTestAgent $agent
            }
        }
        $pwshName = if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' }
        $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME $pwshName))
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardError = $true
        foreach ($argument in '-NoProfile', '-NonInteractive', '-Command', $testScript.ToString()) {
            $start.ArgumentList.Add($argument)
        }
        $start.Environment['NETWORKTOOLS_TEST_MODULE'] = (Resolve-Path -LiteralPath $modulePath).Path
        $start.Environment['NETWORKTOOLS_TEST_AGENT'] = (Join-Path $here 'SnmpTestAgent.ps1')
        $process = [System.Diagnostics.Process]::Start($start)
        try {
            $errorOutput = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(15000)) {
                throw 'The bulk-response test exceeded its 15-second deadline.'
            }
            if ($process.ExitCode -ne 0) {
                throw "The bulk-response test failed: $($errorOutput.GetAwaiter().GetResult())"
            }
        }
        finally {
            if (-not $process.HasExited) {
                $process.Kill()
                [void]$process.WaitForExit(1000)
            }
            $process.Dispose()
        }
    }
}
