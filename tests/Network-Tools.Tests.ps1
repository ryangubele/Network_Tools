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

        It 'extends privacy keys to the AES-256 key length' {
            $master = ConvertTo-SnmpUsmKey -HashName SHA1 -Password $password
            (Get-SnmpPrivacyKey -HashName SHA1 -MasterKey $master -EngineId $engineId -PrivProtocol AES256).Length | Should Be 32
            (Get-SnmpPrivacyKey -HashName SHA1 -MasterKey $master -EngineId $engineId -PrivProtocol AES256C).Length | Should Be 32
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
}
