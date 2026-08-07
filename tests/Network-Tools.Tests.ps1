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
        $thrown = $false
        $result = $null

        try {
            $result = Invoke-NetworkScan -Target '127.0.0.1/32' -TimeoutMs 50 -ThrottleLimit 4 -ResolveMacVendor
        }
        catch {
            $thrown = $true
        }

        $thrown | Should Be $false
        @($result).Count | Should Be 0
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

        $result.Vendor | Should Be 'VMware'
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
