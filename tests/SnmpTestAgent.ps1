# Loopback SNMP agent used by the Pester tests (and handy for demoing Invoke-BandwidthMonitor
# without a real device). It answers Get/GetNext/GetBulk for v1, v2c and v3 (USM) from an
# in-memory MIB, using the module's own BER/USM helpers. Counter entries can carry a Rate
# (units per second) so successive polls see traffic.
#
#   . .\tests\SnmpTestAgent.ps1
#   $agent = Start-SnmpTestAgent -ModulePath .\Network-Tools.psm1 -Mib (New-SnmpTestMib)
#   Invoke-BandwidthMonitor 127.0.0.1 -Port $agent.Port
#   Stop-SnmpTestAgent $agent

function New-SnmpTestMib {
    param ([int]$InterfaceCount = 4)

    $mib = @{}
    $add = {
        param ($Oid, $Type, $Value, $Rate = 0)
        $mib[$Oid] = @{ Type = $Type; Value = $Value; Rate = $Rate }
    }

    & $add '1.3.6.1.2.1.1.1.0' 'OctetString' 'Network-Tools loopback test agent'
    & $add '1.3.6.1.2.1.1.3.0' 'TimeTicks' 1234567 100
    & $add '1.3.6.1.2.1.1.5.0' 'OctetString' 'test-agent'
    & $add '1.3.6.1.2.1.1.6.0' 'OctetString' 'lab rack 3'

    # HOST-RESOURCES-MIB: two CPUs, 256 MiB of RAM half used, plus a disk entry to skip.
    & $add '1.3.6.1.2.1.25.3.3.1.2.1' 'Integer' 12
    & $add '1.3.6.1.2.1.25.3.3.1.2.2' 'Integer' 35
    & $add '1.3.6.1.2.1.25.2.3.1.2.65536' 'ObjectIdentifier' '1.3.6.1.2.1.25.2.1.2'
    & $add '1.3.6.1.2.1.25.2.3.1.2.131072' 'ObjectIdentifier' '1.3.6.1.2.1.25.2.1.4'
    & $add '1.3.6.1.2.1.25.2.3.1.4.65536' 'Integer' 1024
    & $add '1.3.6.1.2.1.25.2.3.1.4.131072' 'Integer' 1024
    & $add '1.3.6.1.2.1.25.2.3.1.5.65536' 'Integer' 262144
    & $add '1.3.6.1.2.1.25.2.3.1.5.131072' 'Integer' 16384
    & $add '1.3.6.1.2.1.25.2.3.1.6.65536' 'Integer' 131072
    & $add '1.3.6.1.2.1.25.2.3.1.6.131072' 'Integer' 9000

    for ($i = 1; $i -le $InterfaceCount; $i++) {
        $inRate = 1250000 * $i      # 10 Mbps per interface number
        $outRate = 125000 * $i      # 1 Mbps per interface number
        $oper = if ($i -eq 3) { 2 } else { 1 }
        & $add "1.3.6.1.2.1.2.2.1.2.$i" 'OctetString' "GigabitEthernet1/0/$i"
        & $add "1.3.6.1.2.1.2.2.1.3.$i" 'Integer' 6
        & $add "1.3.6.1.2.1.2.2.1.5.$i" 'Gauge32' 1000000000
        & $add "1.3.6.1.2.1.2.2.1.7.$i" 'Integer' 1
        & $add "1.3.6.1.2.1.2.2.1.8.$i" 'Integer' $oper
        & $add "1.3.6.1.2.1.2.2.1.10.$i" 'Counter32' ([uint64]4294967295 - 1000) $inRate
        & $add "1.3.6.1.2.1.2.2.1.13.$i" 'Counter32' 0
        & $add "1.3.6.1.2.1.2.2.1.14.$i" 'Counter32' (100 * $i) $(if ($i -eq 2) { 5 } else { 0 })
        & $add "1.3.6.1.2.1.2.2.1.16.$i" 'Counter32' 0 $outRate
        & $add "1.3.6.1.2.1.2.2.1.19.$i" 'Counter32' 7
        & $add "1.3.6.1.2.1.2.2.1.20.$i" 'Counter32' 0
        & $add "1.3.6.1.2.1.31.1.1.1.1.$i" 'OctetString' "Gi1/0/$i"
        & $add "1.3.6.1.2.1.31.1.1.1.6.$i" 'Counter64' ([uint64]1e12) $inRate
        & $add "1.3.6.1.2.1.31.1.1.1.10.$i" 'Counter64' ([uint64]5e11) $outRate
        & $add "1.3.6.1.2.1.31.1.1.1.15.$i" 'Gauge32' 1000
        & $add "1.3.6.1.2.1.31.1.1.1.18.$i" 'OctetString' "test port $i"
    }

    # A routed VLAN interface that only exposes 32-bit counters.
    & $add '1.3.6.1.2.1.2.2.1.2.100' 'OctetString' 'Vlan100'
    & $add '1.3.6.1.2.1.2.2.1.3.100' 'Integer' 136
    & $add '1.3.6.1.2.1.2.2.1.5.100' 'Gauge32' 100000000
    & $add '1.3.6.1.2.1.2.2.1.7.100' 'Integer' 1
    & $add '1.3.6.1.2.1.2.2.1.8.100' 'Integer' 1
    & $add '1.3.6.1.2.1.2.2.1.10.100' 'Counter32' 0 250000
    & $add '1.3.6.1.2.1.2.2.1.13.100' 'Counter32' 0
    & $add '1.3.6.1.2.1.2.2.1.14.100' 'Counter32' 0
    & $add '1.3.6.1.2.1.2.2.1.16.100' 'Counter32' 0 500000
    & $add '1.3.6.1.2.1.2.2.1.19.100' 'Counter32' 0
    & $add '1.3.6.1.2.1.2.2.1.20.100' 'Counter32' 0

    return $mib
}

function Start-SnmpTestAgent {
    param (
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][hashtable]$Mib,
        [string]$Community = 'public',
        # @{ UserName; AuthProtocol; AuthPassword; PrivProtocol; PrivPassword }
        [hashtable]$V3User,
        # Report boots/time as 0 during discovery to force the notInTimeWindows resync path.
        [switch]$HideEngineTime,
        # Answer Get requests carrying more varbinds than this with tooBig (0 = unlimited).
        [int]$MaxResponseVarbinds = 0,
        # Upper bounds for one GetBulk reply, whatever max-repetitions the request asks for.
        [ValidateRange(1, 10000)]
        [int]$MaxBulkVarbinds = 64,
        [ValidateRange(64, 65000)]
        [int]$MaxBulkBytes = 4096,
        [ValidateRange(0, 5000)]
        [int]$ResponseDelayMs = 0,
        [ValidateRange(0, 5000)]
        [int]$ReportDelayMs = 0,
        [int]$Port = 0
    )

    $udp = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port))
    $engine = [hashtable]::Synchronized(@{
        Id = [byte[]](@(0x80, 0x00, 0x1F, 0x88, 0x04) + [System.Text.Encoding]::ASCII.GetBytes('nt-test'))
        Discoveries = 0
    })
    $options = @{
        Community           = $Community
        V3User              = $V3User
        HideEngineTime      = [bool]$HideEngineTime
        MaxResponseVarbinds = $MaxResponseVarbinds
        MaxBulkVarbinds     = $MaxBulkVarbinds
        MaxBulkBytes        = $MaxBulkBytes
        ResponseDelayMs     = $ResponseDelayMs
        ReportDelayMs       = $ReportDelayMs
        Engine              = $engine
    }

    $agentScript = {
        param ($Udp, $ModulePath, $Mib, $Options)

        $module = Import-Module $ModulePath -PassThru -Force
        & $module {
            param ($Udp, $Mib, $Options)

            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            $sortKey = { param ($oid) ($oid.Split('.') | ForEach-Object { $_.PadLeft(10, '0') }) -join '.' }
            $ordered = @($Mib.Keys | ForEach-Object { [PSCustomObject]@{ Oid = $_; Key = (& $sortKey $_) } } |
                Sort-Object -Property Key -CaseSensitive)

            $readValue = {
                param ($oid)
                $entry = $Mib[$oid]
                $value = $entry.Value
                if ($entry.Rate) {
                    $grown = [decimal]$value + [Math]::Floor($entry.Rate * $clock.Elapsed.TotalSeconds)
                    if ($entry.Type -in 'Counter32', 'TimeTicks') {
                        $grown = $grown % [decimal]4294967296
                    }
                    $value = [uint64]$grown
                }
                [PSCustomObject]@{ Oid = $oid; Type = $entry.Type; Value = $value }
            }

            $nextOid = {
                param ($oid)
                $key = & $sortKey $oid
                foreach ($item in $ordered) {
                    if ([string]::CompareOrdinal($item.Key, $key) -gt 0) {
                        return $item.Oid
                    }
                }
                return $null
            }

            $answer = {
                param ($pdu, $version)
                $out = [System.Collections.Generic.List[object]]::new()
                $errorStatus = 0
                $errorIndex = 0
                $requested = @($pdu.Varbinds)

                if ($pdu.PduType -eq 0xA0) {
                    if ($Options.MaxResponseVarbinds -gt 0 -and $requested.Count -gt $Options.MaxResponseVarbinds) {
                        $errorStatus = 1
                    }
                    for ($i = 0; $i -lt $requested.Count -and $errorStatus -eq 0; $i++) {
                        $oid = $requested[$i].Oid
                        if ($Mib.ContainsKey($oid)) {
                            $out.Add((& $readValue $oid))
                        } elseif ($version -eq 0) {
                            $errorStatus = 2
                            $errorIndex = $i + 1
                        } else {
                            $out.Add([PSCustomObject]@{ Oid = $oid; Type = 'NoSuchInstance'; Value = $null })
                        }
                    }
                } elseif ($pdu.PduType -eq 0xA1) {
                    for ($i = 0; $i -lt $requested.Count; $i++) {
                        $next = & $nextOid $requested[$i].Oid
                        if ($next) {
                            $out.Add((& $readValue $next))
                        } elseif ($version -eq 0) {
                            $errorStatus = 2
                            $errorIndex = $i + 1
                            break
                        } else {
                            $out.Add([PSCustomObject]@{ Oid = $requested[$i].Oid; Type = 'EndOfMibView'; Value = $null })
                        }
                    }
                } elseif ($pdu.PduType -eq 0xA5) {
                    # Limit GetBulk work and keep at least one binding so a walk can progress.
                    $limit = [Math]::Max(1, $Options.MaxBulkVarbinds)
                    $nonRepeaters = [Math]::Min([Math]::Max(0, $pdu.ErrorStatus), $requested.Count)
                    $repetitions = [Math]::Max(1, $pdu.ErrorIndex)
                    for ($i = 0; $i -lt $nonRepeaters -and $out.Count -lt $limit; $i++) {
                        $next = & $nextOid $requested[$i].Oid
                        $out.Add($(if ($next) { & $readValue $next } else { [PSCustomObject]@{ Oid = $requested[$i].Oid; Type = 'EndOfMibView'; Value = $null } }))
                    }
                    $cursors = @($requested | Select-Object -Skip $nonRepeaters | ForEach-Object { $_.Oid })
                    $ended = [bool[]]::new($cursors.Count)
                    for ($r = 0; $r -lt $repetitions -and $cursors.Count -gt 0 -and $out.Count -lt $limit; $r++) {
                        if ($ended -notcontains $false) {
                            break
                        }
                        for ($c = 0; $c -lt $cursors.Count -and $out.Count -lt $limit; $c++) {
                            $next = if ($ended[$c]) { $null } else { & $nextOid $cursors[$c] }
                            if ($next) {
                                $out.Add((& $readValue $next))
                                $cursors[$c] = $next
                            } else {
                                $out.Add([PSCustomObject]@{ Oid = $cursors[$c]; Type = 'EndOfMibView'; Value = $null })
                                $ended[$c] = $true
                            }
                        }
                    }
                    while ($out.Count -gt 1 -and (ConvertTo-SnmpVarbindListTlv -Varbinds @($out)).Length -gt $Options.MaxBulkBytes) {
                        $keep = [Math]::Max(1, [int][Math]::Floor($out.Count * 0.8))
                        $out.RemoveRange($keep, $out.Count - $keep)
                    }
                }

                if ($errorStatus -ne 0) {
                    $out = $requested
                }
                return , (ConvertTo-SnmpPduBytes -PduType 0xA2 -RequestId $pdu.RequestId -ErrorStatus $errorStatus -ErrorIndex $errorIndex -Varbinds @($out))
            }

            $agentSession = $null
            if ($Options.V3User) {
                $user = $Options.V3User
                $sessionParams = @{
                    ComputerName = '127.0.0.1'
                    V3           = $true
                    UserName     = $user.UserName
                }
                foreach ($name in 'AuthProtocol', 'AuthPassword', 'PrivProtocol', 'PrivPassword') {
                    if ($user[$name]) {
                        $sessionParams[$name] = $user[$name]
                    }
                }
                $agentSession = New-SnmpSession @sessionParams
                # The agent only needs the session's keys, not its client socket. Close-SnmpSession
                # would also wipe the keys, so it runs when the agent stops (below).
                $agentSession.Socket.Dispose()
                $agentSession.Socket = $null
                Set-SnmpV3Engine -Session $agentSession -EngineId $Options.Engine.Id -Boots 7 -Time 4242
            }

            $sendReport = {
                param ($remote, $message, $reportOid, $level)
                $requestId = if ($message.Pdu) { $message.Pdu.RequestId } else { 0 }
                $reportPdu = ConvertTo-SnmpPduBytes -PduType 0xA8 -RequestId $requestId -Varbinds @(
                    [PSCustomObject]@{ Oid = $reportOid; Type = 'Counter32'; Value = 1 }
                )
                $reportSession = $agentSession
                if ($Options.HideEngineTime -and $reportOid -eq '1.3.6.1.6.3.15.1.1.4.0') {
                    $reportSession = $agentSession.Clone()
                    $reportSession.EngineBoots = 0
                    $reportSession.EngineTime = 0
                    $reportSession.EngineTimeSyncedAt = $reportSession.Clock.Elapsed.TotalSeconds
                }
                $bytes = ConvertTo-SnmpV3Message -Session $reportSession -MsgId $message.MsgId -Pdu $reportPdu -SecurityLevel $level -Reportable $false -UserName $message.UserName
                if ($Options.ReportDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $Options.ReportDelayMs
                }
                [void]$Udp.Send($bytes, $bytes.Length, $remote)
            }

            $sendResponse = {
                param ($Bytes, $Remote)
                if ($Options.ResponseDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $Options.ResponseDelayMs
                }
                [void]$Udp.Send($Bytes, $Bytes.Length, $Remote)
            }

            while ($true) {
                $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                try {
                    $data = $Udp.Receive([ref]$remote)
                }
                catch [System.ObjectDisposedException] {
                    break
                }
                catch [System.Net.Sockets.SocketException] {
                    if ($null -eq $Udp.Client) { break }
                    continue
                }
                catch {
                    break
                }

                try {
                    $message = ConvertFrom-SnmpMessage -Data $data
                    if ($message.Version -in 0, 1) {
                        if ($message.Community -ne $Options.Community) {
                            continue
                        }
                        $responsePdu = & $answer $message.Pdu $message.Version
                        $bytes = ConvertTo-SnmpCommunityMessage -Version $message.Version -Community $message.Community -Pdu $responsePdu
                        & $sendResponse $bytes $remote
                        continue
                    }

                    if ($null -eq $agentSession) {
                        continue
                    }
                    $engineId = $Options.Engine.Id
                    if (-not (Test-SnmpBytesEqual $engineId $agentSession.EngineId)) {
                        Set-SnmpV3Engine -Session $agentSession -EngineId $engineId -Boots 7 -Time 4242
                    }
                    if (-not (Test-SnmpBytesEqual $message.EngineId $agentSession.EngineId)) {
                        if ($message.EngineId.Length -eq 0) {
                            $Options.Engine.Discoveries++
                        }
                        & $sendReport $remote $message '1.3.6.1.6.3.15.1.1.4.0' 'NoAuthNoPriv'
                        continue
                    }
                    if ($message.UserName -ne $agentSession.UserName) {
                        & $sendReport $remote $message '1.3.6.1.6.3.15.1.1.3.0' 'NoAuthNoPriv'
                        continue
                    }
                    $requiredFlags = switch ($agentSession.SecurityLevel) { 'AuthPriv' { 3 } 'AuthNoPriv' { 1 } default { 0 } }
                    if (($message.Flags -band 3) -ne $requiredFlags) {
                        & $sendReport $remote $message '1.3.6.1.6.3.15.1.1.1.0' 'NoAuthNoPriv'
                        continue
                    }
                    try {
                        $scoped = Resolve-SnmpV3Message -Session $agentSession -Data $data -Message $message
                    }
                    catch {
                        $reportOid = if ($_.Exception.Message -match 'digest') { '1.3.6.1.6.3.15.1.1.5.0' } else { '1.3.6.1.6.3.15.1.1.6.0' }
                        & $sendReport $remote $message $reportOid 'NoAuthNoPriv'
                        continue
                    }
                    $agentTime = Get-SnmpEngineTime -Session $agentSession
                    if ($message.EngineBoots -ne $agentSession.EngineBoots -or [Math]::Abs($message.EngineTime - $agentTime) -gt 150) {
                        $level = if ($agentSession.SecurityLevel -eq 'NoAuthNoPriv') { 'NoAuthNoPriv' } else { 'AuthNoPriv' }
                        & $sendReport $remote $message '1.3.6.1.6.3.15.1.1.2.0' $level
                        continue
                    }

                    $responsePdu = & $answer $scoped.Pdu 3
                    $bytes = ConvertTo-SnmpV3Message -Session $agentSession -MsgId $message.MsgId -Pdu $responsePdu -Reportable $false
                    & $sendResponse $bytes $remote
                }
                catch {
                    # Ignore anything the agent cannot parse or answer, like a real agent would.
                }
            }
            if ($null -ne $agentSession) {
                Close-SnmpSession $agentSession
            }
        } $Udp $Mib $Options
    }

    $powershell = [powershell]::Create()
    [void]$powershell.AddScript($agentScript).AddArgument($udp).AddArgument((Resolve-Path $ModulePath).Path).AddArgument($Mib).AddArgument($options)
    $handle = $powershell.BeginInvoke()

    [PSCustomObject]@{
        Port       = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
        Udp        = $udp
        PowerShell = $powershell
        Handle     = $handle
        Engine     = $engine
    }
}

function Stop-SnmpTestAgent {
    param ($Agent)

    if ($null -eq $Agent) {
        return
    }
    $Agent.Udp.Dispose()
    try {
        [void]$Agent.Handle.AsyncWaitHandle.WaitOne(5000)
        $Agent.PowerShell.Stop()
    }
    catch {
    }
    $Agent.PowerShell.Dispose()
}
