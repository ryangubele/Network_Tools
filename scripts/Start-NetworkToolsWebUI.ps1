<#
.SYNOPSIS
Starts a minimal local web UI for the Network Tools commands.

.DESCRIPTION
Serves a single self-contained page from System.Net.HttpListener on http://localhost:<Port>/.
The page has one tab per exported Network Tools command. Each tab is a form built from that
command's parameter metadata, and the Run button executes the command on this machine and shows
the formatted output, errors, warnings, and host messages in the panel below the form.

This is a demo. It only listens on localhost and runs commands as the current user, so do not
expose it to a network. Press Ctrl+C, or open http://localhost:<Port>/stop, to shut it down.

.PARAMETER Port
Local TCP port to listen on.

.PARAMETER TimeoutSeconds
Maximum run time for a single command. Long-running commands such as Invoke-BandwidthMonitor
are stopped at this limit and whatever output they produced is returned.

.EXAMPLE
./scripts/Start-NetworkToolsWebUI.ps1 -Port 8080
Starts the web UI at http://localhost:8080/.
#>
[CmdletBinding()]
param (
    [ValidateRange(1, 65535)]
    [int]$Port = 8080,

    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'

$modulePath = [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..\Network-Tools.psd1'))
$module = Import-Module $modulePath -Force -PassThru

$commonParameters = [System.Management.Automation.PSCmdlet]::CommonParameters +
    [System.Management.Automation.PSCmdlet]::OptionalCommonParameters

# Build the tab and form metadata from the module's exported commands.
$commandInfo = foreach ($command in ($module.ExportedFunctions.Values | Sort-Object Name)) {
    $parameterSet = $command.ParameterSets |
        Where-Object { $_.IsDefault -or $_.Name -eq $command.DefaultParameterSet } |
        Select-Object -First 1
    if ($null -eq $parameterSet) {
        $parameterSet = $command.ParameterSets[0]
    }

    $parameters = foreach ($parameter in $parameterSet.Parameters) {
        if ($commonParameters -contains $parameter.Name) {
            continue
        }

        $validateSet = $parameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1

        $kind = if ($parameter.ParameterType -eq [switch]) {
            'switch'
        } elseif ($null -ne $validateSet) {
            'select'
        } elseif ($parameter.ParameterType.IsArray) {
            'array'
        } else {
            'text'
        }

        [ordered]@{
            Name      = $parameter.Name
            Type      = $parameter.ParameterType.Name
            Kind      = $kind
            Mandatory = $parameter.IsMandatory
            Values    = @(if ($null -ne $validateSet) { $validateSet.ValidValues })
            Help      = (Get-Help $command.Name -Parameter $parameter.Name -ErrorAction SilentlyContinue).Description.Text -join ' '
        }
    }

    [ordered]@{
        Name       = $command.Name
        Synopsis   = ((Get-Help $command.Name -ErrorAction SilentlyContinue).Synopsis | Out-String).Trim()
        Parameters = @($parameters)
    }
}

$commandLookup = @{}
foreach ($entry in $commandInfo) {
    $commandLookup[$entry.Name] = $entry
}

function Invoke-WebUICommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Command,

        [hashtable]$Values = @{}
    )

    # Convert form values into a splat. The parameter binder handles int/double conversion.
    $splat = @{}
    foreach ($parameter in $Command.Parameters) {
        if (-not $Values.ContainsKey($parameter.Name)) {
            continue
        }
        $value = $Values[$parameter.Name]
        switch ($parameter.Kind) {
            'switch' {
                if ($value -eq $true) { $splat[$parameter.Name] = $true }
            }
            'array' {
                $items = @("$value" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($items.Count -gt 0) { $splat[$parameter.Name] = $items }
            }
            default {
                if (-not [string]::IsNullOrWhiteSpace("$value")) { $splat[$parameter.Name] = "$value".Trim() }
            }
        }
    }

    # Run in a fresh runspace so a stuck or long-running command can be stopped at the timeout.
    $ps = [powershell]::Create()
    $output = [System.Management.Automation.PSDataCollection[psobject]]::new()
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $text = ''
    try {
        [void]$ps.AddScript({
            param($ModulePath, $Name, $Splat)
            Import-Module $ModulePath -Force
            & $Name @Splat | Out-String -Width 160 -Stream
        }).AddArgument($modulePath).AddArgument($Command.Name).AddArgument($splat)

        $async = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[psobject]]::new(), $output)
        if (-not $async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds))) {
            # Ask the run to stop without waiting on it, so a blocking call can't hold up the UI.
            $timedOut = $true
            [void]$ps.BeginStop($null, $null)
        } else {
            try { [void]$ps.EndInvoke($async) } catch { $ps.Streams.Error.Add($_.Exception.InnerException.ErrorRecord ?? $_) }
        }

        # ReadAll takes what is there now; enumerating an open collection would wait for the run to end.
        $text = ($output.ReadAll() | ForEach-Object { "$_" }) -join [Environment]::NewLine
        $messages = @(
            $ps.Streams.Information.ReadAll() | ForEach-Object { "$($_.MessageData)" }
            $ps.Streams.Warning.ReadAll() | ForEach-Object { "WARNING: $($_.Message)" }
        )
        $errors = @($ps.Streams.Error.ReadAll() | ForEach-Object { "$_" })
    }
    finally {
        if (-not $timedOut) {
            $ps.Dispose()
        }
    }

    [ordered]@{
        Command  = $Command.Name
        Splat    = $splat
        Output   = $text.TrimEnd()
        Messages = ($messages -join [Environment]::NewLine)
        Errors   = ($errors -join [Environment]::NewLine)
        TimedOut = $timedOut
        Elapsed  = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    }
}

$html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Tools</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; background: #f4f5f7; color: #1d1f23; }
header { background: #1d1f23; color: #fff; padding: 10px 16px; font-weight: 600; }
nav { display: flex; flex-wrap: wrap; background: #2b2e34; }
nav button { background: none; border: 0; color: #c9ccd2; padding: 10px 14px; cursor: pointer; font: inherit; }
nav button.active { background: #f4f5f7; color: #1d1f23; }
main { padding: 16px; max-width: 1100px; }
.synopsis { color: #555; margin: 0 0 12px; }
form { display: grid; grid-template-columns: max-content 1fr; gap: 8px 12px; align-items: center; }
label { font-family: ui-monospace, monospace; }
label .req { color: #c0392b; }
input[type=text], select { padding: 5px 7px; font: inherit; max-width: 420px; }
input[type=checkbox] { justify-self: start; }
.hint { grid-column: 2; color: #777; font-size: 12px; margin-top: -6px; }
.actions { grid-column: 2; }
.actions button { padding: 6px 18px; font: inherit; cursor: pointer; }
pre { background: #111; color: #e6e6e6; padding: 12px; min-height: 160px; overflow: auto; white-space: pre; margin-top: 16px; }
.err { color: #ff8a80; }
.msg { color: #ffd479; }
.meta { color: #8ab4f8; }
</style>
</head>
<body>
<header>Network Tools web UI (localhost demo)</header>
<nav id="tabs"></nav>
<main>
<p class="synopsis" id="synopsis"></p>
<form id="form"></form>
<pre id="output">Pick a tool, fill in the fields, and press Run.</pre>
</main>
<script>
const commands = __COMMANDS__;
const tabs = document.getElementById('tabs');
const form = document.getElementById('form');
const output = document.getElementById('output');
let current = null;

function el(tag, props, text) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  if (text !== undefined) node.textContent = text;
  return node;
}

function show(command) {
  current = command;
  for (const b of tabs.children) b.classList.toggle('active', b.textContent === command.Name);
  document.getElementById('synopsis').textContent = command.Synopsis;
  form.replaceChildren();
  for (const p of command.Parameters) {
    const id = 'p_' + p.Name;
    const label = el('label', { htmlFor: id }, '-' + p.Name + ' ');
    label.title = p.Type;
    if (p.Mandatory) label.appendChild(el('span', { className: 'req' }, '*'));
    let input;
    if (p.Kind === 'switch') {
      input = el('input', { type: 'checkbox', id: id });
    } else if (p.Kind === 'select') {
      input = el('select', { id: id });
      input.appendChild(el('option', { value: '' }, ''));
      for (const v of p.Values) input.appendChild(el('option', { value: v }, v));
    } else {
      input = el('input', { type: 'text', id: id, placeholder: p.Type + (p.Kind === 'array' ? ' (comma separated)' : '') });
    }
    input.dataset.name = p.Name;
    form.append(label, input);
    if (p.Help) form.appendChild(el('div', { className: 'hint' }, p.Help));
  }
  const actions = el('div', { className: 'actions' });
  actions.appendChild(el('button', { type: 'submit' }, 'Run'));
  form.appendChild(actions);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const values = {};
  for (const input of form.querySelectorAll('[data-name]')) {
    values[input.dataset.name] = input.type === 'checkbox' ? input.checked : input.value;
  }
  const button = form.querySelector('button');
  button.disabled = true;
  output.textContent = 'Running ' + current.Name + '...';
  try {
    const response = await fetch('/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ Command: current.Name, Values: values })
    });
    const result = await response.json();
    output.replaceChildren();
    if (result.Output) output.appendChild(el('span', {}, result.Output + '\n'));
    if (result.Messages) output.appendChild(el('span', { className: 'msg' }, result.Messages + '\n'));
    if (result.Errors) output.appendChild(el('span', { className: 'err' }, result.Errors + '\n'));
    const note = result.TimedOut ? ' (stopped at the time limit)' : '';
    output.appendChild(el('span', { className: 'meta' }, '-- ' + (result.Command || '') + ' finished in ' + result.Elapsed + 's' + note));
  } catch (error) {
    output.textContent = 'Request failed: ' + error;
  } finally {
    button.disabled = false;
  }
});

for (const command of commands) {
  tabs.appendChild(el('button', { onclick: () => show(command) }, command.Name));
}
if (commands.length) show(commands[0]);
</script>
</body>
</html>
'@
$html = $html.Replace('__COMMANDS__', (ConvertTo-Json -InputObject @($commandInfo) -Depth 6 -Compress).Replace('</', '<\/'))

function Send-WebUIResponse {
    param (
        [System.Net.HttpListenerResponse]$Response,
        [int]$StatusCode = 200,
        [string]$ContentType = 'text/plain; charset=utf-8',
        [string]$Body = ''
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.Close()
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "Network Tools web UI listening on http://localhost:$Port/ (Ctrl+C or /stop to quit)"

try {
    $running = $true
    while ($running -and $listener.IsListening) {
        # Poll the async accept so Ctrl+C is handled between waits.
        $pending = $listener.GetContextAsync()
        while (-not $pending.Wait(250)) { }
        $context = $pending.Result
        $request = $context.Request
        $response = $context.Response

        try {
            # Only answer requests addressed to localhost, which blocks DNS rebinding.
            $hostName = ($request.UserHostName -split ':')[0]
            if ($hostName -notin @('localhost', '127.0.0.1', '[::1]')) {
                Send-WebUIResponse -Response $response -StatusCode 403 -Body 'Forbidden'
                continue
            }

            $path = $request.Url.AbsolutePath
            if ($request.HttpMethod -eq 'GET' -and $path -eq '/') {
                Send-WebUIResponse -Response $response -ContentType 'text/html; charset=utf-8' -Body $html
            }
            elseif ($request.HttpMethod -eq 'POST' -and $path -eq '/run') {
                # Requiring a JSON body means a cross-site page cannot submit runs without a CORS preflight.
                if ($request.ContentType -notlike 'application/json*') {
                    Send-WebUIResponse -Response $response -StatusCode 415 -Body 'Expected application/json'
                    continue
                }

                $reader = [System.IO.StreamReader]::new($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json -AsHashtable
                $reader.Dispose()

                $command = $commandLookup["$($payload.Command)"]
                if ($null -eq $command) {
                    Send-WebUIResponse -Response $response -StatusCode 400 -Body 'Unknown command'
                    continue
                }

                $values = if ($payload.Values -is [hashtable]) { $payload.Values } else { @{} }
                Write-Host "Running $($command.Name)"
                $result = Invoke-WebUICommand -Command $command -Values $values
                Send-WebUIResponse -Response $response -ContentType 'application/json; charset=utf-8' -Body (ConvertTo-Json -InputObject $result -Depth 4)
            }
            elseif ($path -eq '/stop') {
                Send-WebUIResponse -Response $response -Body 'Network Tools web UI stopped.'
                $running = $false
            }
            else {
                Send-WebUIResponse -Response $response -StatusCode 404 -Body 'Not found'
            }
        }
        catch {
            Write-Warning $_.Exception.Message
            try { Send-WebUIResponse -Response $response -StatusCode 500 -Body $_.Exception.Message } catch { }
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host 'Network Tools web UI stopped.'
}
