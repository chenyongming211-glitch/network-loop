Set-StrictMode -Version Latest

function ConvertTo-WindowsNativeArgument {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Argument)

    if ($Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $Builder = [System.Text.StringBuilder]::new()
    $null = $Builder.Append('"')
    $Backslashes = 0
    foreach ($Character in $Argument.ToCharArray()) {
        if ($Character -eq [char]92) {
            $Backslashes++
            continue
        }
        if ($Character -eq [char]34) {
            $null = $Builder.Append((('\' * (($Backslashes * 2) + 1)) -join ''))
            $null = $Builder.Append('"')
            $Backslashes = 0
            continue
        }
        if ($Backslashes -ne 0) {
            $null = $Builder.Append((('\' * $Backslashes) -join ''))
            $Backslashes = 0
        }
        $null = $Builder.Append($Character)
    }
    if ($Backslashes -ne 0) {
        $null = $Builder.Append((('\' * ($Backslashes * 2)) -join ''))
    }
    $null = $Builder.Append('"')
    $Builder.ToString()
}

function Assert-IsolatedRunId {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $RunId)

    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'run ID must be exactly 32 lowercase hexadecimal characters'
    }
}

function New-IsolatedNames {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $RunId)

    Assert-IsolatedRunId -RunId $RunId
    [pscustomobject]@{
        RunId = $RunId
        Namespace = "l2ns-$($RunId.Substring(0, 12))"
        HostVeth = "l2h$($RunId.Substring(0, 10))"
        PeerVeth = "l2n$($RunId.Substring(0, 10))"
        RemoteRunRoot = "/run/l2-loop/accept/$RunId"
        Journal = "/run/l2-loop/tests/$RunId.json"
        PinRoot = "/sys/fs/bpf/l2-loop/test/$RunId"
    }
}

function Get-SshArguments {
    param(
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [string[]] $RemoteArguments
    )

    if ($Target -notmatch '^[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+$') {
        throw 'test target must be an explicit user and host'
    }
    if ([string]::IsNullOrWhiteSpace($KeyPath)) {
        throw 'test key path must not be empty'
    }
    @(
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-i', $KeyPath,
        '--', $Target
    ) + $RemoteArguments
}

function Get-ScpArguments {
    param(
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [string[]] $Sources,
        [Parameter(Mandatory)] [string] $Destination
    )

    if ($Target -notmatch '^[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+$') {
        throw 'test target must be an explicit user and host'
    }
    if ([string]::IsNullOrWhiteSpace($KeyPath) -or $Sources.Count -eq 0) {
        throw 'SCP inputs must be explicit'
    }
    @(
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-i', $KeyPath,
        '--'
    ) + $Sources + @("${Target}:$Destination")
}

function Assert-CleanupTarget {
    param(
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Namespace,
        [Parameter(Mandatory)] [string] $HostVeth,
        [Parameter(Mandatory)] [string] $PeerVeth,
        [Parameter(Mandatory)] [string] $RunRoot
    )

    Assert-IsolatedRunId -RunId $Names.RunId
    if ($Namespace -cne $Names.Namespace -or
        $HostVeth -cne $Names.HostVeth -or
        $PeerVeth -cne $Names.PeerVeth -or
        $RunRoot -cne $Names.RemoteRunRoot) {
        throw 'cleanup target does not exactly match the active isolated run'
    }
}

Export-ModuleMember -Function @(
    'ConvertTo-WindowsNativeArgument',
    'Assert-IsolatedRunId',
    'New-IsolatedNames',
    'Get-SshArguments',
    'Get-ScpArguments',
    'Assert-CleanupTarget'
)
