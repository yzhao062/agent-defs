<#
.SYNOPSIS
Scan a built artifact with whatever scanner this machine has, and record it.

.DESCRIPTION
SAMPLES.md rule 5: a detection on our own release is a release blocker, so the
question has to be answered before a user answers it for us. Rule content
carries attack strings by construction, because a detection pattern for a
dropper contains the dropper's indicators, so whether a bundle of them trips a
scanner is a real question rather than a formality.

The artifact is copied to a temporary directory and the copy is scanned. A
detection would quarantine the copy, leaving the repository file alone. The
copy also passes under whatever real-time protection is active, so the run
answers two questions: whether an on-demand scan reports a threat, and whether
resident protection removes the file on contact.

The result is written with the artifact's digest, so the record names the exact
bytes that were scanned rather than a path that has since been rebuilt.

.NOTES
Every handled failure replaces the record, and the exit code says which
happened: 0 clean and recorded, 1 a detection, 2 an inconclusive run, 3 a
result that could not be published. That is a narrower promise than "every exit
writes a record", which this file claimed after the round 2 review and could
not keep: a destination that cannot be written cannot be written, and the run
says so on stderr and in the exit code rather than pretending otherwise.

Two rounds of review shaped the failure handling and both defects are worth
naming. The version before round 2 threw the moment resident protection removed
the copy, so the single outcome that most needed recording produced no record
and an older clean result for the same bytes stayed authoritative. The version
before round 3 built the record only after hashing the artifact and creating
the scan directory, so a failure in either left that old record standing again,
and it published with `Move-Item -Force`, whose provider answers a sharing
violation on the destination by deleting it and retrying. Setup now runs inside
the guarded block, the record is created before any of it, and publication uses
`File.Replace`.

What this establishes is narrower than "two scanners cleared it". The product
list comes from the SecurityCenter registration, which says a product is
installed rather than that it was scanning this path; a delayed detection after
the three-second window is not observed either. The durable claim is one
recorded on-demand scan plus short-term survival on a machine listing those
products.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Out
)

$ErrorActionPreference = 'Stop'

function Write-Record {
    # Untyped on purpose: declaring [hashtable] re-boxes the ordered dictionary
    # and the record comes back with its keys shuffled.
    param($Record, [string]$Destination)
    $json = $Record | ConvertTo-Json -Depth 6
    if ($Destination) {
        $temp = "$Destination.$([guid]::NewGuid().ToString('N').Substring(0,8)).tmp"
        [IO.File]::WriteAllText($temp, $json + "`n", (New-Object Text.UTF8Encoding $false))
        try {
            # Not Move-Item -Force. Its provider handles an IOException on a
            # forced move by deleting the destination and retrying, so a
            # transient share lock on the target destroys the previous record
            # and then fails, which is the opposite of what a replacement is
            # for. File.Replace is the same-volume atomic operation.
            if ([IO.File]::Exists($Destination)) {
                [IO.File]::Replace($temp, $Destination, [NullString]::Value)
            } else {
                [IO.File]::Move($temp, $Destination)
            }
        } catch {
            # The previous record is intact; say so rather than implying this
            # run published anything. No script can promise a durable record
            # when it cannot write its own destination.
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
            Write-Error ("could not publish the scan record to ${Destination}: " +
                         "$($_.Exception.Message). Any earlier record there is unchanged " +
                         "and does not describe this run.") -ErrorAction Continue
            $script:PublishFailed = $true
        }
    }
    $json
}

#: Set when a record could not be published. The exit code carries it out, so a
#: caller cannot read a zero as "the artifact is clean and recorded".
$script:PublishFailed = $false

if (-not (Test-Path -LiteralPath $Path)) { throw "no such artifact: $Path" }

# The record exists before anything that can fail, and it starts pending. Every
# later step overwrites fields on it. The previous version built the record
# after hashing and after creating the scan directory, so injecting a failure
# in either left an existing clean record for these bytes untouched and still
# authoritative; the release test would then accept it.
$result = [ordered]@{
    artifact     = $Path
    sha256       = $null
    bytes        = $null
    scanned_at   = (Get-Date).ToUniversalTime().ToString('o')
    resident     = [ordered]@{ products = @(); removed_on_contact = $null; note = 'not reached' }
    on_demand    = [ordered]@{ scanner = $null; clean = $null; output = 'not reached' }
    verdict      = 'inconclusive: run did not complete'
}

$artifact = $null
$dir = $null
try {
    $artifact = Get-Item -LiteralPath $Path
    $result.artifact = $artifact.FullName
    $result.bytes = $artifact.Length
    $result.sha256 = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLower()

    $dir = Join-Path $env:TEMP ('agent-defs-scan-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
    $copy = Join-Path $dir $artifact.Name

    $products = @()
    try {
        $products = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
            Select-Object -ExpandProperty displayName
    } catch { $products = @('unknown') }
    $result.resident = [ordered]@{
        products = @($products)
        removed_on_contact = $null
        note = 'products are registered with SecurityCenter, which does not say this path was scanned'
    }

    try {
        Copy-Item -LiteralPath $artifact.FullName -Destination $copy
    } catch {
        # A copy that never lands leaves nothing scanned. Resident protection
        # is one reason and a lock or a permission is another, and this cannot
        # tell them apart, so it records the failure rather than naming a
        # cause. What matters is that it is written down: the old version threw
        # here, and an earlier clean record for the same bytes stayed the
        # answer.
        $result.resident.note = "copy blocked: $($_.Exception.Message)"
        $result.on_demand = [ordered]@{ scanner = $null; clean = $null; output = 'copy never landed' }
        $result.verdict = 'inconclusive: the artifact could not be copied for scanning'
        Write-Record $result $Out
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        if ($script:PublishFailed) { exit 3 }
        exit 2
    }

    Start-Sleep -Seconds 3
    $survived = Test-Path -LiteralPath $copy
    $result.resident.removed_on_contact = (-not $survived)
    $result.resident.note = 'a resident scanner that removes the copy within three seconds is a detection'
    if (-not $survived) {
        # Resident detection outranks a missing on-demand result: the file is
        # gone, so there is nothing left to scan, and the absence of an
        # on-demand verdict must not read as an absence of a finding.
        $result.on_demand = [ordered]@{ scanner = $null; clean = $null
                                        output = 'copy removed before an on-demand scan could run' }
        $result.verdict = 'DETECTED'
        Write-Record $result $Out
        if ($script:PublishFailed) { exit 3 }
        exit 1
    }

    $mp = Get-Item "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $mp) { $mp = Get-Item "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ErrorAction SilentlyContinue }
    if ($mp) {
        $output = (& $mp.FullName -Scan -ScanType 3 -File $copy 2>&1 | Out-String).Trim()
        $result.on_demand = [ordered]@{
            scanner = $mp.FullName
            exit_code = $LASTEXITCODE
            output = $output
            clean = ($LASTEXITCODE -eq 0 -and $output -match 'found no threats')
        }
    } else {
        $result.on_demand = [ordered]@{ scanner = $null; clean = $null; output = 'no on-demand scanner found' }
    }

    # A copy that vanished during the on-demand scan is still a detection.
    if (-not (Test-Path -LiteralPath $copy)) {
        $result.resident.removed_on_contact = $true
        $result.resident.note = 'copy removed during the on-demand scan'
    }
} catch {
    # Setup now runs inside this block, so a failure to hash the artifact or to
    # make the scan directory replaces the record instead of leaving whatever
    # was there before as the answer.
    $result.verdict = "inconclusive: $($_.Exception.Message)"
    Write-Record $result $Out
    if ($dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($script:PublishFailed) { exit 3 }
    exit 2
} finally {
    if ($dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

$result.verdict = if ($result.resident.removed_on_contact -eq $true) {
    'DETECTED'
} elseif ($result.on_demand.clean -eq $true) {
    'clean'
} elseif ($null -eq $result.on_demand.clean) {
    'inconclusive: no scanner'
} else {
    'DETECTED'
}

Write-Record $result $Out
# 1 a detection, 2 an inconclusive run, 3 a result that could not be published.
# Only 0 means both clean and recorded.
if ($script:PublishFailed) { exit 3 }
if ($result.verdict -eq 'DETECTED') { exit 1 }
if ($result.verdict -ne 'clean') { exit 2 }
