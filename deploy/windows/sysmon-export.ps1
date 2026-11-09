# Exports the Sysmon events of the last 3 minutes into the "sysmon" folder next to this script, for AegisLens
# (monitor.sysmon.folder). install-sysmon-export.cmd copies it to C:\ProgramData\AegisLens and runs it every minute
# as SYSTEM, because reading the Sysmon log needs administrator rights and AegisLens itself never does.
# The windows overlap so a late run loses nothing; AegisLens skips events it already read.
# Exports older than one day are deleted (they contain user names and command lines).
$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'sysmon'
$status = Join-Path $PSScriptRoot 'last-export.txt'
try {
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $tmp = Join-Path $out "sysmon-$stamp.part"
    $final = Join-Path $out "sysmon-$stamp.xml"
    # cmd's redirection writes wevtutil's bytes unchanged (UTF-8), exactly like the manual export in the README
    & cmd.exe /d /c "wevtutil qe Microsoft-Windows-Sysmon/Operational `"/q:*[System[TimeCreated[timediff(@SystemTime) <= 180000]]]`" /f:xml > `"$tmp`""
    if ($LASTEXITCODE -ne 0) { throw "wevtutil exit code $LASTEXITCODE (is Sysmon installed?)" }
    $size = (Get-Item $tmp).Length
    if ($size -gt 0) {
        Move-Item -LiteralPath $tmp -Destination $final       # a rename: AegisLens only sees the finished .xml
    } else {
        Remove-Item -LiteralPath $tmp                          # no new events
    }
    Get-ChildItem -Path $out -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Force
    Set-Content -Path $status -Value "$(Get-Date -Format o) OK $size bytes"
} catch {
    Set-Content -Path $status -Value "$(Get-Date -Format o) FAILED $($_.Exception.Message)"
    exit 1
}
