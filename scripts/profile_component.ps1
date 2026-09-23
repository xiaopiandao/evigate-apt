param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$OutputJson,
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$ProcessArguments
)

$ErrorActionPreference = "Stop"
$outputPath = [System.IO.Path]::GetFullPath($OutputJson)
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputPath)
[System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
$stdoutPath = [System.IO.Path]::Combine($outputDirectory, "$Name.stdout.log")
$stderrPath = [System.IO.Path]::Combine($outputDirectory, "$Name.stderr.log")

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$process = Start-Process `
    -FilePath $Executable `
    -ArgumentList $ProcessArguments `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

$peakWorkingSet = 0L
$peakIndividualWorkingSet = 0L
$sampleCount = 0
while (-not $process.HasExited) {
    $processIds = @($process.Id)
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)" -ErrorAction Stop
        $processIds += @($children | ForEach-Object { [int]$_.ProcessId })
    }
    catch {
        # A short-lived child may exit between enumeration and sampling.
    }
    $treeWorkingSet = 0L
    foreach ($processId in ($processIds | Select-Object -Unique)) {
        try {
            $snapshot = Get-Process -Id $processId -ErrorAction Stop
            $workingSet = [int64]$snapshot.WorkingSet64
            $treeWorkingSet += $workingSet
            $peakIndividualWorkingSet = [Math]::Max($peakIndividualWorkingSet, $workingSet)
        }
        catch {
            # The process may exit between enumeration and Get-Process.
        }
    }
    $peakWorkingSet = [Math]::Max($peakWorkingSet, $treeWorkingSet)
    $sampleCount += 1
    Start-Sleep -Milliseconds 100
}
$process.WaitForExit()
$stopwatch.Stop()

$result = [ordered]@{
    schema_version = "1.0"
    component = $Name
    executable = [System.IO.Path]::GetFullPath($Executable)
    arguments = $ProcessArguments
    exit_code = $process.ExitCode
    wall_time_seconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 6)
    peak_working_set_bytes = $peakWorkingSet
    peak_working_set_mib = [Math]::Round($peakWorkingSet / 1MB, 3)
    peak_individual_working_set_bytes = $peakIndividualWorkingSet
    peak_individual_working_set_mib = [Math]::Round($peakIndividualWorkingSet / 1MB, 3)
    sampling_interval_ms = 100
    samples = $sampleCount
    stdout_log = $stdoutPath
    stderr_log = $stderrPath
    limitation = "Peak working set is the sampled sum of the launcher and its direct child processes every 100 ms; it excludes external data collection, may miss shorter peaks, and does not follow deeper descendants."
}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outputPath -Encoding utf8
$result | ConvertTo-Json -Depth 5

if ($process.ExitCode -ne 0) {
    exit $process.ExitCode
}
