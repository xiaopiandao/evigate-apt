param(
    [string]$PandocPath,
    [string]$TectonicPath,
    [string]$AuthorMetadataPath,
    [switch]$SubmissionReady
)

$ErrorActionPreference = 'Stop'
$submissionDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $submissionDir '..\..')

if (-not $PandocPath) {
    $PandocPath = Join-Path $repoRoot '.tmp_tools\pandoc\pandoc-3.11\pandoc.exe'
}
if (-not $TectonicPath) {
    $TectonicPath = Join-Path $repoRoot '.tmp_tools\tectonic\tectonic.exe'
}

$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
$builderPath = Join-Path $repoRoot 'scripts\build_iotj_submission.py'
$texPath = Join-Path $submissionDir 'evigate_apt_iotj.tex'

foreach ($requiredPath in @($pythonPath, $PandocPath, $TectonicPath, $builderPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required build dependency not found: $requiredPath"
    }
}

$builderArguments = @($builderPath, '--root', $repoRoot, '--pandoc', $PandocPath)
if ($AuthorMetadataPath) {
    $builderArguments += @('--author-metadata', $AuthorMetadataPath)
}
if ($SubmissionReady) {
    $builderArguments += '--submission-ready'
}

& $pythonPath @builderArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Markdown-to-IEEEtran conversion failed.'
}

& $TectonicPath $texPath --keep-logs --keep-intermediates
if ($LASTEXITCODE -ne 0) {
    throw 'LaTeX compilation failed.'
}

Write-Host "Built $submissionDir\evigate_apt_iotj.pdf"
