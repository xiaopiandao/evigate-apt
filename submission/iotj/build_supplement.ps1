param(
    [string]$PandocPath,
    [string]$TectonicPath
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

$source = Join-Path $repoRoot 'paper\evigate_apt_supplement.md'
$bibliography = Join-Path $repoRoot 'references\references.bib'
$output = Join-Path $repoRoot 'output\pdf\evigate_apt_supplement.pdf'
$outputDir = Split-Path -Parent $output

foreach ($requiredPath in @($PandocPath, $TectonicPath, $source, $bibliography)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required supplement dependency not found: $requiredPath"
    }
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

& $PandocPath $source `
    --from 'markdown+raw_tex+tex_math_dollars' `
    --standalone `
    --citeproc `
    --bibliography $bibliography `
    --resource-path (Join-Path $repoRoot 'paper') `
    --pdf-engine $TectonicPath `
    -V 'geometry:margin=0.65in' `
    -V 'fontsize=9pt' `
    -V 'colorlinks=false' `
    -o $output

if ($LASTEXITCODE -ne 0) {
    throw 'Supplement build failed.'
}

Write-Host "Built $output"
