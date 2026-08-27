Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$repo = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
    & uv sync --frozen --extra dev
    if ($LASTEXITCODE -ne 0) { throw 'uv sync failed' }

    & uv run ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'ruff check failed' }

    & uv run ruff format --check .
    if ($LASTEXITCODE -ne 0) { throw 'ruff format check failed' }

    & uv run mypy src tests
    if ($LASTEXITCODE -ne 0) { throw 'mypy failed' }

    & uv run pytest --basetemp .pytest-tmp --cov=tracehush --cov-branch --cov-fail-under=90
    if ($LASTEXITCODE -ne 0) { throw 'pytest failed' }

    & uv build
    if ($LASTEXITCODE -ne 0) { throw 'package build failed' }

    & uv run pip-audit
    if ($LASTEXITCODE -ne 0) { throw 'dependency audit failed' }

    & uv run python examples/build_examples.py
    if ($LASTEXITCODE -ne 0) { throw 'example build failed' }

    & uv run tracehush audit examples/generated/safe-trace.zip
    if ($LASTEXITCODE -ne 0) { throw 'safe example did not exit 0' }

    & uv run tracehush audit examples/generated/leaky-trace.zip --format json --output examples/generated/leaky-report.json
    if ($LASTEXITCODE -ne 1) { throw 'leaky example did not exit 1' }

    & uv run tracehush sanitize examples/generated/leaky-trace.zip examples/generated/leaky-trace.redacted.zip --format json --report examples/generated/sanitize-report.json
    if ($LASTEXITCODE -ne 0) { throw 'sanitize example failed' }

    & uv run tracehush audit examples/generated/leaky-trace.redacted.zip
    if ($LASTEXITCODE -ne 0) { throw 'redacted example did not re-audit clean' }

    $wheel = Get-ChildItem -Path (Join-Path $repo 'dist/*.whl') | Select-Object -First 1
    if ($null -eq $wheel) { throw 'wheel was not built' }
    & uvx --from $wheel.FullName tracehush --version
    if ($LASTEXITCODE -ne 0) { throw 'wheel execution smoke failed' }

    Write-Output 'TRACEHUSH_RELEASE_GATE=PASS'
}
finally {
    Pop-Location
}
