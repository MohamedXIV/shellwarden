$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$tunnelVersion = "0.0.14"
$tunnelArchive = "tunnel-client-runtime-v0.0.14-windows-amd64.zip"
$tunnelSha256 = "c276db68609ac9771b07f078eac3dc23f8943a42f9dedd4c50a4001cb74df149"
$tunnelBase = "https://github.com/openai/tunnel-client/releases/download/v0.0.14"
$runtimeDir = Join-Path $repoRoot "packaging/runtime"
$downloadDir = Join-Path $env:RUNNER_TEMP "shellwarden-tunnel-runtime"
$archivePath = Join-Path $downloadDir $tunnelArchive
$extractDir = Join-Path $downloadDir "expanded"

Remove-Item $runtimeDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $runtimeDir, $downloadDir, $extractDir | Out-Null

Invoke-WebRequest "$tunnelBase/$tunnelArchive" -OutFile $archivePath
$actualSha = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
if ($actualSha -ne $tunnelSha256) { throw "tunnel-client archive SHA-256 mismatch: expected $tunnelSha256, got $actualSha" }

$licenseName = "tunnel-client-runtime-v0.0.14-windows-amd64-licenses.txt"
$spdxName = "tunnel-client-runtime-v0.0.14-windows-amd64.spdx.json"
Invoke-WebRequest "$tunnelBase/$licenseName" -OutFile (Join-Path $runtimeDir "tunnel-client-LICENSES.txt")
Invoke-WebRequest "$tunnelBase/$spdxName" -OutFile (Join-Path $runtimeDir "tunnel-client.spdx.json")

Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force
$tunnelExe = Get-ChildItem $extractDir -Filter "tunnel-client.exe" -Recurse | Select-Object -First 1
if ($null -eq $tunnelExe) { throw "official tunnel-client runtime archive did not contain tunnel-client.exe" }
Copy-Item $tunnelExe.FullName (Join-Path $runtimeDir "tunnel-client.exe")

$versionOutput = & (Join-Path $runtimeDir "tunnel-client.exe") --version 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch "0\.0\.14") { throw "bundled tunnel-client version check failed: $versionOutput" }

python -m pip install --disable-pip-version-check -r execution/requirements.txt
python -m pip install --disable-pip-version-check "pyinstaller==6.16.0"
Remove-Item "execution/build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "execution/dist" -Recurse -Force -ErrorAction SilentlyContinue
python -m PyInstaller --noconfirm --clean --onefile --collect-all mcp_shell_server --name shellwarden-broker --distpath execution/dist --workpath execution/build execution/broker.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed to build shellwarden-broker.exe" }

$brokerOutput = '{"id":"packaging-smoke","type":"health"}' | & ".\execution\dist\shellwarden-broker.exe" 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $brokerOutput -notmatch '"type":"ready"' -or $brokerOutput -notmatch '"ok":true') { throw "packaged execution broker health smoke failed: $brokerOutput" }

Write-Host "Prepared packaged runtime: tunnel-client v$tunnelVersion + standalone execution broker."
