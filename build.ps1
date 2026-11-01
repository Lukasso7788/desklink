param([string]$OutputDirectory = 'dist')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& .\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --windowed --name DeskLink --distpath $OutputDirectory --add-data 'web;web' desklink.py
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
