# Run once as administrator, beside DeskLink.exe.
# Limits inbound access to LAN and the Tailscale address range; no public router port forwarding.
$ErrorActionPreference = 'Stop'
$exePath = Join-Path $PSScriptRoot 'DeskLink.exe'
if (-not (Test-Path -LiteralPath $exePath)) { throw 'Place this script beside DeskLink.exe first.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as administrator and run this script again.'
}
New-NetFirewallRule -DisplayName 'DeskLink - LAN and private VPN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47831 -Program $exePath -RemoteAddress LocalSubnet,100.64.0.0/10 -Profile Any
