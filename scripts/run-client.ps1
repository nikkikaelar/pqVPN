# Simple helper to run the pqVPN client with a local SOCKS5 proxy
param(
    [string]$Server = "127.0.0.1:9443",
    [string]$Socks = "127.0.0.1:1080",
    [ValidateSet("classic","pq-mock")]
    [string]$Mode = "pq-mock"
)

Write-Host "Starting pqVPN client -> server=$Server, socks=$Socks, mode=$Mode" -ForegroundColor Cyan

# Ensure we run from repo root if script is executed directly
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

# Build is optional; go run compiles on the fly
# go build -v

go run . client -server $Server -socks $Socks -mode $Mode
