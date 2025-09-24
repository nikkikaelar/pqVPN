# Simple helper to run the pqVPN server
param(
    [string]$Listen = ":9443"
)

Write-Host "Starting pqVPN server on $Listen" -ForegroundColor Cyan

# Ensure we run from repo root if script is executed directly
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

# Build is optional; go run compiles on the fly
# go build -v

go run . server -listen $Listen
