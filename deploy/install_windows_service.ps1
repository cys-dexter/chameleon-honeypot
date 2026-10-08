# ==============================================================================
# Chameleon Honeypot — Windows 24/7 Background Service Deployment
# ==============================================================================

param (
    [string]$Action = "install" # "install", "uninstall", "start", "stop"
)

$ServiceName = "ChameleonHoneypot"
$ServiceDisplayName = "Chameleon Cyber Deception & Tarpit Engine"
$ServiceDescription = "Enterprise-Grade Network Honeypot and Active Psychological Tarpit Service."
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
$BinaryPath = "$ProjectRoot\chameleon.exe"
$ConfigPath = "$ProjectRoot\config\config.json"

function Ensure-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be executed in an Elevated PowerShell prompt (Run as Administrator)."
        exit 1
    }
}

Ensure-Admin

switch ($Action.ToLower()) {
    "install" {
        Write-Host "[*] Registering $ServiceName as a 24/7 background service..."
        if (-not (Test-Path $BinaryPath)) {
            Write-Host "[*] Compiling chameleon.exe..."
            Push-Location $ProjectRoot
            go build -o $BinaryPath .\cmd\chameleon
            Pop-Location
        }

        # Check if NSSM (Non-Sucking Service Manager) is available, otherwise use native sc.exe
        $nssm = Get-Command "nssm" -ErrorAction SilentlyContinue
        if ($nssm) {
            & nssm install $ServiceName $BinaryPath "-c `"$ConfigPath`""
            & nssm set $ServiceName AppDirectory $ProjectRoot
            & nssm set $ServiceName Description $ServiceDescription
            & nssm set $ServiceName Start SERVICE_AUTO_START
            Write-Host "[+] Service successfully installed via NSSM."
        } else {
            # Native Service Creation using sc.exe
            $binArgs = "`"$BinaryPath`" -c `"$ConfigPath`""
            & sc.exe create $ServiceName binPath= $binArgs start= auto DisplayName= $ServiceDisplayName
            & sc.exe description $ServiceName $ServiceDescription
            Write-Host "[+] Service successfully registered via Windows Service Controller."
        }

        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-Host "[+] $ServiceName started."
    }
    "uninstall" {
        Write-Host "[*] Removing $ServiceName..."
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName
        Write-Host "[+] $ServiceName removed."
    }
    "start" {
        Start-Service -Name $ServiceName
        Write-Host "[+] $ServiceName started."
    }
    "stop" {
        Stop-Service -Name $ServiceName
        Write-Host "[+] $ServiceName stopped."
    }
    default {
        Write-Host "Usage: .\install_windows_service.ps1 -Action [install|uninstall|start|stop]"
    }
}
