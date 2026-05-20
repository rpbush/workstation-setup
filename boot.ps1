# ============================================================================
# PHASE-BASED WORKSTATION SETUP SCRIPT
# ============================================================================
# This script uses a phase-based execution model:
# - Phase 1: Prerequisites (NFS, etc.) - may require reboot
# - Phase 2: Main installation and configuration
#
# ELEVATION STRATEGY:
# This script runs in USER context (non-elevated) by default to support WinGet.
# WinGet is a per-user AppX package and does NOT work in elevated/admin contexts.
# Microsoft's solution: WinGet automatically prompts for UAC elevation when it
# needs admin privileges for installations, even when running from a non-elevated session.
#
# For other admin operations (Windows features, registry), the script elevates
# only those specific commands using Start-Process -Verb RunAs.
#
# RECOMMENDED: Run this script in a non-elevated PowerShell session.
# WinGet will handle elevation prompts automatically when needed.
# ============================================================================

# 1. PARAMETERS & PREAMBLE
param (
    [switch]$ResumeAfterReboot,            # This flag tells the script we just rebooted
    [switch]$Unattended,                   # Skip interactive prompts (MSA sign-in, post-NFS reboot confirmation)
    [string]$RepoOwner = "rpbush",         # GitHub owner to download DSC YAMLs from (fork-friendly)
    [string]$RepoName  = "workstation-setup",
    [string]$RepoBranch = "main"
)

# Strict mode: catches uninitialized variable references. Kept at Version 1.0
# rather than Latest because the script relies on missing-property checks via
# -ErrorAction SilentlyContinue and would break under Version 3+ until each
# call site is hardened. Raise this once analyzer findings are clean.
Set-StrictMode -Version 1.0

$mypath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path $mypath -Parent
Write-Output "Path of the script: $mypath"
Write-Output "Args for script: $Args"
Write-Output "ResumeAfterReboot: $ResumeAfterReboot"
Write-Output "Unattended: $Unattended"

# 2. DOT-SOURCE HELPER MODULES FROM src/
# Helper function definitions live in src/*.ps1 and are dot-sourced into the
# current scope, so $script:-scoped state (IsAdmin, ErrorCount, SectionTimings,
# etc.) declared below remains accessible from each helper. Done before any
# function call so the log-startup banner can use Write-Log immediately.
$srcDir = Join-Path $scriptDir 'src'
if (-not (Test-Path $srcDir)) {
    Write-Host "FATAL: src/ directory not found next to boot.ps1 ($srcDir)" -ForegroundColor Red
    Write-Host "Fetch the full repo: https://github.com/$RepoOwner/$RepoName" -ForegroundColor Red
    exit 1
}
Get-ChildItem -Path $srcDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }

# 3. ELEVATION CHECK
# The script runs in USER context: WinGet is a per-user AppX package and fails
# when elevated. Admin operations elevate per-command via Invoke-AdminCommand
# (src/Elevation.ps1). See CLAUDE.md for details.
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($script:IsAdmin) {
    Write-Host "WARNING: Running as Administrator. WinGet operations may fail." -ForegroundColor Yellow
    Write-Host "For best results, run this script in a non-elevated PowerShell session." -ForegroundColor Yellow
    Write-Host "WinGet will prompt for elevation when needed for installations." -ForegroundColor Yellow
}

# 3. PERSISTENT LOGGING SETUP
# We determine the log file name ONCE. If we are resuming, we append to the old log.
$logPathFile = "$env:TEMP\SetupLogPath.txt"

if ($ResumeAfterReboot -and (Test-Path $logPathFile)) {
    # We are resuming, read the previous log file path
    $logFilePath = Get-Content $logPathFile -Raw
    Write-Output "Resuming setup. Appending to log: $logFilePath"
} else {
    # New run, create new log
    $scriptDir = Split-Path $mypath -Parent
    $logFileName = "workstation-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    $logFilePath = Join-Path $scriptDir $logFileName
    # Save log path for resume after reboot
    $logFilePath | Out-File $logPathFile -Force
}

$scriptStartTime = Get-Date
$sectionStartTimes = @{}

# Log script start
Write-Log "========================================" -Level 'INFO'
Write-Log "Workstation Setup Script Started" -Level 'SECTION_START'
Write-Log "Script Path: $mypath" -Level 'INFO'
Write-Log "Script Arguments: $($Args -join ' ')" -Level 'INFO'
Write-Log "Log File: $logFilePath" -Level 'INFO'
Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level 'INFO'
Write-Log "OS Version: $([System.Environment]::OSVersion.VersionString)" -Level 'INFO'
Write-Log "Computer Name: $($env:COMPUTERNAME)" -Level 'INFO'
Write-Log "User: $($env:USERNAME)" -Level 'INFO'
Write-Log "========================================" -Level 'INFO'

# turning off progress bar to make invoke WebRequest fast
$ProgressPreference = 'SilentlyContinue'

# Suppress all confirmation prompts for the entire script
$ConfirmPreference = 'None'
$ErrorActionPreference = 'Continue'

# Track errors globally
$script:ErrorCount = 0
$script:WarningCount = 0
$script:SuccessCount = 0
$script:SectionResults = @{}  # Track success/failure status for each section
$script:SectionTimings = @{}

# Track detailed installation/configuration status
$script:InstalledItems = @()      # Items that were installed/applied
$script:AlreadySetItems = @()     # Items that were already installed/configured
$script:FailedItems = @()         # Items that failed to install/configure
$script:SettingsApplied = @()    # Settings that were applied
$script:SettingsAlreadySet = @() # Settings that were already configured

# Check if WinGet is already installed and working
# Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/
# IMPORTANT: WinGet is a per-user AppX package and does NOT work in elevated/admin contexts
# If running as admin (SYSTEM), WinGet operations will fail and should be done at user level
Start-Section "WinGet Check"
$isRunningAsSystem = ($env:USERNAME -eq "SYSTEM")
if ($isRunningAsSystem) {
    Write-Host "WARNING: Running as admin (SYSTEM). WinGet is user-scoped and may not be available." -ForegroundColor Yellow
    Write-Host "WinGet operations should be performed in a non-elevated user session." -ForegroundColor Yellow
    Write-Log "Running as SYSTEM/admin - WinGet is user-scoped and may not work" -Level 'WARNING' -Section "WinGet Check"
}

$wingetStatus = Test-WinGetInstalled
$wingetInstalled = $wingetStatus.Installed
$wingetWorking = $wingetStatus.Working

if ($wingetInstalled -and $wingetWorking) {
    Write-Log "WinGet is already installed and working (Version: $($wingetStatus.Version)). Skipping WinGet installation." -Level 'SUCCESS' -Section "WinGet Check"
    $script:AlreadySetItems += "WinGet (v$($wingetStatus.Version))"
    End-Section "WinGet Check"
    $skipWinGetInstall = $true
} else {
    if ($isRunningAsSystem) {
        Write-Log "WinGet is not available in admin context (expected - WinGet is user-scoped)." -Level 'WARNING' -Section "WinGet Check"
        Write-Log "WinGet installation and operations should be done in a non-elevated user session." -Level 'WARNING' -Section "WinGet Check"
        Write-Host "NOTE: WinGet operations will be skipped when running as admin." -ForegroundColor Yellow
        Write-Host "Please run WinGet commands manually in a non-elevated PowerShell session." -ForegroundColor Yellow
    } else {
        Write-Log "WinGet is not installed or not working. Proceeding with installation..." -Level 'INFO' -Section "WinGet Check"
    }
    End-Section "WinGet Check"
    $skipWinGetInstall = $false
}

# Only proceed with WinGet installation if it's not already installed
if (-not $skipWinGetInstall) {
    # Install WinGet using preferred method from official documentation
    # Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/
    # WinGet is available as part of App Installer, a System Component
    Start-Section "WinGet Bootstrap"
    $wingetBootstrapSuccess = $false
    
    # Preferred Method 1: Register App Installer (System Component method)
    # WinGet comes with App Installer, which is a System Component on Windows 10/11
    # If App Installer exists but WinGet isn't registered, we can register it
    try {
        Write-Log "Attempting to register App Installer (preferred method)..." -Level 'INFO' -Section "WinGet Bootstrap"
        Write-Log "WinGet is part of App Installer, a System Component delivered via Microsoft Store" -Level 'INFO' -Section "WinGet Bootstrap"
        Write-Log "Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/" -Level 'INFO' -Section "WinGet Bootstrap"
        
        # Register App Installer package to make WinGet available
        # This is the preferred method per Microsoft documentation
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        # Refresh PATH to pick up WinGet
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Start-Sleep -Seconds 2
        
        # Verify WinGet is now working
        $verifyStatus = Test-WinGetInstalled
        if ($verifyStatus.Installed -and $verifyStatus.Working) {
            Write-Log "WinGet registered successfully via App Installer (Version: $($verifyStatus.Version))" -Level 'SUCCESS' -Section "WinGet Bootstrap"
            Write-Log "Skipping alternative install methods - App Installer method succeeded" -Level 'INFO' -Section "WinGet Bootstrap"
            $wingetBootstrapSuccess = $true
        } else {
            Write-Log "App Installer registration completed but WinGet not yet available. May need PowerShell restart." -Level 'WARNING' -Section "WinGet Bootstrap"
            $wingetBootstrapSuccess = $false
        }
    } catch {
        Write-Log "App Installer registration method failed. Will try alternative install methods." -Level 'WARNING' -Section "WinGet Bootstrap" -Exception $_
        $wingetBootstrapSuccess = $false
    }
    
    # Alternative Install Methods: Only run if App Installer method failed
    # PowerShell module method (for Windows Sandbox and environments without App Installer)
    # This method is specifically recommended for Windows Sandbox per Microsoft documentation
    if (-not $wingetBootstrapSuccess) {
        try {
            Write-Log "Attempting PowerShell module method (for Windows Sandbox and other environments)..." -Level 'INFO' -Section "WinGet Bootstrap"
            Write-Log "This method works in Windows Sandbox where App Installer may not be available" -Level 'INFO' -Section "WinGet Bootstrap"
            
            # Install NuGet package provider (required for PowerShell Gallery)
            Write-Log "Installing NuGet package provider..." -Level 'INFO' -Section "WinGet Bootstrap"
            Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            Write-Log "NuGet package provider installed successfully" -Level 'SUCCESS' -Section "WinGet Bootstrap"
            
            # Install Microsoft.WinGet.Client module
            Write-Log "Installing Microsoft.WinGet.Client PowerShell module..." -Level 'INFO' -Section "WinGet Bootstrap"
            Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -ErrorAction Stop | Out-Null
            Write-Log "Microsoft.WinGet.Client module installed successfully" -Level 'SUCCESS' -Section "WinGet Bootstrap"
            
            # Bootstrap WinGet using Repair-WinGetPackageManager
            Write-Log "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..." -Level 'INFO' -Section "WinGet Bootstrap"
            Repair-WinGetPackageManager -AllUsers -ErrorAction Stop
            Write-Log "WinGet bootstrapped successfully via PowerShell module" -Level 'SUCCESS' -Section "WinGet Bootstrap"
            
            # Refresh PATH and verify WinGet is now working
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Start-Sleep -Seconds 3
            
            $fallbackStatus = Test-WinGetInstalled
            if ($fallbackStatus.Installed -and $fallbackStatus.Working) {
                Write-Log "WinGet verified and working after PowerShell module installation (Version: $($fallbackStatus.Version))" -Level 'SUCCESS' -Section "WinGet Bootstrap"
                $wingetBootstrapSuccess = $true
            } else {
                Write-Log "WinGet installed via PowerShell module but not yet available. May need PowerShell restart." -Level 'WARNING' -Section "WinGet Bootstrap"
            }
        } catch {
            $script:ErrorCount++
            Write-Log "PowerShell module method also failed" -Level 'WARNING' -Section "WinGet Bootstrap" -Exception $_
        }
    }
    
    # Final fallback: Manual installation instructions
    if (-not $wingetBootstrapSuccess) {
        Write-Log "All automated methods failed. WinGet may need manual installation." -Level 'ERROR' -Section "WinGet Bootstrap"
        Write-Log "Please install WinGet manually from: https://www.microsoft.com/store/productId/9NBLGGH4NNS1" -Level 'INFO' -Section "WinGet Bootstrap"
        Write-Log "Or download from: https://github.com/microsoft/winget-cli/releases" -Level 'INFO' -Section "WinGet Bootstrap"
    }
    
    End-Section "WinGet Bootstrap"
}

# ---------------
# Enable WinGet Configuration Features (required for DSC files)
Start-Section "WinGet Configuration Enable"
$configEnabled = Ensure-WinGetConfigurationEnabled -Section "WinGet Configuration Enable"
if (-not $configEnabled) {
    $script:ErrorCount++
    Write-Log "WinGet configuration features could not be enabled. DSC configurations may fail." -Level 'ERROR' -Section "WinGet Configuration Enable"
    Write-Log "You may need to run 'winget configure --enable' manually as Administrator." -Level 'WARNING' -Section "WinGet Configuration Enable"
}
End-Section "WinGet Configuration Enable"

# ---------------
# NOTE: NFS Client installation is now handled in Phase 1 (before reboot)
# This section is skipped as NFS is handled earlier in the script
# ---------------
# Installing NFS Client feature (moved to start as it may require reboot)
# REMOVED - Now handled in Phase 1
# Start-Section "NFS Client Installation"
$nfsNeedsReboot = $false
try {
    # Try different feature names depending on Windows version
    $nfsFeatureNames = @("ClientForNFS-Infrastructure", "ServicesForNFS-ClientOnly")
    $nfsInstalled = $false
    
    foreach ($featureName in $nfsFeatureNames) {
        if (Test-WindowsFeatureInstalled -FeatureName $featureName) {
            Write-Log "NFS Client feature ($featureName) is already installed" -Level 'INFO' -Section "NFS Client Installation"
            $script:AlreadySetItems += "NFS Client"
            $nfsInstalled = $true
            break
        } else {
        $nfsFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
        if ($nfsFeature) {
                Write-Log "Installing NFS Client feature ($featureName) - this may take a few minutes..." -Level 'INFO' -Section "NFS Client Installation"
                $installSuccess = $false
                
                # Try Enable-WindowsOptionalFeature first (PowerShell method)
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Stop | Out-Null
                    Write-Log "NFS Client feature ($featureName) installed successfully using PowerShell method" -Level 'SUCCESS' -Section "NFS Client Installation"
                    $nfsInstalled = $true
                    $nfsNeedsReboot = $true
                    $installSuccess = $true
                    break
                } catch {
                    # If COM exception (Class not registered), try DISM as fallback
                    if ($_.Exception.Message -match "Class not registered" -or $_.Exception -is [System.Runtime.InteropServices.COMException]) {
                        Write-Log "PowerShell method failed with COM exception. Trying DISM as fallback..." -Level 'WARNING' -Section "NFS Client Installation"
                        try {
                            # Use DISM to enable the feature
                            $dismResult = dism.exe /Online /Enable-Feature /FeatureName:$featureName /All /NoRestart 2>&1 | Out-String
                            $dismExitCode = $LASTEXITCODE
                            
                            if ($dismExitCode -eq 0 -or $dismResult -match "completed successfully" -or $dismResult -match "The operation completed successfully") {
                                Write-Log "NFS Client feature ($featureName) installed successfully using DISM" -Level 'SUCCESS' -Section "NFS Client Installation"
                                $nfsInstalled = $true
                                $nfsNeedsReboot = $true
                                $installSuccess = $true
                                break
                            } else {
                                Write-Log "DISM installation attempt failed. Exit code: $dismExitCode" -Level 'WARNING' -Section "NFS Client Installation"
                                Write-Log "DISM output: $dismResult" -Level 'INFO' -Section "NFS Client Installation"
                            }
                        } catch {
                            Write-Log "DISM fallback also failed: $_" -Level 'WARNING' -Section "NFS Client Installation"
                        }
                    } else {
                        # Other error, log it
                        $script:ErrorCount++
                        Write-Log "Failed to install NFS Client feature ($featureName)" -Level 'ERROR' -Section "NFS Client Installation" -Exception $_
                    }
                }
            }
        }
    }
    
    if (-not $nfsInstalled) {
        Write-Warning "Could not find or install NFS Client feature. NFS drive mapping may fail."
    }
    
    # Prompt for reboot if NFS was just installed.
    # In -Unattended mode (or if Phase 1 already armed the RunOnce path), auto-reboot.
    if ($nfsNeedsReboot) {
        Write-Host ""
        Write-Host "NFS Client feature requires a system restart to function properly." -ForegroundColor Yellow
        Write-Host ""
        if ($Unattended) {
            Write-Host "Unattended mode: restarting in 10 seconds... Press Ctrl+C to cancel" -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            Restart-Computer -Force
            exit
        }
        $rebootChoice = Read-Host "Would you like to restart now? (Y/N)"
        if ($rebootChoice -eq 'Y' -or $rebootChoice -eq 'y') {
            Write-Host "Restarting computer in 10 seconds... Press Ctrl+C to cancel"
            Start-Sleep -Seconds 10
            Restart-Computer -Force
            exit
        } else {
            Write-Host "Skipping reboot. Please restart manually and run this script again to continue."
            Write-Host "The script will continue, but NFS drive mapping may fail until after reboot."
            Write-Host ""
        }
    }
} catch {
    $script:ErrorCount++
    Write-Log "Failed to install NFS Client feature" -Level 'ERROR' -Section "NFS Client Installation" -Exception $_
}
End-Section "NFS Client Installation"
# ---------------

# ---------------
# Activating Windows with HWID (integrated - no external file needed)
# Moved to start of script to activate Windows early
Start-Section "Windows HWID Activation"
try {
    Write-Log "Checking Windows activation status..." -Level 'INFO' -Section "Windows HWID Activation"
    
    # Check if Windows is already permanently activated using helper function
    if (Test-WindowsActivated) {
        Write-Log "Windows is already permanently activated - skipping activation" -Level 'SUCCESS' -Section "Windows HWID Activation"
        $script:AlreadySetItems += "Windows Activation"
        End-Section "Windows HWID Activation"
        # Continue with rest of script - don't return
    } else {
        Write-Log "Windows is not activated, proceeding with HWID activation..." -Level 'INFO' -Section "Windows HWID Activation"
        
        try {
            # Check Windows version/build
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            $buildNumber = [int]$osInfo.BuildNumber
            $edition = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name EditionID).EditionID
            
            Write-Log "Windows Edition: $edition, Build: $buildNumber" -Level 'INFO' -Section "Windows HWID Activation"
            
            # HWID activation is only supported on Windows 10/11 (build 10240+)
            if ($buildNumber -lt 10240) {
                Write-Log "HWID activation is only supported on Windows 10/11 (build 10240+). Current build: $buildNumber" -Level 'WARNING' -Section "Windows HWID Activation"
                End-Section "Windows HWID Activation"
                # Continue with rest of script - don't return
            } elseif (Test-Path "$env:SystemRoot\Servicing\Packages\Microsoft-Windows-Server*Edition~*.mum") {
                # Check if it's Windows Server (not supported)
                Write-Log "HWID activation is not supported on Windows Server" -Level 'WARNING' -Section "Windows HWID Activation"
                End-Section "Windows HWID Activation"
                # Continue with rest of script - don't return
            } else {
                # Check internet connection (Google public DNS used as a well-known reachable target)
                $connectivityProbeHost = "8.8.8.8"
                $internetConnected = $false
                try {
                    $testConnection = Test-Connection -ComputerName $connectivityProbeHost -Count 1 -Quiet -ErrorAction Stop
                    if ($testConnection) {
                        $internetConnected = $true
                    }
                } catch {
                    # Try alternative method
                    try {
                        $webClient = New-Object System.Net.NetworkInformation.Ping
                        $result = $webClient.Send($connectivityProbeHost, 1000)
                        $internetConnected = ($result.Status -eq 'Success')
                    } catch {
                        $internetConnected = $false
                    }
                }
                
                if (-not $internetConnected) {
                    Write-Log "Internet connection required for HWID activation. Skipping activation." -Level 'WARNING' -Section "Windows HWID Activation"
                    End-Section "Windows HWID Activation"
                    # Continue with rest of script - don't return
                } else {
                    Write-Log "Internet connection verified" -Level 'INFO' -Section "Windows HWID Activation"
                    
                    # Generic product keys for Windows 10/11 editions (for installation/upgrade purposes)
                    # These are publicly available generic keys that allow installation and activation via digital license
                    $genericKeys = @{
                        'Windows 10 Home' = 'TX9XD-98N7V-6WMQ6-BX7FG-H8Q99'
                        'Windows 10 Home N' = '3KHY7-WNT83-DGQKR-F7HPR-844BM'
                        'Windows 10 Home Single Language' = '7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH'
                        'Windows 10 Home Country Specific' = 'PVMJN-6DFY6-9CCP6-7BKTT-D3WVR'
                        'Windows 10 Professional' = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
                        'Windows 10 Professional N' = 'MH37W-N47XK-V7XM9-C7227-GCQG9'
                        'Windows 10 Professional Education' = '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'
                        'Windows 10 Professional Education N' = 'YVWGF-BXNMC-HTQYQ-CPQ99-66QFC'
                        'Windows 10 Professional Workstation' = 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'
                        'Windows 10 Professional Workstation N' = '9FNHH-K3HBT-3W4TD-6383H-6XYWF'
                        'Windows 10 Education' = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
                        'Windows 10 Education N' = '2WH4N-8QGBV-H22JP-CT43Q-MDWWJ'
                        'Windows 10 Enterprise' = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
                        'Windows 10 Enterprise N' = 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'
                        'Windows 10 Enterprise G' = 'YYVX9-NTFWV-6MDM3-9PT4T-4M68B'
                        'Windows 10 Enterprise G N' = '44RPN-FTY23-9VTTB-MP9BX-T84FV'
                        'Windows 10 Enterprise LTSB 2015' = 'WNMTR-4C88C-JK8YV-HQ7T2-76DF9'
                        'Windows 10 Enterprise LTSB 2016' = 'DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ'
                        'Windows 10 Enterprise LTSC 2019' = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'
                        'Windows 10 Enterprise LTSC 2021' = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'
                        'Windows 11 Home' = 'TX9XD-98N7V-6WMQ6-BX7FG-H8Q99'
                        'Windows 11 Home N' = '3KHY7-WNT83-DGQKR-F7HPR-844BM'
                        'Windows 11 Home Single Language' = '7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH'
                        'Windows 11 Home Country Specific' = 'PVMJN-6DFY6-9CCP6-7BKTT-D3WVR'
                        'Windows 11 Professional' = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
                        'Windows 11 Professional N' = 'MH37W-N47XK-V7XM9-C7227-GCQG9'
                        'Windows 11 Professional Education' = '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'
                        'Windows 11 Professional Education N' = 'YVWGF-BXNMC-HTQYQ-CPQ99-66QFC'
                        'Windows 11 Professional Workstation' = 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'
                        'Windows 11 Professional Workstation N' = '9FNHH-K3HBT-3W4TD-6383H-6XYWF'
                        'Windows 11 Education' = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
                        'Windows 11 Education N' = '2WH4N-8QGBV-H22JP-CT43Q-MDWWJ'
                        'Windows 11 Enterprise' = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
                        'Windows 11 Enterprise N' = 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'
                        'Windows 11 Enterprise G' = 'YYVX9-NTFWV-6MDM3-9PT4T-4M68B'
                        'Windows 11 Enterprise G N' = '44RPN-FTY23-9VTTB-MP9BX-T84FV'
                    }
                    
                    # Map edition ID to key name
                    $editionKeyMap = @{
                        'Core' = 'Windows 10 Home'
                        'CoreN' = 'Windows 10 Home N'
                        'CoreSingleLanguage' = 'Windows 10 Home Single Language'
                        'CoreCountrySpecific' = 'Windows 10 Home Country Specific'
                        'Professional' = 'Windows 10 Professional'
                        'ProfessionalN' = 'Windows 10 Professional N'
                        'ProfessionalEducation' = 'Windows 10 Professional Education'
                        'ProfessionalEducationN' = 'Windows 10 Professional Education N'
                        'ProfessionalWorkstation' = 'Windows 10 Professional Workstation'
                        'ProfessionalWorkstationN' = 'Windows 10 Professional Workstation N'
                        'Education' = 'Windows 10 Education'
                        'EducationN' = 'Windows 10 Education N'
                        'Enterprise' = 'Windows 10 Enterprise'
                        'EnterpriseN' = 'Windows 10 Enterprise N'
                        'EnterpriseG' = 'Windows 10 Enterprise G'
                        'EnterpriseGN' = 'Windows 10 Enterprise G N'
                        'EnterpriseS' = 'Windows 10 Enterprise'
                        'EnterpriseSN' = 'Windows 10 Enterprise N'
                    }
                    
                    # For Windows 11, use same mapping but with Windows 11 keys
                    if ($buildNumber -ge 22000) {
                        $editionKeyMap = @{
                            'Core' = 'Windows 11 Home'
                            'CoreN' = 'Windows 11 Home N'
                            'CoreSingleLanguage' = 'Windows 11 Home Single Language'
                            'CoreCountrySpecific' = 'Windows 11 Home Country Specific'
                            'Professional' = 'Windows 11 Professional'
                            'ProfessionalN' = 'Windows 11 Professional N'
                            'ProfessionalEducation' = 'Windows 11 Professional Education'
                            'ProfessionalEducationN' = 'Windows 11 Professional Education N'
                            'ProfessionalWorkstation' = 'Windows 11 Professional Workstation'
                            'ProfessionalWorkstationN' = 'Windows 11 Professional Workstation N'
                            'Education' = 'Windows 11 Education'
                            'EducationN' = 'Windows 11 Education N'
                            'Enterprise' = 'Windows 11 Enterprise'
                            'EnterpriseN' = 'Windows 11 Enterprise N'
                            'EnterpriseG' = 'Windows 11 Enterprise G'
                            'EnterpriseGN' = 'Windows 11 Enterprise G N'
                            'EnterpriseS' = 'Windows 11 Enterprise'
                            'EnterpriseSN' = 'Windows 11 Enterprise N'
                        }
                    }
                    
                    # Get the appropriate generic key
                    $keyName = $editionKeyMap[$edition]
                    if (-not $keyName) {
                        Write-Log "Edition '$edition' not supported for HWID activation" -Level 'WARNING' -Section "Windows HWID Activation"
                        End-Section "Windows HWID Activation"
                        # Continue with rest of script - don't return
                    } elseif (-not $genericKeys[$keyName]) {
                        Write-Log "No generic key found for edition: $keyName" -Level 'WARNING' -Section "Windows HWID Activation"
                        End-Section "Windows HWID Activation"
                        # Continue with rest of script - don't return
                    } else {
                        $genericKey = $genericKeys[$keyName]
                        Write-Log "Installing generic product key for $keyName..." -Level 'INFO' -Section "Windows HWID Activation"
                        
                        # Install the generic product key using slmgr
                        $installKeyResult = & cscript.exe //B //Nologo "$env:SystemRoot\System32\slmgr.vbs" /ipk $genericKey 2>&1
                        $installKeyOutput = $installKeyResult -join "`n"
                        
                        if ($installKeyOutput -match "successfully|installed") {
                            Write-Log "Product key installed successfully" -Level 'SUCCESS' -Section "Windows HWID Activation"
                        } else {
                            Write-Log "Product key installation output: $installKeyOutput" -Level 'INFO' -Section "Windows HWID Activation"
                        }
                        
                        # Activate Windows using slmgr /ato (activates online)
                        Write-Log "Activating Windows online..." -Level 'INFO' -Section "Windows HWID Activation"
                        $activateResult = & cscript.exe //B //Nologo "$env:SystemRoot\System32\slmgr.vbs" /ato 2>&1
                        $activateOutput = $activateResult -join "`n"
                        
                        Write-Log "Activation output: $activateOutput" -Level 'INFO' -Section "Windows HWID Activation"
                        
                        # Wait a moment for activation to process
                        Start-Sleep -Seconds 5
                        
                        # Check activation status
                        $finalStatus = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { 
                            $_.PartialProductKey -and $_.LicenseStatus -eq 1 
                        } | Select-Object -First 1
                        
                        # Wait a bit more and check activation status again
                        Start-Sleep -Seconds 3
                        
                        # Final verification using helper function
                        if (Test-WindowsActivated) {
                            Write-Log "Windows successfully activated with digital license" -Level 'SUCCESS' -Section "Windows HWID Activation"
                        } else {
                            Write-Log "Activation may still be processing. Please check activation status manually." -Level 'INFO' -Section "Windows HWID Activation"
                            Write-Log "You can check activation status with: slmgr /xpr" -Level 'INFO' -Section "Windows HWID Activation"
                        }
                    }
                }
            }
        } catch {
            $script:ErrorCount++
            Write-Log "Error during Windows HWID activation" -Level 'ERROR' -Section "Windows HWID Activation" -Exception $_
        }
    }
} catch {
    $script:ErrorCount++
    Write-Log "Error during Windows HWID activation check" -Level 'ERROR' -Section "Windows HWID Activation" -Exception $_
}
End-Section "Windows HWID Activation"
# ---------------

# Try to use local DSC files first, then fall back to GitHub
$scriptDir = Split-Path $mypath -Parent
# CRITICAL: Use $env:TEMP for DSC files to avoid saving to System32 when running from RunOnce
# Only reference DSC files that actually exist in the repository
$dscAdmin = Join-Path $env:TEMP "rpbush.dev.dsc.yml"
$dscOffice = Join-Path $env:TEMP "rpbush.office.dsc.yml"

# Check if DSC files exist locally (in script directory)
$dscAdminLocal = Join-Path $scriptDir "rpbush.dev.dsc.yml"
$dscOfficeLocal = Join-Path $scriptDir "rpbush.office.dsc.yml"

# GitHub repository for DSC files. Derived from -RepoOwner / -RepoName / -RepoBranch
# so a fork can override without editing the script. The DSC filenames remain
# `rpbush.*.dsc.yml` because they're the owner's personal configs; a fork should
# either keep the names or rename in lockstep here.
$dscUri = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$RepoBranch/"

# Use just the filename for URIs (not the full temp path)
$dscOfficeUri = $dscUri + "rpbush.office.dsc.yml"
$dscAdminUri = $dscUri + "rpbush.dev.dsc.yml"

# ============================================================================
# PHASE 1: PREREQUISITES & REBOOT HANDLING
# ============================================================================
# This phase handles features that require a reboot (like NFS Client)
# If a reboot is needed, the script will automatically restart and resume
# ============================================================================

if (-not $ResumeAfterReboot) {
    Write-Log "========================================" -Level 'INFO'
    Write-Log "PHASE 1: Prerequisites" -Level 'SECTION_START'
    Write-Log "========================================" -Level 'INFO'
    
    # Run non-admin DSC first (if needed)
    # Shoulder tap terminal to it gets registered moving forward
    try {
        Start-Process shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App -ErrorAction SilentlyContinue
    } catch {
        # Terminal may not be installed yet, continue
    }

    # NonAdmin DSC section removed - file does not exist in repository
    # Only rpbush.dev.dsc.yml and rpbush.office.dsc.yml are available
    
    # Check NFS Client installation - this requires a reboot
    # Note: The NFS section below (line 820+) will be skipped if we handle it here
    # We need to check if NFS needs installation and handle reboot
    $nfsNeedsReboot = $false
    $nfsInstalled = $false
    
    # OS capability guard: NFS Client is not supported on Windows Home editions
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    if ($osCaption -notmatch 'Pro|Enterprise|Education|Server') {
        Write-Log "NFS Client not supported on this Windows edition ($osCaption). Skipping NFS configuration." -Level 'WARNING' -Section "NFS Client Installation"
        Write-Host "  ⚠ NFS Client is not available on Windows Home edition" -ForegroundColor Yellow
        $script:WarningCount++
        $nfsInstalled = $false  # Mark as not installed so we skip NFS mapping
    } else {
        # Try different feature names depending on Windows version
        $nfsFeatureNames = @("ClientForNFS-Infrastructure", "ServicesForNFS-ClientOnly")
        
        foreach ($featureName in $nfsFeatureNames) {
            if (Test-WindowsFeatureInstalled -FeatureName $featureName) {
                Write-Log "NFS Client feature ($featureName) is already installed" -Level 'INFO' -Section "NFS Client Installation"
                $script:AlreadySetItems += "NFS Client"
                $nfsInstalled = $true
                break
            } else {
                $nfsFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
                if ($nfsFeature) {
                    Write-Log "Installing NFS Client feature ($featureName) - this requires a reboot..." -Level 'INFO' -Section "NFS Client Installation"
                    Write-Host "Installing NFS Client feature (this requires a reboot)..." -ForegroundColor Yellow
                
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Stop | Out-Null
                    Write-Log "NFS Client feature ($featureName) installation initiated" -Level 'SUCCESS' -Section "NFS Client Installation"
                    $nfsInstalled = $true
                    $nfsNeedsReboot = $true
                    break
                } catch {
                    if ($_.Exception.Message -match "Class not registered" -or $_.Exception -is [System.Runtime.InteropServices.COMException]) {
                        try {
                            $dismResult = dism.exe /Online /Enable-Feature /FeatureName:$featureName /All /NoRestart 2>&1 | Out-String
                            if ($LASTEXITCODE -eq 0 -or $dismResult -match "completed successfully") {
                                Write-Log "NFS Client feature ($featureName) installed successfully using DISM" -Level 'SUCCESS' -Section "NFS Client Installation"
                                $nfsInstalled = $true
                                $nfsNeedsReboot = $true
                                break
                            }
                        } catch {
                            # Continue to next feature name
                        }
                    }
                }
            }
        }
        }  # Close the else block that started at line 1251 (OS capability guard)
    }
    
    # If NFS was just installed, we need to reboot
    if ($nfsNeedsReboot) {
        Write-Host ""
        Write-Host "NFS Client feature requires a system restart to function properly." -ForegroundColor Yellow
        Write-Host "The script will automatically restart and resume after reboot." -ForegroundColor Yellow
        Write-Host ""
        
        Write-Log "NFS installed. Preparing for automatic reboot and resume..." -Level 'INFO'
        
        # CRITICAL: Copy script to safe location before reboot
        # The original path might be in a temp folder that gets cleaned up on reboot
        $safeDir = "C:\ProgramData\WorkstationSetup"
        if (-not (Test-Path $safeDir)) {
            New-Item -Path $safeDir -ItemType Directory -Force | Out-Null
            Write-Log "Created safe directory for script persistence: $safeDir" -Level 'INFO'
        }
        $safeScriptPath = Join-Path $safeDir "boot.ps1"
        
        # Copy current script to safe location
        Write-Log "Copying script, helper modules, and DSC files to safe location..." -Level 'INFO'
        Copy-Item -Path $mypath -Destination $safeScriptPath -Force
        Write-Log "Script copied successfully to safe location: $safeScriptPath" -Level 'SUCCESS'

        # CRITICAL: Copy the src/ helper modules too. boot.ps1 dot-sources src/*.ps1
        # at startup, so without these the post-reboot run will exit immediately.
        $sourceDir = Split-Path $mypath -Parent
        $sourceSrcDir = Join-Path $sourceDir 'src'
        if (Test-Path $sourceSrcDir) {
            $destSrcDir = Join-Path $safeDir 'src'
            Copy-Item -Path $sourceSrcDir -Destination $destSrcDir -Recurse -Force
            Write-Log "Copied src/ helper modules to safe location for resume" -Level 'SUCCESS'
        } else {
            Write-Log "src/ directory not found next to script — post-reboot resume will fail" -Level 'ERROR'
            $script:ErrorCount++
        }

        # CRITICAL: Copy any YAML files in the same directory to the safe location
        # This ensures offline resume capability - if script is run from a folder with local DSC files,
        # they will be available after reboot even if the original folder is deleted
        $yamlFiles = @()
        $yamlFiles += Get-ChildItem -Path $sourceDir -Filter "*.yaml" -ErrorAction SilentlyContinue
        $yamlFiles += Get-ChildItem -Path $sourceDir -Filter "*.yml" -ErrorAction SilentlyContinue

        if ($yamlFiles.Count -gt 0) {
            foreach ($yamlFile in $yamlFiles) {
                $destPath = Join-Path $safeDir $yamlFile.Name
                Copy-Item -Path $yamlFile.FullName -Destination $destPath -Force
                Write-Log "Copied DSC file to safe location: $($yamlFile.Name)" -Level 'INFO'
            }
            Write-Log "Copied $($yamlFiles.Count) DSC file(s) to safe location for offline resume" -Level 'SUCCESS'
        } else {
            Write-Log "No local DSC files found in source directory - will download from GitHub after reboot" -Level 'INFO'
        }
        
        # Create a RunOnce key to auto-start this script on next login
        # We add the -ResumeAfterReboot flag here
        # IMPORTANT: Use the safe path, not the original temp path
        $command = "PowerShell.exe -ExecutionPolicy Bypass -File `"$safeScriptPath`" -ResumeAfterReboot"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ContinueSetup" -Value $command -Force
        Write-Log "RunOnce key created pointing to safe script location" -Level 'INFO'
        
        Write-Log "RunOnce key created. Rebooting in 10 seconds..." -Level 'INFO'
        Write-Host "Rebooting in 10 seconds... Press Ctrl+C to cancel" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
        Exit  # Stop script here, let Windows restart
    }
    
    Write-Log "========================================" -Level 'INFO'
    Write-Log "PHASE 1: Prerequisites Complete" -Level 'SECTION_END'
    Write-Log "========================================" -Level 'INFO'
} else {
    Write-Log "========================================" -Level 'INFO'
    Write-Log "Resuming after reboot..." -Level 'SECTION_START'
    Write-Log "========================================" -Level 'INFO'
    
    # Remove the RunOnce key since we've resumed
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ContinueSetup" -ErrorAction SilentlyContinue
}

# ============================================================================
# PHASE 2: MAIN INSTALLATION & CONFIGURATION
# ============================================================================
# This phase runs after prerequisites are met (and after reboot if needed)
# ============================================================================

Write-Log "========================================" -Level 'INFO'
Write-Log "PHASE 2: Main Installation & Configuration" -Level 'SECTION_START'
Write-Log "========================================" -Level 'INFO'

# Admin section now
    # ---------------
    # Windows Settings: a single section that applies all dependency-free
    # OS-level tweaks (registry / powercfg). Settings with prerequisites
    # (e.g., setting PowerShell 7 as the default Windows Terminal profile)
    # stay near their dependency further down.
    Write-Host "Start: Applying Windows settings"
    Start-Section "Windows Settings"
    try {
        # --- File Explorer: show hidden files / folders / drives -----------
        try {
            $explorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            if (-not (Test-Path $explorerKey)) {
                New-Item -Path $explorerKey -Force | Out-Null
            }
            Set-ItemProperty -Path $explorerKey -Name "Hidden" -Value 2 -Type DWORD -Force
            Write-Log "File Explorer configured to show hidden files, folders, and drives" -Level 'SUCCESS' -Section "Windows Settings"
            $script:SettingsApplied += "File Explorer: Show hidden files/folders"

            # Restart explorer.exe to apply the registry changes
            Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process "explorer.exe"
        } catch {
            $script:ErrorCount++
            Write-Log "Failed to configure File Explorer settings" -Level 'ERROR' -Section "Windows Settings" -Exception $_
        }

        # --- Power profile: Ultimate Performance, falling back to High ----
        try {
            $powerSchemes = powercfg /list 2>$null

            function Get-PowerSchemeGuid {
                param([string]$SchemeName)
                # Parse `powercfg /list` output: "Power Scheme GUID: <guid> (<Name>)"
                $lines = $powerSchemes -split "`n"
                foreach ($line in $lines) {
                    if ($line -match "($([regex]::Escape($SchemeName)))" -and $line -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
                        return $matches[2]
                    }
                }
                return $null
            }

            $ultimatePerfGuid = Get-PowerSchemeGuid "Ultimate Performance"
            if ($ultimatePerfGuid) {
                powercfg /setactive $ultimatePerfGuid 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Power profile set to Ultimate Performance" -Level 'SUCCESS' -Section "Windows Settings"
                    $script:SettingsApplied += "Power Profile: Ultimate Performance"
                } else {
                    Write-Warning "Failed to set Ultimate Performance profile"
                }
            } else {
                $highPerfGuid = Get-PowerSchemeGuid "High Performance"
                if ($highPerfGuid) {
                    powercfg /setactive $highPerfGuid 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "Power profile set to High Performance" -Level 'SUCCESS' -Section "Windows Settings"
                        $script:SettingsApplied += "Power Profile: High Performance"
                    } else {
                        Write-Warning "Failed to set High Performance profile"
                    }
                } else {
                    # Last resort: standard GUIDs (consistent across Windows installs)
                    $standardUltimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
                    $standardHighGuid     = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
                    if ($powerSchemes -match $standardUltimateGuid) {
                        powercfg /setactive $standardUltimateGuid 2>$null
                        Write-Log "Power profile set to Ultimate Performance (via standard GUID)" -Level 'SUCCESS' -Section "Windows Settings"
                        $script:SettingsApplied += "Power Profile: Ultimate Performance"
                    } elseif ($powerSchemes -match $standardHighGuid) {
                        powercfg /setactive $standardHighGuid 2>$null
                        Write-Log "Power profile set to High Performance (via standard GUID)" -Level 'SUCCESS' -Section "Windows Settings"
                        $script:SettingsApplied += "Power Profile: High Performance"
                    } else {
                        Write-Warning "Performance power profile not found. Available profiles:"
                        $powerSchemes | ForEach-Object { Write-Host "  $_" }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to set power profile: $_"
        }

        # --- System tray: always show all icons ----------------------------
        try {
            # Clear the hidden-icons cache so the new setting takes effect.
            $trayNotifyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
            if (Test-Path $trayNotifyPath) {
                Remove-ItemProperty -Path $trayNotifyPath -Name "IconStreams"     -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $trayNotifyPath -Name "PastIconsStream" -ErrorAction SilentlyContinue
            }

            $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
            if (-not (Test-Path $explorerPath)) {
                New-Item -Path $explorerPath -Force | Out-Null
            }
            # EnableAutoTray: 0 = show all icons, 1 = hide some
            Set-ItemProperty -Path $explorerPath -Name "EnableAutoTray" -Value 0 -Type DWORD -Force
            Write-Log "System tray configured to show all icons" -Level 'SUCCESS' -Section "Windows Settings"
            $script:SettingsApplied += "System Tray: Show all icons"
        } catch {
            Write-Warning "Failed to configure system tray: $_"
        }
    } finally {
        End-Section "Windows Settings"
    }
    Write-Host "Done: Applying Windows settings"
    # ---------------
    # Adding Microsoft Account (MSA) sign-in
    # Note: Windows does not provide a direct command-line method to add a Microsoft account
    # The process requires user interaction through the Windows Settings GUI
    Write-Host "Start: Microsoft Account sign-in"
    try {
        Write-Host "Opening Windows Settings for Microsoft Account sign-in..."
        Write-Host ""
        Write-Host "Note: Windows does not support command-line Microsoft account sign-in." -ForegroundColor Yellow
        Write-Host "You will need to complete the sign-in process in the Settings window." -ForegroundColor Yellow
        Write-Host ""
        
        if ($Unattended) {
            Write-Host "Unattended mode: skipping interactive Microsoft Account sign-in." -ForegroundColor Yellow
            Write-Host "Sign in later via Settings > Accounts > Email & accounts."
        } else {
            # Open Windows Settings to the Accounts page for adding a Microsoft account
            Start-Process "ms-settings:emailandaccounts" -ErrorAction Stop

            Write-Host "Instructions:" -ForegroundColor Cyan
            Write-Host "1. In the Settings window, click 'Add a Microsoft account' or 'Add account'"
            Write-Host "2. Enter your Microsoft Account email address"
            Write-Host "3. Enter your password and follow the authentication prompts"
            Write-Host "4. Complete any additional verification steps (if required)"
            Write-Host ""
            Write-Host "Press any key after you've completed the Microsoft Account sign-in (or to skip)..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host ""
        }
    } catch {
        Write-Warning "Failed to open account settings: $_"
        Write-Host "You can manually add your Microsoft Account from Settings > Accounts > Email & accounts"
    }
    Write-Host "Done: Microsoft Account sign-in"
    # ---------------
    # Installing Windows Features
    Write-Host "Start: Installing Windows Features"
    try {
        # Install Windows Sandbox feature
        Start-Section "Windows Sandbox Installation"
        $sandboxFeatureName = "Containers-DisposableClientVM"
        
        if (Test-WindowsFeatureInstalled -FeatureName $sandboxFeatureName) {
            Write-Log "Windows Sandbox feature is already installed" -Level 'INFO' -Section "Windows Sandbox Installation"
            $script:AlreadySetItems += "Windows Sandbox"
        } else {
        $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName $sandboxFeatureName -ErrorAction SilentlyContinue
        if ($sandboxFeature) {
                Write-Log "Installing Windows Sandbox feature - this may take a few minutes..." -Level 'INFO' -Section "Windows Sandbox Installation"
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName $sandboxFeatureName -All -NoRestart -ErrorAction Stop | Out-Null
                    Write-Log "Windows Sandbox feature installed successfully" -Level 'SUCCESS' -Section "Windows Sandbox Installation"
                } catch {
                    $script:ErrorCount++
                    Write-Log "Failed to install Windows Sandbox feature" -Level 'ERROR' -Section "Windows Sandbox Installation" -Exception $_
            }
        } else {
                $script:WarningCount++
                Write-Log "Could not find Windows Sandbox feature. It may not be available on this Windows edition." -Level 'WARNING' -Section "Windows Sandbox Installation"
        }
        }
        End-Section "Windows Sandbox Installation"
    } catch {
        Write-Warning "Failed to install Windows Sandbox feature: $_"
    }
    
    # Installing Windows Subsystem for Linux (WSL)
    # Reference: https://learn.microsoft.com/en-us/windows/wsl/
    Write-Host "Installing Windows Subsystem for Linux (WSL)..."
    try {
        # Check if WSL is already installed
        $wslInstalled = $false
        try {
            $wslStatus = wsl --status 2>$null
            if ($wslStatus) {
                $wslInstalled = $true
                Write-Host "WSL is already installed"
                $script:AlreadySetItems += "Windows Subsystem for Linux (WSL)"
                # Check if WSL 2 is set as default
                $wslVersion = wsl --status 2>$null | Select-String "Default Version"
                if ($wslVersion -notmatch "2") {
                    Write-Host "Setting WSL 2 as default version..."
                    wsl --set-default-version 2 2>$null
                    Write-Host "WSL 2 set as default version"
                } else {
                    Write-Host "WSL 2 is already the default version"
                }
            }
        } catch {
            # WSL not installed or not available
        }
        
        if (-not $wslInstalled) {
            Write-Host "Installing WSL using the recommended method (wsl --install)..."
            Write-Host "This will install WSL with the default Linux distribution (Ubuntu)"
            Write-Host "Reference: https://learn.microsoft.com/en-us/windows/wsl/install"
            
            # Use the modern wsl --install command (recommended by Microsoft)
            # This automatically enables required features and installs WSL 2
            try {
                $wslInstallOutput = wsl --install 2>&1
                
                # Check if installation was successful or if it requires a reboot
                if ($LASTEXITCODE -eq 0 -or $wslInstallOutput -match "restart" -or $wslInstallOutput -match "reboot") {
                    Write-Host "WSL installation initiated successfully"
                    Write-Host "Note: A system restart may be required to complete WSL installation"
                } else {
                    # If wsl --install fails, try manual installation
                    Write-Host "wsl --install did not complete automatically, trying manual installation..."
                    
                    # Enable WSL feature
                    if (Test-WindowsFeatureInstalled -FeatureName "Microsoft-Windows-Subsystem-Linux") {
                        Write-Log "Windows Subsystem for Linux feature is already enabled" -Level 'INFO' -Section "WSL Installation"
                    } else {
                        Write-Log "Enabling Windows Subsystem for Linux feature..." -Level 'INFO' -Section "WSL Installation"
                    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue
                    if ($wslFeature) {
                            try {
                                Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -All -NoRestart -ErrorAction Stop | Out-Null
                                Write-Log "Windows Subsystem for Linux feature enabled successfully" -Level 'SUCCESS' -Section "WSL Installation"
                            } catch {
                                $script:ErrorCount++
                                Write-Log "Failed to enable Windows Subsystem for Linux feature" -Level 'ERROR' -Section "WSL Installation" -Exception $_
                            }
                        }
                    }
                    
                    # Enable Virtual Machine Platform feature (required for WSL 2)
                    if (Test-WindowsFeatureInstalled -FeatureName "VirtualMachinePlatform") {
                        Write-Log "Virtual Machine Platform feature is already enabled" -Level 'INFO' -Section "WSL Installation"
                    } else {
                        Write-Log "Enabling Virtual Machine Platform feature (required for WSL 2)..." -Level 'INFO' -Section "WSL Installation"
                    $vmPlatformFeature = Get-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -ErrorAction SilentlyContinue
                    if ($vmPlatformFeature) {
                            try {
                                Enable-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -All -NoRestart -ErrorAction Stop | Out-Null
                                Write-Log "Virtual Machine Platform feature enabled successfully" -Level 'SUCCESS' -Section "WSL Installation"
                            } catch {
                                $script:ErrorCount++
                                Write-Log "Failed to enable Virtual Machine Platform feature" -Level 'ERROR' -Section "WSL Installation" -Exception $_
                            }
                        }
                    }
                    
                    # Set WSL 2 as default version
                    Write-Host "Setting WSL 2 as default version..."
                    wsl --set-default-version 2 2>$null
                    
                    # Install Ubuntu (default distribution)
                    Write-Host "Installing Ubuntu Linux distribution..."
                    wsl --install -d Ubuntu 2>$null
                    
                    Write-Host "WSL installation completed. A system restart may be required."
                }
            } catch {
                Write-Warning "WSL installation encountered an error: $_"
                Write-Host "You may need to install WSL manually. See: https://learn.microsoft.com/en-us/windows/wsl/install"
            }
        }
        
        # List installed distributions and check for Ubuntu
        # WSL distributions are user-specific, so when running as admin (SYSTEM), 
        # we need to check/install in the logged-in user's context
        Write-Host "Checking installed WSL distributions..."
        $ubuntuInstalled = $false
        $isRunningAsSystem = ($env:USERNAME -eq "SYSTEM")
        
        try {
            if ($isRunningAsSystem) {
                # Running as SYSTEM/admin - WSL distributions are user-specific
                # Get the logged-in user to check their WSL distributions
                $loggedInUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
                if ($loggedInUser -and $loggedInUser -ne "SYSTEM") {
                    $username = $loggedInUser.Split('\')[-1]
                    Write-Log "Running as SYSTEM - checking WSL distributions for logged-in user: $username" -Level 'INFO' -Section "WSL Installation"
                    Write-Host "Note: Checking WSL distributions for user: $username"
                    
                    # Create a temporary script to run wsl --list as the logged-in user
                    $tempScript = Join-Path $env:TEMP "check-wsl-ubuntu.ps1"
                    $checkScript = @"
`$wslList = wsl --list 2>`$null
if (`$wslList -match 'Ubuntu') {
    Write-Output 'UBUNTU_FOUND'
} else {
    Write-Output 'UBUNTU_NOT_FOUND'
}
"@
                    $checkScript | Out-File -FilePath $tempScript -Encoding UTF8 -Force
                    
                    # Try to run as the logged-in user using runas (requires password, so may not work)
                    # Instead, just note that Ubuntu check needs to happen at user level
                    Write-Host "WSL distributions are user-specific. Ubuntu check should be done at user level."
                    Write-Host "If Ubuntu is already installed, it will be detected when running at user level."
                    Write-Log "Skipping Ubuntu check when running as SYSTEM (user-specific)" -Level 'INFO' -Section "WSL Installation"
                } else {
                    Write-Host "Could not determine logged-in user. Ubuntu check skipped."
                    Write-Log "Could not determine logged-in user for WSL check" -Level 'WARNING' -Section "WSL Installation"
                }
            } else {
                # Running in user context - can check directly
                Write-Log "Running in user context - checking WSL distributions directly" -Level 'INFO' -Section "WSL Installation"
                try {
                    # Use --quiet flag for cleaner output, or --verbose for more details
                    $wslListOutput = wsl --list --quiet 2>$null | Out-String
                    if (-not $wslListOutput) {
                        # Fallback to regular list if --quiet doesn't work
                        $wslListOutput = wsl --list 2>$null | Out-String
                    }
                    
                    if ($wslListOutput) {
                        Write-Host "Installed WSL distributions:"
                        $wslListOutput -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" }
                        
                        # Check if Ubuntu is already installed - check for various Ubuntu distribution names
                        # Ubuntu distributions can be named: Ubuntu, Ubuntu-22.04, Ubuntu-20.04, Ubuntu (Default), etc.
                        $ubuntuPatterns = @(
                            '^\s*Ubuntu\s*$',
                            '^\s*Ubuntu\s*\(Default\)',
                            '^\s*Ubuntu-\d+\.\d+',
                            '^\s*Ubuntu\s+\d+\.\d+',
                            '\bUbuntu\b'
                        )
                        
                        $ubuntuFound = $false
                        foreach ($pattern in $ubuntuPatterns) {
                            if ($wslListOutput -match $pattern) {
                                $ubuntuFound = $true
                                break
                            }
                        }
                        
                        # Also check each line individually for more precise matching
                        if (-not $ubuntuFound) {
                            $wslLines = $wslListOutput -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch '^Windows Subsystem for Linux' -and $_ -notmatch '^\s*NAME\s*STATE\s*VERSION' }
                            foreach ($line in $wslLines) {
                                $lineTrimmed = $line.Trim()
                                if ($lineTrimmed -match '^Ubuntu' -or $lineTrimmed -match '\bUbuntu\b') {
                                    $ubuntuFound = $true
                                    break
                                }
                            }
                        }
                        
                        if ($ubuntuFound) {
                            $ubuntuInstalled = $true
                            Write-Host "Ubuntu is already installed"
                            $script:AlreadySetItems += "WSL Ubuntu"
                        }
                    } else {
                        Write-Host "No WSL distributions found or WSL not yet available"
                    }
                } catch {
                    Write-Log "Error checking WSL list: $_" -Level 'WARNING' -Section "WSL Installation"
                    Write-Host "Could not check WSL distributions list"
                }
            }
        } catch {
            Write-Host "No WSL distributions found or WSL not yet available"
            Write-Log "Error checking WSL distributions: $_" -Level 'WARNING' -Section "WSL Installation" -Exception $_
        }
        
        # Install Ubuntu if WSL is installed but Ubuntu is not
        # Note: Ubuntu installation must be done at user level, not admin level
        if ($wslInstalled -and -not $ubuntuInstalled) {
            if ($isRunningAsSystem) {
                # Running as SYSTEM - Ubuntu installation must happen at user level
                Write-Host "WSL is installed but Ubuntu check/install must be done at user level."
                Write-Host "Please run 'wsl --install ubuntu' manually in a user context, or"
                Write-Host "the script will attempt to install it when run at user level."
                Write-Log "Skipping Ubuntu installation when running as SYSTEM (user-specific operation)" -Level 'WARNING' -Section "WSL Installation"
                $script:WarningCount++
            } else {
                # Running in user context - can install directly
                # Double-check Ubuntu is not installed before attempting installation
                $finalCheck = $false
                try {
                    $finalWslList = wsl --list --quiet 2>$null | Out-String
                    if (-not $finalWslList) {
                        $finalWslList = wsl --list 2>$null | Out-String
                    }
                    if ($finalWslList -and ($finalWslList -match '\bUbuntu\b')) {
                        $finalCheck = $true
                        Write-Host "Ubuntu is already installed (verified before installation attempt)"
                        $script:AlreadySetItems += "WSL Ubuntu"
                    }
                } catch {
                    # If check fails, proceed with installation attempt
                }
                
                if (-not $finalCheck) {
                    Write-Host "WSL is installed but Ubuntu is not. Installing Ubuntu..."
                    Write-Log "Installing Ubuntu (running in user context)" -Level 'INFO' -Section "WSL Installation"
                    try {
                        $ubuntuInstallOutput = wsl --install ubuntu 2>&1 | Out-String
                        # Check if the output indicates Ubuntu is already installed
                        if ($ubuntuInstallOutput -match 'already installed' -or $ubuntuInstallOutput -match 'is already a valid distribution') {
                            Write-Host "Ubuntu is already installed (detected during installation attempt)"
                            $script:AlreadySetItems += "WSL Ubuntu"
                        } elseif ($LASTEXITCODE -eq 0) {
                            Write-Host "Ubuntu installation initiated successfully"
                            $script:InstalledItems += "WSL Ubuntu"
                        } else {
                            # Check if error is because Ubuntu is already installed
                            if ($ubuntuInstallOutput -match 'already' -or $ubuntuInstallOutput -match 'exists') {
                                Write-Host "Ubuntu appears to be already installed"
                                $script:AlreadySetItems += "WSL Ubuntu"
                            } else {
                                Write-Log "Ubuntu installation may require user interaction or a reboot" -Level 'WARNING' -Section "WSL Installation"
                                Write-Host "Note: Ubuntu installation may require user interaction or a system restart"
                            }
                        }
                    } catch {
                        $script:WarningCount++
                        Write-Log "Failed to install Ubuntu: $_" -Level 'WARNING' -Section "WSL Installation" -Exception $_
                        Write-Host "You can install Ubuntu manually using: wsl --install ubuntu"
                    }
                }
            }
        }
        
    } catch {
        Write-Warning "Failed to install WSL: $_"
        Write-Host "You can install WSL manually using: wsl --install"
        Write-Host "Documentation: https://learn.microsoft.com/en-us/windows/wsl/install"
    }
    Write-Host "Done: Installing Windows Features"
    # ---------------
    # Power profile + system tray + File Explorer settings are applied earlier
    # in the "Windows Settings" section near the top of Phase 2.
    # Network drive mapping is handled via Group Policy, not this script.
    # ---------------
    # Installing Windows Terminal
    # Reference: https://learn.microsoft.com/en-us/windows/terminal/
    Write-Host "Start: Installing Windows Terminal"
    try {
        # Check if Windows Terminal is already installed
        if (Test-AppxPackageInstalled -PackageName "Microsoft.WindowsTerminal") {
        $wtInstalled = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
            Write-Log "Windows Terminal is already installed (Version: $($wtInstalled.Version))" -Level 'INFO' -Section "Windows Terminal Installation"
            $script:AlreadySetItems += "Windows Terminal (v$($wtInstalled.Version))"
        } else {
            Write-Host "Installing Windows Terminal using WinGet..."
            Write-Host "Reference: https://learn.microsoft.com/en-us/windows/terminal/install"
            
            # Install Windows Terminal using winget (recommended by Microsoft)
            # Use -e for exact match and --accept-package-agreements for automation
            try {
                Write-Host "  → Installing Windows Terminal via winget..." -ForegroundColor Cyan
                $wingetOutput = winget install --id Microsoft.WindowsTerminal -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-String
                
                # Show progress from output
                Show-WinGetProgress -OutputText $wingetOutput -Section "Windows Terminal Installation"
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  ✓ Windows Terminal installed successfully" -ForegroundColor Green
                } elseif (Test-MicrosoftStoreAvailable) {
                    Write-Log "WinGet installation may have failed. Trying Microsoft Store fallback..." -Level 'WARNING' -Section "Windows Terminal Installation"
                    try {
                        Start-Process "ms-windows-store://pdp/?ProductId=9N0DX20HK701" -ErrorAction Stop
                        Start-Sleep -Seconds 2  # Give Store time to open

                        $installed = Wait-ForStoreInstallation -AppName "Windows Terminal" -PackageName "Microsoft.WindowsTerminal"
                        if ($installed) {
                            $wtCheck = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
                            if ($wtCheck) {
                                Write-Log "Windows Terminal installed via Microsoft Store" -Level 'SUCCESS' -Section "Windows Terminal Installation"
                            }
                        }
                    } catch {
                        $script:ErrorCount++
                        Write-Log "Could not open Microsoft Store for Windows Terminal" -Level 'ERROR' -Section "Windows Terminal Installation" -Exception $_
                    }
                } else {
                    $script:WarningCount++
                    Write-Log "WinGet install of Windows Terminal failed and Microsoft Store is unavailable on this edition. Skipping fallback." -Level 'WARNING' -Section "Windows Terminal Installation"
                }
            } catch {
                Write-Warning "Failed to install Windows Terminal via WinGet: $_"
                Write-Host "You can install Windows Terminal manually from: https://www.microsoft.com/store/productId/9N0DX20HK701"
            }
        }
        
        # Verify installation
        $wtFinalCheck = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
        if ($wtFinalCheck) {
            Write-Host "Windows Terminal is available and ready to use"
        } else {
            Write-Warning "Windows Terminal installation could not be verified"
        }
        
    } catch {
        Write-Warning "Failed to install Windows Terminal: $_"
        Write-Host "You can install Windows Terminal manually using: winget install --id Microsoft.WindowsTerminal -e"
        Write-Host "Or from Microsoft Store: https://www.microsoft.com/store/productId/9N0DX20HK701"
    }
    Write-Host "Done: Installing Windows Terminal"
    # ---------------
    # Installing office workload
    Write-Host "Start: Office install"
    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\' -Name 'DefaultProfile' -Value "OutlookAuto" -PropertyType String -Force

    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\OutlookAuto' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\OutlookAuto' -Name 'Default' -Value "" -PropertyType String -Force


    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover' -Name 'ZeroConfigExchange' -Value "1" -PropertyType DWORD -Force

    # Run gpupdate and check for MDM failures
    Write-Host "`n[STEP] Group Policy Update - Applying policy changes..." -ForegroundColor Cyan
    Write-Host "  → Running gpupdate /force..." -ForegroundColor Gray
    Start-Section "Group Policy Update"
    
    try {
        # Capture both stdout and stderr from gpupdate
        $gpupdateOutput = & cmd.exe /c "gpupdate /force 2>&1" | Out-String
        Write-Log "Group Policy update command executed" -Level 'INFO' -Section "Group Policy Update"
        Write-Log "gpupdate output: $gpupdateOutput" -Level 'INFO' -Section "Group Policy Update"
        Write-Host "  ✓ Group Policy update completed" -ForegroundColor Green
        
        # Check for MDM failures in the output (case-insensitive, multiple patterns)
        $mdmFailurePatterns = @(
            "MDM.*failed",
            "failed.*MDM",
            "MDM Policy.*failed",
            "Windows failed to apply the MDM",
            "failed to apply the MDM Policy",
            "MDM Policy settings"
        )
        
        $mdmFailureDetected = $false
        foreach ($pattern in $mdmFailurePatterns) {
            if ($gpupdateOutput -match $pattern) {
                $mdmFailureDetected = $true
                break
            }
        }
        
        if ($mdmFailureDetected) {
            Write-Log "MDM failure detected in gpupdate output" -Level 'WARNING' -Section "Group Policy Update"
            Write-Host "  ⚠ MDM failure detected in Group Policy update" -ForegroundColor Yellow
            Write-Host "  → Cleaning up MDM failed registry attempts..." -ForegroundColor Gray
            
            $cleaned = Clear-MDMFailedRegistryAttempts -Section "Group Policy Update"
            if ($cleaned) {
                Write-Host "  ✓ MDM cleanup completed" -ForegroundColor Green
                $script:SuccessCount++
                $script:SettingsApplied += "MDM failed registry cleanup"
                if (-not $script:SectionResults.ContainsKey("Group Policy Update")) {
                    $script:SectionResults["Group Policy Update"] = @{
                        Status = "Success"
                        Message = "MDM failures cleaned up"
                    }
                }
            } else {
                if (-not $script:SectionResults.ContainsKey("Group Policy Update")) {
                    $script:SectionResults["Group Policy Update"] = @{
                        Status = "Warning"
                        Message = "MDM failure detected but no cleanup needed"
                    }
                }
            }
        } else {
            Write-Log "No MDM failures detected in gpupdate output" -Level 'INFO' -Section "Group Policy Update"
            $script:SettingsApplied += "Group Policy update"
            if (-not $script:SectionResults.ContainsKey("Group Policy Update")) {
                $script:SectionResults["Group Policy Update"] = @{
                    Status = "Success"
                    Message = "Group Policy updated successfully"
                }
            }
        }
    } catch {
        Write-Log "Error running gpupdate: $_" -Level 'WARNING' -Section "Group Policy Update" -Exception $_
        Write-Host "  ⚠ Error running gpupdate: $_" -ForegroundColor Yellow
        if (-not $script:SectionResults.ContainsKey("Group Policy Update")) {
            $script:SectionResults["Group Policy Update"] = @{
                Status = "Warning"
                Message = "Error running gpupdate: $_"
            }
        }
    }
    
    End-Section "Group Policy Update"

    Start-Section "Office Installation"
    Write-Host "`n[STEP] Office Installation - Checking if Office is already installed..." -ForegroundColor Cyan
    
    # Check if Office is already installed using reliable detection methods
    $officeInstalled = $false
    $teamsInstalled = $false
    
    Write-Log "Checking if Microsoft Office is already installed..." -Level 'INFO' -Section "Office Installation"
    Write-Host "  → Checking for Outlook.exe and Office registry keys..." -ForegroundColor Gray
    if (Test-OfficeInstalled) {
        Write-Log "Microsoft Office is already installed, skipping installation" -Level 'SUCCESS' -Section "Office Installation"
        Write-Host "  ✓ Microsoft Office is already installed" -ForegroundColor Green
        $officeInstalled = $true
        $script:SuccessCount++
        $script:AlreadySetItems += "Microsoft Office"
    } else {
        Write-Log "Microsoft Office not detected via direct methods, checking winget (with timeout)..." -Level 'INFO' -Section "Office Installation"
        Write-Host "  → Office not found via direct methods, checking winget catalog (5s timeout)..." -ForegroundColor Gray
        # Fallback to winget check with short timeout
        if (Test-SoftwareInstalled -PackageId "Microsoft.Office" -TimeoutSeconds 5) {
            Write-Log "Microsoft Office detected via winget, skipping installation" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Microsoft Office detected via winget" -ForegroundColor Green
            $officeInstalled = $true
            $script:SuccessCount++
        } else {
            Write-Log "Microsoft Office not detected - will attempt installation" -Level 'INFO' -Section "Office Installation"
            Write-Host "  → Office not found - will install via DSC" -ForegroundColor Yellow
        }
    }
    
    Write-Log "Checking if Microsoft Teams is already installed..." -Level 'INFO' -Section "Office Installation"
    Write-Host "  → Checking for Teams executable..." -ForegroundColor Gray
    if (Test-TeamsInstalled) {
            Write-Log "Microsoft Teams is already installed, skipping installation" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Microsoft Teams is already installed" -ForegroundColor Green
            $teamsInstalled = $true
            $script:SuccessCount++
            $script:AlreadySetItems += "Microsoft Teams"
    } else {
        Write-Log "Microsoft Teams not detected via direct methods, checking winget (with timeout)..." -Level 'INFO' -Section "Office Installation"
        Write-Host "  → Teams not found via direct methods, checking winget catalog (5s timeout)..." -ForegroundColor Gray
        # Fallback to winget check with short timeout
        if (Test-SoftwareInstalled -PackageId "Microsoft.Teams" -TimeoutSeconds 5) {
            Write-Log "Microsoft Teams detected via winget, skipping installation" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Microsoft Teams detected via winget" -ForegroundColor Green
            $teamsInstalled = $true
            $script:SuccessCount++
        } else {
            Write-Log "Microsoft Teams not detected - will attempt installation" -Level 'INFO' -Section "Office Installation"
            Write-Host "  → Teams not found - will install via DSC" -ForegroundColor Yellow
        }
    }
    
    # If Office is already installed, skip DSC configuration to avoid conflicts
    # The DSC configuration installs both Office and Teams, so if Office exists, skip it
    if ($officeInstalled) {
        Write-Host "`n[SKIP] Office is already installed - skipping DSC configuration to avoid conflicts" -ForegroundColor Green
        if ($teamsInstalled) {
            Write-Log "Office and Teams are already installed, skipping DSC configuration" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Both Office and Teams are installed" -ForegroundColor Green
        } else {
            Write-Log "Office is already installed, skipping DSC configuration. Teams can be installed separately if needed." -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  → Office installed, Teams not found (can be installed separately if needed)" -ForegroundColor Yellow
        }
        # Start Outlook if it exists
        $outlookPath = Get-Command outlook.exe -ErrorAction SilentlyContinue
        if ($outlookPath) {
            Start-Process outlook.exe -ErrorAction SilentlyContinue
            Write-Log "Outlook started successfully" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Started Outlook" -ForegroundColor Green
        }
        # Start Teams if it exists
        $teamsPath = Get-Command ms-teams.exe -ErrorAction SilentlyContinue
        if ($teamsPath) {
            Start-Process ms-teams.exe -ErrorAction SilentlyContinue
            Write-Log "Teams started successfully" -Level 'SUCCESS' -Section "Office Installation"
            Write-Host "  ✓ Started Teams" -ForegroundColor Green
        }
        # Mark Office section as successful
        if (-not $script:SectionResults.ContainsKey("Office Installation")) {
            $script:SectionResults["Office Installation"] = @{
                Status = "Success"
                Message = "Office already installed, skipped DSC"
            }
        }
    } else {
        Write-Host "`n[INSTALL] Office not found - proceeding with installation via DSC" -ForegroundColor Cyan
        $officeDscDownloaded = $false
        
        # Check if file exists locally first
        Write-Host "  → Preparing Office DSC configuration file..." -ForegroundColor Gray
        if (Test-Path $dscOfficeLocal) {
            Write-Log "Using local Office DSC file: $dscOfficeLocal" -Level 'INFO' -Section "Office Installation"
            Write-Host "  → Using local DSC file: $dscOfficeLocal" -ForegroundColor Gray
            Copy-Item $dscOfficeLocal $dscOffice -Force
            $officeDscDownloaded = $true
        } else {
            try {
                Write-Log "Downloading Office DSC configuration from: $dscOfficeUri" -Level 'INFO' -Section "Office Installation"
                Write-Host "  → Downloading Office DSC configuration..." -ForegroundColor Gray
                $downloadStart = Get-Date
                Invoke-WebRequest -Uri $dscOfficeUri -OutFile $dscOffice -ErrorAction Stop
                $downloadDuration = (Get-Date) - $downloadStart
                Write-Log "Office DSC downloaded successfully (Duration: $($downloadDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "Office Installation"
                Write-Host "  ✓ DSC file downloaded ($($downloadDuration.TotalSeconds.ToString('F2'))s)" -ForegroundColor Green
                $officeDscDownloaded = $true
            } catch {
                $script:ErrorCount++
                Write-Log "Failed to download Office DSC configuration" -Level 'ERROR' -Section "Office Installation" -Exception $_
                Write-Host "  ✗ Failed to download Office DSC configuration" -ForegroundColor Red
                Write-Host "    Error: $_" -ForegroundColor Red
                if (-not $script:SectionResults.ContainsKey("Office Installation")) {
                    $script:SectionResults["Office Installation"] = @{
                        Status = "Failed"
                        Message = "Failed to download DSC configuration: $_"
                    }
                }
            }
        }
    
        if ($officeDscDownloaded) {
            # Ensure WinGet configuration is enabled before running DSC
            Write-Host "  → Verifying WinGet configuration is enabled..." -ForegroundColor Gray
            Write-Log "Verifying WinGet configuration is enabled before Office DSC..." -Level 'INFO' -Section "Office Installation"
            $configEnabled = Ensure-WinGetConfigurationEnabled -Section "Office Installation"
            if (-not $configEnabled) {
                $script:ErrorCount++
                Write-Log "Cannot proceed with Office DSC - WinGet configuration features are not enabled" -Level 'ERROR' -Section "Office Installation"
                Write-Host "  ✗ WinGet configuration features are not enabled" -ForegroundColor Red
                if (-not $script:SectionResults.ContainsKey("Office Installation")) {
                    $script:SectionResults["Office Installation"] = @{
                        Status = "Failed"
                        Message = "WinGet configuration features not enabled"
                    }
                }
            } else {
                Write-Host "  ✓ WinGet configuration enabled" -ForegroundColor Green
                # Refresh winget catalog to ensure connectivity
                Write-Host "  → Refreshing winget catalog to ensure connectivity..." -ForegroundColor Gray
                $catalogRefreshed = Refresh-WinGetCatalog -Section "Office Installation"
                if ($catalogRefreshed) {
                    Write-Host "  ✓ Winget catalog refreshed" -ForegroundColor Green
                } else {
                    Write-Host "  ⚠ Winget catalog refresh had issues (continuing anyway)" -ForegroundColor Yellow
                }
                
                try {
                    Write-Host "  → Running winget configuration for Office (this may take a few minutes)..." -ForegroundColor Gray
                    Write-Log "Running winget configuration for Office DSC" -Level 'INFO' -Section "Office Installation"
                    $configStart = Get-Date
                    $configOutput = winget configuration -f $dscOffice --accept-configuration-agreements 2>&1
                    $configDuration = (Get-Date) - $configStart
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "Office DSC configuration completed successfully (Duration: $($configDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "Office Installation"
                        Write-Host "  ✓ Office installation completed successfully ($($configDuration.TotalSeconds.ToString('F2'))s)" -ForegroundColor Green
                        $script:SuccessCount++
                        if (-not $script:SectionResults.ContainsKey("Office Installation")) {
                            $script:SectionResults["Office Installation"] = @{
                                Status = "Success"
                                Message = "Office installed via DSC"
                            }
                        }
                    } else {
                        $script:ErrorCount++
                        Write-Log "Office DSC configuration failed with exit code: $LASTEXITCODE" -Level 'ERROR' -Section "Office Installation"
                        if ($configOutput -is [array]) {
                            $outputText = $configOutput -join " | "
                        } else {
                            $outputText = $configOutput.ToString()
                        }
                        Write-Log "Output: $outputText" -Level 'ERROR' -Section "Office Installation"
                        Write-Host "  ✗ Office installation failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
                        
                        # Check for catalog connection errors
                        if ($outputText -match "error.*connecting.*catalog|error.*occurred.*connecting|catalog.*error") {
                            Write-Host "    ERROR: Catalog connection failure detected" -ForegroundColor Red
                            Write-Host "    This may be due to:" -ForegroundColor Yellow
                            Write-Host "      - Network connectivity issues" -ForegroundColor Yellow
                            Write-Host "      - Firewall blocking winget catalog access" -ForegroundColor Yellow
                            Write-Host "      - Winget catalog service temporarily unavailable" -ForegroundColor Yellow
                            Write-Host "    Try running 'winget source update' manually" -ForegroundColor Yellow
                            Write-Log "Catalog connection error detected. This may indicate:" -Level 'WARNING' -Section "Office Installation"
                            Write-Log "1. Network connectivity issues" -Level 'WARNING' -Section "Office Installation"
                            Write-Log "2. Firewall blocking winget catalog access" -Level 'WARNING' -Section "Office Installation"
                            Write-Log "3. Winget catalog service temporarily unavailable" -Level 'WARNING' -Section "Office Installation"
                            Write-Log "Try running 'winget source update' manually to refresh the catalog" -Level 'INFO' -Section "Office Installation"
                        }
                        if (-not $script:SectionResults.ContainsKey("Office Installation")) {
                            $script:SectionResults["Office Installation"] = @{
                                Status = "Failed"
                                Message = "DSC configuration failed (exit code: $LASTEXITCODE)"
                            }
                        }
                    }
                } catch {
                    $script:ErrorCount++
                    Write-Log "Exception during Office DSC configuration" -Level 'ERROR' -Section "Office Installation" -Exception $_
                    Write-Host "  ✗ Exception during Office installation: $_" -ForegroundColor Red
                    if (-not $script:SectionResults.ContainsKey("Office Installation")) {
                        $script:SectionResults["Office Installation"] = @{
                            Status = "Failed"
                            Message = "Exception: $_"
                        }
                    }
                }
            }
        }
        
        # Cleanup and start applications (regardless of DSC success)
        if ($officeDscDownloaded) {
            if (Test-Path $dscOffice) {
                Remove-Item $dscOffice -verbose
            }
            
            # Start Outlook and Teams if they exist
            $outlookPath = Get-Command outlook.exe -ErrorAction SilentlyContinue
            if ($outlookPath) {
                Start-Process outlook.exe -ErrorAction SilentlyContinue
                Write-Log "Outlook started successfully" -Level 'SUCCESS' -Section "Office Installation"
            } else {
                $script:WarningCount++
                Write-Log "Outlook.exe not found. Office may not be installed yet." -Level 'WARNING' -Section "Office Installation"
            }
            
            $teamsPath = Get-Command ms-teams.exe -ErrorAction SilentlyContinue
            if ($teamsPath) {
                Start-Process ms-teams.exe -ErrorAction SilentlyContinue
            } else {
                $script:WarningCount++
                Write-Log "ms-teams.exe not found. Teams may not be installed yet." -Level 'WARNING' -Section "Office Installation"
            }
        }
    }  # End of else block for Office DSC configuration
    
    End-Section "Office Installation"
    # Ending office workload
    # ---------------

    # Starting dev workload
    Start-Section "Dev Flows Installation"
    Write-Host "`n[STEP] Dev Flows Installation - Installing development tools and applications..." -ForegroundColor Cyan
    
    # --------------------------------------------------------------------------
    # STEP 1: FIX WINGET CATALOG ERRORS
    # --------------------------------------------------------------------------
    Write-Host "  → Resetting Winget sources to fix catalog connection errors..." -ForegroundColor Gray
    Write-Log "Resetting Winget sources to fix Catalog connection errors..." -Level 'INFO' -Section "Dev Flows Installation"
    try {
        $resetOutput = winget source reset --force 2>&1 | Out-String
        Write-Log "Winget source reset completed" -Level 'INFO' -Section "Dev Flows Installation"
        Start-Sleep -Seconds 5
        Write-Log "Updating Winget sources after reset..." -Level 'INFO' -Section "Dev Flows Installation"
        $updateOutput = winget source update 2>&1 | Out-String
        Write-Log "Winget source update completed after reset" -Level 'INFO' -Section "Dev Flows Installation"
        Start-Sleep -Seconds 5
        Write-Host "  ✓ Winget sources reset and updated" -ForegroundColor Green
    } catch {
        Write-Log "Winget source reset failed, but continuing with DSC execution" -Level 'WARNING' -Section "Dev Flows Installation" -Exception $_
        Write-Host "  ⚠ Winget source reset had issues (continuing anyway)" -ForegroundColor Yellow
    }

    # --------------------------------------------------------------------------
    # STEP 2: SELECT DSC FILE
    # --------------------------------------------------------------------------
    # Dev Drive creation is delegated to the StorageDsc 'Disk' resource declared
    # in rpbush.dev.dsc.yml — it formats Z: as a 75GB ReFS Dev Drive on disk 0.
    # If conditions aren't met (already-formatted disk, insufficient space, Home
    # edition, etc.) the resource fails gracefully and the rest of the DSC still
    # applies. No imperative partitioning logic in PowerShell.
    $dscFileToUse = $dscAdmin
    $dscFileToUseLocal = $dscAdminLocal
    $dscFileToUseUri = $dscAdminUri

    Write-Log "Using Dev Flows DSC file: $dscFileToUse" -Level 'INFO' -Section "Dev Flows Installation"
    
    # Download or use local file
    if (Test-Path $dscFileToUseLocal) {
        Write-Log "Using local Dev flows DSC file: $dscFileToUseLocal" -Level 'INFO' -Section "Dev Flows Installation"
        Copy-Item $dscFileToUseLocal $dscFileToUse -Force
    } else {
        try {
            Write-Log "Downloading Dev flows DSC configuration from: $dscFileToUseUri" -Level 'INFO' -Section "Dev Flows Installation"
            $downloadStart = Get-Date
            Invoke-WebRequest -Uri $dscFileToUseUri -OutFile $dscFileToUse -ErrorAction Stop
            $downloadDuration = (Get-Date) - $downloadStart
            Write-Log "Dev flows DSC downloaded successfully (Duration: $($downloadDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "Dev Flows Installation"
        } catch {
            $script:ErrorCount++
            Write-Log "Failed to download Dev flows DSC configuration" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
            Write-Log "Skipping Dev flows installation due to download failure" -Level 'WARNING' -Section "Dev Flows Installation"
            End-Section "Dev Flows Installation"
            return
        }
    }
    
    # OLD REGEX EDITING CODE REMOVED - Now using separate files instead
    # This eliminates the fragile regex parsing that was causing DSC failures
    # Use --accept-configuration-agreements for winget configure (not --accept-package-agreements)
    Write-Log "Preparing to run winget configuration for Dev flows DSC..." -Level 'INFO' -Section "Dev Flows Installation"
    Write-Log "DSC file path: $dscFileToUse" -Level 'INFO' -Section "Dev Flows Installation"
    if (-not (Test-Path $dscFileToUse)) {
        $script:ErrorCount++
        Write-Log "DSC file does not exist: $dscFileToUse" -Level 'ERROR' -Section "Dev Flows Installation"
        End-Section "Dev Flows Installation"
        return
    }
    
    # Ensure WinGet configuration is enabled before running DSC
    Write-Host "  → Verifying WinGet configuration is enabled..." -ForegroundColor Gray
    Write-Log "Verifying WinGet configuration is enabled before Dev flows DSC..." -Level 'INFO' -Section "Dev Flows Installation"
    $configEnabled = Ensure-WinGetConfigurationEnabled -Section "Dev Flows Installation"
    if (-not $configEnabled) {
        $script:ErrorCount++
        Write-Log "Cannot proceed with Dev flows DSC - WinGet configuration features are not enabled" -Level 'ERROR' -Section "Dev Flows Installation"
        Write-Host "  ✗ WinGet configuration features are not enabled" -ForegroundColor Red
        $script:SectionResults["Dev Flows Installation"] = @{
            Status = "Failed"
            Message = "WinGet configuration features not enabled"
        }
        End-Section "Dev Flows Installation"
        return
    }
    Write-Host "  ✓ WinGet configuration enabled" -ForegroundColor Green
    
    # Note: Winget source reset and catalog refresh is now done at the top of this section (STEP 1)
    
    try {
        Write-Host "  → Running winget configuration for Dev Flows (this may take 10-30 minutes)..." -ForegroundColor Gray
        Write-Host "    Installing: Git, PowerShell 7, PowerToys, Signal, Steam, 7zip, Notepad++, GitHub CLI, Cursor, Windows Terminal, and more..." -ForegroundColor Gray
        Write-Log "Running winget configuration for Dev flows DSC (this may take several minutes)..." -Level 'INFO' -Section "Dev Flows Installation"
        Write-Log "DSC file contains packages: Git, PowerShell 7, PowerToys, Signal, Steam, 7zip, Notepad++, GitHub CLI, Cursor, Windows Terminal, and more..." -Level 'INFO' -Section "Dev Flows Installation"
        $configStart = Get-Date
        
        # Run winget configuration with real-time output streaming
        # All output will be logged to the main log file
        $configOutput = @()
        $script:currentPackage = $null
        $script:packageStartTime = $null
        
        # Ensure we have the full path to the DSC file
        $dscFileToUseFullPath = if ([System.IO.Path]::IsPathRooted($dscFileToUse)) {
            $dscFileToUse
        } else {
            $resolvedPath = Resolve-Path -Path $dscFileToUse -ErrorAction SilentlyContinue
            if ($resolvedPath) {
                $resolvedPath.Path
            } else {
                Join-Path (Get-Location) $dscFileToUse
            }
        }
        
        # Normalize the path (resolve any .. or . components)
        $dscFileToUseFullPath = [System.IO.Path]::GetFullPath($dscFileToUseFullPath)
        
        # Verify the file exists before running
        if (-not (Test-Path $dscFileToUseFullPath)) {
            $script:ErrorCount++
            Write-Log "DSC file not found at: $dscFileToUseFullPath" -Level 'ERROR' -Section "Dev Flows Installation"
            Write-Log "Original path: $dscFileToUse" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Current directory: $(Get-Location)" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Files in current directory: $((Get-ChildItem -File | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ')" -Level 'INFO' -Section "Dev Flows Installation"
            End-Section "Dev Flows Installation"
            return
        }
        
        Write-Log "Using DSC file: $dscFileToUseFullPath" -Level 'INFO' -Section "Dev Flows Installation"
        
        # Run winget configuration through cmd.exe for better output capture
        # This approach works better for capturing all output streams
        Write-Log "Running winget configuration via cmd.exe for better output capture..." -Level 'INFO' -Section "Dev Flows Installation"
        
        $tempOutputFile = [System.IO.Path]::GetTempFileName()
        $tempErrorFile = [System.IO.Path]::GetTempFileName()
        $outputText = ""
        $errorText = ""
        $exitCode = -1
        
        try {
            # Use cmd.exe to run winget configuration (captures output better)
            $cmdArgs = "/c `"winget configuration -f `"$dscFileToUseFullPath`" --accept-configuration-agreements 2>&1`""
            $proc = Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArgs -NoNewWindow -PassThru -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile
            
            # Monitor output file in real-time to show progress
            $lastSize = 0
            $processedContent = ""
            Write-Host "  → Starting package installations..." -ForegroundColor Cyan
            
            while (-not $proc.HasExited) {
                Start-Sleep -Milliseconds 500
                
                if (Test-Path $tempOutputFile) {
                    $currentContent = Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue
                    if ($currentContent -and $currentContent.Length -gt $lastSize) {
                        $newContent = $currentContent.Substring($lastSize)
                        $processedContent += $newContent
                        $lastSize = $currentContent.Length
                        
                        # Show progress from new content
                        Show-WinGetProgress -OutputText $newContent -Section "Dev Flows Installation"
                    }
                }
            }
            
            # Wait for process to fully exit
            $proc.WaitForExit()
            
            # Get final output
            $outputText = Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue
            $errorText = Get-Content $tempErrorFile -Raw -ErrorAction SilentlyContinue
            $exitCode = $proc.ExitCode
            
            # Show any remaining progress
            if ($outputText -and $outputText.Length -gt $lastSize) {
                $remainingContent = $outputText.Substring($lastSize)
                Show-WinGetProgress -OutputText $remainingContent -Section "Dev Flows Installation"
            }
            
            # Clean up temp files
            Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue
            Remove-Item $tempErrorFile -Force -ErrorAction SilentlyContinue
            
            Write-Log "winget configuration completed via cmd.exe (exit code: $exitCode)" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Output length: $($outputText.Length) characters, Error length: $($errorText.Length) characters" -Level 'INFO' -Section "Dev Flows Installation"
            
            # Parse output to track installed packages
            if ($outputText) {
                $outputLines = $outputText -split "`r?`n"
                # Define regex patterns as variables to avoid bracket interpretation issues
                $packagePattern = 'WinGetPackage\s+' + [char]91 + '([^' + [char]93 + ']+)' + [char]93
                $processingPattern = 'Processing.*' + [char]91 + '([^' + [char]93 + ']+)' + [char]93
                foreach ($line in $outputLines) {
                    $packageMatch = [regex]::Match($line, $packagePattern)
                    if (-not $packageMatch.Success) {
                        $packageMatch = [regex]::Match($line, $processingPattern)
                    }
                    if ($packageMatch.Success) {
                        $packageId = $packageMatch.Groups[1].Value
                        if ($packageId -and $packageId -notmatch '^\s*$') {
                            # Track package processing
                            if (-not ($script:InstalledItems -contains $packageId) -and -not ($script:AlreadySetItems -contains $packageId)) {
                                # Will be updated based on success/failure
                            }
                        }
                    }
                    if ($line -match 'Successfully|installed|completed') {
                        $packageMatch = [regex]::Match($line, $packagePattern)
                        if ($packageMatch.Success) {
                            $packageId = $packageMatch.Groups[1].Value
                            if ($packageId) {
                                $script:InstalledItems += "Dev Flows: $packageId"
                            }
                        }
                    }
                    if ($line -match 'Already\s+installed|Skipping|No\s+change') {
                        $packageMatch = [regex]::Match($line, $packagePattern)
                        if ($packageMatch.Success) {
                            $packageId = $packageMatch.Groups[1].Value
                            if ($packageId) {
                                $script:AlreadySetItems += "Dev Flows: $packageId"
                            }
                        }
                    }
                    if ($line -match 'Failed|Error') {
                        $packageMatch = [regex]::Match($line, $packagePattern)
                        if ($packageMatch.Success) {
                            $packageId = $packageMatch.Groups[1].Value
                            if ($packageId) {
                                $script:FailedItems += "Dev Flows: $packageId"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log "Error running winget configuration via cmd.exe: $_" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
            $exitCode = -1
        }
        
        # Log the captured output
        if ($outputText) {
            Write-Log "=== Winget Configuration Output ===" -Level 'INFO' -Section "Dev Flows Installation"
            $outputLines = $outputText -split "`r?`n"
            foreach ($line in $outputLines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Log "WINGET OUTPUT: $line" -Level 'INFO' -Section "Dev Flows Installation"
                }
            }
        }
        
        if ($errorText) {
            Write-Log "=== Winget Configuration Errors ===" -Level 'ERROR' -Section "Dev Flows Installation"
            $errorLines = $errorText -split "`r?`n"
            foreach ($line in $errorLines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Log "WINGET ERROR: $line" -Level 'ERROR' -Section "Dev Flows Installation"
                }
            }
        }
        
        $configDuration = (Get-Date) - $configStart
        Write-Log "winget configuration process completed with exit code: $exitCode (Duration: $($configDuration.TotalMinutes.ToString('F2')) minutes)" -Level 'INFO' -Section "Dev Flows Installation"
        
        # Note: If Dev Drive creation fails, the DSC will still continue with package installation
        # The Dev Drive resource failure is non-blocking - packages will still be installed
        if ($exitCode -ne 0 -and ($outputText -match "There is no unallocated space available to create the Dev Drive volume" -or $errorText -match "There is no unallocated space available to create the Dev Drive volume")) {
            Write-Log "Dev Drive creation failed due to lack of unallocated space, but package installation will continue." -Level 'WARNING' -Section "Dev Flows Installation"
            Write-Host "  ⚠ Dev Drive creation failed (no unallocated space), but packages will still install..." -ForegroundColor Yellow
        }
        
        if ($exitCode -eq 0) {
            Write-Log "Dev flows DSC configuration completed successfully" -Level 'SUCCESS' -Section "Dev Flows Installation"
            Write-Host "  ✓ Dev Flows installation completed successfully ($($configDuration.TotalMinutes.ToString('F2')) minutes)" -ForegroundColor Green
            $script:SuccessCount++
            $script:SectionResults["Dev Flows Installation"] = @{
                Status = "Success"
                Message = "Dev Flows installed via DSC"
            }
            # If no packages were tracked individually, mark the whole section as installed
            if ($script:InstalledItems.Count -eq 0 -or ($script:InstalledItems | Where-Object { $_ -like "Dev Flows:*" }).Count -eq 0) {
                $script:InstalledItems += "Dev Flows: All packages"
            }
        } else {
            $script:ErrorCount++
            Write-Log "Dev flows DSC configuration failed with exit code: $exitCode" -Level 'ERROR' -Section "Dev Flows Installation"
            Write-Host "  ✗ Dev Flows installation failed (exit code: $exitCode, Duration: $($configDuration.TotalMinutes.ToString('F2')) minutes)" -ForegroundColor Red
            # Mark Dev Flows as failed if no individual packages were tracked
            if (($script:FailedItems | Where-Object { $_ -like "Dev Flows:*" }).Count -eq 0) {
                $script:FailedItems += "Dev Flows: Installation failed (exit code: $exitCode)"
            }
            
            # Provide detailed error information
            if ($errorText) {
                Write-Log "Error details have been logged above. Review the WINGET ERROR section for specific failure information." -Level 'ERROR' -Section "Dev Flows Installation"
                Write-Host "    Review WINGET ERROR section in log for details" -ForegroundColor Yellow
            } else {
                Write-Log "No error output captured. This may indicate a silent failure or process termination." -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Host "    No error output captured - may be a silent failure" -ForegroundColor Yellow
            }
            
            # Check for catalog connection errors in both output and error text
            $allOutput = "$outputText $errorText"
            $catalogErrorDetected = $false
            
            if ($allOutput -match "error.*connecting.*catalog|error.*occurred.*connecting|catalog.*error|An error occurred while connecting to the catalog") {
                $catalogErrorDetected = $true
            }
            
            # Also check if exit code -1978286075 with empty output might indicate catalog issues
            if ($exitCode -eq -1978286075 -and [string]::IsNullOrWhiteSpace($outputText) -and [string]::IsNullOrWhiteSpace($errorText)) {
                Write-Log "Exit code -1978286075 with no output captured - likely catalog connection issue" -Level 'WARNING' -Section "Dev Flows Installation"
                $catalogErrorDetected = $true
            }
            
            if ($catalogErrorDetected) {
                Write-Host "    ERROR: Catalog connection failure detected" -ForegroundColor Red
                Write-Host "    This may be due to:" -ForegroundColor Yellow
                Write-Host "      - Network connectivity issues" -ForegroundColor Yellow
                Write-Host "      - Firewall blocking winget catalog access" -ForegroundColor Yellow
                Write-Host "      - Winget catalog service temporarily unavailable" -ForegroundColor Yellow
                Write-Host "    Try running 'winget source update' manually" -ForegroundColor Yellow
                Write-Log "Catalog connection error detected. This may indicate:" -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "1. Network connectivity issues" -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "2. Firewall blocking winget catalog access" -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "3. Winget catalog service temporarily unavailable" -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "Try running 'winget source update' manually to refresh the catalog" -Level 'INFO' -Section "Dev Flows Installation"
            }
            
            # Common error code meanings
            if ($exitCode -eq -1978286075) {
                Write-Host "    Exit code -1978286075: Configuration processing error or package installation failure" -ForegroundColor Yellow
                if ([string]::IsNullOrWhiteSpace($outputText) -and [string]::IsNullOrWhiteSpace($errorText)) {
                    Write-Host "    No output captured - this often indicates a catalog connection failure" -ForegroundColor Yellow
                    Write-Host "    The catalog refresh may have failed or timed out" -ForegroundColor Yellow
                } else {
                    Write-Host "    Check WINGET OUTPUT and WINGET ERROR sections in log for specific package that failed" -ForegroundColor Yellow
                }
                Write-Log "Exit code -1978286075 typically indicates a configuration processing error or package installation failure." -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "This may be caused by: package download failure, installation conflict, or DSC resource error." -Level 'WARNING' -Section "Dev Flows Installation"
                Write-Log "Check the WINGET OUTPUT and WINGET ERROR sections above for specific package or resource that failed." -Level 'INFO' -Section "Dev Flows Installation"
            }
            
            $script:SectionResults["Dev Flows Installation"] = @{
                Status = "Failed"
                Message = "DSC configuration failed (exit code: $exitCode)"
            }
            
            # Suggest troubleshooting steps
            Write-Log "Troubleshooting steps:" -Level 'WARNING' -Section "Dev Flows Installation"
            Write-Log "1. Review the WINGET ERROR output above to identify which package/resource failed" -Level 'WARNING' -Section "Dev Flows Installation"
            Write-Log "2. Try running the failed package installation manually: winget install <package-id>" -Level 'WARNING' -Section "Dev Flows Installation"
            Write-Log "3. Check if any packages in the DSC file are already installed and causing conflicts" -Level 'WARNING' -Section "Dev Flows Installation"
            Write-Log "4. Verify network connectivity if package downloads are failing" -Level 'WARNING' -Section "Dev Flows Installation"
        }
        
        # Log summary of packages processed using actual tracking arrays
        $devFlowsInstalled = ($script:InstalledItems | Where-Object { $_ -like "Dev Flows:*" }).Count
        $devFlowsAlreadySet = ($script:AlreadySetItems | Where-Object { $_ -like "Dev Flows:*" }).Count
        $devFlowsFailed = ($script:FailedItems | Where-Object { $_ -like "Dev Flows:*" }).Count
        $processedCount = $devFlowsInstalled + $devFlowsAlreadySet + $devFlowsFailed
        
        Write-Log "Dev Flows summary: Installed=$devFlowsInstalled, AlreadyConfigured=$devFlowsAlreadySet, Failed=$devFlowsFailed" -Level 'INFO' -Section "Dev Flows Installation"
        
        if ($processedCount -gt 0) {
            Write-Log "Total Dev Flows packages processed: $processedCount" -Level 'INFO' -Section "Dev Flows Installation"
        }
        
    } catch {
        $script:ErrorCount++
        Write-Log "Exception during Dev flows DSC configuration" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
    }

    # Clean up DSC file
    if (Test-Path $dscFileToUse) {
        Remove-Item $dscFileToUse -Force -ErrorAction SilentlyContinue
    }
    End-Section "Dev Flows Installation"
    # ending dev workload
    
    # Setting PowerShell 7 as default in Windows Terminal
    Write-Host "Start: Setting PowerShell 7 as default terminal"
    $wtSettingsPaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
        "$env:LOCALAPPDATA\Microsoft\Windows Terminal\settings.json"
    )
    
    foreach ($settingsPath in $wtSettingsPaths) {
        if (Test-Path $settingsPath) {
            try {
                $settingsContent = Get-Content $settingsPath -Raw
                $settings = $settingsContent | ConvertFrom-Json
                
                # Find PowerShell 7 profile (typically has commandline with pwsh.exe)
                $pwsh7Profile = $null
                if ($settings.profiles.list) {
                    $pwsh7Profile = $settings.profiles.list | Where-Object { 
                        ($_.commandline -like "*pwsh.exe*" -or $_.commandline -like "*pwsh*") -or 
                        $_.guid -eq "{574e775e-4f2a-5b96-ac1e-a2962a402336}" -or
                        $_.name -like "*PowerShell*7*"
                    } | Select-Object -First 1
                }
                
                if ($pwsh7Profile) {
                    # Set PowerShell 7 as default profile (check both root level and defaults object)
                    if ($settings.defaults) {
                        $settings.defaults.defaultProfile = $pwsh7Profile.guid
                    } else {
                        $settings.defaultProfile = $pwsh7Profile.guid
                    }
                    
                    # Preserve formatting by using ConvertTo-Json with proper depth
                    $jsonContent = $settings | ConvertTo-Json -Depth 10
                    # Windows Terminal expects UTF-8 with BOM for proper formatting
                    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
                    [System.IO.File]::WriteAllText($settingsPath, $jsonContent, $utf8WithBom)
                    Write-Host "PowerShell 7 set as default in Windows Terminal"
                    break
                } else {
                    Write-Warning "PowerShell 7 profile not found in Windows Terminal settings"
                }
            } catch {
                Write-Warning "Failed to update Windows Terminal settings: $_"
            }
        }
    }
    Write-Host "Done: Setting PowerShell 7 as default terminal"
    
    # Upgrade WinGet to Microsoft Store version for automatic updates (at the very end)
    # This is done last so Store unavailability doesn't interfere with the rest of the script
    Write-Host "Start: Upgrading WinGet to Microsoft Store version for automatic updates"
    try {
        # Check if WinGet is available
        $wingetAvailable = $false
        try {
            $wingetCheck = winget --info 2>$null
            if ($wingetCheck) {
                $wingetAvailable = $true
            }
        } catch {
            # WinGet not available
        }
        
        if ($wingetAvailable) {
            if (Test-MicrosoftStoreAvailable) {
                # Check if we already have the Store version
                $appInstaller = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue
                if ($appInstaller) {
                    Write-Host "WinGet is already installed from Microsoft Store - will receive automatic updates"
                } else {
                    Write-Log "Opening Microsoft Store to install/upgrade to Store version for automatic updates..." -Level 'INFO' -Section "WinGet Upgrade"
                    try {
                        Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1" -ErrorAction Stop
                        Start-Sleep -Seconds 2  # Give Store time to open
                        
                        $installed = Wait-ForStoreInstallation -AppName "App Installer (WinGet) - Store Version" -PackageName "Microsoft.DesktopAppInstaller"
                        if ($installed) {
                            Write-Log "WinGet Store version installation/upgrade completed" -Level 'SUCCESS' -Section "WinGet Upgrade"
                        }
                    } catch {
                        $script:WarningCount++
                        Write-Log "Could not open Microsoft Store for WinGet upgrade" -Level 'WARNING' -Section "WinGet Upgrade" -Exception $_
                        Write-Log "You can manually upgrade WinGet from: https://www.microsoft.com/store/productId/9NBLGGH4NNS1" -Level 'INFO' -Section "WinGet Upgrade"
                    }
                }
            } else {
                Write-Host "Microsoft Store not available (e.g., Windows Sandbox) - keeping current WinGet installation"
                Write-Host "Current WinGet installation will continue to work, but won't receive automatic updates"
            }
        } else {
            Write-Host "WinGet not available - skipping Store upgrade"
        }
    } catch {
        Write-Warning "Failed to upgrade WinGet to Store version: $_"
        Write-Host "This is non-critical - the script has completed successfully"
    }
    Write-Host "Done: Upgrading WinGet to Microsoft Store version"
    
    # Cleanup log path file
    Remove-Item $logPathFile -ErrorAction SilentlyContinue
    
Write-Log "========================================" -Level 'INFO'
Write-Log "PHASE 2: Main Installation & Configuration Complete" -Level 'SECTION_END'
Write-Log "========================================" -Level 'INFO'

# Cleanup log path file
Remove-Item $logPathFile -ErrorAction SilentlyContinue

# Final Summary
$scriptEndTime = Get-Date
$totalDuration = $scriptEndTime - $scriptStartTime

Write-Host "`n" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "WORKSTATION SETUP SCRIPT COMPLETED" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "========================================" -Level 'INFO'
Write-Log "Workstation Setup Script Completed" -Level 'SECTION_END'
Write-Log "========================================" -Level 'INFO'
Write-Log "Total Execution Time: $($totalDuration.TotalMinutes.ToString('F2')) minutes ($($totalDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'INFO'
Write-Log "Total Successes: $script:SuccessCount" -Level 'SUCCESS'
Write-Log "Total Errors: $script:ErrorCount" -Level $(if ($script:ErrorCount -gt 0) { 'ERROR' } else { 'SUCCESS' })
Write-Log "Total Warnings: $script:WarningCount" -Level $(if ($script:WarningCount -gt 0) { 'WARNING' } else { 'INFO' })
Write-Log "Log File Location: $logFilePath" -Level 'INFO'
Write-Log "========================================" -Level 'INFO'

# Comprehensive Summary
Write-Host "EXECUTION SUMMARY" -ForegroundColor White
Write-Host "  Total Time: $($totalDuration.TotalMinutes.ToString('F2')) minutes ($($totalDuration.TotalSeconds.ToString('F2')) seconds)" -ForegroundColor Gray
Write-Host ""

# Success Summary
$successSections = $script:SectionResults.GetEnumerator() | Where-Object { $_.Value.Status -eq "Success" }
if ($successSections.Count -gt 0) {
    Write-Host "✓ SUCCESSFUL SECTIONS ($($successSections.Count)):" -ForegroundColor Green
    foreach ($section in $successSections) {
        Write-Host "  ✓ $($section.Key)" -ForegroundColor Green
        if ($section.Value.Message) {
            Write-Host "    → $($section.Value.Message)" -ForegroundColor DarkGreen
        }
    }
    Write-Host ""
}

# Failed Summary
$failedSections = $script:SectionResults.GetEnumerator() | Where-Object { $_.Value.Status -eq "Failed" }
if ($failedSections.Count -gt 0) {
    Write-Host "✗ FAILED SECTIONS ($($failedSections.Count)):" -ForegroundColor Red
    foreach ($section in $failedSections) {
        Write-Host "  ✗ $($section.Key)" -ForegroundColor Red
        if ($section.Value.Message) {
            Write-Host "    → $($section.Value.Message)" -ForegroundColor DarkRed
        }
    }
    Write-Host ""
}

# Sections without explicit results (may have succeeded or been skipped)
$allSections = $script:SectionTimings.Keys
$trackedSections = $script:SectionResults.Keys
$untrackedSections = $allSections | Where-Object { $_ -notin $trackedSections }
if ($untrackedSections.Count -gt 0) {
    Write-Host "○ OTHER SECTIONS ($($untrackedSections.Count)):" -ForegroundColor Yellow
    foreach ($section in $untrackedSections) {
        $timing = $script:SectionTimings[$section]
        if ($timing.Duration) {
            Write-Host "  ○ $section ($($timing.Duration.TotalSeconds.ToString('F2'))s)" -ForegroundColor Yellow
        } else {
            Write-Host "  ○ $section" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Detailed Configuration Summary
Write-Host "DETAILED CONFIGURATION SUMMARY" -ForegroundColor White
Write-Host ""

# Software/Items Installed
if ($script:InstalledItems.Count -gt 0) {
    Write-Host "✓ INSTALLED/APPLIED ($($script:InstalledItems.Count)):" -ForegroundColor Green
    foreach ($item in $script:InstalledItems | Sort-Object) {
        Write-Host "  ✓ $item" -ForegroundColor Green
    }
    Write-Host ""
}

# Software/Items Already Set
if ($script:AlreadySetItems.Count -gt 0) {
    Write-Host "○ ALREADY INSTALLED/CONFIGURED ($($script:AlreadySetItems.Count)):" -ForegroundColor Yellow
    foreach ($item in $script:AlreadySetItems | Sort-Object) {
        Write-Host "  ○ $item" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Settings Applied
if ($script:SettingsApplied.Count -gt 0) {
    Write-Host "✓ SETTINGS APPLIED ($($script:SettingsApplied.Count)):" -ForegroundColor Green
    foreach ($setting in $script:SettingsApplied | Sort-Object) {
        Write-Host "  ✓ $setting" -ForegroundColor Green
    }
    Write-Host ""
}

# Failed Items
if ($script:FailedItems.Count -gt 0) {
    Write-Host "✗ FAILED TO INSTALL/CONFIGURE ($($script:FailedItems.Count)):" -ForegroundColor Red
    foreach ($item in $script:FailedItems | Sort-Object) {
        Write-Host "  ✗ $item" -ForegroundColor Red
    }
    Write-Host ""
}

# Error and Warning Summary
Write-Host "STATISTICS" -ForegroundColor White
Write-Host "  Successes: $script:SuccessCount" -ForegroundColor $(if ($script:SuccessCount -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  Errors: $script:ErrorCount" -ForegroundColor $(if ($script:ErrorCount -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  Warnings: $script:WarningCount" -ForegroundColor $(if ($script:WarningCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ""

# Section Timing Summary
Write-Host "SECTION TIMING SUMMARY" -ForegroundColor White
foreach ($section in $script:SectionTimings.Keys | Sort-Object) {
    $timing = $script:SectionTimings[$section]
    if ($timing.Duration) {
        $status = if ($script:SectionResults.ContainsKey($section)) {
            if ($script:SectionResults[$section].Status -eq "Success") { "✓" }
            elseif ($script:SectionResults[$section].Status -eq "Failed") { "✗" }
            else { "○" }
        } else { "○" }
        $color = if ($script:SectionResults.ContainsKey($section)) {
            if ($script:SectionResults[$section].Status -eq "Success") { "Green" }
            elseif ($script:SectionResults[$section].Status -eq "Failed") { "Red" }
            else { "Yellow" }
        } else { "Gray" }
        Write-Host "  $status $section : $($timing.Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor $color
        Write-Log "  $section : $($timing.Duration.TotalSeconds.ToString('F2')) seconds" -Level 'INFO'
    }
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "For detailed logs, review: $logFilePath" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "========================================" -Level 'INFO'
Write-Log "For optimization data, review the log file: $logFilePath" -Level 'INFO'
Write-Log "========================================" -Level 'INFO'

# Exit with appropriate code for automation/CI compatibility
if ($script:ErrorCount -gt 0) {
    exit 1
} else {
    exit 0
}
