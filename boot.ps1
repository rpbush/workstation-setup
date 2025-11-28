$mypath = $MyInvocation.MyCommand.Path
Write-Output "Path of the script: $mypath"
Write-Output "Args for script: $Args"

# Initialize logging system
$scriptDir = Split-Path $mypath -Parent
$logFileName = "workstation-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$logFilePath = Join-Path $scriptDir $logFileName
$scriptStartTime = Get-Date
$sectionStartTimes = @{}

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'SECTION_START', 'SECTION_END')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory=$false)]
        [object]$Exception = $null,
        [Parameter(Mandatory=$false)]
        [string]$Section = ''
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Level]"
    
    if ($Section) {
        $logEntry += " [$Section]"
    }
    
    $logEntry += " $Message"
    
    # Add exception details if provided
    if ($Exception) {
        # Handle both Exception objects and ErrorRecord objects
        if ($Exception -is [System.Management.Automation.ErrorRecord]) {
            $actualException = $Exception.Exception
            $logEntry += " | ErrorRecord: $($Exception.GetType().FullName)"
            $logEntry += " | Exception: $($actualException.GetType().FullName)"
            $logEntry += " | Message: $($Exception.Exception.Message)"
            if ($Exception.Exception.StackTrace) {
                $logEntry += " | StackTrace: $($Exception.Exception.StackTrace -replace "`r?`n", " | ")"
            }
            if ($Exception.Exception.InnerException) {
                $logEntry += " | InnerException: $($Exception.Exception.InnerException.Message)"
            }
            # Also include the ErrorRecord's error message which may have more details
            if ($Exception.ToString() -ne $Exception.Exception.Message) {
                $logEntry += " | ErrorRecord: $($Exception.ToString() -replace "`r?`n", " | ")"
            }
        } else {
            # It's already an Exception object
            $logEntry += " | Exception: $($Exception.GetType().FullName)"
            $logEntry += " | Message: $($Exception.Message)"
            if ($Exception.StackTrace) {
                $logEntry += " | StackTrace: $($Exception.StackTrace -replace "`r?`n", " | ")"
            }
            if ($Exception.InnerException) {
                $logEntry += " | InnerException: $($Exception.InnerException.Message)"
            }
        }
    }
    
    # Write to log file
    try {
        Add-Content -Path $logFilePath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # If logging fails, at least try to write to console
        Write-Host "Logging failed: $_" -ForegroundColor Red
    }
    
    # Also write to console with appropriate color
    switch ($Level) {
        'ERROR' { Write-Host $Message -ForegroundColor Red }
        'WARNING' { Write-Warning $Message }
        'SUCCESS' { Write-Host $Message -ForegroundColor Green }
        'SECTION_START' { Write-Host $Message -ForegroundColor Cyan }
        'SECTION_END' { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

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
$script:SectionTimings = @{}

# Helper function to check if Windows feature is installed
function Test-WindowsFeatureInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
        if ($feature -and $feature.State -eq "Enabled") {
            return $true
        }
    } catch {
        # Feature not found or error checking
    }
    return $false
}

# Helper function to check if software is installed via winget
function Test-SoftwareInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageId
    )
    
    try {
        # Refresh PATH to ensure winget is available
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Check if winget is available
        $wingetCheck = winget --info 2>$null
        if (-not $wingetCheck) {
            return $false
        }
        
        # Use winget list to check if package is installed
        $listOutput = winget list --id $PackageId --exact 2>&1
        if ($LASTEXITCODE -eq 0 -and $listOutput -match $PackageId) {
            return $true
        }
    } catch {
        # Error checking, assume not installed
    }
    return $false
}

# Helper function to check if AppX package is installed
function Test-AppxPackageInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,
        [Parameter(Mandatory=$false)]
        [switch]$UseWildcard
    )
    
    try {
        if ($UseWildcard) {
            # Use wildcard matching for packages with versioned names (e.g., Microsoft.WindowsAppRuntime.1.8)
            $package = Get-AppxPackage -Name "$PackageName*" -ErrorAction SilentlyContinue
            return ($null -ne $package -and $package.Count -gt 0)
        } else {
            # Exact name matching
            $package = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
            return ($null -ne $package)
        }
    } catch {
        return $false
    }
}

# Helper function to check if Windows is already activated
function Test-WindowsActivated {
    try {
        # Check for permanently activated license (LicenseStatus = 1 means activated)
        $activationStatus = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue | Where-Object { 
            $_.PartialProductKey -and $_.LicenseStatus -eq 1 
        } | Select-Object -First 1
        
        if ($activationStatus) {
            return $true
        }
        
        # Also check using slmgr for additional verification
        $slmgrOutput = & cscript.exe //B //Nologo "$env:SystemRoot\System32\slmgr.vbs" /xpr 2>&1
        $slmgrOutputString = $slmgrOutput -join "`n"
        
        # Check if output indicates permanent activation
        if ($slmgrOutputString -match "permanently|permanent activation|digital license") {
            return $true
        }
        
        return $false
    } catch {
        # If we can't check, assume not activated to be safe
        return $false
    }
}

# Helper function to prompt user after opening Windows Store
function Wait-ForStoreInstallation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        [Parameter(Mandatory=$false)]
        [string]$PackageName = $null,
        [Parameter(Mandatory=$false)]
        [switch]$UseWildcard
    )
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Windows Store Installation" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The Microsoft Store has been opened for: $AppName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please complete the following steps:" -ForegroundColor White
    Write-Host "1. In the Microsoft Store window, click 'Get' or 'Install'" -ForegroundColor White
    Write-Host "2. Wait for the installation to complete" -ForegroundColor White
    Write-Host "3. Close the Microsoft Store window when done" -ForegroundColor White
    Write-Host ""
    Write-Host "Press ENTER after you have completed the installation (or 'S' to skip)..." -ForegroundColor Cyan
    $response = Read-Host
    
    if ($response -eq 'S' -or $response -eq 's') {
        Write-Log "User skipped $AppName installation" -Level 'WARNING' -Section "Store Installation"
        return $false
    }
    
    # If package name provided, verify installation
    if ($PackageName) {
        Start-Sleep -Seconds 2
        if ($UseWildcard) {
            $installed = Test-AppxPackageInstalled -PackageName $PackageName -UseWildcard
        } else {
            $installed = Test-AppxPackageInstalled -PackageName $PackageName
        }
        if ($installed) {
            Write-Log "$AppName installation verified successfully" -Level 'SUCCESS' -Section "Store Installation"
            return $true
        } else {
            Write-Log "$AppName installation could not be verified. It may still be installing." -Level 'WARNING' -Section "Store Installation"
            return $true  # Assume user completed it
        }
    }
    
    return $true
}

# Section timing helper functions
function Start-Section {
    param([string]$SectionName)
    $script:SectionTimings[$SectionName] = @{
        StartTime = Get-Date
        EndTime = $null
        Duration = $null
    }
    Write-Log "Starting section: $SectionName" -Level 'SECTION_START' -Section $SectionName
}

function End-Section {
    param([string]$SectionName)
    if ($script:SectionTimings.ContainsKey($SectionName)) {
        $script:SectionTimings[$SectionName].EndTime = Get-Date
        $duration = $script:SectionTimings[$SectionName].EndTime - $script:SectionTimings[$SectionName].StartTime
        $script:SectionTimings[$SectionName].Duration = $duration
        Write-Log "Completed section: $SectionName (Duration: $($duration.TotalSeconds.ToString('F2')) seconds)" -Level 'SECTION_END' -Section $SectionName
    }
}

# Function to check if WinGet is available and working
# Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/
function Test-WinGetInstalled {
    try {
        # Refresh PATH to ensure winget is available if recently installed
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Use --info for better compatibility (recommended by Microsoft docs)
        $wingetInfo = winget --info 2>$null
        if ($wingetInfo) {
            # Extract version from --info output or use -v
            $wingetVersion = winget -v 2>$null
            if ($wingetVersion) {
                return @{
                    Installed = $true
                    Version = $wingetVersion
                    Working = $true
                }
            }
        }
    } catch {
        # WinGet command not available
    }
    
    return @{
        Installed = $false
        Version = $null
        Working = $false
    }
}

# Helper function to ensure WinGet configuration is enabled
# This function verifies configuration is enabled by actually testing it
function Ensure-WinGetConfigurationEnabled {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Section = ''
    )
    
    $maxRetries = 2
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        # Test if configuration is actually enabled by trying a valid command
        # We'll use 'winget configure list' which should work if enabled, or return an error if not
        try {
            # Capture both stdout and stderr (2>&1 redirects stderr to stdout)
            $testOutput = winget configure list 2>&1 | Out-String
            $testOutputLower = $testOutput.ToLower()
            
            # Check for the error message (case-insensitive)
            # The error message is: "Extended features are not enabled. Run `winget configure --enable` to enable them."
            $needsEnable = $testOutputLower -match "extended features are not enabled" -or 
                          $testOutputLower -match "run.*winget configure.*--enable"
            
            if ($needsEnable) {
                Write-Log "WinGet configuration features are not enabled. Enabling them (attempt $($retryCount + 1))..." -Level 'INFO' -Section $Section
                
                # Enable configuration features
                $tempOutput = [System.IO.Path]::GetTempFileName()
                $tempError = [System.IO.Path]::GetTempFileName()
                
                $process = Start-Process -FilePath "winget.exe" -ArgumentList "configure", "--enable" -NoNewWindow -PassThru -RedirectStandardOutput $tempOutput -RedirectStandardError $tempError -ErrorAction Stop -Wait
                
                $enableOutput = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
                $errorOutput = Get-Content $tempError -Raw -ErrorAction SilentlyContinue
                
                Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
                Remove-Item $tempError -Force -ErrorAction SilentlyContinue
                
                # Wait a moment for the change to take effect (even if exit code suggests failure)
                # Sometimes the enable command returns non-zero exit codes but still succeeds
                Start-Sleep -Seconds 3
                
                # Always verify by testing if configuration is actually enabled now
                # This is more reliable than checking exit codes
                $verifyOutput = winget configure list 2>&1 | Out-String
                $verifyOutputLower = $verifyOutput.ToLower()
                if ($verifyOutputLower -notmatch "extended features are not enabled") {
                    Write-Log "WinGet configuration features enabled and verified successfully" -Level 'SUCCESS' -Section $Section
                    return $true
                } else {
                    # Verification failed - log details for troubleshooting
                    if ($process.ExitCode -ne 0) {
                        Write-Log "Enable command returned exit code: $($process.ExitCode) (may still have succeeded)" -Level 'WARNING' -Section $Section
                    }
                    if ($enableOutput) {
                        Write-Log "Enable output: $enableOutput" -Level 'INFO' -Section $Section
                    }
                    if ($errorOutput) {
                        Write-Log "Enable error output: $errorOutput" -Level 'INFO' -Section $Section
                    }
                    Write-Log "WinGet configuration enable command completed but verification failed. Retrying..." -Level 'WARNING' -Section $Section
                }
            } else {
                # Configuration appears to be enabled
                Write-Log "WinGet configuration features are enabled" -Level 'SUCCESS' -Section $Section
                return $true
            }
        } catch {
            Write-Log "Exception while checking/enabling WinGet configuration: $_" -Level 'ERROR' -Section $Section -Exception $_
        }
        
        $retryCount++
        if ($retryCount -lt $maxRetries) {
            Start-Sleep -Seconds 3
        }
    }
    
    Write-Log "Failed to enable WinGet configuration features after $maxRetries attempts" -Level 'ERROR' -Section $Section
    return $false
}

# Check if WinGet is already installed and working
# Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/
Start-Section "WinGet Check"
$wingetStatus = Test-WinGetInstalled
$wingetInstalled = $wingetStatus.Installed
$wingetWorking = $wingetStatus.Working

if ($wingetInstalled -and $wingetWorking) {
    Write-Log "WinGet is already installed and working (Version: $($wingetStatus.Version)). Skipping WinGet installation." -Level 'SUCCESS' -Section "WinGet Check"
    End-Section "WinGet Check"
    $skipWinGetInstall = $true
} else {
    Write-Log "WinGet is not installed or not working. Proceeding with installation..." -Level 'INFO' -Section "WinGet Check"
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
# Installing NFS Client feature (moved to start as it may require reboot)
Start-Section "NFS Client Installation"
$nfsNeedsReboot = $false
try {
    # Try different feature names depending on Windows version
    $nfsFeatureNames = @("ClientForNFS-Infrastructure", "ServicesForNFS-ClientOnly")
    $nfsInstalled = $false
    
    foreach ($featureName in $nfsFeatureNames) {
        if (Test-WindowsFeatureInstalled -FeatureName $featureName) {
            Write-Log "NFS Client feature ($featureName) is already installed" -Level 'INFO' -Section "NFS Client Installation"
            $nfsInstalled = $true
            break
        } else {
        $nfsFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
        if ($nfsFeature) {
                Write-Log "Installing NFS Client feature ($featureName) - this may take a few minutes..." -Level 'INFO' -Section "NFS Client Installation"
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Stop | Out-Null
                    Write-Log "NFS Client feature ($featureName) installed successfully" -Level 'SUCCESS' -Section "NFS Client Installation"
                $nfsInstalled = $true
                $nfsNeedsReboot = $true
                break
                } catch {
                    $script:ErrorCount++
                    Write-Log "Failed to install NFS Client feature ($featureName)" -Level 'ERROR' -Section "NFS Client Installation" -Exception $_
                }
            }
        }
    }
    
    if (-not $nfsInstalled) {
        Write-Warning "Could not find or install NFS Client feature. NFS drive mapping may fail."
    }
    
    # Prompt for reboot if NFS was just installed
    if ($nfsNeedsReboot) {
        Write-Host ""
        Write-Host "NFS Client feature requires a system restart to function properly." -ForegroundColor Yellow
        Write-Host "Please restart your computer now, then run this script again to continue." -ForegroundColor Yellow
        Write-Host ""
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
                # Check internet connection
                $internetConnected = $false
                try {
                    $testConnection = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction Stop
                    if ($testConnection) {
                        $internetConnected = $true
                    }
                } catch {
                    # Try alternative method
                    try {
                        $webClient = New-Object System.Net.NetworkInformation.Ping
                        $result = $webClient.Send("8.8.8.8", 1000)
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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Try to use local DSC files first, then fall back to GitHub
$scriptDir = Split-Path $mypath -Parent
$dscNonAdmin = "rpbush.nonAdmin.dsc.yml";
$dscAdmin = "rpbush.dev.dsc.yml";
$dscOffice = "rpbush.office.dsc.yml";

# Check if DSC files exist locally
$dscNonAdminLocal = Join-Path $scriptDir $dscNonAdmin
$dscAdminLocal = Join-Path $scriptDir $dscAdmin
$dscOfficeLocal = Join-Path $scriptDir $dscOffice

# GitHub repository for DSC files (use workstation-setup repo which contains the files)
$dscUri = "https://raw.githubusercontent.com/rpbush/workstation-setup/main/"

$dscOfficeUri = $dscUri + $dscOffice;
$dscNonAdminUri = $dscUri + $dscNonAdmin 
$dscAdminUri = $dscUri + $dscAdmin

# amazing, we can now run WinGet get fun stuff
if (!$isAdmin) {
   # Shoulder tap terminal to it gets registered moving foward
   Start-Process shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App

   Start-Section "NonAdmin DSC Installation"
   $nonAdminDscDownloaded = $false
   
   # Check if file exists locally first
   if (Test-Path $dscNonAdminLocal) {
       Write-Log "Using local NonAdmin DSC file: $dscNonAdminLocal" -Level 'INFO' -Section "NonAdmin DSC Installation"
       Copy-Item $dscNonAdminLocal $dscNonAdmin -Force
       $nonAdminDscDownloaded = $true
   } else {
       try {
           Write-Log "Downloading NonAdmin DSC configuration from: $dscNonAdminUri" -Level 'INFO' -Section "NonAdmin DSC Installation"
           $downloadStart = Get-Date
           Invoke-WebRequest -Uri $dscNonAdminUri -OutFile $dscNonAdmin -ErrorAction Stop
           $downloadDuration = (Get-Date) - $downloadStart
           Write-Log "NonAdmin DSC downloaded successfully (Duration: $($downloadDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "NonAdmin DSC Installation"
           $nonAdminDscDownloaded = $true
       } catch {
           $script:ErrorCount++
           Write-Log "Failed to download NonAdmin DSC configuration" -Level 'ERROR' -Section "NonAdmin DSC Installation" -Exception $_
           Write-Log "Skipping NonAdmin installation due to download failure" -Level 'WARNING' -Section "NonAdmin DSC Installation"
       }
   }
   
   if ($nonAdminDscDownloaded) {
       try {
           Write-Log "Running winget configuration for NonAdmin DSC" -Level 'INFO' -Section "NonAdmin DSC Installation"
           $configStart = Get-Date
           $configOutput = winget configuration -f $dscNonAdmin --accept-configuration-agreements 2>&1
           $configDuration = (Get-Date) - $configStart
           if ($LASTEXITCODE -eq 0) {
               Write-Log "NonAdmin DSC configuration completed successfully (Duration: $($configDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "NonAdmin DSC Installation"
           } else {
               $script:ErrorCount++
               Write-Log "NonAdmin DSC configuration failed with exit code: $LASTEXITCODE" -Level 'ERROR' -Section "NonAdmin DSC Installation"
               Write-Log "Output: $($configOutput -join ' | ')" -Level 'ERROR' -Section "NonAdmin DSC Installation"
           }
       } catch {
           $script:ErrorCount++
           Write-Log "Exception during NonAdmin DSC configuration" -Level 'ERROR' -Section "NonAdmin DSC Installation" -Exception $_
       }
   }
   End-Section "NonAdmin DSC Installation"
   
   # clean up, Clean up, everyone wants to clean up
   if (Test-Path $dscNonAdmin) {
       Remove-Item $dscNonAdmin -verbose
   }

   # restarting for Admin now
	Start-Process PowerShell -wait -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$mypath' $Args;`"";
	exit;
}
else {
   # admin section now
   # ---------------
    # ---------------
    # Configure File Explorer to show hidden files and folders
    Write-Host "Start: Configuring File Explorer settings"
    try {
        Start-Section "File Explorer Configuration"
        $explorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        
        # Ensure the registry path exists
        if (-not (Test-Path $explorerKey)) {
            New-Item -Path $explorerKey -Force | Out-Null
        }
        
        # Set Hidden to 2 (Show hidden files, folders, and drives)
        Set-ItemProperty -Path $explorerKey -Name "Hidden" -Value 2 -Type DWORD -Force
        Write-Log "File Explorer configured to show hidden files, folders, and drives" -Level 'SUCCESS' -Section "File Explorer Configuration"
        
        # Refresh File Explorer to apply changes
        # This will restart explorer.exe to apply the registry changes
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process "explorer.exe"
        
        End-Section "File Explorer Configuration"
    } catch {
        $script:ErrorCount++
        Write-Log "Failed to configure File Explorer settings" -Level 'ERROR' -Section "File Explorer Configuration" -Exception $_
    }
    Write-Host "Done: Configuring File Explorer settings"
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
        
        # Open Windows Settings to the Accounts page for adding a Microsoft account
        # This opens the "Add a Microsoft account" page
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
        
        # List installed distributions
        Write-Host "Checking installed WSL distributions..."
        try {
            $wslList = wsl --list --verbose 2>$null
            if ($wslList) {
                Write-Host "Installed WSL distributions:"
                $wslList | ForEach-Object { Write-Host "  $_" }
            }
        } catch {
            Write-Host "No WSL distributions found or WSL not yet available"
        }
        
    } catch {
        Write-Warning "Failed to install WSL: $_"
        Write-Host "You can install WSL manually using: wsl --install"
        Write-Host "Documentation: https://learn.microsoft.com/en-us/windows/wsl/install"
    }
    Write-Host "Done: Installing Windows Features"
    # ---------------
    # Setting power profile to Performance/Ultimate Performance
    Write-Host "Start: Setting power profile to Performance"
    try {
        # Get all power schemes
        $powerSchemes = powercfg /list 2>$null
        
        # Function to find power scheme GUID by name
        function Get-PowerSchemeGuid {
            param([string]$SchemeName)
            
            # Parse powercfg /list output to find scheme by name
            # Format: "Power Scheme GUID: Name (GUID)"
            $lines = $powerSchemes -split "`n"
            foreach ($line in $lines) {
                if ($line -match "($([regex]::Escape($SchemeName)))" -and $line -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
                    return $matches[2]  # Return the GUID
                }
            }
            return $null
        }
        
        # Try to find Ultimate Performance first (highest performance)
        $ultimatePerfGuid = Get-PowerSchemeGuid "Ultimate Performance"
        if ($ultimatePerfGuid) {
            powercfg /setactive $ultimatePerfGuid 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Power profile set to Ultimate Performance"
            } else {
                Write-Warning "Failed to set Ultimate Performance profile"
            }
        } else {
            # Fall back to High Performance
            $highPerfGuid = Get-PowerSchemeGuid "High Performance"
            if ($highPerfGuid) {
                powercfg /setactive $highPerfGuid 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Power profile set to High Performance"
                } else {
                    Write-Warning "Failed to set High Performance profile"
                }
            } else {
                # Last resort: try standard GUIDs (these are consistent across Windows)
                Write-Host "Could not find performance profile by name, trying standard GUIDs..."
                $standardUltimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
                $standardHighGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
                
                if ($powerSchemes -match $standardUltimateGuid) {
                    powercfg /setactive $standardUltimateGuid 2>$null
                    Write-Host "Power profile set to Ultimate Performance (via standard GUID)"
                } elseif ($powerSchemes -match $standardHighGuid) {
                    powercfg /setactive $standardHighGuid 2>$null
                    Write-Host "Power profile set to High Performance (via standard GUID)"
                } else {
                    Write-Warning "Performance power profile not found. Available profiles:"
                    $powerSchemes | ForEach-Object { Write-Host "  $_" }
                }
            }
        }
    } catch {
        Write-Warning "Failed to set power profile: $_"
    }
    Write-Host "Done: Setting power profile to Performance"
    # ---------------
    # Setting system tray to show all icons
    Write-Host "Start: Setting system tray to show all icons"
    try {
        # Clear the hidden icons list in the system tray
        $trayNotifyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
        if (Test-Path $trayNotifyPath) {
            # Remove the IconStreams and PastIconsStream values which contain hidden icon data
            Remove-ItemProperty -Path $trayNotifyPath -Name "IconStreams" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $trayNotifyPath -Name "PastIconsStream" -ErrorAction SilentlyContinue
            Write-Host "Cleared system tray hidden icons list"
        }
        
        # Set registry to always show all icons (Windows 10/11)
        $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        if (-not (Test-Path $explorerPath)) {
            New-Item -Path $explorerPath -Force | Out-Null
        }
        
        # Enable "Always show all icons in the notification area" setting
        # This is controlled by the EnableAutoTray DWORD value (0 = show all, 1 = hide some)
        Set-ItemProperty -Path $explorerPath -Name "EnableAutoTray" -Value 0 -Type DWORD -Force
        Write-Host "System tray configured to show all icons"
        
        # Restart Explorer to apply changes (optional, but ensures immediate effect)
        # Get-Process explorer | Stop-Process -Force
        # Start-Sleep -Seconds 2
        # Start-Process explorer.exe
        
    } catch {
        Write-Warning "Failed to configure system tray: $_"
    }
    Write-Host "Done: Setting system tray to show all icons"
    # ---------------
    # Mapping network drives
    Start-Section "Network Drive Mapping"
    try {
        # NFS Client feature installation moved to start of script (may require reboot)
        # Windows Sandbox feature installation moved to Windows Features section
        
        # Domain-joined workstation: use logged-in user's credentials automatically
        # No credential prompting needed - Windows will use domain authentication
        $sDrive = "S:"
        $sPath = "\\FS-1\Storage"
        $serverName = ($sPath -split '\\')[2]
        
        Write-Log "Domain-joined workstation detected. Using logged-in user's domain credentials automatically." -Level 'INFO' -Section "Network Drive Mapping"
        
        # Map N: drive to NFS:/media (NFS Network)
        $nDrive = "N:"
        $nPath = "NFS:/media"
        Write-Log "Attempting to map $nDrive to $nPath" -Level 'INFO' -Section "Network Drive Mapping"
        
        # Check if NFS Client service is running
        # Try multiple possible service names (varies by Windows version and NFS feature installed)
        $nfsServiceNames = @("NfsClnt", "NfsRdr", "NfsService")
        $nfsService = $null
        $nfsServiceName = $null
        
        foreach ($serviceName in $nfsServiceNames) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $nfsService = $service
                $nfsServiceName = $serviceName
                break
            }
        }
        
        if ($nfsService) {
            if ($nfsService.Status -ne "Running") {
                Write-Log "NFS Client service ($nfsServiceName) is not running. Attempting to start it..." -Level 'WARNING' -Section "Network Drive Mapping"
                $serviceStarted = $false
                
                # Try using nfsadmin command first (more reliable for NFS)
                try {
                    $nfsAdminResult = nfsadmin client start 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "NFS Client service started successfully using nfsadmin" -Level 'SUCCESS' -Section "Network Drive Mapping"
                        $serviceStarted = $true
                        Start-Sleep -Seconds 3
                    }
                } catch {
                    # nfsadmin not available or failed, try Start-Service
                }
                
                # If nfsadmin didn't work, try Start-Service
                if (-not $serviceStarted) {
                    try {
                        Start-Service -Name $nfsServiceName -ErrorAction Stop
                        Write-Log "NFS Client service ($nfsServiceName) started successfully" -Level 'SUCCESS' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 2
                    } catch {
                        $script:WarningCount++
                        Write-Log "Failed to start NFS Client service ($nfsServiceName): $_" -Level 'WARNING' -Section "Network Drive Mapping"
                        Write-Log "You may need to start the service manually or restart the computer if NFS was just installed" -Level 'WARNING' -Section "Network Drive Mapping"
                    }
                }
            } else {
                Write-Log "NFS Client service ($nfsServiceName) is running" -Level 'INFO' -Section "Network Drive Mapping"
            }
        } else {
            $script:WarningCount++
            Write-Log "NFS Client service not found (checked: $($nfsServiceNames -join ', ')). NFS mapping may fail." -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "This may indicate that the NFS Client feature is not installed or requires a reboot after installation" -Level 'WARNING' -Section "Network Drive Mapping"
            
            # Try to use nfsadmin to check if NFS is available at all
            try {
                $nfsAdminCheck = nfsadmin client 2>&1 | Out-String
                if ($nfsAdminCheck -notmatch "not recognized" -and $nfsAdminCheck -notmatch "not found") {
                    Write-Log "nfsadmin command is available. Attempting to start NFS client using nfsadmin..." -Level 'INFO' -Section "Network Drive Mapping"
                    $nfsAdminResult = nfsadmin client start 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "NFS Client started successfully using nfsadmin" -Level 'SUCCESS' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 3
                    }
                }
            } catch {
                # nfsadmin not available
            }
        }
        
        # Remove existing mapping if it exists
        Write-Log "Removing any existing mapping for $nDrive..." -Level 'INFO' -Section "Network Drive Mapping"
        $deleteResult = net use $nDrive /delete /yes 2>&1
        $deleteOutput = $deleteResult | Out-String
        if ($LASTEXITCODE -eq 0 -or $deleteOutput -match "not found" -or $deleteOutput -match "not exist" -or $deleteOutput -match "not connected") {
            Write-Log "Existing mapping removed or did not exist" -Level 'INFO' -Section "Network Drive Mapping"
        } else {
            Write-Log "Note: Could not remove existing mapping: $deleteOutput" -Level 'WARNING' -Section "Network Drive Mapping"
        }
        
        # Create persistent mapping
        Write-Log "Creating NFS mapping to $nPath..." -Level 'INFO' -Section "Network Drive Mapping"
        # NFS will use logged-in user's domain credentials automatically
        $mapResult = net use $nDrive $nPath /persistent:yes 2>&1
        $mapOutput = $mapResult | Out-String
        $mapExitCode = $LASTEXITCODE
        
        Write-Log "net use command output: $mapOutput" -Level 'INFO' -Section "Network Drive Mapping"
        
        if ($mapExitCode -eq 0) {
            # Wait longer for the mapping to register and become accessible
            Start-Sleep -Seconds 3
            
            # Verify the mapping multiple times to ensure it's actually working and persistent
            $verified = $false
            $maxRetries = 5
            for ($retry = 1; $retry -le $maxRetries; $retry++) {
                # Check if drive shows up in net use list
                $netUseList = net use 2>&1 | Out-String
                $driveInList = $netUseList -match [regex]::Escape($nDrive)
                
                if ($driveInList) {
                    # Try to access the drive
                    $testPath = Test-Path $nDrive -ErrorAction SilentlyContinue
                    if ($testPath) {
                        # Double-check it's actually accessible by trying to list contents
                        try {
                            $items = Get-ChildItem $nDrive -ErrorAction Stop | Select-Object -First 1
                            $verified = $true
                            Write-Log "Drive $nDrive verified and accessible (attempt $retry of $maxRetries)" -Level 'INFO' -Section "Network Drive Mapping"
                            break
                        } catch {
                            Write-Log "Drive $nDrive exists but not accessible (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                            Start-Sleep -Seconds 2
                        }
        } else {
                        Write-Log "Drive $nDrive in net use list but not accessible via Test-Path (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 2
                    }
                } else {
                    Write-Log "Drive $nDrive not in net use list yet (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                    Start-Sleep -Seconds 2
                }
            }
            
            if ($verified) {
                # Try to refresh Explorer to show the drive
                try {
                    $shell = New-Object -ComObject Shell.Application
                    $shell.Windows() | Where-Object { $_.Document.Folder.Self.Path -eq "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" } | ForEach-Object { $_.Refresh() }
                } catch {
                    # Explorer refresh failed, but continue
                }
                
                Write-Log "Successfully mapped $nDrive to $nPath and verified access" -Level 'SUCCESS' -Section "Network Drive Mapping"
            } else {
                $script:WarningCount++
                Write-Log "Drive $nDrive mapping command succeeded but drive is not accessible after $maxRetries attempts" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Full output: $mapOutput" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Current net use output: $(net use 2>&1 | Out-String)" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Note: The drive may not be accessible from this session. The mapping may have failed silently." -Level 'WARNING' -Section "Network Drive Mapping"
            }
        } else {
            $script:ErrorCount++
            Write-Log "Failed to map $nDrive to $nPath (Exit code: $mapExitCode)" -Level 'ERROR' -Section "Network Drive Mapping"
            Write-Log "Error output: $mapOutput" -Level 'ERROR' -Section "Network Drive Mapping"
            
            # Provide detailed troubleshooting information
            Write-Log "Troubleshooting NFS mapping failure:" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "1. Verify NFS Client feature is installed: Get-WindowsOptionalFeature -Online | Where-Object {`$_.FeatureName -like '*NFS*'}" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "2. Check NFS Client service status: Get-Service | Where-Object {`$_.Name -like '*NFS*'}" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "3. Try starting NFS client manually: nfsadmin client start" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "4. Verify NFS server is accessible and path format is correct" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "5. NFS path format should be: NFS:/server/share (not \\server\share for NFS)" -Level 'WARNING' -Section "Network Drive Mapping"
            Write-Log "6. If NFS was just installed, a reboot may be required" -Level 'WARNING' -Section "Network Drive Mapping"
            
            # Check if service is actually running now
            $currentService = Get-Service | Where-Object { $_.Name -like "*NFS*" -or $_.DisplayName -like "*NFS*" } | Select-Object -First 1
            if ($currentService) {
                Write-Log "Current NFS service status: $($currentService.Name) - $($currentService.Status)" -Level 'INFO' -Section "Network Drive Mapping"
            } else {
                Write-Log "No NFS services found. NFS Client feature may not be installed." -Level 'WARNING' -Section "Network Drive Mapping"
            }
        }
        
        # Map S: drive to \\FS-1\Storage (Windows Network)
        Write-Log "Attempting to map $sDrive to $sPath" -Level 'INFO' -Section "Network Drive Mapping"
        
        # Test network connectivity to the server first (with timeout to prevent hanging)
        Write-Log "Testing connectivity to server: $serverName" -Level 'INFO' -Section "Network Drive Mapping"
        try {
            # Use a job with timeout to prevent hanging
            $pingJob = Start-Job -ScriptBlock { param($server) Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue } -ArgumentList $serverName
            $pingResult = $pingJob | Wait-Job -Timeout 5 | Receive-Job
            $pingJob | Remove-Job -Force -ErrorAction SilentlyContinue
            
            if ($pingResult) {
                Write-Log "Server is reachable" -Level 'INFO' -Section "Network Drive Mapping"
            } else {
                $script:WarningCount++
                Write-Log "Server $serverName may not be reachable or ping timed out. Will attempt mapping anyway." -Level 'WARNING' -Section "Network Drive Mapping"
            }
        } catch {
            $script:WarningCount++
            Write-Log "Could not test server connectivity (may be normal if ping is blocked). Will attempt mapping anyway." -Level 'WARNING' -Section "Network Drive Mapping"
        }
        
        # Remove existing mapping if it exists
        Write-Log "Removing any existing mapping for $sDrive..." -Level 'INFO' -Section "Network Drive Mapping"
        $deleteResult = net use $sDrive /delete /yes 2>&1
        $deleteOutput = $deleteResult | Out-String
        if ($LASTEXITCODE -eq 0 -or $deleteOutput -match "not found" -or $deleteOutput -match "not exist" -or $deleteOutput -match "not connected") {
            Write-Log "Existing mapping removed or did not exist" -Level 'INFO' -Section "Network Drive Mapping"
        } else {
            Write-Log "Note: Could not remove existing mapping: $deleteOutput" -Level 'WARNING' -Section "Network Drive Mapping"
        }
        
        # Create persistent mapping
        Write-Log "Creating Windows network mapping to $sPath..." -Level 'INFO' -Section "Network Drive Mapping"
        
        # Attempt mapping - net use will automatically use logged-in user's domain credentials
        $mapSuccess = $false
        $mapOutput = ""
        $mapExitCode = -1
        
        Write-Log "Attempting to map drive using logged-in user's domain credentials..." -Level 'INFO' -Section "Network Drive Mapping"
        
        try {
            # Use net use - it will automatically use the logged-in user's domain credentials
            $tempOutput = [System.IO.Path]::GetTempFileName()
            $tempError = [System.IO.Path]::GetTempFileName()
            
            $process = Start-Process -FilePath "net.exe" -ArgumentList "use", $sDrive, $sPath, "/persistent:yes" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOutput -RedirectStandardError $tempError
            
            $mapOutput = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
            $errorOutput = Get-Content $tempError -Raw -ErrorAction SilentlyContinue
            if ($errorOutput) {
                $mapOutput += "`nError: $errorOutput"
            }
            $mapExitCode = $process.ExitCode
            
            Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
            Remove-Item $tempError -Force -ErrorAction SilentlyContinue
            
            if ($mapExitCode -eq 0) {
                $mapSuccess = $true
                Write-Log "net use command succeeded with domain credentials: $mapOutput" -Level 'SUCCESS' -Section "Network Drive Mapping"
            } else {
                Write-Log "net use command failed (Exit code: $mapExitCode): $mapOutput" -Level 'WARNING' -Section "Network Drive Mapping"
                $script:WarningCount++
            }
        } catch {
            $script:ErrorCount++
            Write-Log "Failed to map drive: $_" -Level 'ERROR' -Section "Network Drive Mapping" -Exception $_
            $mapExitCode = -1
            $mapOutput = "Command failed: $_"
        }
        
        if ($mapExitCode -eq 0) {
            # Wait longer for the mapping to register and become accessible
            Start-Sleep -Seconds 3
            
            # Verify the mapping multiple times to ensure it's actually working and persistent
            $verified = $false
            $maxRetries = 5
            for ($retry = 1; $retry -le $maxRetries; $retry++) {
                # Check if drive shows up in net use list
                $netUseList = net use 2>&1 | Out-String
                $driveInList = $netUseList -match [regex]::Escape($sDrive)
                
                if ($driveInList) {
                    # Try to access the drive
                    $testPath = Test-Path $sDrive -ErrorAction SilentlyContinue
                    if ($testPath) {
                        # Double-check it's actually accessible by trying to list contents
                        try {
                            $items = Get-ChildItem $sDrive -ErrorAction Stop | Select-Object -First 1
                            $verified = $true
                            Write-Log "Drive $sDrive verified and accessible (attempt $retry of $maxRetries)" -Level 'INFO' -Section "Network Drive Mapping"
                            break
                        } catch {
                            Write-Log "Drive $sDrive exists but not accessible (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                            Start-Sleep -Seconds 2
                        }
                    } else {
                        Write-Log "Drive $sDrive in net use list but not accessible via Test-Path (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 2
                    }
                } else {
                    Write-Log "Drive $sDrive not in net use list yet (attempt $retry of $maxRetries), waiting..." -Level 'INFO' -Section "Network Drive Mapping"
                    Start-Sleep -Seconds 2
                }
            }
            
            if ($verified) {
                # Try to refresh Explorer to show the drive
                try {
                    $shell = New-Object -ComObject Shell.Application
                    $shell.Windows() | Where-Object { $_.Document.Folder.Self.Path -eq "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" } | ForEach-Object { $_.Refresh() }
                } catch {
                    # Explorer refresh failed, but continue
                }
                
                Write-Log "Successfully mapped $sDrive to $sPath and verified access" -Level 'SUCCESS' -Section "Network Drive Mapping"
            } else {
                $script:WarningCount++
                Write-Log "Drive $sDrive mapping command succeeded but drive is not accessible after $maxRetries attempts" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Full output: $mapOutput" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Current net use output: $(net use 2>&1 | Out-String)" -Level 'WARNING' -Section "Network Drive Mapping"
                Write-Log "Note: The drive may not be accessible from this session. The mapping may have failed silently." -Level 'WARNING' -Section "Network Drive Mapping"
            }
        } else {
            $script:ErrorCount++
            Write-Log "Failed to map $sDrive to $sPath (Exit code: $mapExitCode)" -Level 'ERROR' -Section "Network Drive Mapping"
            Write-Log "Error output: $mapOutput" -Level 'ERROR' -Section "Network Drive Mapping"
            Write-Log "Troubleshooting: Check network connectivity, server availability, and share permissions" -Level 'WARNING' -Section "Network Drive Mapping"
        }
        
        # List all mapped drives for verification
        Write-Log "Current mapped network drives:" -Level 'INFO' -Section "Network Drive Mapping"
        $mappedDrives = net use 2>&1
        foreach ($line in $mappedDrives) {
            if ($line -match "^\s+\w:") {
                Write-Log "  $line" -Level 'INFO' -Section "Network Drive Mapping"
            }
        }
        
    } catch {
        $script:ErrorCount++
        Write-Log "Exception during network drive mapping" -Level 'ERROR' -Section "Network Drive Mapping" -Exception $_
    }
    End-Section "Network Drive Mapping"
    # ---------------
    # Installing Windows Terminal
    # Reference: https://learn.microsoft.com/en-us/windows/terminal/
    Write-Host "Start: Installing Windows Terminal"
    try {
        # Check if Windows Terminal is already installed
        if (Test-AppxPackageInstalled -PackageName "Microsoft.WindowsTerminal") {
        $wtInstalled = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
            Write-Log "Windows Terminal is already installed (Version: $($wtInstalled.Version))" -Level 'INFO' -Section "Windows Terminal Installation"
        } else {
            Write-Host "Installing Windows Terminal using WinGet..."
            Write-Host "Reference: https://learn.microsoft.com/en-us/windows/terminal/install"
            
            # Install Windows Terminal using winget (recommended by Microsoft)
            # Use -e for exact match and --accept-package-agreements for automation
            try {
                winget install --id Microsoft.WindowsTerminal -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Windows Terminal installed successfully"
                } else {
                    Write-Log "WinGet installation may have failed. Trying alternative method..." -Level 'WARNING' -Section "Windows Terminal Installation"
                    # Fallback: Try installing via Microsoft Store
                    try {
                        Start-Process "ms-windows-store://pdp/?ProductId=9N0DX20HK701" -ErrorAction Stop
                        Start-Sleep -Seconds 2  # Give Store time to open
                        
                        $installed = Wait-ForStoreInstallation -AppName "Windows Terminal" -PackageName "Microsoft.WindowsTerminal"
                        if ($installed) {
                        # Check if it got installed
                        $wtCheck = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
                        if ($wtCheck) {
                                Write-Log "Windows Terminal installed via Microsoft Store" -Level 'SUCCESS' -Section "Windows Terminal Installation"
                            }
                        }
                    } catch {
                        $script:ErrorCount++
                        Write-Log "Could not open Microsoft Store for Windows Terminal" -Level 'ERROR' -Section "Windows Terminal Installation" -Exception $_
                    }
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

    gpupdate /force

    Start-Section "Office Installation"
    
    # Check if Office is already installed
    $officeInstalled = $false
    $teamsInstalled = $false
    
    if (Test-SoftwareInstalled -PackageId "Microsoft.Office") {
        Write-Log "Microsoft Office is already installed, skipping installation" -Level 'INFO' -Section "Office Installation"
        $officeInstalled = $true
    }
    
    if (Test-SoftwareInstalled -PackageId "Microsoft.Teams") {
        Write-Log "Microsoft Teams is already installed, skipping installation" -Level 'INFO' -Section "Office Installation"
        $teamsInstalled = $true
    }
    
    # If both are installed, skip DSC configuration but continue with rest of script
    if ($officeInstalled -and $teamsInstalled) {
        Write-Log "Office and Teams are already installed, skipping DSC configuration" -Level 'SUCCESS' -Section "Office Installation"
        # Don't return here - continue to Dev Flows Installation section
    } else {
    $officeDscDownloaded = $false
        
        # Check if file exists locally first
        if (Test-Path $dscOfficeLocal) {
            Write-Log "Using local Office DSC file: $dscOfficeLocal" -Level 'INFO' -Section "Office Installation"
            Copy-Item $dscOfficeLocal $dscOffice -Force
            $officeDscDownloaded = $true
        } else {
            try {
                Write-Log "Downloading Office DSC configuration from: $dscOfficeUri" -Level 'INFO' -Section "Office Installation"
                $downloadStart = Get-Date
        Invoke-WebRequest -Uri $dscOfficeUri -OutFile $dscOffice -ErrorAction Stop
                $downloadDuration = (Get-Date) - $downloadStart
                Write-Log "Office DSC downloaded successfully (Duration: $($downloadDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "Office Installation"
        $officeDscDownloaded = $true
    } catch {
                $script:ErrorCount++
                Write-Log "Failed to download Office DSC configuration" -Level 'ERROR' -Section "Office Installation" -Exception $_
                Write-Log "Skipping Office installation due to download failure" -Level 'WARNING' -Section "Office Installation"
            }
    }
    
    if ($officeDscDownloaded) {
            # Ensure WinGet configuration is enabled before running DSC
            Write-Log "Verifying WinGet configuration is enabled before Office DSC..." -Level 'INFO' -Section "Office Installation"
            $configEnabled = Ensure-WinGetConfigurationEnabled -Section "Office Installation"
            if (-not $configEnabled) {
                $script:ErrorCount++
                Write-Log "Cannot proceed with Office DSC - WinGet configuration features are not enabled" -Level 'ERROR' -Section "Office Installation"
            } else {
                try {
                    Write-Log "Running winget configuration for Office DSC" -Level 'INFO' -Section "Office Installation"
                    $configStart = Get-Date
                    $configOutput = winget configuration -f $dscOffice --accept-configuration-agreements 2>&1
                $configDuration = (Get-Date) - $configStart
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Office DSC configuration completed successfully (Duration: $($configDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section "Office Installation"
                    } else {
                        $script:ErrorCount++
                        Write-Log "Office DSC configuration failed with exit code: $LASTEXITCODE" -Level 'ERROR' -Section "Office Installation"
                        Write-Log "Output: $($configOutput -join ' | ')" -Level 'ERROR' -Section "Office Installation"
                    }
                } catch {
                    $script:ErrorCount++
                    Write-Log "Exception during Office DSC configuration" -Level 'ERROR' -Section "Office Installation" -Exception $_
                }
            } 
        
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

    # Staring dev workload
    Start-Section "Dev Flows Installation"
    
    # Check if a second physical drive already exists (skip dev drive creation if it does)
    $physicalDrives = Get-PhysicalDisk | Where-Object { $_.OperationalStatus -eq 'OK' -and $_.MediaType -ne 'Unspecified' } | Sort-Object DeviceID
    $secondDriveExists = $physicalDrives.Count -gt 1
    
    if ($secondDriveExists) {
        Write-Host "Second physical drive detected ($($physicalDrives.Count) drives found). Skipping Dev Drive creation from C: drive."
        # Check if file exists locally first
        if (Test-Path $dscAdminLocal) {
            Write-Log "Using local Dev flows DSC file: $dscAdminLocal" -Level 'INFO' -Section "Dev Flows Installation"
            Copy-Item $dscAdminLocal $dscAdmin -Force
        } else {
            try {
                Write-Log "Downloading Dev flows DSC configuration from: $dscAdminUri" -Level 'INFO' -Section "Dev Flows Installation"
                $downloadStart = Get-Date
            Invoke-WebRequest -Uri $dscAdminUri -OutFile $dscAdmin -ErrorAction Stop
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
        
        # Remove Dev Drive resource from DSC file if it exists
        Write-Log "Processing Dev flows DSC file to remove Dev Drive resource (if needed)..." -Level 'INFO' -Section "Dev Flows Installation"
        try {
            $dscLines = Get-Content $dscAdmin -ErrorAction Stop
            Write-Log "DSC file loaded successfully ($($dscLines.Count) lines)" -Level 'INFO' -Section "Dev Flows Installation"
        } catch {
            $script:ErrorCount++
            Write-Log "Failed to read DSC file: $dscAdmin" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
            End-Section "Dev Flows Installation"
            return
        }
        
        $newDscContent = @()
        $inDevDriveResource = $false
        $devDriveResourceStart = -1
        
        Write-Log "Processing $($dscLines.Count) lines to remove Dev Drive resource..." -Level 'INFO' -Section "Dev Flows Installation"
        
        $devDriveFound = $false
        $loopCount = 0
        $maxLoopIterations = $dscLines.Count * 2  # Safety limit to prevent infinite loops
        
        for ($i = 0; $i -lt $dscLines.Count; $i++) {
            $loopCount++
            if ($loopCount -gt $maxLoopIterations) {
                Write-Log "ERROR: Processing loop exceeded safety limit. Breaking to prevent infinite loop." -Level 'ERROR' -Section "Dev Flows Installation"
                break
            }
            
            $line = $dscLines[$i]
            
            # Progress indicator every 50 lines
            if ($i -gt 0 -and $i % 50 -eq 0) {
                Write-Log "Processing line $i of $($dscLines.Count)..." -Level 'INFO' -Section "Dev Flows Installation"
            }
            
            # Detect start of Dev Drive resource block
            if (-not $inDevDriveResource -and $line -match '^\s+-\s+resource:\s+Disk' -and $i + 1 -lt $dscLines.Count) {
                # Check if next line or nearby has "id: DevDrive1"
                $checkAhead = [Math]::Min(5, $dscLines.Count - $i - 1)
                for ($k = 1; $k -le $checkAhead; $k++) {
                    if ($dscLines[$i + $k] -match '^\s+id:\s+DevDrive1') {
                        Write-Log "Found Dev Drive resource starting at line $($i+1), removing it..." -Level 'INFO' -Section "Dev Flows Installation"
                        $devDriveFound = $true
                        $inDevDriveResource = $true
                        $devDriveResourceStart = $i
                        # Skip this resource block - don't add this line
                        continue
                    }
                }
            }
            
            # If we're in the Dev Drive resource, skip until we find the next resource or end of block
            if ($inDevDriveResource) {
                # Check if we've reached the next resource (starts with "    - resource:")
                if ($line -match '^\s+-\s+resource:' -and $i -gt $devDriveResourceStart) {
                    # We've reached the next resource, stop skipping
                    $inDevDriveResource = $false
                    Write-Log "Reached next resource at line $($i+1), ending Dev Drive resource removal" -Level 'INFO' -Section "Dev Flows Installation"
                        $newDscContent += $line
                    }
                # Otherwise, skip this line (don't add it to new content)
                continue
            }
            
            # Add line if we're not skipping
            $newDscContent += $line
        }
        
        Write-Log "DSC file processing complete. Original: $($dscLines.Count) lines, New: $($newDscContent.Count) lines" -Level 'INFO' -Section "Dev Flows Installation"
        
        if ($devDriveFound -and $newDscContent.Count -lt $dscLines.Count) {
            Write-Log "Removing Dev Drive resource from DSC configuration..." -Level 'INFO' -Section "Dev Flows Installation"
            try {
                Set-Content -Path $dscAdmin -Value ($newDscContent -join "`r`n") -ErrorAction Stop
                Write-Log "Dev Drive resource removed from configuration (removed $($dscLines.Count - $newDscContent.Count) lines)" -Level 'SUCCESS' -Section "Dev Flows Installation"
            } catch {
                $script:ErrorCount++
                Write-Log "Failed to write modified DSC file" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
            }
        } else {
            Write-Log "Dev Drive resource not found in DSC file (may have already been removed)" -Level 'INFO' -Section "Dev Flows Installation"
        }
    } else {
        Write-Log "No second physical drive detected ($($physicalDrives.Count) drive(s) found). Checking if Dev Drive can be created from C: drive." -Level 'INFO' -Section "Dev Flows Installation"
        
        # Check if file exists locally first
        if (Test-Path $dscAdminLocal) {
            Write-Log "Using local Dev flows DSC file: $dscAdminLocal" -Level 'INFO' -Section "Dev Flows Installation"
            Copy-Item $dscAdminLocal $dscAdmin -Force
        } else {
            try {
                Write-Log "Downloading Dev flows DSC configuration from: $dscAdminUri" -Level 'INFO' -Section "Dev Flows Installation"
                $downloadStart = Get-Date
            Invoke-WebRequest -Uri $dscAdminUri -OutFile $dscAdmin -ErrorAction Stop
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
        
        # Check available space on C: drive for Dev Drive creation (requires 75GB)
        try {
            $cDrive = Get-PSDrive -Name C -ErrorAction Stop
            $freeSpaceGB = [math]::Round($cDrive.Free / 1GB, 2)
            $requiredSpaceGB = 75
            Write-Log "C: drive free space: $freeSpaceGB GB (required: $requiredSpaceGB GB for Dev Drive)" -Level 'INFO' -Section "Dev Flows Installation"
            
            if ($freeSpaceGB -lt $requiredSpaceGB) {
                Write-Log "Insufficient space on C: drive for Dev Drive creation. Removing Dev Drive resource from DSC configuration." -Level 'WARNING' -Section "Dev Flows Installation"
                $removeDevDrive = $true
            } else {
                Write-Log "Sufficient space available on C: drive. Dev Drive will be created." -Level 'INFO' -Section "Dev Flows Installation"
                $removeDevDrive = $false
            }
        } catch {
            Write-Log "Could not check C: drive free space. Removing Dev Drive resource to avoid potential failures." -Level 'WARNING' -Section "Dev Flows Installation" -Exception $_
            $removeDevDrive = $true
        }
        
        # Remove Dev Drive resource from DSC file if needed
        if ($removeDevDrive) {
            Write-Log "Processing Dev flows DSC file to remove Dev Drive resource..." -Level 'INFO' -Section "Dev Flows Installation"
            try {
                $dscLines = Get-Content $dscAdmin -ErrorAction Stop
                Write-Log "DSC file loaded successfully ($($dscLines.Count) lines)" -Level 'INFO' -Section "Dev Flows Installation"
            } catch {
                $script:ErrorCount++
                Write-Log "Failed to read DSC file: $dscAdmin" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
                End-Section "Dev Flows Installation"
                return
            }
            
            $newDscContent = @()
            $inDevDriveResource = $false
            $devDriveResourceStart = -1
            $devDriveFound = $false
            $loopCount = 0
            $maxLoopIterations = $dscLines.Count * 2
            
            for ($i = 0; $i -lt $dscLines.Count; $i++) {
                $loopCount++
                if ($loopCount -gt $maxLoopIterations) {
                    Write-Log "ERROR: Processing loop exceeded safety limit. Breaking to prevent infinite loop." -Level 'ERROR' -Section "Dev Flows Installation"
                    break
                }
                
                $line = $dscLines[$i]
                
                # Detect start of Dev Drive resource block
                if (-not $inDevDriveResource -and $line -match '^\s+-\s+resource:\s+Disk' -and $i + 1 -lt $dscLines.Count) {
                    # Check if next line or nearby has "id: DevDrive1"
                    $checkAhead = [Math]::Min(5, $dscLines.Count - $i - 1)
                    for ($k = 1; $k -le $checkAhead; $k++) {
                        if ($dscLines[$i + $k] -match '^\s+id:\s+DevDrive1') {
                            Write-Log "Found Dev Drive resource starting at line $($i+1), removing it..." -Level 'INFO' -Section "Dev Flows Installation"
                            $devDriveFound = $true
                            $inDevDriveResource = $true
                            $devDriveResourceStart = $i
                            # Skip this resource block - don't add this line
                            continue
                        }
                    }
                }
                
                # If we're in the Dev Drive resource, skip until we find the next resource or end of block
                if ($inDevDriveResource) {
                    # Check if we've reached the next resource (starts with "    - resource:")
                    if ($line -match '^\s+-\s+resource:' -and $i -gt $devDriveResourceStart) {
                        # We've reached the next resource, stop skipping
                        $inDevDriveResource = $false
                        Write-Log "Reached next resource at line $($i+1), ending Dev Drive resource removal" -Level 'INFO' -Section "Dev Flows Installation"
                        $newDscContent += $line
                    }
                    # Otherwise, skip this line (don't add it to new content)
                    continue
                }
                
                # Add line if we're not skipping
                $newDscContent += $line
            }
            
            Write-Log "DSC file processing complete. Original: $($dscLines.Count) lines, New: $($newDscContent.Count) lines" -Level 'INFO' -Section "Dev Flows Installation"
            
            if ($devDriveFound -and $newDscContent.Count -lt $dscLines.Count) {
                Write-Log "Removing Dev Drive resource from DSC configuration..." -Level 'INFO' -Section "Dev Flows Installation"
                try {
                    Set-Content -Path $dscAdmin -Value ($newDscContent -join "`r`n") -ErrorAction Stop
                    Write-Log "Dev Drive resource removed from configuration (removed $($dscLines.Count - $newDscContent.Count) lines)" -Level 'SUCCESS' -Section "Dev Flows Installation"
                } catch {
                    $script:ErrorCount++
                    Write-Log "Failed to write modified DSC file" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
                }
            } else {
                Write-Log "Dev Drive resource not found in DSC file (may have already been removed)" -Level 'INFO' -Section "Dev Flows Installation"
            }
        }
    }
    
    # Use --accept-configuration-agreements for winget configure (not --accept-package-agreements)
    Write-Log "Preparing to run winget configuration for Dev flows DSC..." -Level 'INFO' -Section "Dev Flows Installation"
    Write-Log "DSC file path: $dscAdmin" -Level 'INFO' -Section "Dev Flows Installation"
    if (-not (Test-Path $dscAdmin)) {
        $script:ErrorCount++
        Write-Log "DSC file does not exist: $dscAdmin" -Level 'ERROR' -Section "Dev Flows Installation"
        End-Section "Dev Flows Installation"
        return
    }
    
    # Ensure WinGet configuration is enabled before running DSC
    Write-Log "Verifying WinGet configuration is enabled before Dev flows DSC..." -Level 'INFO' -Section "Dev Flows Installation"
    $configEnabled = Ensure-WinGetConfigurationEnabled -Section "Dev Flows Installation"
    if (-not $configEnabled) {
        $script:ErrorCount++
        Write-Log "Cannot proceed with Dev flows DSC - WinGet configuration features are not enabled" -Level 'ERROR' -Section "Dev Flows Installation"
        End-Section "Dev Flows Installation"
        return
    }
    
    try {
        Write-Log "Running winget configuration for Dev flows DSC (this may take several minutes)..." -Level 'INFO' -Section "Dev Flows Installation"
        Write-Log "DSC file contains packages: Git, PowerShell 7, PowerToys, Signal, Steam, 7zip, Notepad++, GitHub CLI, Cursor, Windows Terminal, and more..." -Level 'INFO' -Section "Dev Flows Installation"
        $configStart = Get-Date
        
        # Run winget configuration with real-time output streaming
        # All output will be logged to the main log file
        $configOutput = @()
        $script:currentPackage = $null
        $script:packageStartTime = $null
        
        # Ensure we have the full path to the DSC file
        $dscAdminFullPath = if ([System.IO.Path]::IsPathRooted($dscAdmin)) {
            $dscAdmin
        } else {
            $resolvedPath = Resolve-Path -Path $dscAdmin -ErrorAction SilentlyContinue
            if ($resolvedPath) {
                $resolvedPath.Path
            } else {
                Join-Path (Get-Location) $dscAdmin
            }
        }
        
        # Normalize the path (resolve any .. or . components)
        $dscAdminFullPath = [System.IO.Path]::GetFullPath($dscAdminFullPath)
        
        # Verify the file exists before running
        if (-not (Test-Path $dscAdminFullPath)) {
            $script:ErrorCount++
            Write-Log "DSC file not found at: $dscAdminFullPath" -Level 'ERROR' -Section "Dev Flows Installation"
            Write-Log "Original path: $dscAdmin" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Current directory: $(Get-Location)" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Files in current directory: $((Get-ChildItem -File | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ')" -Level 'INFO' -Section "Dev Flows Installation"
            End-Section "Dev Flows Installation"
            return
        }
        
        Write-Log "Using DSC file: $dscAdminFullPath" -Level 'INFO' -Section "Dev Flows Installation"
        
        # Create process info for real-time output capture
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "winget"
        $psi.Arguments = "configuration -f `"$dscAdminFullPath`" --accept-configuration-agreements"
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        
        # Set up event handlers for real-time output using script scope
        $outputBuilder = New-Object System.Text.StringBuilder
        $errorBuilder = New-Object System.Text.StringBuilder
        
        # Register output data received event with script scope access
        $scriptBlockOutput = {
            param($sender, $e)
            if (-not [string]::IsNullOrWhiteSpace($e.Data)) {
                $line = $e.Data
                $null = $script:outputBuilder.AppendLine($line)
                $script:configOutput += $line
                
                # Parse output to identify package installations
                # Look for patterns like: "Installing [PackageName]", "Found [PackageName]", "Successfully installed", etc.
                if ($line -match 'Installing\s+([^\s]+|"[^"]+")' -or $line -match 'Found\s+([^\s]+|"[^"]+")') {
                    $packageName = if ($matches[1] -match '^"(.+)"$') { $matches[1] } else { $matches[1] }
                    if ($packageName -and $packageName -ne $script:currentPackage) {
                        if ($script:currentPackage) {
                            $packageDuration = (Get-Date) - $script:packageStartTime
                            Write-Log "Completed: $script:currentPackage (Duration: $($packageDuration.TotalSeconds.ToString('F1')) seconds)" -Level 'INFO' -Section "Dev Flows Installation"
                        }
                        $script:currentPackage = $packageName
                        $script:packageStartTime = Get-Date
                        Write-Log "Installing: $script:currentPackage" -Level 'INFO' -Section "Dev Flows Installation"
                    }
                } elseif ($line -match 'Successfully\s+installed|Installation\s+completed|Package\s+installed' -and $script:currentPackage) {
                    $packageDuration = (Get-Date) - $script:packageStartTime
                    Write-Log "Successfully installed: $script:currentPackage (Duration: $($packageDuration.TotalSeconds.ToString('F1')) seconds)" -Level 'SUCCESS' -Section "Dev Flows Installation"
                    $script:currentPackage = $null
                } elseif ($line -match 'Skipping|Already\s+installed|No\s+change' -and $script:currentPackage) {
                    Write-Log "Skipped (already installed): $script:currentPackage" -Level 'INFO' -Section "Dev Flows Installation"
                    $script:currentPackage = $null
                } elseif ($line -match 'Error|Failed|Exception' -and $script:currentPackage) {
                    Write-Log "Failed: $script:currentPackage - $line" -Level 'ERROR' -Section "Dev Flows Installation"
                    $script:currentPackage = $null
                } elseif ($line -match 'Processing\s+([^\s]+|"[^"]+")|Applying\s+([^\s]+|"[^"]+")') {
                    # Try to extract package ID from processing/applying messages
                    $packageId = if ($matches[1]) { 
                        if ($matches[1] -match '^"(.+)"$') { $matches[1] } else { $matches[1] }
                    } elseif ($matches[2]) {
                        if ($matches[2] -match '^"(.+)"$') { $matches[2] } else { $matches[2] }
                    }
                    if ($packageId -and $packageId -ne $script:currentPackage) {
                        if ($script:currentPackage) {
                            $packageDuration = (Get-Date) - $script:packageStartTime
                            Write-Log "Completed: $script:currentPackage (Duration: $($packageDuration.TotalSeconds.ToString('F1')) seconds)" -Level 'INFO' -Section "Dev Flows Installation"
                        }
                        $script:currentPackage = $packageId
                        $script:packageStartTime = Get-Date
                        Write-Log "Processing package: $script:currentPackage" -Level 'INFO' -Section "Dev Flows Installation"
                    }
                }
                
                # Also log important progress lines in real-time
                if ($line -match 'Configuration\s+unit|Applying|Validating|Progress|Unit\s+\[') {
                    Write-Log "Progress: $line" -Level 'INFO' -Section "Dev Flows Installation"
                }
            }
        }
        
        $scriptBlockError = {
            param($sender, $e)
            if (-not [string]::IsNullOrWhiteSpace($e.Data)) {
                $line = $e.Data
                $null = $script:errorBuilder.AppendLine($line)
                $script:configOutput += $line
                Write-Log "Error output: $line" -Level 'ERROR' -Section "Dev Flows Installation"
            }
        }
        
        # Store references in script scope for event handlers
        $script:outputBuilder = $outputBuilder
        $script:errorBuilder = $errorBuilder
        $script:configOutput = $configOutput
        
        Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $scriptBlockOutput | Out-Null
        Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $scriptBlockError | Out-Null
        
        # Start the process
        Write-Log "Starting winget configuration process..." -Level 'INFO' -Section "Dev Flows Installation"
        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        
        # Wait for process to complete with timeout (30 minutes max)
        $timeoutMinutes = 30
        $timeout = (Get-Date).AddMinutes($timeoutMinutes)
        $processCompleted = $false
        
        while (-not $process.HasExited) {
            Start-Sleep -Milliseconds 500
            if ((Get-Date) -gt $timeout) {
                Write-Log "winget configuration process exceeded timeout of $timeoutMinutes minutes. Terminating..." -Level 'ERROR' -Section "Dev Flows Installation"
                $process.Kill()
                $processCompleted = $false
                break
            }
        }
        
        if ($process.HasExited) {
            $processCompleted = $true
            # Wait a bit more for async output to finish
            Start-Sleep -Seconds 2
        }
        
        # Clean up event handlers
        Get-EventSubscriber | Where-Object { $_.SourceObject -eq $process } | Unregister-Event
        
        # Write all captured output to the main log file instead of separate files
        $outputText = $script:outputBuilder.ToString()
        $errorText = $script:errorBuilder.ToString()
        
        if ($outputText) {
            Write-Log "=== Winget Configuration Output ===" -Level 'INFO' -Section "Dev Flows Installation"
            $outputText -split "`r?`n" | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Log "WINGET OUTPUT: $_" -Level 'INFO' -Section "Dev Flows Installation"
                }
            }
        }
        
        if ($errorText) {
            Write-Log "=== Winget Configuration Errors ===" -Level 'ERROR' -Section "Dev Flows Installation"
            $errorText -split "`r?`n" | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Log "WINGET ERROR: $_" -Level 'ERROR' -Section "Dev Flows Installation"
                }
            }
        }
        
        $configDuration = (Get-Date) - $configStart
        $exitCode = $process.ExitCode
        
        if ($script:currentPackage) {
            $packageDuration = (Get-Date) - $script:packageStartTime
            Write-Log "Final package status: $script:currentPackage (Duration: $($packageDuration.TotalSeconds.ToString('F1')) seconds)" -Level 'INFO' -Section "Dev Flows Installation"
        }
        
        Write-Log "winget configuration process completed with exit code: $exitCode (Duration: $($configDuration.TotalMinutes.ToString('F2')) minutes)" -Level 'INFO' -Section "Dev Flows Installation"
        
        if ($exitCode -eq 0) {
            Write-Log "Dev flows DSC configuration completed successfully" -Level 'SUCCESS' -Section "Dev Flows Installation"
        } else {
            $script:ErrorCount++
            Write-Log "Dev flows DSC configuration failed with exit code: $exitCode" -Level 'ERROR' -Section "Dev Flows Installation"
        }
        
        # Log summary of packages processed
        $packageCount = ($script:configOutput | Where-Object { $_ -match 'Installing|Processing package|Successfully installed' }).Count
        if ($packageCount -gt 0) {
            Write-Log "Total packages processed: $packageCount" -Level 'INFO' -Section "Dev Flows Installation"
        }
        
    } catch {
        $script:ErrorCount++
        Write-Log "Exception during Dev flows DSC configuration" -Level 'ERROR' -Section "Dev Flows Installation" -Exception $_
    }

    # clean up, Clean up, everyone wants to clean up
    if (Test-Path $dscAdmin) {
        Remove-Item $dscAdmin -verbose
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
            # Check if Microsoft Store is available
            $storeAvailable = $false
            try {
                $storeTest = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction SilentlyContinue
                if ($storeTest) {
                    $storeAvailable = $true
                }
            } catch {
                # Store not available
            }
            
            if ($storeAvailable) {
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
}  # End of else block (admin section)

# Final Summary
$scriptEndTime = Get-Date
$totalDuration = $scriptEndTime - $scriptStartTime

Write-Log "========================================" -Level 'INFO'
Write-Log "Workstation Setup Script Completed" -Level 'SECTION_END'
Write-Log "========================================" -Level 'INFO'
Write-Log "Total Execution Time: $($totalDuration.TotalMinutes.ToString('F2')) minutes ($($totalDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'INFO'
Write-Log "Total Errors: $script:ErrorCount" -Level $(if ($script:ErrorCount -gt 0) { 'ERROR' } else { 'SUCCESS' })
Write-Log "Total Warnings: $script:WarningCount" -Level $(if ($script:WarningCount -gt 0) { 'WARNING' } else { 'INFO' })
Write-Log "Log File Location: $logFilePath" -Level 'INFO'
Write-Log "========================================" -Level 'INFO'

# Section Timing Summary
Write-Log "Section Timing Summary:" -Level 'INFO'
foreach ($section in $script:SectionTimings.Keys | Sort-Object) {
    $timing = $script:SectionTimings[$section]
    if ($timing.Duration) {
        Write-Log "  $section : $($timing.Duration.TotalSeconds.ToString('F2')) seconds" -Level 'INFO'
    }
}

Write-Log "========================================" -Level 'INFO'
Write-Log "For optimization data, review the log file: $logFilePath" -Level 'INFO'
Write-Log "========================================" -Level 'INFO'
