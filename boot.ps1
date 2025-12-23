# ============================================================================
# PHASE-BASED WORKSTATION SETUP SCRIPT
# ============================================================================
# This script uses a phase-based execution model:
# - Phase 1: Prerequisites (NFS, etc.) - may require reboot
# - Phase 2: Main installation and configuration
# ============================================================================

# 1. PARAMETERS & PREAMBLE
param (
    [switch]$ResumeAfterReboot  # This flag tells the script we just rebooted
)

$mypath = $MyInvocation.MyCommand.Path
Write-Output "Path of the script: $mypath"
Write-Output "Args for script: $Args"
Write-Output "ResumeAfterReboot: $ResumeAfterReboot"

# 2. IMMEDIATE ELEVATION CHECK
# If not admin, restart self as admin immediately to preserve variables and logs
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Elevation..." -ForegroundColor Yellow
    # Pass the current arguments and script path to the new process
    # Use array for ArgumentList to handle spaces/quotes properly
    $argList = @('-ExecutionPolicy', 'Bypass', '-File', $mypath)
    if ($ResumeAfterReboot) {
        $argList += '-ResumeAfterReboot'
    }
    if ($Args.Count -gt 0) {
        $argList += $Args
    }
    Start-Process PowerShell -Verb RunAs -ArgumentList $argList
    Exit
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
$script:SuccessCount = 0
$script:SectionResults = @{}  # Track success/failure status for each section
$script:SectionTimings = @{}

# Track detailed installation/configuration status
$script:InstalledItems = @()      # Items that were installed/applied
$script:AlreadySetItems = @()     # Items that were already installed/configured
$script:FailedItems = @()         # Items that failed to install/configure
$script:SettingsApplied = @()    # Settings that were applied
$script:SettingsAlreadySet = @() # Settings that were already configured

# Helper function to clean up MDM failed registry attempts
function Clear-MDMFailedRegistryAttempts {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Section = ''
    )
    
    try {
        Write-Log "Cleaning up MDM failed registry attempts..." -Level 'INFO' -Section $Section
        Write-Host "  → Cleaning up MDM failed registry attempts..." -ForegroundColor Gray
        
        $cleanedCount = 0
        
        # Clean up failed MDM policy application attempts in PolicyManager
        $policyManagerPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager"
        if (Test-Path $policyManagerPath) {
            try {
                # Look for policy application errors/failures
                $policyKeys = Get-ChildItem -Path $policyManagerPath -Recurse -ErrorAction SilentlyContinue | Where-Object {
                    $keyName = $_.PSChildName
                    # Look for keys with error/failure indicators in their name or properties
                    if ($keyName -match "Failed|Error|Pending|Retry") {
                        return $true
                    }
                    
                    # Check properties for failure indicators
                    try {
                        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        if ($props) {
                            $propNames = $props.PSObject.Properties.Name
                            foreach ($propName in $propNames) {
                                if ($propName -match "Status|State|Error|Failed" -and $props.$propName -match "Failed|Error|0x[0-9A-Fa-f]{8}") {
                                    return $true
                                }
                            }
                        }
                    } catch {
                        # Ignore errors reading properties
                    }
                    return $false
                }
                
                foreach ($key in $policyKeys) {
                    try {
                        # Double-check it's actually a failure before removing
                        $keyProps = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                        $shouldRemove = $false
                        
                        if ($keyProps) {
                            # Check for explicit failure states
                            if ($keyProps.PSObject.Properties.Name -contains "Status" -and $keyProps.Status -eq "Failed") {
                                $shouldRemove = $true
                            }
                            if ($keyProps.PSObject.Properties.Name -contains "State" -and $keyProps.State -eq "Failed") {
                                $shouldRemove = $true
                            }
                            if ($keyProps.PSObject.Properties.Name -contains "LastError" -and $keyProps.LastError -ne $null -and $keyProps.LastError -ne 0) {
                                $shouldRemove = $true
                            }
                        }
                        
                        # Also check if key name indicates failure
                        if ($key.PSChildName -match "Failed|Error") {
                            $shouldRemove = $true
                        }
                        
                        if ($shouldRemove) {
                            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            $cleanedCount++
                            Write-Log "Removed MDM failed registry key: $($key.PSPath)" -Level 'INFO' -Section $Section
                        }
                    } catch {
                        Write-Log "Could not remove MDM registry key $($key.PSPath): $_" -Level 'WARNING' -Section $Section
                    }
                }
            } catch {
                Write-Log "Error processing PolicyManager path: $_" -Level 'WARNING' -Section $Section
            }
        }
        
        # Clean up failed MDM enrollment attempts (only if explicitly marked as failed)
        $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if (Test-Path $enrollmentPath) {
            try {
                $enrollments = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
                foreach ($enrollment in $enrollments) {
                    try {
                        $enrollmentProps = Get-ItemProperty -Path $enrollment.PSPath -ErrorAction SilentlyContinue
                        if ($enrollmentProps) {
                            # Only remove if explicitly marked as failed and not active
                            $isFailed = $false
                            $isActive = $false
                            
                            if ($enrollmentProps.PSObject.Properties.Name -contains "EnrollmentState") {
                                if ($enrollmentProps.EnrollmentState -eq "Failed") {
                                    $isFailed = $true
                                } elseif ($enrollmentProps.EnrollmentState -eq "Enrolled" -or $enrollmentProps.EnrollmentState -eq "Enrolling") {
                                    $isActive = $true
                                }
                            }
                            
                            if ($enrollmentProps.PSObject.Properties.Name -contains "EnrollmentStatus") {
                                if ($enrollmentProps.EnrollmentStatus -eq "Failed") {
                                    $isFailed = $true
                                } elseif ($enrollmentProps.EnrollmentStatus -eq "Enrolled" -or $enrollmentProps.EnrollmentStatus -eq "Enrolling") {
                                    $isActive = $true
                                }
                            }
                            
                            # Only remove if failed and not active
                            if ($isFailed -and -not $isActive) {
                                Remove-Item -Path $enrollment.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                                $cleanedCount++
                                Write-Log "Removed failed MDM enrollment: $($enrollment.PSPath)" -Level 'INFO' -Section $Section
                            }
                        }
                    } catch {
                        Write-Log "Could not process MDM enrollment $($enrollment.PSPath): $_" -Level 'WARNING' -Section $Section
                    }
                }
            } catch {
                Write-Log "Error processing enrollment path: $_" -Level 'WARNING' -Section $Section
            }
        }
        
        if ($cleanedCount -gt 0) {
            Write-Log "Cleaned up $cleanedCount MDM failed registry attempts" -Level 'SUCCESS' -Section $Section
            Write-Host "  ✓ Cleaned up $cleanedCount MDM failed registry attempts" -ForegroundColor Green
            return $true
        } else {
            Write-Log "No MDM failed registry attempts found to clean up" -Level 'INFO' -Section $Section
            Write-Host "  ✓ No MDM failed registry attempts found" -ForegroundColor Green
            return $false
        }
    } catch {
        Write-Log "Error cleaning up MDM failed registry attempts: $_" -Level 'WARNING' -Section $Section
        Write-Host "  ⚠ Error cleaning up MDM registry: $_" -ForegroundColor Yellow
        return $false
    }
}

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
        [string]$PackageId,
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 10
    )
    
    try {
        # Refresh PATH to ensure winget is available
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Check if winget is available
        $wingetCheck = winget --info 2>$null
        if (-not $wingetCheck) {
            return $false
        }
        
        # Use winget list to check if package is installed with timeout
        $job = Start-Job -ScriptBlock {
            param($PackageId)
            $listOutput = winget list --id $PackageId --exact 2>&1
            return @{
                ExitCode = $LASTEXITCODE
                Output = $listOutput
                Matched = ($listOutput -match $PackageId)
            }
        } -ArgumentList $PackageId
        
        $result = $job | Wait-Job -Timeout $TimeoutSeconds | Receive-Job
        $job | Remove-Job -Force -ErrorAction SilentlyContinue
        
        if ($result -and $result.ExitCode -eq 0 -and $result.Matched) {
            return $true
        }
    } catch {
        # Error checking, assume not installed
    }
    return $false
}

# Helper function to check if Office is installed using multiple detection methods
function Test-OfficeInstalled {
    try {
        # Method 1: Check for Outlook.exe (most reliable)
        $outlookPath = Get-Command outlook.exe -ErrorAction SilentlyContinue
        if ($outlookPath) {
            return $true
        }
        
        # Method 2: Check registry for Office installation
        $officeKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot"
        )
        
        foreach ($key in $officeKeys) {
            if (Test-Path $key) {
                return $true
            }
        }
        
        # Method 3: Check for Office installation directory
        $officePaths = @(
            "${env:ProgramFiles}\Microsoft Office",
            "${env:ProgramFiles(x86)}\Microsoft Office"
        )
        
        foreach ($path in $officePaths) {
            if (Test-Path $path) {
                $officeDirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
                if ($officeDirs -and $officeDirs.Count -gt 0) {
                    return $true
                }
            }
        }
    } catch {
        # Error checking, assume not installed
    }
    return $false
}

# Helper function to check if Teams is installed
function Test-TeamsInstalled {
    try {
        # Check for Teams executable
        $teamsPath = Get-Command ms-teams.exe -ErrorAction SilentlyContinue
        if ($teamsPath) {
            return $true
        }
        
        # Check for Teams in common installation locations
        $teamsPaths = @(
            "${env:LOCALAPPDATA}\Microsoft\Teams\current\Teams.exe",
            "${env:ProgramFiles}\Microsoft\Teams\current\Teams.exe",
            "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe"
        )
        
        foreach ($path in $teamsPaths) {
            if (Test-Path $path) {
                return $true
            }
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
    # If package name provided, poll for installation instead of blocking on Read-Host
    # This prevents the script from hanging indefinitely if user walks away
    if ($PackageName) {
        Write-Host "Waiting for installation to complete (Timeout: 5 minutes)..." -ForegroundColor Cyan
        Write-Host "The script will automatically detect when installation completes." -ForegroundColor Gray
        Write-Host "Press Ctrl+C to skip and continue..." -ForegroundColor Yellow
        Write-Log "Polling for $AppName installation completion..." -Level 'INFO' -Section "Store Installation"
        
        $timeout = New-TimeSpan -Minutes 5
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $installed = $false
        $checkInterval = 10  # Check every 10 seconds
        
        while ($sw.Elapsed -lt $timeout -and -not $installed) {
            Start-Sleep -Seconds $checkInterval
            
            # Check if package is installed
            if ($UseWildcard) {
                $installed = Test-AppxPackageInstalled -PackageName $PackageName -UseWildcard
            } else {
                $installed = Test-AppxPackageInstalled -PackageName $PackageName
            }
            
            if ($installed) {
                $sw.Stop()
                Write-Host "Installation detected!" -ForegroundColor Green
                Write-Log "$AppName installation verified successfully (detected after $($sw.Elapsed.TotalSeconds.ToString('F1')) seconds)" -Level 'SUCCESS' -Section "Store Installation"
                return $true
            }
            
            # Show progress every 30 seconds
            if (($sw.Elapsed.TotalSeconds % 30) -lt $checkInterval) {
                $remaining = $timeout - $sw.Elapsed
                Write-Host "  Still waiting... ($($remaining.TotalMinutes.ToString('F1')) minutes remaining)" -ForegroundColor Gray
            }
        }
        $sw.Stop()
        
        if (-not $installed) {
            Write-Host "Timeout reached. Installation may still be in progress." -ForegroundColor Yellow
            Write-Log "$AppName installation could not be verified within timeout period. It may still be installing." -Level 'WARNING' -Section "Store Installation"
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

# Helper function to refresh winget catalog to ensure connectivity
function Refresh-WinGetCatalog {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Section = ''
    )
    
    try {
        Write-Log "Refreshing winget catalog to ensure connectivity..." -Level 'INFO' -Section $Section
        Write-Host "    → Running 'winget source update'..." -ForegroundColor Gray
        
        $refreshStart = Get-Date
        $refreshOutput = winget source update 2>&1 | Out-String
        $refreshDuration = (Get-Date) - $refreshStart
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Winget catalog refreshed successfully (Duration: $($refreshDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'SUCCESS' -Section $Section
            Write-Log "Catalog refresh output: $refreshOutput" -Level 'INFO' -Section $Section
            return $true
        } else {
            Write-Log "Winget catalog refresh completed with warnings (exit code: $LASTEXITCODE, Duration: $($refreshDuration.TotalSeconds.ToString('F2')) seconds)" -Level 'WARNING' -Section $Section
            Write-Log "Output: $refreshOutput" -Level 'INFO' -Section $Section
            Write-Host "    ⚠ Catalog refresh had warnings (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
            # Still return true as this is not critical - catalog might be recent enough
            return $true
        }
    } catch {
        Write-Log "Failed to refresh winget catalog, but continuing anyway: $_" -Level 'WARNING' -Section $Section
        Write-Host "    ⚠ Catalog refresh failed: $_ (continuing anyway)" -ForegroundColor Yellow
        # Don't fail the whole process if catalog refresh fails
        return $false
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
    $script:AlreadySetItems += "WinGet (v$($wingetStatus.Version))"
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

# Try to use local DSC files first, then fall back to GitHub
$scriptDir = Split-Path $mypath -Parent
# CRITICAL: Use $env:TEMP for DSC files to avoid saving to System32 when running from RunOnce
$dscNonAdmin = Join-Path $env:TEMP "rpbush.nonAdmin.dsc.yml"
$dscAdmin = Join-Path $env:TEMP "rpbush.dev.dsc.yml"
$dscAdminNoDrive = Join-Path $env:TEMP "rpbush.dev.nodrive.dsc.yml"  # DSC file without Dev Drive resource
$dscOffice = Join-Path $env:TEMP "rpbush.office.dsc.yml"

# Check if DSC files exist locally (in script directory)
$dscNonAdminLocal = Join-Path $scriptDir "rpbush.nonAdmin.dsc.yml"
$dscAdminLocal = Join-Path $scriptDir "rpbush.dev.dsc.yml"
$dscAdminNoDriveLocal = Join-Path $scriptDir "rpbush.dev.nodrive.dsc.yml"
$dscOfficeLocal = Join-Path $scriptDir "rpbush.office.dsc.yml"

# GitHub repository for DSC files (use workstation-setup repo which contains the files)
$dscUri = "https://raw.githubusercontent.com/rpbush/workstation-setup/main/"

# Use just the filename for URIs (not the full temp path)
$dscOfficeUri = $dscUri + "rpbush.office.dsc.yml"
$dscNonAdminUri = $dscUri + "rpbush.nonAdmin.dsc.yml"
$dscAdminUri = $dscUri + "rpbush.dev.dsc.yml"
$dscAdminNoDriveUri = $dscUri + "rpbush.dev.nodrive.dsc.yml"

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
    
    # Clean up
    if (Test-Path $dscNonAdmin) {
        Remove-Item $dscNonAdmin -Force -ErrorAction SilentlyContinue
    }
    
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
        Write-Log "Copying script and DSC files to safe location..." -Level 'INFO'
        Copy-Item -Path $mypath -Destination $safeScriptPath -Force
        Write-Log "Script copied successfully to safe location: $safeScriptPath" -Level 'SUCCESS'
        
        # CRITICAL: Copy any YAML files in the same directory to the safe location
        # This ensures offline resume capability - if script is run from a folder with local DSC files,
        # they will be available after reboot even if the original folder is deleted
        $sourceDir = Split-Path $mypath -Parent
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
        $script:SettingsApplied += "File Explorer: Show hidden files/folders"
        
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
                    $script:SettingsApplied += "Power Profile: Ultimate Performance"
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
        $script:SettingsApplied += "System Tray: Show all icons"
        
        # Restart Explorer to apply changes (optional, but ensures immediate effect)
        # Get-Process explorer | Stop-Process -Force
        # Start-Sleep -Seconds 2
        # Start-Process explorer.exe
        
    } catch {
        Write-Warning "Failed to configure system tray: $_"
    }
    Write-Host "Done: Setting system tray to show all icons"
    # ---------------
    
    # ============================================================================
    # NETWORK STABILIZATION FUNCTIONS
    # ============================================================================
    # These functions ensure network and DNS are ready before attempting drive mapping
    # This fixes "System error 67" caused by DNS resolution delays
    
    function Wait-ForNetwork {
        param(
            [Parameter(Mandatory=$false)]
            [string[]]$Servers = @("FS-1"),
            [Parameter(Mandatory=$false)]
            [int]$MaxRetries = 30,
            [Parameter(Mandatory=$false)]
            [int]$RetryDelaySeconds = 2
        )
        
        Write-Host "Waiting for network stability..." -ForegroundColor Cyan
        Write-Log "Waiting for network stability (checking servers: $($Servers -join ', '))..." -Level 'INFO' -Section "Network Stabilization"
        
        $allReachable = $false
        $attempts = 0
        
        while ($attempts -lt $MaxRetries -and -not $allReachable) {
            $attempts++
            $allReachable = $true
            
            foreach ($server in $Servers) {
                Write-Log "Checking connectivity to $server (attempt $attempts of $MaxRetries)..." -Level 'INFO' -Section "Network Stabilization"
                
                # Test actual service port (Port 445 for SMB/Windows) - more reliable than ping
                # Many corporate networks block ICMP but allow SMB
                $tcpResult = $null
                try {
                    $tcpResult = Test-NetConnection -ComputerName $server -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                } catch {
                    # Test-NetConnection might not be available or failed
                }
                
                $serverReachable = $false
                
                if ($tcpResult -and $tcpResult.TcpTestSucceeded) {
                    Write-Log "$server is reachable on Port 445 (SMB)" -Level 'SUCCESS' -Section "Network Stabilization"
                    $serverReachable = $true
                } else {
                    # Fallback to ping if port 445 test failed or unavailable
                    $pingResult = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
                    
                    if ($pingResult) {
                        Write-Log "$server is reachable via ICMP (ping)" -Level 'SUCCESS' -Section "Network Stabilization"
                        $serverReachable = $true
                    } else {
                        # Last resort: try DNS resolution
                        try {
                            $dnsResult = [System.Net.Dns]::GetHostEntry($server)
                            if ($dnsResult -and $dnsResult.AddressList.Count -gt 0) {
                                Write-Log "DNS resolution successful for $server (IP: $($dnsResult.AddressList[0]))" -Level 'INFO' -Section "Network Stabilization"
                                $serverReachable = $true
                            }
                        } catch {
                            # DNS resolution also failed
                            Write-Log "DNS resolution failed for ${server}: $($_.Exception.Message)" -Level 'WARNING' -Section "Network Stabilization"
                        }
                    }
                }
                
                if (-not $serverReachable) {
                    $allReachable = $false
                    Write-Host "  → Waiting for $server to be reachable..." -ForegroundColor Yellow
                    break
                } else {
                    Write-Log "$server is reachable" -Level 'SUCCESS' -Section "Network Stabilization"
                }
            }
            
            if (-not $allReachable) {
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
        
        if ($allReachable) {
            Write-Host "Network is stable and all servers are reachable." -ForegroundColor Green
            Write-Log "Network stabilization complete - all servers are reachable" -Level 'SUCCESS' -Section "Network Stabilization"
            return $true
        } else {
            Write-Warning "Network might not be fully ready after $MaxRetries attempts. Continuing anyway..."
            Write-Log "Network stabilization incomplete after $MaxRetries attempts - some servers may not be reachable" -Level 'WARNING' -Section "Network Stabilization"
            return $false
        }
    }
    
    function Ensure-NfsServiceReady {
        Write-Log "Ensuring NFS Client service is ready..." -Level 'INFO' -Section "Network Drive Mapping"
        
        # Try multiple possible service names
        $nfsServiceNames = @("NfsClnt", "NfsRdr", "NfsService")
        $nfsService = $null
        $nfsServiceName = $null
        
        foreach ($serviceName in $nfsServiceNames) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $nfsService = $service
                    $nfsServiceName = $serviceName
                    break
                }
            } catch {
                # Service not found, continue
            }
        }
        
        if ($nfsService) {
            if ($nfsService.Status -ne "Running") {
                Write-Log "NFS Client service ($nfsServiceName) is not running. Starting it..." -Level 'WARNING' -Section "Network Drive Mapping"
                
                # Try nfsadmin first (more reliable for NFS)
                try {
                    $nfsAdminResult = nfsadmin client start 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "NFS Client service started successfully using nfsadmin" -Level 'SUCCESS' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 3
                        return $true
                    }
                } catch {
                    # nfsadmin not available, try Start-Service
                }
                
                # Fallback to Start-Service
                try {
                    Start-Service -Name $nfsServiceName -ErrorAction Stop
                    Write-Log "NFS Client service ($nfsServiceName) started successfully" -Level 'SUCCESS' -Section "Network Drive Mapping"
                    Start-Sleep -Seconds 2
                    return $true
                } catch {
                    Write-Log "Failed to start NFS Client service ($nfsServiceName): $_" -Level 'WARNING' -Section "Network Drive Mapping"
                    return $false
                }
            } else {
                Write-Log "NFS Client service ($nfsServiceName) is running" -Level 'INFO' -Section "Network Drive Mapping"
                # Give it a moment to ensure the network provider is registered
                Start-Sleep -Seconds 1
                return $true
            }
        } else {
            # Try nfsadmin as fallback
            try {
                $nfsAdminCheck = nfsadmin client 2>&1 | Out-String
                if ($nfsAdminCheck -notmatch "not recognized" -and $nfsAdminCheck -notmatch "not found") {
                    Write-Log "nfsadmin available, attempting to start NFS client..." -Level 'INFO' -Section "Network Drive Mapping"
                    $nfsAdminResult = nfsadmin client start 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "NFS Client started successfully using nfsadmin" -Level 'SUCCESS' -Section "Network Drive Mapping"
                        Start-Sleep -Seconds 3
                        return $true
                    }
                }
            } catch {
                # nfsadmin not available
            }
            
            Write-Log "NFS Client service not found. NFS mapping may fail." -Level 'WARNING' -Section "Network Drive Mapping"
            return $false
        }
    }
    
    # ============================================================================
    # Mapping network drives
    # ============================================================================
    Start-Section "Network Drive Mapping"
    
    # CRITICAL: Wait for network stability before attempting any drive mapping
    # This fixes "System error 67" caused by DNS resolution delays
    Write-Host "`n[STEP] Network Stabilization - Ensuring network is ready..." -ForegroundColor Cyan
    $networkReady = Wait-ForNetwork -Servers @("FS-1") -MaxRetries 30 -RetryDelaySeconds 2
    
    if (-not $networkReady) {
        Write-Host "  ⚠ Network may not be fully ready, but continuing with drive mapping..." -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ Network is stable and ready" -ForegroundColor Green
    }
    try {
        # NFS Client feature installation moved to start of script (may require reboot)
        # Windows Sandbox feature installation moved to Windows Features section
        
        # Domain-joined workstation: use logged-in user's credentials automatically
        # No credential prompting needed - Windows will use domain authentication
        $sDrive = "S:"
        $sPath = "\\FS-1\Storage"
        $serverName = ($sPath -split '\\')[2]
        
        Write-Log "Domain-joined workstation detected. Using logged-in user's domain credentials automatically." -Level 'INFO' -Section "Network Drive Mapping"
        
        # SAFETY: Check if S: drive is a physical disk before mapping
        try {
            $volume = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$sDrive'" -ErrorAction SilentlyContinue
            if ($volume -and $volume.DriveType -eq 3) {  # Type 3 = Local Disk
                Write-Log "CRITICAL: Drive $sDrive is a local physical disk! Cannot map SMB share." -Level 'ERROR' -Section "Network Drive Mapping"
                Write-Host "  ✗ ERROR: Drive $sDrive is already in use as a physical disk" -ForegroundColor Red
                Write-Host "    Please free up drive $sDrive or modify the script to use a different drive letter" -ForegroundColor Yellow
                $script:ErrorCount++
                $script:FailedItems += "Network Drive Mapping: Drive $sDrive is a physical disk"
            } else {
                Write-Log "Drive $sDrive is available for mapping (not a physical disk)" -Level 'INFO' -Section "Network Drive Mapping"
            }
        } catch {
            # If we can't check, assume it's safe to proceed
            Write-Log "Could not verify drive type for $sDrive, proceeding with mapping attempt" -Level 'INFO' -Section "Network Drive Mapping"
        }
        
        # Map N: drive to NFS:/media (NFS Network)
        $nDrive = "N:"
        $nPath = "NFS:/media"
        Write-Log "Attempting to map $nDrive to $nPath" -Level 'INFO' -Section "Network Drive Mapping"
        Write-Host "  → Mapping N: to NFS:/media..." -ForegroundColor Gray
        
        # SAFETY: Check if drive letter is a physical disk before mapping
        # Prevents conflicts with USB drives or SD cards
        try {
            $volume = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$nDrive'" -ErrorAction SilentlyContinue
            if ($volume -and $volume.DriveType -eq 3) {  # Type 3 = Local Disk
                Write-Log "CRITICAL: Drive $nDrive is a local physical disk! Cannot map NFS." -Level 'ERROR' -Section "Network Drive Mapping"
                Write-Host "  ✗ ERROR: Drive $nDrive is already in use as a physical disk" -ForegroundColor Red
                Write-Host "    Please free up drive $nDrive or modify the script to use a different drive letter" -ForegroundColor Yellow
                $script:ErrorCount++
                $script:FailedItems += "Network Drive Mapping: Drive $nDrive is a physical disk"
            } else {
                # Drive is either not in use or is a network drive (can be safely removed)
                Write-Log "Drive $nDrive is available for mapping (not a physical disk)" -Level 'INFO' -Section "Network Drive Mapping"
            }
        } catch {
            # If we can't check, assume it's safe to proceed (might be network drive or not exist)
            Write-Log "Could not verify drive type for $nDrive, proceeding with mapping attempt" -Level 'INFO' -Section "Network Drive Mapping"
        }
        
        # CRITICAL: Ensure NFS service is running and network provider is ready
        # This fixes "System error 67" for NFS caused by provider not being registered
        $nfsReady = Ensure-NfsServiceReady
        if (-not $nfsReady) {
            $script:WarningCount++
            Write-Host "  ⚠ NFS service may not be ready, but continuing with mapping attempt..." -ForegroundColor Yellow
        } else {
            Write-Host "  ✓ NFS service is ready" -ForegroundColor Green
        }
        
        # Remove existing mapping if it exists (only if it's a network drive)
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
        Write-Host "  → Mapping S: to \\FS-1\Storage..." -ForegroundColor Gray
        
        # CRITICAL: Verify server is still reachable (network may have changed)
        # This fixes "System error 67" for SMB caused by DNS resolution delays
        Write-Log "Verifying connectivity to server: $serverName" -Level 'INFO' -Section "Network Drive Mapping"
        Write-Host "  → Verifying connectivity to FS-1..." -ForegroundColor Gray
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
            $script:AlreadySetItems += "Windows Terminal (v$($wtInstalled.Version))"
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
                        $outputText = $configOutput -join ' | '
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
    
    # Determine which DSC file to use based on drive configuration
    # Instead of regex editing, we use separate files: rpbush.dev.dsc.yml (with Dev Drive) or rpbush.dev.nodrive.dsc.yml (without)
    Write-Host "  → Checking physical drives and space..." -ForegroundColor Gray
    $physicalDrives = Get-PhysicalDisk | Where-Object { $_.OperationalStatus -eq 'OK' -and $_.MediaType -ne 'Unspecified' } | Sort-Object DeviceID
    $secondDriveExists = $physicalDrives.Count -gt 1
    
    # Determine if we need Dev Drive or not
    $useDevDrive = $false
    if ($secondDriveExists) {
        Write-Host "  ✓ Second physical drive detected ($($physicalDrives.Count) drives found). Using full DSC with Dev Drive." -ForegroundColor Green
        $useDevDrive = $true
    } else {
        # Check if C: has enough space (75GB required)
        try {
            $cDrive = Get-PSDrive -Name C -ErrorAction Stop
            $freeSpaceGB = [math]::Round($cDrive.Free / 1GB, 2)
            $requiredSpaceGB = 75
            Write-Log "C: drive free space: $freeSpaceGB GB (required: $requiredSpaceGB GB for Dev Drive)" -Level 'INFO' -Section "Dev Flows Installation"
            
            if ($freeSpaceGB -ge $requiredSpaceGB) {
                Write-Host "  ✓ Sufficient space on C: drive ($freeSpaceGB GB). Using full DSC with Dev Drive." -ForegroundColor Green
                $useDevDrive = $true
            } else {
                Write-Host "  → Insufficient space on C: drive ($freeSpaceGB GB). Using DSC without Dev Drive." -ForegroundColor Yellow
                $useDevDrive = $false
            }
        } catch {
            Write-Log "Could not check C: drive free space. Using DSC without Dev Drive to avoid potential failures." -Level 'WARNING' -Section "Dev Flows Installation" -Exception $_
            Write-Host "  → Could not check drive space. Using DSC without Dev Drive." -ForegroundColor Yellow
            $useDevDrive = $false
        }
    }
    
    # Select the appropriate DSC file
    if ($useDevDrive) {
        $dscFileToUse = $dscAdmin
        $dscFileToUseLocal = $dscAdminLocal
        $dscFileToUseUri = $dscAdminUri
        Write-Log "Using Dev Flows DSC file WITH Dev Drive: $dscFileToUse" -Level 'INFO' -Section "Dev Flows Installation"
    } else {
        $dscFileToUse = $dscAdminNoDrive
        $dscFileToUseLocal = $dscAdminNoDriveLocal
        $dscFileToUseUri = $dscAdminNoDriveUri
        Write-Log "Using Dev Flows DSC file WITHOUT Dev Drive: $dscFileToUse" -Level 'INFO' -Section "Dev Flows Installation"
    }
    
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
    
    # Refresh winget catalog to ensure connectivity
    Write-Host "  → Refreshing winget catalog to ensure connectivity..." -ForegroundColor Gray
    $catalogRefreshed = Refresh-WinGetCatalog -Section "Dev Flows Installation"
    if ($catalogRefreshed) {
        Write-Host "  ✓ Winget catalog refreshed" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Winget catalog refresh had issues (continuing anyway)" -ForegroundColor Yellow
    }
    
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
            $proc = Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArgs -NoNewWindow -PassThru -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile -Wait
            
            $outputText = Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue
            $errorText = Get-Content $tempErrorFile -Raw -ErrorAction SilentlyContinue
            $exitCode = $proc.ExitCode
            
            # Clean up temp files
            Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue
            Remove-Item $tempErrorFile -Force -ErrorAction SilentlyContinue
            
            Write-Log "winget configuration completed via cmd.exe (exit code: $exitCode)" -Level 'INFO' -Section "Dev Flows Installation"
            Write-Log "Output length: $($outputText.Length) characters, Error length: $($errorText.Length) characters" -Level 'INFO' -Section "Dev Flows Installation"
            
            # Parse output to track installed packages
            if ($outputText) {
                $outputLines = $outputText -split "`r?`n"
                foreach ($line in $outputLines) {
                    if ($line -match 'WinGetPackage\s+\[([^\]]+)\]' -or $line -match 'Processing.*\[([^\]]+)\]') {
                        $packageId = $matches[1]
                        if ($packageId -and $packageId -notmatch '^\s*$') {
                            # Track package processing
                            if (-not ($script:InstalledItems -contains $packageId) -and -not ($script:AlreadySetItems -contains $packageId)) {
                                # Will be updated based on success/failure
                            }
                        }
                    }
                    if ($line -match 'Successfully|installed|completed' -and $line -match 'WinGetPackage\s+\[([^\]]+)\]') {
                        $packageId = $matches[1]
                        if ($packageId) {
                            $script:InstalledItems += "Dev Flows: $packageId"
                        }
                    }
                    if ($line -match 'Already\s+installed|Skipping|No\s+change' -and $line -match 'WinGetPackage\s+\[([^\]]+)\]') {
                        $packageId = $matches[1]
                        if ($packageId) {
                            $script:AlreadySetItems += "Dev Flows: $packageId"
                        }
                    }
                    if ($line -match 'Failed|Error' -and $line -match 'WinGetPackage\s+\[([^\]]+)\]') {
                        $packageId = $matches[1]
                        if ($packageId) {
                            $script:FailedItems += "Dev Flows: $packageId"
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
        
        # Log summary of packages processed
        # Use the captured output text instead of $script:configOutput (which was never set)
        $packageCount = 0
        if ($outputText) {
            $packageCount = ($outputText -split "`n" | Where-Object { $_ -match 'Installing|Processing package|Successfully installed' }).Count
        }
        if ($packageCount -gt 0) {
            Write-Log "Total packages processed: $packageCount" -Level 'INFO' -Section "Dev Flows Installation"
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
