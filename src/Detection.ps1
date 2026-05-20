# Detection helpers: "is X installed / available?"
#
# All return $true / $false (or in Test-WinGetInstalled's case, a hashtable).
# Dot-sourced from boot.ps1; shares its scope.

# Is a Windows optional feature ("Microsoft-Windows-Subsystem-Linux" etc.) enabled?
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

# Is a winget package installed? Uses a background job with timeout because
# `winget list` can hang on fresh installs while the source catalog warms up.
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

# Is Microsoft Office installed? Multi-pronged detection because winget alone
# is unreliable (Office C2R sometimes doesn't show up in `winget list`).
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

# Is Microsoft Teams installed?
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

# Is an AppX package installed? -UseWildcard allows matching versioned names
# like Microsoft.WindowsAppRuntime.1.8 by passing "Microsoft.WindowsAppRuntime".
function Test-AppxPackageInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,
        [Parameter(Mandatory=$false)]
        [switch]$UseWildcard
    )

    try {
        if ($UseWildcard) {
            $package = Get-AppxPackage -Name "$PackageName*" -ErrorAction SilentlyContinue
            return ($null -ne $package -and $package.Count -gt 0)
        } else {
            $package = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
            return ($null -ne $package)
        }
    } catch {
        return $false
    }
}

# Is the Microsoft Store available on this system? Returns $false on Windows
# Sandbox, LTSC, Server, and other editions that ship without it. Use this to
# gate any `ms-windows-store://` launch — those URLs silently hang if the
# Store isn't installed.
function Test-MicrosoftStoreAvailable {
    try {
        $store = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction SilentlyContinue
        return ($null -ne $store)
    } catch {
        return $false
    }
}

# Is Windows already activated (permanent license)?
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

# After launching the Store UI, poll Get-AppxPackage until the named package
# appears (5-minute timeout). Avoids blocking forever on Read-Host if the user
# walks away.
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
