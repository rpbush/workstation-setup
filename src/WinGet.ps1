# WinGet-specific helpers.
#
# Reference: https://learn.microsoft.com/en-us/windows/package-manager/winget/
# Key invariant: WinGet is a per-user AppX package. It does NOT work in
# elevated/admin/SYSTEM contexts. Functions here handle that explicitly.

# Run a winget command. If invoked from SYSTEM context, locates the logged-in
# user's winget.exe under WindowsApps and runs it in the user's name; otherwise
# uses winget on PATH directly.
function Invoke-WinGetCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,
        [Parameter(Mandatory=$false)]
        [switch]$CaptureOutput
    )

    $isRunningAsSystem = ($env:USERNAME -eq "SYSTEM")

    if ($isRunningAsSystem) {
        # Running as SYSTEM/admin - winget won't work, need to run as logged-in user
        $loggedInUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
        if ($loggedInUser -and $loggedInUser -ne "SYSTEM") {
            $username = $loggedInUser.Split('\')[-1]
            Write-Log "Running winget as user $username (winget is user-scoped and doesn't work as admin)" -Level 'INFO' -Section "WinGet"

            # Try to find the user's profile path
            $userProfile = (Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like "*$username" }).LocalPath
            if ($userProfile) {
                $wingetPath = Join-Path $env:ProgramFiles "WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe"
                $wingetExe = Get-Item $wingetPath -ErrorAction SilentlyContinue | Select-Object -First 1

                if ($wingetExe) {
                    if ($CaptureOutput) {
                        $tempOutput = [System.IO.Path]::GetTempFileName()
                        $tempError = [System.IO.Path]::GetTempFileName()
                        $process = Start-Process -FilePath $wingetExe.FullName -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOutput -RedirectStandardError $tempError -ErrorAction SilentlyContinue
                        $output = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
                        $stderr = Get-Content $tempError -Raw -ErrorAction SilentlyContinue
                        Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
                        Remove-Item $tempError -Force -ErrorAction SilentlyContinue
                        return @{
                            ExitCode = $process.ExitCode
                            Output = $output
                            Error = $stderr
                        }
                    } else {
                        $process = Start-Process -FilePath $wingetExe.FullName -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                        return @{
                            ExitCode = $process.ExitCode
                            Output = ""
                            Error = ""
                        }
                    }
                }
            }

            # Fallback: warn that winget needs to run at user level
            Write-Log "WARNING: Cannot run winget as admin (SYSTEM). Winget is user-scoped and must run in user context." -Level 'WARNING' -Section "WinGet"
            Write-Log "Please run winget commands manually in a non-elevated user session." -Level 'WARNING' -Section "WinGet"
            return @{
                ExitCode = -1
                Output = ""
                Error = "Winget is not available in admin context"
            }
        }
    }

    # Running in user context - can use winget directly
    if ($CaptureOutput) {
        $tempOutput = [System.IO.Path]::GetTempFileName()
        $tempError = [System.IO.Path]::GetTempFileName()
        $process = Start-Process -FilePath "winget.exe" -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOutput -RedirectStandardError $tempError -ErrorAction SilentlyContinue
        $output = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content $tempError -Raw -ErrorAction SilentlyContinue
        Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
        Remove-Item $tempError -Force -ErrorAction SilentlyContinue
        return @{
            ExitCode = $process.ExitCode
            Output = $output
            Error = $stderr
        }
    } else {
        $process = Start-Process -FilePath "winget.exe" -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
        return @{
            ExitCode = $process.ExitCode
            Output = ""
            Error = ""
        }
    }
}

# Parse `winget configure` / `winget install` output line-by-line and surface
# per-package progress to the console.
function Show-WinGetProgress {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputText,
        [Parameter(Mandatory=$false)]
        [string]$Section = "Installation"
    )

    if (-not $OutputText) { return }

    $outputLines = $OutputText -split "`r?`n"
    $currentPackage = $null
    $packageStartTime = $null

    # Patterns to detect package names and status. Bracket character codes are
    # used here because raw `[` / `]` in PowerShell regex literals interact
    # poorly with string interpolation in some PS versions.
    $packagePattern = 'WinGetPackage\s+' + [char]91 + '([^' + [char]93 + ']+)' + [char]93
    $processingPattern = 'Processing.*' + [char]91 + '([^' + [char]93 + ']+)' + [char]93
    $foundPattern = 'Found\s+([^\s]+)'

    foreach ($line in $outputLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $packageMatch = [regex]::Match($line, $packagePattern)
        if (-not $packageMatch.Success) {
            $packageMatch = [regex]::Match($line, $processingPattern)
        }
        if (-not $packageMatch.Success) {
            $packageMatch = [regex]::Match($line, $foundPattern)
        }

        if ($packageMatch.Success) {
            $newPackage = $packageMatch.Groups[1].Value.Trim()
            if ($newPackage -and $newPackage -ne $currentPackage) {
                if ($currentPackage) {
                    $packageDuration = if ($packageStartTime) { ((Get-Date) - $packageStartTime).TotalSeconds } else { 0 }
                    Write-Host "    ✓ Completed: $currentPackage ($([math]::Round($packageDuration, 1))s)" -ForegroundColor Green
                }
                $currentPackage = $newPackage
                $packageStartTime = Get-Date
                Write-Host "  → Installing: $currentPackage..." -ForegroundColor Cyan
                Write-Log "Installing package: $currentPackage" -Level 'INFO' -Section $Section
            }
        } elseif ($line -match 'Downloading|Downloaded' -and $currentPackage) {
            Write-Host "    ↓ Downloading: $currentPackage..." -ForegroundColor Yellow
        } elseif ($line -match 'Installing' -and $currentPackage) {
            Write-Host "    ⚙ Installing: $currentPackage..." -ForegroundColor Cyan
        } elseif ($line -match 'Verifying|Verified' -and $currentPackage) {
            Write-Host "    ✓ Verifying: $currentPackage..." -ForegroundColor Gray
        } elseif ($line -match 'Successfully|installed|completed' -and $currentPackage) {
            $packageDuration = if ($packageStartTime) { ((Get-Date) - $packageStartTime).TotalSeconds } else { 0 }
            Write-Host "    ✓ Completed: $currentPackage ($([math]::Round($packageDuration, 1))s)" -ForegroundColor Green
            $currentPackage = $null
            $packageStartTime = $null
        } elseif ($line -match 'Already\s+installed|Skipping|No\s+change' -and $currentPackage) {
            Write-Host "    ⊙ Skipped: $currentPackage (already installed)" -ForegroundColor Gray
            $currentPackage = $null
            $packageStartTime = $null
        } elseif ($line -match 'Failed|Error' -and $currentPackage) {
            Write-Host "    ✗ Failed: $currentPackage" -ForegroundColor Red
            $currentPackage = $null
            $packageStartTime = $null
        }
    }

    # Handle final package if still processing
    if ($currentPackage) {
        $packageDuration = if ($packageStartTime) { ((Get-Date) - $packageStartTime).TotalSeconds } else { 0 }
        Write-Host "    ✓ Completed: $currentPackage ($([math]::Round($packageDuration, 1))s)" -ForegroundColor Green
    }
}

# Is WinGet available + working? Returns a hashtable: @{Installed,Version,Working}.
function Test-WinGetInstalled {
    try {
        # Refresh PATH to ensure winget is available if recently installed
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        # Check if running as admin (SYSTEM) - winget won't work in that context
        $isRunningAsSystem = ($env:USERNAME -eq "SYSTEM")
        if ($isRunningAsSystem) {
            Write-Log "WARNING: Running as SYSTEM/admin. WinGet is user-scoped and may not be available." -Level 'WARNING' -Section "WinGet Check"
            Write-Log "WinGet operations should be performed in a non-elevated user session." -Level 'WARNING' -Section "WinGet Check"
            # Still try to check, but expect it may fail
        }

        # Use --info for better compatibility (recommended by Microsoft docs)
        $wingetInfo = winget --info 2>$null
        if ($wingetInfo) {
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
        $isRunningAsSystem = ($env:USERNAME -eq "SYSTEM")
        if ($isRunningAsSystem) {
            Write-Log "WinGet not available in admin context (expected - WinGet is user-scoped)" -Level 'WARNING' -Section "WinGet Check"
        }
    }

    return @{
        Installed = $false
        Version = $null
        Working = $false
    }
}

# `winget source update`, treated as best-effort (returns $true even when it
# logs warnings — a stale-but-present catalog is usually fine).
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
            return $true
        }
    } catch {
        Write-Log "Failed to refresh winget catalog, but continuing anyway: $_" -Level 'WARNING' -Section $Section
        Write-Host "    ⚠ Catalog refresh failed: $_ (continuing anyway)" -ForegroundColor Yellow
        return $false
    }
}

# Ensure `winget configure` is enabled (verifies by actually running it).
# Up to two attempts: probe, enable, re-probe. Returns $true on success.
function Ensure-WinGetConfigurationEnabled {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Section = ''
    )

    $maxRetries = 2
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            # Capture both stdout and stderr
            $testOutput = winget configure list 2>&1 | Out-String
            $testOutputLower = $testOutput.ToLower()

            # Error message: "Extended features are not enabled. Run `winget configure --enable` to enable them."
            $needsEnable = $testOutputLower -match "extended features are not enabled" -or
                          $testOutputLower -match "run.*winget configure.*--enable"

            if ($needsEnable) {
                Write-Log "WinGet configuration features are not enabled. Enabling them (attempt $($retryCount + 1))..." -Level 'INFO' -Section $Section

                $tempOutput = [System.IO.Path]::GetTempFileName()
                $tempError = [System.IO.Path]::GetTempFileName()

                $process = Start-Process -FilePath "winget.exe" -ArgumentList "configure", "--enable" -NoNewWindow -PassThru -RedirectStandardOutput $tempOutput -RedirectStandardError $tempError -ErrorAction Stop -Wait

                $enableOutput = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
                $errorOutput = Get-Content $tempError -Raw -ErrorAction SilentlyContinue

                Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
                Remove-Item $tempError -Force -ErrorAction SilentlyContinue

                # Sometimes the enable command returns non-zero exit codes but still succeeds
                Start-Sleep -Seconds 3

                # Always verify by testing if configuration is actually enabled now
                $verifyOutput = winget configure list 2>&1 | Out-String
                $verifyOutputLower = $verifyOutput.ToLower()
                if ($verifyOutputLower -notmatch "extended features are not enabled") {
                    Write-Log "WinGet configuration features enabled and verified successfully" -Level 'SUCCESS' -Section $Section
                    return $true
                } else {
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
