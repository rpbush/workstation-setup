# Logging + section-timing helpers.
#
# All functions here are dot-sourced from boot.ps1 so they share its scope.
# That means:
# - `$logFilePath`         — initialized in boot.ps1 (persistent across reboot)
# - `$script:SectionTimings` — initialized in boot.ps1; Start/End-Section mutate it
# - State arrays like `$script:InstalledItems` are written by callers, not here.

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
