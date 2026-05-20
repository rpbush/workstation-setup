# MDM cleanup helper.
#
# `gpupdate /force` sometimes prints "failed to apply the MDM Policy" even
# though the actual Group Policy update succeeds — leftover state from prior
# enrollment attempts. This function scrubs the stale failure markers so the
# next gpupdate cycles cleanly. Pure registry cleanup; safe to no-op.
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
                $policyKeys = Get-ChildItem -Path $policyManagerPath -Recurse -ErrorAction SilentlyContinue | Where-Object {
                    $keyName = $_.PSChildName
                    if ($keyName -match "Failed|Error|Pending|Retry") {
                        return $true
                    }

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
                            if ($keyProps.PSObject.Properties.Name -contains "Status" -and $keyProps.Status -eq "Failed") {
                                $shouldRemove = $true
                            }
                            if ($keyProps.PSObject.Properties.Name -contains "State" -and $keyProps.State -eq "Failed") {
                                $shouldRemove = $true
                            }
                            if ($keyProps.PSObject.Properties.Name -contains "LastError" -and $null -ne $keyProps.LastError -and $keyProps.LastError -ne 0) {
                                $shouldRemove = $true
                            }
                        }

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
