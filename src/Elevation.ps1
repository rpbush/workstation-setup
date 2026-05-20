# Per-command elevation helper.
#
# The script intentionally runs in user context (WinGet is per-user AppX and
# fails when elevated). For the few operations that need admin (Windows
# optional features, HKLM registry writes), this helper elevates JUST that
# scriptblock via UAC — leaving the parent session non-elevated.
#
# Reads `$script:IsAdmin` from boot.ps1's scope; if already admin, runs the
# block directly. Otherwise spawns `Start-Process PowerShell -Verb RunAs`
# with the scriptblock serialized to a temp .ps1.
function Invoke-AdminCommand {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory=$false)]
        [string]$Description = "Administrative operation"
    )

    if ($script:IsAdmin) {
        # Already running as admin, execute directly
        return & $ScriptBlock
    } else {
        Write-Host "Elevating for: $Description" -ForegroundColor Cyan
        $tempScript = Join-Path $env:TEMP "elevated-command-$(Get-Random).ps1"
        $ScriptBlock.ToString() | Out-File -FilePath $tempScript -Encoding UTF8 -Force

        try {
            $process = Start-Process PowerShell -Verb RunAs -ArgumentList "-ExecutionPolicy", "Bypass", "-File", $tempScript -Wait -PassThru -NoNewWindow
            $exitCode = $process.ExitCode
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            return $exitCode
        } catch {
            Write-Warning "Failed to elevate command: $_"
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            return -1
        }
    }
}
