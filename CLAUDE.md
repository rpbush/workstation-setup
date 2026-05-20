# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A single-purpose Windows 11 workstation bootstrap kit, intended to be curl-piped from GitHub onto a fresh machine. There is no build, no test suite, no package manager — just a PowerShell script that orchestrates WinGet DSC configurations and registry/feature tweaks.

The files that do the work:
- `boot.ps1` — the orchestrator. Param parsing, dot-sources `src/*.ps1`, then runs Phase 1 → Phase 2 → summary.
- `src/Logging.ps1` — `Write-Log`, `Start-Section`, `End-Section`.
- `src/Detection.ps1` — `Test-WindowsFeatureInstalled`, `Test-OfficeInstalled`, `Test-TeamsInstalled`, `Test-AppxPackageInstalled`, `Test-MicrosoftStoreAvailable`, `Test-WindowsActivated`, `Test-SoftwareInstalled`, `Wait-ForStoreInstallation`.
- `src/Elevation.ps1` — `Invoke-AdminCommand` (per-command UAC).
- `src/WinGet.ps1` — `Invoke-WinGetCommand`, `Show-WinGetProgress`, `Test-WinGetInstalled`, `Refresh-WinGetCatalog`, `Ensure-WinGetConfigurationEnabled`.
- `src/MDM.ps1` — `Clear-MDMFailedRegistryAttempts`.
- `rpbush.dev.dsc.yml` — WinGet DSC config listing dev apps (Git, PowerShell 7, Cursor, Windows Terminal, etc.) plus an optional Dev Drive `Disk` resource.
- `rpbush.office.dsc.yml` — WinGet DSC config for Microsoft Office + Teams (separated so Office can be skipped/installed independently).

The `src/*.ps1` files are **dot-sourced**, not modules — they share `boot.ps1`'s scope so `$script:`-scoped state (`$script:IsAdmin`, `$script:ErrorCount`, `$script:SectionTimings`, the various tracking arrays) is visible from every helper. Don't convert these to `.psm1` without first solving cross-module state sharing.

## How it's run (there are no dev commands)

End user invocation, from a **non-elevated** PowerShell prompt (see elevation note below):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null; Set-Location "C:\temp"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "C:\temp\boot.ps1"; & "C:\temp\boot.ps1"
```

When iterating locally, run `./boot.ps1` from the repo root — the script checks for `rpbush.dev.dsc.yml` / `rpbush.office.dsc.yml` next to itself first and only falls back to GitHub when not found.

To resume after a reboot manually: `./boot.ps1 -ResumeAfterReboot` (normally invoked automatically via the RunOnce key — see Phase 1).

## Architectural details that span files

### Elevation model (read this before changing anything in boot.ps1)
The script intentionally runs in **user context, not admin**. WinGet is a per-user AppX package and silently fails in elevated/SYSTEM contexts. The script warns if launched as Administrator. Admin-only operations (Windows features, HKLM registry) are elevated per-command via `Invoke-AdminCommand` (`src/Elevation.ps1`), which writes the scriptblock to a temp `.ps1` and spawns `Start-Process -Verb RunAs`. WinGet itself prompts for UAC when an installer needs it.

A consequence: when adding admin work, wrap it in `Invoke-AdminCommand { ... }`, don't add `#Requires -RunAsAdministrator`. There is also `Invoke-WinGetCommand` (`src/WinGet.ps1`) which handles the inverse case — running WinGet from a SYSTEM context by locating the logged-in user's `winget.exe` under `WindowsApps\Microsoft.DesktopAppInstaller_*`.

### Two-phase execution with reboot persistence
boot.ps1 has two phases separated by an optional reboot:

- **Phase 1** — Prerequisites that may require reboot. Currently just NFS Client (`ClientForNFS-Infrastructure` / `ServicesForNFS-ClientOnly`). If enabling it triggers a reboot, the script:
  1. Copies itself to `C:\ProgramData\WorkstationSetup\boot.ps1` (the original `C:\temp` path can be cleaned up post-reboot).
  2. Copies the `src/` directory recursively to `C:\ProgramData\WorkstationSetup\src\` — required because boot.ps1 dot-sources `src/*.ps1` at startup.
  3. Copies all `*.yml` / `*.yaml` siblings to the same safe directory (offline resume support).
  4. Writes a `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\ContinueSetup` key that re-runs the saved script with `-ResumeAfterReboot`.
  5. `Restart-Computer -Force`.
- **Phase 2** — Main installation. Runs unconditionally on the second invocation; on first invocation runs only if no reboot was needed. Removes the RunOnce key on resume.

If you add a new prereq that needs reboot, put it in Phase 1 alongside the NFS block and follow the same RunOnce + safe-copy pattern, or the resume will lose the in-progress work.

### DSC file resolution
`$dscAdmin` / `$dscOffice` always point to `$env:TEMP`. The script first tries `$dscAdminLocal` / `$dscOfficeLocal` (next to the script) and `Copy-Item`s them to TEMP. Failing that, it downloads from `$dscUri = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$RepoBranch/"` — `RepoOwner` / `RepoName` / `RepoBranch` are script parameters with defaults `rpbush` / `workstation-setup` / `main`, so a fork can override without editing the script.

DSC files are applied via `winget configuration -f <file> --accept-configuration-agreements` (not `--accept-package-agreements` — that's a different flag for the `install` verb). Configuration features must be enabled first; `Ensure-WinGetConfigurationEnabled` (`src/WinGet.ps1`) handles that and is called before any DSC apply.

### Adding/removing software
For most apps, add a `Microsoft.WinGet.DSC/WinGetPackage` resource to `rpbush.dev.dsc.yml`. The schema is `https://aka.ms/configuration-dsc-schema/0.2`. Keep the convention: `id` matches the winget package id, `directives.allowPrerelease: true`, `settings.source: winget`. Anything requiring imperative logic (registry, optional features, Store-only apps like Windows Terminal fallback) lives directly in boot.ps1 — search for `Start-Section "..."` to find the right neighbor.

### Idempotency helpers
Before installing anything imperatively, check the relevant `Test-*Installed` helper near the top of boot.ps1 (lines 346–525): `Test-WindowsFeatureInstalled`, `Test-SoftwareInstalled` (winget catalog with timeout), `Test-OfficeInstalled` (registry + Outlook.exe), `Test-TeamsInstalled`, `Test-AppxPackageInstalled`, `Test-WindowsActivated`. Use them to gate work and push to `$script:AlreadySetItems` so the final summary stays accurate.

### Logging and section tracking
Every meaningful unit of work is wrapped in `Start-Section "Name"` / `End-Section "Name"` (`src/Logging.ps1`) with `Write-Log -Level ... -Section "Name"` calls in between. Levels: `INFO | WARNING | ERROR | SUCCESS | SECTION_START | SECTION_END`. The log file path is persisted to `$env:TEMP\SetupLogPath.txt` so post-reboot resumes append to the same log. The end-of-run summary aggregates from `$script:InstalledItems`, `$script:AlreadySetItems`, `$script:SettingsApplied`, `$script:FailedItems`, `$script:SectionResults`, and `$script:SectionTimings` — push to these arrays from new sections or they won't appear in the summary.

## Historical notes
- `MAS_AIO.cmd` and `rpbush.nonAdmin.dsc.yml` are mentioned in older docs/commits but do not exist in this repo and are not referenced by `boot.ps1`. Remove any new references that re-introduce them.
- Network drive mapping (N:, S:) was removed from boot.ps1 in favor of Group Policy.
