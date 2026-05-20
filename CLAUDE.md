# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A single-purpose Windows 11 workstation bootstrap kit, intended to be curl-piped from GitHub onto a fresh machine. There is no build, no test suite, no package manager — just a PowerShell script that orchestrates WinGet DSC configurations and registry/feature tweaks.

Three files do the work:
- `boot.ps1` — the orchestrator (~3150 lines, runs end-to-end).
- `rpbush.dev.dsc.yml` — WinGet DSC config listing dev apps (Git, PowerShell 7, Cursor, Windows Terminal, etc.) plus an optional Dev Drive `Disk` resource.
- `rpbush.office.dsc.yml` — WinGet DSC config for Microsoft Office + Teams (separated so Office can be skipped/installed independently).

## How it's run (there are no dev commands)

End user invocation, from a **non-elevated** PowerShell prompt (see elevation note below):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null; Set-Location "C:\temp"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "C:\temp\boot.ps1"; & "C:\temp\boot.ps1"
```

When iterating locally, run `./boot.ps1` from the repo root — the script checks for `rpbush.dev.dsc.yml` / `rpbush.office.dsc.yml` next to itself first and only falls back to GitHub when not found.

To resume after a reboot manually: `./boot.ps1 -ResumeAfterReboot` (normally invoked automatically via the RunOnce key — see Phase 1).

## Architectural details that span files

### Elevation model (read this before changing anything in boot.ps1)
The script intentionally runs in **user context, not admin**. WinGet is a per-user AppX package and silently fails in elevated/SYSTEM contexts. The script warns if launched as Administrator. Admin-only operations (Windows features, HKLM registry) are elevated per-command via `Invoke-AdminCommand` (boot.ps1:48), which writes the scriptblock to a temp `.ps1` and spawns `Start-Process -Verb RunAs`. WinGet itself prompts for UAC when an installer needs it.

A consequence: when adding admin work, wrap it in `Invoke-AdminCommand { ... }`, don't add `#Requires -RunAsAdministrator`. There is also `Invoke-WinGetCommand` (boot.ps1:620) which handles the inverse case — running WinGet from a SYSTEM context by locating the logged-in user's `winget.exe` under `WindowsApps\Microsoft.DesktopAppInstaller_*`.

### Two-phase execution with reboot persistence
boot.ps1 has two phases separated by an optional reboot:

- **Phase 1 (boot.ps1:1395+)** — Prerequisites that may require reboot. Currently just NFS Client (`ClientForNFS-Infrastructure` / `ServicesForNFS-ClientOnly`). If enabling it triggers a reboot, the script:
  1. Copies itself to `C:\ProgramData\WorkstationSetup\boot.ps1` (the original `C:\temp` path can be cleaned up post-reboot).
  2. Copies all `*.yml` / `*.yaml` siblings to the same safe directory (offline resume support).
  3. Writes a `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\ContinueSetup` key that re-runs the saved script with `-ResumeAfterReboot`.
  4. `Restart-Computer -Force`.
- **Phase 2 (boot.ps1:1541+)** — Main installation. Runs unconditionally on the second invocation; on first invocation runs only if no reboot was needed. Removes the RunOnce key on resume.

If you add a new prereq that needs reboot, put it in Phase 1 alongside the NFS block and follow the same RunOnce + safe-copy pattern, or the resume will lose the in-progress work.

### DSC file resolution
`$dscAdmin` / `$dscOffice` always point to `$env:TEMP`. The script first tries `$dscAdminLocal` / `$dscOfficeLocal` (next to the script) and `Copy-Item`s them to TEMP. Failing that, it downloads from `$dscUri = "https://raw.githubusercontent.com/rpbush/workstation-setup/main/"` (boot.ps1:1389). **This URL is hard-coded — fork-friendly only if you also edit `$dscUri`.**

DSC files are applied via `winget configuration -f <file> --accept-configuration-agreements` (not `--accept-package-agreements` — that's a different flag for the `install` verb). Configuration features must be enabled first; `Ensure-WinGetConfigurationEnabled` (boot.ps1:857) handles that and is called before any DSC apply.

### Adding/removing software
For most apps, add a `Microsoft.WinGet.DSC/WinGetPackage` resource to `rpbush.dev.dsc.yml`. The schema is `https://aka.ms/configuration-dsc-schema/0.2`. Keep the convention: `id` matches the winget package id, `directives.allowPrerelease: true`, `settings.source: winget`. Anything requiring imperative logic (registry, optional features, Store-only apps like Windows Terminal fallback) lives directly in boot.ps1 — search for `Start-Section "..."` to find the right neighbor.

### Idempotency helpers
Before installing anything imperatively, check the relevant `Test-*Installed` helper near the top of boot.ps1 (lines 346–525): `Test-WindowsFeatureInstalled`, `Test-SoftwareInstalled` (winget catalog with timeout), `Test-OfficeInstalled` (registry + Outlook.exe), `Test-TeamsInstalled`, `Test-AppxPackageInstalled`, `Test-WindowsActivated`. Use them to gate work and push to `$script:AlreadySetItems` so the final summary stays accurate.

### Logging and section tracking
Every meaningful unit of work is wrapped in `Start-Section "Name"` / `End-Section "Name"` (boot.ps1:598) with `Write-Log -Level ... -Section "Name"` calls in between. Levels: `INFO | WARNING | ERROR | SUCCESS | SECTION_START | SECTION_END`. The log file path is persisted to `$env:TEMP\SetupLogPath.txt` so post-reboot resumes append to the same log. The end-of-run summary (boot.ps1:2996+) aggregates from `$script:InstalledItems`, `$script:AlreadySetItems`, `$script:SettingsApplied`, `$script:FailedItems`, `$script:SectionResults`, and `$script:SectionTimings` — push to these arrays from new sections or they won't appear in the summary.

## Things the README mentions that don't exist in-repo
- `MAS_AIO.cmd` (Windows activation) is referenced by the README and downloaded at runtime if missing — not committed here.
- `rpbush.nonAdmin.dsc.yml` is mentioned in the README's "Repository Structure" but does not exist; the relevant Phase 1 block (boot.ps1:1415) explicitly notes its removal.
- Network drive mapping (N:, S:) described in the README has been removed from boot.ps1 in favor of Group Policy (see boot.ps1:2004).
