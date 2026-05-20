# rpbush workstation-setup

Opinionated Windows 11 bootstrap. One PowerShell command on a fresh machine; ~30 minutes later you have a working dev workstation. Still work in progress — validated on Azure VMs and personal hardware, but treat it as "trusted-but-verify."

## Quick start

Open PowerShell as a **non-elevated user** (WinGet doesn't work elevated — the script will elevate per-command via UAC when it needs to):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null; Set-Location "C:\temp"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "C:\temp\boot.ps1"; & "C:\temp\boot.ps1"
```

### Prerequisites

- Windows 11 (Windows 10 mostly works; NFS Client and Dev Drive bits are Win11-only)
- Pro / Enterprise / Education edition (NFS Client is gated off on Home)
- PowerShell 5.1 or later
- Internet connection
- A logged-in user account (WinGet is per-user; don't run from SYSTEM)

### What it does

**Phase 1** — Installs Windows features that may need a reboot (currently just NFS Client). If a reboot fires, the script copies itself to `C:\ProgramData\WorkstationSetup\`, registers a RunOnce key, reboots, and resumes automatically.

**Phase 2** — WinGet DSC applies + imperative Windows tweaks (registry, optional features, settings).

### Software installed via DSC

Defined in [`rpbush.dev.dsc.yml`](rpbush.dev.dsc.yml) and [`rpbush.office.dsc.yml`](rpbush.office.dsc.yml). Fork and trim if you don't want these.

| Category | Packages |
|---|---|
| Dev tools | Git, GitHub CLI, PowerShell 7, Windows Terminal, Cursor, Notepad++, 7zip |
| Productivity | Microsoft Office, Microsoft Teams, Adobe Acrobat Reader, PowerToys |
| Communication | Signal |
| Gaming / media | Steam, HandBrake, balenaEtcher |
| Hardware utilities | Corsair iCUE 5, Sound Blaster Command, Garmin Express, Ubiquiti Identity Desktop, Ubiquiti WiFiman Desktop |
| Creative / VPN | Adobe Creative Cloud, PrivadoVPN |
| Storage | Dev Drive (75GB ReFS on disk 0, drive letter Z:) |

### Additional setup done by boot.ps1

- Enables WSL + Virtual Machine Platform, installs Ubuntu
- Enables Windows Sandbox and NFS Client (Pro+ only) optional features
- Sets PowerShell 7 as the default Windows Terminal profile
- Power profile → Ultimate Performance (falls back to High Performance)
- File Explorer → show hidden files / folders / drives
- System tray → always show all icons
- Outlook AutoDiscover registry hints for zero-config Exchange
- Attempts Windows HWID/digital-license activation via `slmgr`
- Upgrades WinGet to the Microsoft Store version (for auto-updates) at the end

### Important notes

- DSC configurations are fetched from `https://raw.githubusercontent.com/rpbush/workstation-setup/main/`. If the YAML files are present next to `boot.ps1`, they're used locally instead — useful for offline reruns after the post-NFS reboot.
- WinGet handles UAC elevation prompts itself; the script is designed to run non-elevated. If you launch it elevated it will warn but try to continue.
- The Microsoft Account sign-in step opens `ms-settings:emailandaccounts` and waits for a keypress — this is interactive by design (no headless API for MSA sign-in).

### Alternative: download and run locally

```powershell
New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
Set-Location "C:\temp"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "C:\temp\boot.ps1"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
& "C:\temp\boot.ps1"
```

To resume manually after a reboot: `& "C:\ProgramData\WorkstationSetup\boot.ps1" -ResumeAfterReboot`

### Running from a fork

`boot.ps1` accepts `-RepoOwner`, `-RepoName`, and `-RepoBranch` parameters; the DSC YAMLs are downloaded from `https://raw.githubusercontent.com/<owner>/<name>/<branch>/`. Defaults are `rpbush` / `workstation-setup` / `main`. After cloning your fork:

```powershell
& .\boot.ps1 -RepoOwner "your-user" -RepoName "your-fork" -RepoBranch "main"
```

If you run from a directory where the DSC YAMLs sit next to `boot.ps1`, those local copies win and no download happens.

### Other switches

- `-Unattended` — auto-reboot after NFS install, skip the interactive Microsoft Account sign-in step.
- `-ResumeAfterReboot` — set automatically by the post-reboot RunOnce hook; rarely passed by hand.

## Repository structure

```
workstation-setup/
├── boot.ps1                # Main setup script
├── rpbush.dev.dsc.yml      # WinGet DSC: dev apps + Dev Drive
├── rpbush.office.dsc.yml   # WinGet DSC: Office + Teams
├── CLAUDE.md               # Architecture notes for AI assistants
├── LICENSE
└── readme.md
```
