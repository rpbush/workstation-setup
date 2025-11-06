# rpbush WinGet Configure list

This is my winget configure script to set up a new computer.  Still work in progress.  There will need to be a hybrid of Needing admin to run.  Parts have been validated on an Azure VM but needs more validation.

Most everything in the dsc.yml should work.

## Assumptions:

- New computer with Windows 11 that can boot a dev drive.
- C:\ can be shrunk by 75 gigs to create dev drive. 
- D:\ will be dev drive

## Quick Start (Run from GitHub)

Run this command in PowerShell (as Administrator) to download and execute the setup script directly:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; $scriptPath = "$env:TEMP\boot.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile $scriptPath; & $scriptPath
```

**One-liner (copy and paste):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; $scriptPath = "$env:TEMP\boot.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile $scriptPath; & $scriptPath
```

### Prerequisites

- Windows 11 (recommended) or Windows 10
- Administrator privileges
- Internet connection
- PowerShell 5.1 or later

### Important Notes

- The script will automatically download required DSC configuration files from GitHub (currently configured to download from `https://github.com/rpbush/New_Computer_Setup/blob/main/`)
- **Windows Activation**: The script references `MAS_AIO.cmd` for Windows HWID activation. If this file is not present in the repository, Windows activation will be skipped with a warning. You can download MAS_AIO separately if needed.
- The script will prompt for administrator privileges when needed
- **Network Drives**: The script maps N: (NFS:/media) and S: (\\FS-1\Storage). Modify these in `boot.ps1` if your network setup differs.

### Alternative: Download and Run Locally

If you prefer to download the script first:

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "$env:TEMP\boot.ps1"

# Run the script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
& "$env:TEMP\boot.ps1"
```

## Publishing to GitHub

To publish this project to GitHub:

1. Create a new repository on GitHub (e.g., `workstation-setup`)
2. Initialize git in the Workstation_Setup directory:
   ```powershell
   cd Workstation_Setup
   git init
   git add .
   git commit -m "Initial commit: Workstation setup script"
   ```
3. Add your GitHub repository as remote:
   ```powershell
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git branch -M main
   git push -u origin main
   ```
4. Update the README.md with your actual GitHub username and repository name in the Quick Start section

### Repository Structure

```
Workstation_Setup/
├── boot.ps1                    # Main setup script
├── readme.md                   # This file
├── LICENSE                     # License file
├── rpbush.dev.dsc.yml          # Dev environment DSC configuration
├── rpbush.nonAdmin.dsc.yml     # Non-admin DSC configuration
├── rpbush.office.dsc.yml       # Office DSC configuration
└── MAS_AIO.cmd                 # Windows activation tool (optional)
```

## Manual Setup (Legacy Method):

1. Open Windows PowerShell (as Administrator)
2. Set execution policy: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force`
3. Copy boot.ps1 to your user folder
4. Run `.\boot.ps1`
5. Reset execution policy if desired: `Set-ExecutionPolicy -ExecutionPolicy Default -Scope Process -Force`

## TO-DO list

### Windows Terminal
- Set PowerShell 7 as default

### File Explorer
- Uncheck "Include account-based insights"
- Uncheck "show frequently used folders"
- Check Display the full path in titlebar

### Power setting
- set to performance

### Snapping configurations
- no top
- no multi-app smart suggestion

### Monitors
- All monitors 100% scale

### System tray
- Everything to visible
- Remove bluetooth icon

### Start
- More Pins
- Turn off show recently added apps
- Turn off Show most used apps
- Turn off show recently opened items in start menu
- Turn off Show recommendations

### Taskbar
- Turn off Copilot

#### Pin taskbar
Unpin everything
- Edge 
- outlook
- VS
- vs code
- Dev Home

### Notifications
- Turn on do not disturb
- Turn off outlook
- turn off teams

### audio output config
This would be the config for my desktop but i would have a var for laptops for work profile i'd group set.
- Rename one to Headphone jack
- Rename one for sonos
- disable monitor 1
- disable monitor 2
- disable yeti

### Quick Access
- Unpin video
- Unpin music
- pin d:\source

### Dark Mode settings
Cannot currently do, only dark / light.  I have hybrid
- Windows mode - dark
- App mode - light

### Edge  (Maybe regkey)
- Bing discovery disabled
- Sidebar disabled

### Authentication
- Visual Studio enterprise

### Bluetooth 
I doubt this can be scripted out to connect on a new computer.  But I can dream :)
- Add mouse
- Add Keyboard


### Logitech Option+ Settings
- Mouse wheel to ratchet only.
