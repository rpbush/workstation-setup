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
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null; Set-Location "C:\temp"; $scriptPath = "C:\temp\boot.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile $scriptPath; & $scriptPath
```

**One-liner (copy and paste):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null; Set-Location "C:\temp"; $scriptPath = "C:\temp\boot.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile $scriptPath; & $scriptPath
```

### Prerequisites

- Windows 11 (recommended) or Windows 10
- Administrator privileges
- Internet connection
- PowerShell 5.1 or later

### Important Notes

- The script will automatically download required DSC configuration files from GitHub (currently configured to download from `https://github.com/rpbush/New_Computer_Setup/blob/main/`)
- **Windows Activation**: The script will automatically download `MAS_AIO.cmd` from the GitHub repository if it's not found locally. Windows activation will be skipped with a warning if the download fails.
- The script will prompt for administrator privileges when needed
- **Network Drives**: The script maps N: (NFS:/media) and S: (\\FS-1\Storage). Modify these in `boot.ps1` if your network setup differs.
- **All Required Files**: The script automatically downloads all required files from GitHub, so you only need to run the one-liner command above.

### Alternative: Download and Run Locally

If you prefer to download the script first:

```powershell
# Create temp directory and change to it
New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
Set-Location "C:\temp"

# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rpbush/workstation-setup/main/boot.ps1" -OutFile "C:\temp\boot.ps1"

# Run the script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
& "C:\temp\boot.ps1"
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
   git remote add origin https://github.com/rpbush/workstation-setup.git
   git branch -M main
   git push -u origin main
   ```

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
