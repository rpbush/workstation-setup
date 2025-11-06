# GitHub Setup Instructions

This guide will help you publish the Workstation_Setup project to GitHub.

## Step 1: Create GitHub Repository

1. Go to [GitHub](https://github.com) and sign in
2. Click the "+" icon in the top right, then select "New repository"
3. Name your repository (e.g., `workstation-setup`)
4. Choose visibility (Public or Private)
5. **Do NOT** initialize with README, .gitignore, or license (we already have these)
6. Click "Create repository"

## Step 2: Initialize Git and Push

Open PowerShell in the `Workstation_Setup` directory and run:

```powershell
# Navigate to the Workstation_Setup directory
cd "E:\Development\Fresh Computer Installer\Workstation_Setup"

# Initialize git repository
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: Workstation setup script"

# Add your GitHub repository as remote (replace YOUR_USERNAME and YOUR_REPO_NAME)
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git

# Rename branch to main
git branch -M main

# Push to GitHub
git push -u origin main
```

## Step 3: Update README with Your Repository URL

After pushing, update the `readme.md` file:

1. Replace `YOUR_USERNAME` with your GitHub username
2. Replace `YOUR_REPO_NAME` with your repository name

For example, if your username is `johndoe` and repo is `workstation-setup`, the URL would be:
```
https://raw.githubusercontent.com/johndoe/workstation-setup/main/boot.ps1
```

## Step 4: Test the One-Liner

Test that the script can be downloaded and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; $scriptPath = "$env:TEMP\boot.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO_NAME/main/boot.ps1" -OutFile $scriptPath; & $scriptPath
```

## Optional: Add MAS_AIO.cmd

If you want to include Windows activation functionality:

1. Download `MAS_AIO.cmd` from the official source
2. Add it to the repository:
   ```powershell
   git add MAS_AIO.cmd
   git commit -m "Add MAS_AIO.cmd for Windows activation"
   git push
   ```

**Note:** MAS_AIO.cmd is a large file (~20MB). Consider using Git LFS if you encounter issues, or host it separately.

## Repository Files

The repository should contain:
- `boot.ps1` - Main setup script
- `readme.md` - Documentation
- `LICENSE` - License file
- `.gitignore` - Git ignore rules
- `rpbush.dev.dsc.yml` - Dev environment configuration
- `rpbush.nonAdmin.dsc.yml` - Non-admin configuration
- `rpbush.office.dsc.yml` - Office configuration
- `MAS_AIO.cmd` - (Optional) Windows activation tool

## Troubleshooting

### Authentication Issues
If you encounter authentication issues when pushing:
- Use a Personal Access Token instead of password
- Or use SSH: `git remote set-url origin git@github.com:YOUR_USERNAME/YOUR_REPO_NAME.git`

### Large File Issues
If MAS_AIO.cmd is too large:
- Use Git LFS: `git lfs install` then `git lfs track "*.cmd"`
- Or exclude it and note in README that users need to download it separately

