$mypath = $MyInvocation.MyCommand.Path
Write-Output "Path of the script: $mypath"
Write-Output "Args for script: $Args"

# turning off progress bar to make invoke WebRequest fast
$ProgressPreference = 'SilentlyContinue'

# Suppress all confirmation prompts for the entire script
$ConfirmPreference = 'None'
$ErrorActionPreference = 'Continue'

# Bootstrap WinGet using PowerShell module (works in Windows Sandbox and other environments)
# Method from official WinGet documentation: https://learn.microsoft.com/en-us/windows/package-manager/
Write-Host "Installing WinGet PowerShell module from PSGallery..."

# Install NuGet package provider (method from WinGet documentation)
Install-PackageProvider -Name NuGet -Force | Out-Null

# Install Microsoft.WinGet.Client module (method from WinGet documentation)
Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null

Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."

# Bootstrap WinGet using the PowerShell module (method from WinGet documentation)
try {
    Repair-WinGetPackageManager -AllUsers -ErrorAction Stop
    Write-Host "WinGet bootstrapped successfully via PowerShell module"
} catch {
    Write-Warning "Repair-WinGetPackageManager failed: $_"
    Write-Host "Will continue with manual WinGet installation..."
}

Write-Host "Done bootstrapping WinGet."

# Check if WinGet is installed and get version
# According to Microsoft documentation: https://learn.microsoft.com/en-us/windows/package-manager/
# WinGet is included in Windows 10 version 1809+ and Windows 11 as part of App Installer
$wingetInstalled = $false
$isWinGetRecent = $null

# Function to check if WinGet is available and get version
function Test-WinGetInstalled {
    try {
        # Use --info for better compatibility (recommended by Microsoft docs)
        $wingetInfo = winget --info 2>$null
        if ($wingetInfo) {
            # Extract version from --info output or use -v
            $wingetVersion = winget -v 2>$null
            if ($wingetVersion) {
                return @{
                    Installed = $true
                    Version = $wingetVersion
                    VersionArray = $wingetVersion.Trim('v').TrimEnd("-preview").split('.')
                }
            }
        }
    } catch {
        # WinGet not available
    }
    
    # Also check if App Installer package is installed (which includes WinGet)
    $appInstaller = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue
    if ($appInstaller) {
        return @{
            Installed = $true
            Version = $null
            VersionArray = $null
            AppInstallerInstalled = $true
        }
    }
    
    return @{
        Installed = $false
        Version = $null
        VersionArray = $null
    }
}

$wingetStatus = Test-WinGetInstalled
$wingetInstalled = $wingetStatus.Installed
$isWinGetRecent = $wingetStatus.VersionArray

# forcing WinGet to be installed if not present or version is too old
if (-not $wingetInstalled -or $null -eq $isWinGetRecent -or !(($isWinGetRecent[0] -gt 1) -or ($isWinGetRecent[0] -ge 1 -and $isWinGetRecent[1] -ge 6))) # WinGet is greater than v1 or v1.6 or higher
{
   Write-Host "Downloading WinGet and its dependencies..."
   
   # Function to check if a package is already installed
   function Test-AppxPackageInstalled {
       param([string]$PackageName)
       $installed = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
       return ($null -ne $installed)
   }
   
   # Function to validate downloaded file
   function Test-FileValid {
       param([string]$FilePath, [long]$MinSizeBytes = 1000)
       if (-not (Test-Path $FilePath)) {
           return $false
       }
       $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
       if ($null -eq $fileInfo) {
           return $false
       }
       # Check if file size is reasonable (at least MinSizeBytes)
       if ($fileInfo.Length -lt $MinSizeBytes) {
           Write-Warning "File $FilePath appears to be too small ($($fileInfo.Length) bytes), may be corrupted"
           return $false
       }
       return $true
   }
   
   # Check if Windows App Runtime is already installed
   $appRuntimeInstalled = Test-AppxPackageInstalled -PackageName "Microsoft.WindowsAppRuntime"
   
   if (-not $appRuntimeInstalled) {
       Write-Host "Windows App Runtime not found, attempting to install..."
       
       # Try Microsoft Store first (if available)
       $storeAvailable = $true
       try {
           $storeTest = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction SilentlyContinue
           if (-not $storeTest) {
               $storeAvailable = $false
               Write-Host "Microsoft Store not available (e.g., Windows Sandbox). Will install WinGet first, then use winget to install Windows App Runtime."
           }
       } catch {
           $storeAvailable = $false
       }
       
       if ($storeAvailable) {
           # Try Microsoft Store method
           try {
               Write-Host "Opening Microsoft Store for Windows App Runtime..."
               Start-Process "ms-windows-store://pdp/?ProductId=9P7KNL5RWT25" -ErrorAction Stop
               Write-Host "Microsoft Store opened. Please click 'Get' or 'Install' if prompted."
               Write-Host "Waiting for installation to complete..."
               Start-Sleep -Seconds 10
               
               # Check if it got installed
               $appRuntimeInstalled = Test-AppxPackageInstalled -PackageName "Microsoft.WindowsAppRuntime"
               if ($appRuntimeInstalled) {
                   Write-Host "Windows App Runtime installed via Microsoft Store"
               }
           } catch {
               Write-Warning "Could not open Microsoft Store for Windows App Runtime: $_"
               $storeAvailable = $false
           }
       }
       
       # If Store method didn't work or isn't available, skip direct download entirely
       # Direct download of Windows App Runtime is unreliable - we'll install WinGet first, then use winget to install the runtime
       if (-not $appRuntimeInstalled) {
           Write-Host "Windows App Runtime not installed."
           Write-Host "Will attempt to install WinGet first, then use winget to install Windows App Runtime."
           Write-Host "This approach works better in environments like Windows Sandbox where Store is unavailable."
       }
   } else {
       Write-Host "Windows App Runtime already installed"
   }
   
   # Download other dependencies
   $paths = @()
   $uris = @()
   $fileNames = @()
   
   # VCLibs
   if (-not (Test-AppxPackageInstalled -PackageName "Microsoft.VCLibs.140.00")) {
       $paths += "Microsoft.VCLibs.x64.14.00.Desktop.appx"
       $uris += "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
       $fileNames += "VCLibs"
   } else {
       Write-Host "VCLibs already installed"
   }
   
   # UI.Xaml
   if (-not (Test-AppxPackageInstalled -PackageName "Microsoft.UI.Xaml.2.8")) {
       $paths += "Microsoft.UI.Xaml.2.8.x64.appx"
       $uris += "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
       $fileNames += "UI.Xaml"
   } else {
       Write-Host "UI.Xaml already installed"
   }
   
   # WinGet bundle
   $wingetBundlePath = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
   $paths += $wingetBundlePath
   $uris += "https://aka.ms/getwinget"
   $fileNames += "WinGet"
   
   # Download dependencies
   for ($i = 0; $i -lt $uris.Length; $i++) {
       $filePath = $paths[$i]
       $fileUri = $uris[$i]
       $fileName = $fileNames[$i]
       Write-Host "Downloading: $fileName from $fileUri"
       try {
           if (Test-Path $filePath) {
               Remove-Item $filePath -Force -ErrorAction SilentlyContinue
           }
           Invoke-WebRequest -Uri $fileUri -OutFile $filePath -ErrorAction Stop
           
           # Validate downloaded file
           $minSize = if ($fileName -eq "WinGet") { 10000000 } else { 1000000 }
           if (-not (Test-FileValid -FilePath $filePath -MinSizeBytes $minSize)) {
               Write-Warning "$fileName download appears invalid, will retry or skip"
               Remove-Item $filePath -Force -ErrorAction SilentlyContinue
               $paths[$i] = $null
           }
       } catch {
           Write-Warning "Failed to download $fileName : $_"
           if (Test-Path $filePath) {
               Remove-Item $filePath -Force -ErrorAction SilentlyContinue
           }
           $paths[$i] = $null
       }
   }
   
   Write-Host "Installing WinGet and its dependencies..."
   
   # Note: Windows App Runtime will be installed via winget after WinGet is installed
   # This approach is more reliable than direct download
   
   # Install VCLibs and UI.Xaml (skip WinGet bundle for now)
   for ($i = 0; $i -lt ($paths.Count - 1); $i++) {
       if ($null -ne $paths[$i] -and (Test-Path $paths[$i])) {
           Write-Host "Installing: $($fileNames[$i])"
           try {
               Add-AppxPackage $paths[$i] -ErrorAction Stop
               Write-Host "$($fileNames[$i]) installed successfully"
           } catch {
               Write-Warning "$($fileNames[$i]) installation failed: $_"
           }
       }
   }
   
   # Install DesktopAppInstaller (WinGet) - this should work now with dependencies installed
   $wingetInstalledSuccessfully = $false
   $wingetBundleIndex = $paths.Count - 1
   if ($null -ne $paths[$wingetBundleIndex] -and (Test-Path $paths[$wingetBundleIndex])) {
       Write-Host "Installing: Microsoft.DesktopAppInstaller (WinGet)"
       try {
           Add-AppxPackage $paths[$wingetBundleIndex] -ErrorAction Stop
           Write-Host "WinGet installed successfully"
           $wingetInstalledSuccessfully = $true
       } catch {
           Write-Warning "WinGet installation failed: $_"
       }
   }
   
   # If WinGet installation failed, try Microsoft Store method (if available)
   # According to Microsoft docs, WinGet is distributed via Microsoft Store for security
   if (-not $wingetInstalledSuccessfully) {
       # Check if Microsoft Store is available
       $storeAvailable = $true
       try {
           $storeTest = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction SilentlyContinue
           if (-not $storeTest) {
               $storeAvailable = $false
           }
       } catch {
           $storeAvailable = $false
       }
       
       if ($storeAvailable) {
           Write-Host "Attempting to install WinGet via Microsoft Store (recommended method)..."
           Write-Host "WinGet is distributed via Microsoft Store for secure installation with certificate pinning."
           try {
               # Use the official Microsoft Store link for App Installer (which includes WinGet)
               Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1" -ErrorAction Stop
               Write-Host "Opened Microsoft Store for App Installer (WinGet)."
               Write-Host "Please click 'Get' or 'Install' in the Microsoft Store window that opened."
               Write-Host "Waiting for installation to complete..."
               # Wait longer for Store installation - user may need to interact
               Start-Sleep -Seconds 15
               
               # Check if App Installer was installed
               $appInstallerCheck = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue
               if ($appInstallerCheck) {
                   Write-Host "App Installer (WinGet) detected after Store installation"
                   $wingetInstalledSuccessfully = $true
               }
           } catch {
               Write-Warning "Could not open Microsoft Store for WinGet: $_"
               Write-Host "You can manually install WinGet from: https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
           }
       } else {
           Write-Host "Microsoft Store not available (e.g., Windows Sandbox). WinGet installation may require manual intervention."
           Write-Host "You can download WinGet manually from: https://github.com/microsoft/winget-cli/releases"
       }
   }
   
   # If WinGet is now installed but Windows App Runtime is still missing, try installing it via winget
   if ($wingetInstalledSuccessfully -and -not $appRuntimeInstalled) {
       Write-Host "WinGet is installed. Attempting to install Windows App Runtime via winget..."
       try {
           winget install --id Microsoft.WindowsAppRuntime -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
           if ($LASTEXITCODE -eq 0) {
               Start-Sleep -Seconds 3
               $appRuntimeInstalled = Test-AppxPackageInstalled -PackageName "Microsoft.WindowsAppRuntime"
               if ($appRuntimeInstalled) {
                   Write-Host "Windows App Runtime installed successfully via winget"
               }
           }
       } catch {
           Write-Warning "Failed to install Windows App Runtime via winget: $_"
       }
   }
   
   Write-Host "Verifying WinGet installation..."
   # Refresh environment to pick up winget
   $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
   
   # Wait a bit more for installation to complete
   Start-Sleep -Seconds 3
   
   # Verify using --info (recommended by Microsoft documentation)
   # Reference: https://learn.microsoft.com/en-us/windows/package-manager/
   $wingetFinalCheck = $false
   try {
       $wingetInfo = winget --info 2>$null
       if ($wingetInfo) {
           $wingetVersion = winget -v 2>$null
           if ($wingetVersion) {
               Write-Host "WinGet installed successfully. Version: $wingetVersion"
               $wingetFinalCheck = $true
           } else {
               Write-Host "WinGet is available (verified with --info)"
               $wingetFinalCheck = $true
           }
       } else {
           Write-Warning "WinGet may not be available yet. You may need to restart PowerShell or wait a moment."
           Write-Host "If WinGet is still not available, please install it manually from the Microsoft Store:"
           Write-Host "https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
       }
   } catch {
       Write-Warning "WinGet verification failed. You may need to restart PowerShell or install WinGet from Microsoft Store."
       Write-Host "Microsoft Store link: https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
   }
   
   # Final verification - if WinGet is still not available, stop the script
   if (-not $wingetFinalCheck) {
       # Wait a bit more and do one final check
       Start-Sleep -Seconds 5
       $finalWingetCheck = Test-WinGetInstalled
       if (-not $finalWingetCheck.Installed) {
           Write-Host ""
           Write-Host "================================================" -ForegroundColor Red
           Write-Host "ERROR: WinGet could not be installed or verified." -ForegroundColor Red
           Write-Host "================================================" -ForegroundColor Red
           Write-Host ""
           Write-Host "The script cannot continue without WinGet, as it is required for installing applications."
           Write-Host ""
           Write-Host "Please try one of the following:"
           Write-Host "1. Install WinGet manually from: https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
           Write-Host "2. Download WinGet from: https://github.com/microsoft/winget-cli/releases"
           Write-Host "3. Restart PowerShell and run this script again"
           Write-Host "4. Ensure Windows App Runtime is installed first, then retry"
           Write-Host ""
           Write-Host "Exiting script..." -ForegroundColor Yellow
           exit 1
       } else {
           Write-Host "WinGet verified successfully after additional wait time"
       }
   }
   
   Write-Host "Cleaning up"
   $allFiles = @($paths)
   if (Test-Path ".\AppRuntime") {
       $allFiles += ".\AppRuntime"
   }
   foreach($filePath in $allFiles)
   {
      if ($null -ne $filePath -and (Test-Path $filePath)) 
      {
         Write-Host "Deleting: ($filePath)"
         Remove-Item $filePath -Recurse -Force -ErrorAction SilentlyContinue
      }
   }
}
else {
   Write-Host "WinGet in decent state, moving to executing DSC"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$dscUri = "https://github.com/rpbush/New_Computer_Setup/blob/main/"
$dscNonAdmin = "rpbush.nonAdmin.dsc.yml";
$dscAdmin = "rpbush.dev.dsc.yml";
$dscOffice = "rpbush.office.dsc.yml";
$dscPowerToysEnterprise = "Z:\source\powertoys\.configurations\configuration.vsEnterprise.dsc.yaml";

$dscOfficeUri = $dscUri + $dscOffice;
$dscNonAdminUri = $dscUri + $dscNonAdmin 
$dscAdminUri = $dscUri + $dscAdmin

# amazing, we can now run WinGet get fun stuff
if (!$isAdmin) {
   # Shoulder tap terminal to it gets registered moving foward
   Start-Process shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App

   Invoke-WebRequest -Uri $dscNonAdminUri -OutFile $dscNonAdmin 
   # Use --accept-package-agreements and --accept-source-agreements as per Microsoft best practices
   winget configuration -f $dscNonAdmin --accept-package-agreements --accept-source-agreements 
   
   # clean up, Clean up, everyone wants to clean up
   Remove-Item $dscNonAdmin -verbose

   # restarting for Admin now
	Start-Process PowerShell -wait -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$mypath' $Args;`"";
	exit;
}
else {
   # admin section now
   # ---------------
    # ---------------
    # Setting power profile to Performance/Ultimate Performance
    Write-Host "Start: Setting power profile to Performance"
    # Try Ultimate Performance first (highest), then High Performance
    $ultimatePerfGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    
    # Check if Ultimate Performance exists
    $powerSchemes = powercfg /list
    if ($powerSchemes -match $ultimatePerfGuid) {
        powercfg /setactive $ultimatePerfGuid
        Write-Host "Power profile set to Ultimate Performance"
    } elseif ($powerSchemes -match $highPerfGuid) {
        powercfg /setactive $highPerfGuid
        Write-Host "Power profile set to High Performance"
    } else {
        Write-Warning "Performance power profile not found"
    }
    Write-Host "Done: Setting power profile to Performance"
    # ---------------
    # Setting system tray to show all icons
    Write-Host "Start: Setting system tray to show all icons"
    try {
        # Clear the hidden icons list in the system tray
        $trayNotifyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
        if (Test-Path $trayNotifyPath) {
            # Remove the IconStreams and PastIconsStream values which contain hidden icon data
            Remove-ItemProperty -Path $trayNotifyPath -Name "IconStreams" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $trayNotifyPath -Name "PastIconsStream" -ErrorAction SilentlyContinue
            Write-Host "Cleared system tray hidden icons list"
        }
        
        # Set registry to always show all icons (Windows 10/11)
        $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        if (-not (Test-Path $explorerPath)) {
            New-Item -Path $explorerPath -Force | Out-Null
        }
        
        # Enable "Always show all icons in the notification area" setting
        # This is controlled by the EnableAutoTray DWORD value (0 = show all, 1 = hide some)
        Set-ItemProperty -Path $explorerPath -Name "EnableAutoTray" -Value 0 -Type DWORD -Force
        Write-Host "System tray configured to show all icons"
        
        # Restart Explorer to apply changes (optional, but ensures immediate effect)
        # Get-Process explorer | Stop-Process -Force
        # Start-Sleep -Seconds 2
        # Start-Process explorer.exe
        
    } catch {
        Write-Warning "Failed to configure system tray: $_"
    }
    Write-Host "Done: Setting system tray to show all icons"
    # ---------------
    # Mapping network drives
    Write-Host "Start: Mapping network drives"
    try {
        # Install NFS Client feature if not already installed (required for NFS drive mapping)
        Write-Host "Checking for NFS Client feature..."
        # Try different feature names depending on Windows version
        $nfsFeatureNames = @("ClientForNFS-Infrastructure", "ServicesForNFS-ClientOnly")
        $nfsInstalled = $false
        
        foreach ($featureName in $nfsFeatureNames) {
            $nfsFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
            if ($nfsFeature) {
                if ($nfsFeature.State -ne "Enabled") {
                    Write-Host "Installing NFS Client feature ($featureName) - this may take a few minutes..."
                    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart | Out-Null
                    Write-Host "NFS Client feature installed"
                    $nfsInstalled = $true
                    break
                } else {
                    Write-Host "NFS Client feature already installed"
                    $nfsInstalled = $true
                    break
                }
            }
        }
        
        if (-not $nfsInstalled) {
            Write-Warning "Could not find or install NFS Client feature. NFS drive mapping may fail."
        }
        
        # Install Windows Sandbox feature
        Write-Host "Checking for Windows Sandbox feature..."
        $sandboxFeatureName = "Containers-DisposableClientVM"
        $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName $sandboxFeatureName -ErrorAction SilentlyContinue
        if ($sandboxFeature) {
            if ($sandboxFeature.State -ne "Enabled") {
                Write-Host "Installing Windows Sandbox feature - this may take a few minutes..."
                Enable-WindowsOptionalFeature -Online -FeatureName $sandboxFeatureName -All -NoRestart | Out-Null
                Write-Host "Windows Sandbox feature installed"
            } else {
                Write-Host "Windows Sandbox feature already installed"
            }
        } else {
            Write-Warning "Could not find Windows Sandbox feature. It may not be available on this Windows edition."
        }
        
        # Map N: drive to NFS:/media (NFS Network)
        $nDrive = "N:"
        $nPath = "NFS:/media"
        Write-Host "Mapping $nDrive to $nPath"
        # Remove existing mapping if it exists
        net use $nDrive /delete /yes 2>$null
        # Create persistent mapping
        net use $nDrive $nPath /persistent:yes | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully mapped $nDrive to $nPath"
        } else {
            Write-Warning "Failed to map $nDrive to $nPath (may not be available yet)"
        }
        
        # Map S: drive to \\FS-1\Storage (Windows Network)
        $sDrive = "S:"
        $sPath = "\\FS-1\Storage"
        Write-Host "Mapping $sDrive to $sPath"
        # Remove existing mapping if it exists
        net use $sDrive /delete /yes 2>$null
        # Create persistent mapping
        net use $sDrive $sPath /persistent:yes | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully mapped $sDrive to $sPath"
        } else {
            Write-Warning "Failed to map $sDrive to $sPath (may not be available yet)"
        }
    } catch {
        Write-Warning "Failed to map network drives: $_"
    }
    Write-Host "Done: Mapping network drives"
    # ---------------
    # Installing Windows Subsystem for Linux (WSL)
    # Reference: https://learn.microsoft.com/en-us/windows/wsl/
    Write-Host "Start: Installing Windows Subsystem for Linux (WSL)"
    try {
        # Check if WSL is already installed
        $wslInstalled = $false
        try {
            $wslStatus = wsl --status 2>$null
            if ($wslStatus) {
                $wslInstalled = $true
                Write-Host "WSL is already installed"
                # Check if WSL 2 is set as default
                $wslVersion = wsl --status 2>$null | Select-String "Default Version"
                if ($wslVersion -notmatch "2") {
                    Write-Host "Setting WSL 2 as default version..."
                    wsl --set-default-version 2 2>$null
                    Write-Host "WSL 2 set as default version"
                } else {
                    Write-Host "WSL 2 is already the default version"
                }
            }
        } catch {
            # WSL not installed or not available
        }
        
        if (-not $wslInstalled) {
            Write-Host "Installing WSL using the recommended method (wsl --install)..."
            Write-Host "This will install WSL with the default Linux distribution (Ubuntu)"
            Write-Host "Reference: https://learn.microsoft.com/en-us/windows/wsl/install"
            
            # Use the modern wsl --install command (recommended by Microsoft)
            # This automatically enables required features and installs WSL 2
            try {
                $wslInstallOutput = wsl --install 2>&1
                
                # Check if installation was successful or if it requires a reboot
                if ($LASTEXITCODE -eq 0 -or $wslInstallOutput -match "restart" -or $wslInstallOutput -match "reboot") {
                    Write-Host "WSL installation initiated successfully"
                    Write-Host "Note: A system restart may be required to complete WSL installation"
                } else {
                    # If wsl --install fails, try manual installation
                    Write-Host "wsl --install did not complete automatically, trying manual installation..."
                    
                    # Enable WSL feature
                    Write-Host "Enabling Windows Subsystem for Linux feature..."
                    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue
                    if ($wslFeature) {
                        if ($wslFeature.State -ne "Enabled") {
                            Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -All -NoRestart | Out-Null
                            Write-Host "Windows Subsystem for Linux feature enabled"
                        } else {
                            Write-Host "Windows Subsystem for Linux feature already enabled"
                        }
                    }
                    
                    # Enable Virtual Machine Platform feature (required for WSL 2)
                    Write-Host "Enabling Virtual Machine Platform feature (required for WSL 2)..."
                    $vmPlatformFeature = Get-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -ErrorAction SilentlyContinue
                    if ($vmPlatformFeature) {
                        if ($vmPlatformFeature.State -ne "Enabled") {
                            Enable-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -All -NoRestart | Out-Null
                            Write-Host "Virtual Machine Platform feature enabled"
                        } else {
                            Write-Host "Virtual Machine Platform feature already enabled"
                        }
                    }
                    
                    # Set WSL 2 as default version
                    Write-Host "Setting WSL 2 as default version..."
                    wsl --set-default-version 2 2>$null
                    
                    # Install Ubuntu (default distribution)
                    Write-Host "Installing Ubuntu Linux distribution..."
                    wsl --install -d Ubuntu 2>$null
                    
                    Write-Host "WSL installation completed. A system restart may be required."
                }
            } catch {
                Write-Warning "WSL installation encountered an error: $_"
                Write-Host "You may need to install WSL manually. See: https://learn.microsoft.com/en-us/windows/wsl/install"
            }
        }
        
        # List installed distributions
        Write-Host "Checking installed WSL distributions..."
        try {
            $wslList = wsl --list --verbose 2>$null
            if ($wslList) {
                Write-Host "Installed WSL distributions:"
                $wslList | ForEach-Object { Write-Host "  $_" }
            }
        } catch {
            Write-Host "No WSL distributions found or WSL not yet available"
        }
        
    } catch {
        Write-Warning "Failed to install WSL: $_"
        Write-Host "You can install WSL manually using: wsl --install"
        Write-Host "Documentation: https://learn.microsoft.com/en-us/windows/wsl/install"
    }
    Write-Host "Done: Installing Windows Subsystem for Linux (WSL)"
    # ---------------
    # Installing Windows Terminal
    # Reference: https://learn.microsoft.com/en-us/windows/terminal/
    Write-Host "Start: Installing Windows Terminal"
    try {
        # Check if Windows Terminal is already installed
        $wtInstalled = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
        if ($wtInstalled) {
            Write-Host "Windows Terminal is already installed (Version: $($wtInstalled.Version))"
        } else {
            Write-Host "Installing Windows Terminal using WinGet..."
            Write-Host "Reference: https://learn.microsoft.com/en-us/windows/terminal/install"
            
            # Install Windows Terminal using winget (recommended by Microsoft)
            # Use -e for exact match and --accept-package-agreements for automation
            try {
                winget install --id Microsoft.WindowsTerminal -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Windows Terminal installed successfully"
                } else {
                    Write-Warning "WinGet installation may have failed. Trying alternative method..."
                    # Fallback: Try installing via Microsoft Store
                    try {
                        Start-Process "ms-windows-store://pdp/?ProductId=9N0DX20HK701" -ErrorAction Stop
                        Write-Host "Opened Microsoft Store for Windows Terminal. Please install it if prompted."
                        Start-Sleep -Seconds 5
                        
                        # Check if it got installed
                        $wtCheck = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
                        if ($wtCheck) {
                            Write-Host "Windows Terminal installed via Microsoft Store"
                        }
                    } catch {
                        Write-Warning "Could not open Microsoft Store for Windows Terminal: $_"
                    }
                }
            } catch {
                Write-Warning "Failed to install Windows Terminal via WinGet: $_"
                Write-Host "You can install Windows Terminal manually from: https://www.microsoft.com/store/productId/9N0DX20HK701"
            }
        }
        
        # Verify installation
        $wtFinalCheck = Get-AppxPackage -Name "Microsoft.WindowsTerminal" -ErrorAction SilentlyContinue
        if ($wtFinalCheck) {
            Write-Host "Windows Terminal is available and ready to use"
        } else {
            Write-Warning "Windows Terminal installation could not be verified"
        }
        
    } catch {
        Write-Warning "Failed to install Windows Terminal: $_"
        Write-Host "You can install Windows Terminal manually using: winget install --id Microsoft.WindowsTerminal -e"
        Write-Host "Or from Microsoft Store: https://www.microsoft.com/store/productId/9N0DX20HK701"
    }
    Write-Host "Done: Installing Windows Terminal"
    # ---------------
    # Activating Windows with HWID
    Write-Host "Start: Windows HWID Activation"
    $scriptDir = Split-Path $mypath -Parent
    $masAioPath = Join-Path $scriptDir "MAS_AIO.cmd"
    
    # If MAS_AIO.cmd not found locally, try downloading from GitHub
    if (-not (Test-Path $masAioPath)) {
        Write-Host "MAS_AIO.cmd not found locally, attempting to download from GitHub..."
        try {
            $masAioUrl = "https://raw.githubusercontent.com/rpbush/workstation-setup/main/MAS_AIO.cmd"
            Invoke-WebRequest -Uri $masAioUrl -OutFile $masAioPath -ErrorAction Stop
            Write-Host "Successfully downloaded MAS_AIO.cmd from GitHub"
        } catch {
            Write-Warning "Failed to download MAS_AIO.cmd from GitHub: $_"
            Write-Warning "Windows activation will be skipped. You can download MAS_AIO.cmd manually if needed."
        }
    }
    
    if (Test-Path $masAioPath) {
        & cmd.exe /c "`"$masAioPath`" /HWID"
        Write-Host "Done: Windows HWID Activation"
    } else {
        Write-Warning "MAS_AIO.cmd not available. Windows activation skipped."
    }
    # ---------------
    # Installing office workload
    Write-Host "Start: Office install"
    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\' -Name 'DefaultProfile' -Value "OutlookAuto" -PropertyType String -Force

    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\OutlookAuto' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\OutlookAuto' -Name 'Default' -Value "" -PropertyType String -Force


    New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover' -Name 'ZeroConfigExchange' -Value "1" -PropertyType DWORD -Force

    gpupdate /force

    Invoke-WebRequest -Uri $dscOfficeUri -OutFile $dscOffice 
    # Use --accept-package-agreements and --accept-source-agreements as per Microsoft best practices
    winget configuration -f $dscOffice --accept-package-agreements --accept-source-agreements 
    Remove-Item $dscOffice -verbose
    Start-Process outlook.exe
    Start-Process ms-teams.exe
    Write-Host "Done: Office install"
    # Ending office workload
    # ---------------
   # Forcing Windows Update -- goal is move to dsc
   Write-Host "Start: Windows Update"
    $UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Installer = New-Object -ComObject Microsoft.Update.Installer
 
    $Searcher.ServerSelection = 2
 
    $Result = $Searcher.Search("IsInstalled=0 and IsHidden=0")
 
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $Result.Updates
    $Downloader.Download()
 
    $Installer.Updates = $Result.Updates
    $Installer.Install()
    Write-Host "Done: Windows Update"
    # Forcing Windows Update complete 

    # Staring dev workload
    Write-Host "Start: Dev flows install"
    
    # Check if a second physical drive already exists (skip dev drive creation if it does)
    $physicalDrives = Get-PhysicalDisk | Where-Object { $_.OperationalStatus -eq 'OK' -and $_.MediaType -ne 'Unspecified' } | Sort-Object DeviceID
    $secondDriveExists = $physicalDrives.Count -gt 1
    
    if ($secondDriveExists) {
        Write-Host "Second physical drive detected ($($physicalDrives.Count) drives found). Skipping Dev Drive creation from C: drive."
        Write-Host "Downloading DSC configuration..."
        Invoke-WebRequest -Uri $dscAdminUri -OutFile $dscAdmin
        
        # Remove Dev Drive resource from DSC file if it exists
        $dscLines = Get-Content $dscAdmin
        $newDscContent = @()
        $skipDevDrive = $false
        $devDriveIndent = 0
        
        for ($i = 0; $i -lt $dscLines.Count; $i++) {
            $line = $dscLines[$i]
            
            # Detect start of Dev Drive resource (look for "id: DevDrive1")
            if ($line -match '^\s+id:\s+DevDrive1') {
                $skipDevDrive = $true
                if ($line -match '^(\s+)') {
                    $devDriveIndent = $matches[1].Length
                } else {
                    $devDriveIndent = 0
                }
                # Skip this line and find the start of the resource block (go back to find "resource: Disk")
                for ($j = $i - 1; $j -ge 0; $j--) {
                    if ($dscLines[$j] -match '^\s+-\s+resource:\s+Disk') {
                        # Remove from the resource start
                        $i = $j - 1
                        break
                    }
                }
                continue
            }
            
            # If we're skipping, check if we've reached the end of this resource block
            if ($skipDevDrive) {
                $currentIndent = if ($line -match '^(\s*)') { $matches[1].Length } else { 0 }
                # Check if we've reached a new resource or back to the same indent level as resources list
                if ($line.Trim() -eq '' -or ($currentIndent -le $devDriveIndent -and ($line -match '^\s+-\s+resource:' -or $line -match '^\s+[a-zA-Z]'))) {
                    $skipDevDrive = $false
                    # Add the line if it's not empty or it's a new resource
                    if ($line.Trim() -ne '') {
                        $newDscContent += $line
                    }
                }
                continue
            }
            
            # Add line if we're not skipping
            $newDscContent += $line
        }
        
        if ($newDscContent.Count -lt $dscLines.Count) {
            Write-Host "Removing Dev Drive resource from DSC configuration..."
            Set-Content -Path $dscAdmin -Value ($newDscContent -join "`r`n")
            Write-Host "Dev Drive resource removed from configuration"
        } else {
            Write-Host "Dev Drive resource not found in DSC file (may have already been removed)"
        }
    } else {
        Write-Host "No second physical drive detected ($($physicalDrives.Count) drive(s) found). Dev Drive will be created from C: drive."
        Invoke-WebRequest -Uri $dscAdminUri -OutFile $dscAdmin
    }
    
    # Use --accept-package-agreements and --accept-source-agreements as per Microsoft best practices
    winget configuration -f $dscAdmin --accept-package-agreements --accept-source-agreements

    Write-Host "Start: PowerToys dsc install"
    # Use --accept-package-agreements and --accept-source-agreements as per Microsoft best practices
    winget configuration -f $dscPowerToysEnterprise --accept-package-agreements --accept-source-agreements # no cleanup needed as this is intentionally local
   
    # clean up, Clean up, everyone wants to clean up
    Remove-Item $dscAdmin -verbose
    Write-Host "Done: Dev flows install"
    # ending dev workload
    
    # Setting PowerShell 7 as default in Windows Terminal
    Write-Host "Start: Setting PowerShell 7 as default terminal"
    $wtSettingsPaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
        "$env:LOCALAPPDATA\Microsoft\Windows Terminal\settings.json"
    )
    
    foreach ($settingsPath in $wtSettingsPaths) {
        if (Test-Path $settingsPath) {
            try {
                $settingsContent = Get-Content $settingsPath -Raw
                $settings = $settingsContent | ConvertFrom-Json
                
                # Find PowerShell 7 profile (typically has commandline with pwsh.exe)
                $pwsh7Profile = $null
                if ($settings.profiles.list) {
                    $pwsh7Profile = $settings.profiles.list | Where-Object { 
                        ($_.commandline -like "*pwsh.exe*" -or $_.commandline -like "*pwsh*") -or 
                        $_.guid -eq "{574e775e-4f2a-5b96-ac1e-a2962a402336}" -or
                        $_.name -like "*PowerShell*7*"
                    } | Select-Object -First 1
                }
                
                if ($pwsh7Profile) {
                    # Set PowerShell 7 as default profile (check both root level and defaults object)
                    if ($settings.defaults) {
                        $settings.defaults.defaultProfile = $pwsh7Profile.guid
                    } else {
                        $settings.defaultProfile = $pwsh7Profile.guid
                    }
                    
                    # Preserve formatting by using ConvertTo-Json with proper depth
                    $jsonContent = $settings | ConvertTo-Json -Depth 10
                    # Windows Terminal expects UTF-8 with BOM for proper formatting
                    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
                    [System.IO.File]::WriteAllText($settingsPath, $jsonContent, $utf8WithBom)
                    Write-Host "PowerShell 7 set as default in Windows Terminal"
                    break
                } else {
                    Write-Warning "PowerShell 7 profile not found in Windows Terminal settings"
                }
            } catch {
                Write-Warning "Failed to update Windows Terminal settings: $_"
            }
        }
    }
    Write-Host "Done: Setting PowerShell 7 as default terminal"
    
    # Upgrade WinGet to Microsoft Store version for automatic updates (at the very end)
    # This is done last so Store unavailability doesn't interfere with the rest of the script
    Write-Host "Start: Upgrading WinGet to Microsoft Store version for automatic updates"
    try {
        # Check if WinGet is available
        $wingetAvailable = $false
        try {
            $wingetCheck = winget --info 2>$null
            if ($wingetCheck) {
                $wingetAvailable = $true
            }
        } catch {
            # WinGet not available
        }
        
        if ($wingetAvailable) {
            # Check if Microsoft Store is available
            $storeAvailable = $false
            try {
                $storeTest = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction SilentlyContinue
                if ($storeTest) {
                    $storeAvailable = $true
                }
            } catch {
                # Store not available
            }
            
            if ($storeAvailable) {
                # Check if we already have the Store version
                $appInstaller = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue
                if ($appInstaller) {
                    Write-Host "WinGet is already installed from Microsoft Store - will receive automatic updates"
                } else {
                    Write-Host "Opening Microsoft Store to install/upgrade to Store version for automatic updates..."
                    try {
                        Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1" -ErrorAction Stop
                        Write-Host "Microsoft Store opened. Please click 'Get' or 'Update' to install the Store version."
                        Write-Host "The Store version will receive automatic updates from Microsoft."
                        Start-Sleep -Seconds 5
                    } catch {
                        Write-Warning "Could not open Microsoft Store for WinGet upgrade: $_"
                        Write-Host "You can manually upgrade WinGet from: https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
                    }
                }
            } else {
                Write-Host "Microsoft Store not available (e.g., Windows Sandbox) - keeping current WinGet installation"
                Write-Host "Current WinGet installation will continue to work, but won't receive automatic updates"
            }
        } else {
            Write-Host "WinGet not available - skipping Store upgrade"
        }
    } catch {
        Write-Warning "Failed to upgrade WinGet to Store version: $_"
        Write-Host "This is non-critical - the script has completed successfully"
    }
    Write-Host "Done: Upgrading WinGet to Microsoft Store version"
}
