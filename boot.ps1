$mypath = $MyInvocation.MyCommand.Path
Write-Output "Path of the script: $mypath"
Write-Output "Args for script: $Args"

# forcing WinGet to be installed
$isWinGetRecent = (winget -v).Trim('v').TrimEnd("-preview").split('.')

# turning off progress bar to make invoke WebRequest fast
$ProgressPreference = 'SilentlyContinue'

if(!(($isWinGetRecent[0] -gt 1) -or ($isWinGetRecent[0] -ge 1 -and $isWinGetRecent[1] -ge 6))) # WinGet is greater than v1 or v1.6 or higher
{
   $paths = "Microsoft.VCLibs.x64.14.00.Desktop.appx", "Microsoft.UI.Xaml.2.8.x64.appx", "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
   $uris = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx", "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx", "https://aka.ms/getwinget"
   Write-Host "Downloading WinGet and its dependencies..."

   for ($i = 0; $i -lt $uris.Length; $i++) {
       $filePath = $paths[$i]
       $fileUri = $uris[$i]
       Write-Host "Downloading: ($filePath) from $fileUri"
       Invoke-WebRequest -Uri $fileUri -OutFile $filePath
   }

   Write-Host "Installing WinGet and its dependencies..."
   
   foreach($filePath in $paths)
   {
       Write-Host "Installing: ($filePath)"
       Add-AppxPackage $filePath
   }

   Write-Host "Verifying Version number of WinGet"
   winget -v

   Write-Host "Cleaning up"
   foreach($filePath in $paths)
   {
      if (Test-Path $filePath) 
      {
         Write-Host "Deleting: ($filePath)"
         Remove-Item $filePath -verbose
      } 
      else
      {
         Write-Error "Path doesn't exits: ($filePath)"
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
   winget configuration -f $dscNonAdmin 
   
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
    winget configuration -f $dscOffice 
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
    Invoke-WebRequest -Uri $dscAdminUri -OutFile $dscAdmin 
    winget configuration -f $dscAdmin 

    Write-Host "Start: PowerToys dsc install"
    winget configuration -f $dscPowerToysEnterprise # no cleanup needed as this is intentionally local
   
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
}
