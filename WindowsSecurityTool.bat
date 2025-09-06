@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Windows Security Tool

REM ------------------------------------------------------------------
REM  Windows Security Tool
REM  - Speculative execution mitigations (Spectre v2, Meltdown, SSBD, BHB)
REM  - Hypervisor/virtualization stack (BCDEdit, VBS, Windows features)
REM  - Microsoft Defender policies (Real-time Protection + Scan)
REM  - Status (registry + Get-SpeculationControlSettings + virtualization + Defender)
REM  - SpeculationControl module install/repair
REM  - Backup/Restore submenu
REM
REM  Notes:
REM    - Run from an elevated (Administrator) session.
REM    - Restart is required after mitigation or virtualization changes.
REM    - Defender policy changes may require gpupdate and/or a restart.
REM ------------------------------------------------------------------

REM === Registry paths ===
set "KEY=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
set "DG_POL=HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
set "WD_POL=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
set "WD_RTP=%WD_POL%\Real-Time Protection"
set "WD_SCAN=%WD_POL%\Scan"

REM === Backup file ===
set "BACKUP=%~dp0MM_Overrides_Backup.reg"

REM === Mitigation bits (FeatureSettingsOverride) ===
set /a BIT_BTI_DISABLE=0x1        REM Spectre v2 OS mitigation disabled
set /a BIT_KVA_DISABLE=0x2        REM Meltdown  OS mitigation disabled
set /a BIT_SSBD_ENABLE=0x8        REM SSBD system-wide enabled
set /a BIT_BHB_ENABLE=0x00800000  REM BHB/BHI mitigation enabled

REM === DISM feature names ===
set "F_HV=Microsoft-Hyper-V-All"
set "F_VMP=VirtualMachinePlatform"
set "F_WHP=HypervisorPlatform"
set "F_SANDBOX=Containers-DisposableClientVM"
set "F_WSL=Microsoft-Windows-Subsystem-Linux"

REM === Defender Scan defaults (change if desired) ===
set "SCAN_CPU_MAX=50"  REM Valid 5-100 (0 disables throttling)

REM === Prefer PowerShell 7 if available ===
where pwsh >nul 2>&1 && (set "PS=pwsh") || (set "PS=powershell")
set "PSFLAGS=-NoProfile -ExecutionPolicy Bypass -Command"

REM --- Self-elevate if not admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

:menu
cls
echo ===========================================================
echo                 Windows Security Tool
echo ===========================================================
echo.
echo   1) Disable Spectre v2 and Meltdown mitigations
echo   2) Enable  SSBD (system-wide)
echo   3) Disable SSBD (system-wide)
echo   4) Enable  BHB/BHI mitigation
echo   5) Disable BHB/BHI mitigation
echo   6) Configure Microsoft Defender policies (Real-time + Scan)
echo   7) Disable virtualization stack
echo   8) Show status (registry + detailed report + concise summary)
echo   9) Install or repair SpeculationControl module
echo   A) Backup/Restore...
echo   0) Exit
echo.
choice /C 123456789A0 /N /M "Select an option [1-9,A,0]: "
set "opt=%errorlevel%"

if "%opt%"=="1"  goto disable_bti_kva
if "%opt%"=="2"  goto ssbd_on
if "%opt%"=="3"  goto ssbd_off
if "%opt%"=="4"  goto bhb_on
if "%opt%"=="5"  goto bhb_off
if "%opt%"=="6"  goto defender_apply
if "%opt%"=="7"  goto disable_virtualization
if "%opt%"=="8"  goto status
if "%opt%"=="9"  goto installmod
if "%opt%"=="10" goto backup_menu
if "%opt%"=="11" goto eof
goto menu

:backup_menu
cls
echo ===================== Backup / Restore =====================
echo.
echo   1) Back up Memory Management overrides to "%BACKUP%"
echo   2) Restore default OS mitigation settings
echo   3) Restore virtualization stack
echo   4) Restore Microsoft Defender policies
echo   0) Return to main menu
echo.
choice /C 12340 /N /M "Select an option [1-4,0]: "
set "bopt=%errorlevel%"

if "%bopt%"=="1" goto backup
if "%bopt%"=="2" goto restore_defaults
if "%bopt%"=="3" goto restore_virtualization
if "%bopt%"=="4" goto defender_restore
if "%bopt%"=="5" goto menu
goto backup_menu

:disable_bti_kva
echo.
echo Disabling OS mitigations for Spectre v2 and Meltdown...
call :read_fso_mask
set /a NEWFSO=FSO ^| (BIT_BTI_DISABLE ^| BIT_KVA_DISABLE)
set /a NEWMASK=FSOMASK ^| (BIT_BTI_DISABLE ^| BIT_KVA_DISABLE)
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto menu

:ssbd_on
echo.
echo Enabling SSBD (system-wide)...
call :read_fso_mask
set /a NEWFSO=FSO ^| BIT_SSBD_ENABLE
set /a NEWMASK=FSOMASK ^| BIT_SSBD_ENABLE
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto menu

:ssbd_off
echo.
echo Disabling SSBD (system-wide)...
call :read_fso_mask
set /a NEWFSO=FSO ^& ~BIT_SSBD_ENABLE
set /a NEWMASK=FSOMASK ^| BIT_SSBD_ENABLE
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto menu

:bhb_on
echo.
echo Enabling BHB/BHI mitigation...
call :read_fso_mask
set /a NEWFSO=FSO ^| BIT_BHB_ENABLE
set /a NEWMASK=FSOMASK ^| BIT_BHB_ENABLE
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto menu

:bhb_off
echo.
echo Disabling BHB/BHI mitigation...
call :read_fso_mask
set /a NEWFSO=FSO ^& ~BIT_BHB_ENABLE
set /a NEWMASK=FSOMASK ^| BIT_BHB_ENABLE
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto menu

:disable_virtualization
echo.
echo Disabling virtualization stack...
echo   - Setting hypervisorlaunchtype to OFF
bcdedit /set hypervisorlaunchtype off
if %errorlevel% neq 0 echo     Note: bcdedit returned an error. Ensure BitLocker is suspended and you have admin rights.

echo   - Disabling Group Policy: Turn On Virtualization Based Security
reg add "%DG_POL%" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul

echo   - Turning off Windows features (no restart):
echo       %F_HV%
dism /online /Disable-Feature /FeatureName:%F_HV% /NoRestart
echo       %F_VMP%
dism /online /Disable-Feature /FeatureName:%F_VMP% /NoRestart
echo       %F_WHP%
dism /online /Disable-Feature /FeatureName:%F_WHP% /NoRestart
echo       %F_SANDBOX%
dism /online /Disable-Feature /FeatureName:%F_SANDBOX% /NoRestart
echo       %F_WSL%
dism /online /Disable-Feature /FeatureName:%F_WSL% /NoRestart

echo.
echo Completed. A restart is required to fully unload the hypervisor and apply changes.
echo.
pause
goto menu

:restore_virtualization
echo.
echo Restoring virtualization stack to defaults...
echo   - Setting hypervisorlaunchtype to AUTO
bcdedit /set hypervisorlaunchtype auto
if %errorlevel% neq 0 echo     Note: bcdedit returned an error. Ensure BitLocker is suspended and you have admin rights.

echo   - Clearing VBS policy value
reg delete "%DG_POL%" /v EnableVirtualizationBasedSecurity /f >nul 2>&1

echo   - Turning on Windows features (no restart):
echo       %F_HV%
dism /online /Enable-Feature /FeatureName:%F_HV% /All /NoRestart
echo       %F_VMP%
dism /online /Enable-Feature /FeatureName:%F_VMP% /All /NoRestart
echo       %F_WHP%
dism /online /Enable-Feature /FeatureName:%F_WHP% /All /NoRestart
echo       %F_SANDBOX%
dism /online /Enable-Feature /FeatureName:%F_SANDBOX% /All /NoRestart
echo       %F_WSL%
dism /online /Enable-Feature /FeatureName:%F_WSL% /All /NoRestart

echo.
echo Completed. A restart is required to load the hypervisor and finalize feature changes.
echo.
pause
goto backup_menu

:defender_apply
echo.
echo ===========================================================
echo Microsoft Defender configuration
echo ===========================================================
echo.
echo  IMPORTANT:
echo    - To allow these policy changes, Windows Security ^
must have **Tamper Protection** turned OFF.
echo    - Path: Windows Security ^> Virus ^& threat protection ^
^> Manage settings ^> Tamper Protection.
echo.
choice /C YNS /N /M "Open Windows Security to that page now? (Y)es / (N)o / (S)kip configuration: "
set "tpchoice=%errorlevel%"
if "%tpchoice%"=="1" (
  start "" windowsdefender://threatsettings
  echo.
  echo After turning **Tamper Protection** OFF, press any key here to continue...
  pause >nul
) else if "%tpchoice%"=="3" (
  echo Skipping Defender configuration.
  echo.
  pause
  goto menu
)

echo Configuring Microsoft Defender policies (Real-time + Scan)...
REM --- Real-time Protection ---
reg add "%WD_RTP%" /v DisableRealtimeMonitoring  /t REG_DWORD /d 1 /f >nul
reg add "%WD_RTP%" /v DisableBehaviorMonitoring  /t REG_DWORD /d 1 /f >nul
reg add "%WD_RTP%" /v DisableIOAVProtection      /t REG_DWORD /d 1 /f >nul
reg add "%WD_RTP%" /v DisableOnAccessProtection  /t REG_DWORD /d 1 /f >nul

REM --- Scan ---
reg add "%WD_SCAN%" /v AvgCPULoadFactor           /t REG_DWORD /d %SCAN_CPU_MAX% /f >nul
reg add "%WD_SCAN%" /v DisableScanningNetworkFiles /t REG_DWORD /d 1 /f >nul
reg add "%WD_SCAN%" /v LowCpuPriority              /t REG_DWORD /d 1 /f >nul
reg add "%WD_SCAN%" /v ScanOnlyIfIdle              /t REG_DWORD /d 1 /f >nul

echo Policies written (Scan CPU limit=%SCAN_CPU_MAX%%). Applying via gpupdate...
gpupdate /target:computer /force
echo Completed. A restart may be required for full enforcement.
echo.
pause
goto menu

:defender_restore
echo.
echo Restoring Microsoft Defender policies...
REM --- Real-time Protection ---
reg delete "%WD_RTP%" /v DisableRealtimeMonitoring /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableBehaviorMonitoring /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableIOAVProtection     /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableOnAccessProtection /f >nul 2>&1

REM --- Scan ---
reg delete "%WD_SCAN%" /v AvgCPULoadFactor            /f >nul 2>&1
reg delete "%WD_SCAN%" /v DisableScanningNetworkFiles  /f >nul 2>&1
reg delete "%WD_SCAN%" /v LowCpuPriority               /f >nul 2>&1
reg delete "%WD_SCAN%" /v ScanOnlyIfIdle               /f >nul 2>&1

echo Policies removed. Applying via gpupdate...
gpupdate /target:computer /force
echo Completed. A restart may be required for full enforcement.
echo.
pause
goto backup_menu

:status
echo.
echo Registry values:
reg query "%KEY%" /v FeatureSettingsOverride       2>nul
reg query "%KEY%" /v FeatureSettingsOverrideMask   2>nul
echo.
echo Decoded FeatureSettingsOverride bits:
"%PS%" %PSFLAGS% ^
 "$p='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management';" ^
 "$v = try {(Get-ItemProperty $p).FeatureSettingsOverride} catch {0};" ^
 "Write-Host ('  Hex: 0x{0:X8}  (Dec: {0})' -f $v);" ^
 "Write-Host ('  Spectre v2 disabled (bit 0): ' + ( ($v -band 0x1)  -ne 0));" ^
 "Write-Host ('  Meltdown disabled (bit 1):   ' + ( ($v -band 0x2)  -ne 0));" ^
 "Write-Host ('  SSBD enabled (bit 3):        ' + ( ($v -band 0x8)  -ne 0));" ^
 "Write-Host ('  BHB/BHI enabled (bit 23):    ' + ( ($v -band 0x00800000) -ne 0));"
echo.
echo Detailed status (Get-SpeculationControlSettings):
call :ensure_speculation_module
if errorlevel 1 (
  echo   The SpeculationControl module is not available. Use the install/repair option.
) else (
  "%PS%" %PSFLAGS% "Import-Module SpeculationControl; Get-SpeculationControlSettings | Out-String | Write-Host"
  "%PS%" %PSFLAGS% ^
   "Import-Module SpeculationControl;" ^
   "$s = Get-SpeculationControlSettings;" ^
   "$btid = (-not $s.BTIWindowsSupportEnabled) -and $s.BTIDisabledBySystemPolicy;" ^
   "$kva  = (-not $s.KVAShadowWindowsSupportEnabled);" ^
   "$ssbd = (-not $s.SSBDWindowsSupportEnabledSystemWide);" ^
   "$bhb  = (-not $s.BhbEnabled) -and $s.BhbDisabledSystemPolicy;" ^
   "$sbd  = (-not $s.FBClearWindowsSupportEnabled);" ^
   "Write-Host '--- Concise summary ---';" ^
   "function T([bool]$b,[string]$on,[string]$off){ @($off,$on)[[int]$b] }" ^
   "$btistr = T $btid 'Disabled' 'Enabled';" ^
   "$kvastr = T $kva  'Disabled' 'Enabled';" ^
   "$ssbdstr= T $ssbd 'Disabled' 'Enabled';" ^
   "$bhbstr = T $bhb  'Disabled' 'Enabled';" ^
   "$sbdstr = T $sbd  'Disabled' 'Enabled';" ^
   "Write-Host ('Spectre v2 (BTI): ' + $btistr);" ^
   "Write-Host ('Meltdown (KVA Shadow): ' + $kvastr);" ^
   "Write-Host ('SSBD (system-wide): ' + $ssbdstr);" ^
   "Write-Host ('BHB/BHI: ' + $bhbstr);" ^
   "Write-Host ('SBDR/FBSDP/PSDP class: ' + $sbdstr);"
)
echo.
echo Hypervisor and virtualization configuration:
echo   - hypervisorlaunchtype:
bcdedit /enum {current} | findstr /i "hypervisorlaunchtype"
call :show_vbs_policy
echo   - Windows feature states:
call :show_feature_state "%F_HV%"      "Hyper-V"
call :show_feature_state "%F_VMP%"     "Virtual Machine Platform"
call :show_feature_state "%F_WHP%"     "Windows Hypervisor Platform"
call :show_feature_state "%F_SANDBOX%" "Windows Sandbox"
call :show_feature_state "%F_WSL%"     "Windows Subsystem for Linux"
echo.
echo Microsoft Defender - Tamper Protection state (if available):
"%PS%" %PSFLAGS% ^
 "try {" ^
 "  $tp=(Get-MpComputerStatus).TamperProtection;" ^
 "  if($null -eq $tp){ Write-Host '  Tamper Protection: Unknown' } else { Write-Host ('  Tamper Protection: ' + $tp) }" ^
 "} catch { Write-Host '  Tamper Protection: Unknown' }"
echo.
echo Microsoft Defender Antivirus (Real-time Protection policy states):
"%PS%" %PSFLAGS% ^
 "$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';" ^
 "$v = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue;" ^
 "function P($exists,$val,$on,$off){ if(-not $exists){'Not Configured'} elseif($val -eq 1){$on}else{$off} }" ^
 "Write-Host ('  Turn off real-time protection: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableRealtimeMonitoring') $v.DisableRealtimeMonitoring 'Enabled (real-time protection OFF)' 'Disabled'));" ^
 "Write-Host ('  Turn on behavior monitoring:  ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableBehaviorMonitoring') $v.DisableBehaviorMonitoring 'Disabled' 'Enabled'));" ^
 "Write-Host ('  Scan all downloaded files and attachments: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableIOAVProtection') $v.DisableIOAVProtection 'Disabled' 'Enabled'));" ^
 "Write-Host ('  Monitor file and program activity on your computer: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableOnAccessProtection') $v.DisableOnAccessProtection 'Disabled' 'Enabled'));"
echo.
echo Microsoft Defender Antivirus (Scan policy states):
"%PS%" %PSFLAGS% ^
 "$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan';" ^
 "$v = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue;" ^
 "$cpu  = if($v -and ($v.PSObject.Properties.Name -contains 'AvgCPULoadFactor')){ $v.AvgCPULoadFactor } else { $null };" ^
 "$net  = if($v -and ($v.PSObject.Properties.Name -contains 'DisableScanningNetworkFiles')){ $v.DisableScanningNetworkFiles } else { $null };" ^
 "$lcp  = if($v -and ($v.PSObject.Properties.Name -contains 'LowCpuPriority')){ $v.LowCpuPriority } else { $null };" ^
 "$idle = if($v -and ($v.PSObject.Properties.Name -contains 'ScanOnlyIfIdle')){ $v.ScanOnlyIfIdle } else { $null };" ^
 "function S($exists,$val,$enabled,$disabled){ if(-not $exists){ return 'Not Configured' } @($disabled,$enabled)[[int]($val -eq 1)] }" ^
 "if($cpu -ne $null){ $cpuStr = ($cpu.ToString() + '%%') } else { $cpuStr = 'Not Configured' };" ^
 "$netStr  = S ($net  -ne $null) $net  'Disabled' 'Enabled';" ^
 "$lcpStr  = S ($lcp  -ne $null) $lcp  'Enabled'  'Disabled';" ^
 "$idleStr = S ($idle -ne $null) $idle 'Enabled'  'Disabled';" ^
 "Write-Host ('  Max CPU during scan: ' + $cpuStr);" ^
 "Write-Host ('  Scan network files: ' + $netStr);" ^
 "Write-Host ('  Low CPU priority for scheduled scans: ' + $lcpStr);" ^
 "Write-Host ('  Start scheduled scan only when device is idle: ' + $idleStr);"
echo.
echo Note: Restart the system after mitigation/virtualization changes. Defender policy changes may also require gpupdate/restart.
echo.
pause
goto menu

:backup
echo.
echo Creating backup: "%BACKUP%"
reg export "%KEY%" "%BACKUP%" /y >nul 2>&1
if errorlevel 1 (echo Backup failed. Check path and permissions. & pause & goto backup_menu)
echo Backup completed.
echo.
pause
goto backup_menu

:installmod
echo.
echo Installing or repairing the SpeculationControl PowerShell module (CurrentUser scope)...
call :ensure_speculation_module
if errorlevel 1 (
  echo Installation or repair did not complete successfully. Internet access and PSGallery trust may be required.
) else (
  echo The SpeculationControl module is available.
)
echo.
pause
goto menu

REM ----------------------- Helper routines -----------------------

:read_fso_mask
set "FSO=0"
set "FSOMASK=0"
for /f "tokens=3" %%A in ('reg query "%KEY%" /v FeatureSettingsOverride 2^>nul ^| findstr /i FeatureSettingsOverride') do set "FSO_RAW=%%A"
for /f "tokens=3" %%A in ('reg query "%KEY%" /v FeatureSettingsOverrideMask 2^>nul ^| findstr /i FeatureSettingsOverrideMask') do set "FSOMASK_RAW=%%A"
if defined FSO_RAW     set /a FSO=%FSO_RAW%
if defined FSOMASK_RAW set /a FSOMASK=%FSOMASK_RAW%
exit /b 0

:write_fso_mask
REM %1 = new FSO (decimal), %2 = new FSOMask (decimal)
reg add "%KEY%" /v FeatureSettingsOverride /t REG_DWORD /d %1 /f
if %errorlevel% neq 0 (echo Failed to set FeatureSettingsOverride. & exit /b 1)
reg add "%KEY%" /v FeatureSettingsOverrideMask /t REG_DWORD /d %2 /f
if %errorlevel% neq 0 (echo Failed to set FeatureSettingsOverrideMask. & exit /b 1)
exit /b 0

:ensure_speculation_module
"%PS%" %PSFLAGS% ^
 "$ErrorActionPreference='Stop';" ^
 "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" ^
 "if (Get-Module -ListAvailable -Name SpeculationControl) { exit 0 }" ^
 "else {" ^
 "  try {" ^
 "    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null };" ^
 "    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default -ErrorAction SilentlyContinue };" ^
 "    try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch {};" ^
 "    Install-Module -Name SpeculationControl -Scope CurrentUser -Force -AllowClobber;" ^
 "    exit 0" ^
 "  } catch {" ^
 "    Write-Host ('  Installation failed: ' + $_.Exception.Message);" ^
 "    exit 1" ^
 "  }" ^
 "}"
exit /b %ERRORLEVEL%

:show_feature_state
REM %1 FeatureName, %2 FriendlyName
set "state=Unknown"
for /f "tokens=2 delims=:" %%S in ('dism /online /Get-FeatureInfo /FeatureName:%~1 ^| findstr /c:"State :"') do set "state=%%S"
set "state=%state: =%"
echo     %~2: %state%
exit /b 0

:show_vbs_policy
set "VBSSTR=Not Configured"
for /f "tokens=3" %%V in ('reg query "%DG_POL%" /v EnableVirtualizationBasedSecurity 2^>nul ^| findstr /i EnableVirtualizationBasedSecurity') do set "VBSVAL=%%V"
if defined VBSVAL (
  if /I "%VBSVAL%"=="0x0"  set "VBSSTR=Disabled"
  if /I "%VBSVAL%"=="0x1"  set "VBSSTR=Enabled"
)
echo   - VBS policy (Turn On Virtualization Based Security): %VBSSTR%
exit /b 0

:restore_defaults
echo.
echo Restoring default OS mitigation settings (clear Spectre v2 and Meltdown overrides)...
call :read_fso_mask
set /a NEWFSO=FSO ^& ~(BIT_BTI_DISABLE ^| BIT_KVA_DISABLE)
set /a NEWMASK=FSOMASK ^| (BIT_BTI_DISABLE ^| BIT_KVA_DISABLE)
call :write_fso_mask %NEWFSO% %NEWMASK%
if errorlevel 1 (echo Operation failed. & pause & goto backup_menu)
echo Completed. Restart is required to apply changes.
echo.
pause
goto backup_menu

:restore_virtualization
echo.
echo Restoring virtualization stack to defaults...
echo   - Setting hypervisorlaunchtype to AUTO
bcdedit /set hypervisorlaunchtype auto
if %errorlevel% neq 0 echo     Note: bcdedit returned an error. Ensure BitLocker is suspended and you have admin rights.

echo   - Clearing VBS policy value
reg delete "%DG_POL%" /v EnableVirtualizationBasedSecurity /f >nul 2>&1

echo   - Turning on Windows features (no restart):
echo       %F_HV%
dism /online /Enable-Feature /FeatureName:%F_HV% /All /NoRestart
echo       %F_VMP%
dism /online /Enable-Feature /FeatureName:%F_VMP% /All /NoRestart
echo       %F_WHP%
dism /online /Enable-Feature /FeatureName:%F_WHP% /All /NoRestart
echo       %F_SANDBOX%
dism /online /Enable-Feature /FeatureName:%F_SANDBOX% /All /NoRestart
echo       %F_WSL%
dism /online /Enable-Feature /FeatureName:%F_WSL% /All /NoRestart

echo.
echo Completed. A restart is required to load the hypervisor and finalize feature changes.
echo.
pause
goto backup_menu

:defender_restore
echo.
echo Restoring Microsoft Defender policies...
REM --- Real-time Protection ---
reg delete "%WD_RTP%" /v DisableRealtimeMonitoring /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableBehaviorMonitoring /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableIOAVProtection     /f >nul 2>&1
reg delete "%WD_RTP%" /v DisableOnAccessProtection /f >nul 2>&1

REM --- Scan ---
reg delete "%WD_SCAN%" /v AvgCPULoadFactor            /f >nul 2>&1
reg delete "%WD_SCAN%" /v DisableScanningNetworkFiles  /f >nul 2>&1
reg delete "%WD_SCAN%" /v LowCpuPriority               /f >nul 2>&1
reg delete "%WD_SCAN%" /v ScanOnlyIfIdle               /f >nul 2>&1

echo Policies removed. Applying via gpupdate...
gpupdate /target:computer /force
echo Completed. A restart may be required for full enforcement.
echo.
pause
goto backup_menu

:eof
endlocal
exit /b 0
