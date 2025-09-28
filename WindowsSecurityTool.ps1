<# 
    Windows Security Tool (PowerShell Edition) - Stream-safe

    Works when run locally OR via:
      powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Ripthulhu/windows-security-tool/refs/heads/main/WindowsSecurityTool.ps1 | iex"

    Features:
      - Speculative execution mitigations (Spectre v2, Meltdown, SSBD, BHB)
      - Hypervisor/virtualization stack (BCDEdit, VBS, Windows features)
      - Microsoft Defender policies (Real-time Protection + Scan)
      - Status (registry + Get-SpeculationControlSettings + virtualization + Defender)
      - SpeculationControl module install/repair
      - Backup/Restore submenu

    Notes:
      - Requires elevation (auto-prompts if not).
      - Restart is required after mitigation or virtualization changes.
      - Defender policy changes may require gpupdate and/or a restart.
#>

# ==================== Configuration (stream-aware) ====================
# Raw URL for streamed elevation re-invoke:
$ScriptRawUrl = 'https://raw.githubusercontent.com/Ripthulhu/windows-security-tool/refs/heads/main/WindowsSecurityTool.ps1'

# Detect a meaningful base directory (PSScriptRoot is $null when streamed via IEX)
$BaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- Self-elevate if not admin (works for local OR streamed runs) ---
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    [Security.Principal.WindowsPrincipal]::new($id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdmin)) {
    Write-Host "Requesting administrator privileges..."
    $psExe = (Get-Process -Id $PID).Path

    # Local script run => relaunch with -File; streamed IEX run => relaunch with web bootstrap.
    $args =
        if ($PSCommandPath) {
            @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        } else {
            @('-NoProfile','-ExecutionPolicy','Bypass','-Command',"irm $ScriptRawUrl | iex")
        }

    Start-Process -FilePath $psExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
}

# Optional: window title
try { $Host.UI.RawUI.WindowTitle = 'Windows Security Tool' } catch {}

# -------------------- Constants & Config --------------------
$KEY     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$DG_POL  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
$WD_POL  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$WD_RTP  = Join-Path $WD_POL 'Real-Time Protection'
$WD_SCAN = Join-Path $WD_POL 'Scan'

# Backup file lives next to the script when local; current dir when streamed
$BACKUP  = Join-Path $BaseDir 'MM_Overrides_Backup.reg'

# Mitigation bits (FeatureSettingsOverride)
[uint32]$BIT_BTI_DISABLE = 0x1         # Spectre v2 OS mitigation disabled
[uint32]$BIT_KVA_DISABLE = 0x2         # Meltdown  OS mitigation disabled
[uint32]$BIT_SSBD_ENABLE = 0x8         # SSBD system-wide enabled
[uint32]$BIT_BHB_ENABLE  = 0x00800000  # BHB/BHI mitigation enabled

# DISM feature names
$F_HV      = 'Microsoft-Hyper-V-All'
$F_VMP     = 'VirtualMachinePlatform'
$F_WHP     = 'HypervisorPlatform'
$F_SANDBOX = 'Containers-DisposableClientVM'
$F_WSL     = 'Microsoft-Windows-Subsystem-Linux'
$FeatureList = @($F_HV,$F_VMP,$F_WHP,$F_SANDBOX,$F_WSL)

# Defender Scan defaults
$SCAN_CPU_MAX = 50   # Valid 5-100 (0 disables throttling)

# -------------------- Helpers --------------------
function Press-Enter { Write-Host; Read-Host "Press Enter to continue..." | Out-Null }

function Get-FsoMask {
    $v  = (Get-ItemProperty -Path $KEY -ErrorAction SilentlyContinue).FeatureSettingsOverride
    $vm = (Get-ItemProperty -Path $KEY -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask
    [uint32]$v  = if ($null -ne $v)  { $v }  else { 0 }
    [uint32]$vm = if ($null -ne $vm) { $vm } else { 0 }
    [pscustomobject]@{ FSO = $v; FSOMASK = $vm }
}
function Set-FsoMask([uint32]$NewFSO, [uint32]$NewMask) {
    try {
        New-Item -Path $KEY -Force | Out-Null
        New-ItemProperty -Path $KEY -Name 'FeatureSettingsOverride'     -Value $NewFSO -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $KEY -Name 'FeatureSettingsOverrideMask' -Value $NewMask -PropertyType DWord -Force | Out-Null
        $true
    } catch {
        Write-Warning "Failed to write FSO/Mask: $($_.Exception.Message)"
        $false
    }
}

function Run-Cmd([string]$File, [string]$Args) { & $File $Args 2>&1 }

function Dism-EnableFeature([string]$Feature)  { Run-Cmd dism "/online /Enable-Feature /FeatureName:$Feature /All /NoRestart" | Write-Host }
function Dism-DisableFeature([string]$Feature) { Run-Cmd dism "/online /Disable-Feature /FeatureName:$Feature /NoRestart"     | Write-Host }

function Get-FeatureState([string]$Feature) {
    try {
        (Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction Stop).State
    } catch {
        $out = Run-Cmd dism "/online /Get-FeatureInfo /FeatureName:$Feature"
        ($out | Where-Object { $_ -match 'State\s*:\s*(.+)$' } | ForEach-Object { ($_ -replace '.*State\s*:\s*','').Trim() }) | Select-Object -First 1
    }
}

function Show-VbsPolicy {
    $name = 'EnableVirtualizationBasedSecurity'
    $v = (Get-ItemProperty -Path $DG_POL -ErrorAction SilentlyContinue).$name
    if ($null -eq $v) { 'Not Configured' }
    elseif ($v -eq 0) { 'Disabled' }
    elseif ($v -eq 1) { 'Enabled' }
    else { "Unknown ($v)" }
}

function Ensure-SpeculationModule {
    try {
        if (Get-Module -ListAvailable -Name SpeculationControl) { return $true }
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction SilentlyContinue
        }
        try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch {}
        Install-Module -Name SpeculationControl -Scope CurrentUser -Force -AllowClobber
        $true
    } catch {
        Write-Warning "SpeculationControl install failed: $($_.Exception.Message)"
        $false
    }
}

function Show-Status {
    Write-Host
    Write-Host 'Registry values:'
    try {
        $props = Get-ItemProperty -Path $KEY -ErrorAction Stop
        $fso  = [uint32]($props.FeatureSettingsOverride)
        $mask = [uint32]($props.FeatureSettingsOverrideMask)
        Write-Host ("  FeatureSettingsOverride     : 0x{0:X8} ({0})" -f $fso)
        Write-Host ("  FeatureSettingsOverrideMask : 0x{0:X8} ({0})" -f $mask)
    } catch {
        Write-Host '  FeatureSettingsOverride     : (not set)'
        Write-Host '  FeatureSettingsOverrideMask : (not set)'
        $fso = [uint32]0
    }

    Write-Host
    Write-Host 'Decoded FeatureSettingsOverride bits:'
    Write-Host ("  Hex: 0x{0:X8}  (Dec: {0})" -f $fso)
    Write-Host ("  Spectre v2 disabled (bit 0): {0}" -f (($fso -band $BIT_BTI_DISABLE) -ne 0))
    Write-Host ("  Meltdown disabled (bit 1):   {0}" -f (($fso -band $BIT_KVA_DISABLE) -ne 0))
    Write-Host ("  SSBD enabled (bit 3):        {0}" -f (($fso -band $BIT_SSBD_ENABLE) -ne 0))
    Write-Host ("  BHB/BHI enabled (bit 23):    {0}" -f (($fso -band $BIT_BHB_ENABLE) -ne 0))

    Write-Host
    Write-Host 'Detailed status (Get-SpeculationControlSettings):'
    if (Ensure-SpeculationModule) {
        Import-Module SpeculationControl -ErrorAction SilentlyContinue
        try {
            $s = Get-SpeculationControlSettings
            $s | Out-String | Write-Host
            function T([bool]$b,[string]$on,[string]$off){ if($b){$on}else{$off} }
            $btid = (-not $s.BTIWindowsSupportEnabled) -and $s.BTIDisabledBySystemPolicy
            $kva  = (-not $s.KVAShadowWindowsSupportEnabled)
            $ssbd = (-not $s.SSBDWindowsSupportEnabledSystemWide)
            $bhb  = (-not $s.BhbEnabled) -and $s.BhbDisabledSystemPolicy
            $sbd  = (-not $s.FBClearWindowsSupportEnabled)
            Write-Host '--- Concise summary ---'
            Write-Host ('Spectre v2 (BTI): ' + (T $btid 'Disabled' 'Enabled'))
            Write-Host ('Meltdown (KVA Shadow): ' + (T $kva  'Disabled' 'Enabled'))
            Write-Host ('SSBD (system-wide): ' + (T $ssbd 'Disabled' 'Enabled'))
            Write-Host ('BHB/BHI: ' + (T $bhb  'Disabled' 'Enabled'))
            Write-Host ('SBDR/FBSDP/PSDP class: ' + (T $sbd 'Disabled' 'Enabled'))
        } catch {
            Write-Warning "SpeculationControl query failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host '  The SpeculationControl module is not available. Use the install/repair option.'
    }

    Write-Host
    Write-Host 'Hypervisor and virtualization configuration:'
    Write-Host '  - hypervisorlaunchtype:'
    try {
        bcdedit /enum {current} | Select-String -Pattern 'hypervisorlaunchtype' | ForEach-Object { "    $_" } | Write-Host
    } catch { Write-Host '    (unavailable)' }

    Write-Host ('  - VBS policy (Turn On Virtualization Based Security): ' + (Show-VbsPolicy))

    Write-Host '  - Windows feature states:'
    Write-Host ("    Hyper-V                        : {0}" -f (Get-FeatureState $F_HV))
    Write-Host ("    Virtual Machine Platform       : {0}" -f (Get-FeatureState $F_VMP))
    Write-Host ("    Windows Hypervisor Platform    : {0}" -f (Get-FeatureState $F_WHP))
    Write-Host ("    Windows Sandbox                : {0}" -f (Get-FeatureState $F_SANDBOX))
    Write-Host ("    Windows Subsystem for Linux    : {0}" -f (Get-FeatureState $F_WSL))

    Write-Host
    Write-Host 'Microsoft Defender - Tamper Protection state (if available):'
    try {
        $tp=(Get-MpComputerStatus).TamperProtection
        if ($null -eq $tp) { Write-Host '  Tamper Protection: Unknown' } else { Write-Host "  Tamper Protection: $tp" }
    } catch { Write-Host '  Tamper Protection: Unknown' }

    Write-Host
    Write-Host 'Microsoft Defender Antivirus (Real-time Protection policy states):'
    $v = Get-ItemProperty -Path $WD_RTP -ErrorAction SilentlyContinue
    function P($exists,$val,$on,$off){ if(-not $exists){'Not Configured'} elseif($val -eq 1){$on}else{$off} }
    Write-Host ('  Turn off real-time protection: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableRealtimeMonitoring') $($v.DisableRealtimeMonitoring) 'Enabled (real-time protection OFF)' 'Disabled'))
    Write-Host ('  Turn on behavior monitoring:  ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableBehaviorMonitoring') $($v.DisableBehaviorMonitoring) 'Disabled' 'Enabled'))
    Write-Host ('  Scan all downloaded files and attachments: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableIOAVProtection') $($v.DisableIOAVProtection) 'Disabled' 'Enabled'))
    Write-Host ('  Monitor file and program activity on your computer: ' + (P ($v -ne $null -and $v.PSObject.Properties.Name -contains 'DisableOnAccessProtection') $($v.DisableOnAccessProtection) 'Disabled' 'Enabled'))

    Write-Host
    Write-Host 'Microsoft Defender Antivirus (Scan policy states):'
    $s = Get-ItemProperty -Path $WD_SCAN -ErrorAction SilentlyContinue
    function S($exists,$val,$enabled,$disabled){ if(-not $exists){ return 'Not Configured' } @($disabled,$enabled)[[int]($val -eq 1)] }
    $cpu  = if($s -and ($s.PSObject.Properties.Name -contains 'AvgCPULoadFactor')){ $s.AvgCPULoadFactor } else { $null }
    $net  = if($s -and ($s.PSObject.Properties.Name -contains 'DisableScanningNetworkFiles')){ $s.DisableScanningNetworkFiles } else { $null }
    $lcp  = if($s -and ($s.PSObject.Properties.Name -contains 'LowCpuPriority')){ $s.LowCpuPriority } else { $null }
    $idle = if($s -and ($s.PSObject.Properties.Name -contains 'ScanOnlyIfIdle')){ $s.ScanOnlyIfIdle } else { $null }
    $cpuStr = if($cpu -ne $null) { "$cpu`%" } else { 'Not Configured' }
    Write-Host ("  Max CPU during scan: {0}" -f $cpuStr)
    Write-Host ("  Scan network files: {0}" -f (S ($net -ne $null)  $net  'Disabled' 'Enabled'))
    Write-Host ("  Low CPU priority for scheduled scans: {0}" -f (S ($lcp -ne $null)  $lcp  'Enabled'  'Disabled'))
    Write-Host ("  Start scheduled scan only when device is idle: {0}" -f (S ($idle -ne $null) $idle 'Enabled'  'Disabled'))

    Write-Host
    Write-Host 'Note: Restart the system after mitigation/virtualization changes. Defender policy changes may also require gpupdate/restart.'
}

# -------------------- Actions --------------------
function Disable-BTI-KVA {
    Write-Host "`nDisabling OS mitigations for Spectre v2 and Meltdown..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -bor ($BIT_BTI_DISABLE -bor $BIT_KVA_DISABLE))
    [uint32]$newMask = ($r.FSOMASK -bor ($BIT_BTI_DISABLE -bor $BIT_KVA_DISABLE))
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}

function SSBD-On {
    Write-Host "`nEnabling SSBD (system-wide)..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -bor $BIT_SSBD_ENABLE)
    [uint32]$newMask = ($r.FSOMASK -bor $BIT_SSBD_ENABLE)
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}
function SSBD-Off {
    Write-Host "`nDisabling SSBD (system-wide)..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -band (-bnot $BIT_SSBD_ENABLE))
    [uint32]$newMask = ($r.FSOMASK -bor $BIT_SSBD_ENABLE)
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}

function BHB-On {
    Write-Host "`nEnabling BHB/BHI mitigation..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -bor $BIT_BHB_ENABLE)
    [uint32]$newMask = ($r.FSOMASK -bor $BIT_BHB_ENABLE)
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}
function BHB-Off {
    Write-Host "`nDisabling BHB/BHI mitigation..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -band (-bnot $BIT_BHB_ENABLE))
    [uint32]$newMask = ($r.FSOMASK -bor $BIT_BHB_ENABLE)
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}

function Disable-Virtualization {
    Write-Host "`nDisabling virtualization stack..."
    Write-Host "  - Setting hypervisorlaunchtype to OFF"
    try { bcdedit /set hypervisorlaunchtype off | Out-Null } catch { Write-Warning "    Note: bcdedit returned an error. Ensure BitLocker is suspended and you have admin rights." }

    Write-Host "  - Disabling Group Policy: Turn On Virtualization Based Security"
    New-Item -Path $DG_POL -Force | Out-Null
    New-ItemProperty -Path $DG_POL -Name EnableVirtualizationBasedSecurity -Value 0 -PropertyType DWord -Force | Out-Null

    Write-Host "  - Turning off Windows features (no restart):"
    foreach ($f in $FeatureList) { Write-Host "      $f"; Dism-DisableFeature $f }

    Write-Host "`nCompleted. A restart is required to fully unload the hypervisor and apply changes."
    Press-Enter
}

function Restore-Virtualization {
    Write-Host "`nRestoring virtualization stack to defaults..."
    Write-Host "  - Setting hypervisorlaunchtype to AUTO"
    try { bcdedit /set hypervisorlaunchtype auto | Out-Null } catch { Write-Warning "    Note: bcdedit returned an error. Ensure BitLocker is suspended and you have admin rights." }

    Write-Host "  - Clearing VBS policy value"
    try { Remove-ItemProperty -Path $DG_POL -Name EnableVirtualizationBasedSecurity -Force -ErrorAction Stop } catch {}

    Write-Host "  - Turning on Windows features (no restart):"
    foreach ($f in $FeatureList) { Write-Host "      $f"; Dism-EnableFeature $f }

    Write-Host "`nCompleted. A restart is required to load the hypervisor and finalize feature changes."
    Press-Enter
}

function Defender-Apply {
@"
===========================================================
Microsoft Defender configuration
===========================================================

  IMPORTANT:
    - To allow these policy changes, Windows Security
      must have **Tamper Protection** turned OFF.
    - Path: Windows Security > Virus & threat protection
            > Manage settings > Tamper Protection.
"@ | Write-Host
    $choice = Read-Host "Open Windows Security to that page now? (Y)es / (N)o / (S)kip configuration"
    if ($choice -match '^[Yy]') {
        Start-Process 'windowsdefender://threatsettings'
        Write-Host
        Read-Host "After turning **Tamper Protection** OFF, press Enter here to continue..." | Out-Null
    } elseif ($choice -match '^[Ss]') {
        Write-Host "Skipping Defender configuration."
        Press-Enter
        return
    }

    Write-Host "Configuring Microsoft Defender policies (Real-time + Scan)..."
    New-Item -Path $WD_RTP -Force | Out-Null
    New-Item -Path $WD_SCAN -Force | Out-Null

    # Real-time Protection
    New-ItemProperty -Path $WD_RTP -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_RTP -Name DisableBehaviorMonitoring -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_RTP -Name DisableIOAVProtection     -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_RTP -Name DisableOnAccessProtection -Value 1 -PropertyType DWord -Force | Out-Null

    # Scan
    New-ItemProperty -Path $WD_SCAN -Name AvgCPULoadFactor            -Value ([int]$SCAN_CPU_MAX) -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_SCAN -Name DisableScanningNetworkFiles -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_SCAN -Name LowCpuPriority              -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WD_SCAN -Name ScanOnlyIfIdle              -Value 1 -PropertyType DWord -Force | Out-Null

    Write-Host ("Policies written (Scan CPU limit={0}%). Applying via gpupdate..." -f $SCAN_CPU_MAX)
    gpupdate /target:computer /force | Out-Null
    Write-Host "Completed. A restart may be required for full enforcement."
    Press-Enter
}

function Defender-Restore {
    Write-Host "`nRestoring Microsoft Defender policies..."
    foreach ($name in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableOnAccessProtection') {
        try { Remove-ItemProperty -Path $WD_RTP -Name $name -Force -ErrorAction Stop } catch {}
    }
    foreach ($name in 'AvgCPULoadFactor','DisableScanningNetworkFiles','LowCpuPriority','ScanOnlyIfIdle') {
        try { Remove-ItemProperty -Path $WD_SCAN -Name $name -Force -ErrorAction Stop } catch {}
    }
    Write-Host "Policies removed. Applying via gpupdate..."
    gpupdate /target:computer /force | Out-Null
    Write-Host "Completed. A restart may be required for full enforcement."
    Press-Enter
}

function Backup-Overrides {
    Write-Host "`nCreating backup: '$BACKUP'"
    try {
        & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' $BACKUP /y | Out-Null
        Write-Host "Backup completed."
    } catch {
        Write-Host "Backup failed. Check path and permissions."
    }
    Press-Enter
}

function Restore-Defaults {
    Write-Host "`nRestoring default OS mitigation settings (clear Spectre v2 and Meltdown overrides)..."
    $r = Get-FsoMask
    [uint32]$newFSO  = ($r.FSO -band (-bnot ($BIT_BTI_DISABLE -bor $BIT_KVA_DISABLE)))
    [uint32]$newMask = ($r.FSOMASK -bor ($BIT_BTI_DISABLE -bor $BIT_KVA_DISABLE))
    if (Set-FsoMask $newFSO $newMask) { Write-Host "Completed. Restart is required to apply changes." } else { Write-Host "Operation failed." }
    Press-Enter
}

function Install-ModuleSpeculation {
    Write-Host "`nInstalling or repairing the SpeculationControl PowerShell module (CurrentUser scope)..."
    if (Ensure-SpeculationModule) { Write-Host "The SpeculationControl module is available." }
    else { Write-Host "Installation or repair did not complete successfully. Internet access and PSGallery trust may be required." }
    Press-Enter
}

# -------------------- Menus --------------------
function Show-MainMenu {
    Clear-Host
    Write-Host "==========================================================="
    Write-Host "                Windows Security Tool"
    Write-Host "==========================================================="
    Write-Host
    Write-Host "  1) Disable Spectre v2 and Meltdown mitigations"
    Write-Host "  2) Enable  SSBD (system-wide)"
    Write-Host "  3) Disable SSBD (system-wide)"
    Write-Host "  4) Enable  BHB/BHI mitigation"
    Write-Host "  5) Disable BHB/BHI mitigation"
    Write-Host "  6) Configure Microsoft Defender policies (Real-time + Scan)"
    Write-Host "  7) Disable virtualization stack"
    Write-Host "  8) Show status (registry + detailed report + concise summary)"
    Write-Host "  9) Install or repair SpeculationControl module"
    Write-Host "  A) Backup/Restore..."
    Write-Host "  0) Exit"
    Write-Host
    Read-Host "Select an option [1-9,A,0]"
}

function Show-BackupMenu {
    Clear-Host
    Write-Host "===================== Backup / Restore ====================="
    Write-Host
    Write-Host "  1) Back up Memory Management overrides to '$BACKUP'"
    Write-Host "  2) Restore default OS mitigation settings"
    Write-Host "  3) Restore virtualization stack"
    Write-Host "  4) Restore Microsoft Defender policies"
    Write-Host "  0) Return to main menu"
    Write-Host
    Read-Host "Select an option [1-4,0]"
}

# -------------------- Main loop --------------------
while ($true) {
    $opt = Show-MainMenu
    switch ($opt.ToUpperInvariant()) {
        '1' { Disable-BTI-KVA }
        '2' { SSBD-On }
        '3' { SSBD-Off }
        '4' { BHB-On }
        '5' { BHB-Off }
        '6' { Defender-Apply }
        '7' { Disable-Virtualization }
        '8' { Show-Status; Press-Enter }
        '9' { Install-ModuleSpeculation }
        'A' { 
            while ($true) {
                $bopt = Show-BackupMenu
                switch ($bopt) {
                    '1' { Backup-Overrides }
                    '2' { Restore-Defaults }
                    '3' { Restore-Virtualization }
                    '4' { Defender-Restore }
                    '0' { break }
                    default { }
                }
            }
        }
        '0' { break }
        default { }
    }
}

exit 0
