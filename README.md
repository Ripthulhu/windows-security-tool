# Windows Security Tool

A single **batch script** for power users to quickly configure Windows security/performance settings from one menu.

## What it does

* **Speculative-execution mitigations**
  Enable/disable: Spectre v2 (BTI), Meltdown (KVA Shadow), SSBD, BHB/BHI.
* **Virtualization stack control**
  Toggle `hypervisorlaunchtype` (BCDEdit), VBS policy, and Windows features: Hyper-V, VMP, WHP, Sandbox, WSL.
* **Microsoft Defender policies**
  One action to set Real-time Protection (disable RTP/behavior/on-access/IOAV) **and** Scan policies (CPU cap, network files, low-priority, idle-only), plus a one-click restore.
* **Status report**
  Shows registry values, decodes mitigation bits, runs `Get-SpeculationControlSettings` (auto-installs module if needed), and reports virtualization & Defender policy states.
* **Backup/Restore submenu**
  Export Memory Management overrides, restore mitigations, virtualization, and Defender policies.

## Quick start

1. Download `WindowsSecurityTool.bat`.
2. **Right-click → Run as administrator**.
3. Choose an option; **restart** after mitigation/virtualization changes.
   For Defender policy changes, the script runs `gpupdate`; a restart may still help.

## Notes

* Disabling mitigations/Defender features **reduces security**. Use only if you understand the risk.
* If Defender changes do not apply, ensure **Tamper Protection** is off in Windows Security.
* Tested on Windows 10/11. Requires Internet on first run to install the `SpeculationControl` PowerShell module (CurrentUser scope).

## License

MIT.
