# Windows Security Tool (PowerShell)

A PowerShell script to quickly configure Windows security/mitigation  settings from one menu.

## What it does

- **Speculative-execution mitigations**  
  Enable/disable: Spectre v2 (BTI), Meltdown (KVA Shadow), SSBD, BHB/BHI.
- **Virtualization stack control**  
  Toggle `hypervisorlaunchtype` (BCDEdit), VBS policy, and Windows features: Hyper-V, VMP, WHP, Sandbox, WSL.
- **Microsoft Defender policies**  
  One action to set Real-time Protection (disable RTP/behavior/on-access/IOAV) **and** Scan policies (CPU cap, network files, low-priority, idle-only), plus a one-click restore.
- **Status report**  
  Shows registry values, decodes mitigation bits, runs `Get-SpeculationControlSettings` (auto-installs module if needed), and reports virtualization & Defender policy states.
- **Backup/Restore submenu**  
  Export Memory Management overrides, restore mitigations, virtualization, and Defender policies.

## Run it

> Requires Administrator. The script self-elevates if needed.

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Ripthulhu/windows-security-tool/refs/heads/main/WindowsSecurityTool.ps1 | iex"
```

## After running

* **Restart** after mitigation or virtualization changes.
* For Defender policy changes, the tool runs `gpupdate`; a restart may still help.

## Notes & requirements

* Disabling mitigations/Defender features **reduces security**. Use only if you understand the risk.
* If Defender changes don’t apply, ensure **Tamper Protection** is **Off**:
  *Windows Security → Virus & threat protection → Manage settings → Tamper Protection*.
* Defender policy management generally requires **Windows Pro/Enterprise** (not Home).
* Tested on Windows 10/11. First run needs Internet to install the `SpeculationControl` module (CurrentUser scope).

## License

MIT.

```
```
