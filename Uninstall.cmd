@echo off
rem NetGuard uninstall - removes dashboard + agent. Add -RemoveData to also delete alerts and backups.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-NetGuard.ps1" -Uninstall %*
