@echo off
rem NetGuard setup - double-click to install the dashboard + agent on this PC.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-NetGuard.ps1" %*
