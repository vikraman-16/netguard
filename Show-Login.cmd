@echo off
rem Shows the NetGuard dashboard login (asks for admin rights). Use -ResetPassword for a new password.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-NetGuard.ps1" -ShowLogin %*
