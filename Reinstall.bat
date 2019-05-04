@echo off
start /B powershell.exe -ExecutionPolicy Unrestricted -command "& { Start-Process powershell.exe -NoNewWindow -ArgumentList '-ExecutionPolicy Unrestricted -file Reinstall.ps1'}"
exit