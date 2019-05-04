@echo off
start /B powershell.exe -ExecutionPolicy Unrestricted -command "& { Start-Process powershell.exe -NoNewWindow -ArgumentList '-ExecutionPolicy Unrestricted -file Uninstall.ps1'}"
exit