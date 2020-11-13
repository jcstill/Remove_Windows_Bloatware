function force-mkdir($path) {
	if (!(Test-Path $path)) {
		#Write-Host "-- Creating full path to: " $path -ForegroundColor White -BackgroundColor DarkGreen
		New-Item -ItemType Directory -Force -Path $path
	}
}
function Takeown-Registry($key) {
	# TODO does not work for all root keys yet
	switch ($key.split('\')[0]) {
		"HKEY_CLASSES_ROOT" {
			$reg = [Microsoft.Win32.Registry]::ClassesRoot
			$key = $key.substring(18)
		}
		"HKEY_CURRENT_USER" {
			$reg = [Microsoft.Win32.Registry]::CurrentUser
			$key = $key.substring(18)
		}
		"HKEY_LOCAL_MACHINE" {
			$reg = [Microsoft.Win32.Registry]::LocalMachine
			$key = $key.substring(19)
		}
	}

	# get administraor group
	$admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
	$admins = $admins.Translate([System.Security.Principal.NTAccount])

	# set owner
	$key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
	$acl = $key.GetAccessControl()
	$acl.SetOwner($admins)
	$key.SetAccessControl($acl)

	# set FullControl
	$acl = $key.GetAccessControl()
	$rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
	$acl.SetAccessRule($rule)
	$key.SetAccessControl($acl)
}
function Takeown-File($path) {
	takeown.exe /A /F $path
	$acl = Get-Acl $path

	# get administraor group
	$admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
	$admins = $admins.Translate([System.Security.Principal.NTAccount])

	# add NT Authority\SYSTEM
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
	$acl.AddAccessRule($rule)

	Set-Acl -Path $path -AclObject $acl
}
function Takeown-Folder($path) {
	Takeown-File $path
	foreach ($item in Get-ChildItem $path) {
		if (Test-Path $item -PathType Container) {
			Takeown-Folder $item.FullName
		} else {
			Takeown-File $item.FullName
		}
	}
}

clear
Write-Host "Jacob's Bloatware Uninstaller"
Write-Host "v1.2"
Write-Host "If there are apps that sould be added to this remover please email jacobcstill@gmail.com"
Write-Host ""
(New-Object -ErrorAction SilentlyContinue System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/install_wim_tweak.zip", "$PSScriptRoot\install_wim_tweak.zip")
Expand-Archive -ErrorAction SilentlyContinue -LiteralPath "$PSScriptRoot\install_wim_tweak.zip" -DestinationPath "C:\Windows\system32\"
rm "$PSScriptRoot\install_wim_tweak.zip"


Write-Host "System Settings:"
Write-Host ""
$prompt = Read-Host 'Disable Windows Error Reporting? [y/n] '
if ($prompt -eq 'y') {
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f'
}
Write-Host ""
$prompt = Read-Host 'Disable Forced Updates? [y/n] '
if ($prompt -eq 'y') {
	force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3
	force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
	Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
	$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
	$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
	takeown /F "$env:WinDIR\System32\MusNotification.exe"
	icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
	takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
	icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"
}
Write-Host ""
$prompt = Read-Host 'Disable License Checking? [y/n] '
if ($prompt -eq 'y') {
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f'
}
Write-Host ""
$prompt = Read-Host 'Disable Windows Sync? [y/n] '
if ($prompt -eq 'y') {
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f'
}
Write-Host ""
$prompt = Read-Host 'Disable Windows Tips and Spotlight? [y/n] '
if ($prompt -eq 'y') {
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f'
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
	# Reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -ErrorAction SilentlyContinue -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}
Write-Host ""
$prompt = Read-Host 'Disable Windows Telemetry? [y/n] '
if ($prompt -eq 'y') {
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater"
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Autochk\Proxy"
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
	Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
	# Office 2016 / 2019
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue
	cmd.exe /c 'sc delete DiagTrack'
	cmd.exe /c 'sc delete dmwappushservice'
	cmd.exe /c 'sc delete WerSvc'
	cmd.exe /c 'sc delete OneSyncSvc'
	cmd.exe /c 'sc delete MessagingService'
	cmd.exe /c 'sc delete wercplsupport'
	cmd.exe /c 'sc delete PcaSvc'
	cmd.exe /c 'sc config wlidsvc start=demand'
	cmd.exe /c 'sc delete wisvc'
	cmd.exe /c 'sc delete RetailDemo'
	cmd.exe /c 'sc delete diagsvc'
	cmd.exe /c 'sc delete shpamsvc '
	cmd.exe /c 'sc delete TermService'
	cmd.exe /c 'sc delete UmRdpService'
	cmd.exe /c 'sc delete SessionEnv'
	cmd.exe /c 'sc delete TroubleshootingSvc'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)'
	cmd.exe /c 'for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)'
	cmd.exe /c 'sc delete diagnosticshub.standardcollector.service'
	cmd.exe /c 'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f'
	cmd.exe /c 'reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f'
	Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS")
	Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost")
	Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost")
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "HKLM:\SYSTEM\CurrentControlSet\Services\DPS"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "HKLM:\SYSTEM\CurrentControlSet\Services\WdiSystemHost"
	Write-Host ""
	Write-Host "READ ME!!!!!" -ForegroundColor yellow
	Write-Host 'Press Win+R, type regedit, press enter, and navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.'
	Write-Host 'Here we need to locate the following keys:'
	Write-Host ' + DPS'
	Write-Host ' + WdiServiceHost'
	Write-Host ' + WdiSystemHost'
	Write-Host 'These keys have messed up permissions and we need to delete them manually.'
	Write-Host 'To delete them, we must fix them, heres how to do it:'
	Write-Host ' - Right click the key and select Permissions'
	Write-Host ' - Click Advanced'
	Write-Host ' - Next to "Owner:" click change'
	Write-Host ' - Enter your username'
	Write-Host ' - Click ok'
	Write-Host ' - Check "Replace owner on subcontainers and objects"'
	Write-Host ' - Check "Replace all child object permission entries with inheritable permission entries from this object"'
	Write-Host ' - If inheritance is enabled, disable it and convert to explicit permissions'
	Write-Host ' - Click apply'
	Write-Host ' - Click the top permission'
	Write-Host ' - Click remove until all the permission entries are gone'
	Write-Host ' - Click add'
	Write-Host ' - Click "Select a Proncipal" '
	Write-Host ' - Enter your username'
	Write-Host ' - Click ok'
	Write-Host ' - Check "Full control"'
	Write-Host ' - Click ok'
	Write-Host ' - Click ok'
	Write-Host ' - Click ok'
	Write-Host ' - Right click the key and select delete'
	Write-Host ' - Click yes'
	Write-Host 'Repeat for all 3 keys and you are done.'
	Write-Host "READ ME!!!!!" -ForegroundColor yellow
	
}
Write-Host ""
$prompt = Read-Host 'Disable Windows Scheduled Tasks that may report data? [y/n] '
if ($prompt -eq 'y') {
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable'
	cmd.exe /c 'del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" '
}









Write-Host ""
Write-Host ""
Write-Host "System Apps:"
Write-Host ""
$prompt = Read-Host 'Disable Cortana? [y/n] '
if ($prompt -eq 'y') {
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
	}
	Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
	Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f'
}
Write-Host ""
$prompt = Read-Host 'Uninstall Windows Defender? [y/n] '
if ($prompt -eq 'y') {
	$tasks = @(
		"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
		"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
		"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
		"\Microsoft\Windows\Windows Defender\Windows Defender Verification"
	)
	foreach ($task in $tasks) {
		$parts = $task.split('\')
		$name = $parts[-1]
		$path = $parts[0..($parts.length-2)] -join '\'
		Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
	}
	force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
	force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1
	Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3
	Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""
	Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f'
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f'
	cmd.exe /c 'reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f'
	cmd.exe /c 'reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f'
	install_wim_tweak /o /c Windows-Defender /r
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f'
}
Write-Host ""
$prompt = Read-Host 'Uninstall Windows Store? (WARNING THIS IS PERMANENT) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
	install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
	install_wim_tweak /o /c Microsoft-Windows-Store /r
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f'
	cmd.exe /c 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f'
	cmd.exe /c 'sc delete PushToInstall'
}
Write-Host ""
$prompt = Read-Host 'Uninstall Microsoft Edge? [y/n] '
if ($prompt -eq 'y') {
	taskkill /F /IM browser_broker.exe
	taskkill /F /IM RuntimeBroker.exe
	taskkill /F /IM MicrosoftEdge.exe
	taskkill /F /IM MicrosoftEdgeCP.exe
	taskkill /F /IM MicrosoftEdgeSH.exe
	mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK -ErrorAction SilentlyContinue
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
	Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
}
Write-Host ""
$prompt = Read-Host 'Remove System Restore? [y/n] '
if ($prompt -eq 'y') {
	Disable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
	vssadmin delete shadows /all /Quiet
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
	schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
}
Write-Host ""
$prompt = Read-Host 'Remove Hello Face? [y/n] '
if ($prompt -eq 'y') {
	Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable'
}
Write-Host ""
$prompt = Read-Host 'Remove Contact Support, Feedback, Assist, Connect, and Get Started? [y/n] '
if ($prompt -eq 'y') {
	install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
	Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
	Get-AppxPackage -AllUsers *feedback* | remove-appxpackage
	Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
	install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
	Get-AppxPackage -AllUsers *getstarted* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Remove OneDrive? [y/n] '
if ($prompt -eq 'y') {
	taskkill.exe /F /IM "OneDrive.exe"
	taskkill.exe /F /IM "explorer.exe"
	if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
		& "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
	}
	if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
		& "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
	}
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
	# check if directory is empty before removing:
	If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
		Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
	}
	force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
	Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
	New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
	mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
	Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
	mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
	Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
	Remove-PSDrive "HKCR"
	reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
	reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
	reg unload "hku\Default"
	Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
	Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
	Start-Process "explorer.exe"
	Start-Sleep 10
	foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
		Takeown-Folder $item.FullName -ErrorAction SilentlyContinue
		Remove-Item -Recurse -Force $item.FullName -ErrorAction SilentlyContinue
	}
}
Write-Host ""
Write-Host ""
Write-Host "Other Bloatware and Advertizing Apps:"
Write-Host ""
$prompt = Read-Host 'Uninstall Groove Music, Movies, and TV Apps? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
	Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
}
Write-Host ""
$prompt = Read-Host 'Uninstall Xbox App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
	cmd.exe /c 'sc delete XblAuthManager'
	cmd.exe /c 'sc delete XblGameSave'
	cmd.exe /c 'sc delete XboxNetApiSvc'
	cmd.exe /c 'sc delete XboxGipSvc'
	cmd.exe /c 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable'
	cmd.exe /c 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f'
}
Write-Host ""
$prompt = Read-Host 'Uninstall Sticky Notes App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Maps App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
	cmd.exe /c 'sc delete MapsBroker'
	cmd.exe /c 'sc delete lfsvc'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable'
	cmd.exe /c 'schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable'
}
Write-Host ""
$prompt = Read-Host 'Uninstall Alarms App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall People App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Calendar App and Mail App? (Packaged Together) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *communicationsapps* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Phone Apps? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *phone* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Messaging App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *messaging* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall OneNote? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *onenote* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Photos? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *photos* | remove-appxpackage
	Write-Host ""
$prompt = Read-Host 'Would you Like to install Windows 7 Style Photo Viewer? (Reccommended) [y/n] '
	if ($prompt -eq 'y') {
		Start-Process '.\ioswpv.reg'
	}
}
Write-Host ""
$prompt = Read-Host 'Uninstall Camera App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *camera* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Bing Apps? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *bing* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Calculator App? (Not Recomended) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *calculator* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Recording App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *soundrecorder* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall New Paint App(s)? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *mspaint* | remove-appxpackage
	Write-Host "READ ME!!!!!" -ForegroundColor yellow
	Write-Host "Open a CMD window in admin mode and paste:"
	Write-Host ""
	Write-Host -NoNewline 'for /f "tokens=1* delims=" %I in ('
	Write-Host -NoNewline "'"
	Write-Host -NoNewline ' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" '
	Write-Host -NoNewline "'"
	Write-Host ') do (reg delete "%I" /f )'
	Write-Host -NoNewline 'for /f "tokens=1* delims=" %I in ('
	Write-Host -NoNewline "'"
	Write-Host -NoNewline ' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" '
	Write-Host -NoNewline "'"
	Write-Host ') do (reg delete "%I" /f )'
	Write-Host "READ ME!!!!!" -ForegroundColor yellow
	Get-AppxPackage -AllUsers *3d* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall App Connector? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *appconnector* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall App Installer? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *appinstaller* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall MS Office Hub App? (Does not remove office utilities ie. Word, Excel, etc.) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *officehub* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Skype App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *skypeapp* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Solitaire App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *solitaire* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Wallet App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *wallet* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Wifi App? (Does Not affect wireless connectivity) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *connectivitystore* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Mobile Plans App? (Does Not affect wireless connectivity) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *oneconnect* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Sway App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *sway* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Holographic App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *holographic* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall ScreenSketch App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *ScreenSketch* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Mixed Reality Viewer? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *MixedReality* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall MS Advertizing App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *Advertising* | remove-appxpackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Candy Crush App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *king.com.CandyCrushSodaSaga* | Remove-AppxPackage
}
Write-Host ""
$prompt = Read-Host 'Uninstall Twitter App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -AllUsers *Twitter* | Remove-AppxPackage
}
Write-Host ""
rm "C:\Windows\system32\install_wim_tweak.exe"
$prompt = Read-Host 'Finished! Would you like to reboot now? [y/n] '
if ($prompt -eq 'y') {
	Restart-Computer
}