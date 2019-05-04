clear
echo "Jacob's Bloatware Reinstaller"
echo "v1.0"
echo "If there are apps that sould be added to this remover please email jacob@smpl.co"
echo ''
$prompt = Read-Host 'Install 3D Builder App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *3dbuilder* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Alarms App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *alarms* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install App Connector? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *appconnector* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install App Installer? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *appinstaller* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Calendar App and Mail App? (Packaged Together) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *communicationsapps* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Calculator App?[y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *calculator* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Camera App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *camera* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Feedback App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *feedback* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install MS Office Hub App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *officehub* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Get Started App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *getstarted* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Skype App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *skypeapp* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Groove Music App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *zunemusic* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Maps App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *maps* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Messaging App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *messaging* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Solitaire App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *solitaire* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Wallet App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *wallet* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Wifi App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *connectivitystore* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Bing Finance? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *bingfinance* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Movies and TV App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *zunevideo* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Bing News? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *bingnews* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install OneNote? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *onenote* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Mobile Plans App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *oneconnect* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install New Paint App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *mspaint* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install People App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *people* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Phone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *commsphone* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install WindowsPhone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *windowsphone* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Photos? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *photos* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	$prompt = Read-Host 'Would you Like to remove Windows 7 Style Photo Viewer? [y/n] '
	if ($prompt -eq 'y') {
		Start-Process '.\Remove Old Style Windows Photo Viewer.reg'
	}
}
$prompt = Read-Host 'Install Bing Sports App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *bingsports* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Sticky Notes App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *sticky* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Sway App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *sway* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install 3D Viwer App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *3d* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Recording App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *soundrecorder* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Bing Weather App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *bingweather* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Holographic App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *holographic* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Xbox App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *xbox* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install ScreenSketch App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *ScreenSketch* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Your Phone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *YourPhone* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Mixed Reality Viewer? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *MixedReality* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install MS Advertizing App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *Advertising* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Candy Crush App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -allusers *king.com.CandyCrushSodaSaga* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install Twitter App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -allusers *Twitter* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
echo.
$prompt = Read-Host 'Install Windows Store? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage -allusers *windowsstore* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install All Phone Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *phone* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install All Bing Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *bing* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
$prompt = Read-Host 'Install All Groove Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage -allusers *zune* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
echo ''
echo "Finished! Please use Uninstall.bat to uninstall anything you may have accidntally Added."
pause
exit