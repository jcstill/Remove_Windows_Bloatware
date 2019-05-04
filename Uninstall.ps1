clear
echo "Jacob's Bloatware Uninstaller"
echo "v1.0"
echo "If there are apps that sould be added to this remover please email jacob@smpl.co"
echo ''
$prompt = Read-Host 'Uninstall 3D Builder App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *3dbuilder* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Alarms App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *alarms* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall App Connector? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *appconnector* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall App Installer? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *appinstaller* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Calendar App and Mail App? (Packaged Together) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *communicationsapps* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Calculator App? (Not Recomended) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *calculator* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Camera App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *camera* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Feedback App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *feedback* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall MS Office Hub App? (Does not remove office utilities ie. Word, Excel, etc.) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *officehub* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Get Started App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *getstarted* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Skype App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *skypeapp* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Groove Music App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *zunemusic* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Maps App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *maps* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Messaging App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *messaging* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Solitaire App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *solitaire* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Wallet App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *wallet* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Wifi App? (Does Not affect wireless connectivity) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *connectivitystore* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Bing Finance? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *bingfinance* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Movies and TV App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *zunevideo* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Bing News? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *bingnews* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall OneNote? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *onenote* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Mobile Plans App? (Does Not affect wireless connectivity) [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *oneconnect* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall New Paint App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *mspaint* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall People App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *people* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Phone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *commsphone* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall WindowsPhone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *windowsphone* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Photos? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *photos* | remove-appxpackage
	$prompt = Read-Host 'Would you Like to install Windows 7 Style Photo Viewer? (Reccommended) [y/n] '
	if ($prompt -eq 'y') {
		Start-Process '.\Install Old Style Windows Photo Viewer.reg'
	}
}
$prompt = Read-Host 'Uninstall Bing Sports App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *bingsports* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Sticky Notes App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *sticky* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Sway App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *sway* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall 3D Viwer App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *3d* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Recording App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *soundrecorder* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Bing Weather App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *bingweather* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Holographic App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *holographic* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Xbox App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *xbox* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall ScreenSketch App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *ScreenSketch* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Your Phone App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *YourPhone* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Mixed Reality Viewer? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *MixedReality* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall MS Advertizing App? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *Advertising* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall Candy Crush App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage
}
$prompt = Read-Host 'Uninstall Twitter App? [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage *Twitter* | Remove-AppxPackage
}
echo.
$prompt = Read-Host 'Uninstall Windows Store? (WARNING THIS IS PERMANENT) [y/n] '
if ($prompt -eq 'y') {
	Get-AppxPackage *windowsstore* | Remove-AppxPackage
}
$prompt = Read-Host 'Uninstall All Phone Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *phone* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall All Bing Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *bing* | remove-appxpackage
}
$prompt = Read-Host 'Uninstall All Groove Apps? [y/n] '
if ($prompt -eq 'y') {
	get-appxpackage *zune* | remove-appxpackage
}
echo ''
echo "Finished! Please use App.Reinstall.bat to install anything you may have accidntally removed."
pause
exit