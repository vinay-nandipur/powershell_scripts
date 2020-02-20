Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PsIni -Confirm:$False -Force

$path = "$ENV:systemRoot\System32\GroupPolicy\Machine\Scripts\Shutdown"
if (-not (Test-Path $path)) {
   New-Item -path $path -itemType Directory
}

echo "`$packer_user = Get-LocalUser -Name 'user1'" | Out-File -FilePath "C:\Admin\Utilities\delete-packer-user.ps1" -Append
echo "if(`$packer_user) { Remove-LocalUser -Name 'user1' }" | Out-File -FilePath "C:\Admin\Utilities\delete-packer-user.ps1" -Append


Get-Content "C:\Admin\Utilities\delete-packer-user.ps1" | Out-File -filePath "$path\delete-packer-user.ps1" -encoding ascii

# Add script to Group Policy through the Registry
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\0',
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0\0' |
 ForEach-Object {
   if (-not (Test-Path $_)) {
       New-Item -path $_ -force
   }
 }

'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0',
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0' |
 ForEach-Object {
   New-ItemProperty -path "$_" -name DisplayName -propertyType String -value "Local Group Policy"
   New-ItemProperty -path "$_" -name FileSysPath -propertyType String -value "$ENV:systemRoot\System32\GroupPolicy\Machine"
   New-ItemProperty -path "$_" -name GPO-ID -propertyType String -value "LocalGPO"
   New-ItemProperty -path "$_" -name GPOName -propertyType String -value "Local Group Policy"
   New-ItemProperty -path "$_" -name PSScriptOrder -propertyType DWord -value 2
   New-ItemProperty -path "$_" -name SOM-ID -propertyType String -value "Local"
 }
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\0',
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0\0' |
 ForEach-Object {
   New-ItemProperty -path "$_" -name Script -propertyType String -value 'delete-packer-user.ps1'
   New-ItemProperty -path "$_" -name Parameters -propertyType String -value ''
   New-ItemProperty -path "$_" -name IsPowershell -propertyType DWord -value 1
   New-ItemProperty -path "$_" -name ExecTime -propertyType QWord -value 0
 }

$scriptsConfig = @{
   StartExecutePSFirst = 'true'
   EndExecutePSFirst =   'true'
}
$Shutdown = @{
   '0CmdLine' =    'C:\Windows\System32\GroupPolicy\Machine\Scripts\delete-packer-user.ps1'
   '0Parameters' = ''
}
$newIniContent = [ordered] @{
   ScriptsConfig = $scriptsConfig
   Shutdown =       $Shutdown
}
$newIniContent | Out-IniFile -filePath C:\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini -encoding Unicode -force
