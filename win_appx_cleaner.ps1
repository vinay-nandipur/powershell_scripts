# This script helps cleanup Windows Appx Apps and also runs sysprep, vm will shutdown and will be ready to use as a latest template.

Import-Module AppX
Import-Module Dism

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f

reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /f

$AppXApps = Get-AppxPackage -AllUser | select Name

foreach ($App in $AppXApps) {
   Get-AppxPackage -Name "*$App*" | Remove-AppxPackage
   Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$App*" | Remove-AppxProvisionedPackage -Online
   }

Get-AppxPackage -AllUsers | where-object {$_.name –notlike '*store*'} | Remove-AppxPackage

Get-appxprovisionedpackage –online | where-object {$_.packagename –notlike '*store*'} | Remove-AppxProvisionedPackage -online

c:\Windows\System32\Sysprep\.\sysprep.exe /generalize /oobe /mode:vm
