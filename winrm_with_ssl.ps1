Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force

Enable-PSRemoting -SkipNetworkProfileCheck -Force

# Initial WinRM config

cmd.exe /c winrm quickconfig -q
cmd.exe /c winrm set "winrm/config/service" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/client" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/client/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{CredSSP="true"}'
cmd.exe /c winrm set "winrm/config/client/auth" '@{CredSSP="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{Certificate="true"}'
cmd.exe /c winrm set "winrm/config/client/auth" '@{Certificate="true"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{AllowRemoteShellAccess="true"}'


$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName "$env:COMPUTERNAME"
Export-Certificate -Cert $Cert -FilePath C:\Users\Administrator\Desktop\cert
Get-ChildItem WSMan:\Localhost\listener | Where -Property Keys -eq "Transport=HTTP" | Remove-Item -Recurse
Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse


New-NetFirewallRule -Name "WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Profile "Any" -Action "Allow" -Direction "Inbound" -LocalPort 5986 -Protocol "TCP"

Set-Item WSMan:\localhost\Service\EnableCompatibilityHttpsListener -Value true
Import-Certificate -Filepath "C:\Users\Administrator\Desktop\cert" -CertStoreLocation "Cert:\LocalMachine\Root"


cmd.exe /c net user /add clintbarton 4231nTult@423
cmd.exe /c net localgroup administrators clintbarton /add
cmd.exe /c wmic useraccount where "name='clintbarton'" set PasswordExpires=FALSE

#$password = ConvertTo-SecureString "4231nTult@423" -AsPlainText -Force
#$Cred = New-Object System.Management.Automation.PSCredential ("clintbarton", $password)

$thumb = $Cert.Thumbprint


$add_thumb1 = "winrm set winrm/config/service @{CertificateThumbprint=""$thumb""}"

cmd.exe /c $add_thumb1

$add_thumb2 = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$env:COMPUTERNAME""; CertificateThumbprint=""$thumb""}"

cmd.exe /c $add_thumb2

$add_thumb3 = "winrm create winrm/config/service/certmapping?Issuer=$thumb+Subject=clintbarton@localhost+URI=* @{Username=""clintbarton"";Password=""4231nTult@423""}"
cmd.exe /c $add_thumb3


# Configure WinRM settings.

cmd.exe /c winrm set "winrm/config" '@{MaxEnvelopeSizekb="1024"}'
cmd.exe /c winrm set "winrm/config" '@{MaxTimeoutms="180000000"}'
cmd.exe /c winrm set "winrm/config" '@{MaxBatchItems="64000"}'
cmd.exe /c winrm set "winrm/config/client" '@{NetworkDelayms="45000"}'
cmd.exe /c winrm set "winrm/config/service" '@{MaxConcurrentOperationsPerUser="6000"}'
cmd.exe /c winrm set "winrm/config/service" '@{EnumerationTimeoutms="9800000"}'
cmd.exe /c winrm set "winrm/config/service" '@{MaxConnections="1500"}'
cmd.exe /c winrm set "winrm/config/service" '@{MaxPacketRetrievalTimeSeconds="900"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{IdleTimeout="21600000"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxConcurrentUsers="60"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxShellRunTime="2147483647"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxProcessesPerShell="90"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxMemoryPerShellMB="3072"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxShellsPerUser="3000"}'

cmd.exe /c net stop winrm
cmd.exe /c sc config winrm start= auto
cmd.exe /c net start winrm


#$skip_check = New-PsSessionOption –SkipCACheck -SkipCNCheck
#Enter-PSSession -ComputerName $env:COMPUTERNAME  -Credential $Cred -UseSSL -SessionOption $skip_check
