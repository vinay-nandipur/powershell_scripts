Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force


# Enable PowerShell remoting.
Enable-PSRemoting -Force

# Create firewall rule for WinRM. The default HTTPS port is 5986.
New-NetFirewallRule -Name "WinRM HTTPS" `
                   -DisplayName "WinRM HTTPS" `
                   -Enabled True `
                   -Profile "Any" `
                   -Action "Allow" `
                   -Direction "Inbound" `
                   -LocalPort 5986 `
                   -Protocol "TCP"

# Create new self-signed-certificate to be used by WinRM.
$Thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My).Thumbprint

# Create WinRM HTTPS listener.
cmd.exe /c winrm quickconfig -q
cmd.exe /c winrm set "winrm/config/service" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/client" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/client/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{CredSSP="true"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{AllowRemoteShellAccess="true"}'
$Cmd_winrm_ssl = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$env:COMPUTERNAME ""; CertificateThumbprint=""$Thumbprint""}"
cmd.exe /c $Cmd_winrm_ssl
cmd.exe /c net stop winrm
cmd.exe /c sc config winrm start= auto
cmd.exe /c net start winrm

# Create/coonfigure WINRM user
cmd.exe /c net user /add testuser1 pass123
cmd.exe /c net localgroup administrators testuser1 /add
cmd.exe /c wmic useraccount where "name='testuser1'" set PasswordExpires=FALSE


# RDP
cmd.exe /c netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
cmd.exe /c netsh advfirewall firewall add rule name="Open Port 4489" dir=in action=allow protocol=TCP localport=4489
cmd.exe /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Test winrm SSL connection

$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions

If ($httpsResult)
{
    $test1 = write-output "WINRM HTTPS Connection Enabled and WINRM SSL PS Remoting has been successfully configured."
    $test1 | Tee-Object -file "c:\Windows\Temp\winrm-ssl-test.log"
}
Else
{
    $test2 = write-output "Unable to establish an HTTPS remoting session."
    $test2 | Tee-Object -file "c:\Windows\Temp\winrm-ssl-test.log"
}
