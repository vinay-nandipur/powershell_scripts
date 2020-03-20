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
$Thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME  -CertStoreLocation Cert:\LocalMachine\My).Thumbprint

# Create WinRM HTTPS listener.
$Cmd = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$env:COMPUTERNAME ""; CertificateThumbprint=""$Thumbprint""}"
cmd.exe /C $Cmd


# Create/coonfigure WINRM user
cmd.exe /c net user /add winrmuser1 password123#
cmd.exe /c net localgroup administrators winrmuser1 /add


# RDP
#cmd.exe /c netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
cmd.exe /c netsh advfirewall firewall add rule name="Open Port 799" dir=in action=allow protocol=TCP localport=799
cmd.exe /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f



# Test winrm SSL connection

$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions

If ($httpsResult)
{
    Write-Host "WINRM HTTPS Connection Enabled"
}
Else
{
    Write-Host "Unable to establish an HTTPS remoting session."
}
Write-Host "WINRM SSL PS Remoting has been successfully configured."
