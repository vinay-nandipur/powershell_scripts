#To view expired certs
#Invoke-Command -ComputerName $env:COMPUTERNAME {Get-ChildItem -Path cert:\* ` -Recurse -ExpiringInDays 0}

# Remove old Remote Desktop SSL Certificate
Get-ChildItem -Path cert:\LocalMachine\'Remote Desktop' | Remove-Item

#generate new SSL certificate
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My

#Create rootStore Object
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList Root, LocalMachine

#Set MaxAllowed
$rootStore.Open("MaxAllowed")

#add new SSL certificate to rootStore 
$rootStore.Add($cert)

#close rootStore object
$rootStore.Close()

#get terminal server rdp general setting in a variable
$tsgs = gwmi -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"

#get the thumbprint of new SSL certificate in a variable
$thumb = (gci -path cert:/LocalMachine/My | select -first 1).Thumbprint

#using swmi add the thumbprint of new certificate to tsgs
swmi -path $tsgs.__path -argument @{SSLCertificateSHA1Hash="$thumb"}
