
Write-Host -ForegroundColor Yellow "Disabling OLD SSL/TLS Versions"

$check_SSL2 = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
# Create Keys if not exist
if(!($check_SSL2))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

# Disable SSL 2.0 for client and server
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
}

$check_SSL3 = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
# Create Keys if not exist
if(!($check_SSL3))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"

# Disable SSL 3.0 for client and server
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
}

$check_TLS1 = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
# Create Keys if not exist
if(!($check_TLS1))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

# Disable TLS 1.0 for client and server
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
}

$check_TLS11 = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
# Create Keys if not exist
if(!($check_TLS11))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

# Disable TLS 1.1 for client and server
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name "Enabled" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
}

$check_TLS12 = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
# Create Keys if not exist
if(!($check_TLS12))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

# Enable TLS 1.2 for client and server SCHANNEL communications
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -name "Enabled" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -name "Enabled" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
}

Write-Host -ForegroundColor Green "Enabled only TLS 1.2"

Write-Host -ForegroundColor Yellow "Disabling weak Cyphers now"

$check_ciphers = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'

#Disabling Weak Cyphers
if(!($check_ciphers))
{
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -name "Enabled" -value 0 -PropertyType "Dword"

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -name "Enabled" -value 0 -PropertyType "Dword"
}

Write-Host -ForegroundColor Green "Finished disabling weak Cyphers.."

$check_cipher_order = get-itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\' | Select-Object -ExpandProperty Functions

#Setting the recommended cipher order
Write-Host -ForegroundColor Yellow "Adding Cipher Order to the System!"
if(!($check_cipher_order))
{
Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -name "Functions" -value "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_MD5,SSL_CK_RC4_128_WITH_MD5,SSL_CK_DES_192_EDE3_CBC_WITH_MD"
}

Write-Host -ForegroundColor Green "Finished ordering Cyphers.."

Write-Host -ForegroundColor Yellow "Securing .Net!"

$check_NET_Security = get-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' | Select-Object -ExpandProperty SchUseStrongCrypto
if(!($check_NET_Security))
{
#Setting the system to use the strong Crypto for x64 .Net (For 32-bit applications on 32-bit systems and 64-bit applications on x64-based systems)
new-itemproperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name "SchUseStrongCrypto" -value 1 -PropertyType "Dword"
}

$check_WOW_NET_Security = get-itemproperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' | Select-Object -ExpandProperty SchUseStrongCrypto

if(!($check_WOW_NET_Security))
{
#Setting the system to use the strong Crypto for x64 .Net (For 64-bit applications on x64-based systems:)
new-itemproperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name "SchUseStrongCrypto" -value 1 -PropertyType "Dword"
}

Write-Host -ForegroundColor Green "Secured .Net!.."
