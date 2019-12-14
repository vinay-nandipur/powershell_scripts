#Defining needed variables

$dt2 = (get-date -Uformat %Y-%b).ToString()
$os_name = Get-CimInstance Win32_OperatingSystem | Select Caption  -ExpandProperty Caption
$os_name = $os_name.Split("") | Where-Object {$_ -notmatch "microsoft|standard|datacenter|enterprise"}
$os_name = & {Write-Host -NoNewline $os_name} 6>&1

# Install MSRCSecurityUpdates Module

if(-not {Get-Module MsrcSecurityUpdates})
 {
     Install-Module MSRCSecurityUpdates -Confirm:$False -Force
 }

# Import MSRCSecurityUpdates Module

Import-Module MSRCSecurityUpdates

# Configure API Key

Set-MSRCApiKey -ApiKey "<API_Key>" -Verbose

# Get CVE Reports as HTML report for current month

Get-MsrcCvrfDocument -ID $dt2 -Verbose | Get-MsrcSecurityBulletinHtml -Verbose | Out-File c:\temp\MSRCSecurityUpdates-$dt2.html

Get-MsrcCvrfDocument -ID $dt2 -Verbose | Get-MsrcVulnerabilityReportHtml -Verbose | Out-File c:\temp\MSRCVulnerabilities-$dt2.html

# generate CVE summary report by filtering the affected product, which will match the currently installed OS

$CVRFDoc = Get-MsrcCvrfDocument -ID $dt2 -Verbose

$cve_list = Get-MsrcCvrfAffectedSoftware -Vulnerability $CVRFDoc.Vulnerability -ProductTree $CVRFDoc.ProductTree | Where-Object {$_.FullProductName -match $os_name} | Select CVE -ExpandProperty CVE | Where-Object {$_ -notmatch "ADV"} | Get-Unique

$CVRFHtmlProperties = @{
   Vulnerability = $CVRFDoc.Vulnerability | Where-Object {$_.CVE -in $cve_list}
   ProductTree = $CVRFDoc.ProductTree
   DocumentTracking = $CVRFDoc.DocumentTracking
   DocumentTitle = $CVRFDoc.DocumentTitle
}

Get-MsrcSecurityBulletinHtml @CVRFHtmlProperties -Verbose | Out-File c:\temp\MSRCSecurityUpdates-local-$dt2.html

# Verify status of Security patches

$latest_kb_list = Get-MsrcCvrfAffectedSoftware -Vulnerability $CVRFDoc.Vulnerability -ProductTree $CVRFDoc.ProductTree | Where-Object {$_.FullProductName -match $os_name} | Select KBArticle -ExpandProperty KBArticle | select ID -ExpandProperty ID | Get-Unique

$installed_kb_list = Get-HotFix | select HotFixID -ExpandProperty HotFixID

Foreach ($kb in $latest_kb_list)
{
 if ($installed_kb_list -Contains $kb)

 {

    Write-Output "KB $KB patched as per $dt2 MSRC Security Updates" | out-file -Append c:\temp\security_patches_status.txt

 }


 else

 {

   Write-Output "KB $KB should be patched ASAP!" | out-file -Append c:\temp\security_patches_status.txt

 }


}
