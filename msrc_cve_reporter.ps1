#Defining needed variables

$dt2 = (get-date -Uformat %Y-%b).ToString()
$os_name = Get-CimInstance Win32_OperatingSystem | Select Caption  -ExpandProperty Caption
$os_name = $os_name.Split("") | Where-Object {$_ -notmatch "microsoft|standard|datacenter|enterprise"}
$os_name = & {Write-Host -NoNewline $os_name} 6>&1
$ami_id = (Invoke-RestMethod -uri http://169.254.169.254/latest/dynamic/instance-identity/document | Select-Object -ExpandProperty imageId).trim()
$instance_id = (Invoke-RestMethod -uri http://169.254.169.254/latest/dynamic/instance-identity/document | Select-Object -ExpandProperty instanceId).trim()

# Install MSRCSecurityUpdates Module

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module MSRCSecurityUpdates -Confirm:$False -Force

# Import MSRCSecurityUpdates Module

Import-Module MSRCSecurityUpdates

# Configure API Key

Set-MSRCApiKey -ApiKey "<api-key>" -Verbose

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

Get-MsrcSecurityBulletinHtml @CVRFHtmlProperties -Verbose | Out-File c:\temp\MSRCSecurityUpdates-$ami_id-$instance_id-$dt2.html

aws s3 cp c:\temp\MSRCSecurityUpdates-$dt2.html s3://<bucket-name>
aws s3 cp c:\temp\MSRCVulnerabilities-$dt2.html s3://<bucket-name>
aws s3 cp c:\temp\MSRCSecurityUpdates-$ami_id-$instance_id-$dt2.html s3://<bucket-name>


# Verify status of Security patches

$latest_kb_list = Get-MsrcCvrfAffectedSoftware -Vulnerability $CVRFDoc.Vulnerability -ProductTree $CVRFDoc.ProductTree | Where-Object {$_.FullProductName -match $os_name} | Select KBArticle -ExpandProperty KBArticle | select ID -ExpandProperty ID | Get-Unique

$installed_kb_list = Get-HotFix | select HotFixID -ExpandProperty HotFixID

Foreach ($kb in $latest_kb_list)
{

if(-not {$installed_kb_list -Contains $kb})

{

 Write-Output "KB $KB should be patched ASAP!" | out-file -Append c:\temp\security_patches_status.txt

}

else

{

 Write-Output "KB $KB patched as per $dt2 MSRC Security Updates" | out-file -Append C:\Temp\security_patches_status_all.txt

}


}

Get-Content C:\Temp\security_patches_status_all.txt | Select-Object -Unique | Out-File C:\Temp\security_patches_status.txt
