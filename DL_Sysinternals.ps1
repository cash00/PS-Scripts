
#Import-Module BitsTransfer

$DLRoot = "C:\temp"

$url1 = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$url2 = "https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip"
$url3 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/ok-sysmon.xml"
$url4 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/zabbix_agentd.win.conf"
$url5 = "https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-i386.zip"
$url6 = "https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-amd64.zip"

$output1 = "$DLRoot\SysinternalsSuite.zip"
$output2 = "$DLRoot\SysinternalsSuite-Nano.zip"
$output3 = "$DLRoot\ok-sysmon.xml"
$output4 = "$DLRoot\zabbix_agentd.win.conf"
$output5 = "$DLRoot\zabbix_agents-4.0.0-win-i386.zip"
$output6 = "$DLRoot\zabbix_agents-4.0.0-win-amd64.zip"

$start_time = Get-Date

If ((Test-Path $DLRoot) -eq $false)
{
    New-Item $DLRoot -type directory
}

<#
#Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url1 -Destination $output1 -Priority High -Asynchronous
Start-BitsTransfer -Source $url2 -Destination $output2 -Priority High -Asynchronous
Start-BitsTransfer -Source $url3 -Destination $output3 -Priority High -Asynchronous
#>

If ((Test-Path $output1) -eq $false)
{
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url1, $output1)
}

If ((Test-Path $output2) -eq $false)
{
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url2, $output2)
#$wc.DownloadFileAsync($url2, $output2)
}

#OR

If ((Test-Path $output3) -eq $false)
{
(New-Object System.Net.WebClient).DownloadFileAsync($url3, $output3)
}

If ((Test-Path $output4) -eq $false)
{
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url4, $output4)
}

If ((Test-Path $output5) -eq $false)
{
(New-Object System.Net.WebClient).DownloadFileAsync($url5, $output5)
}

If ((Test-Path $output6) -eq $false)
{
(New-Object System.Net.WebClient).DownloadFileAsync($url6, $output6)
}

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

#Get-BitsTransfer -AllUsers | Where-Object { $_.JobState -like "TransientError" } | Remove-BitsTransfer

If ((Test-Path $output1) -eq $true)
{
    Write-Output "OK "$output1" !!!"
}

If ((Test-Path $output2) -eq $true)
{
    Write-Output "OK "$output2" !!!"
}

If ((Test-Path $output3) -eq $true)
{
    Write-Output "OK "$output3" !!!"
}

If ((Test-Path $output4) -eq $true)
{
    Write-Output "OK "$output4" !!!"
}

If ((Test-Path $output5) -eq $true)
{
    Write-Output "OK "$output5" !!!"
}

If ((Test-Path $output6) -eq $true)
{
    Write-Output "OK "$output6" !!!"
}