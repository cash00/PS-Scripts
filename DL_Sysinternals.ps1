
#Import-Module BitsTransfer

$DLRoot = "C:\temp"

$url1 = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$url2 = "https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip"
$url3 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/ok-sysmon.xml"
$url4 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/zabbix_agentd.win.conf"
$url5 = "https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-i386.zip"
$url6 = "https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-amd64.zip"
$url7 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/IISAdministration.zip"
$url8 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/RDWebClientManagement.zip"
$url9 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/xPSDesiredStateConfiguration.zip"
$url10 = "https://raw.githubusercontent.com/cash00/PS-Scripts/master/xRemoteDesktopSessionHost.zip"


$output1 = "$DLRoot\SysinternalsSuite.zip"
$output2 = "$DLRoot\SysinternalsSuite-Nano.zip"
$output3 = "$DLRoot\ok-sysmon.xml"
$output4 = "$DLRoot\zabbix_agentd.win.conf"
$output5 = "$DLRoot\zabbix_agents-4.0.0-win-i386.zip"
$output6 = "$DLRoot\zabbix_agents-4.0.0-win-amd64.zip"
$output7 = "$DLRoot\IISAdministration.zip"
$output8 = "$DLRoot\RDWebClientManagement.zip"
$output9 = "$DLRoot\xPSDesiredStateConfiguration.zip"
$output10 = "$DLRoot\xRemoteDesktopSessionHost.zip"

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

If (((Test-Path $output6) -eq $false) -or ((Get-ChildItem $output6).Length -lt 1))
{
    $ln = Invoke-WebRequest -Uri $url6 -DisableKeepAlive -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    if ($ln.StatusCode -eq 200)
    {
        While ($ln.RawContentLength -ne (Get-ChildItem $output6 -ErrorAction SilentlyContinue).Length)
        {
            Remove-Item $output6 -Force -ErrorAction SilentlyContinue
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url6, $output6)
        }        
    }
}

If (((Test-Path $output7) -eq $false) -or ((Get-ChildItem $output7).Length -lt 1))
{
    $ln = Invoke-WebRequest -Uri $url7 -DisableKeepAlive -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    if ($ln.StatusCode -eq 200)
    {
        While ($ln.RawContentLength -ne (Get-ChildItem $output7 -ErrorAction SilentlyContinue).Length)
        {
            Remove-Item $output7 -Force -ErrorAction SilentlyContinue
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url7, $output7)
        }        
    }
}

If (((Test-Path $output8) -eq $false) -or ((Get-ChildItem $output8).Length -lt 1))
{
    $ln = Invoke-WebRequest -Uri $url8 -DisableKeepAlive -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    if ($ln.StatusCode -eq 200)
    {
        While ($ln.RawContentLength -ne (Get-ChildItem $output8 -ErrorAction SilentlyContinue).Length)
        {
            Remove-Item $output8 -Force -ErrorAction SilentlyContinue
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url8, $output8)
        }        
    }
}

If (((Test-Path $output9) -eq $false) -or ((Get-ChildItem $output9).Length -lt 1))
{
    $ln = Invoke-WebRequest -Uri $url9 -DisableKeepAlive -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    if ($ln.StatusCode -eq 200)
    {
        While ($ln.RawContentLength -ne (Get-ChildItem $output9 -ErrorAction SilentlyContinue).Length)
        {
            Remove-Item $output9 -Force -ErrorAction SilentlyContinue
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url9, $output9)
        }        
    }
}

If (((Test-Path $output10) -eq $false) -or ((Get-ChildItem $output10).Length -lt 1))
{
    $ln = Invoke-WebRequest -Uri $url10 -DisableKeepAlive -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    if ($ln.StatusCode -eq 200)
    {
        While ($ln.RawContentLength -ne (Get-ChildItem $output10 -ErrorAction SilentlyContinue).Length)
        {
            Remove-Item $output10 -Force -ErrorAction SilentlyContinue
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url10, $output10)
        }        
    }
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

If (((Test-Path $output6) -eq $true) -and ((Get-ChildItem $output6).Length -gt 1kb))
{
    Write-Output "OK "$output6" !!!"
}

If ((Test-Path $output7) -eq $true)
{
    Write-Output "OK "$output7" !!!"
}

If ((Test-Path $output8) -eq $true)
{
    Write-Output "OK "$output8" !!!"
}

If ((Test-Path $output9) -eq $true)
{
    Write-Output "OK "$output9" !!!"
}

If ((Test-Path $output10) -eq $true)
{
    Write-Output "OK "$output10" !!!"
}
