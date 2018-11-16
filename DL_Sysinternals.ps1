
Import-Module BitsTransfer

$DLRoot = "C:\temp\DL_Sysinternals"

$url1 = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$url2 = "https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip"
$url3 = "https://github.com/cash00/PS-Scripts/blob/master/ok-sysmon.xml"

$output1 = "$DLRoot\SysinternalsSuite.zip"
$output2 = "$DLRoot\SysinternalsSuite-Nano.zip"
$output3 = "$DLRoot\ok-sysmon.xml"

$start_time = Get-Date

If ((Test-Path $DLRoot) -eq $false)
{
    New-Item $DLRoot -type directory
}

#Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url1 -Destination $output1 -Priority High #-Asynchronous
Start-BitsTransfer -Source $url2 -Destination $output2 -Priority High #-Asynchronous
Start-BitsTransfer -Source $url3 -Destination $output3 -Priority High #-Asynchronous

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

Get-BitsTransfer -AllUsers | Where-Object { $_.JobState -like "TransientError" } | Remove-BitsTransfer

If ((Test-Path $output1) -eq $false)
{
    Write-Output "No Have " $output1" !!!"
    exit
}

If ((Test-Path $output2) -eq $false)
{
    Write-Output "No Have" $output2" !!!"
    exit
}

If ((Test-Path $output3) -eq $false)
{
    Write-Output "No Have" $output3" !!!"
    exit
}








