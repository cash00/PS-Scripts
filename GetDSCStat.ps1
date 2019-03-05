cls
Stop-Transcript

<#
Get-ExecutionPolicy -List
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
Get-ExecutionPolicy -List
#>

If ( [IntPtr]::Size * 8 -ne 64 )
{
    C:\Windows\SysNative\WindowsPowerShell\v1.0\PowerShell.exe -File $MyInvocation.MyCommand.Path
}
Else
{
$hostname = $env:computername
#$FQDNhostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

#$udd = $env:userdnsdomain
$compdomain = (gwmi win32_computersystem).Domain
$compver = (Get-WmiObject Win32_OperatingSystem).Version
$DNSSUF = Get-DnsClientGlobalSetting

$datetime = Get-Date -Format 'yyyyMMdd_HHmmss'
$gloc = Get-Location
$path = '\\'+$hostname+'\C$\temp'
$Script = $MyInvocation.MyCommand.Name.TrimEnd(".ps1")

if($Script -eq "")
{
    $Script = "GetDSCStat" #<REPLACE WITH THE SCRIPT NAME>
}

if ($DNSSUF.UseSuffixSearchList -eq $True)
{
    foreach ($dns in $DNSSUF.DNSSuffixesToAppend)
    {
        if ($dns -eq $compdomain)
        {
            $path = '\\'+$compdomain+'\sysvol\'+$compdomain+'\scripts\'+$Script
            break;
        }
        else
        {
            $path = '\\'+$hostname+'\C$\temp\'+$Script
        }
    }
}
else
{
    $path = '\\'+$hostname+'\C$\temp\'+$Script
}
#Uncomment below line to test script on local machine
#$path = '\\'+$hostname+'\C$\temp\'+$Script

$outlog = "$path\$hostname"+"_"+"$Script"+"_"+"$datetime.txt"
$errlog = "$path\$hostname"+"_"+"$Script"+"_Err_"+"$datetime.txt"
$outhncsv = "$path\$hostname"+"_"+"$Script"+"_"+"$datetime.csv"
$outcsv = "$path\$Script.csv"

Start-Transcript -Path $outlog -Verbose

"======================================================================================================================================"
"List env:PSModulePath"
#dir $env:PSModulePath.Split(";")
"======================================================================================================================================"
"profile: "+$profile
#dir $profile
"======================================================================================================================================"

"BEFORE"
#Get-Module|ft -Property * -AutoSize

#Import-Module -Name Dism -Force -Verbose

#Import-Module -Name ServerManager -Force -Verbose
"AFTER"
#Get-Module|ft -Property * -AutoSize

"======================================================================================================================================"
'START'
#'hostname:'+$hostname
'DateTime:'+$datetime
'Path:'+$path
'Running path:'+$gloc.Path
'Script:'+$Script
#'Outlog:'+$outlog
#'Errlog:'+$errlog
"======================================================================================================================================"

function Do-Something
{
[cmdletbinding()]
param()

#Export-Csv -NoTypeInformation -Path $outcsv

if (!(test-path $path))
{
    New-Item -Path $path -ItemType directory
}

    $psco = @{}

try{
    $dsccs = Get-DscConfigurationStatus
    $RNIDS = $dsccs.ResourcesNotInDesiredState

    write-host("using forEach Loop")
    foreach ($element in $RNIDS)
    {
      $element
    }

}
catch
{
    "Get-DscConfigurationStatus ERROR!"
    $PSItem.ToString() | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.ScriptStackTrace | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.InvocationInfo | Format-List * | Out-File -Append $errlog
    "" | Out-File -Append $errlog
}

try{
    $psco = [pscustomobject]@{Name = $hostname ;Status = $dsccs.Status; RebootRequested = $dsccs.RebootRequested; Error = $dsccs.Error; ResourcesNotInDesiredState = $dsccs.ResourcesNotInDesiredState.ResourceId; MetaData = $dsccs.MetaData}
    $psco | Export-Csv -NoTypeInformation -Path $outhncsv -Append -ErrorAction Continue -Force
    $psco | Export-Csv -NoTypeInformation -Path $outcsv -Append -ErrorAction Continue -Force
}
catch [System.IO.IOException]
{
    "Cannot Open File!"
    $PSItem.ToString() | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.ScriptStackTrace | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.InvocationInfo | Format-List * | Out-File -Append $errlog
    "" | Out-File -Append $errlog

    $done = $false
    Start-Sleep -Seconds 1
    $a = 0

    While ($done -ne $True)
    {
        try{
            $psco | Export-Csv -NoTypeInformation -Path $outcsv -Append -ErrorAction Continue -Force
            "TRY N DONE"
            $done = $True
        }
        catch [System.IO.IOException]
        {
            "Cannot Open File AGAIN! "+$a++
            $done = $false
            Start-Sleep -Seconds 1
        }
    }
}
catch
{
    $PSItem.ToString() | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.ScriptStackTrace | Out-File -Append $errlog
    "" | Out-File -Append $errlog
    $PSItem.InvocationInfo | Format-List * | Out-File -Append $errlog
    "" | Out-File -Append $errlog
}

}

Do-Something

<#
$edatetime = Get-Date -Format 'yyyyMMdd_HHmmss'
"======================================================================================================================================"
'END'
#'hostname:'+$hostname
'datetime:'+$edatetime
#'path:'+$path
#'Script:'+$Script
#'outlog:'+$outlog
"======================================================================================================================================"
#>

Stop-Transcript
}
