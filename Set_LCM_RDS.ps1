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
$Script = "Set_LCM_RDS" #<REPLACE WITH THE SCRIPT NAME>
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
$path = '\\'+$hostname+'\C$\temp\'+$Script

$outlog = "$path\$hostname"+"_"+"$Script"+"_"+"$datetime.txt"
$errlog = "$path\$hostname"+"_"+"$Script"+"_Err_"+"$datetime.txt"
#$outcsv = "$path\$Script"+"_"+"$datetime.csv"
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

[DscLocalConfigurationManager()]

configuration LCM {

param (
[parameter(Mandatory=$true)]
[string[]]$computername
)

node $computername {

    settings {
        ActionAfterReboot = 'ContinueConfiguration' #Change to default 'ContinueConfiguration' is other value
        ConfigurationMode = 'ApplyAndMonitor' #Change back to default 'ApplyAndMonitor' after completed
        RebootNodeIfNeeded = $true #Change back to default $False after completed
    }
}
}

function Do-Something
{
[cmdletbinding()]
param()

#Export-Csv -NoTypeInformation -Path $outcsv

if (!(test-path $path))
{
    New-Item -Path $path -ItemType directory
}

try{

LCM -OutputPath 'C:\Temp\LCMSettings' -computername $hostname -verbose
Set-DscLocalConfigurationManager -Path 'C:\Temp\LCMSettings' -ComputerName $hostname -Verbose -Force

Get-DscLocalConfigurationManager|fl *
}
catch
{
$PSItem.ToString() | Out-File -Append $errlog
"" | Out-File -Append $errlog
$PSItem.ScriptStackTrace | Out-File -Append $errlog
"" | Out-File -Append $errlog
$PSItem.InvocationInfo | Format-List * | Out-File -Append $errlog
"" | Out-File -Append $errlog
$PSCmdlet.ThrowTerminatingError($PSitem) | Out-File -Append $errlog
}

}

Do-Something

$edatetime = Get-Date -Format 'yyyyMMdd_HHmmss'
"======================================================================================================================================"
'END'
#'hostname:'+$hostname
'datetime:'+$edatetime
#'path:'+$path
#'Script:'+$Script
#'outlog:'+$outlog
"======================================================================================================================================"

Stop-Transcript
}
