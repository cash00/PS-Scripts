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
    $Script = "PowerShellLogging" #<REPLACE WITH THE SCRIPT NAME>
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
$errlog = "C:\temp\$Script"+"Err_"+"$datetime.txt"
$outcsv = "$path\$Script"+"_"+"$datetime.csv"
#$outcsv = "$path\$Script.csv"

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

Configuration PowerShellLogging
{
Param(
    [string]$TranscriptPath = 'C:\Temp\PSTranscripts',
    [ValidateRange(1,365)][int]$TranscriptDays = 14,
    [ValidateRange(1,1024)][int]$EventLogSizeInMB = 2048,
    [string]$WindowsEventLogsPath = 'G:\WindowsEventLogs'
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration #–ModuleName @{ModuleName="UserConfigProvider";ModuleVersion="3.0"}

    Node $hostname
    {
        ### Script Execution ##############################################
        Registry EnableScripts
        {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueName = 'EnableScripts'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry ExecutionPolicy
        {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueName = 'ExecutionPolicy'
            ValueData = 'Unrestricted'
            ValueType = 'String'
            Ensure    = 'Present'
        }

        ### Script Block Logging ##############################################
        Registry EnableScriptBlockLogging
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        # Enable this setting to log start / stop events. Not usually recommended, as it causes
        # a significant impact on log volume
        <#
        Registry ScriptBlockInvocationLogging
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = 1
            ValueType = 'String'
            Ensure    = 'Present'
        }#>

        ### Module Logging ##############################################
        Registry EnableModuleLogging
        {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            ValueName = 'EnableModuleLogging'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry ModuleNames
        {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
            ValueName = '*'
            ValueData = '*'
            ValueType = 'String'
            Ensure    = 'Present'
        }

        ### Logs Directory#####################################################
        File WindowsEventLogs
        {
            DestinationPath = $WindowsEventLogsPath
            Type            = 'Directory'
            Ensure          = 'Present'
        }

        ### Environment#####################################################
        Environment WindowsEventLogLocation
        {
            Name = 'WindowsEventLogs'
            Ensure = 'Present'
            Path = $true
            Value = 'G:\WindowsEventLogs'
        }
        
        ### Transcription #####################################################
        ### Remove this resource if sending Transcripts to a remote share.
        File TranscriptsOutputDirectory
        {
            DestinationPath = $TranscriptPath
            Type            = 'Directory'
            Ensure          = 'Present'
        }

        Registry EnableTranscripting
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'EnableTranscripting'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        # Remove this setting to descrease transcript file size
        <#
        Registry TranscriptionInvocationHeader
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'EnableInvocationHeader'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>

        Registry TranscriptionPath
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'OutputDirectory'
            ValueData = $TranscriptPath
            ValueType = 'String'
            Ensure    = 'Present'
            DependsOn = '[File]TranscriptsOutputDirectory'
        }

        ### Enable PowerShell Constraint mode ##############################################
        Registry PSLockdownPolicy
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            ValueName = '_PSLockdownPolicy'
            ValueData = '4'
            ValueType = 'String'
            Ensure    = 'Present'
        }

        ### CommandLine Logging ##############################################
        Registry CommandLineLogging
        {
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### PowerShell Log Size##############################################
        Script PowerShellLogSize
        {
            GetScript = {
                Return @{
                    Result = Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational | Out-String
                }
            }

            TestScript = {
                $Log = Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational
                If ($Log.LogMode -ne 'AutoBackup' -or $Log.MaximumSizeInBytes -lt ($using:EventLogSizeInMB * 1MB)) {
                    Write-Verbose 'Event log [Microsoft-Windows-PowerShell/Operational] is NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Event log [Microsoft-Windows-PowerShell/Operational] is in desired state.'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Applying settings to event log [Microsoft-Windows-PowerShell/Operational].'
                wevtutil set-log Microsoft-Windows-PowerShell/Operational /AutoBackup:false /Retention:false /maxsize:$($using:EventLogSizeInMB * 1MB)
            }
        }
        
        ### EventLog Report KEY##############################################
        Script RegPowerShellEventLogReport
        {
            GetScript = {
                Return @{
                    Result = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational')
            }
        }
    }#End of Node localhost
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
    cd C:\Temp
    PowerShellLogging -OutputPath 'C:\Temp\PowerShellLogging' -Verbose
    Start-DscConfiguration -Path C:\Temp\PowerShellLogging -Wait -Verbose -Force
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
