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
$Script = "PSSecDSC" #<REPLACE WITH THE SCRIPT NAME>
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

Configuration PSSecDSC
{
Param(
    [ValidateRange(1,2048)][int]$EventLogSizeInMB = 256
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration #–ModuleName @{ModuleName="UserConfigProvider";ModuleVersion="3.0"}

    Node $hostname
    {
        File SysmonOKConfigFile
        {
            DestinationPath = 'C:\Temp\ok-sysmon.xml'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        File SysinternalsSuiteFolder
        {
            DestinationPath = 'C:\SysinternalsSuite'
            Type            = 'Directory'
            #Ensure          = 'Present'
            DependsOn = '[File]SysmonOKConfigFile'
        }

        File CheckSysmonOKConfigFile #File is a DSC Resource
        {
           Ensure = 'Present'
           SourcePath = 'C:\Temp\ok-sysmon.xml'
           DestinationPath = 'C:\SysinternalsSuite\ok-sysmon.xml'
           MatchSource = $true
           DependsOn = '[File]SysinternalsSuiteFolder'
        }

        ### Check For Sysmon Service #####################################################
        Script CheckSysmonService
        {
            GetScript = {
                
                Return @{Result = 
                    If ((Get-Service | where "Name" -Like 'Sysmon*').Status -eq $null)
                    {
                        $False
                    }
                    else
                    {
                        $True
                    }
                }

            }

            TestScript = {
                
                If ((Get-Service | where "Name" -Like 'Sysmon*').Status -eq $null)
                {
                    Write-Verbose ' is NOT in desired state.'
                    Return $false
                }
                else
                {
                    Write-Verbose ' is in desired state.'
                    Return $true
                }

            }

            SetScript = {
                
                & C:\SysinternalsSuite\Sysmon.exe -accepteula -i C:\SysinternalsSuite\ok-sysmon.xml
                
            }
            DependsOn = '[File]CheckSysmonOKConfigFile'
        }

        <#
        WindowsProcess Sysmon 
        {
            Path = 'C:\Windows\Sysmon.exe'
            Arguments = '-accepteula -i C:\SysinternalsSuite\ok-sysmon.xml'
            DependsOn = '[File]CheckSysmonOKConfigFile'
        }#>

        Script SysmonLogSize
        {
            GetScript = {
                Return @{
                    Result = Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational | Out-String
                }
            }

            TestScript = {
                $Log = Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational
                If ($Log.LogMode -ne 'AutoBackup' -or $Log.MaximumSizeInBytes -lt ($using:EventLogSizeInMB * 1MB)) {
                    Write-Verbose 'Event log [Microsoft-Windows-Sysmon/Operational] is NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Event log [Microsoft-Windows-Sysmon/Operational] is in desired state.'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Applying settings to event log [Microsoft-Windows-Sysmon/Operational].'
                wevtutil set-log Microsoft-Windows-Sysmon/Operational /AutoBackup:true /Retention:true /maxsize:$($using:EventLogSizeInMB * 1MB)
            }
            DependsOn = '[Script]CheckSysmonService'
        }

        ### Remove PowerShellV2####################################################################################################
        WindowsFeature PowerShellV2 #ResourceName
        {
            Name = 'PowerShell-V2'
            Ensure = 'Absent'
            #IncludeAllSubFeature = $true
        }

        WindowsOptionalFeature MicrosoftWindowsPowerShellV2 #ResourceName
        {
            Name = 'MicrosoftWindowsPowerShellV2'
            Ensure = 'Disable'
            NoWindowsUpdateCheck = $true
            RemoveFilesOnDisable = $true
            LogLevel = 'ErrorsAndWarningAndInformation'
        }

        ### Enable Schannel Logging####################################################################################################
        Registry SchannelLogging
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
            ValueName = 'EventLogging'
            ValueData = '1'#1 (Basic) #7 (Verbose)
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### RC2 40/128 KEY##############################################
        Script RegRC240128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
            }
        }

        ### RC2 56/128 KEY##############################################
        Script RegRC256128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')
            }
        }

        ### RC2 128/128 KEY##############################################
        Script RegRC2128128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
            }
        }

        ### RC4 40/128 KEY##############################################
        Script RegRC440128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
            }
        }

        ### RC4 56/128 KEY##############################################
        Script RegRC456128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
            }
        }

        ### RC4 64/128 KEY##############################################
        Script RegRC464128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
            }
        }

        ### RC4 128/128 KEY##############################################
        Script RegRC4128128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
            }
        }

        ### DES 56/56 KEY##############################################
        Script RegDES5656KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')
            }
        }

        ### DES 168/168 KEY##############################################
        Script RegDES168168KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168')
            }
        }

        ### Triple DES 112 KEY##############################################
        Script RegTripleDES112KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112')
            }
        }

        ### Triple DES 168 KEY##############################################
        Script RegTripleDES168KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')
            }
        }

        ### AES 128/128 KEY##############################################
        Script RegAES128128KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128')
            }
        }

        ### AES 256/256 KEY##############################################
        Script RegAES256256KEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256')
            }
        }

        ### Disable PCT 1.0  Server##############################################
        Registry DisablePCT10Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisablePCT10Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable PCT 1.0  Client##############################################
        Registry DisablePCT10Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisablePCT10Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable SSL 2.0  Server##############################################
        Registry DisableSSL20Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableSSL20Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable SSL 2.0  Client##############################################
        Registry DisableSSL20Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableSSL20Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable SSL 3.0  Server##############################################
        Registry DisableSSL30Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableSSL30Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable SSL 3.0  Client##############################################
        Registry DisableSSL30Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableSSL30Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable TLS 1.0  Server##############################################
        Registry DisableTLS10Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS10Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable TLS 1.0  Client##############################################
        Registry DisableTLS10Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS10Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable TLS 1.1  Server##############################################
        Registry DisableTLS11Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS11Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable TLS 1.1  Client##############################################
        Registry DisableTLS11Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS11Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable TLS 1.2  Server##############################################
        Registry DisableTLS12Server1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS12Server2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable TLS 1.2  Client##############################################
        Registry DisableTLS12Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS12Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Ciphers####################################################
        ### Disable NULL##############################################
        Registry DisableNULL
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable RC4##############################################
        Registry DisableRC4128
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableRC440
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableRC456
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableRC464
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable RC2##############################################
        Registry DisableRC2128
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableRC240
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableRC256
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable DES##############################################
        Registry DisableDES56
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableDES168
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable 3DES##############################################
        Registry Disable3DES112
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry Disable3DES168
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable AES128##############################################
        Registry DisableAES128
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable AES256##############################################
        Registry EnableAES256
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Hash###########################################################
        ### Disable MD5 Hash##############################################
        Registry DisableMD5Hash
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Key Exchange###############################################################
        ### Disable Diffie Hellman##############################################
        Registry DisableDiffieHellman
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }
        <#
        ### Cipher Suites Order##############################################
        Registry CipherSuitesOrder
        {
            Key       = 'HKLM:\System\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
            ValueName = 'Functions'
            ValueData = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA'
            ValueType = 'MultiString'
            Ensure    = 'Present'
        }#>

        ### Enable Strong Authentication on .Net Framework version 3 and below##############################################
        Registry UseStrong64DNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Absent'
        }

        Registry SysDef64DNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry UseStrong32DNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Absent'
        }

        Registry SysDef32DNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable Strong Authentication on .Net Framework version 4 and above##############################################
        Registry UseStrong64DNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Absent'
        }

        Registry SysDef64DNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry UseStrong32DNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Absent'
        }

        Registry SysDef32DNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable HTTP2##############################################
        Registry EnableHTTP21
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'EnableHttp2Tls'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableHTTP22
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'EnableHttp2Cleartext'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable HTTP Server Header##############################################
        Registry DisableHTTPServerHeader
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'DisableServerHeader'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable Secure Protocols##############################################
        Registry EnableSecureProtocols32
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueData = '2048'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableSecureProtocols64
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueData = '2048'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableMachineIESecureProtocols
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueData = '2048'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableUserIESecureProtocols
        {
            Key       = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueData = '2048'
            ValueType = 'DWord'
            Ensure    = 'Present'
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
PSSecDSC -OutputPath 'C:\Temp\PSSecDSC' -Verbose
Start-DscConfiguration -Path 'C:\temp\PSSecDSC' -Wait -Verbose -Force
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
