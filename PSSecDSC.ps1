
.\DL_Sysinternals.ps1

Configuration EnablePowerShellLogging
{
Param(
    [string]$TranscriptPath = 'C:\Temp\PSTranscripts',
    [ValidateRange(1,365)][int]$TranscriptDays = 14,
    [ValidateRange(1,1024)][int]$EventLogSizeInMB = 256,
    [string]$WindowsEventLogsPath = 'G:\WindowsEventLogs',
    [string]$CheckDrive = 'G:' #G:\WindowsEventLogs

) #G:\WindowsEventLogs\PSTranscripts

    Import-DscResource -ModuleName PSDesiredStateConfiguration #–ModuleName @{ModuleName="UserConfigProvider";ModuleVersion="3.0"}

    Node localhost
    {
        File SysinternalsSuiteFile
        {
            DestinationPath = 'C:\Temp\SysinternalsSuite.zip'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        Archive UnzipSysinternalsSuiteFile #Unzip file
        {
            Destination = 'C:\SysinternalsSuite'
            Path = 'C:\Temp\SysinternalsSuite.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]SysinternalsSuiteFile'
        }
        
        File SysmonOKConfigFile
        {
            DestinationPath = 'C:\Temp\ok-sysmon.xml'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        File CheckSysmonOKConfigFile #File is a DSC Resource
        {
           Ensure = 'Present'
           SourcePath = 'C:\Temp\ok-sysmon.xml'
           DestinationPath = 'C:\SysinternalsSuite\ok-sysmon.xml'
           MatchSource = $true
           DependsOn = '[File]SysmonOKConfigFile'
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

        File ZabbixConfFile
        {
            DestinationPath = 'C:\Temp\zabbix_agentd.win.conf'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        File Zabbixi386File
        {
            DestinationPath = 'C:\Temp\zabbix_agents-4.0.0-win-i386.zip'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        File Zabbixamd64File
        {
            DestinationPath = 'C:\Temp\zabbix_agents-4.0.0-win-amd64.zip'
            Type            = 'File'
            #Ensure          = 'Present'
        }

        Archive UnzipZabbixamd64File #Unzip file
        {
            Destination = 'C:\zabbix'
            Path = 'C:\Temp\zabbix_agents-4.0.0-win-amd64.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]Zabbixamd64File'
        }

        File CheckZabbixConfFile #File is a DSC Resource
        {
           Ensure = 'Present'
           SourcePath = 'C:\Temp\zabbix_agentd.win.conf'
           DestinationPath = 'C:\zabbix\zabbix_agentd.win.conf'
           MatchSource = $true
           DependsOn = '[File]ZabbixConfFile'
        }

        <#Service ZabbixAgent
        {
            Name = 'Zabbix Agent'
            Ensure = 'Absent'
        }#>

        Service ZabbixAgent
        {
            Name = 'Zabbix Agent'
            BuiltInAccount = 'LocalSystem'
            Description = 'Zabbix System Monitoring'
            DisplayName = 'Zabbix Agent'
            Ensure = 'Present'
            Path = '"C:\zabbix\bin\zabbix_agentd.exe" --config "C:\zabbix\zabbix_agentd.win.conf"'
            StartupType = 'Automatic'
            State = 'Running'
        }

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
                wevtutil set-log Microsoft-Windows-PowerShell/Operational /AutoBackup:true /Retention:true /maxsize:$($using:EventLogSizeInMB * 1MB)
            }
        }

        Script SecurityLogSize
        {
            GetScript = {
                Return @{
                    Result = Get-WinEvent -ListLog Security | Out-String
                }
            }

            TestScript = {
                $Log = Get-WinEvent -ListLog Security
                If ($Log.MaximumSizeInBytes -lt ($using:EventLogSizeInMB * 1MB)) {
                    Write-Verbose 'Event log [Security] is NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Event log [Security] is in desired state.'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Applying settings to event log [Security].'
                wevtutil set-log Security /maxsize:$($using:EventLogSizeInMB * 1MB)
            }
        }

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

        ### Transcription #####################################################
        ### Check For G: drive #####################################################
        Script CheckGDrive
        {
            GetScript = {

                Return @{Result = test-path $using:CheckDrive | Out-String}

            }

            TestScript = {

                If (!(test-path $using:CheckDrive))
                {
                    Write-Verbose ' is NOT in desired state.'
                    Return $false
                }
                Else
                {   
                    Write-Verbose ' is in desired state.'
                    Return $true
                }

            }

            SetScript = {

                #New-Item -Path $path -ItemType directory
                If (!(test-path $using:CheckDrive))
                {
                    Write-Verbose ' is NOT in desired state.'
                    New-Item -Path $using:WindowsEventLogsPath -ItemType directory
                    Return $false
                }
                Else
                {   
                    Write-Verbose ' is in desired state.'
                    Return $true
                }

            }

        }

        <#
        File WindowsEventLogs
        {
            DestinationPath = $WindowsEventLogsPath
            Type            = 'Directory'
            Ensure          = 'Present'
            DependsOn = '[Script]CheckGDrive'
        }#>

        Environment WindowsEventLogLocation #ResourceName
        {
            Name = 'WindowsEventLogs'
            Ensure = 'Present'
            Path = $true
            Value = 'G:\WindowsEventLogs'
        }

        ### Remove this resource if sending Transcripts to a remote share.
        File TranscriptsOutputDirectory
        {
            DestinationPath = $TranscriptPath
            Type            = 'Directory'
            Ensure          = 'Present'
        }

        ### Remove this resource if sending transcripts to a remote share.
        Script TranscriptsOutputDirectoryPermissions
        {
            GetScript = {
                $acl = Get-Acl $using:TranscriptPath
                Return @{
                    Result = $acl.Sddl
                }
            }
            TestScript = {
                $acl = Get-Acl $using:TranscriptPath
                Write-Verbose "Transcript directory permissions: $($acl.Sddl)"
                If ($acl.Sddl -ne 'O:BAG:BAD:AI(A;OICI;0x1301bf;;;BU)') {
                    Write-Verbose 'Transcript directory permissions are NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Transcript directory permissions are in desired state.'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Applying transcript directory permissions.'
                # Remove inherited permissions.
                # Allow Administrators full control.
                # Allow SYSTEM full control.
                # Allow Users Read and Execute.
                # Allow Users Modify.
                $acl = Get-Acl $using:TranscriptPath
                $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:AI(A;OICI;0x1301bf;;;BU)') #(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)
                $acl | Set-Acl $using:TranscriptPath -Verbose
            }
            DependsOn = '[File]TranscriptsOutputDirectory'
        }

        ### Remove this resource if sending transcripts to a remote share.
        ### NOTE: This will generate errors due to permissions of the local transcript directory.
        Script TranscriptsDirectoryTrim
        {
            GetScript = {
                Return @{
                    Result = $using:TranscriptPath
                }
            }
            TestScript = {
                $ErrorActionPreference = 'Stop'
                Try {
                    $OldContent = Get-ChildItem $using:TranscriptPath -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays($using:TranscriptDays * -1)}
                }
                Catch {
                    Write-Warning 'Access denied to some of the transcript files.'
                }
                If ($OldContent) {
                    Write-Verbose "Transcript directory contains content older than $($using:TranscriptDays) days."
                    Return $false
                } Else {   
                    Write-Verbose "Transcript directory DOES NOT contain content older than $($using:TranscriptDays) days."
                    Return $true
                }
            }
            SetScript = {
                $ErrorActionPreference = 'Stop'
                Try {
                    Get-ChildItem $using:TranscriptPath -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays($using:TranscriptDays * -1)} | Remove-Item -Force -Confirm:$false -Verbose
                }
                Catch {
                    Write-Warning 'Access denied to some of the transcript files.'
                }
            }
            DependsOn = '[File]TranscriptsOutputDirectory'
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
        ### Enable Logging End##########################################################################################################
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

        ### Disable TLS 1.0  Client##############################################
        Registry DisableTLS10Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS10Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
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

        ### Disable TLS 1.1  Client##############################################
        Registry DisableTLS11Client1
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry DisableTLS11Client2
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '1'
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

        ### Disable TLS 1.2  Client##############################################
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
        <#
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

        ### Disable NULL##############################################
        Registry DisableNULL
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'
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
        }#>
        <#
        ### Disable AES128##############################################
        Registry DisableAES128
        {
            Key       = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable AES256##############################################
        Registry EnableAES256
        {
            Key       = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
            ValueName = 'Enabled'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>
        <#
        ### Disable MD5 Hash##############################################
        Registry DisableMD5Hash
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'
            ValueName = 'Enabled'
            ValueData = '0'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Disable Diffie Hellman##############################################
        Registry DisableDiffieHellman
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
            ValueName = 'ServerMinKeyBitLength'
            ValueData = '00000800'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>

        ### Cipher Suites Order##############################################
        <#
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
        }
        #>
        <#
        ### Enable Strong Authentication on .Net Framework version 3 and below##############################################
        Registry Enable64bitDNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry Enable32bitDNFW3
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        ### Enable Strong Authentication on .Net Framework version 4 and above##############################################
        Registry Enable64bitDNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry Enable32bitDNFW4
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>
        <#
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
        }#>
        <#
        ### Disable HTTP Server Header##############################################
        Registry DisableHTTPServerHeader
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'DisableServerHeader'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>
        <#
        ### Enable Secure Protocols##############################################
        Registry EnableSecureProtocols32
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueData = '00000800'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableSecureProtocols64
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueData = '00000800'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableMachineIESecureProtocols
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueData = '00000800'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

        Registry EnableUserIESecureProtocols
        {
            Key       = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueData = '00000800'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }#>

        ### Disable CRL Check##############################################
        Registry DisableCRLCheck
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo'
            ValueName = 'DefaultSslCertCheckMode'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
        }

    }#End of Node localhost

}

cd c:\temp
EnablePowerShellLogging -OutputPath 'C:\Temp\EnablePowerShellLogging' -Verbose
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 112')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128')
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256')

#Start-DscConfiguration -Path C:\temp\EnablePowerShellLogging -Wait -Verbose -Force

