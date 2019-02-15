
Configuration ManEngEvtLogAnlyRpt
{

Param(
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration #–ModuleName @{ModuleName="UserConfigProvider";ModuleVersion="3.0"}

    Node localhost
    {
        ### Application-Experience/Program-Inventory KEY##############################################
        Script RegAEPIKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Application-Experience/Program-Inventory' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Application-Experience/Program-Inventory'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Application-Experience/Program-Inventory] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Application-Experience/Program-Inventory] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-Application-Experience/Program-Inventory]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Application-Experience/Program-Inventory')
            }
        }

        ### AppLocker/EXE and DLL KEY##############################################
        Script RegALEDEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/EXE and DLL' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/EXE and DLL'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/EXE and DLL] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/EXE and DLL] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-AppLocker/EXE and DLL]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/EXE and DLL')
            }
        }

        ### AppLocker/MSI and Script KEY##############################################
        Script RegALMSKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/MSI and Script' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/MSI and Script'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/MSI and Script] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/MSI and Script] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-AppLocker/MSI and Script]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-AppLocker/MSI and Script')
            }
        }

        ### Backup KEY##############################################
        Script RegBKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Backup' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Backup'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Backup] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Backup] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-Backup]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Backup')
            }
        }

        ### Windows Firewall With Advanced Security/Firewall KEY##############################################
        Script RegWFASFKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Windows Firewall With Advanced Security/Firewall')
            }
        }

        ### DriverFrameworks-UserMode/Operational KEY##############################################
        Script RegDFUMOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-DriverFrameworks-UserMode/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational')
            }
        }

        ### GroupPolicy/Operational KEY##############################################
        Script RegGPOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-GroupPolicy/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-GroupPolicy/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-GroupPolicy/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-GroupPolicy/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-GroupPolicy/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-GroupPolicy/Operational')
            }
        }

        ### NetworkProfile/Operational KEY##############################################
        Script RegNPOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-NetworkProfile/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-NetworkProfile/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-NetworkProfile/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-NetworkProfile/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-NetworkProfile/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-NetworkProfile/Operational')
            }
        }

        ### WindowsUpdateClient/Operational KEY##############################################
        Script RegWUCOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WindowsUpdateClient/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WindowsUpdateClient/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WindowsUpdateClient/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WindowsUpdateClient/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-WindowsUpdateClient/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WindowsUpdateClient/Operational')
            }
        }

        ### Winlogon/Operational KEY##############################################
        Script RegWOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Winlogon/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Winlogon/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Winlogon/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Winlogon/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-Winlogon/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Winlogon/Operational')
            }
        }

        ### WLAN-AutoConfig/Operational KEY##############################################
        Script RegWLACOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WLAN-AutoConfig/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WLAN-AutoConfig/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WLAN-AutoConfig/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WLAN-AutoConfig/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-WLAN-AutoConfig/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-WLAN-AutoConfig/Operational')
            }
        }

        ### TerminalServices-Gateway/Operational KEY##############################################
        Script RegTSGOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-Gateway/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-Gateway/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-Gateway/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-Gateway/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-TerminalServices-Gateway/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-Gateway/Operational')
            }
        }

        ### TerminalServices-RDPClient/Operational KEY##############################################
        Script RegTSRDPCOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RDPClient/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RDPClient/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RDPClient/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RDPClient/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-TerminalServices-RDPClient/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RDPClient/Operational')
            }
        }

        ### TerminalServices-RemoteConnectionManager/Operational KEY##############################################
        Script RegTSRCMOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational')
            }
        }

        ### Wired-AutoConfig/Operational KEY##############################################
        Script RegWACOKEY
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Wired-AutoConfig/Operational' | Out-String
                }
            }

            TestScript = {
                $Key = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Wired-AutoConfig/Operational'
                If (!$Key) {
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Wired-AutoConfig/Operational] is NOT in desired state'
                    Return $false
                } Else {   
                    Write-Verbose 'Registry [HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Wired-AutoConfig/Operational] is in desired state'
                    Return $true
                }
            }

            SetScript = {
                Write-Verbose 'Creating registry KEY [HKLM:\SYSTEM\CurrentControlSet\Services\Microsoft-Windows-Wired-AutoConfig/Operational]'
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Wired-AutoConfig/Operational')
            }
        }
    }#End of Node localhost
}

ManEngEvtLogAnlyRpt -OutputPath 'C:\Temp\ManEngEvtLogAnlyRpt' -Verbose
#Start-DscConfiguration -Path 'C:\Temp\ManEngEvtLogAnlyRpt' -Wait -Verbose -Force
