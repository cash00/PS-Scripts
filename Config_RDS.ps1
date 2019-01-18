#$hostname = $env:computername
$hostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

$data = @{
AllNodes = @()

RDSData = @{
    ConnectionBroker = $hostname
    LicenseServer = $hostname
    SessionHost = $hostname
    WebAccessServer = $hostname
    CollectionName = 'WFH'
    CollectionDescription = 'WFH Collection'
    DisconnectedSessionLimitMin = 30
    ActiveSessionLimitMin = 0
    IdleSessionLimitMin = 60
    AutomaticReconnectionEnabled = $true
    BrokenConnectionAction = 'Disconnect' # default -> 'Disconnect'. "None, Disconnect, LogOff"
    ClientDeviceRedirectionOptions = 'Clipboard' #'ClientDeviceRedirectionOptions : None, AudioVideoPlayBack, AudioRecording, COMPort, PlugAndPlayDevice, SmartCard, Clipboard, LPTPort, Drive, TimeZone'
    ClientPrinterAsDefault = $false
    ClientPrinterRedirected = $false
    RDEasyPrintDriverEnabled = $false
    EnableUserProfileDisk = $false
    TemporaryFoldersDeletedOnExit = $true
    MaxRedirectedMonitors = 2
    AuthenticateUsingNLA = $true
    EncryptionLevel = 'High' #'ClientCompatible'
    SecurityLayer = 'Negotiate'
    LicenseMode = 'PerUser'
    UserGroup = 'VEGAS\RDS Test'
}
 
}

#######################################################################################################

$computername = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

Configuration RDS {
 
param (
)

Import-DscResource -ModuleName PSDesiredStateConfiguration, @{ModuleName='xRemoteDesktopSessionHost';ModuleVersion="1.8.0.0"}

Node $computername {
    $RDData = $data.RDSData

    WindowsFeature RDSConnectionBroker {
    Name = 'RDS-Connection-Broker'
    Ensure = 'Present'
    }

    WindowsFeature SessionHost {
    Name = 'RDS-RD-Server'
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]RDSConnectionBroker'
    }

    WindowsFeature WebAccess {
    Name = 'RDS-Web-Access'
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]SessionHost'
    }

    WindowsFeature RDLicensing {
    Name = 'RDS-Licensing'
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]WebAccess'
    }

    WindowsFeature RemoteDesktopServices {
    Name = 'Remote-Desktop-Services'
    Ensure = 'Present'
    }

    xRDSessionDeployment NewDeployment {
    ConnectionBroker = $RDData.ConnectionBroker
    SessionHost = $RDData.SessionHost
    WebAccessServer = $RDData.WebAccessServer
    DependsOn = '[WindowsFeature]RDLicensing'
    }

    xRDSessionCollection collection {
    CollectionName = $RDData.CollectionName
    SessionHost = $RDData.SessionHost
    ConnectionBroker = $RDData.ConnectionBroker
    DependsOn = '[xRDSessionDeployment]NewDeployment'
    }

    xRDSessionCollectionConfiguration collectionconfig {
    CollectionName = $RDData.CollectionName
    ConnectionBroker = $RDData.ConnectionBroker
    ActiveSessionLimitMin = $RDData.ActiveSessionLimitMin
    AuthenticateUsingNLA = $RDData.AuthenticateUsingNLA
    AutomaticReconnectionEnabled = $RDData.AutomaticReconnectionEnabled
    DisconnectedSessionLimitMin = $RDData.DisconnectedSessionLimitMin
    IdleSessionLimitMin = $RDData.IdleSessionLimitMin
    BrokenConnectionAction = $RDData.BrokenConnectionAction
    ClientDeviceRedirectionOptions = $RDData.ClientDeviceRedirectionOptions
    ClientPrinterAsDefault = $RDData.ClientPrinterAsDefault
    ClientPrinterRedirected = $RDData.ClientPrinterRedirected
    CollectionDescription = $RDData.CollectionDescription
    EnableUserProfileDisk = $RDData.EnableUserProfileDisk
    EncryptionLevel = $RDData.EncryptionLevel
    MaxRedirectedMonitors = $RDData.MaxRedirectedMonitors
    RDEasyPrintDriverEnabled = $RDData.RDEasyPrintDriverEnabled
    SecurityLayer = $RDData.SecurityLayer
    TemporaryFoldersDeletedOnExit = $RDData.TemporaryFoldersDeletedOnExit
    UserGroup = $RDData.UserGroup
    DependsOn = '[xRDSessionCollection]collection'
    }

    xRDLicenseConfiguration licenseconfig {
    ConnectionBroker = $RDData.ConnectionBroker
    LicenseServer = $RDData.LicenseServer
    LicenseMode = $RDData.LicenseMode
    DependsOn = '[xRDSessionCollectionConfiguration]collectionconfig'
    }

    xRDRemoteApp zCalculator {
    CollectionName = $RDData.CollectionName
    Alias = 'win32calc'
    DisplayName = 'Calculator'
    FilePath = 'C:\Windows\system32\win32calc.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

    xRDRemoteApp zRemoteDesktopConnection {
    CollectionName = $RDData.CollectionName
    Alias = 'mstsc'
    DisplayName = 'Remote Desktop Connection'
    FilePath = 'C:\Windows\system32\mstsc.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }
    <#
    xRDRemoteApp zNotepad {
    CollectionName = $RDData.CollectionName
    Alias = 'notepad'
    DisplayName = 'Notepad'
    FilePath = 'C:\Windows\notepad.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }#>

    xRDRemoteApp zWordPad {
    CollectionName = $RDData.CollectionName
    Alias = 'wordpad'
    DisplayName = 'WordPad'
    FilePath = 'C:\Program Files\Windows NT\Accessories\wordpad.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

    WindowsFeature RDSGatewayTools {
    Name = 'RSAT-RDS-Gateway'
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]RDSConnectionBroker'
    }

    WindowsFeature RDSLicDiagTools {
    Name = 'RSAT-RDS-Licensing-Diagnosis-UI'
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]RDLicensing'
    }

    WindowsFeature RDSLicTools {
    Name = 'RDS-Licensing-UI '
    Ensure = 'Present'
    DependsOn = '[WindowsFeature]RDLicensing'
    }

    WindowsFeature RDSTools {
    Name = 'RSAT-RDS-Tools'
    Ensure = 'Present'
    IncludeAllSubFeature = $true
    DependsOn = '[WindowsFeature]WebAccess'
    }
}

}

RDS -OutputPath 'C:\Temp\RDSConfig\' -ConfigurationData $data -Verbose
