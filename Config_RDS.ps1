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
    AutomaticReconnectionEnabled = $false
    BrokenConnectionAction = 'End' #'Disconnect'
    ClientDeviceRedirectionOptions = '' #'ClientDeviceRedirectionOptions : AudioVideoPlayBack, AudioRecording, PlugAndPlayDevice, SmartCard, Clipboard, Drive'
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
    UserGroup = 'RDS Test'
}
 
}

#######################################################################################################

$computername = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

Configuration RDS {
 
param (
)
#region DSC Resource Modules
#OBS!!! Be sure that the modules exist on the destination host servers

Import-DscResource -ModuleName PSDesiredStateConfiguration, @{ModuleName='xRemoteDesktopSessionHost';ModuleVersion="1.8.0.0"}

#endregion

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
    Alias = 'zCalculator'
    DisplayName = 'zCalculator'
    FilePath = '%SYSTEMDRIVE%\Windows\system32\win32calc.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

    xRDRemoteApp zRemoteDesktopConnection {
    CollectionName = $RDData.CollectionName
    Alias = 'zRemoteDesktopConnection'
    DisplayName = 'zRemoteDesktopConnection'
    FilePath = '%SYSTEMDRIVE%\Windows\system32\mstsc.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

    xRDRemoteApp zNotepad {
    CollectionName = $RDData.CollectionName
    Alias = 'zNotepad'
    DisplayName = 'zNotepad'
    FilePath = '%SYSTEMDRIVE%\Windows\notepad.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

    xRDRemoteApp zWordPad {
    CollectionName = $RDData.CollectionName
    Alias = 'zWordPad'
    DisplayName = 'zWordPad'
    FilePath = '%SYSTEMDRIVE%\Program Files\Windows NT\Accessories\wordpad.exe'
    DependsOn = '[xRDLicenseConfiguration]licenseconfig'
    }

}

}

RDS -OutputPath 'C:\Temp\RDSConfig\' -ConfigurationData $data -Verbose
