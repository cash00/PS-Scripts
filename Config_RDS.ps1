#$hostname = $env:computername
$hostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

$data = @{
AllNodes = @()

RDSData = @{
    ConnectionBroker = $hostname
    SessionHost = $hostname
    WebAccessServer = $hostname
    CollectionName = 'zzzTEST'
    AutomaticReconnectionEnabled = $true
    DisconnectedSessionLimitMin = 360
    IdleSessionLimitMin = 360
    BrokenConnectionAction = 'Disconnect'
    UserGroup = 'RDS Test'
    LicenseServer = $hostname
    LicenseMode = 'PerUser'
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
AutomaticReconnectionEnabled = $true
DisconnectedSessionLimitMin = $RDData.DisconnectedSessionLimitMin
IdleSessionLimitMin = $RDData.IdleSessionLimitMin
BrokenConnectionAction = $RDData.BrokenConnectionAction
UserGroup = $RDData.UserGroup
DependsOn = '[xRDSessionCollection]collection'
}

xRDLicenseConfiguration licenseconfig {
ConnectionBroker = $RDData.ConnectionBroker
LicenseServer = $RDData.LicenseServer
LicenseMode = $RDData.LicenseMode
DependsOn = '[xRDSessionCollectionConfiguration]collectionconfig'
}

xRDRemoteApp zNotepad {
CollectionName = $RDData.CollectionName
Alias = 'zNotepad'
DisplayName = 'zNotepad'
FilePath = 'C:\Windows\notepad.exe'
DependsOn = '[xRDLicenseConfiguration]licenseconfig'
}
}

}

RDS -OutputPath 'C:\Temp\RDSConfig\' -ConfigurationData $data -Verbose
