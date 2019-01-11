#$hostname = $env:computername
$hostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

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

$computername = $env:computername

LCM -OutputPath 'C:\Temp\LCMSettings\' -computername $computername -verbose
Set-DscLocalConfigurationManager -Path 'C:\Temp\LCMSettings\' -ComputerName $computername -Verbose -Force

Get-DscLocalConfigurationManager|fl