#Install-PackageProvider -Name NuGet -Force
#Get-PackageProvider -Name NuGet -Force
#Install-Module -Name xRemoteDesktopSessionHost -Force
#Get-DscResource -Module xRemoteDesktopSessionHost

Configuration CopyxModule
{
    param (
    [parameter(Mandatory=$true)]
    [string[]]$computername
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $computername
    {
        Script CheckIISAdministrationFolder
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'C:\Program Files\WindowsPowerShell\Modules\IISAdministration' | Out-String
                }
            }
            TestScript = {
                If ((Test-Path 'C:\Program Files\WindowsPowerShell\Modules\IISAdministration') -eq $true)
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\IISAdministration is present'
                    Return $false
                }
                else
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\IISAdministration is NOT present'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Folder present'
                Return $false
            }
        }

        File IISAdministration
        {
            DestinationPath = 'C:\Temp\IISAdministration.zip'
            Type            = 'File'
            #Ensure          = 'Present'
            DependsOn = '[Script]CheckIISAdministrationFolder'
        }

        Archive UnzipIISAdministrationFile #Unzip file
        {
            Destination = 'C:\Program Files\WindowsPowerShell\Modules\IISAdministration'
            Path = 'C:\Temp\IISAdministration.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]IISAdministration'
        }

########################################################################################################################

        Script CheckRDWebClientManagementFolder
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'C:\Program Files\WindowsPowerShell\Modules\RDWebClientManagement' | Out-String
                }
            }
            TestScript = {
                If ((Test-Path 'C:\Program Files\WindowsPowerShell\Modules\RDWebClientManagement') -eq $true)
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\RDWebClientManagement is present'
                    Return $false
                }
                else
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\RDWebClientManagement is NOT present'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Folder present'
                Return $false
            }
        }

        File RDWebClientManagement
        {
            DestinationPath = 'C:\Temp\RDWebClientManagement.zip'
            Type            = 'File'
            #Ensure          = 'Present'
            DependsOn = '[Script]CheckRDWebClientManagementFolder'
        }

        Archive UnzipRDWebClientManagementFile #Unzip file
        {
            Destination = 'C:\Program Files\WindowsPowerShell\Modules\RDWebClientManagement'
            Path = 'C:\Temp\RDWebClientManagement.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]RDWebClientManagement'
        }

########################################################################################################################

        Script CheckxPSDSCFolder
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'C:\Program Files\WindowsPowerShell\Modules\xPSDesiredStateConfiguration' | Out-String
                }
            }
            TestScript = {
                If ((Test-Path 'C:\Program Files\WindowsPowerShell\Modules\xPSDesiredStateConfiguration') -eq $true)
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\xPSDesiredStateConfiguration is present'
                    Return $false
                }
                else
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\xPSDesiredStateConfiguration is NOT present'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Folder present'
                Return $false
            }
        }

        File xPSDSC
        {
            DestinationPath = 'C:\Temp\xPSDesiredStateConfiguration.zip'
            Type            = 'File'
            #Ensure          = 'Present'
            DependsOn = '[Script]CheckxPSDSCFolder'
        }

        Archive UnzipxPSDSCFile #Unzip file
        {
            Destination = 'C:\Program Files\WindowsPowerShell\Modules\xPSDesiredStateConfiguration'
            Path = 'C:\Temp\xPSDesiredStateConfiguration.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]xPSDSC'
        }

########################################################################################################################

        Script CheckxRDSHostFolder
        {
            GetScript = {
                Return @{
                    Result = Test-Path 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost' | Out-String
                }
            }
            TestScript = {
                If ((Test-Path 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost') -eq $true)
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost is present'
                    Return $false
                }
                else
                {
                    Write-Verbose 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost is NOT present'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Folder present'
                Return $false
            }
        }

        File xRDSHost
        {
            DestinationPath = 'C:\Temp\xRemoteDesktopSessionHost.zip'
            Type            = 'File'
            #Ensure          = 'Present'
            DependsOn = '[Script]CheckxRDSHostFolder'
        }

        Archive UnzipxRDSHostFile #Unzip file
        {
            Destination = 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost'
            Path = 'C:\Temp\xRemoteDesktopSessionHost.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]xRDSHost'
        }

########################################################################################################################


########################################################################################################################


########################################################################################################################


########################################################################################################################


########################################################################################################################







    }#End of Node localhost
}

$computername = $env:computername

CopyxModule -OutputPath 'C:\Temp\CopyxModule\' -computername $computername -verbose
Start-DscConfiguration -Path C:\Temp\CopyxModule\ -Wait -Verbose -Force

Get-DscResource -Module xRemoteDesktopSessionHost|ft -AutoSize
