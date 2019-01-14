#Install-PackageProvider -Name NuGet -Force
#Get-PackageProvider -Name NuGet -Force
#Install-Module -Name xRemoteDesktopSessionHost -Force
#Get-DscResource -Module xRemoteDesktopSessionHost

Configuration CopyxRemoteDesktopSessionHost
{
    param (
    [parameter(Mandatory=$true)]
    [string[]]$computername
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $computername
    {
        Script CheckxRemoteDesktopSessionHostFolder
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

        File xRemoteDesktopSessionHost
        {
            DestinationPath = 'C:\Temp\xRemoteDesktopSessionHost.zip'
            Type            = 'File'
            #Ensure          = 'Present'
            DependsOn = '[Script]CheckxRemoteDesktopSessionHostFolder'
        }

        Archive UnzipxRemoteDesktopSessionHostFile #Unzip file
        {
            Destination = 'C:\Program Files\WindowsPowerShell\Modules\xRemoteDesktopSessionHost'
            Path = 'C:\Temp\xRemoteDesktopSessionHost.zip'
            Checksum = 'SHA-256'
            Validate = $true
            Force = $true
            Ensure = 'Present'
            DependsOn = '[File]xRemoteDesktopSessionHost'
        }
    }#End of Node localhost
}

$computername = $env:computername

CopyxRemoteDesktopSessionHost -OutputPath 'C:\Temp\CopyxRemoteDesktopSessionHost\' -computername $computername -verbose
Start-DscConfiguration -Path C:\Temp\CopyxRemoteDesktopSessionHost\ -Wait -Verbose -Force

Get-DscResource -Module xRemoteDesktopSessionHost|ft -AutoSize
