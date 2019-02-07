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
$Script = "CopyxModule" #<REPLACE WITH THE SCRIPT NAME>
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
#$path = '\\'+$hostname+'\C$\temp\'+$Script

$outlog = "$path\$hostname"+"_"+"$Script"+"_"+"$datetime.txt"
$errlog = "C:\temp\$Script"+"Err_"+"$datetime.txt"
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
    }#End of Node localhost
}

CopyxModule -OutputPath 'C:\Temp\CopyxModule\' -computername $hostname -verbose

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

    Start-DscConfiguration -Path C:\Temp\CopyxModule\ -Wait -Verbose -Force

    Get-DscResource -Module IISAdministration|ft -AutoSize
    Get-DscResource -Module RDWebClientManagement|ft -AutoSize
    Get-DscResource -Module xPSDesiredStateConfiguration|ft -AutoSize
    Get-DscResource -Module xRemoteDesktopSessionHost|ft -AutoSize
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
