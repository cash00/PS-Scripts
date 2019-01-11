
Configuration DisablePowerShell
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        WindowsFeature PowerShellV2 #ResourceName
        {
            Name = 'PowerShell-V2'
            Ensure = 'Absent'
            #IncludeAllSubFeature = $true
        }

        Script OptionalFeaturePowerShellV2
        {
            GetScript = {
                Return @{
                    Result = Get-WindowsOptionalFeature -Online -ErrorAction Continue | where {$_.FeatureName -Match "MicrosoftWindowsPowerShellV2"} | Out-String
                }
            }
            TestScript = {
                $WinOptFeat = Get-WindowsOptionalFeature -Online -ErrorAction Continue | where {$_.FeatureName -Match "MicrosoftWindowsPowerShellV2"}
                
                If ($WinOptFeat.State -eq 'DisabledWithPayloadRemoved') #$WinOptFeat.State -eq 'Disabled' -or $WinOptFeat.State -eq 'DisabledWithPayloadRemoved'
                {
                    Write-Verbose 'MicrosoftWindowsPowerShellV2 is in desired state.'
                    Return $true
                }
                Else
                {   
                    Write-Verbose 'MicrosoftWindowsPowerShellV2 is NOT in desired state.'
                    Return $false
                }
            }
            SetScript = {
                Write-Verbose 'Removing settings MicrosoftWindowsPowerShellV2.'
                Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -Remove -NoRestart -LogLevel WarningsInfo -ErrorAction Continue
            }
        }

    }#End of Node localhost

}

cd c:\temp
DisablePowerShell
Start-DscConfiguration -Path C:\temp\DisablePowerShell -Wait -Verbose -Force
"1"
###############################################################################
"2"
break
"3"

Get-DscConfiguration

dir 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Recurse
dir 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

"4"
###############################################################################
"5"
break
"6"

Configuration DisablePowerShellLogging
{
Param(
    $Paths = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        # Currently the registry resource does not support deleting an entire
        # key. So we will delete each key with a script resource.
        Script RemovePowerShellLogging
        {
            GetScript = {
                Return @{
                    Result = Get-Item -Path $Using:Paths -ErrorAction SilentlyContinue | Out-String
                }
            }
            TestScript = {
                If (Get-Item -Path $Using:Paths -ErrorAction SilentlyContinue) {
                    Write-Verbose "Registry keys for PowerShell logging and/or transcription found."
                    Return $false
                } Else {   
                    Write-Verbose "Registry keys for PowerShell logging and/or transcription NOT found."
                    Return $true
                }
            }
            SetScript = {
                Get-Item -Path $Using:Paths |
                    Remove-Item -Force -Confirm:$false -Verbose
            }
        }

    }

}

cd c:\temp
DisablePowerShellLogging
Start-DscConfiguration -Path C:\temp\DisablePowerShellLogging -Wait -Verbose -Force
"7"

break
"8"

dir 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Recurse

###############################################################################
"9"
break

# Note that the PowerShell policy is cached when the ISE or Console is opened.
# Run these commands in a fresh session to see the effect.
"Catch me if you can"

# Commands run, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4104 } -MaxEvents 5 | ft Message -Wrap
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4104 } -MaxEvents 5 | ? Message -like "*catch*" | ft Message -Wrap

# Commands started, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4105 } -MaxEvents 5 | ft TimeCreated,Message -Wrap

# Commands stopped, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4106 } -MaxEvents 5 | ft TimeCreated,Message -Wrap

# View the transcript output
# NOTE: Access denied if on a local path instead of UNC path
Get-ChildItem 'C:\PSTranscripts' -Recurse

