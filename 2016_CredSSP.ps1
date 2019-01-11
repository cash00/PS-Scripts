#Create a download location
$path = "C:\Temp"


if (!(test-path $path))
{
    New-Item -Path $path -ItemType directory
}

If (Get-HotFix|where {($_.HotFixID -match "KB4103723") -or ($_.HotFixID -match "KB4103731") -or ($_.HotFixID -match "KB4103727")})
{
    Get-HotFix|where {($_.HotFixID -match "KB4103723") -or ($_.HotFixID -match "KB4103731") -or ($_.HotFixID -match "KB4103727")}

    Invoke-Command –Computername "localhost" –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -Force}

    Invoke-Command –Computername "localhost" –ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}

    Invoke-Command –Computername "localhost" –ScriptBlock {Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False}

    Invoke-Command –Computername "localhost" –ScriptBlock {netsh advfirewall set allprofiles state off}
}
else
{
If ((Test-Path $output1) -eq $false)
{
    ##Download the KB file
    $source = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/05/windows10.0-kb4103723-x64_2adf2ea2d09b3052d241c40ba55e89741121e07e.msu"
    $output1 = "$path\windows10.0-kb4103723-x64_2adf2ea2d09b3052d241c40ba55e89741121e07e.msu"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($source,$output1)
    }

    #Install the KB
    expand -F:* $output1 C:\Temp\
    dism /ONLINE /add-package /packagepath:"C:\Temp\Windows10.0-KB4103723-x64.cab" /norestart

    #Add the vulnerability key to allow unpatched clients
    REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f

    Invoke-Command –Computername "localhost" –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -Force}
    
    Invoke-Command –Computername "localhost" –ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}

    Invoke-Command –Computername "localhost" –ScriptBlock {Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False}

    Invoke-Command –Computername "localhost" –ScriptBlock {netsh advfirewall set allprofiles state off}
    #Restart the VM to complete the installations/settings
    #shutdown /r /t 0 /f
}