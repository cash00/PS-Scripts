#Create a download location
$path = "C:\Temp"

if (!(test-path $path))
{
    New-Item -Path $path -ItemType directory
}

If (Get-HotFix|where {($_.HotFixID -match "KB4103715") -or ($_.HotFixID -match "KB4103725")})
{
    Get-HotFix|where {($_.HotFixID -match "KB4103715") -or ($_.HotFixID -match "KB4103725")}

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
    $source = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/05/windows8.1-kb4103725-x64_cdf9b5a3be2fd4fc69bc23a617402e69004737d9.msu"
    $output1 = "$path\windows8.1-kb4103725-x64_cdf9b5a3be2fd4fc69bc23a617402e69004737d9.msu"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($source,$output1)
    }

    #Install the KB
    expand -F:* $output1 C:\Temp\
    dism /ONLINE /add-package /packagepath:"C:\Temp\Windows8.1-KB4103725-x64.cab" /norestart

    #Add the vulnerability key to allow unpatched clients
    REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f

    Invoke-Command –Computername "localhost" –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -Force}

    Invoke-Command –Computername "localhost" –ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}
    
    Invoke-Command –Computername "localhost" –ScriptBlock {Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False}

    Invoke-Command –Computername "localhost" –ScriptBlock {netsh advfirewall set allprofiles state off}

    #Restart the VM to complete the installations/settings
    #shutdown /r /t 0 /f
}
