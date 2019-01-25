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
#$hostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

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
$Script = "2016_CredSSP" #<REPLACE WITH THE SCRIPT NAME>
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
dir $env:PSModulePath.Split(";")
"======================================================================================================================================"
"profile: "+$profile
dir $profile
"======================================================================================================================================"

"BEFORE"
Get-Module|ft -Property * -AutoSize

Import-Module -Name Dism -Force -Verbose

Import-Module -Name ServerManager -Force -Verbose
"AFTER"
Get-Module|ft -Property * -AutoSize

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

    If (Get-HotFix|where {($_.HotFixID -match "KB4103723") -or ($_.HotFixID -match "KB4103731") -or ($_.HotFixID -match "KB4103727")})
    {
        #List Hotfix
        Get-HotFix|where {($_.HotFixID -match "KB4103723") -or ($_.HotFixID -match "KB4103731") -or ($_.HotFixID -match "KB4103727")}

        #Add the vulnerability key to allow unpatched clients
        REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f

        #Disable windows firewall
        Invoke-Command –Computername "localhost" –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -Force}
        Invoke-Command –Computername "localhost" –ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}
        Invoke-Command –Computername "localhost" –ScriptBlock {Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False}
        Invoke-Command –Computername "localhost" –ScriptBlock {netsh advfirewall set allprofiles state off}
        Invoke-Command –Computername "localhost" –ScriptBlock {Auditpol /set /subcategory:"Registry" /success:enable /failure:disable}
    }
    else
    {
        $output1 = "$path\windows10.0-kb4103723-x64_2adf2ea2d09b3052d241c40ba55e89741121e07e.msu"

        If ((Test-Path $output1) -eq $false)
        {
            ##Download the KB file
            $source = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/05/windows10.0-kb4103723-x64_2adf2ea2d09b3052d241c40ba55e89741121e07e.msu"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($source,$output1)
        }

        #Install the KB
        expand -F:* $output1 C:\Temp\
        dism /ONLINE /add-package /packagepath:"C:\Temp\Windows10.0-KB4103723-x64.cab" /norestart

        #Add the vulnerability key to allow unpatched clients
        REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f
    
        #Disable windows firewall
        Invoke-Command –Computername "localhost" –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -Force}
        Invoke-Command –Computername "localhost" –ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}
        Invoke-Command –Computername "localhost" –ScriptBlock {Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False}
        Invoke-Command –Computername "localhost" –ScriptBlock {netsh advfirewall set allprofiles state off}
        Invoke-Command –Computername "localhost" –ScriptBlock {Auditpol /set /subcategory:"Registry" /success:enable /failure:disable}

        #Restart the VM to complete the installations/settings
        #shutdown /r /t 0 /f
    }
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
