<#
Name:Send SCOM Alerts via SMS
Filename:SMS_SCRIPT.ps1
Author:Adrian Chia
Disclaimer:THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 Self Explanatory. If you do not know you should not even be looking at it!
===============================================================================================================================================================
Version History
===============
20160505 - V1.0: Initial Script
20170601 - V1.1: Modified Script to remove "Dept" variable
20170608 - V1.2: Modified Script to move transcript log to C:\temp\SMS_Logs\
20170615 - V1.3: Modified Script to check for BLD in Path & Source. Exit script if present.
20171109 - V1.4: Modified Script to check for office hour and Exit script.

===============================================================================================================================================================

Usage:.\SMS_SCRIPT.ps1 -Description "Whatever you want to put in here"

#>

[CmdletBinding()]
Param(
[String]$Description="Description"
)

#Get Date/Time for log
$logday = Get-Date -Format "yyyyMMdd"
$logtime = Get-Date -Format HHmmss

Start-Transcript -Path C:\temp\SMS_Logs\SMSTranscript_"$logday"_"$logtime".txt

#Get Mobile
$listcsv = Import-Csv C:\SMS\list.csv
#$listcsv = Import-Csv C:\SCOM_SMS\list_testing.csv #For testing

#Configure SMS Trace Log File Location
$Tracefile = "C:\temp\SMS_Logs\SMSLogTrace_$logday.log"

#Configure SMS Error Log File Location
$Errorfile = "C:\temp\SMS_Logs\SMSLogErrors_$logday.log"

#Configure SMS Alerts Log File Location
$Logfile = "C:\temp\SMS_Logs\SMSLogAlerts_$logday.log"

try{

$DateTime = Get-Date -Uformat "%y-%m-%d %H:%M:%S"

#Get Configuration
$ConfigXML = "C:\SMS\config.xml"
$xml = [xml](get-content $ConfigXML)
$SMSURL = $xml.Configuration.SMS.URL
$Username = $xml.Configuration.Credential.Username
$Password = $xml.Configuration.Credential.Password

#log inputs to trace file
Add-content $Tracefile -value "DateTime:$DateTime"
Add-content $Tracefile -value "Description:$Description"

#Exit script if during office hour
$todayhr = (Get-Date).Hour
$todayday = (Get-Date).DayOfWeek.value__
$starthr =  08
$endhr   =  18

<#
#Exit script if office hour
if($todayhr -ge $starthr -and $todayhr -le $endhr -and $todayday -lt 6)
{
    Add-content $Tracefile -value "Office Hour: DAY-$todayday && HOUR-$todayhr is, so end script and do not send SMS`r`n"
    Stop-Transcript
    Exit
    Add-content $Tracefile -value "Script exited this should not be logged`r`n"
}
#>

#Trim common words to save charater count
<#
if ($Category -like '*Health')
{
    $Category=$Category -replace ".{6}$"
}
elseif ($Category -like '*Collection')
{
    $Category=$Category -replace ".{10}$"
}
Add-content $Tracefile -value "TrimCategory:$Category"

#Delete '.its.cpfb.gov.sg' in Source
$Source=$Source -replace (".its.cpfb.gov.sg","")
Add-content $Tracefile -value "Source:$Source"

#Delete '.its.cpfb.gov.sg' in Path
$Path=$Path -replace (".its.cpfb.gov.sg","")
Add-content $Tracefile -value "Path:$Path"
#>

#Delete '.its.cpfb.gov.sg' in Description
$Description=$Description -replace (".its.cpfb.gov.sg","")
Add-content $Tracefile -value "Description1:$Description"

#Delete '\n ' in Description
$Description=$Description -replace ("\\n ","")
Add-content $Tracefile -value "Description2:$Description"

#Replace '\' with '/' in Description
$Description=$Description -replace ("\\","/")
Add-content $Tracefile -value "Description3:$Description"

#Count total charaters in the SCOM alert, if exceed 600 charaters truncate the alert(Max Char with space 744)
$totalCount="$DateTime$Description"
Add-content $Tracefile -value "totalCount:$totalCount"

if ($totalCount.Length -gt 600)
{
    $x=$totalCount.Length
    Add-content $Tracefile -value "totalCount:$x"
    $Description=$Description.subString(0, [System.Math]::Min(570, $Description.Length))
    Add-content $Tracefile -value "Description:$Description"
}

#Concate alerts to a single string
$Logstring = "Description:$Description"
$newline = "`r`n"
Add-content $Tracefile -value "Logstring:$Logstring"

$Name = ""
$Mobile = ""

foreach($list in $listcsv)
{
    $Name = $list.Name
    $Mobile = $list.Mobile
    Add-content $Tracefile -value "Name:$Name"
    Add-content $Tracefile -value "Mobile:$Mobile"

    $DateTime = Get-Date -Uformat "%y-%m-%d %H:%M:%S"

    $SMSUSER = "&u=$Username"
    $SMSPASS = "&h=$Password"
    $SMSOP = "&op=pv"
    $SMSNUM = "&to=$Mobile"
    $SMSMSG = "&msg=$DateTime`r`n$Logstring"
    $SMSFOOT = "&nofooter=1"

    $SMS1=$SMSURL+$SMSUSER+$SMSPASS+$SMSOP+$SMSNUM+$SMSMSG+$SMSFOOT
    Add-content $Tracefile -value "SMS1:$SMS1"

    #Invoke-WebRequest "http://192.168.1.31/index.php?app=ws&u=admin&h=4b194b66be5ed45577596b7843365929&op=pv&to=6596837828&msg=Hello+world&nofooter=1"
    
    Invoke-WebRequest $SMS1 -UseBasicParsing

    Add-content $Logfile -value $Name$newline$Mobile$newline$DateTime$newline$Logstring$newline
}

}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Add-content $Errorfile -value "$DateTime`r`nFailItem:$FailedItem`r`nErrorMessage:$ErrorMessage"
    Add-content $Errorfile -value "`r`n"
    Break
}

Add-content $Tracefile -value "`r`n"

#.\SMS_SCRIPT.ps1 "AlertName Description Severity Priority Category ResolutionStateName Path Source"
#.\SMS_SCRIPT.ps1 -Description "AlertName Description Severity Priority Category ResolutionStateName Path Source"

Stop-Transcript
Exit 0