
$slackuri = 'https://hooks.slack.com/services/'
$ChannelID = '' #right click channel
$FN = $MyInvocation.MyCommand.Path.TrimEnd("Slack_Channel_POST.ps1")+'\Slack_JSON_test.JSON'
$data = Get-Content -Path $FN

$contype = 'application/json'
$meth = 'Post'

Invoke-RestMethod -Uri $slackuri -Body $data -ContentType $contype -Method $meth
