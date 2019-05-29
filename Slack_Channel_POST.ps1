
$slackuri = 'https://hooks.slack.com/services/'
$ChannelID = '' #right click channel

$data = Get-Content -Path .\Slack_JSON_test.JSON

$contype = 'application/json'
$meth = 'Post'

Invoke-RestMethod -Uri $slackuri -Body $data -ContentType $contype -Method $meth
