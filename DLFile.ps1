
Configuration DLFile
{
Param(
)

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node localhost
    {
        xRemoteFile SysinternalsSuite_Nano
        {
            DestinationPath = 'C:\asd\SysinternalsSuite-Nano.zip'
            MatchSource = $True
            Uri = 'https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile SysinternalsSuite
        {
            DestinationPath = 'C:\asd\SysinternalsSuite.zip'
            MatchSource = $True
            Uri = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile ok_sysmon
        {
            DestinationPath = 'C:\asd\ok-sysmon.xml'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/ok-sysmon.xml'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile zabbix_agentd_win
        {
            DestinationPath = 'C:\asd\zabbix_agentd.win.conf'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/zabbix_agentd.win.conf'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile zabbix_agents_4_0_0_win_amd64
        {
            DestinationPath = 'C:\asd\zabbix_agents-4.0.0-win-amd64.zip'
            MatchSource = $True
            Uri = 'https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-amd64.zip' #'https://www.zabbix.com/downloads/4.0.0/zabbix_agents-4.0.0-win-i386.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile IISAdministration
        {
            DestinationPath = 'C:\asd\IISAdministration.zip'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/IISAdministration.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile RDWebClientManagement
        {
            DestinationPath = 'C:\asd\RDWebClientManagement.zip'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/RDWebClientManagement.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile xPSDesiredStateConfiguration
        {
            DestinationPath = 'C:\asd\xPSDesiredStateConfiguration.zip'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/xPSDesiredStateConfiguration.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }

        xRemoteFile xRemoteDesktopSessionHost
        {
            DestinationPath = 'C:\asd\xRemoteDesktopSessionHost.zip'
            MatchSource = $True
            Uri = 'https://raw.githubusercontent.com/cash00/PS-Scripts/master/xRemoteDesktopSessionHost.zip'
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }






    }
}

DLFile -OutputPath 'C:\Temp\DLFile' -Verbose
Start-DscConfiguration -Path 'C:\temp\DLFile' -Wait -Verbose -Force



