
Configuration AddGrp
{
Param(
)

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node localhost
    {
        xGroup LocalAdminGrp
        {
            GroupName = 'Administrators'
            MembersToInclude = 'VEGAS\RDS Test'
        }
    }
}

AddGrp -OutputPath 'C:\Temp\AddGrp' -Verbose
Start-DscConfiguration -Path 'C:\temp\AddGrp' -Wait -Verbose -Force

