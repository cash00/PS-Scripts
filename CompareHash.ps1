Get-FileHash -Path C:\VisualStudioEnt2017\VisualStudioEnt2017.* -Algorithm SHA1 -Verbose|Export-Csv -NoTypeInformation -Path C:\VisualStudioEnt2017\list.csv -Verbose

$listcsv = Import-Csv C:\VisualStudioEnt2017\list.csv

foreach($list in $listcsv)
{
    $Algo = $list.Algorithm
    $Hash = $list.Hash
    $Fn = $list.Path
    $Fn
    Write-Host "Hash   :" $Hash

    $Compare = (Get-FileHash -Path $Fn -Algorithm $Algo).Hash

    Write-Host "Compare:" $Compare

    if ($Compare -eq $Hash)
    {
    Write-Host "OK" -ForegroundColor Green
    }
    else
    {
    Write-Host "NOT OK" -ForegroundColor Red
    }
}

