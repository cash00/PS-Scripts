[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem")
$Compression = [System.IO.Compression.CompressionLevel]::Optimal
$IncludeBaseDirectory = $false

$Source = "C:\test"
$Destination = "C:\TEMP\AAAAAAAAAAAAAAAA.zip"

[System.IO.Compression.ZipFile]::CreateFromDirectory($Source,$Destination,$Compression,$IncludeBaseDirectory)


Compress-Archive -LiteralPath 'C:\test' -DestinationPath "C:\TEMP\AAAAAAAAAAAAAAAA.zip" -CompressionLevel Optimal

Expand-Archive -LiteralPath "C:\TEMP\AAAAAAAAAAAAAAAA.zip" -DestinationPath "C:\" -Force




