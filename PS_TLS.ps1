#Force PowerShell to use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::'Ssl3','Tls';#default
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
[Net.ServicePointManager]::SecurityProtocol

#trust self-signed certificates
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
[System.Net.ServicePointManager]::ServerCertificateValidationCallback|fl

