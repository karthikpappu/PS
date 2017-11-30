$global:Server= read-host 'serverFQDN/IP'
$global:user=read-host 'Username'
$global:pass=Read-Host 'Password' -AsSecureString


$uri='https://'+$Server+'/vedsdk/Authorize'
$pr=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
$hashobject=@{Username=$user;Password=$pr}
$json=$hashobject|ConvertTo-Json
$response=Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType 'Application/json'
$global:headers = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String], [String]]'
$headers.Add('X-Venafi-Api-Key', $response.APIKey)

$apiKey = $response.APIKey

$strOut = "My API Key is {0}" -f $apiKey
Write-Host $strOut

echo $response.APIKey