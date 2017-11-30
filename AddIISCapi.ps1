#target server URL
#$uri = "https://venafi-qa.humana.com/vedsdk/"
$uri = "https://louappwps1338/vedsdk/"

#Username and Password
$credential = Get-Credential -message "Enter a user with access to VED WebSDK"
$user = $credential.GetNetworkCredential().username
$pass = $credential.GetNetworkCredential().password
$json = @{ Username = $user;  Password = $pass; } | ConvertTo-JSON 




$appdriver = "appcapi"

#authorize
$Respone = Invoke-RestMethod -Uri $uri/Authorize/ -Method Post -ContentType "application/json" -Body $json
foreach ($i in $input)
{
$myhost = $i.servers
$cert = $i.Cert
$ip = $i.IP


$dn = "\VED\Policy\Humana Test, Dev, Int Devices & Apps\Windows Servers\$myhost"
$appname = $i.Site + "_" + $i.port
$friendname = $i.Site
$certdn = $i.CERT
$site = $i.Site
$port = $i.Port

# Applications are associated with devices by placing the applications underneath the device's ObjectDN
   $appdn = $dn + "\" + $appname
   $nal=@{ObjectDN=$appdn;Class=$appdriver;NameAttributeList=(@{Name="Friendly Name";Value=$friendname}, @{Name="Network Validation Disabled";Value="0"}, @{Name="Certificate";Value="$certdn"}, @{Name="Update IIS";Value="1"}, @{Name="Binding Port";Value="$port"},@{Name="Binding IP Address";Value="$ip"}, @{Name="Web Site Name";Value="$site"}, @{Name="Use Specified Host";Value="1"}, @{Name="SSL Listen Host";Value="$ip"}, @{Name="SSL Listen Port";Value="$port"})}
   $jscreate = convertto-json($nal)
   $result = (Invoke-RestMethod -Uri $uri/Config/Create -Body $jscreate -Method POST -ContentType 'application/json' -Header @{"X-Venafi-Api-Key"=$Respone.APIKey})
if ($result.Result -eq "1")
{
write-host "Successfully created app on $dn" 
}
else
{
write-host $result.Error
}}