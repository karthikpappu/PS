function addAttributes(){
    param(
        [string]$ObjectDN,
        [string]$AttributeName,
        [string]$Value,
        [switch]$Read,
        [switch]$Append
    )
    $addAttsplat=@{"params"="ObjectDN","AttributeName","Value";
        "values"="$ObjectDN","$AttributeName",$Value;
        "r"="config/addvalue";
        "log"="VedAutoMatedSetup";"preview"=$false}
    $readAttSplat=@{"params"="ObjectDN","AttributeName"
        "values"="$ObjectDN","$AttributeName";
        "r"="config/read";
        "log"="VedAutoMatedSetup";"preview"=$false}
    $remAttSplatt=@{"params"="ObjectDN","AttributeName";
        "values"="$ObjectDN","$AttributeName";
        "r"="config/clearattribute";
        "log"="VedAutoMatedSetup";"preview"=$false}
    if($Read){
        .\vedapi.ps1 @readAttSplat
    } else {
        if(-not($Append) -and $Value){
            $original=.\vedapi.ps1 @readAttSplat
            .\vedapi.ps1 @remAttSplatt
        }
        if($Value){
            .\vedapi.ps1 @addAttsplat 
        }
    }
}
function findObjClass(){
    param(
        [string]$Class="x509 Certificate",
        [string]$ObjectDN="\ved\Policy"
    )
    $FindCSplat=@{"params"="Class","ObjectDN";
        "values"="$Class","$ObjectDN";
        "r"="config/findobjectsofclass";"preview"=$false;
        "log"="VedAutoMatedSetup"}
    .\vedapi.ps1 @FindCSplat
    
}
$Objects=findObjClass -Class "x509 Certificate"
foreach($i in $Objects.objects.dn){
    addAttributes -ObjectDN $i -AttributeName X509` Subject -Read
}

Get-ChildItem -Recurse Cert:\CurrentUser| Where-Object {$_.Thumbprint -match "32c77d"};Get-ChildItem -Recurse Cert:\LocalMachine| Where-Object {$_.Thumbprint -match "32c77d"}