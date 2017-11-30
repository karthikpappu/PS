function findObjClass(){
    param(
        [string]$Class="x509 Certificate",
        [string]$ObjectDN="\ved\Policy",
        [switch]$R
    )
    $FindCSplat=@{"params"="Class","ObjectDN";
        "values"="$Class","$ObjectDN";
        "r"="config/findobjectsofclass";"preview"=$false;
        "log"="VedAutoMatedSetup"}
    if($R){
        $FindCSplat.params+="Recursive"
        $FindCSplat.values+=$True
    }
    .\vedapi.ps1 @FindCSplat
    
}
function createPolicyObj(){
    param(
        [string]$ObjectDN,
        [string]$Class, # Information about the CA template object
        [array]$NameAttributeList
    )

    $createCaTempSplat=@{"params"="ObjectDN","Class","NameAttributeList";
        "Values"=$ObjectDN,$Class,$NameAttributeList;
        "r"="config/create";"log"="VedAutoMatedSetup"
        "Preview"=$false}
    .\vedapi.ps1 @createCaTempSplat   
}
function addAttributes(){
    param(
        [string]$ObjectDN,
        [string]$AttributeName,
        [string]$Value,
        [switch]$Read,
        [switch]$Append,
        [switch]$Remove
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
    } elseif($Remove){
        .\vedapi.ps1 @remAttSplatt
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
$Devices=(findObjClass -Class Device -R -ObjectDN \ved\policy).objects
foreach($D in $Devices){
    $Dname=(($D.DN -split "\\")[-1] -split "\.")[0]
    $Application=(findObjClass -Class Basic -ObjectDN $D.DN -R).objects
    foreach($A in $Application){
        $ExistingCert=addAttributes -ObjectDN $A.DN -AttributeName Certificate -Read
        createPolicyObj -Class CAPI -ObjectDN "$($D.DN)\$Dname-444" -NameAttributeList @(@{"Name"="Driver Name";"Value"="appcapi"},
            @{"Name"="Disabled";"Value"="0"},
            @{"Name"="Update IIS";"Value"="0"},
            @{"Name"="Friendly Name";"Value"="$Dname"},
            @{"Name"="Credential";"Value"="\\VED\\Policy\Credentials\msca"},
            @{"Name"="Port";"Value"="5985"};
            @{"Name"="Certificate";"Value"="$ExistingCert"},
            @{"Name"="Managed By";"Value"="Aperture"},
            @{"Name"="Non-Exportable";"Value"="1"},
            @{"Name"="Description";"Value"="Created by API"}) | ConvertTo-Json
        
    }

}


