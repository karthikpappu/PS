$DAR=@()
$OBJS=findObjClass -Class 'x509 User Certificate' -ObjectDN \ved -R
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

foreach($I in $OBJS.objects.dn){
    $I=($I -split "\\")[-1]
    (.\vedapi.ps1 -r secretstore/lookupbyassociation -params Name,Value -values 'CN',"$I").vaultIds
}
invoke-sqlcmd "select * from store_access as sa 
    join store_vault as sv on sa.VaultID=sv.VaultID 
    where sa.Owner='{d24c09ac-5632-42d8-9509-132232fff987}' and sv.VaultType=1073741826"