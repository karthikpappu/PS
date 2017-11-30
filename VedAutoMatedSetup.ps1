#. .\vedapi.ps1

#. .\vedtools.ps1
function identity(){
    param(
        [string]$Filter=$Credential.username,
        [int]$Limit=50,
        [int]$IdentityType=11,
        [switch]$GUID
    )
    $IDsplat=@{"params"="Filter","Limit","IdentityType";
        "values"="$Filter",$Limit,$IdentityType;
        "r"="identity/browse";"preview"=$false}
    $IDResult=.\vedapi.ps1 @IDsplat
    $IDResult
    if($GUID){
        foreach($i in $IDResult.Identities){
            $pre=$i.prefix
            $uni=$i.Universal
            if($i.prefix -eq "local"){
                $IDGUID="$pre`:$uni"            
            }
            if($i.prefix -eq "AD"){
                $IDGUID="$pre`:$uni"            
            }
            if($i.prefix -eq "LDAP"){
                $IDGUID="$pre`:$uni"            
            }
            $IDGUID
        }
    } else {
        $IDResult.identities.Prefix+":"+$IDResult.identities.universal  
    }

}
$Iden=(identity).identities
$Identity=($Iden.Prefix+":"+$Iden.Universal).trim()
function renameObject(){
    param(
        [string]$ObjectDN,
        [string]$NewObjectDN
    )
    $renameSplat=@{"params"="ObjectDN","NewObjectDN";
        "values"="$ObjectDN","$NewObjectDN";
        "r"="config/renameobject";"preview"=$false}
    .\vedapi.ps1 @renameSplat

}
function CASetupAuto(){
        $Symantec=@{"CAName"="SymantecMPKI";
            "FN"="Certificate";
            "Path"=".\vice2_pilot_api_willp_2017april23.p12";
            "Class"="VeriSign CA";
            "NALName"="Contact","Driver Name","SAN Enabled","Signature Algorithm",
                "Specific End Date Enabled","Template","Test Account","Validity Period","Credential","Organization";
            "NALVal"="$Identity","caverisign","0","sha256WithRSAEncryptionFull","0","Server","1","1","SymantecMPKI","Venafi";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="MPKI","0","Enrollment","Venafi, Inc","Sha256","0"}
        $ComodoWebReseller=@{"CAName"="Comodo Web Reseller";
            "FN"="Password";
            "Uname"="venaficomodo";
            "Class"="Comodo CA";
            "NALName"="Contact","Driver Name","SAN Enabled","Template","Test Account","Validity Period","Credential";
            "NALVal"="$Identity","cacomodo","1","24","1","1","Comodo Web Reseller";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="Comodo Web Reseller","0","Enrollment","Venafi, Inc","Sha256","0"}
        $ComodoCCM=@{"CAName"="ComodoCCM";
            "FN"="UsernamePassword";
            "Uname"="director";
            "Class"="Comodo CCM";
            "NALName"="Customer Login URI","Contact","Driver Name","SAN Enabled",
                "Template","Test Account","Validity Period","Organization","Secret Key","Credential";
            "NALVal"="https://demo.cert-manager.com/customer/venafi","$Identity","cacomodoccm","1","51","1","1","152","a1b2c3d4e5","ComodoCCM";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="ComodoCCM","0","Enrollment","Venafi, Inc","Sha256","0"}
        $Digicert=@{"CAName"="Digicert";
            "FN"="UsernamePassword";
            "Uname"="director";
            "Class"="DigiCert CA";
            "NALName"="Contact","Driver Name","SAN Enabled","Template","Test Account","Validity Period",
                "Account Number","Signature Algorithm","Profile ID","UC Allowed","API Key";
            "NALVal"="$Identity","cadigicert","0","SSL Plus","1","1",
                "107525","SHA256","Standard~~~!~~~Standard","1","mgrnh7nqd3bzf643rm2r5cwwngj5jf68";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="Digicert","0","Enrollment","Venafi TEST","Sha256","0"}
        $EntrustNet=@{"CAName"="EntrustNet";
            "FN"="Certificate";
            "Path"=".\entrust_net_pooling_api_2016oct12.p12";
            "Class"="EntrustNET CA";
            "NALName"="Contact","Driver Name","Organization","SAN Enabled","Signature Algorithm","Template",
                "Username Credential","Credential";
            "NALVal"="$Identity","caentrustnet","1: Venafi, Inc.","1","sha2","standard","Entrust Username",
                $CRDN+"EntrustNet";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="EntrustNet","0","Enrollment","Venafi, Inc.","Sha256","0"}
        $GlobalSign=@{"CAName"="GlobalSignMSSL";
            "FN"="UsernamePassword";
            "Uname"="PAR02900_venafitest";
            "Class"="GlobalSign MSSL CA";
            "NALName"="Contact","Validity Period","Driver Name","SAN Enabled","Signature Algorithm","Template","Test Account","Profile ID","Domain ID","Credential";
            "NALVal"="$Identity","1","caglobalsignmssl","0","SHA256","PV","1","02900_SMS2_000112","DSMS20000000126","GlobalSignMSSL";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="GlobalSignMSSL","0","Enrollment","Venafi, Inc.","Sha256","0"}
        $SelfSigned=@{"CAName"="Self-Signed";
            "Class"="Self Signed CA";
            "NALName"="Contact","Driver Name","Enhanced Key Usage","Key Usage","SAN Enabled";
            "NALVal"="$Identity","caselfsigned","1.3.6.1.5.5.7.3.2","None","1";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="Self-Signed","0","Enrollment","Venafi, Inc.","Sha256","0"}
        $MSCA=@{"CAName"="MSCA";
            "FN"="UsernamePassword";
            "Uname"="training1\administrator";
            "Class"="Microsoft CA";
            "NALName"="Contact","Driver Name","Credential","Given Name","Host","Include CN as SAN","Manual Approval","SAN Enabled","Template";
            "NALVal"="$Identity","camicrosoft","MSCA","training-primary-ca","localhost","0","0","0","User";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="MSCA","0","Enrollment","Venafi, Inc.","Sha256","0"}
        $MSCA1=@{"CAName"="MSCA1";
            "FN"="UsernamePassword";
            "Uname"="training1\administrator";
            "Class"="Microsoft CA";
            "NALName"="Contact","Driver Name","Credential","Given Name","Host","Include CN as SAN","Manual Approval","SAN Enabled","Template";
            "NALVal"="$Identity","camicrosoft","MSCA","training-primary-ca","localhost","0","0","0","Server";
            "LockAtt"="Certificate Authority","Enforce Unique Subject",
                "Management Type","Organization","PKCS10 Hash Algorithm","Prohibit Wildcard";
            "LockVal"="MSCA1","0","Enrollment","Venafi, Inc.","Sha256","0"}
        $CBlock=@(
            'Verizon Public SureServer SSL G14-SHA2 - 1 Year,5825',
            'Verizon Public SureServer EV SSL G14-SHA2 - 2 Year,6347',
            'Verizon Public SureServer EV SSL G14-SHA2 - 1 Year,6348');
        $VerizonCA=@{"CAName"="Verizon";
            "FN"="Certificate";
            "Path"=".\verizon_sureserver_staging_api_2017jan15.p12";"Class"="Verizon CA"
            "NALName"="Admin Email","Admin Firstname","Admin Surname","Admin Telnumber","Certificate Block","Contact","Driver Name","SAN Enabled","Template","Test Account","Credential";
            "NALVal"="michael.anderson@venafi.com","Michael","Anderson","801-676-6960","Verizon Public SureServer CA G14-SHA2/256 - 1 Year,721","$Identity","caverizon","0","721","1","Verizon";
            "LockAtt"="Verizon CA:Challenge Credential","Verizon CA:Server Type","Verizon CA:Tech Email","Verizon CA:Tech Firstname","Verizon CA:Tech Surname";
            "LockVal"="\ved\policy\credentials\Verizon Challenge Credential","1","j@a.com","J","A"}
        createCredential -FriendlyName UsernamePassword -UserName venafi -CredentialPath Entrust` Username
        createCredential -FriendlyName Password -CredentialPath Verizon` Challenge` Credential -Password "passw0rd"
        CATemplate @Symantec
        CATemplate @ComodoWebReseller
        CATemplate @ComodoCCM
        CATemplate @Digicert
        CATemplate @EntrustNet
        CATemplate @GlobalSign
        CATemplate @SelfSigned
        CATemplate @MSCA
        CATemplate @MSCA1
        CATemplate @VerizonCA
}
function checkObject(){
    param(
        [string]$ObjectDN
    )
    $checkObjSplat=@{"params"="ObjectDN";
        "values"="$ObjectDN";
        "r"="config/isvalid";
        "log"="VedAutoMatedSetup";
        "preview"=$false}
    .\vedapi.ps1 @checkObjSplat
}
function mutateObject(){
    param(
        [string]$ObjectDN,
        [string]$Class
    )
    $MutateSplat=@{"params"="ObjectDN","Class";
        "values"="$ObjectDN","$Class";
        "r"="config/mutateobject";"preview"=$false}
    .\vedapi.ps1 @MutateSplat

}
function policyFolderSetup(){
    param(
        [array]$PolicyFolders=@("\ved\policy\CA Templates","\ved\policy\Certificates","\ved\policy\Devices",
            "\ved\policy\User Certificates","\ved\policy\Workflow","\ved\policy\Credentials","\VED\Policy\Certificates\APIDiscovery"),
        [array]$caPolicyFolders=@("Comodo` Web` Reseller","ComodoCCM","DigiCert` Enterprise` Test",
            "EntrustNet","GlobalSign","Hydrant",@{"MSCA"=@("Folder1","Folder2","MSCA Import")},"OpenSSL","OpenTrust",
            "QuoVadis","RSA","SymantecMPKI","Thawte","Trend Micro",
            "TrustWave","Verizon Business","Xolphin","Self-Signed")
    )
    $CreatePolicyClassSplat=@{"Class"="Policy"}
    if($PolicyFolders.Count -ge 1){
        foreach($i in $PolicyFolders){
            $CreatePolicyClassSplat=@{"ObjectDN"="$i";
                "Class"="Policy"}
            createPolicyObj @CreatePolicyClassSplat
        }
    }
    if($caPolicyFolders.count -ge 1){
        foreach($o in $caPolicyFolders){
            if($o.values.count -ge 1){
                $PPF=$o.keys
                $CreatePolicyClassSplat.ObjectDN="\ved\policy\certificates\"+$o.keys
                $NR=$true
            } else {
                $CreatePolicyClassSplat.ObjectDN="\ved\policy\certificates\$o"
            }
            if($NR){
                foreach($PO in ($o."$PPF")){
                    $CreatePolicyClassSplat.ObjectDN="\ved\policy\certificates\"+$PPF+"\"+$PO
                    createPolicyObj @CreatePolicyClassSplat
                    $NR=$false
                }
            }
            createPolicyObj @CreatePolicyClassSplat
        }
    }
}
function applicationSetup(){
    param(
        [switch]$Discovery,
        [switch]$Mutate
    )
    function bigipf5(){
        param(
            [switch]$Discovery,
            [switch]$Import,
            [switch]$Mutate,
            [switch]$Rename,
            [switch]$Onboard
        )
        $Class="F5 LTM Advanced"
        $ScanDN="\VED\Discovery\F5 Scan"
        $PolicyDN="\VED\Policy\Certificates\F5 Scan"
        $OnboardDN="\VED\Discovery\F5 Onboard Scan"
        $PolicyOnboardDN="\VED\Policy\Certificates\F5 Scan\Onboard Scan"
        function f5configAtt(){
            $F5listSplat=@{"Class"="F5 LTM Advanced"}
            $F5ProvisonApp=@(@{"Driver Name"="appf5ltmadvanced"},
                @{"Provisioning To"="Standalone"},
                @{"SSL Profile Name"="VedAutoTest"},
                @{"SSL Profile Type"="Client"},
                @{"Use Basic Provisioning"="0"},
                @{"Virtual Server Name"="Common"};
                @{"Provisioning Work To Do"="1"};
                @{"Install Chain File"="0"};
                @{"Credential"="\ved\policy\credentials\F5 Credential"})
            $F5list=findObjClass @F5listSplat
            foreach($i in $F5list.objects){
                foreach($o in $F5ProvisonApp){
                    $addAtt=@{"ObjectDN"="$($i.dn)";
                        "AttributeName"="$($o.Keys)";
                        "Value"="$($o.Values)"}
                    addAttributes @addAtt
                }
            }
        }
        function f5Onboard(){
            $NameAttributeList=@(
                @{"Name"="Application Type";"Value"="F5 LTM Advanced"},
                @{"Name"="Certificates Placement Folder";"Value"="$PolicyOnboardDN"},
                @{"Name"="Devices Folder";"Value"="$PolicyDN"},
                @{"Name"="Extract Private Key";"Value"="0"},
                @{"Name"="Profiles To Import";"Value"="0"},
                @{"Name"="Start Now";"Value"="1"},
                @{"Name"="Driver Name";"Value"="appf5ltmadvanced"})
            $caObjParam=@{"ObjectDN"="$OnboardDN";"Class"="Onboard Discovery";
                "NameAttributeList"=$NameAttributeList}
            $PolicyObj=@{"ObjectDN"="$PolicyOnboardDN";
                "Class"="Policy"}
            createPolicyObj @caObjParam
            createPolicyObj @PolicyObj
        }
        function f5Mutate(){
            $Devices=findObjClass -Class "Basic"
            $f5Devices=($Devices.objects | Where-Object { $_.Parent -match "F5 Scan" }).DN
            foreach($i in $f5Devices){
                $f5Mutatesplat=@{"ObjectDN"="$i";"Class"="$Class"}
                $F5AttSplat=@{"DN"="$i"}
                mutateObject @f5Mutatesplat
                f5configAtt @F5AttSplat
            }
        }
        function f5Rename(){
            # Rename App to associated Certificate name port offset
            $F5=findObjClass -Class $Class
            foreach($i in $F5.objects){
                $ObjectDN=$i.DN
                $Regex=($PolicyDN+"\" | ConvertTo-Json).trim("`"")
                $CertList=addAttributes -Read -ObjectDN $ObjectDN -AttributeName Certificate
                $CertName=$CertList.Values -replace "$Regex",""
                $NewObjectDN=$ObjectDN+$CertName
                renameObject -ObjectDN $ObjectDN -NewObjectDN $NewObjectDN
            }
        }
        function f5Discovery(){
            $F5BigIP="192.168.3.2,192.168.5.173,192.168.6.77,192.168.6.83,192.168.6.78,192.168.6.94"
            $IsVal=checkObject -ObjectDN $ScanDN
            if($IsVal.Result -eq 400){
                $f5Discsplat=@{"IPRange"="$F5BigIP";
                    "ports"="443";"JobName"="F5 Scan";
                    "StartNow"=$true}
                createDiscoveryJob @f5Discsplat
            } else {
                $ScanStatus=createDiscoveryJob -CheckStatus -JobName "F5 Scan"
                $CheckDefDNSplat=@{"ObjectDN"="$ScanDN";
                    "AttributeName"="Certificate Location DN";
                    "Read"=$true}
                $DefaultDNset=addAttributes @CheckDefDNSplat
                if($ScanStatus.values -match "Scan Complete" -and $DefaultDNset.result -ne 1){
                    createDiscoveryJob -Import -JobName "F5 Scan"
                } else {
                    $ScanStatus
                }
            }
            $EnStat=@{"ObjectDN"="\ved\policy\certificates\F5 Scan";
                "AttributeName"="Management Type";
                "Read"=$true}
            $BIPS=addAttributes @EnStat
            if($BIPS){
                # Lock Policy Provisioning
                $f5Lock=@{"ObjectDN"=$PolicyDN;
                    "AttributeName"="Management Type";
                    "Class"="X509 Certificate";
                    "Value"="Provisioning";
                    "Locked"=$true}
                $f5Cred=@{"ObjectDN"="\ved\policy\Credentials\F5 Scan";
                    "FriendlyName"="UsernamePassword";
                    "UserName"="admin";
                    "Password"="passw0rd";
                    "CredentialPath"="F5 Credential"}
                createCredential @f5Cred
                addPolicyValue @f5Lock
            }
        }
        if($Discovery){
            f5Discovery
        }
        if($Mutate){
            f5Mutate
        }
        if($Rename){
            f5Rename
        }
        if($Onboard){
            f5Onboard
        }

    }
    function netscaler(){
        param(
            [switch]$Discovery,
            [switch]$Import,
            [switch]$Mutate,
            [switch]$Rename
        )
        $Class="NetScaler"
        $ScanDN="\ved\Discovery\NetScaler Scan"
        $PolicyDN="\VED\Policy\Certificates\NetScaler Scan"
        function nsMutate(){
            $Devices=findObjClass -Class "Basic"
            $nsDevices=($Devices.objects | Where-Object { $_.Parent -match "NetScaler Scan" }).DN
            foreach($i in $nsDevices){
                $nsMutatesplat=@{"ObjectDN"="$i";"Class"="$Class"}
                mutateObject @nsMutatesplat
            }
        }
        function nsRename(){
            # Rename App to associated Certificate name port offset
            $NS=findObjClass -Class $Class
            foreach($i in $NS.objects){
                $ObjectDN=$i.DN
                $Regex=($PolicyDN+"\" | ConvertTo-Json).trim("`"")
                $CertList=addAttributes -Read -ObjectDN $ObjectDN -AttributeName Certificate
                $CertName=$CertList.Values -replace "$Regex",""
                $NewObjectDN=$ObjectDN+$CertName
                renameObject -ObjectDN $ObjectDN -NewObjectDN $NewObjectDN 
            }
        }
        function nsDiscovery(){
            $NSIP="192.168.4.90,192.168.7.27,192.168.7.51,192.168.5.184"
            $IsVal=checkObject -ObjectDN $ScanDN
            if($IsVal.Result -eq 400){
                $nsDiscsplat=@{"IPRange"="$NSIP";
                    "ports"="443";"JobName"="NetScaler Scan";
                    "StartNow"=$true}
                createDiscoveryJob @nsDiscsplat
            } else {
                $ScanStatus=createDiscoveryJob -CheckStatus -JobName "NetScaler Scan"
                $CheckDefDNSplat=@{"ObjectDN"="$ScanDN";
                    "AttributeName"="Certificate Location DN";
                    "Read"=$true}
                $DefaultDNset=addAttributes @CheckDefDNSplat
                if($ScanStatus.values -match "Scan Complete" -and $DefaultDNset.result -ne 1){
                    createDiscoveryJob -Import -JobName "NetScaler Scan"
                } else {
                    $ScanStatus
                }
            }
        }
        if($Discovery){
            nsDiscovery
        }
        if($Mutate){
            nsMutate
        }
        if($Rename){
            nsRename
        }       
    }
    bigipf5 -Discovery
    netscaler -Discovery
    bigipf5 -Onboard

}
function randomAscii(){
    param(
        [int]$Length=15,
        [int]$NumOfWords=10,
        [switch]$Random,
        [switch]$RandLen
    )
    $Limit=10000
    $Words=@()
    $TW=@()
    if(!$Random){$IL=0}
    do {
        if($RandLen){
            $Length=Get-Random -Maximum 19
        }
        if($TW.Count -lt $Length){
            if($Random){
                $IL=Get-Random -Maximum $Limit
            } else {
                $IL++
            }
            $W=[char]$IL
            $TW+=$W
        } else {
            $Words+=$(-join [char[]]$TW)
            $TW=@()
        }
    } until ($Words.Count -ge $NumOfWords)
    $Words
}
function SecretStore(){
    param(
        [ValidateSet('0','1','2','4','8','16','32','64',
            '128','256','512','1024','2048','1073741826',
            '1073741828','1073741832','1073741840','1073741856',
            '1073741952','1073742080','1073742336','1073742848',
            '1073743872')]
        [string]$VaultType,
        [string]$KeyName="Null:Null",
        [string]$CertString,
        [string]$Namespace="Config",
        [string]$OwnerDN
    )
    $StoreSplat=@{"params"="VaultType","Keyname","Base64Data","Namespace","Owner";
        "values"="$VaultType","$KeyName","$CertString","$Namespace","$OwnerDN";
        "log"="VedAutoMatedSetup";
        "Preview"=$false;
        "r"="secretstore/add"}
    .\vedapi.ps1 @StoreSplat
}
function CertImport(){
    param(
        [string]$Base64,
        [string]$OwnerDN,
        [array]$TypedNameValues=@(@{"Name"="Custom Purpose";"Type"="string";"Value"="Tst"}),
        [string]$ProtectionKey
    )
    $CertImportSplat=@{"params"="CertificateString","OwnerDN","TypedNameValues";
        "values"="$Base64","$OwnerDN",$TypedNameValues;
        "r"="x509certificatestore/add";
        "log"="VedAutoMatedSetup";
        "Preview"=$false}
    .\vedapi.ps1 @CertImportSplat
}
function MassProvision(){
    param(
        [ValidateSet('MSCA','Self-Signed')]
        [string]$CA,
        [string]$Device,
        [string]$Application,
        [string]$IP,
        [int]$NumberOfCerts
    )
    $CSplat=@{"FriendlyName"="UsernamePassword";
        "CredentialPath"="Linux";
        "UserName"="jarek"}
    $NCred="\ved\policy\credentials\Linux"
    $Nal=@{"Name"="Host";"Value"="$IP"},
        @{"Name"="Credential";"Value"="$NCred"},
        @{"Name"="Remote Server Type";"Value"="OS_AUTO"},
        @{"Name"="Temp Directory";"Value"="/tmp"}
    $DSplat=@{"Class"="Device";
        "ObjectDN"="\ved\policy\certificates\$CA\APITest";
        "NameAttributeList"=$Nal}
    createPolicyObj @DSplat
    createCredential @CSplat
    $CertificatesMade=createXCerts -CA MSCA -NumberofCerts 10
    for($i = 0; $i -le $CertificatesMade.count;$i++){
        $AppDn="\ved\policy\certificates\$CA\APITest\App-$i"
        $CFile = ($CertificatesMade[$i]).CertificateDN -replace "\\VED\\Policy\\Certificates\\$CA\\",""
        $Nal1=@(
            @{"Name"="Certificate File";"Value"="/var/www/html/ssl/"+$CFile},
            @{"Name"="Disabled";"Value"="0";},
            @{"Name"="Driver Name";"Value"="appPem"},
            @{"Name"="Private Key File";"Value"="/var/www/html/ssl/"+$CFile},
            @{"Name"="Private Key Password Credential";"Value"="$NCred"})
        $ASplat=@{"Class"="PEM";
            "NameAttributeList"=$Nal1;
            "ObjectDN"="$AppDn"}
        createPolicyObj @ASplat
        $ATT1=@{"ObjectDN"=$AppDn;"AttributeName"="Certificate";"Value"=$CertificatesMade[$i]}
        $ATT2=@{"ObjectDN"=$CertificatesMade[$i];"AttributeName"="Consumers";"Value"=$AppDn}
        addAttributes @ATT1
        addAttributes @ATT2
    }

}
function ADUsers(){
    param(
        [switch]$Disable
    )
    function BabbleData(){
        $BabbleURL="https://libraryofbabel.info/book.cgi?0-w1-s1-v01:random"
        $Request=New-Object System.Net.WebClient
        $Response=$Request.DownloadString($BabbleURL) -split '<PRE id = "textblock">' -split '</PRE>'
        $Response[1]
    }
    $NameSource=(BabbleData)  -split "\.|`," -split "\s"
    function Rand($RandomInt){
        $Rand=Get-Random -Maximum $RandomInt
        return $Rand
    }
    $Date=Get-Date -Format MM/dd/yyyy` hh:mm:ss
    for($e =0;$e -lt 4;$e++ ){
        $GroupSplat=@{"Name"="ved-$e";
            "GroupScope"="DomainLocal"}
        try {
            New-ADGroup @GroupSplat
        } catch {
            
        }
    }
    $NewGroups=Get-ADGroup -Filter * | Where-Object {$_.distinguishedname -match "ved-"}
    $RandomInt=$NameSource.Length
    $PW=Read-Host -AsSecureString Password
    for($i =0; $i -lt $RandomInt;$i++ ){
        $ID=$NameSource[$(Rand($RandomInt))]
        $GR=$NewGroups[$(Rand($NewGroups.length))]
        $NU=@{"Enabled"=$True;
            "Name"="$ID";
            "EmailAddress"="$ID@training.local";
            "PassThru"=$true;
            "AccountPassword"=$PW}
        $AddADG=@{"Identity"="$GR";
            "Members"="$ID"}
        $GSID=$GR.sid.value.Substring($GR.sid.value.lastindexof("-")+1)
        New-ADUser @NU
        Add-ADGroupMember @AddADG
        
    }
    $Users=Get-ADGroup -Filter * | Where-Object {$_.distinguishedname -match "ved-"} | Get-ADGroupMember
    $Users | Enable-adaccount
}
function F5PTest(){
    $F5Stages=@((800..900))
    $Associate=@()
    foreach($F5 in $F5Stages){
        $Nal=@{"Name"="Rule";"Value"="028Venafi.Drivers.WFApplicationB-003$F5`C-044local:{9b22ac4c-20e1-4f88-ac1b-62644457a8fc}800"}
        $POSplat=@{"ObjectDN"="\VED\Policy\Workflow\F5-$F5";
            "Class"="Workflow";
            "NameAttributeList"=$Nal}
        $Associate+=$POSplat.ObjectDN
        createPolicyObj @POSplat
    }
    foreach($WD in $Associate){
        $PolicyDN="\VED\Policy\Certificates\f5 scan"
        addAttributes -ObjectDN $PolicyDN -AttributeName Workflow -Value $WD -Append
    }
}
Function SmokeTesting(){
    Get-EventLog -Verbose -LogName Application -EntryType Error,Warning -Newest 15 -ComputerName PRIMARY | ft -AutoSize
    apilog -rowCount 500 -show All | Where-Object {$_.Result -notmatch "Result=1|ObjectAlreadyExists|401"} | ft -AutoSize
}
function runall(){
    policyFolderSetup
    CASetupAuto
    createDiscoveryJob
    applicationSetup
    createXCerts -NumberofCerts 2
    createXCerts -ca MSCA -NumberofCerts 2
    DeviceApp -Items 10 -Name VedAutoSetup
    PortScanDiscovery
    
}