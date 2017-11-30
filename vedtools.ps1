$global:epoch=Get-Date -Date "01/01/1970" # Epoch date
. .\vedapi.ps1
function VenafiGrab(){
    [cmdletbinding()]
    param(
        [string]$User, # Uses current API credentials otherwise
        [string]$OutFile="TempAttTest.txt",
        [string]$InFile,
        [string]$StartingDN="\Ved\"
    )
    if($User){
        $Oldcredi=$credi
        $credi=Get-Credential -UserName $User -Message "Venafi Username or AD Credential"
    }
    if(!$InFile){
        if(Test-Path $OutFile){
            "" > $OutFile
        }
        $OU=@()
        $PObjects=.\vedapi.ps1 -r config/enumerate -params ObjectDN,Recursive -values $StartingDN,1
        foreach($ODN in $PObjects.objects){
            $Vals=.\vedapi.ps1 -r config/readall -params ObjectDN -values $ODN.DN
            $CSS=.\vedapi.ps1 -r config/isvalid -params ObjectDN -values $ODN.DN
            $OU+=@{"DN"=$ODN.DN;"Data"=@{"PolicyValues"=$Vals.NameValues;"Class"=$CSS.object.TypeName}}
            if($OU.Count -ge 1){
                $OU | ConvertTo-Json -Depth 5 -Compress >> $OutFile
                Write-Verbose "$($OU | ConvertTo-Json -Depth 5 -Compress)"
                $OU=@()
            }
        }
    } elseif(Test-Path $InFile) {
        $JobCont=(Get-Content -path $InFile | ConvertFrom-Json)
        $JobSort=$JobCont.dn | Sort-Object length
        for($JC-1;$JC - $JobSort.Count;$jc++){
            $JobSort[$JC]
            "test"
            #$JobCont | Where-Object {$_.dn -match "$($JCDN -replace "\\","`\\")"}
        }
    }
    if($User){
        $credi=$Oldcredi
    }
}
function VenafiPush(){
    [cmdletbinding()]
    param(
        [string]$InFile,
        [switch]$Preview
    )
    if(Test-Path $InFile){
        $VedData=VenafiGrab -InFile $InFile
        foreach($VN in $VedData){
            # Double array because of splitting of job in previous function
            foreach($VD in $VN){
                $NAL=@()
                foreach($AL in $VD.Data.PolicyValues){
                    $NAL+=@{"Name"=$AL.name;"Value"="$($AL.Values)"}
                }
                $TM=@{"ObjectDN"=$VD.DN;"Class"=$VD.Data.Class;"NameAttributeList"=$NAL;"Preview"=$Preview.IsPresent}
                if($Preview){
                    createPolicyObj @TM
                } else {
                    createPolicyObj @TM
                }
                
            }
        }
    }
}
function userPrefs(){
    [cmdletbinding()]
    param(
        [string[]]$Preference,
        [string]$GUID='{fb01d95a-4c68-41c9-84fd-0e20ecfdb762}'
    )
    $Query="select * from config_contains where GUID like '%$GUID%' and Attribute = 'User Preferences'"
    $CPref=Invoke-Sqlcmd -Database Dictator -Query $Query 
    foreach($CP in $Preference){
        $CP
        $AttName=$(($CP -split '=')[0])
        $MatchedObject=$CPref | Where-Object {$_.attributevalue -match $AttName}
        if($CPref.AttributeValue -match $AttName){
            $UPDQ="Update config_contains set AttributeValue='$($CP)' where GUID = '$($MatchedObject.GUID)' and AttributeValue like '%$AttName%'"
            Write-Verbose $UPDQ
            invoke-sqlcmd -database Dictator $UPDQ
        } else {
            $INSQ="insert into config_contains values ('$GUID','User Preferences','$CP',0,0,0,0,0,0,0,0,0)"
            Write-Verbose $INSQ
            invoke-sqlcmd -database Dictator $INSQ
        }
    }
    
}
function renewall(){
    [CmdLetBinding()]
    param(
        [string]$ObjectDN
    )
    $CertList=@()
    $Ctypes=@(
    "X509 Certificate",
    "X509 Root Certificate",
    "X509 Intermediate Root Certificate",
    "X509 User Certificate",
    "X509 Device Certificate",
    "X509 Server Certificate",
    "Certificate Trust Bundle")
    foreach($C in $Ctypes){
        findObjClass -Class $C -R | %{$CertList+=$_.objects}
    }
    foreach($E in $CertList.DN){
        $Att=@{"ObjectDN"=$E;"AttributeName"="Work To Do";"Value"="1"}
        addAttributes @Att
    }
}
function resetall(){
    [CmdLetBinding()]
    param(
        [string]$ObjectDN
    )
    $CertList=@()
    $Ctypes=@(
    "X509 Certificate",
    "X509 Root Certificate",
    "X509 Intermediate Root Certificate",
    "X509 User Certificate",
    "X509 Device Certificate",
    "X509 Server Certificate",
    "Certificate Trust Bundle")
    foreach($C in $Ctypes){
        findObjClass -Class $C -R | %{$CertList+=$_.objects}
    }
    foreach($E in $CertList.DN){
        $Atts=@(@{"ObjectDN"=$E;"AttributeName"="Status";"Remove"=$true},
            @{"ObjectDN"=$E;"AttributeName"="In Error";"Remove"=$true},
            @{"ObjectDN"=$E;"AttributeName"="Stage";"Remove"=$true},
            @{"ObjectDN"=$E;"AttributeName"="Work To Do";"Remove"=$true})
        foreach($A in $Atts){
            addAttributes @A
        }

    }
}
function certificateDownload(){
    [cmdletbinding()]
    param(
        [string]$PolicyDN
    )
    $CERDN=$PolicyDN
    $Exists=(.\vedapi.ps1 -r config/isvalid -params ObjectDN -values $CERDN).object
    if($Exists -match "400"){
        createCertificate -PolicyDN msca -Subject $Subject
    }
    $CertificateData=.\vedapi.ps1 -r certificates/retrieve -params CertificateDN,Format,Password,IncludePrivateKey -values $CERDN,"Base64 (PKCS #8)",Passw0rd,$true
    if($CertificateData -match "500"){
        $Cert=@{"Status"="";"InError"=""}
        $Cert.Status=(addAttributes -ObjectDN $CERDN -AttributeName Status -Read).values
        $Cert.InError=(addAttributes -ObjectDN $CERDN -AttributeName "In Error" -Read).values
        $Cert
    } else {
        $CertificateData
    }
    
}
function addPolicyValue(){
    param(
        [string]$ObjectDN,
        [string]$AttributeName,
        [string]$Value,
        [string]$Class="x509 Certificate",
        [switch]$Locked,
        [switch]$Append,
        [switch]$Remove,
        [switch]$Preview
    )

    $remAttSplatt=@{"params"="ObjectDN","AttributeName","Class";
        "values"="$ObjectDN","$AttributeName","$Class";
        "r"="config/clearpolicyattribute";
        "log"="VedAutoMatedSetup";"preview"=$Preview.IsPresent}
    $addPVsplat=@{"params"="ObjectDN","AttributeName","Value","Class","Locked";
        "values"="$ObjectDN","$AttributeName",$Value,$Class,$Locked.IsPresent;
        "r"="config/addpolicyvalue";
        "log"="VedAutoMatedSetup";"preview"=$Preview.IsPresent}
    if(-not($Append)){
        .\vedapi.ps1 @remAttSplatt
    } 
    if($remove){   
        .\vedapi.ps1 @remAttSplatt
    } else {
        .\vedapi.ps1 @addPVsplat
    }
}
function CATemplate(){
        param(
            [string]$CAName,
            [string]$FN,
            [string]$Uname,
            [string]$Class,
            [string]$Path,
            [array]$NALName,
            [array]$NALVal,
            [array]$LockAtt,
            [array]$LockVal
        )
        $CADNpath="\VED\Policy\CA Templates\"
        $CredObjpath="\VED\Policy\Credentials\"
        $CertsPath="\VED\Policy\Certificates\"
        $CADN=$CADNpath+$CAName
        $CPDN=$CertsPath+$CAName
        $CRDN=$CredObjpath+$CAName
        $NameAttributeList=@()
        $lockSplatArr=@()
        for($NAL=0;$NAL -lt $NALName.Count;$NAL++){
            if($NALName[$NAL] -match "Credential"){
               $NameAttributeList+=@{"Name"=$NALName[$NAL];
                    "Value"="$CredObjpath"+$NALVal[$NAL]}
            } else {
               $NameAttributeList+=@{"Name"=$NALName[$NAL];
                    "Value"=$NALVal[$NAL]}
            }
        }
        for($LAT=0;$LAT -lt $LockAtt.Count;$LAT++){
            if($LockAtt[$LAT] -match "Certificate Authority"){
               $lockSplatArr+=@{"AttributeName"=$LockAtt[$LAT];
                    "Value"=$CADNpath+$LockVal[$LAT]}
            } else {
               $lockSplatArr+=@{"AttributeName"=$LockAtt[$LAT];
                    "Value"=$LockVal[$LAT]}
            }
        }
        $createCredSplat=@{"FriendlyName"="$FN";
            "CredentialPath"=$CAName}
        if($FN -eq "Certificate"){
            $createCredSplat+=@{"Path"="$Path"}
        } else {
            $createCredSplat+=@{"UserName"="$Uname"}
        }

        $caObjParam=@{"ObjectDN"="$CADN";
            "Class"="$Class";"NameAttributeList"=$NameAttributeList} 
        $caPolicyFolder=@{"ObjectDN"=$CPDN;
            "Class"="Policy"}
        createCredential @createCredSplat
        createPolicyObj @caObjParam
        createPolicyObj @caPolicyFolder
        foreach($PolicyAtt in $lockSplatArr){
            $PolicyAtt.Add("Class","x509 Certificate")
            $PolicyAtt.Add("Locked",$true)
            $PolicyAtt.Add("ObjectDN",$CPDN)
            addPolicyValue @PolicyAtt
        }
}
function createCredential(){
    # 15.1 - Does not work
    param(
        [ValidateSet("Certificate","UsernamePassword","Password")]
        [string]$FriendlyName,
        [string]$CredentialPath,
        [string]$UserName,
        [string]$Password,
        [string]$Type="string",
        [string]$Expiration, # Default UsernamePassword expires one year from the day
        [string]$Path
    )
    $call="credentials/create"
    $CredentialPath="\ved\policy\credentials\"+$CredentialPath
    switch($FriendlyName){
       "Certificate" {
            $b64d=Get-Content $Path -Encoding Byte -ReadCount 0
            $B64String=[System.Convert]::ToBase64String($b64d)
            $Expiration=(Get-PfxCertificate $Path).NotAfter
            $Exp=(New-TimeSpan -Start $global:epoch -End $Expiration).TotalMilliseconds
            $Date="/Date("+$Exp+")/"
            $Values=@( # Values for credentials/create
                @{"Name"="Certificate";
                "Type"="byte[]";"Value"="$B64String"},
                @{"Name"="Password";
                "Type"="string";"Value"="passw0rd"})
            $CredSplat=@{"params"="CredentialPath","FriendlyName","Expiration","Values"
                "values"=$CredentialPath,$FriendlyName,$Date,$Values}
        }
        "UsernamePassword" {
            if(-not($Expiration)){
                $Expiration=(Get-Date).AddYears(1) # Default expiration to 1 year
                $Exp=(New-TimeSpan -Start $global:epoch -End $Expiration).TotalMilliseconds
                $Date="/Date("+$Exp+")/"
            }
            if(-not($Password)){
                $Password=Read-Host $CredentialPath Password
            }
            $values=@(
                @{"Name"="Password";
                "Type"="$Type";"Value"="$Password"},
                @{"Name"="Username";
                "Type"="$type";"Value"="$Username"})
            $CredSplat=@{"params"="CredentialPath","FriendlyName","Expiration","Values"
                "values"=$CredentialPath,"$FriendlyName",$Date,$Values}
        }
        "Password" {
            if(-not($Expiration)){
                $Expiration=(Get-Date).AddYears(1) # Default expiration to 1 year
                $Exp=(New-TimeSpan -Start $global:epoch -End $Expiration).TotalMilliseconds
                $Date="/Date("+$Exp+")/"
            }
            if(-not($Password)){
                $Password=Read-Host $CredentialPath Password
            }
            $values=@( # Only Supply password for this type of credential
                @{"Name"="Password";
                "Type"="$Type";"Value"="$Password"})
            $CredSplat=@{"params"="CredentialPath","FriendlyName","Expiration","Values"
                "values"=$CredentialPath,"$FriendlyName",$Date,$Values}
        }
    }
    $addSplat=@{"r"=$call;"log"="VedAutoMatedSetup";"Preview"=$false}
    $CredSplat+=$addSplat
    .\vedapi.ps1 @CredSplat
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
        [switch]$Remove,
        [switch]$Preview
    )
    $addAttsplat=@{"params"="ObjectDN","AttributeName","Value";
        "values"="$ObjectDN","$AttributeName",$Value;
        "r"="config/addvalue";
        "log"="VedAutoMatedSetup";"preview"=$Preview.IsPresent}
    $readAttSplat=@{"params"="ObjectDN","AttributeName"
        "values"="$ObjectDN","$AttributeName";
        "r"="config/read";
        "log"="VedAutoMatedSetup";"preview"=$Preview.IsPresent}
    $remAttSplatt=@{"params"="ObjectDN","AttributeName";
        "values"="$ObjectDN","$AttributeName";
        "r"="config/clearattribute";
        "log"="VedAutoMatedSetup";"preview"=$Preview.IsPresent}
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
function createDiscoveryJob(){
    # Pleased
    param(
        [string[]]$IPRange="localhost",
        [string]$ports="1-1024",
        [string[]]$JobName="Discovery Default",
        [bool]$StartNow=$false,
        [switch]$CheckStatus,
        [switch]$Import
    )
    $CIDN="\ved\Discovery\"+$JobName
    $CPDN="\ved\policy\certificates\"+$JobName
    if($CheckStatus){
        $CheckStatusSplat=@{"ObjectDN"="$CIDN";
            "AttributeName"="Status";
            "Read"=$true}
        addAttributes @CheckStatusSplat
    } else {
        if(-not($Import)){
            $ports=$ports -replace " ",","
            $Range="$IPRange`:$ports"
            if($StartNow -eq $true){
                $SN="1"
            } else {
                $SN="0"
            }
            $NameAttributeList=@( # Configure Discovery Attributes
                @{"Name"="Address Range";"Value"="$Range"},
                @{"Name"="Start Now";"Value"="$SN"},
                @{"Name"="Contact";"Value"="$Identity"})
            $caObjParam=@{"ObjectDN"="$CIDN";
                "Class"="Discovery";"NameAttributeList"=$NameAttributeList} 
            $PolicyObjparam=@{"ObjectDN"="$CPDN";
                "Class"="Policy"}
            createPolicyObj @caObjParam
            createPolicyObj @PolicyObjparam
        } elseif($StartNow -and -not ($ports -or $IPRange)) {
            $startSplat=@{"ObjectDN"="$CIDN";
                "AttributeName"="Start Now";
                "Value"=1}
            addAttributes @startSplat
        } elseif($Import){
            $addDefDN=@{"ObjectDN"="$CIDN";
                "AttributeName"="Certificate Location DN";
                "Value"="$CPDN"}
            $addIMN=@{"ObjectDN"="$CIDN";
                "AttributeName"="Import Results Now";
                "Value"="1"}
            addAttributes @addDefDN
            addAttributes @addIMN
        }
    }
}
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
function createCertificate(){
    param(
        [string]$PolicyDN='MSCA',
        [string]$Subject="test.vfidev.com",
        [array]$CASpecificAttributes, # An array of objects with name,value params
        [switch]$Preview
    )
    if(($PolicyDN -split "\\").count -ge 1){
        $CRDN="\ved\policy\certificates\$PolicyDN"
    } else {
        $CRDN="$PolicyDN"
    }
    if($Subject -eq "test.vfidev.com"){ # Prevents duplicates up to 100 when using default
        $SubDN=(Get-Random -Minimum 0 -Maximum 100).ToString()
        $Subject=$SubDN+$Subject
    }
    if(-not($CASpecificAttributes)){
        $CASpecificAttributes=@(
            @{"Name"="Validity Period";"Value"="1"})
    }
    $CertReqSplat=@{"params"="PolicyDN","Subject"; # CADN not included, should be locked
        "values"="$CRDN","$Subject";
        "r"="certificates/request";
        "preview"=$preview.IsPresent;}
    
    if(-not ($PolicyDN -match "Self-Signed")){
        $CertReqSplat.params+="CASpecificAttributes"
        $CertReqSplat.values+=[array]$CASpecificAttributes
    }
    .\vedapi.ps1 @CertReqSplat
}
function createXCerts(){
    [CmdLetBinding()]
    param(
        [string]$CA="Self-Signed",
        [int]$NumberofCerts=10, # 4369 for all characters in utf 
        [switch]$Random,
        [switch]$Preview
        
    )
    $BadChars=@()
    if($Random){
        [array]$Names=randomAscii -NumOfWords $NumberofCerts -Length 1
    } else {
        $Names="-test.vfidev.com"
    }
    
    for($i=0;$i -lt $NumberofCerts;$i++){
        $AltName=randomAscii  -NumOfWords 1 -Random -Length 2
        $res=createCertificate -PolicyDN $CA -Subject "NewCert-$i"
        Write-Verbose $Names[$i]
        Write-Verbose $([string]$i+" of "+$NumberofCerts)
        $res
        if($res -match "Bad Request"){
            $L=$Names[$i] -split ""
            foreach($q in $L){
                $AltName=randomAscii -NumOfWords 1 -Random -Length 6
                $sr=createCertificate -PolicyDN $CA -Subject "3-$i"
                $sr
                if($sr -match "Bad Request"){
                    Write-Verbose "$q"
                    $q | Out-File C:\Users\jarek.ketcheside\badchars.txt -Append
                }
            }
        }
    }
}
function PortScanDiscovery(){
    [cmdletbinding()]
    param(
        [string]$ObjectDN="\VED\Policy\Certificates\APIDiscovery\",
        [int[]]$PortRange=443,
        [string[]]$IP="www.venafi.com",
        [string[]]$Protocol="all"
    )
    $PolicyDN="\VED\Policy\Certificates\APIDiscovery\"

    $PortScanSplat=@{"PortRange"="$PortRange";
        "IP"=$IP; "Protocol"="$Protocol"}
    $ScanResult=.\PortScan.ps1 @PortScanSplat
    foreach($n in $ScanResult.keys){;
        $DN=$ObjectDN+$n
        $Subject=$ScanResult.$n.sslData.RemoteCert.Subject
        $AppDN=$DN+"\APP-"+$ScanResult.$n.Port
        $CertDN=$AppDN+"\"+$Subject[0]
        $PK=$ScanResult.$n.sslData.RemoteCert.Cert | select -First 1
        $DeviceSplat=@{
            "Class"="Device";
            "ObjectDN"="$DN";
            "NameAttributList"=@(
                @{"Name"="Remote Server Type";"Value"="OS_AUTO"})}
        $ApplicationSplat=@{
            "Class"="Basic";
            "ObjectDN"="$AppDN";
            "NameAttributeList"=@(
                @{"Name"="Disabled";"Value"="0"},
                @{"Name"="Driver Name";"Value"="appbasic"})}
        $CertSplat=@{"Class"="X509 Certificate";
            "ObjectDN"="$CertDN";
            "NameAttributeList"=@(
                @{"Name"="Driver Name";"Value"="appx509certificate"},
                @{"Name"="X509 Subject";"Value"="$n"})}
        $StoreSplat=@{"Base64"="$PK";
            "OwnerDN"="$CertDN"}
        # Orphan protection Program
        if((createPolicyObj @DeviceSplat).Result -ne 401){
            Write-Verbose "$DN Created"
            if((createPolicyObj @ApplicationSplat).Result -ne 401){
                Write-Verbose "$AppDN Created"
                if((createPolicyObj @CertSplat).Result -ne 401){
                    $VaultID=(CertImport @StoreSplat).VaultId
                    $VaultCertSplat=@{"ObjectDN"=$CertDN;
                        "AttributeName"="Certificate Vault Id";
                        "Value"="$VaultID"}
                    Write-Verbose "$VaultID added to $CertDN"
                    if((addAttributes @VaultCertSplat).Result -ne 401){
                            Write-Host "$n Complete"
                    } else {Write-Error "$n Could not write attributes"}
                } else {Write-Error "$CertDN Could not be created"}
            } else {Write-Error "$AppDN Could not be created"}
        } else {Write-Error "$DN Could not be created"}
    }
}
function ReportOnCerts(){
    $Ctypes=@(
    "X509 Certificate",
    "X509 Root Certificate",
    "X509 Intermediate Root Certificate",
    "X509 User Certificate",
    "X509 Device Certificate",
    "X509 Server Certificate",
    "Certificate Trust Bundle")
    $Attributes=@('X509 Subject','Certificate Authority','PKCS10 Hash Algorithm','Key Bit Strength','Description',
        'Consumers','Certificate Vault Id','Contact','Approver')
    $FinalList=@{}
    $CertificateList=@{}
    foreach($t in $Ctypes){
        $CertificateList.$t=findObjClass -Class $t -ObjectDN \ved\ -R   
    }
    foreach($k in $CertificateList.Keys){
        foreach($n in $CertificateList[$k].objects){
            $FinalList.$($n.name)=@{"DN"=$n.DN}
            for($e=0; $e -lt $Attributes.Count;$e++){
                $RetVal=.\vedapi.ps1 -r config/readeffectivepolicy -params ObjectDN,AttributeName -values $n.DN,$Attributes[$e]
                if($RetVal.values -match "\*" -and $Attributes[$e] -match "x509 Subject"){
                    $FinalList.$($n.name).add("Wildcard",$true)
                } elseif($Attributes[$e] -match "x509 Subject" -and $RetVal.values -notmatch "\*") {
                    $FinalList.$($n.name).add("Wildcard",$false)
                }
                $Stringit=Out-String -InputObject $RetVal.Values
                $FinalList.$($n.name).add($Attributes[$e],$Stringit)
            }
            $Certificate=(.\vedapi.ps1 -r certificates/retrieve -params CertificateDN,Format -values $n.DN,Base64)
            $FI=[system.convert]::FromBase64String($Certificate.CertificateData)
            $CertData=[System.Text.Encoding]::UTF8.GetString($FI) | openssl x509 -noout -text
            $VF= ($CertData | sls "Not Before").ToString().Trim()
            $VT= ($CertData | sls "Not After").ToString().Trim()
            try { 
                $SAN=($CertData | sls "Subject Alt" -Context 0,1).ToString().Trim()
            } catch {
                $SAN="Unsupported"
            }
            $FinalList.$($n.name).add("Valid From",$VF)
            $FinalList.$($n.name).add("Valid To",$VT)
            if($SAN -notmatch "Unsupported"){
                $FinalList.$($n.name).add("SAN",$SAN)
            } else {
                $FinalList.$($n.name).add("SAN","Unsupported")
            }

        }
    }
    foreach($q in $FinalList.Keys){
        $FinalList[$q] | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Export-Csv -Append newest.csv -Force -NoTypeInformation
    }
}
function VersionCheckup(){
    [CmdLetBinding()]
    param(
        [string]$OutFile,
        [array]$Directories=@("C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.Core",
            "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.Core.Bootstrap",
            "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.MSBuild.AssemblyInfo",
            "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.Permissions",
            "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.ProductLogic.Ssh",
            "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.RTF",
            'C:\Program Files\Venafi')
    )
    function ExtraPlugins(){
        $Check=@{"Core"="C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Venafi.Core",@();
            "Utilities"="C:\Program Files\Venafi\Utilities",@();
            "Platform"="C:\Program Files\Venafi\Platform",@()}
        foreach($K in $Check.Keys){
            $Check.$K[1]+=Get-ChildItem -Recurse $Check.$K[0] -Include *.exe,*.dll
        }
        foreach($E in $Check.Keys){
            $CoreTime=$Check.Core[1] | select {$_.fullname},{$_.creationtime}
            $Check.$E[1] | Where-Object {$_.CreationTime -notmatch $Check.Core[1].CreationTime} | select {$_.Fullname},{$_.creationTime},{$_.versioninfo.fileversion} | ConvertTo-Json -Depth 10 | Tee-Object -FilePath $OutFile -Append
        }
    }
    if(Test-Path $OutFile){
        "" > $OutFile
    }
    $VedReg="HKLM:\SOFTWARE\Venafi"
    $ThumbPrints=@('B44994C905B4D411D1FB4F202E15857141200CCF')
    $RegVersion=Get-ChildItem -Recurse $VedReg | % { $_.GetValue("Version") -replace "\.0",""}
    $FileVersion=Get-ChildItem -Recurse $Directories -File | Where-Object {$_.Extension -match "(.dll|.exe)" -and ($_.FullName -notmatch "C:\\Program Files\\Venafi\\Utilities\\" -and $_.FullName -notmatch "C:\\Program Files\\Venafi\\SDK")}
    $FileList=@()
    $SigMismatch=@()
    foreach($File in $FileVersion){
        $DllThumbprint=(Get-AuthenticodeSignature $File.FullName).SignerCertificate
        if($ThumbPrint -match $DllThumbprint.Thumbprint){
            $FileList+=$File | select -ExpandProperty VersionInfo -Property FullName
        } else {
            $SigMismatch+=@{"Signature"=$DllThumbprint.Thumbprint;
                "File"=$File.FullName}
        }
    }
    foreach($V in $FileList){
        $FVersion=$V.FileVersion -split "\."
        $FV=$FVersion[0]+"."+$FVersion[1]+"."+$FVersion[2]
        if($FV -notmatch $RegVersion){
            $V >> $OutFile
            Write-Verbose $V
        }
    }
    $SigMismatch >> $OutFile
    Write-Verbose $($SigMismatch | ConvertTo-Json -Depth 10)
    ExtraPlugins
}
function webconfig(){
    param(
        [string[]]$Search=".*",
        [string]$OutFile
    )
    $Directories=@(
        "C:\Program Files\Venafi",
        "C:\Windows\Microsoft.NET\Framework",
        "C:\Windows\Microsoft.NET\Framework64")
    $ConfigDN=Get-ChildItem -Recurse -Path $Directories -Filter web.config
    $FinalContent=@()
    foreach($C in $ConfigDN){
        $Content=@{$C.FullName=$(Get-Content -Encoding String $C.FullName)}
        $FinalContent+=$Content
    }
    $MatchingObjects=$FinalContent | Where-Object {$_.values -match $Search} |  Sort-Object -Descending 
    foreach($M in $MatchingObjects){
        $M.keys
        $V=$M.Values | Select-String $Search
        $V
        if($OutFile){
            $V | Out-File -FilePath $OutFile -Append
        }
    }
}
function newCsr(){
    param(
        [string]$C="US",
        [string]$ST="UT",
        [string]$O="Venafi, Inc.",
        [string]$L="Utah",
        [string]$CN="Test-New-Cert",
        [switch]$V
    )
    if($V){
        $URL="http://192.168.132.128/CertificateProcessing/?DATA=C=$C|ST=$ST|O=$O|L=$L|CN=$CN&Verbose=1"        
    } else {
        $URL="http://192.168.132.128/CertificateProcessing/?DATA=C=$C|ST=$ST|O=$O|L=$L|CN=$CN"
    }
    (Invoke-WebRequest -uri $URL -Method Post).content
}
function deleteEverything(){
    (.\vedapi.ps1 -r config/enumerateall).objects | Where-Object {$_.DN -notmatch "\\ved\\Identity\\|\\ved\\Logging\\Event Definitions|\\VED\\Console\\UserPrefs\\"}  | %{.\vedapi.ps1 -r config/delete -params ObjectDN,Recursive -values $_.dn,1}
}
function DeviceApp(){
    param(
        [int]$Items,
        [string]$Name   
    )
    $Count=0
    for($I=0;$I -le $Items;$I++){
        $DDN=(createPolicyObj -Class Device -ObjectDN \ved\policy\16.3.2\Patch$($Name+$Count+"Device") -NameAttributeList @(@{"Name"="Host";"Value"="localhost"},
            @{"Name"="Remote Server Type";"Value"="OS_AUTO"})).Object.DN
        $APPDN=(createPolicyObj -Class CAPI -ObjectDN $($DDN+"\"+$Name+$Count+"App\") -NameAttributeList @(
            @{"Name"="Disabled";"Value"="0"},
            @{"Name"="Credential";"Value"="\VED\Policy\Credentials\MSCA"},
            @{"Name"="Driver Name";"Value"="appcapi"},
            @{"Name"="Friendly Name";"Value"="training1"},
            @{"Name"="Port";"Value"="5985"})).Object.DN
        $CERTDN=(createCertificate -PolicyDN $("MSCA\"+$Name+$Count+"Device\"+$Name+$Count+"App\") -Subject $($Name+$Count+"cert")).CertificateDN
        addAttributes -ObjectDN $CERTDN -AttributeName Consumers -Value $APPDN
        addAttributes -ObjectDN $APPDN -AttributeName Certificate -Value $CERTDN
        $OBJl=@{"Device"="$DDN";"Application"="$APPDN";"Certificate"="$CERTDN"}
        $OBJl
        $Count++
    }
}
