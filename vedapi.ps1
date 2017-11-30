param(
    [ValidateSet("AD","ApprovalExplanation","ApprovalFrom","ApprovalReason","Approver",
    "Associate","Attribute","AttributeDefinition","AttributeDefinitions","AttributeName",
    "CASpecificAttributes","Filter","Limit","IdentityType","AttributeNames",
    "Certificate","CertificateCollection","CertificateCollectionStrings","CertificateData",
    "CertificateDetails","CertificateDN","CertificateString","Class","ClassDefinition",
    "ClassDefinitions","ClassInvalidSuperClass","ClassName","ClassNames","CN","CADN","Component",
    "ConfigAttribute","ConfigAttributeNameValue","ConfigClass","ConfigCreateFailed",
    "ConfigDeleteFailed","ConfigDnNotfolder","ConfigLockFailed","ConfigObject",
    "ConfigPolicy","ConfigReadFailed","ConfigWriteFailed","Contact","Count",
    "Create","Created","CreatedOn","CreatedOnGreater","CreatedOnLess","CredentialInfos",
    "CredentialPath","Data","DataRange","DateTime","DaysToExpiration","DefaultDN","DefaultKey",
    "Delete","DerivedFrom","Description","DeviceGuid","Disabled","DN","EncryptionKey",
    "EncryptionKeys","Error","Expiration","Explanation","ExplicitPermissions","File","Filename",
    "Filepath","Fingerprint","folders","Format","FriendlyName","Generational","Generic","GenericFailure",
    "GroupBy","Grouping","GUID","GuidData","HierarchicalGUID","Hostname",
    "ID","Identities","Identity","IdentityEntry","ImplicitPermissions","InError",
    "InsufficientPrivileges","Integer","InvalidClass","InvalidConfigObject","InvalidDN",
    "InvalidItem","InvalidMetadataObject","InvalidName","InvalidPolicyState","InvalidRights",
    "IsAssociateAllowed","IsCreateAllowed","IsDeleteAllowed","IsManagePermissionsAllowed",
    "IsPolicyWriteAllowed","IsPrivateKeyReadAllowed","IsPrivateKeyWriteAllowed","IsReadAllowed",
    "IsRenameAllowed","IsRevokeAllowed","IssuedDueTo","Issuer","IncludePrivateKey",
    "IsViewAllowed","IsWriteAllowed","Item","ItemAlreadyExists","ItemGuid","ItemGuids",
    "ItemIsNull","ItemNotValidForClass","Items","ItemTypeUnknown","Key","KeyAlgorithm",
    "KeyData","KeyId","Keyname","Keynames","KeysetData","KeysetId","KeySize","KeySizeGreater",
    "KeySizeLess","KeyUsageId","LeafExisted","limit","List","Local","Locked","ManagementType",
    "MetadataInUse","MetadataObject","minAllowedKeyLength","Name","Namespace","NameTooLong",
    "NameValues","NameAttributeList","NetworkValidationDisabled","NewCredentialPath","NewObjectDN","NoAllowedValues",
    "Object","ObjectDN","ObjectGUID","Objects","Overridden","Owner","OwnerDN","Owners","PageSize",
    "Parameter","ParentDn","ParentDnRecursive","Password","Pattern","PendingWorkflow","PolicyDN",
    "PolicyDn","PolicyItems","principal","PrivateKey","ProcessingDetails","Provisioning","Read",
    "Reason","Recursive","ReferenceAttributeName","Rename","RenewalDetails","Requested","ResolveNested",
    "Response","Returns","Revision","Revoke","Revoked","ScheduledStart","ScheduledStop","SchemaClass",
    "Serial","ServerName","SeverAccount","Severity","Shared","SignatureAlgorithm","SshDeviceData",
    "SshKeyUsageData","Stage","StageGreater","StageLess","Status","String","Subject","TooManyfolders","TotalCount",
    "Type","TypedNameValues","Updated","UserData","Username","UsernamePassword","ValidationDetails",
    "ValidationDisabled","ValidFrom","ValidTo","ValidToGreater","ValidToLess",
    "ValidUntil","Value","ValueNotInAllowedList","Values","VaultID","VaultIDs","VaultType","View","Write","Text1","Text2","PKCS10","Value1","Value2",
    $null)] # Params
    [array]$params,
    # If provided, Values should be in order of the params
    [array]$values,
    [ValidateSet("authorize","authorize/checkvalid","certificates/renew",
    "certificates/request","certificates/retrieve","certificates/revoke",
    "config/adddnvalue","config/addpolicyvalue","config/addvalue","config/clearattribute",
    "config/clearpolicyattribute","config/containableclasses","config/create",
    "config/defaultdn","config/delete","config/dntoguid","config/enumerate",
    "config/enumerateall","config/enumeratefolders","config/enumerateobjectsderivedfrom",
    "config/enumeratepolicies","config/find","config/findcontainers",
    "config/findfolders","config/findobjectsofclass","config/findpolicy",
    "config/gethighestrevision","config/getrevision","config/guidtodn","config/isvalid",
    "config/mutateobject","config/read","config/readall","config/readdn","config/readdnreferences",
    "config/readeffectivepolicy","config/readpolicy","config/removeattributevalues",
    "config/removednvalue","config/removepolicyvalue","config/removevalue","config/renameobject",
    "configrights/getobjectrights","configrights/getobjecttrustees","configrights/grantobjectrights",
    "configrights/removeobjectrights","config/write","config/writedn","config/writepolicy",
    "credentials/create","credentials/delete","credentials/deletecontainer","credentials/enumerate",
    "credentials/rename","credentials/renamecontainer","credentials/retrieve","credentials/update",
    "crypto/availablekeys","crypto/defaultkey","identity/browse","identity/getassociatedentries",
    "identity/getmembers","identity/getmemberships","identity/readattribute","identity/self",
    "identity/validate","log","metadata/defineitem","metadata/find","metadata/finditem",
    "metadata/get","metadata/getitemguids","metadata/getpolicyitems","metadata/items",
    "metadata/readeffectivevalues","metadata/readpolicy","metadata/set","metadata/setpolicy",
    "metadata/undefineitem","metadata/updateitem","permissions/object","rights/add",
    "rights/find","rights/get","rights/getright","rights/gettoken","rights/match","rights/refresh",
    "rights/remove","rights/removeall","rights/removeallbyprefix","secretstore/add",
    "secretstore/associate","secretstore/delete","secretstore/dissociate",
    "secretstore/encryptionkeysinuse","secretstore/lookup","secretstore/lookupbyassociation",
    "secretstore/lookupbyowner","secretstore/lookupbyvaulttype","secretstore/mutate","secretstore/orphanlookup",
    "secretstore/owneradd","secretstore/ownerdelete","secretstore/ownerlookup","secretstore/retrieve",
    "ssh/addauthorizedkey","ssh/addknownhostkey","ssh/adduserprivatekey","ssh/cancelkeyoperation",
    "ssh/cancelrotation","ssh/devices","ssh/importauthorizedkey","ssh/importprivatekey","ssh/keydetails",
    "ssh/keysetdetails","ssh/removekey","ssh/retrykeyoperation","ssh/retryrotation","ssh/rotate",
    "ssh/widget/stats","workflow/ticket/create","workflow/ticket/delete","workflow/ticket/details",
    "workflow/ticket/enumerate","workflow/ticket/exists","workflow/ticket/status",
    "workflow/ticket/updatestatus","x509certificatestore/add","x509certificatestore/lookup",
    "x509certificatestore/lookupexpiring","x509certificatestore/remove","x509certificatestore/retrieve")] # Calls
    [string]$r,
    [string]$server="venafiuat.ntrs.com",
    [System.Management.Automation.CredentialAttribute()]
    $Credential=$credi,
    [string]$log, # Saved in Json format, .VedApiLog extension
    [switch]$preview, <# Prievew the json #>
    [switch]$help,
    [switch]$ShowKey
)
$credi=$Credential
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$sUri="https://$server/vedsdk/"
function apilog(){
    param(
        [string]$path=".\VedAutoMatedSetup.VedApilog",
        [string]$rowCount=10, # Default is 10 from last
        [ValidateSet("Url","Result","Json","APIKey","callID","All","Failed")]
        [string[]]$show,
        [int[]]$CallID
    )
    if($show -match "all"){
        $show=@("Url","Result","Json","APIKey")
    }
    if($rowCount -match "all"){
        $apilog=Get-Content -Path $path | ConvertFrom-Json
    } elseif($show -match "Failed"){
        $apilog=Get-Content -Path .\Fuzz.VedApilog  | ConvertFrom-Json | Where-Object {$_.Result -match "bad"} | select -ExpandProperty Json 
    } else {
        $apilog=Get-Content -Path $path | select -Last $rowCount | ConvertFrom-Json
    }
    if($show -and $CallID){
        $show+="callID"
        $apilog | Select-Object -Property $show | Where-Object {$_.callID -in $CallID}
    } elseif($show -notmatch "Failed") {
        $apilog | Select-Object -Property $show 
    } else {
        $apilog
    }
}
function auth(){
    <# Function to obtain an API key with the credentials provided #>
    $pass=$credential.password 
    $pr=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
    $api_auth_Obj=@{"Username"="$($credential.UserName)";"Password"="$pr"} # Build Auth Obj
    $sUri=$($sUri)+"authorize" # Specifically define auth URL
    $api_auth_Json=ConvertTo-Json $api_auth_Obj -Compress # Convert Object to json, Compress 
    try{
        # Try and authenticate, obtain API key
        $api_auth_resp=Invoke-RestMethod -uri $sUri -body $api_auth_Json -method Post -ContentType 'application/json' -UseDefaultCredentials #Changed to get 
        $apiKey=$api_auth_resp.APIKey
        $global:apiKeyObj=@{"X-Venafi-Api-Key"="$apiKey"} # Set the global variable value
    } catch {
        $_.Exception
    }
}
function api_request(){
    <# Generally run FROM build_rest, can also take variables directly #>
    param(
        [object]$params, # If provided, format is @{"Param Name"="Value"}, Takes variable
        [string]$r, # Request URL
        [string]$log # Log information on the request
    )
    $rUri=$($sUri)+$r
    $params=$params | ConvertTo-Json -Compress -Depth 10 # Convert the values to json
    if($log){
        $lastID=(Get-Content -Path $($log+".VedApiLog") | select -last 1 | ConvertFrom-Json).callID
        $lastID=$lastID+1
    } else {
        $lastID=1
    }
    $logObj=@{"callID"=$lastID;"ClientTime"="";"Url"=$rUri;"Json"=$params;"APIKey"=$global:apiKeyObj.Values;"Result"=""}
    if(-not ($preview)){
        try {
            $api_request_resp=Invoke-RestMethod -Uri $rUri -Body $params -ContentType 'application/json' -Method Post -Headers $global:apiKeyObj -UseDefaultCredentials
            $api_request_resp # Output the output objects
            $logObj.Result=$api_request_resp
        } catch {
            if($_.Exception -match "Unauthorized"){
                # If api call fails due to Unauthorized (apikey expired/bad auth)
                $params=$params | ConvertFrom-Json # Turn back into object, fixes double json on first call
                $apiReSplat=@{"params"=$params;"r"=$r;"log"=$log}
                $authReSplat=@{"Credential"=$Credential}
                auth @authReSplat
                api_request @apiReSplat
            } elseif($_.Exception -match "Method not allowed") {
                # If the api call fails due to bad Method

                $webReq=Invoke-WebRequest -Uri $rUri -ContentType 'application/json' -Method Get -Headers $global:apiKeyObj -UseDefaultCredentials
                $webReq.Content
                $logObj.Result=$webReq.Content
            } elseif($_.Exception -match "404") {
                if($params){
                    $params=$params | ConvertFrom-Json
                    if($params -match "GUID"){
                        $DN=.\vedapi.ps1 -r config/guidtodn -params ObjectGUID -values $params.GUID
                        $DN.ObjectDN
                        $rUri=$rUri+"/"+$($params -replace "@{(.*)=","" -replace "(}{2})","}")
                    } else {
                        $rUri=$rUr+"/?"+$($params -replace "@{","" -replace "(}{2})","}")
                    } 
                    $webReq=Invoke-WebRequest -Uri $rUri -ContentType 'application/json' -Method Get -Headers $global:apiKeyObj -UseDefaultCredentials
                    if($webReq -ne $null){
                        foreach($WR in $webReq.Content){
                            if($WR -ne "[]"){
                                $WR
                                $rUri=$rUri+"/"+$($WR -replace ":","/" -replace "(`"|\[|\])","") 
                                $NE=Invoke-WebRequest -Uri $rUri -ContentType 'application/json' -Method Get -Headers $global:apiKeyObj -UseDefaultCredentials
                                $NE.content
                            }
                        }
                    } else {
                        $webReq.Content
                    }
                    $logObj.Result=$webReq.Content
                } else {
                    $webReq=Invoke-WebRequest -Uri $rUri -ContentType 'application/json' -Method Get -Headers $global:apiKeyObj -UseDefaultCredentials
                    $webReq.Content
                    $logObj.Result=$webReq.Content
                }
            } else {
                # Print Exception informaiton
                $logObj.Result=$_.Exception
                $_.Exception
            }
        }
        if($log){
            # Log file Param set
            if($log -notmatch "(VedApiLog)$"){
                # If the extension is not given, add it
                $log=$log+".VedApilog"
            }
            # Save the logs in compressed json format
            $logObj.ClientTime=$(Get-Date -Format MM/dd/yyyy` hh:mm:ss` tt)
            $logObj | ConvertTo-Json -Compress| Out-File -FilePath $log -Append
        }
    } else {
        # Preview set, list call, params in Json, and the APIKey
        $rUri
        $params | ConvertFrom-Json | ConvertTo-Json
        $global:apiKeyObj.values
    }
}
function build_rest(){
    param(
        [object]$params, # If provided, format is @{"Param Name"="Value"}, Takes variable
        [object]$values,
        [string]$OutFile # Saves in .json format to specified file
    )
    function make_json(){
        # If no values provided, prompt for parameter values
        param(
            [object]$params
        )
        $paramObj=@{}
        foreach($i in $params){
            if($paramObj.keys -notcontains $i){
                   $paramObj += @{$i=$(read-host $i)} # Use read-host to get params
            }
        }
        # Return object
        if($OutFile){
            if($OutFile -notmatch "json"){
                $OutFile=$OutFile+".json"
            }
            $paramObj | ConvertTo-Json | Out-File $OutFile -Append
        } else {
            $paramObj
        }
    }
    if(-not($values)){
        $params=@{"params"=$params}
        make_json @params
    } else {
        # Pair given parameters and values, if they are equal
        if($values.Count -eq $params.Count){
            $paramObj=@{}
            for($i=0;$i -lt $params.Count;$i++){
                if($paramObj.keys -notcontains $i){
                    $paramObj += @{$params[$i]=$values[$i]}
                }
            }
            if($OutFile){
                if($OutFile -notmatch "(json)$"){
                    $OutFile=$OutFile+".json"
                }
                $paramObj | ConvertTo-Json | Out-File -FilePath $OutFile -Append
            } else {
                $paramObj
            }
            
        } else {
            # Number of Parameters does not match
            Write-Host "Missing or additional Value provided"
        }
    } 
}
if($ShowKey){
    auth
    $global:apiKeyObj
} else {
    if($params -or $values){
        # If run from the script level
        if($global:apiKeyObj.count -eq 0){
            # Get APIKey if none
            $buildRestSplat=@{"params"=$params;"values"=$values}
            $params_Json=build_rest @buildRestSplat
            $apiSplat=@{"params"=$params_Json;"r"=$r;"log"=$log}
            $authReSplat=@{"Credential"=$Credential}
            auth @authReSplat
            api_request @apiSplat
        } else {
            # If we have APIkey just run request
            $buildRestSplat=@{"params"=$params;"values"=$values}
            $params_Json=build_rest @buildRestSplat
            $apiSplat=@{"params"=$params_Json;"r"=$r;"log"=$log}
            api_request @apiSplat
        }

    } elseif($params -eq $null -and $values -eq $null -and $r){
        $apiSplat=@{"r"=$r;
            "log"=$log
            "params"=@{}}
        api_request @apiSplat
    }
}