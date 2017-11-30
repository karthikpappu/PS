[cmdletbinding()]
param(
    [switch]$GetIdentity,
    [ValidateSet('/users/{~usr~}/tickets/assigned.json','/tickets.json','/users.json','/api/v2/tickets/{~tid~}.json','/api/v2/tickets/show_many.json?ids={ids}',
        "/help_center/articles.json","/help_center/{locale}/categories/{id}/articles.json","/help_center/en-US/sections/{id}/articles.json",
        "/help_center/users/{~usr~}/articles.json","/help_center/incremental/articles.json?start_time={start_time}","/help_center/{~locale~}/sections/{id}/articles.json",
        "/locales.json",'/help_center/incremental/articles.json?start_time={~start_time~}','/organizations.json','/community/posts/{~id~}.json',
        '/organizations/{~organization_id~}/tickets.json','/organizations/{~organization_id~}/organization_memberships.json',
        '/users/{~user_id~}/identities.json','/help_center/en-us/articles/{~ARjson~}.json','/community/posts.json','/community/topics/{~id~}.json',
        '/help_center/en-us/articles/{~ARjson~}/comments.json','/help_center/en-us/sections.json','/community/topics.json','/community/topics/{~id~}/posts.json')]
    [string[]]$ApiCall,
    [System.Management.Automation.CredentialAttribute()]
    $Credential=$Zcredi,
    [array[]]$Param, # Respective Param, value
    [array[]]$Value,
    [switch]$Preview,
    [ValidateSet('GET','POST','PUT')]
    [string]$Method,
    [string]$Nuser,
    [datetime]$StartDate,
    [string]$Org,
    [switch]$ResetPW,
    [string]$ARID
)
$Zcredi=$Credential
$global:epoch=Get-Date -Date "01/01/1970" # Epoch date
$Global:ZDURL="https://venafi.zendesk.com/api/v2"
if($StartDate){
    $ESD=(New-TimeSpan -Start $global:epoch -End $StartDate).TotalSeconds
}
$CFields=@{"BugField"="20464928";"Category"="20409552"}
function zauth(){
    $Global:zIdentity=(.\ZedApi.ps1 -ApiCall /users.json -Param role -Value admin -GetIdentity).users  | Where-Object {$_.email -match "$($Zcredi.UserName)"}
    $ret="Logged in as "+$Global:zIdentity.email
    return $ret
}
function api_callZ(){
    param(
        [Object]$CallData
    )
    if(!$Method){
        $Method="GET"
    }
    if(!$Global:AuthObj){
        $PW=[Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CallData.credential.password))
        $Global:AuthObj=@{Authorization='Basic '+[Convert]::ToBase64String(
            [Text.Encoding]::ASCII.GetBytes("$($CallData.Credential.Username):$($PW)"))}
    }
    $ApiObj=@{"Headers"=$Global:AuthObj;
        "Uri"=$CallData.CallID;
        "Method"="$Method";
        "UserAgent"="application/json"}
    if(($CallData.rest) -and ($Method -match "Get")){
        foreach($A in $($CallData.Rest)){
            $A=$A | ConvertFrom-Json
            $AttName=$($A | gm -MemberType NoteProperty).Name
            $AttVal=$A."$($($A | gm -MemberType NoteProperty).Name)"
            if($ApiObj.Uri -notmatch "\/\?"){
                $ApiObj.Uri=$ApiObj.Uri+"/?"+$AttName+"="+$AttVal
            } else {
                $ApiObj.Uri=$ApiObj.Uri+"/"+$AttName+"="+$AttVal
            }
        }
    } elseif($CallData.rest) {
        $ApiObj.body="$($CallData.Rest)"
    }
    switch -wildcard ($ApiObj.Uri) {
        "*{~usr~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~usr~}","$($Global:zIdentity.id)"}
        "*{~user_id~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~user_id~}","$Nuser"}
        "*{~start_time~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~start_time~}","$ESD"}
        "*{~organization_id~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~organization_id~}","$Org"}
        "*{~ARjson~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~ARjson~}","$ARID"}
        "*{~id~}*" {if($ApiObj.uri -match "community"){$ApiObj.uri=$ApiObj.uri -replace "{~id~}","$ARID"}}
        "*{~id~}*" {$ApiObj.uri=$ApiObj.uri -replace "{~id~}","$ARID"}
        "*{~locale~}*" {{$ApiObj.uri=$ApiObj.uri -replace "{~locale~}","en-us"}}

    }
    if($Preview){
        $ApiObj | ConvertTo-Json -Depth 3
    } else {
        $FRES=Invoke-RestMethod @ApiObj
        $FRES
        if($FRES.next_page -ne $CallData.callid -and $FRES.next_page -ne $null){
            $CallData.callid=$FRES.next_page
            api_callz $CallData
        }
    }
}
function BuildzRest(){
    param(
        [string[]]$Attributes,
        [string[]]$Values
    )
    $ZDCall=@{"CallID"="$($Global:ZDURL+$ApiCall)";"Credential"=$Zcredi}
    if($Param -and $Values){
        $RestData=@()
        if($Attributes.Count -ge 1){
            for($i=0;$i -lt $Attributes.Count;$i++){
                $RestData+=@{$Attributes[$i]=$Values[$i]}
            }
        }
        $RestData=$RestData | ConvertTo-Json -Depth 3 -Compress
        $ZDCall.add("Rest",$RestData)
    }
    api_callZ $ZDCall
}
if((Test-Path .\ZedApi.ps1) -or $Host.Name -match "ServerRemoteHost"){
    if($ResetPW){
        zauth
    } else {
        if($global:zidentity -ne $null -or $GetIdentity){
            BuildzRest -Attributes $Param -Values $Value
        } else {
            zauth
        }
    }
} else {
    Write-Host ".\ZedApi.ps1 not found"
}
