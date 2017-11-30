function showBugs(){
    $JURL='https://jira.eng.venafi.com:8443/browse/VEN-'
    $ZURL='https://venafi.zendesk.com/agent/tickets/'
    $Tickets=.\ZedApi.ps1 -ApiCall '/users/{~usr~}/tickets/assigned.json' -Param status -Value hold
    $Bugs=($Tickets.tickets.custom_fields | Where-Object {$_ -match "20464928" -and $_.value -ne $null}).value  
    foreach($B in $Bugs){
        sleep -Milliseconds 750
        "$JURL+$B"
        start $JURL+$B 
    }
    
}
function UsersArticles(){
    $URep=@()
    $Users=((.\ZedApi.ps1 -ApiCall /users.json -Param role -Value admin).users)
    foreach($u in $Users){
        $UAD=(.\ZedApi.ps1 -ApiCall '/help_center/users/{~usr~}/articles.json' -Nuser $_.id)
        $NUO=@{$u.id=@()}
        foreach($ID in $UAD.articles){
            $NUO.$($u.id)+=@{"Article_Name"=$ID.title;"CreatedAt"=$id.created_at;}
            $ID.url
        }
        $URep+=$NUO
    }
    $URep[0].88715797
    
}
function ZDar(){
    param(
        [object]$LinkBuilder
    )
    $Alist=.\ZedApi.ps1 -ApiCall /help_center/articles.json

    $Alist[1]
}


function runRemote(){
    param(
        [object]$LinkBuilder=$LinkBuilder
    )
    $zCredi1=$Global:zcredi
    Invoke-Command -Session $Linkbuilder.Session -ScriptBlock {
            param($zCredi1)
            if(!(test-path "z:\")){
                net use Z: "\\vmware-host\Shared Folders" | out-null
            }
            cd z:\kb\api\vedapi\;

            $EndRes=@()
            $Articles=Z:\kb\api\vedapi\ZedApi.ps1 -ApiCall '/help_center/articles.json'
            foreach($A in $Artic){
                foreach($AB in $A){
                    $AB.articles | %{$EndRes+=Z:\kb\api\vedapi\ZedApi.ps1 -apicall "/help_center/en-us/articles/{~ARjson~}/comments.json" -ARID "$($_.id)" }
                }
            }
            $EndRes=$EndRes | Where-Object {$_.comments}
    } -ArgumentList $zCredi1
}
