. .\vedapi.ps1
function ApplicationCreate(){
    param(
        [switch]$Preview,
    )
    $AppClass = 'CAPI'
    $DeviceList=.\vedapi.ps1 -r config/findobjectsofclass -params Class -values Device
    # Modify the attributes here
    $NAL = $(@{"Name"="Credential";"Value"="\VED\Policy\Credentials\MSCA1"},
        @{"Name"="Disabled";"Value"="0"},
        @{"Name"="Driver Name";"Value"="appcapi"},
        @{"Name"="Friendly Name";"Value"="Test"},
        @{"Name"="Non-Exportable";"Value"="0"},
        @{"Name"="Use Specified Host";"Value"="1"})
    foreach($D in $DeviceList.objects){ 
        $ADN=$D.DN+'\test-App'
        if($Preview){
            .\vedapi.ps1 -r config/create -params Class,ObjectDN,NameAttributeList -values $AppClass,$ADN,$NAL -preview
        } else{
            .\vedapi.ps1 -r config/create -params Class,ObjectDN,NameAttributeList -values $AppClass,$ADN,$NAL
            
        }
    }
}
ApplicationCreate