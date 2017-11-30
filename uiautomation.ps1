function GUIautomation(){
    [CmdLetBinding()]
    param(
        [ValidateSet("Policy","Discovery","Credentials","Encryption","Identity",
            "Logging","Platforms","Reports","Roots","Workflow")]
        [string]$Tree="Policy",
        [string]$Search,
        [string]$Values,
        [System.Management.Automation.CredentialAttribute()]
        $Credential=$credi,
        [string]$URL="https://192.168.132.151/vedadmin/default.aspx",
        [string[]]$FieldId,
        [string[]]$FieldVal,
        [switch]$Record
    )
    Add-Type -MemberDefinition @'
    [DllImport("User32")]
    public static extern short GetAsyncKeyState(int vKey);
'@ -Name NativeInterop -Namespace KbdUtil
    add-type -AssemblyName microsoft.VisualBasic
    add-type -AssemblyName System.Windows.Forms
    $TreeList=@("Credentials","Discovery","Encryption","Identity","Logging","Platforms","Policy","Reports"
            "Roots","Workflow")
    function getUrl(){
        if(!$Global:ie){
            try {
                $global:ie=new-object -com internetexplorer.application;
                $global:ie.Visible=$true
                $global:ie.navigate($URL)
            } catch {
                Write-Host "Browser unable to start, wait a few seconds and try again."
            }
        } else {
            try {
                $Global:ie.Quit()
            } catch {
                
            }
            $Global:ie=$null
            getUrl
        }
    }
    getUrl # Initiate the browser
    function busyWait(){
        # Check broswer busy status
        do {
            if($ie.Busy -eq $true){
                Write-Verbose "Browser Busy"
            }
        } until ($ie.Busy -eq $false)
        return $false
    }
    function getDoc(){
        # Get the new Document if busy wait done
        do {
            if($ie.ReadyState -eq 4){
                $Doc=$ie.Document
            }
        } until ((($ie.ReadyState -eq 4) -or ($ie.ReadyState -match "complete")) -and $(busyWait) -eq $false)
        $global:Doc=$Doc
        return $true
    }
    function generalReseval(){
        $Res=getDoc
        if($Res){
            $ObjEval=@{"Title"=$global:Doc.title;"id"="";"Type"="";"value"="";"href"="";"Tree"=""}
            $ObjEval.id=$global:Doc | select id
            $FieldRes=$global:Doc.all | Where-Object {$_.type -match "text|hidden|password|$Null|button"} | select type,value,href,id
            $ObjEval.type=$FieldRes.type
            $ObjEval.id=$FieldRes.id
            $ObjEval.value=$FieldRes.value
            $ObjEval.href=$FieldRes.href
            $ObjEval.Tree=($global:Doc.all | Where-Object {$_.id -match "ctl00_bodySection_treeList"}).selectedIndex
            return $ObjEval
        }
    }
    function treeSel(){
        $TDL=$Global:Doc.getElementById("ctl00_bodySection_treeList")
        ($TDL | where-object {$_.index -eq $TreeList.IndexOf($Tree)}).selected=$True
        $TDL.fireevent("Onchange")
    }
    function inputHandle(){
        $Fields=generalReseval
        $Fields | Where-Object {($_.ID -match "$FieldId")} 
        # Input/passwords
        # Links/buttons
        # Drop Down Options
    }
    function performAction(){
        $pageAtt=generalReseval
        if($pageAtt.Title -match "Certificate Error: Navigation Blocked"){
            # Get past certificate error
            $Global:Doc.getElementById("overridelink").click()
            performAction
        } elseif($pageAtt.id -contains "usernameTextbox" -or $pageAtt.id -contains "passwordTextbox"){
            $pass=$credential.password 
            $pr=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
            $Global:Doc.getElementById("username").value=$Credential.username
            $Global:Doc.getElementById("password").value=$pr
            $Global:Doc.getElementById("loginButton2").click()
            performAction
        } elseif($pageAtt.Tree -ne $TreeList.indexof($Tree)){
            treeSel
            performAction
        } else {
            inputHandle
        }
    }
    $Global:Actions=@{}
    function current(){
        return $Global:ie.Document.activeElement
    }
    if($Record){
        $ActionCounter=0
        while($Global:ie.visible){
            $C=current
            $NC=$C | select id,name,value,href,innerhtml,outerhtml
            $Enter=0x0D
            $Tab=0x09
            if(([KbdUtil.NativeInterop]::GetAsyncKeyState($Enter) -band 0x8000) -eq 32768 `
                -or ([KbdUtil.NativeInterop]::GetAsyncKeyState($Tab) -band 0x8000) -eq 32768 `
                -or ([System.Windows.Forms.Control]::MouseButtons) -ne "None"){
                $ActionCounter++
            }
            $UID=$ActionCounter
            if(($NC.id -or $NC.name -or $NC.href) -eq !$null){
                Write-Verbose "$UID $NC"
                $Global:Actions.$UID=$NC
            }
        }
        $Global:Actions
    } else {
        performAction # Run once to get past Cert error or login
    }
    
}
function buildabear(){
        function Policy(){
            # Create Policy folder
            # Create Device
            # Create Application(s)
            # Create Workflow
            # Create CA template(s)
        }
        function Logging(){

        }
        function Identity(){

        }
        function Platforms(){

        }
        function Reports(){

        }
        function Roots(){

        }
        function Encryption(){

        }
        function Discovery(){

        }
}
