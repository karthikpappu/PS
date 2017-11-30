$OutJob=$env:USERPROFILE+"\AutomationJob.txt"
function GUIautomation(){
    [CmdLetBinding()]
    param(
        [string]$URL="https://192.168.132.151/aperture",
        [switch]$Record,
        [switch]$Append,
        [string]$OutJob=$env:USERPROFILE+"\AutomationJob.txt",
        [string[]]$InJob
    )
    Add-Type -MemberDefinition @'
    [DllImport("User32")]
    public static extern short GetAsyncKeyState(int vKey);
'@ -Name NativeInterop -Namespace KbdUtil
    add-type -AssemblyName microsoft.VisualBasic
    add-type -AssemblyName System.Windows.Forms
    function getUrl(){
        if(!$Global:ie){
            try {
                $global:ie=new-object -com internetexplorer.application;
                $global:ie.Visible=$true
                $global:ie.navigate($URL)
            } catch {
                Write-Host "Unable to start IE, Try again in a few seconds"
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
        while($Global:ie.busy -or $Global:ie.ReadyState -ne 4){ sleep 1}
        sleep -Milliseconds 250
    }
    function ElemBusy($ES){
        # Check if element is ready for action
        if($ES.Count -gt 1){
            foreach($E in $ES){
                if($E.ReadyState -ne $Null){
                    write-verbose $E.Readystate 
                    while($E.Readystate -ne "complete"){sleep 1}
                }
            }
        } else {
            if($ES.ReadyState -ne $Null){
                Write-Verbose $ES.ReadyState
                while($ES.ReadyState -ne "complete"){sleep 1}
            }
        }
        sleep -Milliseconds 250
    }
    function getelem($JobSteps){
        busyWait
        if($JobSteps.id -ne $null){
            $ES=$Global:ie.Document.getElementById($JobSteps.id)
        } elseif($JobSteps.name -ne $null) {
            $ES=$Global:ie.Document.getElementsByName($JobSteps.Name)
        } elseif($JobSteps.href -ne $null) {
            $ES=$Global:ie.Document.getElementsByTagName('a') | `
                Where-Object {$_.outerhtml -match $JobSteps.outerhtml}
        } elseif($JobSteps.outerhtml -ne $null){
            $HT=$JobSteps.outerhtml -split "<|\s"
            $ES=$Global:ie.Document.getElementsByTagName($HT[1]) | Where-Object {$_.outerhtml -match $JobSteps.outerhtml `
                -or $_.innertext -match $JobSteps.innertext}
        } else {
            Write-Host "Not Found"
        }
        ElemBusy $ES
        return $ES
    }
    function performAction($JobSteps){
        if($JobSteps.Action -eq "Click"){
            $BT=getelem $JobSteps
            if($BT -ne $Null){
                busyWait
                $BT.click()
                busyWait
            }
        } else {
            $NA=getelem $JobSteps
            if($JobSteps.value -ne $null -and $NA -ne $null -and $JobSteps.outerhtml -notmatch "combobox"){
                foreach($N in $NA){
                    $N.click()
                    while($N.value -ne $JobSteps.value){$N.value=$JobSteps.value}
                    busyWait
                }
            } else {
                busywait
                $CB=getelem $JobSteps
                $CB.click()
                #$CB.FireEvent("onmousedown")
                #$CB.FireEvent("onkeypress")
                busywait

            }
        }
    }
    function findObj($JobSteps){
        if($JobSteps.href -ne $null -or $JobSteps.outerhtml -match "Button" -and $JobSteps.outerhtml -notmatch "combobox"){
            $AC="Click"
        } elseif (($JobSteps.id -ne $null) -or ($JobSteps.name -ne $null) -and ($JobSteps.value -ne $Null -or $JobSteps.outerhtml -match "combobox")){
            $AC="AddValue"
        } else {
            $AC="Click"
        }
        Write-Verbose "$AC $JobSteps"
        $objA = New-Object System.Object
        $objA | Add-Member Action $AC
        $JobSteps+=$objA
        performAction $JobSteps
    }
    function injob(){
        param(
            [string]$InJob
        )
        $JobSteps=Get-Content -Encoding String $InJob -Delimiter "`r`n" | ConvertFrom-Json
        $JS=($JobSteps | %{if($_ -ne $null){$_ | Get-Member -MemberType NoteProperty}}).Name | sort {[int]$_}
        foreach($J in $JS){
            Write-Verbose "$J $($JobSteps.$J)"
            findObj $JobSteps.$J
        }
    }
    $Global:Actions=@{}
    function current(){
        $CE=$Global:ie.Document.activeElement
        if($CE.outerhtml -notmatch "body|wrapper"){
            if($CE.outerhtml -match "iframe"){
                $IDOC=@()
                do {
                    $IDOC+=$CE.outerhtml
                    $CE=$CE.contentDocument.activeelement
                } until ($CE.outerhtml -notmatch "iframe")
                # "COM objects cant +=... PSH"
                $CE.onmsgesturetap=$IDOC
                if($CE.outerhtml -notmatch "body|wrapper"){
                    return $CE
                }
            } elseif($CE.outerhtml -match "role.*combobox"){
                $CE.onmsgesturetap=(($CE.attributes | Where-Object {$_.name -match "aria-active"}) -split "-")[-1][-1]
                return $CE
            } else {
                return $CE
            }
        }
    }
    if($Record){
        $ActionCounter=0
        $Enter=0x0D
        $Tab=0x09
        $LBTN=0x01
        if($Append){
            $AJOBS=Get-Content -Encoding String $OutJob -Delimiter "`r`n" | ConvertFrom-Json
            [int]$AS=($AJOBS | %{if($_ -ne $null){$_ | Get-Member -MemberType NoteProperty}}).Name | sort {[int]$_} | Select -Last 1
            if($AS -ne $null){
                $ActionCounter=$AS+1
                injob -InJob $OutJob
                Write-Verbose "Recording"
            } else {
                Write-Error "Couldn't get last action number"
            }
        }
        while($Global:ie.visible){
            $NC=current
            sleep -Milliseconds 1
            $NC=Select-Object -InputObject $NC -Property id,name,value,href,outerhtml,innertext,onmsgesturetap,class
            $LAC=$ActionCounter-1
            $CLV=Select-Object -InputObject $Global:Actions.$LAC -Property * -ExcludeProperty value
            $CAV=Select-Object -InputObject $Global:Actions.$ActionCounter -Property * -ExcludeProperty value
            $CNV=Select-Object -InputObject $NC -Property * -ExcludeProperty value
            if($NC -ne $Null){
                if($ActionCounter -eq 0){
                    $Global:Actions.$ActionCounter=$NC
                    $ActionCounter++
                }
                if($CNV -notmatch $CAV){
                    $ActionCounter++
                }
                $Global:Actions.$ActionCounter=$NC
                Write-Verbose "$ActionCounter $($NC)"
            }

        }
        if((Test-Path $OutJob) -and !$Append){
            "" > $OutJob
        }
        foreach($GA in $Global:Actions.Keys){ 
            @{"$GA"=$Global:Actions.$GA} | ConvertTo-Json -Depth 3 -Compress | Out-File $OutJob -Append
        }
    } else {
        if(Test-Path $InJob){
            injob $InJob
        } else {
            Write-Error "Could not find  $InJob"
        }
    }
}