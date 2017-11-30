[CmdLetBinding()]
param(
    [string[]]$IPS, # Path to CSV || Comma Separated array of IPs || single port
    [string[]]$PORT, # Path to CSV || Coma Separated array of Ports || single IP
    [string]$JobFile="$ENV:USERPROFILE\DiscoveryPartionJob.txt", # Path to output file
    [string]$StartHour=1, # Integer for start hour, AM assumed if nothing is specified (example input: 1AM)
    [string]$EndHour=8 # Interger for End hour, PM assumed if nothing is specified (example input: 8PM)

)
if($StartHour -notmatch "M"){
    $StartHour=$StartHour+"AM"
}
if($EndHour -notmatch "M"){
    $EndHour=$EndHour+"PM"
}
$ScheduleTime=New-TimeSpan $StartHour $EndHour
if(Test-Path $IPS){
    $IPS=Get-Content -Encoding String $IPS
} else {
    $IPS=$IPS -split ","
}
if(Test-Path $PORT){
    $PORT=Get-Content -Encoding String $PORT 
} else {
    $PORT=$PORT -split ","
}
$BSIPs=@($IPS -replace "-.*","" | Sort-Object {"{0:d3}.{1:d3}.{2:d3}" -f @([int[]]$_.split('.'))} -Unique )
 # Baseline IP's will replace domains below, Ports as well
$CMDTime=Measure-Command {.\PortScan.ps1 -PortRange $PORT -IP $BSIPs -Protocol Tls }
$Count=0
$Jobs=@{}
$LastReq=0
function ExpandRange(){
    [CmdLetBinding()]
    param(
        [string[]]$IPR,
        [string[]]$Ports
    )
    function TotalPorts($Ports){
        $TP=@()
        foreach($P in ($Ports -split ",")){
            if($P -match "-"){
                $PI=$P -split "-"
                ($PI[0]..$PI[1]) | %{$TP+=$_}
            } else {
                $TP+=$P
            }
        }
        ($TP | Sort-Object -Unique).Count
    }
    $TotalPort=TotalPorts($Ports)
    foreach($I in $IPR){
        if($I -match "-"){
            $R=$I -split "-"
            $RE=((($R[0] -split "\.")[-1]..($R[1] -split "\.")[-1]).count)
            $TE=((($R[0] -split "\.")[-1]..($R[1] -split "\.")[-1]).Count * $TotalPort)
            Write-Verbose "IP Requests $RE x $TotalPort Ports"
            Write-Verbose "Total Requests $TE"
        } else {
            $TE=($I).Count * $TotalPort
        }
    }
    return $TE
}

$Requests=ExpandRange -IPR $IPS -Ports $PORT # Total number of requests

$TBlock=$ScheduleTime.TotalMilliseconds / $CMDTime.TotalMilliseconds # Number of requests per block

$NumberOfJobs=$Requests / $TBlock # Number of Jobs

$RPJ=$Requests / $NumberOfJobs # Number of Requests per job

$NewJob=@{"Number of Requests"=$Requests;
    "Number of Jobs"=$NumberOfJobs;
    "Number of Requests per Job"=$RPJ;}
$NewJob.'Number of Requests per Job'
foreach($e in $IPS){
    $e=$e.trim()
    $ReqCount=ExpandRange -IPR $e -Ports $PORT -Verbose
    $Tracker=($NewJob.'Number of Requests per Job' - $LastReq)
    if($Tracker -le 0){
        $Count++
        $Tracker=0
    }
    $Count
    $Jobs."$Count"+=@(@{"Range"=$e;"Ports"=$PORT})
    $LastReq=$ReqCount
}
function buildJobs(){
    if(Test-Path $JobFile){
        "" > $JobFile
    }
    foreach($J in $Jobs.Keys){
        $IPT=$Jobs.$J.Range
        $PRT=$Jobs.$J.Ports | select -First 1
        "Job Number $J" | Out-File -FilePath $JobFile -Append
        foreach($q in $IPT){
            $q+":"+$PRT | Out-File -FilePath $JobFile -Append
        }
    }
}
buildJobs

$NewJob