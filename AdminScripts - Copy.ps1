function initRemSession(){
    [cmdletbinding()]
    param(
        [string[]]$ComputerName="PRIMARY",
        [int]$Port=5985,
        [System.Management.Automation.CredentialAttribute()]
        $VSVRCredi=$RCredi
    )
    if(-not($SessionName)){
        if(-not($VSVRCredi)){
            $RCredi=$VSVRCredi
        }
        $psSplat=@{"ComputerName"=$ComputerName;
            "Port"=$Port;
            "Credential"=$VSVRCredi}
        $SessionName=New-PSSession @psSplat
        try {
            Enter-PSSession $SessionName
        } catch {
            Write-Host "Could not Connect:"
        }
    }
}
function ServicesF(){
    param(
        [string]$Service="venafi|world wide",
        [ValidateSet("Start","Stop","Show","Restart")]
        [string]$Status
    )
    $Services=service | Where-Object {$_.DisplayName -match "$Service"}
    switch($Status){
        "Start" { Start-Service $Services }
        "Stop"  { Stop-Service $Services }
        "Show"  { $Services }
        "Restart" { Stop-Service $Services;Start-Service $Services}
    }
}
function certTil(){
    [array]$CMDS=("
      -dump             
      -isvalid          
      -getconfig        
      -ping             
      -pingadmin        
      -CAInfo           
      -ca.cert          
      -ca.chain        
      -GetCRL        
      -CRL             
      -shutdown        
      -schema           
      -view             
      -db               
      -dynamicfilelist 
      -databaselocations 
      -verifystore      
      -UI               
      -attest           
      -dsPublish        
      -ADTemplate    
      -Template         
      -TemplateCAs      
      -CATemplates     
      -enrollmentServerURL 
      -ADCA             
      -CA               
      -Policy           
      -PolicyCache      
      -CredStore        
      -URLCache         
      -MachineInfo      
      -DCInfo           
      -EntInfo       
      -TCAInfo        
      -SCInfo          
      -oid              
      -error           
      -getreg           
    " -split "\r\n")
    foreach($i in $CMDS){
        $i=$i.trim()
        certutil.exe $i
    }
}
function ShowVedEvents(){
    param(
        [string]$Search="venafi*",
        [string]$Num=100
    )
    Get-EventLog -Newest $Num -LogName Application | Where-Object {$_.Source -match "$Search"}
}
function fusionLogs(){
    param(
        [ValidateSet("on","off","show")]
        [string]$Status="show",
        [string[]]$Name=@('ForceLog','LogFailures','LogResourceBinds','LogPath'),
        [string]$Path="HKLM:\Software\Microsoft\Fusion",
        [string]$Directory="C:\FusionLogs"
    )
    $OldPath=pwd
    if($Status -match "on"){
        $nVal=1
    } elseif($Status -match "off") {
        $nVal=0
    } else {
        $nVal="Show"
    }
    $RegPath="HKLM:\Software\Microsoft\Fusion"
    $Keys=@(
        @{"Name"="ForceLog";"Value"=$nVal;"Type"="DWord"},
        @{"Name"="LogFailures";"Value"=$nVal;"Type"="DWord"},
        @{"Name"="LogResourceBinds";"Value"=$nVal;"Type"="DWord"},
        @{"Name"="LogPath";"Value"="$Directory";"Type"="String"})
    cd HKLM:\
    $ShowObj=@()
    foreach($H in $Keys){
        $H.add("Path",$RegPath)
        if($nVal -match "Show"){
            $H.Remove("Value")
            $H.Remove("Type")
            Get-ItemProperty @H
        } else {
            Set-ItemProperty @H
        }
    }
    if($Status -match "on|off"){
        fusionLogs -Status show
    }
    cd $OldPath
}
function RegistryScript(){
    [Cmdletbinding()]
    param(
        [string]$Name,
        [string]$Value,
        [string]$Type,
        [string]$Search,
        [string]$RegPath="HKLM:\software\venafi"
    )
    $OldPath=pwd
    $RP=$RegPath -split "\\"
    $Rpath=$RP[0]+"\"
    cd $Rpath
    try {
        if(!($Search) -and $Value -or $Type -and $Name){
            $RegObj=@{"Name"=$Name;"Value"=$Value;"Type"=$Type;"Path"=$RegPath}
            $ShowRec=@{"Search"=$Name;"RegPath"=$($RegPath -replace "(\\[a-z0-9])","")}
            $RegPath -replace "(\\(.*)[a-z0-9])$",""
            Write-Verbose "$Name $Value $Type"
            try {
                Set-ItemProperty @RegObj
            } catch {
                $_
            }
            RegistryScript @ShowRec
        } else {
            Write-Verbose "$Search $RegPath"
            $RegInfo=Get-ChildItem -Recurse $RegPath
            if($Search){
                $RegSearch=$Reginfo | Where-Object {$_.Name -match $Search -or $_.Property -match $Search}
                $RegSearch
            } else {
                $RegSearch
            }   
        }
    } catch {
        cd $OldPath
    }
    cd $OldPath
}
function RequestID(){
    param(
        [int]$RequestID
    )
    certutil -view -out "Request ID" | select -Last 10 | select -First 1
    
}
function hashFiles(){
    param(
        [string[]]$Directory="C:\Program Files\Venafi",
        [string]$String,
        [string[]]$OutFile="C:\VenHashScan.txt",
        [switch]$Compare,
        [switch]$Report
    )
    if(!$Compare){
    $FileList=Get-ChildItem -Recurse -Path $Directory -File
    $Sha=[Security.Cryptography.HashAlgorithm]::Create("SHA256")
    $NewFileList=@()
    foreach($F in $FileList.FullName){
        $Read=[System.IO.File]::ReadAllBytes($F)
        $Fb64=[System.Convert]::ToBase64String($sha.ComputeHash($Read))
        $OutF=@{"FileName"=$F;
            "Hash"=$Fb64}
        $NewFileList+=$OutF
    }
    }
    if($Compare -or $OutFile.Count -ge 2){
        $File1=[System.IO.File]::ReadAllLines($OutFile[0])
        $File2=[System.IO.File]::ReadAllLines($OutFile[1])
        $CompareContent=Compare-Object $File1 $File2
        if($Report){
            $CompareReport=$OutFile[0]+"-"+$OutFile[1]+"-Report"
            [System.IO.File]::WriteAllLines($CompareReport,$CompareContent)
        } else {
            $CompareContent
        }
    } elseif(!($Compare)){
        [System.IO.File]::WriteAllLines($OutFile[0],(ConvertTo-Json -Depth 3 $NewFileList))
    }

}
function exeConfigLogs(){
    param(
        [string[]]$Strings=$("error","exception","unexpected","TimedOut"),
        [string]$Path='.\log.log',
        [string]$OutFile
    )
    if($OutFile -notmatch "(.*\.txt)$"){ $OutFile=$OutFile+".txt"}
    $Lines=Get-Content $Path | sls $Strings | select LineNumber,Line
    foreach($i in $Lines){
        $Out=[string]$i.LineNumber+" "+$i.Line
        if($OutFile){
            $Out >> $OutFile
        } else {
            $Out
        }
    }
}
function SearchFile(){
    param(
        [string]$Search="Authentication",
        [string]$Directory=$PWD
    )
    $CNFFiles=Get-ChildItem -Recurse -Path $Directory -File
    if($Search -ne "*"){
        foreach($C in $CNFFiles){
            
            $Content=Get-Content $C.FullName
            if($Content -match $Search){
                $C.FullName
                $Content | Select-String "$Search"
            }
        }
    } else {
        foreach($C in $CNFFiles){
            $Content=Get-Content $C.FullName
            if($Content -match $Search){
                $C.FullName
                $Content 
            }
        }
    }
}
function PortScan(){
    [cmdletbinding()]
    param(
        [int[]]$PortRange=443,
        [string[]]$IP="www.venafi.com",
        [switch]$ShowAll,
        [ValidateSet('Tls11','Tls12','Tls','Ssl2','Ssl3','All')]
        [string[]]$Protocol='Tls', # Scans all protocols
        [ValidateSet('Json','Object')]
        [string]$ResultView='Object'
    )
    foreach($o in $IP){
        $OutObj=@()
        foreach($i in $PortRange){
            if($Protocol -match "All"){
                $Protocol=@('Tls11','Tls12','Tls','Ssl2','Ssl3')
            }
            $sslData=@()
            $TempObj=@{"Port"="$i";"Result"="";"sslData"=@()}
            foreach($P in $Protocol){
                $Sock = New-Object System.Net.Sockets.TcpClient
                try {
                    $Res=$Sock.ConnectAsync($o,$i).Wait(10)
                    $TempObj.Result="$Res"
                    $Stream=$Sock.GetStream()
                    $sslStream = New-Object System.Net.Security.SslStream($Stream,$false)
                    try{
                        $sslStream.AuthenticateAsClient($o,$null,$P,$false)
                        $CN=($sslStream.RemoteCertificate.Subject -split " " | select -First 1).trim(",")
                        $CertData=$sslStream.RemoteCertificate.GetRawCertData()
                        $Rcert=[system.convert]::ToBase64String($CertData)
                        $TempObj.sslData+=@{"RemoteCert"=@{"Subject"=$CN;"Cert"="$Rcert"};
                            "Protocol"="$($sslStream.SslProtocol) : Success"}
                    } catch {
                        $TempObj.sslData+=@{"Protocol"="$P : Failed";
                            "RemoteCert"="Could Not Establish SSL connection"}
                    }
                } catch {
                    $TempObj.Result="$Res"
                }
                $sock.Close()           
            }
            $OutObj+=$TempObj
            Write-Verbose "$o $i $Res $($sslData.Protocol)"
        }
        $PortResult=$OutObj | ConvertTo-Json -Depth 100 | ConvertFrom-Json
        $Result=@{"$o"=@($PortResult)}
        if($ResultView -match "Object"){
            $Result    
        } elseif($ResultView -match "Json") {
            $Result | ConvertTo-Json -Depth 100
        }
    }
}
function BabbleData(){
    $BabbleURL="https://libraryofbabel.info/book.cgi?0-w1-s1-v01:random"
    $Request=New-Object System.Net.WebClient
    $Response=$Request.DownloadString($BabbleURL) -split '<PRE id = "textblock">' -split '</PRE>'
    $Response[1]
}
function newStuff(){
    param(
        [string[]]$Types=@("der","pem","crt","cer","key","bundle","p7b","p7s","p7c","pfx"),
        [string[]]$Path=$PWD
    )
    if($Types -eq "All"){
        $Types=@("der","pem","crt","cer","key","bundle","p7b","p7s","p7c","pfx")
    }
    $Files=Get-ChildItem -Recurse -Path $Path | Where-Object {$_.Extension -match $Types}
    $Files
    
}
function Unzip(){
    param(
        [string]$Zipfile,
        [string]$OutPath
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Zipfile, $OutPath)
}
function MSIProperties(){
    param(
        [string]$PathInfo='C:\Users\administrator\Desktop\15.4.zip\New folder\15.4.0\Venafi Trust Protection Platform 15.4.0\VenafiTPPInstallx64.msi',
        [string]$Search="ProductVersion"
    )
    $query = "SELECT * FROM Property" 
    $WI = New-Object -ComObject WindowsInstaller.Installer
    $WIDB = $WI.GetType().InvokeMember("OpenDatabase","InvokeMethod",$Null,$WI,@($PathInfo,0))
    $View = $WIDB.GetType().InvokeMember("OpenView","InvokeMethod",$null,$WIDB,$query)
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
    $Res=@()
    while($Record = $View.GetType().InvokeMember("Fetch","InvokeMethod",$null,$View,$null)){
        $Res+=@{$Record.GetType().InvokeMember("StringData","GetProperty",$null,$Record,1)=$Record.GetType().InvokeMember("StringData","GetProperty",$null,$Record,2)}
    }
    $View.GetType().InvokeMember("Close","InvokeMethod",$null,$View,$null)
    return $Res.$Search
}
function CAtest(){
    $CAURL=$((certutil.exe) | sls "config" | %{$_ -replace "(config:|\s|'|``)"})
    certutil.exe -ping $CAURL
    for($i=0;$i -le 10;$i++){
        certutil.exe -v -template $CAURL
        sleep 1
    }
}
function randomAscii(){
    param(
        [int]$Length=8,
        [int]$NumOfWords=10
    )
    $Limit=65535
    $Words=@()
    $TW=@()
    do {
        if($TW.Count -lt $Length){
            $IL=Get-Random -Maximum $Limit
            $W=[char]$IL
            $TW+=$W
        } else {
            $Words+=$(-join [char[]]$TW)
            $TW=@()
        }
    } until ($Words.Count -ge $NumOfWords)
    $Words
}
function PortTool(){
    param(
        [string]$Server,
        [string]$Port=8888
    )
    if($Server){
        $Session=New-Object System.Net.Sockets.TcpClient
        $Session.ConnectAsync($Server,$Port).Wait(10)
        $Stream=$Session.GetStream()
        $SR=New-Object System.IO.StreamReader($Stream)
        $SR
        $Stream.Close()
    }

}
function IPrange(){
    [CmdLetBinding()]
    param(
        [string]$Path,
        [string]$IPList,
        [string]$OutJob,
        [string]$Ports="21,22,25,80,139,443,444,445,540,587,1000,1002,1010,1028,1030,1032,1050,1109,1158,1311,1500,2000,2100,2376,3001,3443,4443,4899,5002,5250,5500,5555,6002,6666,6789,7000,7002,7273,7443,7777,8001,8002,8003,8008,8009,8010,8011,8032,8080,8081,8082,8083,8084,8087,8088,8089,8090,8123,8161,8181,8443,8531,8880,8881,8882,8888,8910,8980,8983,8989,9000,9002,9006,9060,9080,9087,9090,9111,9443,9850,9996,9999,10000,10051,10162,10443,11086,11087,14300,17002,17080,18101,18443,32771,32773,32774,32775,32778,32779,32781,32782,32783,32784,32785,32786,32787,32788,32789,32790,40421,44333,44337,44876,50000,50001,50030,51365,55993,56914,58368,58960,60008"
    )
    $AR=@{}
    if($Path -and (Test-Path $Path)){
        $IPL=Get-Content $Path -Encoding String | ? {$_.length -le 85} | `
            Sort-Object {"{0:d3}.{1:d3}.{2:d3}.{3:d3}" -f @([int[]]$_.split('.'))} -Unique
    } elseif($IPList) {
        $IPL=($IPList -split "\,") | ? {$_.length -le 85} | `
            Sort-Object {"{0:d3}.{1:d3}.{2:d3}.{3:d3}" -f @([int[]]$_.split('.'))} -Unique
    }
    $TotalObj=@{}
    $FinalJob=@()
    foreach($E in $IPL){
        $OBJKEY=$E -split "\."
        $F3=$OBJKEY[0]+"."+$OBJKEY[1]+"."+$OBJKEY[2]
        $TotalObj.$F3+=","+$OBJKEY[3]
    }
    foreach($M in $TotalObj.Keys){
        $RC=$TotalObj.$M -split ","| sort -Descending
        $CheckArr=@{"f"=$Null;"s"=$Null}
        foreach($G in $RC){
            if($CheckArr.f -eq $Null){
                $CheckArr.f=$G
            } else {
                $CheckArr.s=$G
            }
            if($G -ne ""){
                $NewIP=$M+"."+$G
                $FinalJob+=$NewIP
                $CheckArr=@{"f"=$Null;"s"=$Null}
            }
            
        }
    }
    $FinalJob=$FinalJob | Sort-Object {"{0:d3}.{1:d3}.{2:d3}.{3:d3}" -f @([int[]]$_.split('.'))} -Unique
    if(!(Test-Path $OutJob)){
        foreach($F in $FinalJob){
            $F+":"+$Ports >> $OutJob
        }
    } else {
        Write-Host "File or job already exists"
    }
}
function ToIP(){
    param(
        [string[]]$IPlist
    )
    $IPF=@()
    foreach($IL in $IPlist){
        $IPF+=([System.Net.IPAddress]$IL).IPAddressToString
    }
    return $IPF
}
function chromeXSS(){
    & "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --disable-xss-auditor
}
function NetworkDiscoveryWatch(){
    [cmdletbinding()]
    param(
        [int]$Interval=100,
        [switch]$Indefinate
    )
    $Count=0
    $Differences=@()
    $Differences+=@{"Diff"=$(netstat -n | Sort-Object -Descending)}
    do{
        $CMP=@{"Diff"=Compare-Object -ReferenceObject $Differences[-1].diff -DifferenceObject $(netstat -n | Sort-Object -Descending) | Where-Object {$_.sideindicator -eq "=>"}}
        if($CMP.diff){
            $Differences+=$CMP
        }
        $Count++
    } until ($Count -ge $Interval -and !$Indefinate)
    $Differences
    
}
function play12(){
    param(
        [ValidateSet('Negotiate','NTLM','SChannel','Kerberos','Kernal')]
        [string]$u,
        [ValidateSet('Connect','Call','pkt','Integrity','Privacy')]
        [string]$a,
        [string]$Server,
        [string[]]$I,
        [switch]$Certificate
    )
    if($I){
        $I[0]=$userN
        $I[1]=$Domain
        $I[2]=$Password
    }
    if($Certificate){
        $T='ncacn_http'
        $F=1
    }

        -I
        -C
        -S
        -E
        RpcPing.exe -s 192.168.132.151 -v 3
        RpcPing.exe -u Kerberos -a Integrity -v 3 -s 192.168.132.151 -t ncacn_http -b -F 1
        Get-WmiObject -Computer PRIMARY 
}
