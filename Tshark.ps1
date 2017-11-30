function tsharktest(){
    param(
        [string]$Infile,
        [string]$Filter='ssl.handshake.extensions_server_name'
    )
    $Test=@()
    $TSD='C:\Program Files\Wireshark\tshark.exe'
    $Options=@("-T fields","-e $Filter", "-r $Infile")
    $CMD = {& $TSD $Options }
    if($Infile -and $Filter){
        $TC=Invoke-Command $CMD
        if($TC -notmatch "^(\s)"){
            $Test+=$TC
        }
    }
    $Test -replace "",""
}


