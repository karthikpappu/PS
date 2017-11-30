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