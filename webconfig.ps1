function webconfig(){
    param(
        [string[]]$Search=".*",
        [string]$OutFile="C:\Webconfiglist.txt"
    )
    if($OutFile -ne $null)
    {
        $Directories=@(
            "C:\Program Files\Venafi",
            "C:\Windows\Microsoft.NET\Framework",
            "C:\Windows\Microsoft.NET\Framework64")
        $ConfigDN=Get-ChildItem -Recurse -Path $Directories -Filter web.config
        $FinalContent=@()
        foreach($C in $ConfigDN){
            $Content=@{$C.FullName=$(Get-Content -Encoding String $C.FullName)}
            $FinalContent+=$Content
        }
        $MatchingObjects=$FinalContent | Where-Object {$_.values -match $Search} |  Sort-Object -Descending 
        foreach($M in $MatchingObjects){
            $M.keys
            $V=$M.Values | Select-String $Search
            $V
            if($OutFile){
                $V | Out-File -FilePath $OutFile -Append
            }
        }
    } else {
        Write-Host "Syntax is: `r`n webconfig -OutFile {Directory}"
    }
}
webconfig