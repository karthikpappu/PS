Add-Type -AssemblyName System.Windows.Forms 
add-type -AssemblyName PresentationCore
$Path="$env:TEMP\Copy.txt"
if(!([System.IO.File]::Exists($Path))){
    echo $null > $Path
}
function CopyData(){
    $Original=[System.Windows.Clipboard]::GetText()
    if([System.Windows.Clipboard]::ContainsAudio()){ 
        $Audio=[System.Convert]::ToBase64String([System.Windows.Clipboard]::GetAudioStream())
        $Audio=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Audio))
    }
    if([System.Windows.Clipboard]::ContainsFileDropList()){ 
        $FDL=[System.Windows.Clipboard]::GetFileDropList()
        $FDL=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($FDL)))
    }
    if([System.Windows.Clipboard]::ContainsImage()){
        $Image=[System.Windows.Clipboard]::GetImage() 
        $Image=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Image))  
    }
    if([System.Windows.Clipboard]::ContainsText()){
        $Text=[System.Windows.Clipboard]::GetText() 
        $Text=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Text))
    }
    $DATA=$(Get-Content $Path | ConvertFrom-Json)
    if($DATA.Last -eq "9"){
        $DATA.Last="0"
    } else {
        [int]$IntF=($DATA.Last)
        $IntF++
        $DATA.Last="$IntF"
    }
    $CPDATA=@{"Audio"="$Audio";
        "FDL"="$FDL";
        "Image"="$Image";
        "Text"="$Text"}
    $CPOBJ=@{"CPDATA"=$CPDATA}
    $DATA."$($DATA.Last)"=$CPOBJ
    $DATA | ConvertTo-Json -Depth 100 -Compress | Out-File -Encoding string $Path
}
CopyData
