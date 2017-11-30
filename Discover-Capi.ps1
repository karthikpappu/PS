function Discover-Capi(){
    param(
        [string]$TPPServerName='PRIMARY',
        [string]$InputFileCSV='C:\Users\Jarek.ketcheside\kb\Discover-CAPI\Sample-InputFile.csv',
        [string]$FailuresFileCSV='C:\Users\Jarek.ketcheside\kb\Discover-CAPI\Fail.csv',
        [string]$NewDeviceFolderDN='\ved\Policy\Devices1',
        [string]$NewCertFolderDN='\ved\policy\Cert1',
        [switch]$IgnoreSSLWarnings
    )
    $EDN='C:\Users\Jarek.ketcheside\kb\Discover-CAPI\Discover-CAPI.exe '
    $CMDString="-TPPServerName $TPPServerName -InputFileCSV $InputFileCSV -FailureFileCSV $FailureFileCSV -NewDeviceFolderDN $NewDeviceFolderDN -NewCertFolderDN $NewCertFolderDN"

    Invoke-Expression {$EDN+$CMDString} -NoNewScope
    
}
Discover-Capi






$D1=((Get-Content .\data1.txt) -split "\(" -split "\)" -split ",") | %{if($_ -match 'VEN\-([0-9])'){$_}}
$D2=((Get-Content .\data2.txt) -split "\(" -split "\)" -split ",") | %{if($_ -match 'VEN\-([0-9])'){$_}}
Compare-Object $D1 $D2


28132 & 28289 (responded >3pm yesterday) and also 27350