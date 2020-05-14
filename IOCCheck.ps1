

$ioc = "MSASCuiL.exe"

$SrchStr = "*"+$ioc+"*"



$RunKeys=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\", 
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
"HKU:\.Default\Software\Microsoft\Windows\CurrentVersion\Run\",
"HKU:\.Default\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run\",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run\")


$ErrorActionPreference = "silentlycontinue"
foreach($k in $RunKeys){
    if ((Get-Item -Path $k) -ne $null){
        if ((Get-ItemPropertyValue -path $k -Name ((Get-Item -Path $k).getvaluenames())[0..-1]) -like $SrchStr ){
            get-item -path $k
        }
    }
}

Get-ScheduledTask | Where-Object {$_.Actions.execute -like "$SrchStr" }| Select-Object Taskname, {$_.Actions.Execute}

if ($ioc.Length -le 4){
    Write-Host "Given IO"
}
#check new services
#file check

<#
testing stuff

$k="HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\"
$test = Get-ItemPropertyValue -path $k -Name ((Get-Item -Path $k).getvaluenames())
if ($test[0..-1] -like $SrchStr){echo "hit`n"; echo $test}
#>
