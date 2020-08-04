[pscredential]$creds = get-credential -message hey -username 'Administrator'
$comps =@('10.110.3.12','10.110.3.13','10.110.3.14')
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

$DNS = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {Get-DnsClientCache} | select-object pscomputername,data,name,entry
$IPs = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {Get-NetTCPConnection} | select-object pscomputername,LocalAddress,LocalPort,RemoteAddress,RemotePort,owningprocess,state

$reg = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    foreach ($key in $using:Runkeys) {
        Get-Item -path $key -ErrorAction SilentlyContinue -Force
    }
}

$skeddy = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    Get-ScheduledTask | Select-Object @{label="SourceHost";expression={hostname}},Taskname,{$_.Actions.Execute}
}| select-Object * -ExcludeProperty Runspaceid

$procs = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    get-wmiobject win32_process | select-Object Name,ProcessId,ParentProcessId,CommandLine
} | select-Object * -ExcludeProperty Runspaceid

$Users = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    Get-LocalUser | select-Object name,enabled,pscomputername,@{label="GroupMembership";expression={net.exe user $_.name | Select-String "Local Group Memberships" }},@{label="LastLogon";expression={net.exe user $_.name | Select-String "Last Logon"}}
} | select-Object * -ExcludeProperty Runspaceid
$services = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    get-wmiobject win32_service | select-Object name,description,pathname,state,processid,status
}| select-Object * -ExcludeProperty Runspaceid

$DNS > ./report.txt
$IPs| ft -autosize -wrap >> ./report.txt
$reg >> ./report.txt
$skeddy | ft -autosize -wrap >> ./report.txt
$procs | ft -autosize -wrap >> ./report.txt
$users >> ./report.txt
$services | ft -autosize -wrap >> ./report.text
<#
$dir = (cmd /c robocopy C:\ null *.* /l /s /njh /njs /ns /fp /lev:12).trim() | select-string "New File" | where {-not [string]::IsNullOrWhiteSpace($_)} |foreach{$_ -replace "`t","" -replace 'New File  ',''} 
#put hashes in here
[hashtable]$hashes =@{
'e4300cff11cbff4c3542a08de61f584b8e0d9ca9' = 'SHA1'
'4a80c5896e2242c99e289a1fac4b7420a0a6af45' = 'SHA1'
}
foreach ($d in $dir){Get-FileHash -Path $d -Algorithm SHA1 -ErrorAction SilentlyContinue | where {$hashes.ContainsKey($_.hash)}}
#>
