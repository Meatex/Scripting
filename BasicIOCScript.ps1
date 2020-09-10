[pscredential]$creds = get-credential -message hey -username 'Administrator'
$comps =@()
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

$reg = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    foreach ($key in $using:Runkeys) {Get-Item -path $key -ErrorAction SilentlyContinue -Force}
} 

$skeddy = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    Get-ScheduledTask | Select-Object @{label="SourceHost";expression={hostname}},Taskname,{$_.Actions.Execute}
}| select-Object * -ExcludeProperty Runspaceid

$procs = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    get-wmiobject win32_process | select-Object Name,ProcessId,ParentProcessId,CommandLine
} | select-Object * -ExcludeProperty Runspaceid

$Users = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    Get-LocalUser | select-Object name,enabled,pscomputername,@{label="GroupMembership";expression={net.exe user $_.name | Select-String "Local Group Memberships" }},@{label="LastLogon";expression={net.exe user $_.name | Select-String "Last Logon"}}
} | select-Object * -ExcludeProperty Runspaceid

$services = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    get-wmiobject win32_service | select-Object name,pathname,state,processid,status
}| select-Object * -ExcludeProperty Runspaceid

#alternate search method below, may be quicker on mechanical drives
$HashMatches = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
#put in MD5 hash and size of suss file in bytes (length) 
$search =@{
'1E4097FB69034E0B019F30228CF25D1A' = '975'
'B43C614FF06CE540B67EB3229A02675C' = '2148'
}

$dir = gci -path C:\ -Recurse -Force -ErrorAction SilentlyContinue | where{$search.containsvalue(($_.length).ToString())}
$dir | foreach{Get-FileHash -path $_.FullName -Algorithm MD5} | where{$search.ContainsKey($_.hash)}
}| select-Object * -ExcludeProperty Runspaceid

$DNS > ./report.txt
$IPs| ft -autosize -wrap >> ./report.txt
$reg >> ./report.txt
$skeddy | ft -autosize -wrap >> ./report.txt
$procs | ft pscomputername,Name,ProcessId,ParentProcessId,CommandLine -autosize -wrap >> ./report.txt
$users | ft -wrap -autosize >> ./report.txt
$services | ft pscomputername,name,State,ProcessId,PathName,Status -autosize -wrap >> ./report.txt
$HashMatches | ft pscomputername,path,hash >> ./report.txt


<#
Tested with nearly 800GB of files on 1TB SSD drive with 2 target hashes/sizes

Measure-Command {
$temp = (cmd /c robocopy C:\ null *.* /l /BYTES /s /njh /njs /ns /fp /lev:15).trim() | select-string "New File"| 
where {-not [string]::IsNullOrWhiteSpace($_)} | foreach{($_ -replace "`t",' ' -replace "New File","").trim()} | where{$search.containsvalue(($_.split(' ')[0]))}
$temp | foreach{Get-FileHash -path $_.split(' ',2)[1] -Algorithm MD5} | where{$search.ContainsKey($_.hash)}
} > 90 seconds to complete

Measure-Command {
$temp = gci -path C:\ -Recurse -Force -ErrorAction SilentlyContinue | where{$search.containsvalue(($_.length).ToString())}
$temp | foreach{Get-FileHash -path $_.FullName -Algorithm MD5} | where{$search.ContainsKey($_.hash)}
} > 53 seconds to complete

#>
