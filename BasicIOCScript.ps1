[pscredential]$creds = get-credential -message hey -username 'domain\admin'
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

$DNS = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {Get-DnsClientCache}
$IPs = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {Get-NetTCPConnection}

$reg = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    foreach ($key in $using:Runkeys) {
        $matches = (Get-Item -path $key).GetValueNames()
        if ($matches -ne $null){Get-ItemProperty -path $key -Name $matches | select-object pscomputername,pspath,$matches}
    }
}| Select-Object * -ExcludeProperty Runspaceid

$skeddy = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    Get-ScheduledTask | Select-Object pscomputername,Taskname,{$_.Actions.Execute}
}

$procs = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    get-wmiobject win32_process | select-Object Name,ProcessId,ParentProcessId,CommandLine
}

$Users = Invoke-Command -ComputerName $comps -Credential $creds -Authentication Negotiate -ScriptBlock {
    Get-LocalUser | select-Object name,enabled,pscomputername,@{label="GroupMembership";expression={net.exe user $_.name | Select-String "Local Group Memberships" }},@{label="LastLogon";expression={net.exe user $_.name | Select-String "Last Logon"}}
} | select-Object * -ExcludeProperty Runspaceid

echo $DNS
echo $IPs
echo $reg
echo $skeddy
echo $procs
echo $users
<#
$dir = (cmd /c robocopy C:\ null *.* /l /s /njh /njs /ns /fp /lev:12).trim() | select-string "New File" | where {-not [string]::IsNullOrWhiteSpace($_)} |foreach{$_ -replace "`t","" -replace 'New File  ',''} 
#put hashes in here
[hashtable]$hashes =@{
'e4300cff11cbff4c3542a08de61f584b8e0d9ca9' = 'SHA1'
'4a80c5896e2242c99e289a1fac4b7420a0a6af45' = 'SHA1'
}
foreach ($d in $dir){Get-FileHash -Path $d -Algorithm SHA1 -ErrorAction SilentlyContinue | where {$hashes.ContainsKey($_.hash)}}
#>
