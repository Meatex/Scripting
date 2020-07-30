#variable and arrays declerations 
[System.Array]$comps = ('172.16.0.50','172.16.0.40','172.16.0.60','172.16.2.10','172.16.2.20','172.16.3.50','172.16.3.51','172.16.4.50') 
set-item wsman:\localhost\Client\TrustedHosts -value ($comps -join ",")
[pscredential]$creds = Get-Credential -Message hey -UserName 'health.range\Administrator'
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

#variables
[System.Array]$DNSrecords = @()
[System.Array]$Connections = @()
[System.Array]$RegKeys = @()

#DNS
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {Get-DnsClientCache | where {$_.Entry -in $Using:$DNSrecords}}

#IPs
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {Get-NetTCPConnection | where-object {$_.RemoteAddress -in $using:Connections}}

#registry
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    $matches = (Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\run).GetValueNames() | where {$_ -in $Using:APTs[0].RegistryKeys} 
    if ($matches -ne $null){Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\run -Name $matches | select pscomputername,pspath,$matches}
    
} | select * -ExcludeProperty RunSpaceId  

#hosts
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    get-content -Path "$env:systemroot\system32\drivers\etc\hosts" | where {(($_ -replace "`t",'' -replace ' ','').trim()) -in (($using:APTs[1].HostsManipulation -replace "`t",'' -replace ' ','').trim())} | 
        select-object pscomputername,@{Label="HostsFileMatch";expression={$_}}
} | select pscomputername,HostsFileMatch

# sched tasks
invoke-command -ComputerName $comps -Credential $creds -ScriptBlock { 
Get-ScheduledTask | Select-Object pscomputername,Taskname,{$_.Actions.Execute} | where {$_.taskname -in $using:APTs[2].ScheduledTasks}
} 

#files and hashes
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    $dir = (cmd /c robocopy C:\ null *.* /l /s /njh /njs /ns /fp /lev:8).trim() | select-string "New File" | where {-not [string]::IsNullOrWhiteSpace($_)} |foreach{$_ -replace "`t","" -replace 'New File  ',''} 
    [hashtable]$hashes =@{}
    if ($using:APTs[2].Hashes -ne $null){
        $using:APTs[2].Hashes | foreach{$hashes[$_] = "MD5"}
        foreach ($d in $dir){Get-FileHash -Path $d -Algorithm MD5 -ErrorAction SilentlyContinue | where {$hashes.ContainsKey($_.hash)}}
    }
    $files = $using:APTs[0].Files
    $filematches = foreach($f in $files){$dir | where-object{$_ -like "*$f"}}
    $filematches | get-item
}

#local users
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {
    Get-LocalUser | select name,enabled,pscomputername,@{label="GroupMembership";expression={net.exe user $_.name | Select-String "Local Group Memberships" }},@{label="LastLogon";expression={net.exe user $_.name | Select-String "Last Logon"}} 
} | select * -ExcludeProperty Runspaceid

# services

<#
Get-LocalUser | 
    ForEach-Object { 
        $user = $_
        return [PSCustomObject]@{ 
            "User" = $user.Name
            "SID" = $user.SID
            "Groups" = Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name"
        } 
    }
#>
