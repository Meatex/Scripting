#variable and arrays declerations 
[System.Array]$comps = (7..13) |ForEach-Object {ping -n 1 172.16.12.$_}| Select-String ttl |ForEach-Object {(($_ -split ' ')[2]).split(':')[0]}
set-item wsman:\localhost\Client\TrustedHosts -value ($comps -join ",")
[pscredential]$creds = Get-Credential -Message hey -UserName Administrator
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

#define class for our IOC object - based of of headers used in IOC files with spaces removed. Also reusing as reporting class
class IOCList {
    [string]$APTName
    [System.Array]$DNSRecords
    [System.Array]$Files
    [System.Array]$IPs
    [System.Array]$RegistryKeys
    [System.Array]$HostsManipulation
    [System.Array]$Hashes
    [System.Array]$UserAgents
    [System.Array]$Users
    [System.Array]$ScheduledTasks
    [system.array]$Services
    [string]$ScannedComp
}
#function to create object based on above class 
function CreateAPTObject ($file)
{
    [System.Array]$doc = (Get-Content -path $file | where-object {$_.length -ge 3}) # only takes lines with 3 or more characters - removes blank lines
    $tempObject = [IOCList]::new()
    $tempObject.APTName = $doc[0]
    [System.Array]$tempArray = @()

    for ($i = 0; $i -lt $doc.count; $i++)
    { 
        <# 
        look for something like
        ############
        header
        ############
        #>
        if (($doc[$i] -like "*####*") -and ($doc[$i+2] -like "*####*")){
            # we know list of IOCs starts from $i+3 - want to keep reading lines into temparray until hit another ######## 
            $x = 3
            while (($doc[$i+$x] -notlike "*####*") -and ($doc[$i+$x] -ne $null))
            {
                $tempArray += $doc[$i+$x]
                $x++
            }
            #header Logic
            $tempObject.($doc[$i+1] -replace ' ','') = $tempArray
            $i = $i + (2 + $tempArray.count) # should skip over all read items put into temp array
            [System.Array]$tempArray = @()
        }
    }
    return $tempObject
}
$APT2IOCs = CreateAPTObject -file 'C:\Users\DCI Student\Desktop\IOCs\APT-2 IOC.txt'
$APT26IOCs = CreateAPTObject -file 'C:\Users\DCI Student\Desktop\IOCs\APT-26 IOCs.txt'
$Fin4IOCs = CreateAPTObject -file 'C:\Users\DCI Student\Desktop\IOCs\Fin4 IOCs.txt'
$APTs = @($APT2IOCs, $APT26IOCs, $Fin4IOCs)

$ReportingTemp = [IOCList]::new()
$report = @()

#place holder commands 
#DNS
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {Get-DnsClientCache | where {$_.Entry -in $Using:APTs[2].DNSRecords}}

#IPs
Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock {Get-NetTCPConnection | where-object {$_.RemoteAddress -in $using:APTs[0].IPs}}

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
    $dir = (cmd /c robocopy C:\ null *.* /l /s /njh /njs /ns /fp /lev:2).trim() | select-string "New File" | where {-not [string]::IsNullOrWhiteSpace($_)} |foreach{$_ -replace "`t","" -replace 'New File  ',''} 
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

