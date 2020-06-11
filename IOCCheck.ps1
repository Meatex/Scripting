
#variable and arrays declerations 
[System.Array]$comps = (7..13) |ForEach-Object {ping -n 1 172.16.12.$_}| Select-String ttl |ForEach-Object {(($_ -split ' ')[2]).split(':')[0]}
[pscredential]$creds = Get-Credential -Message hey -UserName Administrator
set-item wsman:\localhost\Client\TrustedHosts -value ($comps -join ",")
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

#define class for our IOC object - based of of headers used in IOC files with spaces removed.
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

#IOC Hunter jobs

