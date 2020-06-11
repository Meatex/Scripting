#limitations so far
# Need to implement job handling
# Will get back all contents of reg key if there is a single match

#variable and arrays declerations 
#[System.Array]$comps = (7..13) |ForEach-Object {ping -n 1 172.16.12.$_}| Select-String ttl |ForEach-Object {(($_ -split ' ')[2]).split(':')[0]}
#[pscredential]$creds = Get-Credential -Message hey -UserName Administrator
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

<#
#IOC Hunter jobs
$filesjob = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock{ 
    foreach ($f in $using:files) 
    {
        Get-ChildItem -Recurse -Path C:\ -ErrorAction SilentlyContinue -force | where-object {$_.FullName -like "*$f"} 
    }
} -asjob -JobName "Filesjob"

$regjob = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock{ 
    foreach ($r in $using:Runkeys)  
    { 
        if ((get-item -erroraction SilentlyContinue -path $r).property | where {$_ -in $using:RegEntries} ){get-item -Path $r}  
    }
} -AsJob -JobName "RegJob"
$ConnsJob = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock{ 
    Get-NetTCPConnection | where-object {$_.RemoteAddress -in $using:IOCIPs} 
} -AsJob -JobName "ConnsJob"

# get data when notified Job has completed and clean up
$joblist = get-job | where {$_.Name -match "FilesJob" -or "RegJob" -or "Connsjob"}
foreach ($job in $joblist){ 
    Register-ObjectEvent $job StateChanged -Action {
    Write-Host ("`nJob #{0} ({1}) complete." -f $sender.Id, $sender.Name) -fore White -back DarkRed
    $eventSubscriber | Stop-Job
    $eventSubscriber | Unregister-Event
    $eventSubscriber.action | Remove-Job -Force
    
    }
} #>
#still have to manually receive-job to get output

#Get-ScheduledTask | Where-Object {$_.Actions.execute -like "$SrchStr" }| Select-Object Taskname, {$_.Actions.Execute}

#check new services


<#

#>
