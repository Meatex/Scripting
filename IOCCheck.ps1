#limitations so far
# Need to implement job handling
# Will get back all contents of reg key if there is a single match


#[System.Array]$files = ((((Get-Content -path 'C:\Users\DCI Student\Desktop\Exercise 4.1-05 - Create a PowerShell Script to Collect Data from Multiple Systems\files.txt') -replace '%\\','\') -replace '%',"`$env:").split("`r")).Trim()
[System.Array]$temp = Get-Content -path 'C:\Users\DCI Student\Desktop\Exercise 4.1-05 - Create a PowerShell Script to Collect Data from Multiple Systems\files.txt'
$files = $temp | foreach {$_.split('%')[-1]}
[System.Array]$comps = @("10.10.10.56", "10.10.10.83", "10.10.10.107")
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
[System.Array]$temp = Get-Content -path 'C:\Users\DCI Student\Desktop\Exercise 4.1-05 - Create a PowerShell Script to Collect Data from Multiple Systems\reg.txt'
[System.Array]$RegEntries = $temp | foreach {$_.split('"')[-2]}

#IOC Hunter jobs
$filesjob = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock 
{ 
    foreach ($f in $using:files) 
    {
        Get-ChildItem -Recurse -Path C:\ -ErrorAction SilentlyContinue | where-object {$_.FullName -like "*$f"} 
    }
} -asjob -JobName "Filesjob"

$regjob = Invoke-Command -ComputerName $comps -Credential $creds -ScriptBlock 
{ 
    foreach ($r in $using:Runkeys)  
    { 
        if ((get-item -erroraction SilentlyContinue -path $r).property | where {$_ -in $using:RegEntries} ){get-item -Path $r}  
    }
}


Get-ScheduledTask | Where-Object {$_.Actions.execute -like "$SrchStr" }| Select-Object Taskname, {$_.Actions.Execute}

#check new services


<#

#>
