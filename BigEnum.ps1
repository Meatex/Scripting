<#
-Description
    Windows Host Enumeration script made for Tango DIEX nodes
    Intent is for the data to be ingestable into a SIEM (maybe one day)
    Does return errors if no active user session is found on the target and for being unable to find processes with specified pid
        these errors are expected and are a feature not a bug

-Usage

    Check $NodeNet and $ReportLoc below
    Run script and enter both admin credentials
    Execution can take as long as 30 minutes
    If script misses a host you can run "SingleEnum -SingleTarget "192.168.0.5" -adminLVL "adds"
        if its a new powershell window you will need to run the variable block portion of the script first


-Version History
    HostEnum version 2.8
        Moved variable declaration into a block so users know what portion to run so they have everything ready
        Added function for single host enumeration - this will output into the folder of most recent scane

    HostEnum version 2.7
        reverted change for typed variables back to System.Array
        added line to remove tmp files so we don't have multiples on next run
        fixed parsing of process creation date that broke when changed from ciminstance to wmiobject- now returns datetime object (this also means that recent process creation is now working again)
        added prefilled "diep\ _a" and "diep\ _adds" to credential prompt
    HostEnum version 2.6
        added alerts on services, tasks, software and hotfixes that are time stamped within the past 14hrs - 1 day
        added/improved grid-view output of previous scan statistics as well as current scan for easier comparisons 
    HostEnem version 2.5
        fixed Registry subkey enumeration and statistic generation
        moved RemoteTree (PSTree like output) into a function that can be easily added into a for loop if desired
        change class typed variables from System.Array to psobject - hopefully this eliminates data duplication in "Value" fields
    HostEnum version 2.4
        added host output for better usability
        fixed quser output parsing so that data matches fields correctly
        added class properties and commands for ntp, content of C:\users, installed hotfixes
    HostEnum version 2.3
        restructered script to be more user friendly
        implemented ping sweep of client IP ranges and adding alive hosts to TargetHosts
        added class propert and commands for enumerating prefetch files (no parsing of .pf files just getting names and dates)        
    HostEnum version 2.2
        added stats calculation
    HostEnum version 2.1
        Bug fixes and improvements
    HostEnum version 2
        Rewrote code for remote execution against multiple target hosts
    HostEnum version 1
        Created class
        developed basic enumeration commands

-TODO

    Rewrite 3.0 to utilise functions in its enumeration
    Add functions for comparing sub objects
    Gibbo is a weeb


#>

#######################################
        #Start Of Variable Block
#######################################

$NodeNet = "192.168.1" # change this to match target node
$ReportLoc = "C:\users\admin\Desktop\Reports\" # output will be generated in this folder in a folder called _Current

# Function to return PSTree like output from remote host
# requires admin creds
function RemoteTree ($TreeTarget)
{
    $RemoteTree = { 
    function PSTree($pslist){
        function Get-ProcessAndChildProcesses($Level, $Process) {
          "+{0}[{1,-5}] [{2}]" -f ("---" * $Level), $Process.ProcessId, $Process.Name
          $Children = $pslist | where-object {$_.ParentProcessId -eq $Process.ProcessId -and $_.CreationDate -ge $Process.CreationDate}
          if ($Children -ne $null) {
            foreach ($Child in $Children) {
              Get-ProcessAndChildProcesses ($Level + 1) $Child
            }
          }
        }
    
        $RootProcesses = @()
        # Process "System Idle Process" is processed differently, as ProcessId and ParentProcessId are 0
        # $pslists is sliced from index 1 to the end of the array
        foreach ($Process in $pslist[1..($pslist.length-1)]) {
          $Parent = $pslist | where-object {$_.ProcessId -eq $Process.ParentProcessId -and $_.CreationDate -lt $Process.CreationDate}
          if ($Parent -eq $null) {
            $RootProcesses += $Process
          }
        }
        #Process the "System Idle process" separately
        "`n=== {0} === `n" -f $env:COMPUTERNAME
        "[{0,-5}] [{1}]" -f $pslist[0].ProcessId, $pslist[0].Name
        foreach ($Process in $RootProcesses) {
          Get-ProcessAndChildProcesses 0 $Process
        }

    }
PSTree(Get-CimInstance -ClassName win32_process)
}
    $c = Get-Credential -Message "Enter Administrative credentials for target"
    Invoke-Command -ComputerName $TreeTarget -Credential $c -ScriptBlock $RemoteTree
    Remove-Variable c
}

# Function for enumerating a single host - this generates a report in most recent Reports folder
# Requires variable block be run if the script hasn't been run alread
function SingleEnum ($SingleTarget, $adminLVL){
    if ($adminLVL -like "*adds"){ $c = $using:creds_adds}
    else {$c = $Using:creds_a}
    $SEnum = Invoke-Command -ScriptBlock $Using:EnumScriptBlock -ComputerName $SingleTarget -Credential $c
    $folder = "{0}_Reports" -f (Get-ChildItem *.tmp).name.Split('.')[0]  
    Set-Location -Path $ReportLoc\$folder
    $filename = "{0}_{1}-Enum.json" -f ($SEnum.RunTime | Get-Date -UFormat "%Y-%m-%d %H%M"), $SEnum.HostName
    $SEnum | select * -ExcludeProperty Value | ConvertTo-Json | Out-File $filename -Force
    Remove-Variable c

}

$creds_a = Get-Credential -Message "Enter administrative _a credentials" -UserName "diep\ _a"
$creds_adds = Get-Credential -Message "Enter administrative _adds credentials" -UserName "diep\ _adds"

$TargetHosts_a = @(
    "$NodeNet.6"
    "$NodeNet.7"
)


$TargetHosts_adds = @(
    "$NodeNet.10"
    "$NodeNet.11"
)

$EnumScriptBlock = {
    # scripting designed to be pushed via invoke and run locally 
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

    class Baseline {
        [datetime]$RunTime
        [System.Array]$IPAdd 
        [string]$HostName
        [System.Array]$ntp
        [System.Array]$Users
        [System.Array]$LoggedUsers
        [System.Array]$DNSCache
        [System.Array]$Registry
        [System.Array]$HostsFile
        [System.Array]$Shares
        [System.Array]$NamedPipes
        [System.Array]$ScheduledTasks
        [System.Array]$Services
        [System.Array]$ProcessList
        [System.Array]$PreFetch
        [System.Array]$TCPConns
        [System.Array]$UDPListeners
        [System.Array]$USBDev
        [System.Array]$Software
        [System.Array]$HotFixes
        [psobject]$stats

    }

    $HostEnum = [Baseline]::new()
 

    $HostEnum.RunTime = (Get-Date -Format o)
    $HostEnum.IPAdd = Get-NetIPAddress | where { $_.AddressFamily -eq "IPv4" } | where { $_.IPAddress -ne "127.0.0.1" } | select IPAddress,InterfaceAlias
    $HostEnum.HostName = ($env:COMPUTERNAME)
    $HostEnum.ntp = ((w32tm.exe /query /status)) -replace ":  ","- " -replace ": ","," | convertfrom-csv -Header "Property", "Data"
    $HostEnum.Users = quser.exe | ForEach-Object -Process { $_ -replace "                  ", "," -replace '\s{2,}',',' } | ConvertFrom-Csv
    $HostEnum.LoggedUsers = Get-ChildItem -Path "C:\users\" | where {$_.Name -ne "Public"} | select Name,LastWriteTime
    $HostEnum.DNSCache = Get-DnsClientCache | where {$_.Data -notlike "$using:NodeNet.*"} |select Name,Entry,Type,Data # filter out DNS for local IPs
    $HostEnum.Registry = foreach ($key in $Runkeys) {if(Test-Path $key){
        $sub = (Get-ItemProperty -path $key)
        $sub.psobject.Properties | where { $_.name -notlike "PS*"} |select @{N="Key";E={$key}},@{N="SubKey";E={$_.name}},@{N="Entry";E={$_.value}} 
        }
    }
    $HostEnum.HostsFile = Get-Content -Path "C:\windows\system32\drivers\etc\hosts"| where {$_ -notlike "#*"} 
    $HostEnum.Shares = Get-SmbShare | select name,path,description
    $HostEnum.NamedPipes = Get-ChildItem -Path "\\.\pipe\" | select fullname
    $HostEnum.ScheduledTasks = Get-ScheduledTask | Select-Object Taskname,TaskPath,@{N="Date2";E={[datetime]::Parse($_.date)}},@{N="CommandLine";E={$_.Actions.Execute}},state,source,@{N="LastRunTime";E={(Get-ScheduledTaskInfo -TaskName $_.uri).lastRunTime}}
    $HostEnum.Services = Get-CimInstance -ClassName win32_service | select ProcessId,DisplayName,PathName,State,InstallDate # TODO confirm properties
    $HostEnum.ProcessList = Get-WmiObject -Class win32_process | select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,@{N="CreationDate";E={[System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)}},@{N="Modules";E={(Get-Process -id $_.ProcessId).Modules}},@{N="UserName";E={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} 
    $HostEnum.PreFetch = Get-ChildItem -Path "C:\windows\Prefetch" *.pf | select name,lastwritetime
    $HostEnum.TCPConns = Get-NetTCPConnection | select LocalAddress,LocalPort,RemoteAddress,Remoteport,State,OwningProcess,@{N="ProcessName";E={(Get-Process -Id $_.owningProcess).name }}
    $HostEnum.UDPListeners = Get-NetUDPEndpoint | select LocalAddress,LocalPort,OwningProcess,@{N="ProcessName";E={(Get-Process -Id $_.owningProcess).name }}
    $HostEnum.USBDev = Get-PnpDevice | Where-Object { $_.InstanceId -match '^USB' } | select PNPClass,DeviceID,InstallDate,Description,Name,Service,Present,Status
    # Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select FriendlyName # Get-PnpDevice for currently in used devices
    # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices
    $HostEnum.Software = Get-CimInstance -ClassName win32_product | select Name,Version,InstallDate2,InstallSource 
    $HostEnum.HotFixes = Get-HotFix | select caption,Description,installedon,installedby,hotfixid

    # statistics calculation block
    $HostEnum.stats = New-Object PSCustomObject
    Add-Member -InputObject $HostEnum.stats -Name Hostname -MemberType NoteProperty  -Value $HostEnum.Hostname
    Add-Member -InputObject $HostEnum.stats -Name ActiveUserCount -MemberType NoteProperty  -Value $HostEnum.Users.count
    Add-Member -InputObject $HostEnum.stats -Name UsersLoggedCount -MemberType NoteProperty -Value $HostEnum.LoggedUsers.count
    Add-Member -InputObject $HostEnum.stats -Name RegistryCount -MemberType NoteProperty -Value $HostEnum.registry.count
    Add-Member -InputObject $HostEnum.stats -Name ServiceCount -MemberType NoteProperty -Value $HostEnum.Services.Count
    Add-Member -InputObject $HostEnum.stats -Name ProcCount -MemberType NoteProperty -Value $HostEnum.ProcessList.count
    Add-Member -InputObject $HostEnum.stats -Name PreFetchCount -MemberType NoteProperty -Value $HostEnum.PreFetch.count    
    Add-Member -InputObject $HostEnum.stats -Name SchedTasksCount -MemberType NoteProperty -Value $HostEnum.ScheduledTasks.count
    Add-Member -InputObject $HostEnum.stats -Name USBDevCount -MemberType NoteProperty -Value $HostEnum.USBdev.count
    Add-Member -InputObject $HostEnum.stats -Name HostsFileLen -MemberType NoteProperty -Value $HostEnum.HostsFile.Length
    Add-Member -InputObject $HostEnum.stats -Name TCPConsCount -MemberType NoteProperty -Value $HostEnum.TCPConns.count
    Add-Member -InputObject $HostEnum.stats -Name HotFixCount -MemberType NoteProperty -Value $HostEnum.HotFixes.count
    Add-Member -InputObject $HostEnum.stats -Name SoftwareCount -MemberType NoteProperty -Value $HostEnum.Software.count

    $HostEnum 
}


#######################################
        #End Of Variable Block
#######################################


100..120 | foreach { 
    
    $up = ping.exe -n 1 -w 1000 "$NodeNet.$_" | select-string "TTL" 
    $ttl = (( $up -split '=')[-1]) -as [int]
    if($ttl -gt 64 -And $ttl -lt 129){$TargetHosts_a += "$NodeNet.$_"}
}
if(($TargetHosts_a.Count - 14) -lt 8 ){ Write-Host "`nNumber of responding clients is lower than expected...`n"
    $TargetHosts_a 
    write-host "`n`nPlease confirm list of hosts and check script (CTRL+C to quit)"}


Write-host "Enumerating hosts.... please wait. `n`nSome errors are expected - no need to panic.`n"
[System.Array]$results = @()
$results = Invoke-Command -ScriptBlock $EnumScriptBlock -ComputerName $TargetHosts_a -Credential $creds_a 
$results += Invoke-Command -ScriptBlock $EnumScriptBlock -ComputerName $TargetHosts_adds -Credential $creds_adds
$results = $results | Sort-Object -Property hostname

if (!(Test-Path $ReportLoc)){
    New-Item -ItemType Directory -Path $ReportLoc 
    }  
Set-Location -Path $ReportLoc


if(Test-Path -Path ".\_Current"){
    Write-Host "_Current folder already exists! Please back up any contents you want to keep prior to deletion and press [ENTER]" -ForegroundColor Red -BackgroundColor Black
    read-host
    Remove-Item -Path ".\_Current" -Recurse -Force}
New-Item -ItemType Directory -Name "_Current"
if(!(Test-Path -Path ".\_Summaries")){New-Item -ItemType Directory -Name "_Summaries"}

foreach($out in $results){ 
    $path = ".\_Current\{0}_{1}-Enum.json" -f ($out.RunTime | Get-Date -UFormat "%Y-%m-%d %H%M"), $out.HostName 
    $out | select * -ExcludeProperty Value | ConvertTo-Json | Out-File $path -Force 
}



# any install/creation date in past 12 hours? SchedTasks, Services, ProcessList, etc
$NewItems = $null
$NewAlerts = @()
$NewItems = foreach ($new in $results){
    $new.hostname
    Write-Output "============================="
    Write-Output "`nPossible newly created items on`n"
    # TODO: check local systime is same timezone as target
    $new.processlist | where { ($_.CreationDate -ge ((get-date).AddHours(-14))) } | select * -ExcludeProperty Modules
    $new.stats.prefetch | where {$_.LastWriteTime -ge ((get-date).AddHours(-14))}
    
    #should be empty
    $A = $null 
    $A += $new.services | where {$_.installdate -ge ((get-date).AddHours(-14))}
    $A += $new.ScheduledTasks | where {$_.date -ge ((get-date).Adddays(-1)) } 
    $A += $new.software | where { ($_.InstallDate2 -ne $null) -and ($_.InstallDate2 -ne $null -ge (get-date).AddHours(-14)) }  
    $A += $new.hotfixes | where { $_.installedon -ge (get-date).AddDays(-1) }
    $A
    if($A){$NewAlerts += ("Possible service, task or software entry of interest for {0}`n" -f $new.hostname) }
}
$NewItems += "`n============================== EOF"
$NewItems | out-file -filepath (".\_Summaries\{0}_NewItems_Summary.txt" -f ((Get-Item ".\_Current").CreationTime | Get-Date -UFormat "%Y-%m-%d %H%M"))

# Alert on new interesting entries - not interested  in process creation alerting
if($NewAlerts){ Write-Host -BackgroundColor Black -ForegroundColor Red $NewAlerts}


if (Get-ChildItem *.tmp){ $prev = ".\_Summaries\{0}_Stats_Summary.csv" -f (Get-ChildItem *.tmp).name.Split('.')[0]
    Import-Csv -Path $prev | Out-GridView -Title $prev

}
$results.stats |select * -ExcludeProperty Value,Length | ConvertTo-Csv |  out-file -filepath (".\_Summaries\{0}_Stats_Summary.csv" -f ((Get-Item ".\_Current").CreationTime | Get-Date -UFormat "%Y-%m-%d %H%M"))
$results.stats | select * -ExcludeProperty Value,Length | Out-GridView



# clean up creds variables so passwords cannot be retrieved easily
Remove-Variable creds_a,creds_adds

# create tmp with date of this run
Get-ChildItem *.tmp | Remove-Item -Force
New-Item -ItemType File -Name ("{0}.tmp" -f ((Get-Item ".\_Current").CreationTime | Get-Date -UFormat "%Y-%m-%d %H%M"))
# rename _Current
$folder = "{0}_Reports" -f ((Get-Item ".\_Current").CreationTime | Get-Date -UFormat "%Y-%m-%d %H%M") ; Rename-Item -Path ".\_Current" -NewName $folder

Read-host "Enumeration complete! - please review statistics and individual reports (open with notepad++) and press [ENTER] to finish"

