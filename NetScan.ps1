
function Invoke-NetScan { 
  <# 
    .SYNOPSIS 
    Scan IP-Addresses, Ports and HostNames 
 
    .DESCRIPTION 
    Scan for IP-Addresses, HostNames and open Ports in your Network. 
     
    .PARAMETER StartAddress 
    StartAddress Range 
 
    .PARAMETER EndAddress 
    EndAddress Range 
 
    .PARAMETER Network
    Specify Network using CIDR notation
    
    .PARAMETER ResolveHost 
    Resolve HostName 
 
    .PARAMETER ScanPort 
    Perform a PortScan 
 
    .PARAMETER TPorts 
    Ports That should be scanned, default values are: 21,22,23,53,69,71,80,98,110,139,111, 
    389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389, 
    5801,5900,5555,5901 
 
    .PARAMETER UPorts
    UDP ports that should be scanned, default values are: 17,37,49,53,67,68,69,88,123,161

    .PARAMETER TimeOut 
    Time (in MilliSeconds) before TimeOut, Default set to 100 
 
    .EXAMPLE 
    Invoke-NetScan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 


    .NOTES 
    Goude 2012, TrueSec 
  #> 
  Param( 
     
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)")] 
    [net.ipaddress]$StartAddress = $null, 
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)")] 
    [net.ipaddress]$EndAddress =$null, 
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)")] 
    [string]$Network = $null,
#    [switch]$ScanTCP,
#    [switch]$ScanUDP, 
#    [int[]]$TPorts = @(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901), 
#    [int[]]$UPorts = @(17,37,49,53,67,68,69,88,123,161),
    [int]$TimeOut = 300 
  ) 
  Begin { 
    function IP-toINT64 () { 
        param ($ip) 
        $octets = $ip.split(".") 
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
    } 
 
    function INT64-toIP() { 
        param ([int64]$int) 
        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    } 
    
   
    $ping = New-Object System.Net.Networkinformation.Ping
    [System.Collections.ArrayList]$IPList = @()
    $Report = New-Object -TypeName psobject
    
  } 
  Process { 
  #if network with CIDR was passed
    if ($Network -ne $null)
    {
        $cidr = [convert]::ToInt32($Network.Split("/")[1]) 
        $IP = [net.ipaddress] $Network.Split("/")[0]
        $maskaddr = [net.ipaddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
        $net = new-object net.ipaddress ($maskaddr.address -band $ip.address)
        # $maskaddr = [Net.IPAddress]::Parse($mask)
        # maybe could do a thing the lets users put cidr or subnet mask
        $broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $net.address))
        [INT64]$startaddress = IP-toINT64 -ip $net.ipaddresstostring 
        
        [INT64]$endaddress = IP-toINT64 -ip $broadcastaddr.ipaddresstostring

        for ($i = $startaddress; $i -le $endaddress; $i++) 
        { 
            $IPList += INT64-toIP -int $i
             
        }
        #remove network and broadcast from list
        $IPList.Remove($net.ToString())
        $IPList.Remove($broadcastaddr.ToString())
    }
    #if start and end address were passed
    elseif($StartAddress -ne $null -and $EndAddress -ne $null){
        for ($i = $startaddress; $i -le $endaddress; $i++) { 
            $IPList += INT64-toIP -int $i
             
        }
    }
    else{
        Write-Host "Input error! Please input a CIDR network or BOTH start and end IP address"
        exit
    }
    #stuff
    workflow ParallelSweep ([System.Collections.ArrayList]$IPList) { foreach -parallel -throttlelimit 10 ($i in $IPList) {ping -n 1 -w 100 $i}} 
    ParallelSweep -IPList $IPList | Select-String ttl
  }
    
  End { 
  } 
}


