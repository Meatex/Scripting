$domain = Get-Content .\iocdomains.txt
$x = 1000000
foreach($i in $domain){
    $c = $i.split(".",[System.StringSplitOptions]::RemoveEmptyEntries)
    $c = $c -join '"; content: "'
    $cmd1 = "alert udp any any -> any any (msg: `"IOC Bad DNS request detected for domain $i !`"; content: `"$c`"; sid: $x;)"
    $x = $x+1
    echo $cmd1 >> .\local.rules.txt
}
