#supress red text that isn't affecting functionality
$ErrorActionPreference= 'silentlycontinue'
#set paths and PIDS
$img = "E:\Images\Memory\SC-WKS01-Snapshot1.vmsn"
$out = "U:\Memory"

#set things up
Write-Host "Getting suggested profile for specified image... Please wait...`n"
$profile = volatility -f $img imageinfo | select-string suggested 
$profile = $profile.ToString().Split(' ')[-1] # edit this index if there is wierd output
$vol = "volatility -f " + $img + " --profile=" + $profile + " "
[System.Collections.ArrayList]$cmds = @("pslist", "pstree", "psscan", "psxview", "netscan", "malfind", "envars")
[System.Collections.ArrayList]$pidscmds = @("dlllist", "getsids")

#if PIDs are set script will run those commands, otherwise it will run the normal commands and spit out txt files
if ($pids.length -eq 0)
{
    foreach ($c in $cmds)
    {
       write-host "Running $c now...`n"
       Invoke-Expression "$vol$c > $out\$c.txt"
    }
}
else
{
    foreach ($c in $pidscmds)
    {
        write-host "Running $c now...`n"
        Invoke-Expression "$vol$c -p $pids > $out\$c.txt"
    }
    write-host "Running procdump on $pids now...`n"
    Invoke-Expression "$vol procdump -p $pids -D U:\FilesOfInterest\"
    Get-ChildItem -Path "U:\FilesOfInterest\" | Get-FileHash -Algorithm MD5 | Out-File procdumpsMD5.txt
}

$yara = Read-Host -Prompt "`nWhat would you like to yarascan for?: "
if ($yara -eq $null)
{
    exit
}
Write-Host "`nThis may take some time...`n"
Invoke-expression "$vol yarascan --yara-rules=$yara > $out\yara$yara.txt"
