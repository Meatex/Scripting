$dir = (cmd /c robocopy C:\ null *.* /l /s /njh /njs /ns /fp /lev:12).trim() | select-string "New File" | where {-not [string]::IsNullOrWhiteSpace($_)} |foreach{$_ -replace "`t","" -replace 'New File  ',''} 
#put hashes in here
[hashtable]$hashes =@{
'e4300cff11cbff4c3542a08de61f584b8e0d9ca9' = 'SHA1'
'4a80c5896e2242c99e289a1fac4b7420a0a6af45' = 'SHA1'
}
foreach ($d in $dir){Get-FileHash -Path $d -Algorithm SHA1 -ErrorAction SilentlyContinue | where {$hashes.ContainsKey($_.hash)}}
