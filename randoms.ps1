#gets list of files and looks for them
$temp = (Get-Content 'C:\Users\DCI Student\Desktop\ioc files.txt').Trim()
$files = $temp | foreach {$_.split('\')[-1]}
Get-ChildItem -path C:\ -Recurse -ErrorAction SilentlyContinue -Include $files

#creates wireshark filter with frame contains and uses list of data
$temp = get-content .\apturls.txt
$filter = $temp | foreach {echo "frame matches"$_ "or"} 
$filter=[system.string]::join(" ",$filter)

# better version of above
gc apturls.txt | % {"frame matches `"$_`" || "} | out-file -NoNewline -filepath "frame.txt"

#alternate data stream stuff
Get-ChildItem -Path .\IdentifyDataExfil_ADS -Recurse | ForEach-Object { Get-Item $_.FullName -Stream *} |
  Where-Object Stream -ne ':$Data' |select filename,stream | 
  ForEach-Object {get-content -Raw $_.filename -Stream $_.stream |Set-Content -Path (($_.filename).tostring()).split('\')[-1]} 
Get-ChildItem -Path .\IdentifyDataExfil_ADS -Recurse |
  ForEach-Object { Get-Item $_.FullName -Stream *} |
  select filename,stream,@{label="DATA";expression={get-content -raw $_.filename -Stream $_.stream}} |
  Where-Object { $_.filename -like "*.txt" -and (($_.DATA).substring(0,4) -eq "Rar!" -or ($_.DATA).substring(0,2) -ceq "PK")} 

