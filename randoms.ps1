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
