# Simple boy to turn text file with format of hash newline filepath into CSV

$base = (get-content .\System32baseline.txt).Split("`r")
$x=0
echo '"Hash", "Path"' > base.csv
while ($x -le $base.count)
{
    [string]$temp = $base[$x] + ", " + $base[$x+1]
    echo $temp >> base.csv
    Write-Progress -Activity "Creating CSV..." -PercentComplete ($x/$base.count*100)
    $x = $x +2
}

