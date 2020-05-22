<#
.SYNOPSIS
Compare two csv files and returns an array of differences.
.DESCRIPTION
The Compare-CSV function computes differences between two a baseline and target CSV. 
Returns entries that differ in the target CSV based on user specified field with however many fields are in the target CSV.
As long as both CSV contain at least one column in common that can be used as a comparison.
.PARAMETER Base 
The baseline CSV to compare to.
.PARAMETER CompTarget 
The CSV file the baseline will be compared to.
.PARAMETER CompareField
The field or Column in each CSV to compare.
.EXAMPLE
Compare-csv -baseline .\baseline.csv -comptarget .\currentlist.csv -compfield "MD5"
#>	

function Compare-CSV 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Baseline,

        [Parameter(Mandatory = $true)]
        [string]$CompTarget,
        
        [parameter(mandatory = $true)]
        [string]$CompField		
	)
	
$Results = @()
$CompArray = @()
[hashtable]$Base = @{}
Import-Csv $Baseline -Delimiter ',' | ForEach-Object {$base[$_.$compfield] = $true}
$Target = import-csv -Path $CompTarget | sort
 
$results += $vm32 | where {-not $my_hash_table.ContainsKey($_.$CompField) }

$Results


<#
shit slow method but keeping for idunno reasons

Get differences from CompTarget CSV only
$CompArray = Compare-Object $Base $Target -Property $CompField | where-object {$_.sideindicator -eq "=>"}
Write-Host "Found" $CompArray.count "differences in $CompTarget"
# match with regex against CompTarget
$i = 0
ForEach ($h in $CompArray.MD5){
    $i += 1
    Write-Progress -activity "Parsing results..." -PercentComplete ($i/$CompArray.count*100) 
    $results += $Target | Where-Object {$h -match $_.md5}
}
$Results


# TotalSeconds      : 261.0195775
#>

# other methods
<#

$vm32 = import-csv .\vm32.csv | sort
$base32 = import-csv .\base32.csv | sort

foreach ($hash in $vm32){
    if ($base32.md5 -notmatch $hash.md5){
        if ($hash.filenames -like "*.exe") {echo $hash.md5 $hash.filenames}
    }
}


TotalSeconds      : 197.8754268

#>
<#

$vm32 | Where-Object {$_.md5 -notin $base32.md5} | Where-Object {$_.filenames -like "*.exe"}


TotalSeconds      : 161.4982009

#>

}
