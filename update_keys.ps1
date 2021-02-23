<#
.SYNOPSIS
  Update PyOTI API Keys
.DESCRIPTION
  This PowerShell script is meant to be run from the root directory of PyOTI.
  It will check the diff between .\pyoti\keys.py.sample and .\pyoti\keys.py and
  append any API key variables that are new.
  Please make sure to update .\pyoti\keys.py with API secrets after running.
.OUTPUTS
  Appends new API key variables in .\pyoti\keys.py and sets them to '' (empty).
.NOTES
  Version:        1.0
  Author:         JJ Josing
  Creation Date:  02/23/2021
  Purpose/Change: Initial script development

.EXAMPLE
  powershell .\update_keys.ps1
#>

function Check-NewLine{
    $content = [IO.File]::ReadAllText('.\pyoti\keys.py')
    ($content -match '(?<=\r\n)\z')
}


$sample_file = '.\pyoti\keys.py.sample'
$keys_file = '.\pyoti\keys.py'

$sample_variables = Get-Content $sample_file | ForEach-Object{$_.split("=")[0]}
$keys_variables = Get-Content $keys_file | ForEach-Object{$_.split("=")[0]}

$compare = Compare-Object -ReferenceObject $keys_variables -DifferenceObject $sample_variables
$count = $compare | Measure-Object

if($count.Count -eq '0'){
    Write-Host -ForegroundColor Green "[*] No keys need to be updated!"
} else
{
    Write-Host -ForegroundColor Green "[!] New keys found!"
    $newline = Check-NewLine
    if ($newline -eq $false ){
        Add-Content -Path ".\pyoti\keys.py" -Value ""
    }
    $compare | ForEach-Object{
        if ($_.SideIndicator -eq "=>")
        {
            Write-Host -ForegroundColor Green "[!] Adding to .\pyoti\keys.py!"
            Add-Content -Path ".\pyoti\keys.py" -Value $_.InputObject -NoNewline
            Add-Content -Path ".\pyoti\keys.py" -Value "= ''"
            Write-Host -ForegroundColor Green "[+] $($_.InputObject) added to .\pyoti\keys.py!"
        }
    }
    Write-Host -ForegroundColor Yellow "[*] Add API secrets to .\pyoti\keys.py!"
}
