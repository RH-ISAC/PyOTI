<#
.SYNOPSIS
  Update PyOTI API Keys
.DESCRIPTION
  This PowerShell script is meant to be run from the root directory of PyOTI.
  It will check the diff between .\examples\keys.py.sample and .\examples\keys.py and
  append any API key variables that are new.
  Please make sure to update .\examples\keys.py with API secrets after running.
.OUTPUTS
  Appends new API key variables in .\examples\keys.py and sets them to '' (empty).
.NOTES
  Version:        1.0
  Author:         JJ Josing
  Creation Date:  02/23/2021
  Purpose/Change: Initial script development

.EXAMPLE
  powershell .\update_keys.ps1
#>

function Check-NewLine{
    $content = [IO.File]::ReadAllText('.\examples\keys.py')
    ($content -match '(?<=\r\n)\z')
}


$sample_file = '.\examples\keys.py.sample'
$keys_file = '.\examples\keys.py'

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
        Add-Content -Path ".\examples\keys.py" -Value ""
    }
    $compare | ForEach-Object{
        if ($_.SideIndicator -eq "=>")
        {
            Write-Host -ForegroundColor Green "[!] Adding to .\examples\keys.py!"
            Add-Content -Path ".\examples\keys.py" -Value $_.InputObject -NoNewline
            Add-Content -Path ".\examples\keys.py" -Value "= ''"
            Write-Host -ForegroundColor Green "[+] $($_.InputObject) added to .\examples\keys.py!"
        }
    }
    Write-Host -ForegroundColor Yellow "[*] Add API secrets to .\examples\keys.py!"
}
