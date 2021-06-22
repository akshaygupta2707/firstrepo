##########Menu to choose available template########
function Show-Menu
{
    param (
        [string]$Title = 'My Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
    Write-Host "1: Press '1' for Windows_2008R2_EE_x64_FR"
    Write-Host "2: Press '2' for Windows_2008R2_EE_x64_US"
    Write-Host "3: Press '3' for Windows_2008R2_SE_x64_FR"
    Write-Host "Q: Press 'Q' to quit."
}

    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
        '1' {
            'You chose option #1'
        } '2' {
            New-CIVM -VApp $VappName -VMTemplate $selection -Name TestAuto -ComputerName TestAuto
        } '3' {
            'You chose option #3'
        }
    }
    pause
