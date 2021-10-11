## Must be run connected with PAA
#Connect-AzAccount -UseDeviceAuthentication

#Param
$subid  = "56cc00c5-1664-49d1-b42c-0ac9a9770e56"
$aaName = "AA-Discovery"
$aaRG   = "Discovery-v2"

Set-AzContext -Subscription $subid

$scriptPath = @("C:\Engie-Git\Discovery-v2\Core","C:\Engie-Git\Discovery-v2\Feature")

foreach ($s in $scriptPath){

    $psScript = Get-ChildItem -path $s *.ps1
    
    foreach ($ps in $psScript) {
        Import-AzAutomationRunbook -AutomationAccountName $aaName `
                            -ResourceGroupName $aaRG `
                            -Name $(($ps.name).TrimEnd('.ps1')) `
                            -Path $ps.FullName `
                            -Published `
                            -Type PowerShell `
                            -LogProgress $true `
                            -Force
    }   

}

