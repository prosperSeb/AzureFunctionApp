## Must be run connected with PAA
#Connect-AzAccount -UseDeviceAuthentication

#Param
$subid  = "4f975edb-da7f-4245-84a3-c1c97b8b9ef3"
$aaRG   = "Discovery-v2.3-Fix"

Set-AzContext -Subscription $subid

$scriptPath = @("./Core")

$aaList = @()
$aaList = Get-AzAutomationAccount -ResourceGroupName $aaRG

foreach ($aa in $aaList){
    foreach ($s in $scriptPath){

    $psScript = Get-ChildItem -path $s *.ps1
    
    foreach ($ps in $psScript) {
        Import-AzAutomationRunbook -AutomationAccountName $aa `
                            -ResourceGroupName $aaRG `
                            -Name $(($ps.name).TrimEnd('.ps1')) `
                            -Path $ps.FullName `
                            -Published `
                            -Type PowerShell `
                            -LogProgress $true `
                            -Force
    }   

    }
}



