## Param
Param
(
  
  [Parameter (Mandatory= $false)]
  [bool] $all = $false,

  [Parameter (Mandatory= $true)]
  [bool] $testing = $true,

  #Features ordered by alphabetic order
  [Parameter (Mandatory= $false)]
  [bool] $getAppGateway = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getASE = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getAzureStats = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getCosmosDb = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getDataBricks = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getDisk = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getFunction = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getGroupBaseline = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getKeyVault = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getLoadBalancerRules = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getNIC  = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getNSG = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getNSGRules = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getPolicies = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getPostgreSQL = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getPublicIP = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getRBAC = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getRecoveryVault = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getRoute = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getSecuCenter = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getSQLServer = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getSQLServerDatabase = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getStorageAccount = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getSubnet = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getVirtualMachines = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getVnet = $false,

  [Parameter (Mandatory= $false)]
  [bool] $getVpnGatewayS2S = $false,
  
  [Parameter (Mandatory= $false)]
  [bool] $getVpnGatewayP2S = $false,
 
  [Parameter (Mandatory= $false)]
  [bool] $getWebApp = $false   

)

# Master switch
if ($all -eq $true) {  
  $getNIC = $getNSG = $getNSGRules = $getRBAC = $getSecuCenter = $true
  $getStorageAccount = $getSubnet = $getVirtualMachines = $getDataBricks = $true
}

## Fixed settings
$testingSub = Get-AutomationVariable -name "TestSub"
$testingSub = $testingSub.split(";")

$rgAA = Get-AutomationVariable -name "ResourceGroup"

$subManagement  = Get-AutomationVariable -name "RootSubscription"  #SubID for OneCloud Management sub
$tenantID       = Get-AutomationVariable -name "RootTenantId"

## Dynamic Settings
if ($testing -eq $true) {
    $azStorageRG   = Get-AutomationVariable -name "ResourceGroup"
    $azStorageName = Get-AutomationVariable -name "StorageAccount"
} else {
    $azStorageRG   = Get-AutomationVariable -name "ResourceGroup"
    $azStorageName = Get-AutomationVariable -name "StorageAccount"
}

## Script config
Disable-AzContextAutosave –Scope Process
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

Write-Progress "Start Launcher"

#Connection to Automation
Connect-AzureAutomation
Set-AzContext -subscriptionId $subManagement

## Switch context to Discovery Account
Write-Progress "Switch to Discovery Account"
$myCred = Get-AutomationPSCredential -Name 'Discovery'
$userName = $myCred.UserName
$password = $myCred.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force

$myPsCred = New-Object System.Management.Automation.PSCredential ($userName,$password)
try {
    Write-Progress "Connection as Discovery"
    Connect-AzAccount -Credential $myPsCred -Subscription $subManagement -tenantId $tenantId
    $context = Get-AzContext
    Write-Verbose $context | Format-List *
    Write-Progress "Connected as Discovery" 
}
catch {
    Write-Error "Problem connexion $subManagement"
}

### Action as Discovery Account

## Get subscriptionFeature to check

if ($testing -eq $true) {
    $subscriptionToScan = Get-AzSubscription | Where-Object {($_.State -eq "Enabled") -and ($_.SubscriptionId -in $testingSub)}
} else {

    # Bug fix to avoid double scan for LightHouse

    # Get all enabled subscriptions with duplicates due to Lighthouse enrollment
    $AllSubscriptions = Get-AzSubscription | Where-Object {$_.State -eq "Enabled"-and $_.SubscriptionId -ne '5673c03b-4b28-4de6-94b9-14e790eae95a'}

    # Remove duplicates by selecting unique SubscriptionId
    $RemoveDuplicatesSubscriptions = $AllSubscriptions | select-object SubscriptionId -Unique

    # Compare to show duplicates subscriptions due to Lighthouse enrollment
    $DuplicatesSubscriptions = (Compare-object $RemoveDuplicatesSubscriptions.SubscriptionId $AllSubscriptions.SubscriptionId).InputObject

    # Create a new sys object array (no fixed size)
    [System.Collections.ArrayList]$subscriptionToScan = $AllSubscriptions

    # Modify array to delete bad subscriptions
    Foreach ($SubId in $DuplicatesSubscriptions)
    {
        $BadSubscriptionsInfos = $subscriptionToScan | Where-Object {($_.SubscriptionId -eq $SubId) -and ($_.TenantId -ne $_.HomeTenantId)}
        Foreach ($BadSub in $BadSubscriptionsInfos)
        {
                $subscriptionToScan.Remove($BadSub)
        }
    }

    $subscriptionToScanLightHouse = Get-AzSubscription | Where-Object {$_.State -eq "Enabled"-and $_.SubscriptionId -ne '5673c03b-4b28-4de6-94b9-14e790eae95a'}

}

## Start scan
Write-Output ($subscriptionToScan).Count
Write-Output ($subscriptionToScanLightHouse).Count

$aaList = (Get-AutomationVariable -name "AAList").split(";")

## Function Start Job
function Start-DiscoverFeature {
    [Parameter (Mandatory = $true)]
    [string] $runbookName,
    [Parameter (Mandatory = $true)]
    $params

    try {
        Write-Progress "Start Runbook $runbookName on $($params.subId)"
        $idRandomAA = Get-Random -Minimum 0 -Maximum (($aaList.count))
        $targetAA = $aaList[$idRandomAA]
        Write-Output $targetAA
        
        Start-AzAutomationRunbook   -AutomationAccountName $targetAA `
                                    -ResourceGroupName $rgAA `
                                    -Name $runbookName `
                                    -Parameters $params         
    }
    catch {
        #throw $error
        Write-Warning "Unable to run $runbookName on $($params.subId)"
    }

}

## End Function

Write-Progress "Launch Scan"

$jobList = 0

foreach ($sub in $subscriptionToScan) {
   
    $params = @{"subId"="$($sub.Id)";"tenantId"="$($sub.TenantId)";"azStorageRG"="$azStorageRG";"azStorageName"="$azStorageName"}

    if ($getAppGateway){
        $runbookName = "Scan-AppGateway"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getAzureStats){
        $runbookName = "Scan-AzureStats"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getCosmosDb){
        $runbookName = "Scan-CosmosDB"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getDataBricks){
        $runbookName = "Scan-DataBricks"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getDisk){
        $runbookName = "Scan-Disk"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getFunction){
        $runbookName = "Scan-Function"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getKeyVault){
        $runbookName = "Scan-KeyVault"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getLoadBalancerRules){
        $runbookName = "Scan-LoadBalancerRules"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getNIC){
        $runbookName = "Scan-NetworkInterfaces"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getNSG){
        $runbookName = "Scan-NSG"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getNSGRules){
        $runbookName = "Scan-NSGRules"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getPolicies){
        $runbookName = "Scan-Policies"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getPostgreSQL){
        $runbookName = "Scan-PostgreSQL"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getPublicIP){
        $runbookName = "Scan-PublicIP"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    #if ($getRBAC){
    #    $runbookName = "Scan-RBAC"
    #    Start-DiscoverFeature -runbookName $runbookName -params $params
    #}

    if ($getRecoveryVault){
        $runbookName = "Scan-RecoveryVault"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getRoute){
        $runbookName = "Scan-Route"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getSecuCenter){
        $runbookName = "Scan-SecuCenter"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getSQLServer){
        $runbookName = "Scan-SQLServer"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getSQLServerDatabase){
        $runbookName = "Scan-SQLServerDatabase"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getStorageAccount){
        $runbookName = "Scan-StorageAccount"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getSubnet){
        $runbookName = "Scan-Subnet"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }
 
    if ($getVirtualMachines){
        $runbookName = "Scan-VirtualMachines"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getVnet){
        $runbookName = "Scan-VirtualNetwork"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getVpnGatewayS2S){
        $runbookName = "Scan-VpnGateway"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getVpnGatewayP2S){
        $runbookName = "Scan-VpnGatewayP2S"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    if ($getWebApp){
        $runbookName = "Scan-WebApp"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }  
    
     if ($getASE){
        $runbookName = "Scan-ASE"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }   

    if ($getGroupBaseline){
        $runbookName = "Scan-GroupBaseline"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    Start-Sleep -Seconds 2

}

foreach ($sub in $subscriptionToScanLightHouse) {

    $params = @{"subId"="$($sub.Id)";"tenantId"="$($sub.TenantId)";"azStorageRG"="$azStorageRG";"azStorageName"="$azStorageName"}

    if ($getRBAC){
        $runbookName = "Scan-RBAC"
        Start-DiscoverFeature -runbookName $runbookName -params $params
    }

    Start-Sleep -Seconds 2
    
}