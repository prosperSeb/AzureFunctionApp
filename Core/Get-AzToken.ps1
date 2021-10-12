## Experimental
# Send an Azure token to an Azure function

# Setting
$subId         = "56cc00c5-1664-49d1-b42c-0ac9a9770e56"
$tenantId      = "24139d14-c62c-4c47-8bdd-ce71ea1d50cf"

# Ensure that the runbook does not inherit an AzContext
Disable-AzContextAutosave –Scope Process
$ErrorActionPreference = "Stop"

## Connect to Azure as Automation Account
$connectionName = "AzureRunAsConnection"
try{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Connect-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
    "Logging in to Azure... Done"
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

## Switch context to Discovery Account
try {
    $myCred = Get-AutomationPSCredential -Name 'Discovery'
    $userName = $myCred.UserName
    $password = $myCred.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force

    $myPsCred = New-Object System.Management.Automation.PSCredential ($userName,$password)

    Connect-AzAccount -Credential $myPsCred -Subscription $subId -tenantId $tenantId
    $context = Get-AzContext
    Write-Progress $context | fl *
    Write-Progress "Context changed" 
}
catch {
    write-error "Problem connexion $subId"
}

Write-Progress "Context changed"


# PowerShell

$context = Get-AzContext
$profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.AccessToken
}

$uri = " https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/pricings?api-version=2018-06-01"

$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers $authHeader
$response.value | ConvertTo-Json

Write-Output $token


##### Export #######
$featureName = "token"

    Write-Progress $scanDataStats
    try {
        $tempCsv = "$env:TEMP\data-$featureName-$subId-$tenantId.csv"
        $token | Export-Csv -Path $tempCsv -Encoding utf8 -Delimiter ";"
        $file = Get-ChildItem $env:TEMP
        Write-Progress $file
    }
    catch {
        Write-Progress "error export CSV"
    }


# 3 - Export StorageAccount

#Connexion and get Storage Context

    try {
        Set-AzContext -Subscription "OneCloud Management" | Out-Null
        $Storage_Account_Key = (Get-AzStorageAccountKey -StorageAccountName $azStorageName -ResourceGroupName $azStorageRG).Value[0] 
        $Ctx                 = New-AzStorageContext -StorageAccountName $azStorageName -StorageAccountKey $Storage_Account_Key
    }
    catch {
        Write-Progress "error key storage account"
    }

    # Create container
    try {
        If (!(Get-AzStorageContainer -Name $storageContainerName -Context $Ctx -ErrorAction SilentlyContinue)){
            $NewExportCSVContainer = New-AzStorageContainer -Name $storageContainerName -Permission Off -Context $Ctx
        }
    }
    catch {
        Write-Progress "error container"
    }

    #Copy to blob
    try {
        $ExportCSVBlobPath = "$($FeatureName)Report\$(get-date -Format 'yyyy-MM-dd')"
        Set-AzStorageBlobContent -File $tempCsv -Container $storageContainerName -Blob "$($ExportCSVBlobPath)\$($subId)_$($tenantId)Azure-$($FeatureName).csv" -Context $Ctx -Force 
    }
    catch {
        Write-Progress "error upload sta" 
    }

