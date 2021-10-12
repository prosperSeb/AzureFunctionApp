#Variables

$subId      = "866f04ec-2840-49ed-891d-1f802ebf4c5c" 
$tenantId   = "24139d14-c62c-4c47-8bdd-ce71ea1d50cf" #engie.onmicrosoft.com
$rightsCSV  = "C:\Engie-Git\Script-Repo\AccesRBAC.csv"

$staName = "kpizaurerawdata"
$staRG = "kpi-azure-rawdata"
$containterRoot = "csv-output" #non compliant
$containterRoot2 = "csv-output2"

#Connection 
Connect-AzAccount -SubscriptionId $subId -TenantId $tenantId -identity

$staCtx = New-AzStorageContext -StorageAccountName $staName -UseConnectedAccount

Write-Progress "Listing blob"
### List all blob NonCompliant
$blobFiles = Get-AzStorageBlob -Container $containterRoot -Context $staCtx
Write-Output $($blobFiles.count)

### List all blob Detailled
$blobFiles2 = Get-AzStorageBlob -Container $containterRoot2 -Context $staCtx
Write-Output $($blobFiles2.count)

start-sleep 20

Write-Progress "Container creation"
### Container organization
$containerList = @()
foreach ($blob in $blobFiles2) {
    Write-Progress ($blob.Name).Substring(0,36)
    $containerList += ($blob.Name).Substring(0,36)
}



write-output "Start container creation"
$date = get-date
write-output $date
$i = 0
foreach ($container in $containerList) {
    
    # Create container
    try {
        If (!(Get-AzStorageContainer -Name $container -Context $staCtx -ErrorAction SilentlyContinue)) {
            $newContainer = New-AzStorageContainer -Name $container -Permission Off -Context $staCtx
            Write-Output "New container $container"
        } else {
            Write-Output "Existing container $container"
        }
    }
    catch {
        Write-Warning "error container $($container)"
    }
    $i++
    
}

write-output "Container done"
write-output $i
$date = get-date
write-output $date


### Copy to blob #Non Compliant

foreach ($blob in $blobFiles) {

    #Download local
    $localBlob = Get-AzStorageBlobContent -Container $containterRoot -Blob $blob.Name -Destination $env:TEMP -Context $staCtx -Force 

    $localCSV = $env:TEMP + "\" + $localBlob.name
    $targetContainer = ($blob.Name).Substring(0,36)
    $dateFolder = get-date -format yyyy-MM-dd
    $targetBlobName = "NonCompliant/" + $dateFolder + "/"  +  $blob.name

    #Upload CSV to right container
    Set-AzStorageBlobContent -File $localCSV `
    -Container $targetContainer `
    -Blob $targetBlobName `
    -Force `
    -Context $staCtx 

    #remove temp local file
    remove-item -Path $localCSV -Force
}

write-output "Copy blob done"
$date = get-date
write-output $date


### Copy to blob detailled

foreach ($blob in $blobFiles2) {

    #Download local
    $localBlob = Get-AzStorageBlobContent -Container $containterRoot2 -Blob $blob.Name -Destination $env:TEMP -Context $staCtx -Force 

    $localCSV = $env:TEMP + "\" + $localBlob.name
    $targetContainer = ($blob.Name).Substring(0,36)
    $dateFolder = get-date -format yyyy-MM-dd
    $targetBlobName = "Detailled/" + $dateFolder + "/"  +  $blob.name

    #Upload CSV to right container
    Set-AzStorageBlobContent -File $localCSV `
    -Container $targetContainer `
    -Blob $targetBlobName `
    -Force `
    -Context $staCtx 

    #remove temp local file
    remove-item -Path $localCSV -Force
}

write-output "Copy blob 2 done"
$date = get-date
write-output $date


### Apply rights

<#
$rightsCSV = import-csv -Path $rightsCSV -Delimiter ";" -Encoding utf8

foreach ($right in $rightsCSV) {
    
    $scopeContainer = "/subscriptions/" + $subId + "/resourcegroups/" + $staRG + "/providers/Microsoft.Storage/storageAccounts/" + $staName + "/blobServices/default/containers/" + $($right.subscriptionId)
    
    New-AzRoleAssignment -RoleDefinitionName "Storage Blob Data Reader" `
    -Scope $scopeContainer `
    -ObjectId $($right.ObjectId)

}


write-output "Apply Right on container done"
$date = get-date
write-output $date


$uniquerights = $rightsCSV | select -Unique ObjectId
foreach ($unique in $uniquerights) {

    $scopeSta = "/subscriptions/" + $subId + "/resourceGroups/" + $staRG +"/providers/Microsoft.Storage/storageAccounts/" + $staName

    New-AzRoleAssignment -RoleDefinitionName "Reader" `
    -Scope $scopeSta `
    -ObjectId $($unique.ObjectId)
    
}



write-output "Apply Right on storage account done"
$date = get-date
write-output $date
#>