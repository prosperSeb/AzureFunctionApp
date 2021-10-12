## Switch context to Build Account

Write-Progress "Switch to Build Account"
$myCred = Get-AutomationPSCredential -Name 'BuildAccount'
$userName = $myCred.UserName
$password = $myCred.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force

$myPsCred = New-Object System.Management.Automation.PSCredential ($userName,$password)
try {
    Write-Progress "Connection as Build"
    Connect-AzAccount -Credential $myPsCred | Out-Null
    $context = Get-AzContext
    Write-Verbose $context | Format-List *
    Write-Progress "Connected as Build" 
}
catch {
    Write-Error "Problem connexion"
}    


function Get-AzCachedAccessToken()
{
    $ErrorActionPreference = 'Stop'
  
    if(-not (Get-Module Az.Accounts)) {
        Import-Module Az.Accounts
    }
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azProfile.Accounts.Count) {
        Write-Error "Ensure you have logged in before calling this function."    
    }
  
    $currentAzureContext = Get-AzContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Tenant.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    $token.AccessToken
}

function Get-AzBearerToken()
{
    $ErrorActionPreference = 'Stop'
    ('Bearer {0}' -f (Get-AzCachedAccessToken))
}

$token = Get-AzBearerToken

$connectionInfo = @()
       
$Obj = New-Object -TypeName psobject 
$Obj | Add-Member -MemberType NoteProperty -Name token  -Value $token
$connectionInfo += $Obj


#export for logic app
$connectionInfo = $connectionInfo | ConvertTo-Json
Write-Output $connectionInfo

Write-Progress "Job done"