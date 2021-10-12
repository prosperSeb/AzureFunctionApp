import operator
import numpy as np
import pandas as pd
import datetime
import operator
import sys

#--------------------------------------Variables definition----------------------------------------------------------------------------
_AUTOMATION_RESOURCE_GROUP = "KPI_Engie"
_AUTOMATION_ACCOUNT = "PythonKPI"
_RUNBOOK_NAME = "Shared"
_RUNBOOK_TYPE = ".py"

#--------------------------------------import function---------------------------------------------------------------------------------

def download_file(resource_group, automation_account, runbook_name, runbook_type):
    """
    Downloads a runbook from the automation account to the cloud container
    """
    import os
    import sys
    import requests
    import automationassets

    # Return token based on Azure automation Runas connection
    def get_automation_runas_token(runas_connection):
        """ Returns a token that can be used to authenticate against Azure resources """
        from OpenSSL import crypto
        import adal

        # Get the Azure Automation RunAs service principal certificate
        cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
        sp_cert = crypto.load_pkcs12(cert)
        pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, sp_cert.get_privatekey())

        # Get run as connection information for the Azure Automation service principal
        application_id = runas_connection["ApplicationId"]
        thumbprint = runas_connection["CertificateThumbprint"]
        tenant_id = runas_connection["TenantId"]

        # Authenticate with service principal certificate
        resource = "https://management.core.windows.net/"
        authority_url = ("https://login.microsoftonline.com/" + tenant_id)
        context = adal.AuthenticationContext(authority_url)
        azure_credential = context.acquire_token_with_client_certificate(
            resource,
            application_id,
            pem_pkey,
            thumbprint)

        # Return the token
        return azure_credential.get('accessToken')

    # Authenticate to Azure using the Azure Automation RunAs service principal
    automation_runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
    access_token = get_automation_runas_token(automation_runas_connection)

    # Set what resources to act against
    subscription_id = str(automation_runas_connection["SubscriptionId"])

    # Set up URI to create a new automation job
    uri = ("https://management.azure.com/subscriptions/" + subscription_id
           + "/resourceGroups/" + resource_group
           + "/providers/Microsoft.Automation/automationAccounts/" + automation_account
           + "/runbooks/" + runbook_name + "/content?api-version=2015-10-31")


    # Make request to create new automation job
    headers = {"Authorization": 'Bearer ' + access_token}
    result = requests.get(uri, headers=headers)

    runbookfile = os.path.join(sys.path[0], runbook_name) + runbook_type

    with open(runbookfile, "w") as text_file:
        text_file.write(result.text)


download_file(_AUTOMATION_RESOURCE_GROUP, _AUTOMATION_ACCOUNT, _RUNBOOK_NAME, _RUNBOOK_TYPE)


#--------------------------------------import Shared-----------------------------------------------------------------------------------

from Shared import *


#--------------------------------------DoKPIAppGateway.py file from Azure function-----------------------------------------------------

def DoKPIAppGateway(container_client):
    AppGateway = read_csv_from_source(container_client, 'AppGateway')
    
    AppGateway = MergeDataBricks(container_client, AppGateway, 'AppGatewayId')
    AppGateway = MergeException(container_client, AppGateway, 'AppGatewayId')

    Total = TotalFromRaw(AppGateway, 'AppGatewayName', 'AppGateway:Total')
    
    # NonCompliant_Firewall, Exceptions_Firewall = NonCompliant_isnull(AppGateway, 'FirewallMode', False, 'AppGateway', ['SubscriptionId','AppGatewayId', 'AppGatewayName'], 'Firewall', 'Firewall')
    # Firewall = NonCompliant_Firewall.groupby('SubscriptionId')['NonCompliant'].count().reset_index(name='AppGateway:WAFDetectionOnly')

    AppGatewayWAF = AppGateway.loc[~(AppGateway['FirewallMode'].isnull())]
    Total_waf = TotalFromRaw(AppGatewayWAF, 'AppGatewayName', 'AppGateway:Total_waf')

    NonCompliant_Firewall, Exceptions_Firewall = NonCompliant_contains(AppGateway, 'FirewallMode', 'Prevention', True, 'AppGateway', ['SubscriptionId','AppGatewayId', 'AppGatewayName'], 'WAFDectionOnly', 'WAFDectionOnly', natest=True)
    Firewall = KPIFromNonCompliant(NonCompliant_Firewall, 'AppGateway', 'AppGateway:WAFDetectionOnly')

    KPIAppGateway = Total.merge(Total_waf, how='left', on='SubscriptionId').merge(Firewall, how='left', on='SubscriptionId').fillna(0)
    NonCompliant_KPIAppGateway = NonCompliant_Firewall
    Exceptions_KPIAppGateway = Exceptions_Firewall



    return(KPIAppGateway, NonCompliant_KPIAppGateway, Exceptions_KPIAppGateway)


#--------------------------------------DoKPICosmoDB.py file from Azure function--------------------------------------------------------


def DoKPICosmosDB(container_client):
    CosmosDB = read_csv_from_source(container_client, 'CosmosDB')
    
    CosmosDB = MergeDataBricks(container_client, CosmosDB, 'CosmosDBId')
    CosmosDB = MergeException(container_client, CosmosDB, 'CosmosDBId')

    Total = TotalFromRaw(CosmosDB, 'CosmosDBName', 'CosmosDB:Total')

    NonCompliant_Private, Exceptions_Private = NonCompliant_contains(CosmosDB, 'CosmosDBPublicAccess', 'Enabled', False, 'CosmosDB', ['SubscriptionId','CosmosDBId', 'CosmosDBName'], 'Public', 'Public')
    Public = KPIFromNonCompliant(NonCompliant_Private, 'CosmosDB', 'CosmosDB:Public')

    KPICosmosDB = Total.merge(Public, how='left', on='SubscriptionId')
    NonCompliant_KPICosmosDB = NonCompliant_Private#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPICosmosDB = Exceptions_Private#.append(NonCompliant_x, ignore_index=True)

    return(KPICosmosDB, NonCompliant_KPICosmosDB, Exceptions_KPICosmosDB)

#--------------------------------------DoKPIDisk.py file from Azure function-----------------------------------------------------------

def DoKPIDisk(container_client):
    Disk = read_csv_from_source(container_client, 'Disk')

    Disk = MergeDataBricks(container_client, Disk, 'diskId')
    Disk = MergeException(container_client, Disk, 'diskId')

    Total =  TotalFromRaw(Disk, 'diskName', 'Disk:Total')
    NonCompliant_EncryptionAtRest, Exceptions_EncryptionAtRest = NonCompliant_contains(Disk, 'diskEncryption', '.*EncryptionAtRest.*', True, 'Disk', ['SubscriptionId','diskId', 'diskName'], 'EncryptionAtRest', 'EncryptionAtRest')
    Encryption = KPIFromNonCompliant(NonCompliant_EncryptionAtRest, 'Disk', 'Disk:NoEncryptionAtRest')

    KPIDisk = Total.merge(Encryption, how='left', on='SubscriptionId').fillna(0)
    KPIDisk['Disk:EncryptionAtRest'] = KPIDisk['Disk:Total'] - KPIDisk['Disk:NoEncryptionAtRest'] - KPIDisk['DataBricks:Disk:NoEncryptionAtRest']
    NonCompliant_KPIDisk = NonCompliant_EncryptionAtRest#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIDisk = Exceptions_EncryptionAtRest#.append(Exceptions_x, ignore_index=True)
    return(KPIDisk, NonCompliant_KPIDisk, Exceptions_KPIDisk)

#--------------------------------------DoKPIFunction.py file from Azure function-------------------------------------------------------

def DoKPIFunction(container_client):
    Function = read_csv_from_source(container_client, 'Function')

    Function = MergeDataBricks(container_client, Function, 'FunctionId')
    Function = MergeException(container_client, Function, 'FunctionId')

    Total = TotalFromRaw(Function, 'FunctionName', 'Function:Total')

    NonCompliant_HTTPS, Exceptions_HTTPS = NonCompliant_operator(Function, 'HttpsOnly', operator.eq, False, False, 'Function', ['SubscriptionId','FunctionId', 'FunctionName'], 'HTTPS', 'HTTPS')
    HTTPS = KPIFromNonCompliant(NonCompliant_HTTPS, 'Function', 'Function:NoHTTPS')

    Function = Function.fillna({'FunctionTLSVersion': 0.0})
    NonCompliant_TLSVersion, Exceptions_TLSVersion = NonCompliant_operator(Function, 'FunctionTLSVersion', operator.lt, 1.2, False, 'Function', ['SubscriptionId','FunctionId', 'FunctionName'], 'TLSVersion', 'TLSVersion')
    TLSVersion = KPIFromNonCompliant(NonCompliant_TLSVersion, 'Function', 'Function:BadTLSVersion')

    KPIFunction = Total.merge(HTTPS, how='left', on='SubscriptionId').merge(TLSVersion, how='left', on='SubscriptionId')
    NonCompliant_KPIFunction = NonCompliant_HTTPS.append(NonCompliant_TLSVersion, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIFunction = Exceptions_HTTPS.append(Exceptions_TLSVersion, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPIFunction, NonCompliant_KPIFunction, Exceptions_KPIFunction)

#--------------------------------------DoKPILoadBalancer.py file from Azure function---------------------------------------------------

def DoKPILoadBalancer(container_client):
    LBRules = read_csv_from_source(container_client, 'LoadBalancerRules')

    LBRules = MergeDataBricks(container_client, LBRules, 'lbId')

    LB = LBRules.drop_duplicates(subset=['lbId'])[['SubscriptionId','lbId','lbName','lbResourceGroup','lbType', 'DataBricksId']]
    LBRules['SSHRDP'] = LBRules['lbRuleFrontend'].isin([22.0, 3389.0])
    LB_SSHRDP = LBRules.groupby('lbId')['SSHRDP'].apply(lambda x: (x.any())).reset_index(name='SSHRDP')
    LBRules['lbPublicIP'] = ~LBRules['lbPublicIP'].isnull()
    LB_PUBLICIP = LBRules.groupby('lbId')['lbPublicIP'].apply(lambda x: (x.any())).reset_index(name='lbPublicIP')
    LB = LB.merge(LB_SSHRDP, how='left', on='lbId').merge(LB_PUBLICIP, how='left', on='lbId')

    LB = MergeException(container_client, LB, 'lbId') #Rework to take exceptions in rules ?
    LBRules = MergeException(container_client, LBRules, 'lbRuleId')

    Total = TotalFromRaw(LB, 'lbId', 'LoadBalancer:Total')
    NonCompliant_PublicIP, Exceptions_PublicIP = NonCompliant_operator(LB, 'lbPublicIP', operator.eq, True, False, 'LB', ['SubscriptionId','lbId', 'lbName'], 'PublicIP')
    PublicIP = KPIFromNonCompliant(NonCompliant_PublicIP, 'LB', 'LB:PublicIP')
    RuleNb = TotalFromRaw(LBRules, 'lbRuleId', 'LoadBalancerRules:Total')

    LBPublic = LB.loc[(LB['lbPublicIP'] == True)]
    LBRulesPublic = LBRules.loc[(LBRules['lbPublicIP'] == True)]

    NonCompliant_SSHRDP, Exceptions_SSHRDP = NonCompliant_operator(LBPublic, 'SSHRDP', operator.eq, True, False, 'LoadBalancer', ['SubscriptionId','lbId', 'lbName'], 'SSHRDP', 'SSHRDP')
    LBSSHRDP = KPIFromNonCompliant(NonCompliant_SSHRDP, 'LoadBalancer', 'LoadBalancer:SSHRDP')
    
    NonCompliant_SSHRDPRule, Exceptions_SSHRDPRule = NonCompliant_operator(LBRulesPublic, 'SSHRDP', operator.eq, True, False, 'LoadBalancerRule', ['SubscriptionId','lbRuleId', 'lbRuleName'], 'SSHRDP', 'SSHRDP')
    LBRuleSSHRDP = KPIFromNonCompliant(NonCompliant_SSHRDPRule, 'LoadBalancerRule', 'LoadBalancerRules:SSHRDP')

    KPILB = Total.merge(PublicIP, how='left', on='SubscriptionId').merge(RuleNb, how='left', on='SubscriptionId').merge(LBSSHRDP, how='left', on='SubscriptionId').merge(LBRuleSSHRDP, how='left', on='SubscriptionId')
    NonCompliant_KPILB = NonCompliant_SSHRDP.append(NonCompliant_SSHRDPRule, ignore_index=True)
    Exceptions_KPILB = Exceptions_PublicIP.append(Exceptions_SSHRDP, ignore_index=True).append(Exceptions_SSHRDPRule, ignore_index=True)
    return(KPILB, NonCompliant_KPILB, Exceptions_KPILB)

#--------------------------------------DoKPIPINSG.py file from Azure function----------------------------------------------------------

def DoKPINSG(container_client):
    NSGRules = read_csv_from_source(container_client, 'NSGRules')

    NSG = NSGRules.drop_duplicates(subset=['nsgID'])[['SubscriptionId','nsgID','nsgName','nsgRG','nsgLocation']]

    NSGRules = NSGRules.loc[(NSGRules['nsgRuleDirection'] == "Inbound")]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleAccess'] == "Allow")]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleSourceAddress'].str.contains('(^|,)' + r'Internet|\*' + '(,|$)', regex=True, na=False))]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleDestinationAddress'].str.contains('(^|,)' + r'Internet|\*' + '(,|$)', regex=True, na=False))]
    NSGRules['DestinationPort:20'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=20)
    NSGRules['DestinationPort:21'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=21)
    NSGRules['DestinationPort:22'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=22)
    NSGRules['DestinationPort:23'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=23)
    NSGRules['DestinationPort:445'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=445)
    NSGRules['DestinationPort:3389'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=3389)
    NSGRules['DestinationPort:LegacyProtocol'] = NSGRules[['DestinationPort:20', 'DestinationPort:21', 'DestinationPort:22', 'DestinationPort:23', 'DestinationPort:445', 'DestinationPort:3389']].any(axis='columns')

    NSG_LegacyProtocol = NSGRules.groupby('nsgID')['DestinationPort:LegacyProtocol'].apply(lambda x: (x.any())).reset_index(name='LegacyProtocol')
    NSG = NSG.merge(NSG_LegacyProtocol, how='left', on='nsgID')
    NSG = NSG.fillna({'LegacyProtocol': False})

    NSG = MergeDataBricks(container_client, NSG, 'nsgID')
    NSG = MergeException(container_client, NSG, 'nsgID')

    Total = TotalFromRaw(NSG, 'nsgID', 'NetworkSecurityGroup:Total')

    NonCompliant_LegacyProtocol, Exceptions_LegacyProtocol = NonCompliant_operator(NSG, 'LegacyProtocol', operator.eq, True, False, 'NetworkSecurityGroup', ['SubscriptionId','nsgID', 'nsgName'], 'LegacyProtocol', 'LegacyProtocol')
    NSGLegacyProtocol = KPIFromNonCompliant(NonCompliant_LegacyProtocol, 'NetworkSecurityGroup', 'NetworkSecurityGroup:LegacyProtocol')
    
    KPINSG = Total.merge(NSGLegacyProtocol, how='left', on='SubscriptionId')#.merge(LBRuleLegacyProtocol, how='left', on='SubscriptionId')
    NonCompliant_KPINSG = NonCompliant_LegacyProtocol#.append(NonCompliant_LegacyProtocolRule, ignore_index=True)
    Exceptions_KPINSG = Exceptions_LegacyProtocol#.append(Exceptions_LegacyProtocolRule, ignore_index=True)
    return(KPINSG, NonCompliant_KPINSG, Exceptions_KPINSG)

#--------------------------------------DoKPIPostgreSQL.py file from Azure function-----------------------------------------------------

def DoKPIPostgreSQL(container_client):
    PostgreSQL = read_csv_from_source(container_client, 'PostgreSQL')

    PostgreSQL = MergeDataBricks(container_client, PostgreSQL, 'postgreId')
    PostgreSQL = MergeException(container_client, PostgreSQL, 'postgreId')
    
    Total = TotalFromRaw(PostgreSQL, 'postgreName', 'PostgreSQL:Total')

    NonCompliant_TransitEncryption, Exceptions_TransitEncryption = NonCompliant_contains(PostgreSQL, 'postgreSSL', 'Enabled', True, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'EncryptionInTransit', 'EncryptionInTransit', natest=True)
    TransitEncryption = KPIFromNonCompliant(NonCompliant_TransitEncryption, 'PostgreSQL', 'PostgreSQL:NoEncryptionInTransit')

    PostgreSQL['postgreTLSVersion'] = PostgreSQL['postgreTLSVersion'].apply(ExtractTLSVersion)
    
    NonCompliant_TLSVersion, Exceptions_TLSVersion = NonCompliant_operator(PostgreSQL, 'postgreTLSVersion', operator.lt, 1.2, False, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'TLSVersion', 'TLSVersion')
    TLSVersion = KPIFromNonCompliant(NonCompliant_TLSVersion, 'PostgreSQL', 'PostgreSQL:BadTLSVersion')

    NonCompliant_Encryption, Exceptions_Encryption = NonCompliant_contains(PostgreSQL, 'postgreEncryption', 'Enabled', True, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'EncryptionAtRest', 'EncryptionAtRest', natest=True)
    Encryption = KPIFromNonCompliant(NonCompliant_Encryption, 'PostgreSQL', 'PostgreSQL:NoEncryptionAtRest')

    NonCompliant_Public, Exceptions_Public = NonCompliant_contains(PostgreSQL, 'postgrePublicAccess', 'Enabled', False, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'Public', 'Public', natest=True)
    Public = KPIFromNonCompliant(NonCompliant_Public, 'PostgreSQL', 'PostgreSQL:Public')
    
    KPIPostgreSQL = Total.merge(TransitEncryption, how='left', on='SubscriptionId').merge(TLSVersion, how='left', on='SubscriptionId').merge(Encryption, how='left', on='SubscriptionId').merge(Public, how='left', on='SubscriptionId')
    NonCompliant_KPIPostgreSQL = NonCompliant_TransitEncryption.append(NonCompliant_TLSVersion, ignore_index=True).append(NonCompliant_Encryption, ignore_index=True).append(NonCompliant_Public, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIPostgreSQL = Exceptions_TransitEncryption.append(Exceptions_TLSVersion, ignore_index=True).append(Exceptions_Encryption, ignore_index=True).append(Exceptions_Public, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPIPostgreSQL, NonCompliant_KPIPostgreSQL, Exceptions_KPIPostgreSQL)

#--------------------------------------DoKPIRBAC.py file from Azure function-----------------------------------------------------------

def ExtractPA(data):
    if (pd.isnull(data)):
        return
    if ('engie.com' in data):
        return(data[0:6].upper())
    return 

def DoKPIRBAC(container_client):
    RBAC = read_csv_from_source(container_client, 'RBAC')
    Referentiel = read_csv_from_source(container_client, 'Referentiel')
    Certified = read_csv_from_source(container_client, 'Certified')
    AADGroup = read_csv_from_source(container_client, 'AADGroup')
    Referentiel = Referentiel[['SubscriptionId', 'TenantId', 'TenantDisplayName']]
    
    #Exceptions : nos 2 comptes
    #Type; filtrer Group / ServicePrincipal
    #AADGuest : #EXT#@engie.onmicrosoft.com or KO

    AADGroup = AADGroup.drop(columns=['SubscriptionId']).drop_duplicates()
    # RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['ServicePrincipal'])))]
    RBAC_Groups = RBAC.loc[(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC_Groups = RBAC_Groups.merge(AADGroup[['GroupObjectId', 'UserObjectId', 'DisplayName', 'UserPrincipalName']], how='left', left_on='rbacObjectId', right_on='GroupObjectId')
    RBAC_Groups['Source'] = RBAC_Groups['rbacDisplayName']
    RBAC_Groups.drop(columns=['rbacSignInName', 'rbacDisplayName', 'rbacObjectId', 'GroupObjectId'], inplace=True)
    RBAC_Groups.rename(columns={'UserObjectId' : 'rbacObjectId', 'DisplayName' : 'rbacDisplayName', 'UserPrincipalName' : 'rbacSignInName'}, inplace=True)
    RBAC_Groups['rbacObjectType'] = 'User'
    RBAC_Groups['rbacAccountType'] = np.where(RBAC_Groups['rbacSignInName'].str.contains('-A', na=False), "PAA", "PA")
    RBAC = RBAC.append(RBAC_Groups, ignore_index=True)
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['Group', 'ServicePrincipal'])))]
    RBAC = RBAC.merge(Referentiel, how='left', on='SubscriptionId')

    RBAC['rbacId'] = RBAC.apply(lambda row: (('/subscriptions/%s/%s/%s') % (row.SubscriptionId, row.rbacSignInName, row.rbacRoleName)), axis = 1)
    RBAC = MergeException(container_client, RBAC, 'rbacId')
    RBAC.loc[(RBAC['rbacSignInName'].str.contains('|'.join(['YZGL74@engie.com', 'ZMWX70@engie.com', r'YZGL74_engie\.com#EXT#.*', r'ZMWX70_engie\.com#EXT#.*']), case=False, na=False)), 'Exceptions'] = 'PAA-Access:Engie:NotNull:AADGuest:AADGuestOther:CertifiedUser:CertifiedUserSubscription:EXTotal'

    RBAC['PA'] = RBAC['rbacSignInName'].apply(ExtractPA)
    RBAC = RBAC.merge(Certified, how='left', on='PA')

    Total = RBAC.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total')
    TotalUser = RBAC.drop_duplicates(subset=['SubscriptionId', 'rbacSignInName']).groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total-User')
    TotalEXT = RBAC.loc[(RBAC['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))].groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:TotalEXT')
    
    ###KPI TenantId Managed
    # 24139d14-c62c-4c47-8bdd-ce71ea1d50cf (TenantId ENGIE)
    # d3f760fe-d4e9-4891-b0ef-4af359897813 (TenantId ENGIE ?)
    Targets_managed = ['24139d14-c62c-4c47-8bdd-ce71ea1d50cf']#, 'd3f760fe-d4e9-4891-b0ef-4af359897813']
    RBAC_managed = RBAC.loc[(RBAC['TenantId'].isin(Targets_managed))]
    Total_managed = RBAC_managed.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total_managed')

    #|(ADM-.*) removed from regex
    NonCompliant_PAA, Exceptions_PAA = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacId', 'rbacDisplayName'], 'PAA-Access', 'PAA-Access', natest=True)
    NoPAA = KPIFromNonCompliant(NonCompliant_PAA, 'RBAC', 'RBAC:NoPAA', databricks=False)

    s = RBAC_managed.Exceptions.str.len().sort_values().index
    RBAC_managed_USERS = RBAC_managed.reindex(s).reset_index(drop=True).drop_duplicates(subset=['SubscriptionId', 'rbacSignInName'], ignore_index=True)
    NonCompliant_PAA_Users, Exceptions_PAA_Users = NonCompliant_contains(RBAC_managed_USERS, 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'PAA-User', 'PAA-Access', natest=True)
    NoPAA_Users = KPIFromNonCompliant(NonCompliant_PAA_Users, 'RBAC', 'RBAC:NoPAA-User', databricks=False)

    NonCompliant_Engie, Exceptions_Engie = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'.*@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'Engie', 'Engie', natest=True)
    NoEngie = KPIFromNonCompliant(NonCompliant_Engie, 'RBAC', 'RBAC:NoENGIE', databricks=False)

    NonCompliant_AADGuest_managed, Exceptions_AADGuest_managed = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'.*#EXT#.*', False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'AADGuest', 'AADGuest', natest=False)
    BadAADGuest_managed = KPIFromNonCompliant(NonCompliant_AADGuest_managed, 'RBAC', 'RBAC:BadAADGuest', databricks=False)

    
    Powerusers_roles = ['Owner', 'Contributor', 'User Access Administrator']
    RBAC_powerusers = RBAC.loc[(RBAC['rbacRoleName'].isin(Powerusers_roles))]
    RBAC_powerusers = RBAC_powerusers.drop_duplicates(subset=['SubscriptionId', 'PA'])
    Total_powerusers = RBAC_powerusers.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total_powerusers')
    RBAC_powerusers = RBAC_powerusers.fillna({'CertificationLevelAzure': '0'})
    RBAC_powerusers['CertificationLevelAzure'] = pd.to_numeric(RBAC_powerusers['CertificationLevelAzure'].str.replace(',', '.', regex=False))
    NonCompliant_CertifiedUser, Exceptions_CertifiedUser = NonCompliant_operator(RBAC_powerusers, 'CertificationLevelAzure', operator.lt, 0.5, False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'CertifiedUser', 'CertifiedUser')
    NonCompliant_CertifiedUser = NonCompliant_CertifiedUser.drop_duplicates(ignore_index=True)
    NoCertifiedUser = KPIFromNonCompliant(NonCompliant_CertifiedUser, 'RBAC', 'RBAC:NoCertifiedUser', databricks=False)

    RBAC_powerusers = RBAC_powerusers.groupby('SubscriptionId')['CertificationLevelAzure'].sum().reset_index(name='CertificationLevelAggregated')
    RBAC_powerusers = RBAC_powerusers.merge(RBAC[['SubscriptionId']].drop_duplicates(subset=['SubscriptionId']), how='right')
    RBAC_powerusers['rbacSignInName'] = 'CurrentSubscription'
    RBAC_powerusers['rbacDisplayName'] = 'PrivilegedUsers'

    NonCompliant_CertifiedUserSubscription, Exceptions_CertifiedUserSubscription = NonCompliant_operator(RBAC_powerusers, 'CertificationLevelAggregated', operator.lt, 0.5, False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'CertifiedUserSubscription', 'CertifiedUserSubscription')
    NoCertifiedUserSubscription = KPIFromNonCompliant(NonCompliant_CertifiedUserSubscription, 'RBAC', 'RBAC:NoCertifiedUserSubscription', databricks=False)

    NonCompliant_NotNull, Exceptions_NotNull = NonCompliant_isnull(RBAC, 'rbacSignInName', False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'NotNull', 'EXNotNull')
    NULL = KPIFromNonCompliant(NonCompliant_NotNull, 'RBAC', 'RBAC:NULL', databricks=False)

    RBAC_Other = RBAC.loc[~(RBAC['TenantId'].isin(Targets_managed))]
    NonCompliant_AADGuest, Exceptions_AADGuest = NonCompliant_contains(RBAC_Other.loc[(RBAC_Other['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'.*_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'AADGuestOther', 'AADGuestOther', natest=False)
    BadAADGuest = KPIFromNonCompliant(NonCompliant_AADGuest, 'RBAC', 'RBAC:BadAADGuestOther', databricks=False)
    
    NonCompliant_PAAOther, Exceptions_PAAOther = NonCompliant_contains(RBAC_Other.loc[(RBAC_Other['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacId', 'rbacDisplayName'], 'PAA-Access', 'PAA-Access', natest=False)
    NoPAAOther = KPIFromNonCompliant(NonCompliant_PAAOther, 'RBAC', 'RBAC:NoPAA', databricks=False)

    s = RBAC_Other.Exceptions.str.len().sort_values().index
    RBAC_Other_USERS = RBAC_Other.reindex(s).reset_index(drop=True).drop_duplicates(subset=['SubscriptionId', 'rbacSignInName'], ignore_index=True)
    NonCompliant_PAAOther_Users, Exceptions_PAAOther_Users = NonCompliant_contains(RBAC_Other_USERS.loc[(RBAC_Other_USERS['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'PAA-User', 'PAA-Access', natest=False)
    NoPAAOther_Users = KPIFromNonCompliant(NonCompliant_PAAOther_Users, 'RBAC', 'RBAC:NoPAA-User', databricks=False)


    NonCompliant_AADGuest = NonCompliant_AADGuest.append(NonCompliant_AADGuest_managed, ignore_index=True)
    Exceptions_AADGuest = Exceptions_AADGuest.append(Exceptions_AADGuest_managed, ignore_index=True)

    BadAADGuest = BadAADGuest.append(BadAADGuest_managed, ignore_index=True)

    # NonCompliant_PAA = NonCompliant_PAA.append(NonCompliant_PAAOther, ignore_index=True)
    # NonCompliant_PAA['NonCompliant'] = 'PAA-Access'
    # NonCompliant_PAA_Users = NonCompliant_PAA.drop_duplicates(ignore_index=True)
    # NonCompliant_PAA_Users['NonCompliant'] = 'PAA-User'
    # NoPAA_Users = NonCompliant_PAA_Users.groupby('SubscriptionId')['NonCompliant'].count().reset_index(name='RBAC:NoPAA-User')
    NonCompliant_PAA = NonCompliant_PAA.append(NonCompliant_PAA_Users, ignore_index=True).append(NonCompliant_PAAOther, ignore_index=True).append(NonCompliant_PAAOther_Users, ignore_index=True)

    Exceptions_PAA = Exceptions_PAA.append(Exceptions_PAA_Users, ignore_index=True).append(Exceptions_PAAOther, ignore_index=True).append(Exceptions_PAAOther_Users, ignore_index=True)

    NoPAA = NoPAA.append(NoPAAOther, ignore_index=True)
    NoPAA_Users = NoPAA_Users.append(NoPAAOther_Users, ignore_index=True)


    ServicePrincipal = RBAC.groupby('SubscriptionId')['rbacObjectType'].apply(lambda x: (x=='ServicePrincipal').sum()).reset_index(name='RBAC:ServicePrincipal')
    Owner = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='Owner').sum()).reset_index(name='RBAC:Owner')
    Contributor = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='Contributor').sum()).reset_index(name='RBAC:Contributor')
    UserAccessAdmin = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='User Access Administrator').sum()).reset_index(name='RBAC:UserAccessAdmin')
    KPIRBAC_INFO = ServicePrincipal.merge(Owner, how='left', on='SubscriptionId').merge(Contributor, how='left', on='SubscriptionId').merge(UserAccessAdmin, how='left', on='SubscriptionId')
    KPIRBAC = Total.merge(TotalUser, how='left', on='SubscriptionId').merge(TotalEXT, how='left', on='SubscriptionId').merge(Total_managed, how='left', on='SubscriptionId').merge(Total_powerusers, how='left', on='SubscriptionId').merge(NoPAA, how='left', on='SubscriptionId').merge(NoPAA_Users, how='left', on='SubscriptionId').merge(NoEngie, how='left', on='SubscriptionId').merge(NULL, how='left', on='SubscriptionId').merge(BadAADGuest, how='left', on='SubscriptionId').merge(KPIRBAC_INFO, how='left', on='SubscriptionId').merge(NoCertifiedUser, how='left', on='SubscriptionId').merge(NoCertifiedUserSubscription, how='left', on='SubscriptionId')
    KPIRBAC['RBAC:PAA'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NoPAA']
    KPIRBAC['RBAC:PAA-User'] = KPIRBAC['RBAC:Total-User'] - KPIRBAC['RBAC:NoPAA-User']
    KPIRBAC['RBAC:ENGIE'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NoENGIE']
    KPIRBAC['RBAC:NotNULL'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NULL']
    KPIRBAC['RBAC:GoodAADGuest'] = 0
    KPIRBAC['RBAC:GoodAADGuestOther'] = KPIRBAC['RBAC:TotalEXT'] - KPIRBAC['RBAC:BadAADGuestOther']
    KPIRBAC['RBAC:CertifiedUser'] = KPIRBAC['RBAC:Total_powerusers'] - KPIRBAC['RBAC:NoCertifiedUser'] 
    KPIRBAC.drop(columns=['RBAC:Total_managed'], inplace=True)
    NonCompliant_KPIRBAC = NonCompliant_PAA.append(NonCompliant_Engie, ignore_index=True).append(NonCompliant_NotNull, ignore_index=True).append(NonCompliant_AADGuest, ignore_index=True).append(NonCompliant_CertifiedUser, ignore_index=True).append(NonCompliant_CertifiedUserSubscription, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    
    NonCompliant_KPIRBAC=NonCompliant_KPIRBAC[~NonCompliant_KPIRBAC['ResourceIdorGroup'].str.contains('Desktop Virtualization User',na=False)]
    
    Exceptions_KPIRBAC = Exceptions_PAA.append(Exceptions_Engie, ignore_index=True).append(Exceptions_NotNull, ignore_index=True).append(Exceptions_AADGuest, ignore_index=True).append(Exceptions_CertifiedUser, ignore_index=True).append(Exceptions_CertifiedUserSubscription, ignore_index=True)#.append(Exceptions_x, ignore_index=True)
    return(KPIRBAC, NonCompliant_KPIRBAC, Exceptions_KPIRBAC)

#--------------------------------------DoKPISecurityCenter.py file from Azure function-------------------------------------------------

def NonCompliant_CustomSC(data, reverse, resource_type, fields, name, exception=None):
    if (data.size > 0):
        mod_data = data
        if (exception is not None) and ('Exceptions' in mod_data.columns):
            mod_data[name + ':Exception'] = data['Exceptions'].str.contains('(^|:)' + exception + '(:|$)', regex=True)
        else:
            mod_data[name + ':Exception'] = False
    else:
        return pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']), pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception'])
    NonCompliant_data = mod_data.loc[mod_data[name + ':Exception'] == False]
    if reverse:
        NonCompliant_data = NonCompliant_data.loc[~(((NonCompliant_data['SecuCenterState'] == "Enabled") & NonCompliant_data['SecuCenterMail'].isnull()))][fields]
    else:
        NonCompliant_data = NonCompliant_data.loc[(((NonCompliant_data['SecuCenterState'] == "Enabled") & NonCompliant_data['SecuCenterMail'].isnull()))][fields]
    return NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, False)

def DoKPISecurityCenter(container_client):
    # SecurityCenter = read_csv_from_source(container_client, 'SecurityCenter')
    SecurityCenter = read_csv_from_source(container_client, 'SecuCenter')

    #NO EXCEPTIONS ?
    SecurityCenter['SecuCenterId'] = SecurityCenter.apply(lambda row: (('/subscriptions/%s/SecuCenter') % (row.SubscriptionId)), axis = 1)
    SecurityCenter = MergeException(container_client, SecurityCenter, 'SecuCenterId')

    Total = TotalFromRaw(SecurityCenter, 'SecuCenterState', 'SecurityCenter:Total', databricks=False)

    NonCompliant_Enabled, Exceptions_Enabled = NonCompliant_operator(SecurityCenter, 'SecuCenterState', operator.eq, "Not Enabled", False, 'SecurityCenter', ['SubscriptionId','SecuCenterMail', 'SecuCenterPhone'], 'Enabled', 'Enabled')
    Disabled = KPIFromNonCompliant(NonCompliant_Enabled, 'SecurityCenter', 'SecurityCenter:Disabled', databricks=False)

    NonCompliant_Configured, Exceptions_Configured = NonCompliant_CustomSC(SecurityCenter, False, 'SecuCenterMail', ['SubscriptionId','SecuCenterMail', 'SecuCenterPhone'], 'Configured', 'Configured')
    NotConfigured = KPIFromNonCompliant(NonCompliant_Configured, 'SecurityCenter', 'SecurityCenter:NotConfigured', databricks=False)

    KPISecurityCenter = Total.merge(Disabled, how='left', on='SubscriptionId').merge(NotConfigured, how='left', on='SubscriptionId')
    NonCompliant_KPISecurityCenter = NonCompliant_Enabled.append(NonCompliant_Configured, ignore_index=True)
    Exceptions_KPISecurityCenter = Exceptions_Enabled.append(Exceptions_Configured, ignore_index=True)
    return(KPISecurityCenter, NonCompliant_KPISecurityCenter, Exceptions_KPISecurityCenter)

#--------------------------------------DoKPISQLServer.py file from Azure function------------------------------------------------------

def DoKPISQLServer(container_client):
    SQLServer = read_csv_from_source(container_client, 'SQLServer')

    SQLServer = MergeDataBricks(container_client, SQLServer, 'sqlServerId')  
    SQLServer = MergeException(container_client, SQLServer, 'sqlServerId')

    Total = TotalFromRaw(SQLServer, 'sqlServerName', 'SQLServer:Total')

    NonCompliant_Private, Exceptions_Private = NonCompliant_contains(SQLServer, 'sqlServerAccess', 'Enabled', False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'Public', 'Public', natest=True)
    Public = KPIFromNonCompliant(NonCompliant_Private, 'SQLServer', 'SQLServer:Public')

    SQLServer = SQLServer.fillna({'sqlServerTLS': 0.0})
    NonCompliant_TLS, Exceptions_TLS = NonCompliant_operator(SQLServer, 'sqlServerTLS', operator.lt, 1.2, False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'TLSVersion', 'TLSVersion')
    # NonCompliant_TLS, Exceptions_TLS = NonCompliant_operator(SQLServer, 'sqlServerAcTLS', operator.lt, 1.2, False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'TLSVersion', 'TLSVersion')
    TLS = KPIFromNonCompliant(NonCompliant_TLS, 'SQLServer', 'SQLServer:BadTLSVersion')
    
    KPISQLServer = Total.merge(Public, how='left', on='SubscriptionId').merge(TLS, how='left', on='SubscriptionId')
    NonCompliant_KPISQLServer = NonCompliant_Private.append(NonCompliant_TLS, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPISQLServer = Exceptions_Private.append(Exceptions_TLS, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPISQLServer, NonCompliant_KPISQLServer, Exceptions_KPISQLServer)

#--------------------------------------DoKPISQLServerDatabase.py file from Azure function----------------------------------------------

def DoKPISQLServerDatabase(container_client):
    SQLServerDatabase = read_csv_from_source(container_client, 'SQLServerDatabase')

    SQLServerDatabase = MergeDataBricks(container_client, SQLServerDatabase, 'DBId')
    SQLServerDatabase = MergeException(container_client, SQLServerDatabase, 'DBId')

    SQLServerDatabase =  SQLServerDatabase.loc[(SQLServerDatabase['DBName'] != 'master')]

    Total = TotalFromRaw(SQLServerDatabase, 'DBName', 'SQLServerDatabase:Total')

    NonCompliant_Encryption, Exceptions_Encryption = NonCompliant_contains(SQLServerDatabase, 'DataTransEncry', 'Enabled', True, 'SQLServerDatabase', ['SubscriptionId','DBId', 'DBName'], 'EncryptionAtRest', 'EncryptionAtRest')
    Encyption = KPIFromNonCompliant(NonCompliant_Encryption, 'SQLServerDatabase', 'SQLServerDatabase:NoEncyptionAtRest')

    KPISQLServerDatabase = Total.merge(Encyption, how='left', on='SubscriptionId')
    NonCompliant_KPISQLServerDatabase = NonCompliant_Encryption#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPISQLServerDatabase = Exceptions_Encryption#.append(NonCompliant_x, ignore_index=True)
    return(KPISQLServerDatabase, NonCompliant_KPISQLServerDatabase, Exceptions_KPISQLServerDatabase)

#--------------------------------------DoKPIStorageAccount.py file from Azure function-------------------------------------------------
def DoKPIStorageAccount(container_client):
    StorageAccount = read_csv_from_source(container_client, 'StorageAccount')

    #To be removed soon
    if not 'staId' in StorageAccount.columns:
        StorageAccount['staId'] = StorageAccount.apply(lambda row: (('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s') % (row.SubscriptionId, row.staResourceGroupName, row.staName)), axis = 1)
    StorageAccount = MergeDataBricks(container_client, StorageAccount, 'staId')
    StorageAccount = MergeException(container_client, StorageAccount, 'staId')

    Total = TotalFromRaw(StorageAccount, 'staName', 'StorageAccount:Total')

    NonCompliant_HTTPS, Exceptions_HTTPS = NonCompliant_operator(StorageAccount, 'staHTTPS', operator.eq, False, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'HTTPS', 'HTTPS')
    NoHTTPS = KPIFromNonCompliant(NonCompliant_HTTPS, 'StorageAccount', 'StorageAccount:NoHTTPS')

    NonCompliant_Firewall, Exceptions_Firewall = NonCompliant_contains(StorageAccount, 'staFirewallDefault', 'Allow', False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'Firewall', 'Firewall')
    FirewallAllow = KPIFromNonCompliant(NonCompliant_Firewall, 'StorageAccount', 'StorageAccount:FirewallAllow')

    StorageAccount = StorageAccount.fillna({'storageAllowBlobPublicAccess': True})
    NonCompliant_Public, Exceptions_Public = NonCompliant_operator(StorageAccount, 'storageAllowBlobPublicAccess', operator.eq, True, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'Public', 'Public')
    Public = KPIFromNonCompliant(NonCompliant_Public, 'StorageAccount', 'StorageAccount:Public')

    StorageAccount['storageTlsVersionMini'] = StorageAccount['storageTlsVersionMini'].apply(ExtractTLSVersion)

    NonCompliant_TLSVersion, Exceptions_TLSVersion = NonCompliant_operator(StorageAccount, 'storageTlsVersionMini', operator.lt, 1.2, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'TLSVersion', 'TLSVersion')
    TLSVersion = KPIFromNonCompliant(NonCompliant_TLSVersion, 'StorageAccount', 'StorageAccount:BadTLSVersion')

    StorageAccount = StorageAccount.fillna({'storageAllowBlobPublicAccess': True})
    NonCompliant_BlobPublicAccess , Exceptions_BlobPublicAccess  = NonCompliant_operator(StorageAccount, 'storageAllowBlobPublicAccess', operator.eq, True, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'BlobNoPublicAccess', 'BlobNoPublicAccess')
    BlobPublicAccess = KPIFromNonCompliant(NonCompliant_BlobPublicAccess, 'StorageAccount', 'StorageAccount:BlobPubliclyAccessible')

    StorageAccount = StorageAccount.fillna({'staFirewallDefault': 'Allow'})
    StorageAccount = StorageAccount.fillna({'storageAccessKey': True})
    StorageAccount['FirewallKO'] = StorageAccount['staFirewallDefault'] == 'Allow'
    StorageAccount['AccessKeyKO'] = StorageAccount['storageAccessKey']
    StorageAccount['SecureStorageAccessKO'] = StorageAccount[['FirewallKO', 'AccessKeyKO']].all(axis='columns')

    NonCompliant_SecureStorageAccess, Exceptions_SecureStorageAccess = NonCompliant_operator(StorageAccount, 'SecureStorageAccessKO', operator.eq, True, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'SecureStorageAccess', '(Firewall|SecureStorageAccess)')
    SecureStorageAccess = KPIFromNonCompliant(NonCompliant_SecureStorageAccess, 'StorageAccount', 'StorageAccount:NoSecureStorageAccess')

    # StorageAccount['CreationTime'] = StorageAccount['staCreationTime'].apply(lambda x:(datetime.datetime.strptime(x, '%m/%d/%Y %I:%M:%S %p')))
    # StorageAccount_2020 = StorageAccount[StorageAccount['CreationTime'] > np.datetime64(datetime.date(2020, 1, 1))]
    # Total_2020 = KPIFromNonCompliant(StorageAccount_2020, 'StorageAccount', 'StorageAccount:Total_2020')

    # NonCompliant_HTTPS_2020, Exceptions_HTTPS_2020 = NonCompliant_operator(StorageAccount_2020, 'staHTTPS', operator.eq, False, False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'HTTPS')
    # NoHTTPS_2020 = KPIFromNonCompliant(NonCompliant_HTTPS_2020, 'StorageAccount', 'StorageAccount:NoHTTPS_2020')

    # NonCompliant_Firewall_2020, Exceptions_Firewall_2020 = NonCompliant_contains(StorageAccount_2020, 'staFirewallDefault', 'Allow', False, 'StorageAccount', ['SubscriptionId','staId', 'staName'], 'Firewall')
    # FirewallAllow_2020 = KPIFromNonCompliant(NonCompliant_Firewall_2020, 'StorageAccount', 'StorageAccount:FirewallAllow_2020')
    
    KPIStorageAccount = Total.merge(NoHTTPS, how='left', on='SubscriptionId').merge(FirewallAllow, how='left', on='SubscriptionId').merge(Public, how='left', on='SubscriptionId').merge(TLSVersion, how='left', on='SubscriptionId').merge(BlobPublicAccess, how='left', on='SubscriptionId').merge(SecureStorageAccess, how='left', on='SubscriptionId')
        # .merge(Total_2020, how='left', on='SubscriptionId')\
        # .merge(NoHTTPS_2020, how='left', on='SubscriptionId')\
        # .merge(FirewallAllow_2020, how='left', on='SubscriptionId')
    NonCompliant_KPIStorageAccount = NonCompliant_HTTPS.append(NonCompliant_Firewall, ignore_index=True).append(NonCompliant_Public, ignore_index=True).append(NonCompliant_TLSVersion, ignore_index=True).append(NonCompliant_BlobPublicAccess, ignore_index=True).append(NonCompliant_SecureStorageAccess, ignore_index=True)#.append(NonCompliant_HTTPS_2020, ignore_index=True).append(NonCompliant_Firewall_2020, ignore_index=True)
    Exceptions_KPIStorageAccount = Exceptions_HTTPS.append(Exceptions_Firewall, ignore_index=True).append(Exceptions_Public, ignore_index=True).append(Exceptions_TLSVersion, ignore_index=True).append(Exceptions_BlobPublicAccess, ignore_index=True).append(Exceptions_SecureStorageAccess, ignore_index=True)#.append(Exceptions_HTTPS_2020, ignore_index=True).append(Exceptions_Firewall_2020, ignore_index=True)
    return(KPIStorageAccount, NonCompliant_KPIStorageAccount, Exceptions_KPIStorageAccount)

#--------------------------------------DoKPISubnet.py file from Azure function---------------------------------------------------------

def DoKPISubnet(container_client):
    Subnet = read_csv_from_source(container_client, 'Subnet')
    NSGRules = read_csv_from_source(container_client, 'NSGRules')
    
    Subnet = MergeDataBricks(container_client, Subnet, 'subnetId')
    Subnet = MergeException(container_client, Subnet, 'subnetId')

    NSGRules['ValidDenyInbound'] = NSGRules.apply(lambda row: row.nsgRuleDirection == "Inbound" and row.nsgRuleAccess == "Deny" and row.nsgRuleSourcePort == '*' and row.nsgRuleSourceAddress == '*' and row.nsgRuleDestinationPort == '*' and row.nsgRuleDestinationAddress == '*', axis = 1)
    NSGRules = NSGRules.loc[(NSGRules['ValidDenyInbound'] == True)]
    NSGRules.drop_duplicates(subset=['nsgID'], inplace=True)
    Subnet = Subnet.merge(NSGRules[['nsgID', 'ValidDenyInbound']], how='left', on='nsgID').fillna({'ValidDenyInbound': False})
    Total = TotalFromRaw(Subnet, 'subnetId', 'Subnet:Total')
    NonCompliant_DenyInbound, Exceptions_DenyInbound = NonCompliant_operator(Subnet, 'ValidDenyInbound', operator.eq, False, False, 'Subnet', ['SubscriptionId','subnetId', 'subnetName'], 'DenyInbound', 'DenyInbound')
    AllowInbound = KPIFromNonCompliant(NonCompliant_DenyInbound, 'Subnet', 'Subnet:AllowInbound')
    
    KPISubnet = Total.merge(AllowInbound, how='left', on='SubscriptionId')
    NonCompliant_KPISubnet = NonCompliant_DenyInbound#.append(NonCompliant_DenyInbound, ignore_index=True)
    Exceptions_KPISubnet = Exceptions_DenyInbound#.append(Exceptions_DenyInbound, ignore_index=True)
    return(KPISubnet, NonCompliant_KPISubnet, Exceptions_KPISubnet)

#--------------------------------------DoKPIVM.py file from Azure function-------------------------------------------------------------

def NonCompliant_CustomVM(data, reverse, resource_type, fields, name, exception=None, split_databricks=True):
    if (data.size > 0):
        mod_data = data
        if (exception is not None) and ('Exceptions' in mod_data.columns):
            mod_data[name + ':Exception'] = data['Exceptions'].str.contains('(^|:)' + exception + '(:|$)', regex=True)
        else:
            mod_data[name + ':Exception'] = False
    else:
        return pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']), pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception'])
    NonCompliant_data = mod_data.loc[mod_data[name + ':Exception'] == False]
    export_fields = fields
    if ('DataBricksId' in mod_data.columns):
        export_fields = set(fields + ['DataBricksId'])
    if reverse:
        NonCompliant_data = NonCompliant_data.loc[~(((NonCompliant_data['vmPublicIP'] == True) & (NonCompliant_data['vmNsgId'].isnull() | NonCompliant_data['CountInvalid'] > 0)))][export_fields]
    else:
        NonCompliant_data = NonCompliant_data.loc[(((NonCompliant_data['vmPublicIP'] == True) & (NonCompliant_data['vmNsgId'].isnull() | NonCompliant_data['CountInvalid'] > 0)))][export_fields]
    return NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, split_databricks)

def DoKPIVM(container_client):
    VM = read_csv_from_source(container_client, 'VM')
    NSGRules = read_csv_from_source(container_client, 'NSGRules')
    NETWORK_INTERFACE = read_csv_from_source(container_client, 'NetworkInterfaces').drop_duplicates(subset=['nicId', 'nicSubnetId', 'nicNSG', 'nicPublicIP'])
    SUBNET = read_csv_from_source(container_client, 'Subnet')

    VM['vmId'] = VM['vmId'].str.lower()
    VM['vmNIC'] = VM['vmNIC'].astype(str).str.lower()
    NSGRules['nsgID'] = NSGRules['nsgID'].str.lower()
    NETWORK_INTERFACE['nicId'] = NETWORK_INTERFACE['nicId'].str.lower()
    NETWORK_INTERFACE['nicVMAttachedId'] = NETWORK_INTERFACE['nicVMAttachedId'].str.lower()
    NETWORK_INTERFACE['nicSubnetId'] = NETWORK_INTERFACE['nicSubnetId'].str.lower()
    NETWORK_INTERFACE['nicNSG'] = NETWORK_INTERFACE['nicNSG'].str.lower()
    SUBNET['vnetId'] = SUBNET['vnetId'].str.lower()
    SUBNET['subnetId'] = SUBNET['subnetId'].str.lower()
    SUBNET['nsgID'] = SUBNET['nsgID'].str.lower()

    VM = MergeDataBricks(container_client, VM, 'vmId')
    VM_DatabricksBackup = VM[['vmId', 'DataBricksId']]
    NSGRules = MergeDataBricks(container_client, NSGRules, 'nsgID')
    NETWORK_INTERFACE = MergeDataBricks(container_client, NETWORK_INTERFACE, 'nicId')
    SUBNET = MergeDataBricks(container_client, SUBNET, 'vnetId')

    VM_NIC = pd.DataFrame(VM['vmNIC'].str.split(',').tolist(), index=VM['vmId']).stack()
    VM_NIC = VM_NIC.reset_index([0, 'vmId'])
    VM_NIC.columns = ['vmId', 'vmNIC']

    VM = VM.drop(columns=['vmNIC']).merge(VM_NIC, how='left', on='vmId')
    VM = VM.merge(NETWORK_INTERFACE[['nicId', 'nicSubnetId', 'nicNSG', 'nicPublicIP']], how='left', left_on='vmNIC', right_on='nicId')
    VM = VM.merge(SUBNET[['subnetId', 'nsgID']], how='left', left_on='nicSubnetId', right_on='subnetId')
    VM = VM.drop(columns=['nicId', 'nicSubnetId']).rename(columns={"nsgID": "subNSG"})
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleDirection'] == "Inbound")]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleAccess'] == "Allow")]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleSourceAddress'].str.contains('(^|,)' + r'Internet|\*' + '(,|$)', regex=True, na=False))]
    # NSGRules = NSGRules.loc[(NSGRules['nsgRuleSourceAddress'].str.contains('*', regex=False, na=False))]
    # NSGRules = NSGRules.loc[(NSGRules['nsgRuleSourcePort'].str.contains('(^|,)' + '*|22|3389' + '(,|$)', regex=True, na=False))]
    NSGRules = NSGRules.loc[(NSGRules['nsgRuleDestinationAddress'].str.contains('(^|,)' + r'Internet|\*' + '(,|$)', regex=True, na=False))]
    # NSGRules = NSGRules.loc[(NSGRules['nsgRuleDestinationAddress'].str.contains('*', regex=False, na=False))]
    # NSGRules.loc[(NSGRules['nsgRuleDestinationPort'].str.contains('(^|,)' + '22|3389|\*' + '(,|$)', regex=True, na=False))]
    # print(NSGRules['nsgRuleDestinationPort'])
    NSGRules['DestinationPort:22'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=22)
    NSGRules['DestinationPort:3389'] = NSGRules['nsgRuleDestinationPort'].apply(RangesContainPort, Target=3389)
    NSGRules['DestinationPort:SSHRDP'] = NSGRules[['DestinationPort:22', 'DestinationPort:3389']].any(axis='columns')
    NSGRules = NSGRules.loc[(NSGRules['DestinationPort:SSHRDP'] == True)]
    NSGRules = (NSGRules.groupby('nsgID')['nsgName'].count().reset_index(name='CountInvalid'))
    VM = VM.merge(NSGRules, how='left', left_on='nicNSG', right_on='nsgID').rename(columns={"CountInvalid": "CountInvalidnic"})
    VM = VM.merge(NSGRules, how='left', left_on='subNSG', right_on='nsgID').rename(columns={"CountInvalid": "CountInvalidsub"})
    VM.fillna({'CountInvalidnic' : 0, 'CountInvalidsub' : 0}, inplace=True)
    VM['CountInvalid'] = VM['CountInvalidnic'] + VM['CountInvalidsub']
    VM['vmPublicIP'] = VM['nicPublicIP'].notna() 
    # VMPublic = VM.loc[(VM['vmPublicIP'] == True)]
    VM['vmNsgId'] = VM['nicNSG'].fillna('') + VM['subNSG'].fillna('')
    VM.loc[(VM['vmNsgId'] == ''), 'vmNsgId'] = np.nan
    
    #Merge and split for VM/Interfaces
    VM = VM[['SubscriptionId', 'vmId', 'vmName', 'CountInvalid', 'vmPublicIP', 'vmNsgId', 'nicPublicIP']]
    VM_INTERFACES = VM.copy()
    VM['vmNsgId'] = ~VM['vmNsgId'].isnull()
    TEST_vmPublicIP =  VM.groupby(['SubscriptionId', 'vmId'])['vmPublicIP'].any().reset_index(name='vmPublicIP')
    TEST_vmNsgId =  VM.groupby(['SubscriptionId', 'vmId'])['vmNsgId'].all(skipna=False).reset_index(name='vmNsgId')
    VM = VM.drop_duplicates(subset=['SubscriptionId', 'vmId'])
    VM.drop(columns=['vmPublicIP', 'vmNsgId'], inplace = True)
    VM = VM.merge(TEST_vmPublicIP, how='left', on=['SubscriptionId', 'vmId'])
    VM = VM.merge(TEST_vmNsgId, how='left', on=['SubscriptionId', 'vmId'])
    VM.loc[(VM['vmNsgId'] == False), 'vmNsgId'] = np.nan
    
    VM = VM.merge(VM_DatabricksBackup, how='left', on='vmId')
    VM = MergeException(container_client, VM, 'vmId')
    VM_INTERFACES = VM_INTERFACES.merge(VM_DatabricksBackup, how='left', on='vmId')
    VM_INTERFACES = MergeException(container_client, VM_INTERFACES, 'vmId')
    
    Total = TotalFromRaw(VM, 'vmName', 'VM:Total')
    # PublicIP = VMPublic.groupby('SubscriptionId')['vmName'].count().reset_index(name='VM:PublicIP')
    NonCompliant_PublicIP, Exceptions_PublicIP = NonCompliant_operator(VM, 'vmPublicIP', operator.eq, True, False, 'VM', ['SubscriptionId','vmId', 'vmName'], 'PublicIP', 'PublicIP')
    PublicIP = KPIFromNonCompliant(NonCompliant_PublicIP, 'VM', 'VM:PublicIP')
    
    NonCompliant_PublicIP2, Exceptions_PublicIP2= NonCompliant_operator(VM_INTERFACES, 'vmPublicIP', operator.eq, True, False, 'VM_INTERFACES', ['SubscriptionId','vmId', 'nicPublicIP'], 'PublicIP', 'PublicIP')
    NonCompliant_PublicIP = NonCompliant_PublicIP.append(NonCompliant_PublicIP2, ignore_index=True)

    NonCompliant_NSG, Exceptions_NSG = NonCompliant_isnull(VM, 'vmNsgId', False, 'VM', ['SubscriptionId','vmId', 'vmName'], 'NSG', 'NSG')
    NoNSG = KPIFromNonCompliant(NonCompliant_NSG, 'VM', 'VM:NoNSG')

    NonCompliant_GoodNSG, Exceptions_GoodNSG = NonCompliant_operator(VM, 'CountInvalid', operator.gt, 0, False, 'VM', ['SubscriptionId','vmId', 'vmName'], 'GoodNSG', 'GoodNSG')
    BadNSG = KPIFromNonCompliant(NonCompliant_GoodNSG, 'VM', 'VM:BadNSG')

    NonCompliant_BlockInternet, Exceptions_BlockInternet = NonCompliant_CustomVM(VM, False, 'VM', ['SubscriptionId','vmId', 'vmName'], 'BlockInternet', 'BlockInternet')
    AccessibleInternet = KPIFromNonCompliant(NonCompliant_BlockInternet, 'VM', 'VM:AccessibleInternet')

    NonCompliant_BlockInternet2, Exceptions_BlockInternet2 = NonCompliant_CustomVM(VM_INTERFACES, False, 'VM_INTERFACES', ['SubscriptionId','vmId', 'nicPublicIP'], 'BlockInternet', 'BlockInternet')
    NonCompliant_BlockInternet = NonCompliant_BlockInternet.append(NonCompliant_BlockInternet2, ignore_index=True)


    KPIVM = Total.merge(PublicIP, how='left', on='SubscriptionId').merge(NoNSG, how='left', on='SubscriptionId').merge(BadNSG, how='left', on='SubscriptionId').merge(AccessibleInternet, how='left', on='SubscriptionId')
    NonCompliant_KPIVM = NonCompliant_NSG.append([NonCompliant_GoodNSG, NonCompliant_BlockInternet, NonCompliant_PublicIP], ignore_index=True)
    Exceptions_KPIVM = Exceptions_NSG.append([Exceptions_GoodNSG, Exceptions_BlockInternet, Exceptions_PublicIP], ignore_index=True)
    return(KPIVM, NonCompliant_KPIVM, Exceptions_KPIVM)



#--------------------------------------DoKPIDataBricks.py file from Azure function-------------------------------------------------------------

def DoKPIDataBricks(container_client):
    DataBricks = read_csv_from_source(container_client, 'Databricks')
    
    DataBricks.dropna(subset=['SubscriptionId'],inplace=True)

    Exceptions_tab=MergeExceptionDataBricks(container_client,DataBricks,'DataBricksId')
    
    NonCompliant,Exceptions=NonCompliantDatabricks(Exceptions_tab)

    data = DataBricks[(DataBricks['DataBricksNoPublicIP'] == False)]

    output=data.groupby(['SubscriptionId'])['DataBricksNoPublicIP'].count().reset_index(name='DataBricks:' + 'NoPublicIP:Total')
    
    return (output,NonCompliant,Exceptions)





