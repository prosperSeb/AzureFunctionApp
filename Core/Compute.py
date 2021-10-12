#!/usr/bin/env python3
import time
import logging
import sys
import os
import pandas as pd
import numpy as np
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import datetime
import time
import automationassets
#--------------------------------------Variables definition----------------------------------------------------------------------------
_AUTOMATION_RESOURCE_GROUP = "KPI_Engie"
_AUTOMATION_ACCOUNT = "PythonKPI"
_RUNBOOK_NAME = ["Shared","DoKPI"]
_RUNBOOK_TYPE = ".py"

#--------------------------------------import function---------------------------------------------------------------------------------

def download_file(resource_group, automation_account, runbook_name, runbook_type):
    """
    Downloads a runbook from the automation account to the cloud container
    """
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


download_file(_AUTOMATION_RESOURCE_GROUP, _AUTOMATION_ACCOUNT, _RUNBOOK_NAME[0], _RUNBOOK_TYPE)
download_file(_AUTOMATION_RESOURCE_GROUP, _AUTOMATION_ACCOUNT, _RUNBOOK_NAME[1], _RUNBOOK_TYPE)

#--------------------------------------import Shared-----------------------------------------------------------------------------------

from Shared import *
from DoKPI import *

#--------------------------------------GlobalKPI.py file from Azure function-----------------------------------------------------------

def DoGlobalKPI(DetailedKPI):
    ag1 = {'SubscriptionName' : 'count','StorageAccount:Total' : 'sum', 'StorageAccount:NoHTTPS' : 'sum', 'StorageAccount:FirewallAllow' : 'sum', 'StorageAccount:Public' : 'sum', 'StorageAccount:BadTLSVersion' : 'sum', 'StorageAccount:BlobPubliclyAccessible' : 'sum', 'StorageAccount:NoSecureStorageAccess' : 'sum','RBAC:Total' : 'sum', 'RBAC:PAA' : 'sum', 'RBAC:ENGIE' : 'sum', 'RBAC:NoENGIE' : 'sum', 'RBAC:NULL' : 'sum', 'RBAC:GoodAADGuest' : 'sum', 'RBAC:BadAADGuest' : 'sum', 'RBAC:GoodAADGuestOther' : 'sum', 'RBAC:BadAADGuestOther' : 'sum', 'RBAC:ServicePrincipal' : 'sum', 'RBAC:Owner' : 'sum', 'RBAC:Contributor' : 'sum', 'RBAC:UserAccessAdmin' : 'sum', 'RBAC:NoCertifiedUser' : 'sum', 'RBAC:NoCertifiedUserSubscription' : 'sum','VM:Total' : 'sum', 'VM:PublicIP' : 'sum', 'VM:NoNSG' : 'sum', 'VM:BadNSG' : 'sum', 'VM:AccessibleInternet' : 'sum','SecurityCenter:Total' : 'sum', 'SecurityCenter:Disabled' : 'sum', 'SecurityCenter:NotConfigured' : 'sum','Disk:Total' : 'sum', 'Disk:EncryptionAtRest' : 'sum','Subnet:Total' : 'sum', 'Subnet:AllowInbound' : 'sum','SQLServer:Total' : 'sum', 'SQLServer:Public' : 'sum', 'SQLServer:BadTLSVersion' : 'sum','LoadBalancer:Total' : 'sum', 'LoadBalancerRules:Total' : 'sum', 'LoadBalancer:SSHRDP' : 'sum', 'LoadBalancerRules:SSHRDP' : 'sum','AppGateway:Total' : 'sum', 'AppGateway:WAFDetectionOnly' : 'sum','CosmosDB:Total' : 'sum', 'CosmosDB:Public' : 'sum','Function:Total' : 'sum', 'Function:NoHTTPS' : 'sum', 'Function:BadTLSVersion' : 'sum','PostgreSQL:Total' : 'sum', 'PostgreSQL:NoEncryptionInTransit' : 'sum', 'PostgreSQL:BadTLSVersion' : 'sum', 'PostgreSQL:NoEncryptionAtRest' : 'sum', 'PostgreSQL:Public' : 'sum','SQLServerDatabase:Total' : 'sum', 'SQLServerDatabase:NoEncyptionAtRest' : 'sum','NetworkSecurityGroup:Total' : 'sum', 'NetworkSecurityGroup:LegacyProtocol' : 'sum'}# 'StorageAccount:Total_2020' : 'sum', 'StorageAccount:NoHTTPS_2020' : 'sum', 'StorageAccount:FirewallAllow_2020' : 'sum',
    GlobalKPI = DetailedKPI.groupby(['BU', 'EntityName', 'OrgID']).agg(ag1)
    GlobalKPI['Subscription:Total'] = GlobalKPI['SubscriptionName'] 
    GlobalKPI['RBAC:ENGIEAAD'] = GlobalKPI['RBAC:ENGIE']
    GlobalKPI['RBAC:NoAAD'] = GlobalKPI['RBAC:NULL']
    GlobalKPI['RBAC:OtherAAD'] = GlobalKPI['RBAC:NoENGIE']
    GlobalKPI['SecurityCenter:Enabled_percent'] = np.where(GlobalKPI['SecurityCenter:Total']==0,np.nan,(1 - (GlobalKPI['SecurityCenter:Disabled'] / GlobalKPI['SecurityCenter:Total'])) * 100)
    GlobalKPI['SecurityCenter:Configured_percent'] = np.where(GlobalKPI['SecurityCenter:Total']==0,np.nan,(1 - ((GlobalKPI['SecurityCenter:NotConfigured'] + GlobalKPI['SecurityCenter:Disabled']) / GlobalKPI['SecurityCenter:Total'])) * 100)
    GlobalKPI['RBAC:PA'] = GlobalKPI['RBAC:ENGIE'] + GlobalKPI['RBAC:GoodAADGuestOther']  - GlobalKPI['RBAC:PAA']
    GlobalKPI['StorageAccount:HTTPS_percent'] = np.where(GlobalKPI['StorageAccount:Total']==0,np.nan,(1 - (GlobalKPI['StorageAccount:NoHTTPS'] / GlobalKPI['StorageAccount:Total'])) * 100)
    GlobalKPI['StorageAccount:FirewallDeny_percent'] = np.where(GlobalKPI['StorageAccount:Total']==0,np.nan,(1 - (GlobalKPI['StorageAccount:FirewallAllow'] / GlobalKPI['StorageAccount:Total'])) * 100)
    # GlobalKPI['StorageAccount:HTTPS_2020_percent'] = np.where(GlobalKPI['StorageAccount:Total_2020']==0,np.nan,(1 - (GlobalKPI['StorageAccount:NoHTTPS_2020'] / GlobalKPI['StorageAccount:Total_2020'])) * 100)
    # GlobalKPI['StorageAccount:FirewallDeny_2020_percent'] = np.where(GlobalKPI['StorageAccount:Total_2020']==0,np.nan,(1 - (GlobalKPI['StorageAccount:FirewallAllow_2020'] / GlobalKPI['StorageAccount:Total_2020'])) * 100)
    GlobalKPI['Disk:EncryptionAtRest_percent'] = np.where(GlobalKPI['Disk:Total']==0,np.nan,((GlobalKPI['Disk:EncryptionAtRest'] / GlobalKPI['Disk:Total'])) * 100)
    GlobalKPI['SQLServer:Public'] = GlobalKPI['SQLServer:Public']
    GlobalKPI['SQLServer:ValidTLS_percent'] = np.where(GlobalKPI['SQLServer:Total']==0,np.nan,(1 - (GlobalKPI['SQLServer:BadTLSVersion'] / GlobalKPI['SQLServer:Total'])) * 100)
    GlobalKPI['VM:ManagementAccessibleFromInternet'] = GlobalKPI['VM:AccessibleInternet']
    GlobalKPI['Subnet:DenyInbound_percent'] = np.where(GlobalKPI['Subnet:Total']==0,np.nan,(1 - (GlobalKPI['Subnet:AllowInbound'] / GlobalKPI['Subnet:Total'])) * 100)

    GlobalKPI['AppGateway:Firewall_percent'] = np.where(GlobalKPI['AppGateway:Total']==0,np.nan,(1 - (GlobalKPI['AppGateway:WAFDetectionOnly'] / GlobalKPI['AppGateway:Total'])) * 100)
    GlobalKPI['CosmosDB:Public_percent'] = np.where(GlobalKPI['CosmosDB:Total']==0,np.nan,((GlobalKPI['CosmosDB:Public'] / GlobalKPI['CosmosDB:Total'])) * 100)
    GlobalKPI['Function:HTTPS_percent'] = np.where(GlobalKPI['Function:Total']==0,np.nan,(1 - (GlobalKPI['Function:NoHTTPS'] / GlobalKPI['Function:Total'])) * 100)
    GlobalKPI['Function:ValidTLS_percent'] = np.where(GlobalKPI['Function:Total']==0,np.nan,(1 - (GlobalKPI['Function:BadTLSVersion'] / GlobalKPI['Function:Total'])) * 100)
    GlobalKPI['PostgreSQL:EncryptionInTransit_percent'] = np.where(GlobalKPI['PostgreSQL:Total']==0,np.nan,(1 - (GlobalKPI['PostgreSQL:NoEncryptionInTransit'] / GlobalKPI['PostgreSQL:Total'])) * 100)
    GlobalKPI['PostgreSQL:ValidTLS_percent'] = np.where(GlobalKPI['PostgreSQL:Total']==0,np.nan,(1 - (GlobalKPI['PostgreSQL:BadTLSVersion'] / GlobalKPI['PostgreSQL:Total'])) * 100)
    GlobalKPI['PostgreSQL:EncryptionAtRest_percent'] = np.where(GlobalKPI['PostgreSQL:Total']==0,np.nan,(1 - (GlobalKPI['PostgreSQL:NoEncryptionAtRest'] / GlobalKPI['PostgreSQL:Total'])) * 100)
    GlobalKPI['PostgreSQL:Public_percent'] = np.where(GlobalKPI['PostgreSQL:Total']==0,np.nan,((GlobalKPI['PostgreSQL:Public'] / GlobalKPI['PostgreSQL:Total'])) * 100)
    GlobalKPI['SQLServerDatabase:EncryptionAtRest_percent'] = np.where(GlobalKPI['SQLServerDatabase:Total']==0,np.nan,(1 - (GlobalKPI['SQLServerDatabase:NoEncyptionAtRest'] / GlobalKPI['SQLServerDatabase:Total'])) * 100)
    
    
    print('ManagementAccessibleFromInternet : %d', GlobalKPI['VM:ManagementAccessibleFromInternet'].sum())
    print('SecurityCenter:Disabled :  %d\nSecurityCenter:NotConfigured : %d\nSecurityCenter:Configured : %d\nSecurityCenter:Configured_percent : %d\nSecurityCenter:Total : %d' % (GlobalKPI['SecurityCenter:Disabled'].sum(), GlobalKPI['SecurityCenter:NotConfigured'].sum(), (GlobalKPI['SecurityCenter:Total'].sum() - (GlobalKPI['SecurityCenter:NotConfigured'].sum() + GlobalKPI['SecurityCenter:Disabled'].sum())), (((GlobalKPI['SecurityCenter:NotConfigured'].sum() + GlobalKPI['SecurityCenter:Disabled'].sum()) / GlobalKPI['SecurityCenter:Total'].sum())*100), GlobalKPI['SecurityCenter:Total'].sum()))

    GlobalKPI = GlobalKPI[['Subscription:Total','RBAC:ENGIEAAD', 'RBAC:OtherAAD', 'RBAC:NoAAD', 'RBAC:PA', 'RBAC:PAA', 'RBAC:BadAADGuest','RBAC:ServicePrincipal', 'RBAC:Owner', 'RBAC:Contributor', 'RBAC:UserAccessAdmin', 'RBAC:NoCertifiedUser', 'RBAC:NoCertifiedUserSubscription','SecurityCenter:Configured_percent', 'SecurityCenter:Enabled_percent','StorageAccount:HTTPS_percent', 'StorageAccount:FirewallDeny_percent','VM:ManagementAccessibleFromInternet', 'VM:PublicIP','Disk:EncryptionAtRest_percent','SQLServer:Public', 'SQLServer:ValidTLS_percent','Subnet:DenyInbound_percent','LoadBalancer:SSHRDP','AppGateway:Firewall_percent','CosmosDB:Public_percent','Function:HTTPS_percent', 'Function:ValidTLS_percent','PostgreSQL:EncryptionInTransit_percent', 'PostgreSQL:ValidTLS_percent', 'PostgreSQL:EncryptionAtRest_percent', 'PostgreSQL:Public_percent','SQLServerDatabase:EncryptionAtRest_percent','NetworkSecurityGroup:LegacyProtocol']]
    # 'StorageAccount:HTTPS_2020_percent', 'StorageAccount:FirewallDeny_2020_percent',
    return(GlobalKPI)

#--------------------------------------DetailedKPI.py file from Azure function---------------------------------------------------------

def DoKPI(container_client):
    KPIStorageAccount, KPIStorageAccount_NonCompliant, KPIStorageAccount_Exceptions = DoKPIStorageAccount(container_client)
    KPIRBAC, KPIRBAC_NonCompliant, KPIRBAC_Exceptions = DoKPIRBAC(container_client)
    KPIVM, KPIVM_NonCompliant, KPIVM_Exceptions = DoKPIVM(container_client)
    KPISecurityCenter, KPISecurityCenter_NonCompliant, KPISecurityCenter_Exceptions = DoKPISecurityCenter(container_client)
    KPIDisk, KPIDisk_NonCompliant, KPIDisk_Exceptions = DoKPIDisk(container_client)
    KPISQLServer, KPISQLServer_NonCompliant, KPISQLServer_Exceptions = DoKPISQLServer(container_client)
    KPISubnet, KPISubnet_NonCompliant, KPISubnet_Exceptions = DoKPISubnet(container_client)
    KPILoadBalancer, KPILoadBalancer_NonCompliant, KPILoadBalancer_Exceptions = DoKPILoadBalancer(container_client)
    KPIAppGateway, KPIAppGateway_NonCompliant, KPIAppGateway_Exceptions = DoKPIAppGateway(container_client)
    KPICosmosDB, KPICosmosDB_NonCompliant, KPICosmosDB_Exceptions = DoKPICosmosDB(container_client)
    KPIFunction, KPIFunction_NonCompliant, KPIFunction_Exceptions = DoKPIFunction(container_client)
    KPIPostgreSQL, KPIPostgreSQL_NonCompliant, KPIPostgreSQL_Exceptions = DoKPIPostgreSQL(container_client)
    KPISQLServerDatabase, KPISQLServerDatabase_NonCompliant, KPISQLServerDatabase_Exceptions = DoKPISQLServerDatabase(container_client)
    KPINSG, KPINSG_NonCompliant, KPINSG_Exceptions = DoKPINSG(container_client)
    KPIDATABRICKS,KPIDATABRICKS_NonCompliant,KPIDATABRICKS_Exceptions=DoKPIDataBricks(container_client)
     
    NonCompliant = KPIStorageAccount_NonCompliant.append([KPIRBAC_NonCompliant,KPIVM_NonCompliant,KPISecurityCenter_NonCompliant,KPIDisk_NonCompliant,KPISQLServer_NonCompliant,KPISubnet_NonCompliant,KPILoadBalancer_NonCompliant,KPIAppGateway_NonCompliant,KPICosmosDB_NonCompliant,KPIFunction_NonCompliant,KPIPostgreSQL_NonCompliant,KPISQLServerDatabase_NonCompliant,KPINSG_NonCompliant,KPIDATABRICKS_NonCompliant], ignore_index=True)

    Exceptions = KPIStorageAccount_Exceptions.append([KPIRBAC_Exceptions,KPIVM_Exceptions,KPISecurityCenter_Exceptions,KPIDisk_Exceptions,KPISQLServer_Exceptions,KPISubnet_Exceptions,KPILoadBalancer_Exceptions,KPIAppGateway_Exceptions,KPICosmosDB_Exceptions,KPIFunction_Exceptions,KPIPostgreSQL_Exceptions,KPISQLServerDatabase_Exceptions,KPINSG_Exceptions,KPIDATABRICKS_Exceptions], ignore_index=True)

    KPI = KPIStorageAccount.merge(KPIRBAC, how='outer', on='SubscriptionId').merge(KPIVM, how='outer', on='SubscriptionId').merge(KPISecurityCenter, how='outer', on='SubscriptionId').merge(KPIDisk, how='outer', on='SubscriptionId').merge(KPISQLServer, how='outer', on='SubscriptionId').merge(KPISubnet, how='outer', on='SubscriptionId').merge(KPILoadBalancer, how='outer', on='SubscriptionId').merge(KPIAppGateway, how='outer', on='SubscriptionId').merge(KPICosmosDB, how='outer', on='SubscriptionId').merge(KPIFunction, how='outer', on='SubscriptionId').merge(KPIPostgreSQL, how='outer', on='SubscriptionId').merge(KPISQLServerDatabase, how='outer', on='SubscriptionId').merge(KPINSG, how='outer', on='SubscriptionId').merge(KPIDATABRICKS,how='outer',on='SubscriptionId')

    KPI.fillna(0, inplace=True)
    Referentiel = read_csv_from_source(container_client, 'Referentiel')
    Referentiel = Referentiel[['SubscriptionId', 'SubscriptionName', 'BU', 'EntityName', 'OrgID']]
    return (Referentiel.merge(KPI, how='left', on='SubscriptionId').set_index('SubscriptionId'), NonCompliant, Exceptions)

#--------------------------------------Compute.py file from Azure function-------------------------------------------------------------

def CustomOutput(Data, blob_service, Name, FileExtension):

    if FileExtension == 'csv':
        stroutput = Data.to_csv(na_rep='null', line_terminator='\n')
    else:
        stroutput = Data.to_json(orient='table')
    if ('SubscriptionId' in Data.columns):
        SubscriptionId = Data['SubscriptionId'].iloc[0]
    else :
        SubscriptionId = Data.index.array[0]
    try:
        container_client_output = blob_service.create_container(SubscriptionId, metadata=None, public_access=None)
    except:
        pass
    try:
        container_client_output = blob_service.get_container_client(SubscriptionId)
        container_client_output.upload_blob(name=Name, data=stroutput, overwrite=True)
    except Exception as err:
        print(SubscriptionId)
        exception_type = type(err).__name__
        print(exception_type)
        print(Data)

def outputresult(container_client, blob_service_client_output, FileType, FileExtension, Date, Data, split = False):
    Output = f"{FileType}Result/{Date}/Azure-{FileType}Result.{FileExtension}"
    Data['Date'] = datetime.date.today()
    Date = Data['Date']
    Data.drop(labels=['Date'], axis=1, inplace = True)
    Data.insert(0, 'Date', Date)
    if FileExtension == 'csv':
        stroutput = Data.to_csv(na_rep='null', line_terminator='\n')
    else:
        stroutput = Data.to_json(orient='table')
    container_client.upload_blob(name=Output, data=stroutput, overwrite=True)
    if (split):
        print("--" + FileType + 'output for each sub:')
        start_time = time.time()
        Data.groupby('SubscriptionId').apply(CustomOutput, blob_service=blob_service_client_output, Name=Output, FileExtension=FileExtension)
        end_time = time.time()
        print("--Time consumed in " + FileType +"output for each sub: " + str(end_time - start_time))

def RBACExport(blob_service_client, container_client):
    RBAC = read_csv_from_source(container_client, 'RBAC')
    AADGroup = read_csv_from_source(container_client, 'AADGroup')

    AADGroup = AADGroup.drop(columns=['SubscriptionId']).drop_duplicates()
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['ServicePrincipal'])))]
    RBAC = RBAC.loc[(RBAC['rbacRoleName'].str.contains('|'.join(['Owner', 'Contributor', 'Security Admin', 'Security Reader'])))]
    RBAC_Groups = RBAC.loc[(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC_Groups = RBAC_Groups.merge(AADGroup[['GroupObjectId', 'UserObjectId', 'DisplayName', 'UserPrincipalName']], how='left', left_on='rbacObjectId', right_on='GroupObjectId')
    RBAC_Groups.drop(columns=['rbacSignInName', 'rbacDisplayName', 'rbacObjectId', 'GroupObjectId'], inplace=True)
    RBAC_Groups.rename(columns={'UserObjectId' : 'rbacObjectId', 'DisplayName' : 'rbacDisplayName', 'UserPrincipalName' : 'rbacSignInName'}, inplace=True)
    RBAC_Groups['rbacObjectType'] = 'User'
    RBAC_Groups['rbacAccountType'] = np.where(RBAC_Groups['rbacSignInName'].str.contains('-A', na=False), "PAA", "PA")

    RBAC = RBAC.append(RBAC_Groups, ignore_index=True)

    RBAC.dropna(subset=['rbacSignInName'], inplace=True)
    ENGIE = RBAC.loc[(RBAC['rbacSignInName'].str.contains(r'.*@engie\.com$', na=False))]
    ENGIE_GUEST = RBAC.loc[(RBAC['rbacSignInName'].str.contains('_engie.com#EXT#@', na=False, regex=False))]
    ENGIE_GUEST['rbacSignInNameindex'] = ENGIE_GUEST['rbacSignInName'].str.index("_engie.com#EXT#")
    ENGIE_GUEST = ENGIE_GUEST.loc[(ENGIE_GUEST['rbacSignInNameindex'] == 6) | (ENGIE_GUEST['rbacSignInNameindex'] == 8)]

    ENGIE_NON_GUEST=RBAC.loc[(RBAC['rbacSignInName'].str.contains('[a-zA-Z0-9]{6}', na=False))]
    ENGIE_NON_GUEST[~ENGIE_NON_GUEST.isin(ENGIE_GUEST)].dropna()
    ENGIE_NON_GUEST[~ENGIE_NON_GUEST.isin(ENGIE)].dropna()

    RBAC = ENGIE.append(ENGIE_GUEST, ignore_index=True)
    RBAC = RBAC.append(ENGIE_NON_GUEST, ignore_index=True)

    RBAC['rbacSignInNamesub'] = RBAC['rbacSignInName'].str.slice(stop=6)
    RBAC = RBAC.loc[(RBAC['rbacSignInNamesub'].str.contains('[a-zA-Z0-9]{6}', na=False))]
    RBAC['GID'] = RBAC['rbacSignInNamesub'] + "@engie.com"
    RBAC = RBAC[['SubscriptionId', 'GID']].drop_duplicates()
    RBAC = RBAC.set_index('SubscriptionId')

    container_client_output = blob_service_client.get_container_client('access-report')
    Output = f"Azure-AccessReport.csv"
    stroutput = RBAC.to_csv(na_rep='null', line_terminator='\n')
    container_client_output.upload_blob(name=Output, data=stroutput, overwrite=True)

def SortDetailedPBI(Detailed,Unexpected):
    PowerBIExpectedValuesDetailed = ['SubscriptionName', 'BU', 'EntityName', 'OrgID', 'StorageAccount:Total', 'StorageAccount:NoHTTPS', 'StorageAccount:FirewallAllow', 'RBAC:Total', 'RBAC:NoPAA', 'RBAC:NoENGIE', 'RBAC:NULL', 'RBAC:BadAADGuest', 'RBAC:ServicePrincipal', 'RBAC:Owner', 'RBAC:Contributor', 'RBAC:UserAccessAdmin', 'RBAC:PAA', 'RBAC:ENGIE', 'RBAC:NotNULL', 'RBAC:GoodAADGuest', 'VM:Total', 'VM:PublicIP', 'VM:NoNSG', 'VM:BadNSG', 'VM:AccessibleInternet', 'SecurityCenter:Total', 'SecurityCenter:Disabled', 'SecurityCenter:NotConfigured', 'Disk:Total', 'Disk:NoEncryptionAtRest', 'Disk:EncryptionAtRest', 'SQLServer:Total', 'SQLServer:Public']
    DetailedPBI = Detailed[PowerBIExpectedValuesDetailed + [col for col in Detailed if col not in PowerBIExpectedValuesDetailed]]
    DetailedPBI.drop(Unexpected,axis=1, inplace = True)
    return (DetailedPBI)

def FilterCompliantPBI(NonCompliant):
    PowerBIUnwantedNonCompliants = [['CosmosDB', 'Public'],['PostgreSQL', 'EncryptionAtRest'],['PostgreSQL', 'Public'],['StorageAccount', 'Public'],['Subnet', 'DenyInbound'],['SQLServer', 'Public'],['Function', 'TLSVersion'],['RBAC', 'CertifiedUser'], ['RBAC', 'NotNull'],]
    
    for Unwanted in PowerBIUnwantedNonCompliants:
        NonCompliant.drop(NonCompliant[(NonCompliant.ResourceType == Unwanted[0]) & (NonCompliant.NonCompliant == Unwanted[1])].index, inplace=True)
    return (NonCompliant)

def compute_task():
    connect_str = automationassets.get_automation_variable('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client_input = BlobServiceClient.from_connection_string(connect_str)
    connect_str_output = automationassets.get_automation_variable('AZURE_STORAGE_CONNECTION_STRING_OUTPUT')
    if connect_str_output is not None:
        blob_service_client_output = BlobServiceClient.from_connection_string(connect_str_output)
    else:
        blob_service_client_output = blob_service_client_input
    container_client_input = blob_service_client_input.get_container_client('csv')
    container_client_output = blob_service_client_output.get_container_client('compute-output')

    sys.stdout.reconfigure(encoding='utf-8')
    Detailed, NonCompliant, Exceptions = DoKPI(container_client_input)
    Global = DoGlobalKPI(Detailed)

    cur_date = datetime.datetime.now().strftime('%Y-%m-%d')

    print('-output results')
    start_time = time.time()
    DetailedPBI = SortDetailedPBI(Detailed.copy(deep=True),[])
    outputresult(container_client_output, blob_service_client_output, 'DetailedFull', 'csv', cur_date, Detailed, split=False)
    outputresult(container_client_output, blob_service_client_output, 'DetailedFull', 'json', cur_date, Detailed, split=False)
    outputresult(container_client_output, blob_service_client_output, 'Detailed', 'csv', cur_date, DetailedPBI, split=False)
    outputresult(container_client_output, blob_service_client_output, 'Detailed', 'json', cur_date, DetailedPBI, split=False)

    outputresult(container_client_output, blob_service_client_output, 'Global', 'csv', cur_date, Global)
    outputresult(container_client_output, blob_service_client_output, 'Global', 'json', cur_date, Global)

    NonCompliantPBI = FilterCompliantPBI(NonCompliant.copy(deep=True))
    outputresult(container_client_output, blob_service_client_output, 'NonCompliantFull','csv', cur_date, NonCompliant.rename_axis('index'), split=False)
    outputresult(container_client_output, blob_service_client_output, 'NonCompliant','csv', cur_date, NonCompliantPBI.rename_axis('index'), split=False)

    outputresult(container_client_output, blob_service_client_output, 'Exceptions','csv', cur_date, Exceptions.rename_axis('index'), split=False)
    RBACExport(blob_service_client_output, container_client_input)
    end_time = time.time()
    print("-Time consumed in output results: " + str(end_time - start_time))





