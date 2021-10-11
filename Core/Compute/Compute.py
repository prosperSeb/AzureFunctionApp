import sys
import os
import pandas as pd
import numpy as np
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import datetime
from .DetailedKPI import DoKPI
from .GlobalKPI import DoGlobalKPI
from .Shared import *
import time
import logging



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
        logging.error(SubscriptionId)
        exception_type = type(err).__name__
        logging.error(exception_type)
        logging.error(Data)

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
        logging.info("--" + FileType + 'output for each sub:')
        start_time = time.time()
        Data.groupby('SubscriptionId').apply(CustomOutput, blob_service=blob_service_client_output, Name=Output, FileExtension=FileExtension)
        end_time = time.time()
        logging.info("--Time consumed in " + FileType +"output for each sub: " + str(end_time - start_time))

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

    ENGIE_NON_GUEST=RBAC.loc[(RBAC['rbacSignInName'].str.contains('[a-zA-Z]{2}''[0-9]{4}', na=False))]
    ENGIE_NON_GUEST.append(RBAC.loc[(RBAC['rbacSignInName'].str.contains('[a-zA-Z]{3}''[0-9]{3}', na=False))])

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
    PowerBIUnwantedNonCompliants = [['CosmosDB', 'Public'],
        ['PostgreSQL', 'EncryptionAtRest'],
        ['PostgreSQL', 'Public'],
        ['StorageAccount', 'Public'],
        ['Subnet', 'DenyInbound'],
        ['SQLServer', 'Public'],
        ['Function', 'TLSVersion'],
        ['RBAC', 'CertifiedUser'], ['RBAC', 'NotNull'],]
    
    for Unwanted in PowerBIUnwantedNonCompliants:
        NonCompliant.drop(NonCompliant[(NonCompliant.ResourceType == Unwanted[0]) & (NonCompliant.NonCompliant == Unwanted[1])].index, inplace=True)
    return (NonCompliant)

def compute_task():
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client_input = BlobServiceClient.from_connection_string(connect_str)
    connect_str_output = os.getenv('AZURE_STORAGE_CONNECTION_STRING_OUTPUT')
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

    logging.info('-output results')
    start_time = time.time()
    DetailedPBI = SortDetailedPBI(Detailed.copy(deep=True),[])
    #test
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
    logging.info("-Time consumed in output results: " + str(end_time - start_time))
