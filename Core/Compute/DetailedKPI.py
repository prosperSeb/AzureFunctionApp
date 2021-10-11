from .DoKPI import *
from .Shared import read_csv_from_source
import sys
import time

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
    
    
    NonCompliant = KPIStorageAccount_NonCompliant.append([KPIRBAC_NonCompliant,
                                                            KPIVM_NonCompliant,
                                                            KPISecurityCenter_NonCompliant,
                                                            KPIDisk_NonCompliant,
                                                            KPISQLServer_NonCompliant,
                                                            KPISubnet_NonCompliant,
                                                            KPILoadBalancer_NonCompliant,
                                                            KPIAppGateway_NonCompliant,
                                                            KPICosmosDB_NonCompliant,
                                                            KPIFunction_NonCompliant,
                                                            KPIPostgreSQL_NonCompliant,
                                                            KPISQLServerDatabase_NonCompliant,
                                                            KPINSG_NonCompliant,
                                                            KPIDATABRICKS_NonCompliant], ignore_index=True)

    Exceptions = KPIStorageAccount_Exceptions.append([KPIRBAC_Exceptions,
                                                            KPIVM_Exceptions,
                                                            KPISecurityCenter_Exceptions,
                                                            KPIDisk_Exceptions,
                                                            KPISQLServer_Exceptions,
                                                            KPISubnet_Exceptions,
                                                            KPILoadBalancer_Exceptions,
                                                            KPIAppGateway_Exceptions,
                                                            KPICosmosDB_Exceptions,
                                                            KPIFunction_Exceptions,
                                                            KPIPostgreSQL_Exceptions,
                                                            KPISQLServerDatabase_Exceptions,
                                                            KPINSG_Exceptions,
                                                            KPIDATABRICKS_Exceptions], ignore_index=True)

    KPI = KPIStorageAccount.merge(KPIRBAC, how='outer', on='SubscriptionId')\
        .merge(KPIVM, how='outer', on='SubscriptionId')\
        .merge(KPISecurityCenter, how='outer', on='SubscriptionId')\
        .merge(KPIDisk, how='outer', on='SubscriptionId')\
        .merge(KPISQLServer, how='outer', on='SubscriptionId')\
        .merge(KPISubnet, how='outer', on='SubscriptionId')\
        .merge(KPILoadBalancer, how='outer', on='SubscriptionId')\
        .merge(KPIAppGateway, how='outer', on='SubscriptionId')\
        .merge(KPICosmosDB, how='outer', on='SubscriptionId')\
        .merge(KPIFunction, how='outer', on='SubscriptionId')\
        .merge(KPIPostgreSQL, how='outer', on='SubscriptionId')\
        .merge(KPISQLServerDatabase, how='outer', on='SubscriptionId')\
        .merge(KPINSG, how='outer', on='SubscriptionId')\
        .merge(KPIDATABRICKS, how='outer', on='SubscriptionId')
            

    KPI.fillna(0, inplace=True)
    Referentiel = read_csv_from_source(container_client, 'Referentiel')
    Referentiel = Referentiel[['SubscriptionId', 'SubscriptionName', 'BU', 'EntityName', 'OrgID']]
    return (Referentiel.merge(KPI, how='left', on='SubscriptionId').set_index('SubscriptionId'), NonCompliant, Exceptions)
