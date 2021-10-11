import pandas as pd
import numpy as np
import logging

def DoGlobalKPI(DetailedKPI):
    ag1 = {
        'SubscriptionName' : 'count',
        'StorageAccount:Total' : 'sum', 'StorageAccount:NoHTTPS' : 'sum', 'StorageAccount:FirewallAllow' : 'sum', 'StorageAccount:Public' : 'sum', 'StorageAccount:BadTLSVersion' : 'sum', 'StorageAccount:BlobPubliclyAccessible' : 'sum', 'StorageAccount:NoSecureStorageAccess' : 'sum', 
        # 'StorageAccount:Total_2020' : 'sum', 'StorageAccount:NoHTTPS_2020' : 'sum', 'StorageAccount:FirewallAllow_2020' : 'sum', 
        'RBAC:Total' : 'sum', 'RBAC:PAA' : 'sum', 'RBAC:ENGIE' : 'sum', 'RBAC:NoENGIE' : 'sum', 'RBAC:NULL' : 'sum', 'RBAC:GoodAADGuest' : 'sum', 'RBAC:BadAADGuest' : 'sum', 'RBAC:GoodAADGuestOther' : 'sum', 'RBAC:BadAADGuestOther' : 'sum', 'RBAC:ServicePrincipal' : 'sum', 'RBAC:Owner' : 'sum', 'RBAC:Contributor' : 'sum', 'RBAC:UserAccessAdmin' : 'sum', 'RBAC:NoCertifiedUser' : 'sum', 'RBAC:NoCertifiedUserSubscription' : 'sum',
        'VM:Total' : 'sum', 'VM:PublicIP' : 'sum', 'VM:NoNSG' : 'sum', 'VM:BadNSG' : 'sum', 'VM:AccessibleInternet' : 'sum',
        'SecurityCenter:Total' : 'sum', 'SecurityCenter:Disabled' : 'sum', 'SecurityCenter:NotConfigured' : 'sum',
        'Disk:Total' : 'sum', 'Disk:EncryptionAtRest' : 'sum',
        'Subnet:Total' : 'sum', 'Subnet:AllowInbound' : 'sum',
        'SQLServer:Total' : 'sum', 'SQLServer:Public' : 'sum', 'SQLServer:BadTLSVersion' : 'sum',
        'LoadBalancer:Total' : 'sum', 'LoadBalancerRules:Total' : 'sum', 'LoadBalancer:SSHRDP' : 'sum', 'LoadBalancerRules:SSHRDP' : 'sum',
        'AppGateway:Total' : 'sum', 'AppGateway:WAFDetectionOnly' : 'sum',
        'CosmosDB:Total' : 'sum', 'CosmosDB:Public' : 'sum',
        'Function:Total' : 'sum', 'Function:NoHTTPS' : 'sum', 'Function:BadTLSVersion' : 'sum',
        'PostgreSQL:Total' : 'sum', 'PostgreSQL:NoEncryptionInTransit' : 'sum', 'PostgreSQL:BadTLSVersion' : 'sum', 'PostgreSQL:NoEncryptionAtRest' : 'sum', 'PostgreSQL:Public' : 'sum',
        'SQLServerDatabase:Total' : 'sum', 'SQLServerDatabase:NoEncyptionAtRest' : 'sum',
        'NetworkSecurityGroup:Total' : 'sum', 'NetworkSecurityGroup:LegacyProtocol' : 'sum',
    }
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
    
    
    logging.info('ManagementAccessibleFromInternet : %d', GlobalKPI['VM:ManagementAccessibleFromInternet'].sum())
    logging.info('SecurityCenter:Disabled :  %d\
                SecurityCenter:NotConfigured : %d\
                SecurityCenter:Configured : %d\
                SecurityCenter:Configured_percent : %d\
                SecurityCenter:Total : %d', GlobalKPI['SecurityCenter:Disabled'].sum(), GlobalKPI['SecurityCenter:NotConfigured'].sum(), (GlobalKPI['SecurityCenter:Total'].sum() - (GlobalKPI['SecurityCenter:NotConfigured'].sum() + GlobalKPI['SecurityCenter:Disabled'].sum())), (((GlobalKPI['SecurityCenter:NotConfigured'].sum() + GlobalKPI['SecurityCenter:Disabled'].sum()) / GlobalKPI['SecurityCenter:Total'].sum())*100), GlobalKPI['SecurityCenter:Total'].sum())

    GlobalKPI = GlobalKPI[['Subscription:Total',
    'RBAC:ENGIEAAD', 'RBAC:OtherAAD', 'RBAC:NoAAD', 'RBAC:PA', 'RBAC:PAA', 'RBAC:BadAADGuest',
    'RBAC:ServicePrincipal', 'RBAC:Owner', 'RBAC:Contributor', 'RBAC:UserAccessAdmin', 'RBAC:NoCertifiedUser', 'RBAC:NoCertifiedUserSubscription',
    'SecurityCenter:Configured_percent', 'SecurityCenter:Enabled_percent',
    'StorageAccount:HTTPS_percent', 'StorageAccount:FirewallDeny_percent',
    # 'StorageAccount:HTTPS_2020_percent', 'StorageAccount:FirewallDeny_2020_percent',
    'VM:ManagementAccessibleFromInternet', 'VM:PublicIP',
    'Disk:EncryptionAtRest_percent',
    'SQLServer:Public', 'SQLServer:ValidTLS_percent',
    'Subnet:DenyInbound_percent',
    'LoadBalancer:SSHRDP',
    'AppGateway:Firewall_percent',
    'CosmosDB:Public_percent',
    'Function:HTTPS_percent', 'Function:ValidTLS_percent',
    'PostgreSQL:EncryptionInTransit_percent', 'PostgreSQL:ValidTLS_percent', 'PostgreSQL:EncryptionAtRest_percent', 'PostgreSQL:Public_percent',
    'SQLServerDatabase:EncryptionAtRest_percent',
    'NetworkSecurityGroup:LegacyProtocol',
    ]]
    return(GlobalKPI)
