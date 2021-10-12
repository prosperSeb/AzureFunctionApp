import operator
import numpy as np
import pandas as pd
import datetime
import operator
from ..Shared import *
import sys

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
    
    KPIStorageAccount = Total.merge(NoHTTPS, how='left', on='SubscriptionId')\
        .merge(FirewallAllow, how='left', on='SubscriptionId')\
        .merge(Public, how='left', on='SubscriptionId')\
        .merge(TLSVersion, how='left', on='SubscriptionId')\
        .merge(BlobPublicAccess, how='left', on='SubscriptionId')\
        .merge(SecureStorageAccess, how='left', on='SubscriptionId')
        # .merge(Total_2020, how='left', on='SubscriptionId')\
        # .merge(NoHTTPS_2020, how='left', on='SubscriptionId')\
        # .merge(FirewallAllow_2020, how='left', on='SubscriptionId')
    NonCompliant_KPIStorageAccount = NonCompliant_HTTPS.append(NonCompliant_Firewall, ignore_index=True).append(NonCompliant_Public, ignore_index=True).append(NonCompliant_TLSVersion, ignore_index=True).append(NonCompliant_BlobPublicAccess, ignore_index=True).append(NonCompliant_SecureStorageAccess, ignore_index=True)#.append(NonCompliant_HTTPS_2020, ignore_index=True).append(NonCompliant_Firewall_2020, ignore_index=True)
    Exceptions_KPIStorageAccount = Exceptions_HTTPS.append(Exceptions_Firewall, ignore_index=True).append(Exceptions_Public, ignore_index=True).append(Exceptions_TLSVersion, ignore_index=True).append(Exceptions_BlobPublicAccess, ignore_index=True).append(Exceptions_SecureStorageAccess, ignore_index=True)#.append(Exceptions_HTTPS_2020, ignore_index=True).append(Exceptions_Firewall_2020, ignore_index=True)
    return(KPIStorageAccount, NonCompliant_KPIStorageAccount, Exceptions_KPIStorageAccount)
