import operator
import pandas as pd
import numpy as np
from ..Shared import *

def NonCompliant_Custom(data, reverse, resource_type, fields, name, exception=None, split_databricks=True):
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

    NonCompliant_BlockInternet, Exceptions_BlockInternet = NonCompliant_Custom(VM, False, 'VM', ['SubscriptionId','vmId', 'vmName'], 'BlockInternet', 'BlockInternet')
    AccessibleInternet = KPIFromNonCompliant(NonCompliant_BlockInternet, 'VM', 'VM:AccessibleInternet')

    NonCompliant_BlockInternet2, Exceptions_BlockInternet2 = NonCompliant_Custom(VM_INTERFACES, False, 'VM_INTERFACES', ['SubscriptionId','vmId', 'nicPublicIP'], 'BlockInternet', 'BlockInternet')
    NonCompliant_BlockInternet = NonCompliant_BlockInternet.append(NonCompliant_BlockInternet2, ignore_index=True)


    KPIVM = Total.merge(PublicIP, how='left', on='SubscriptionId').merge(NoNSG, how='left', on='SubscriptionId').merge(BadNSG, how='left', on='SubscriptionId').merge(AccessibleInternet, how='left', on='SubscriptionId')
    NonCompliant_KPIVM = NonCompliant_NSG.append([NonCompliant_GoodNSG, NonCompliant_BlockInternet, NonCompliant_PublicIP], ignore_index=True)
    Exceptions_KPIVM = Exceptions_NSG.append([Exceptions_GoodNSG, Exceptions_BlockInternet, Exceptions_PublicIP], ignore_index=True)
    return(KPIVM, NonCompliant_KPIVM, Exceptions_KPIVM)
