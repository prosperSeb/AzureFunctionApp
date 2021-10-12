import operator
import pandas as pd
from ..Shared import *

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
