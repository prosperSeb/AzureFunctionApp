import operator
import pandas as pd
from ..Shared import *

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
