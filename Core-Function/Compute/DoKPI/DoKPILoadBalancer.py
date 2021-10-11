import operator
import pandas as pd
from ..Shared import *

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
