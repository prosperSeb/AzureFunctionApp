import operator
import pandas as pd
import numpy as np
from ..Shared import *


def NonCompliant_Custom(data, reverse, resource_type, fields, name, exception=None):
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

    NonCompliant_Configured, Exceptions_Configured = NonCompliant_Custom(SecurityCenter, False, 'SecuCenterMail', ['SubscriptionId','SecuCenterMail', 'SecuCenterPhone'], 'Configured', 'Configured')
    NotConfigured = KPIFromNonCompliant(NonCompliant_Configured, 'SecurityCenter', 'SecurityCenter:NotConfigured', databricks=False)

    KPISecurityCenter = Total.merge(Disabled, how='left', on='SubscriptionId').merge(NotConfigured, how='left', on='SubscriptionId')
    NonCompliant_KPISecurityCenter = NonCompliant_Enabled.append(NonCompliant_Configured, ignore_index=True)
    Exceptions_KPISecurityCenter = Exceptions_Enabled.append(Exceptions_Configured, ignore_index=True)
    return(KPISecurityCenter, NonCompliant_KPISecurityCenter, Exceptions_KPISecurityCenter)
