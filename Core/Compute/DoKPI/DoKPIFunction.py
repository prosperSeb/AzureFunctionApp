import operator
from ..Shared import *


def DoKPIFunction(container_client):
    Function = read_csv_from_source(container_client, 'Function')

    Function = MergeDataBricks(container_client, Function, 'FunctionId')
    Function = MergeException(container_client, Function, 'FunctionId')

    Total = TotalFromRaw(Function, 'FunctionName', 'Function:Total')

    NonCompliant_HTTPS, Exceptions_HTTPS = NonCompliant_operator(Function, 'HttpsOnly', operator.eq, False, False, 'Function', ['SubscriptionId','FunctionId', 'FunctionName'], 'HTTPS', 'HTTPS')
    HTTPS = KPIFromNonCompliant(NonCompliant_HTTPS, 'Function', 'Function:NoHTTPS')

    Function = Function.fillna({'FunctionTLSVersion': 0.0})
    NonCompliant_TLSVersion, Exceptions_TLSVersion = NonCompliant_operator(Function, 'FunctionTLSVersion', operator.lt, 1.2, False, 'Function', ['SubscriptionId','FunctionId', 'FunctionName'], 'TLSVersion', 'TLSVersion')
    TLSVersion = KPIFromNonCompliant(NonCompliant_TLSVersion, 'Function', 'Function:BadTLSVersion')

    KPIFunction = Total.merge(HTTPS, how='left', on='SubscriptionId').merge(TLSVersion, how='left', on='SubscriptionId')
    NonCompliant_KPIFunction = NonCompliant_HTTPS.append(NonCompliant_TLSVersion, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIFunction = Exceptions_HTTPS.append(Exceptions_TLSVersion, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPIFunction, NonCompliant_KPIFunction, Exceptions_KPIFunction)
