import operator
from ..Shared import *


def DoKPISQLServer(container_client):
    SQLServer = read_csv_from_source(container_client, 'SQLServer')

    SQLServer = MergeDataBricks(container_client, SQLServer, 'sqlServerId')  
    SQLServer = MergeException(container_client, SQLServer, 'sqlServerId')

    Total = TotalFromRaw(SQLServer, 'sqlServerName', 'SQLServer:Total')

    NonCompliant_Private, Exceptions_Private = NonCompliant_contains(SQLServer, 'sqlServerAccess', 'Enabled', False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'Public', 'Public', natest=True)
    Public = KPIFromNonCompliant(NonCompliant_Private, 'SQLServer', 'SQLServer:Public')

    SQLServer = SQLServer.fillna({'sqlServerTLS': 0.0})
    NonCompliant_TLS, Exceptions_TLS = NonCompliant_operator(SQLServer, 'sqlServerTLS', operator.lt, 1.2, False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'TLSVersion', 'TLSVersion')
    # NonCompliant_TLS, Exceptions_TLS = NonCompliant_operator(SQLServer, 'sqlServerAcTLS', operator.lt, 1.2, False, 'SQLServer', ['SubscriptionId','sqlServerId', 'sqlServerName'], 'TLSVersion', 'TLSVersion')
    TLS = KPIFromNonCompliant(NonCompliant_TLS, 'SQLServer', 'SQLServer:BadTLSVersion')
    
    KPISQLServer = Total.merge(Public, how='left', on='SubscriptionId').merge(TLS, how='left', on='SubscriptionId')
    NonCompliant_KPISQLServer = NonCompliant_Private.append(NonCompliant_TLS, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPISQLServer = Exceptions_Private.append(Exceptions_TLS, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPISQLServer, NonCompliant_KPISQLServer, Exceptions_KPISQLServer)
