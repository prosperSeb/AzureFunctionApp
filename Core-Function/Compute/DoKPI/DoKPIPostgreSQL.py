import operator
from ..Shared import *


def DoKPIPostgreSQL(container_client):
    PostgreSQL = read_csv_from_source(container_client, 'PostgreSQL')

    PostgreSQL = MergeDataBricks(container_client, PostgreSQL, 'postgreId')
    PostgreSQL = MergeException(container_client, PostgreSQL, 'postgreId')
    
    Total = TotalFromRaw(PostgreSQL, 'postgreName', 'PostgreSQL:Total')

    NonCompliant_TransitEncryption, Exceptions_TransitEncryption = NonCompliant_contains(PostgreSQL, 'postgreSSL', 'Enabled', True, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'EncryptionInTransit', 'EncryptionInTransit', natest=True)
    TransitEncryption = KPIFromNonCompliant(NonCompliant_TransitEncryption, 'PostgreSQL', 'PostgreSQL:NoEncryptionInTransit')

    PostgreSQL['postgreTLSVersion'] = PostgreSQL['postgreTLSVersion'].apply(ExtractTLSVersion)
    
    NonCompliant_TLSVersion, Exceptions_TLSVersion = NonCompliant_operator(PostgreSQL, 'postgreTLSVersion', operator.lt, 1.2, False, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'TLSVersion', 'TLSVersion')
    TLSVersion = KPIFromNonCompliant(NonCompliant_TLSVersion, 'PostgreSQL', 'PostgreSQL:BadTLSVersion')

    NonCompliant_Encryption, Exceptions_Encryption = NonCompliant_contains(PostgreSQL, 'postgreEncryption', 'Enabled', True, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'EncryptionAtRest', 'EncryptionAtRest', natest=True)
    Encryption = KPIFromNonCompliant(NonCompliant_Encryption, 'PostgreSQL', 'PostgreSQL:NoEncryptionAtRest')

    NonCompliant_Public, Exceptions_Public = NonCompliant_contains(PostgreSQL, 'postgrePublicAccess', 'Enabled', False, 'PostgreSQL', ['SubscriptionId','postgreId', 'postgreName'], 'Public', 'Public', natest=True)
    Public = KPIFromNonCompliant(NonCompliant_Public, 'PostgreSQL', 'PostgreSQL:Public')
    
    KPIPostgreSQL = Total.merge(TransitEncryption, how='left', on='SubscriptionId').merge(TLSVersion, how='left', on='SubscriptionId').merge(Encryption, how='left', on='SubscriptionId').merge(Public, how='left', on='SubscriptionId')
    NonCompliant_KPIPostgreSQL = NonCompliant_TransitEncryption.append(NonCompliant_TLSVersion, ignore_index=True).append(NonCompliant_Encryption, ignore_index=True).append(NonCompliant_Public, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIPostgreSQL = Exceptions_TransitEncryption.append(Exceptions_TLSVersion, ignore_index=True).append(Exceptions_Encryption, ignore_index=True).append(Exceptions_Public, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    return(KPIPostgreSQL, NonCompliant_KPIPostgreSQL, Exceptions_KPIPostgreSQL)
