from ..Shared import *


def DoKPISQLServerDatabase(container_client):
    SQLServerDatabase = read_csv_from_source(container_client, 'SQLServerDatabase')

    SQLServerDatabase = MergeDataBricks(container_client, SQLServerDatabase, 'DBId')
    SQLServerDatabase = MergeException(container_client, SQLServerDatabase, 'DBId')

    SQLServerDatabase =  SQLServerDatabase.loc[(SQLServerDatabase['DBName'] != 'master')]

    Total = TotalFromRaw(SQLServerDatabase, 'DBName', 'SQLServerDatabase:Total')

    NonCompliant_Encryption, Exceptions_Encryption = NonCompliant_contains(SQLServerDatabase, 'DataTransEncry', 'Enabled', True, 'SQLServerDatabase', ['SubscriptionId','DBId', 'DBName'], 'EncryptionAtRest', 'EncryptionAtRest')
    Encyption = KPIFromNonCompliant(NonCompliant_Encryption, 'SQLServerDatabase', 'SQLServerDatabase:NoEncyptionAtRest')

    KPISQLServerDatabase = Total.merge(Encyption, how='left', on='SubscriptionId')
    NonCompliant_KPISQLServerDatabase = NonCompliant_Encryption#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPISQLServerDatabase = Exceptions_Encryption#.append(NonCompliant_x, ignore_index=True)
    return(KPISQLServerDatabase, NonCompliant_KPISQLServerDatabase, Exceptions_KPISQLServerDatabase)
