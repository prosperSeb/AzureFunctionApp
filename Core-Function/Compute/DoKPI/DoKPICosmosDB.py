from ..Shared import *


def DoKPICosmosDB(container_client):
    CosmosDB = read_csv_from_source(container_client, 'CosmosDB')
    
    CosmosDB = MergeDataBricks(container_client, CosmosDB, 'CosmosDBId')
    CosmosDB = MergeException(container_client, CosmosDB, 'CosmosDBId')

    Total = TotalFromRaw(CosmosDB, 'CosmosDBName', 'CosmosDB:Total')

    NonCompliant_Private, Exceptions_Private = NonCompliant_contains(CosmosDB, 'CosmosDBPublicAccess', 'Enabled', False, 'CosmosDB', ['SubscriptionId','CosmosDBId', 'CosmosDBName'], 'Public', 'Public')
    Public = KPIFromNonCompliant(NonCompliant_Private, 'CosmosDB', 'CosmosDB:Public')

    KPICosmosDB = Total.merge(Public, how='left', on='SubscriptionId')
    NonCompliant_KPICosmosDB = NonCompliant_Private#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPICosmosDB = Exceptions_Private#.append(NonCompliant_x, ignore_index=True)
    return(KPICosmosDB, NonCompliant_KPICosmosDB, Exceptions_KPICosmosDB)
