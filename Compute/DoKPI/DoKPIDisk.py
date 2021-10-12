from ..Shared import *


def DoKPIDisk(container_client):
    Disk = read_csv_from_source(container_client, 'Disk')

    Disk = MergeDataBricks(container_client, Disk, 'diskId')
    Disk = MergeException(container_client, Disk, 'diskId')

    Total =  TotalFromRaw(Disk, 'diskName', 'Disk:Total')
    NonCompliant_EncryptionAtRest, Exceptions_EncryptionAtRest = NonCompliant_contains(Disk, 'diskEncryption', '.*EncryptionAtRest.*', True, 'Disk', ['SubscriptionId','diskId', 'diskName'], 'EncryptionAtRest', 'EncryptionAtRest')
    Encryption = KPIFromNonCompliant(NonCompliant_EncryptionAtRest, 'Disk', 'Disk:NoEncryptionAtRest')

    KPIDisk = Total.merge(Encryption, how='left', on='SubscriptionId').fillna(0)
    KPIDisk['Disk:EncryptionAtRest'] = KPIDisk['Disk:Total'] - KPIDisk['Disk:NoEncryptionAtRest'] - KPIDisk['DataBricks:Disk:NoEncryptionAtRest']
    NonCompliant_KPIDisk = NonCompliant_EncryptionAtRest#.append(NonCompliant_x, ignore_index=True)
    Exceptions_KPIDisk = Exceptions_EncryptionAtRest#.append(Exceptions_x, ignore_index=True)
    return(KPIDisk, NonCompliant_KPIDisk, Exceptions_KPIDisk)
