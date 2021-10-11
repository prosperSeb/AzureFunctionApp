from io import StringIO
import pandas as pd
import numpy as np

#Filetype values :
# Referentiel,Keyvault,NSG,PublicIP,RBAC,SecurityCenter,StorageAccount,VM,Vnet
def Get_FileName(container_client, FileType):
# Get latest filename for the FileType category
    if (FileType == 'Referentiel'):
        return('ReferentielSubAzure.csv')
    for report_type in container_client.walk_blobs(name_starts_with=FileType, delimiter="/"):
        if (FileType + 'Report' in report_type.name):
            savedname = report_type.name
            for report_date in container_client.walk_blobs(name_starts_with=report_type.name, delimiter="/"):
                pass
    Filename = ("Azure-%s.csv") % savedname[:-7]
    Output = "%s%s" % (report_date.name, Filename)
    return(Output)

Storage_cache = {}

def read_csv_from_source(container_client, FileType):
    if FileType in Storage_cache:
        return ((pd.read_csv(StringIO(Storage_cache[FileType]), sep=';', error_bad_lines=False, encoding='utf8')).dropna(how='all'))
    filename = Get_FileName(container_client, FileType)
    obj = container_client.download_blob(filename, encoding='UTF-8')
    csv_string = obj.content_as_text()
    output = pd.read_csv(StringIO(csv_string), sep=';', error_bad_lines=False, encoding='utf8')
    Storage_cache[FileType] = csv_string
    return (output.dropna(how='all'))
