import pandas as pd
import numpy as np
import re
from .read_csv_from_source import read_csv_from_source
import sys

#Expected fromat TLS{X}_{Y} where {X} and {Y} are number
def ExtractTLSVersion(Data):
    if (pd.isnull(Data)):
        return (0.0)
    tmp = re.findall(r'TLS(\d+)_(\d+)', Data)
    if (len(tmp) == 1):
        tmp = [".".join(x) for x in tmp][0]
    else:
        return (0.0)
    return(float(tmp))

def RangesContainPort(data, Target):
    if ("*" in data):
        return (True)
    if (data == str(Target)):
        return (True)
    array = data.split(',')
    if (str(Target) in array):
        return (True)
    for item in array:
        if ('-' in item):
            try:
                Range = [int(n) for n in item.split("-")]
                if (Range[0] <= Target and Target <= Range[1]):
                    return (True)
            except:
                pass
    return (False)

def MergeException(container_client, data, id_field):
    Exceptions = read_csv_from_source(container_client, 'Exceptions')[['ResourceId', 'TestName']]

    Exceptions = Exceptions.groupby('ResourceId')['TestName'].apply(lambda x: ':'.join(x)).reset_index()
    Exceptions['Exceptions_ResourceId'] = Exceptions['ResourceId'].str.lower()
    Exceptions = Exceptions.drop(columns=['ResourceId'])
    data[id_field + '_lower'] = data[id_field].str.lower()
    data = data.merge(Exceptions, how='left', left_on=id_field + '_lower', right_on='Exceptions_ResourceId')
    data.fillna({'TestName': ''}, inplace=True)
    data = data.drop(columns=[id_field + '_lower', 'Exceptions_ResourceId'])
    if 'DataBricksId' in data.columns:
        Exceptions.rename(columns={"TestName": "TestNameDataBricks"}, inplace=True)
        data['DataBricksId' + '_lower'] = data['DataBricksId'].str.lower()
        data = data.merge(Exceptions, how='left', left_on='DataBricksId' + '_lower', right_on='Exceptions_ResourceId')
        data.fillna({'TestNameDataBricks': ''}, inplace=True)
        data = data.drop(columns=['DataBricksId' + '_lower', 'Exceptions_ResourceId'])
    else:
        data['TestNameDataBricks']= np.nan
    data['Exceptions'] = data[['TestName', 'TestNameDataBricks']].apply(lambda row: ':'.join(row.values.astype(str)), axis=1)
    data = data.drop(columns=['TestName', 'TestNameDataBricks'])
    return (data)

def MergeDataBricks(container_client, data, id_field):
    DataBricks = read_csv_from_source(container_client, 'Databricks')[['DataBricksId', 'DataBricksNoPublicIP', 'managedResourceGroupId']]

    DataBricks['managedResourceGroupId'] = DataBricks['managedResourceGroupId'].str.lower()
    data[id_field + '_lower'] = data[id_field].apply(lambda x: (('/'.join((x.lower().split('/')[:5])))))
    data = data.merge(DataBricks, how='left', left_on=id_field + '_lower', right_on='managedResourceGroupId')
    data = data.drop(columns=[id_field + '_lower'])
    return (data)

def KPIFromData(data, value, resource_type, outputstring, databricks = True):
    if (databricks):
        data_kpi = data.loc[(data['ResourceType'] == (resource_type))]
        data_kpi_databricks = data.loc[(data['ResourceType'] == ('DataBricks:' + resource_type))]
        output2 = data_kpi_databricks.groupby('SubscriptionId')[value].count().reset_index(name='DataBricks:' + outputstring)
        output = data_kpi.groupby('SubscriptionId')[value].count().reset_index(name=outputstring)
        output = output.merge(output2, how='outer', on='SubscriptionId')
    else:
        output = data.groupby('SubscriptionId')[value].count().reset_index(name=outputstring)
    return output

def KPIFromNonCompliant(data, resource_type, outputstring, databricks = True):
    return KPIFromData(data, 'NonCompliant', resource_type, outputstring, databricks)

def TotalFromRaw(data, value, outputstring, databricks = True):
    if (databricks):
        data_kpi = data.loc[pd.isna(data['DataBricksId'])]
        data_kpi_databricks = data.loc[~pd.isna(data['DataBricksId'])]
        output2 = data_kpi_databricks.groupby('SubscriptionId')[value].count().reset_index(name='DataBricks:' + outputstring)
        output = data_kpi.groupby('SubscriptionId')[value].count().reset_index(name=outputstring)
        output = output.merge(output2, how='outer', on='SubscriptionId')
    else:
        output = data.groupby('SubscriptionId')[value].count().reset_index(name=outputstring)
    return output

def MergeExceptionDataBricks(container_client,data, id_field):
    Exceptions = read_csv_from_source(container_client, 'Exceptions')[['ResourceId', 'TestName']]
    Exceptions = Exceptions.groupby('ResourceId')['TestName'].apply(lambda x: ':'.join(x)).reset_index()
    Exceptions['Exceptions_ResourceId'] = Exceptions['ResourceId'].str.lower()
    Exceptions = Exceptions.drop(columns=['ResourceId'])
    data[id_field + '_lower'] = data[id_field].str.lower()
    data = data.merge(Exceptions, how='left', left_on=id_field + '_lower', right_on='Exceptions_ResourceId')
    data.fillna({'TestName': ''}, inplace=True)
    data = data.drop(columns=[id_field + '_lower', 'Exceptions_ResourceId'])
    data['TestNameDataBricks']= np.nan
    data['Exceptions'] = data[['TestName', 'TestNameDataBricks']].apply(lambda row: ':'.join(row.values.astype(str)), axis=1)
    data = data.drop(columns=['TestName', 'TestNameDataBricks'])
    return (data)