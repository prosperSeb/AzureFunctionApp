import pandas as pd
import numpy as np
import sys

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.width', 9000)
pd.set_option('display.max_colwidth', 9000)
# data : DataFrame(Panda)
# field : Field to test (str)
# value : Value to test (any)
# reverse : True to reverse the check (bool)
# resource_type : Ressource Type (str)
# fields : Columns name of subid, DdorGroup, Name (str[3])
# name : Name of the fail (str)

def NonCompliant_init(data, field, fields, name, exception, split_databricks):
    if (data.size > 0):
        #Add Exceptions if exist in data or nothing (duplicated field will be removed)
        fields_array = set(fields + [field, 'Exceptions' if 'Exceptions' in data.columns else field])
        if (split_databricks == True and 'DataBricksId' in data.columns):
            fields_array.add('DataBricksId')
        mod_data = data[fields_array].copy()
        if (exception is not None) and ('Exceptions' in mod_data.columns):
            mod_data[name + ':Exception'] = data['Exceptions'].str.contains('(^|:)' + exception + '(:|$)', regex=True, na=False, case=False)
        else:
            mod_data[name + ':Exception'] = False
        return mod_data
    else:
        return None

def NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, split_databricks):
    if ('DataBricksId' in mod_data.columns):
        fields.append('DataBricksId')
    if (split_databricks == True and 'DataBricksId' in mod_data.columns ):
        NonCompliant_data_Databricks = NonCompliant_data.loc[(~pd.isna(NonCompliant_data['DataBricksId']))]
        NonCompliant_data = NonCompliant_data.loc[(pd.isna(NonCompliant_data['DataBricksId']))]
        mod_data_Databricks = mod_data.loc[(~pd.isna(mod_data['DataBricksId']))]
        mod_data = mod_data.loc[(pd.isna(mod_data['DataBricksId']))]

    NonCompliant_data = NonCompliant_data[fields]
    NonCompliant_data['Type'] = resource_type
    NonCompliant_data['NonCompliant'] = name
    if ('DataBricksId' in mod_data.columns):
        NonCompliant_data.drop(columns=['DataBricksId'], inplace=True)
    NonCompliant_data.columns = ['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']     

    Exceptions_data = mod_data[fields + [name + ':Exception']]
    Exceptions_data = Exceptions_data.loc[(Exceptions_data[name + ':Exception'] == True)]
    Exceptions_data.drop(columns=[name + ':Exception'], inplace=True)
    Exceptions_data['Type'] = resource_type
    Exceptions_data['Exception'] = exception
    if ('DataBricksId' in mod_data.columns):
        Exceptions_data.drop(columns=['DataBricksId'], inplace=True)
    Exceptions_data.columns = ['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception']
    
    if (split_databricks == True and 'DataBricksId' in mod_data.columns ):
        NonCompliant_data_Databricks = NonCompliant_data_Databricks[fields]
        NonCompliant_data_Databricks['Type'] = 'DataBricks:' + resource_type
        NonCompliant_data_Databricks['NonCompliant'] = name
        NonCompliant_data_Databricks.drop(columns=['DataBricksId'], inplace=True)
        NonCompliant_data_Databricks.columns = ['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']
        NonCompliant_data = NonCompliant_data.append(NonCompliant_data_Databricks)
        Exceptions_data_Databricks = mod_data_Databricks[fields + [name + ':Exception']]
        Exceptions_data_Databricks = Exceptions_data_Databricks.loc[(Exceptions_data_Databricks[name + ':Exception'] == True)]
        Exceptions_data_Databricks.drop(columns=[name + ':Exception'], inplace=True)
        Exceptions_data_Databricks['Type'] = 'DataBricks:' + resource_type
        Exceptions_data_Databricks['Exception'] = exception
        Exceptions_data_Databricks.drop(columns=['DataBricksId'], inplace=True)
        Exceptions_data_Databricks.columns = ['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception']
        Exceptions_data = Exceptions_data.append(Exceptions_data_Databricks)

    return (NonCompliant_data, Exceptions_data)

def NonCompliant_contains(data, field, value, reverse, resource_type, fields, name, exception=None, natest=False, case=False, split_databricks=True):
    mod_data = NonCompliant_init(data, field, fields, name, exception, split_databricks)
    if mod_data is None:
        return pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']), pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception'])
    NonCompliant_data = mod_data.loc[mod_data[name + ':Exception'] == False]
    export_fields = fields
    if ('DataBricksId' in mod_data.columns):
        export_fields = set(fields + ['DataBricksId'])
    if reverse:
        NonCompliant_data = NonCompliant_data.loc[~(NonCompliant_data[field].str.contains(value, case=case, regex=True, na=natest))][export_fields]
    else:
        NonCompliant_data = NonCompliant_data.loc[(NonCompliant_data[field].str.contains(value, case=case, regex=True, na=natest))][export_fields]
    return NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, split_databricks)

def NonCompliant_isnull(data, field, reverse, resource_type, fields, name, exception=None, split_databricks=True):
    mod_data = NonCompliant_init(data, field, fields, name, exception, split_databricks)
    if mod_data is None:
        return pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']), pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception'])
    NonCompliant_data = mod_data.loc[mod_data[name + ':Exception'] == False]
    export_fields = fields
    if ('DataBricksId' in mod_data.columns):
        export_fields = set(fields + ['DataBricksId'])
    if reverse:
        NonCompliant_data = NonCompliant_data.loc[~(NonCompliant_data[field].isnull())][export_fields]
    else:
        NonCompliant_data = NonCompliant_data.loc[(NonCompliant_data[field].isnull())][export_fields]
    return NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, split_databricks)

def NonCompliant_operator(data, field, operator, value, reverse, resource_type, fields, name, exception=None, split_databricks=True):
    mod_data = NonCompliant_init(data, field, fields, name, exception, split_databricks)
    if mod_data is None:
        return pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'NonCompliant']), pd.DataFrame(columns=['SubscriptionId','ResourceIdorGroup', 'Name', 'ResourceType', 'Exception'])
    NonCompliant_data = mod_data.loc[mod_data[name + ':Exception'] == False]
    export_fields = fields
    if ('DataBricksId' in mod_data.columns):
        export_fields = set(fields + ['DataBricksId'])
    if reverse:
        NonCompliant_data = NonCompliant_data.loc[~(operator(NonCompliant_data[field], value))][export_fields]
    else:
        NonCompliant_data = NonCompliant_data.loc[(operator(NonCompliant_data[field], value))][export_fields]
    return NonCompliant_return(resource_type, fields, name, exception, mod_data, NonCompliant_data, split_databricks)


def NonCompliantDatabricks(data):
    NonCompliantData=data
    NonCompliantData=NonCompliantData.rename(columns={'DataBricksId':'ResourceIdorGroup','DataBricksName':'Name'})[['SubscriptionId','ResourceIdorGroup','Name','Exceptions','DataBricksNoPublicIP']]
    NonCompliantData['ResourceType'] = pd.Series(["Databricks" for x in range(len(NonCompliantData.index))])
    NonCompliantData['NonCompliant'] = pd.Series(["PublicIP" for x in range(len(NonCompliantData.index))])

    Exceptions = NonCompliantData[(NonCompliantData['DataBricksNoPublicIP']==False)&(NonCompliantData['Exceptions']!=':nan')][['SubscriptionId','ResourceIdorGroup','Name','ResourceType']]
    NonCompliantData=NonCompliantData[(NonCompliantData['DataBricksNoPublicIP']==False)&(NonCompliantData['Exceptions']==':nan')][['SubscriptionId','ResourceIdorGroup','Name','ResourceType','NonCompliant']]

    return(NonCompliantData.reset_index(drop=True),Exceptions.reset_index(drop=True))
