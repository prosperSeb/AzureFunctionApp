from ..Shared import *


def DoKPIDataBricks(container_client):
    DataBricks = read_csv_from_source(container_client, 'Databricks')
    
    DataBricks.dropna(subset=['SubscriptionId'],inplace=True)

    Exceptions_tab=MergeExceptionDataBricks(container_client,DataBricks,'DataBricksId')
    
    NonCompliant,Exceptions=NonCompliantDatabricks(Exceptions_tab)

    data = DataBricks[(DataBricks['DataBricksNoPublicIP'] == False)]

    output=data.groupby(['SubscriptionId'])['DataBricksNoPublicIP'].count().reset_index(name='DataBricks:' + 'NoPublicIP:Total')
    
    return (output,NonCompliant,Exceptions)
    #return output
