from ..Shared import *


def DoKPIAppGateway(container_client):
    AppGateway = read_csv_from_source(container_client, 'AppGateway')
    
    AppGateway = MergeDataBricks(container_client, AppGateway, 'AppGatewayId')
    AppGateway = MergeException(container_client, AppGateway, 'AppGatewayId')

    Total = TotalFromRaw(AppGateway, 'AppGatewayName', 'AppGateway:Total')
    
    # NonCompliant_Firewall, Exceptions_Firewall = NonCompliant_isnull(AppGateway, 'FirewallMode', False, 'AppGateway', ['SubscriptionId','AppGatewayId', 'AppGatewayName'], 'Firewall', 'Firewall')
    # Firewall = NonCompliant_Firewall.groupby('SubscriptionId')['NonCompliant'].count().reset_index(name='AppGateway:WAFDetectionOnly')

    AppGatewayWAF = AppGateway.loc[~(AppGateway['FirewallMode'].isnull())]
    Total_waf = TotalFromRaw(AppGatewayWAF, 'AppGatewayName', 'AppGateway:Total_waf')

    NonCompliant_Firewall, Exceptions_Firewall = NonCompliant_contains(AppGateway, 'FirewallMode', 'Prevention', True, 'AppGateway', ['SubscriptionId','AppGatewayId', 'AppGatewayName'], 'WAFDectionOnly', 'WAFDectionOnly', natest=True)
    Firewall = KPIFromNonCompliant(NonCompliant_Firewall, 'AppGateway', 'AppGateway:WAFDetectionOnly')

    KPIAppGateway = Total.merge(Total_waf, how='left', on='SubscriptionId').merge(Firewall, how='left', on='SubscriptionId').fillna(0)
    NonCompliant_KPIAppGateway = NonCompliant_Firewall
    Exceptions_KPIAppGateway = Exceptions_Firewall
    return(KPIAppGateway, NonCompliant_KPIAppGateway, Exceptions_KPIAppGateway)
