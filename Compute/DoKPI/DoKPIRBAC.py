from ..Shared import *
import pandas as pd
import numpy as np
import operator

def ExtractPA(data):
    if (pd.isnull(data)):
        return
    if ('engie.com' in data):
        return(data[0:6].upper())
    return 

def DoKPIRBAC(container_client):
    RBAC = read_csv_from_source(container_client, 'RBAC')
    Referentiel = read_csv_from_source(container_client, 'Referentiel')
    Certified = read_csv_from_source(container_client, 'Certified')
    AADGroup = read_csv_from_source(container_client, 'AADGroup')
    Referentiel = Referentiel[['SubscriptionId', 'TenantId', 'TenantDisplayName']]
    
    #Exceptions : nos 2 comptes
    #Type; filtrer Group / ServicePrincipal
    #AADGuest : #EXT#@engie.onmicrosoft.com or KO

    AADGroup = AADGroup.drop(columns=['SubscriptionId']).drop_duplicates()
    # RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['ServicePrincipal'])))]
    RBAC_Groups = RBAC.loc[(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['Group'])))]
    RBAC_Groups = RBAC_Groups.merge(AADGroup[['GroupObjectId', 'UserObjectId', 'DisplayName', 'UserPrincipalName']], how='left', left_on='rbacObjectId', right_on='GroupObjectId')
    RBAC_Groups['Source'] = RBAC_Groups['rbacDisplayName']
    RBAC_Groups.drop(columns=['rbacSignInName', 'rbacDisplayName', 'rbacObjectId', 'GroupObjectId'], inplace=True)
    RBAC_Groups.rename(columns={'UserObjectId' : 'rbacObjectId', 'DisplayName' : 'rbacDisplayName', 'UserPrincipalName' : 'rbacSignInName'}, inplace=True)
    RBAC_Groups['rbacObjectType'] = 'User'
    RBAC_Groups['rbacAccountType'] = np.where(RBAC_Groups['rbacSignInName'].str.contains('-A', na=False), "PAA", "PA")
    RBAC = RBAC.append(RBAC_Groups, ignore_index=True)
    RBAC = RBAC.loc[~(RBAC['rbacObjectType'].str.contains('|'.join(['Group', 'ServicePrincipal'])))]
    RBAC = RBAC.merge(Referentiel, how='left', on='SubscriptionId')

    RBAC['rbacId'] = RBAC.apply(lambda row: (('/subscriptions/%s/%s/%s') % (row.SubscriptionId, row.rbacSignInName, row.rbacRoleName)), axis = 1)
    RBAC = MergeException(container_client, RBAC, 'rbacId')
    RBAC.loc[(RBAC['rbacSignInName'].str.contains('|'.join(['YZGL74@engie.com', 'ZMWX70@engie.com', r'YZGL74_engie\.com#EXT#.*', r'ZMWX70_engie\.com#EXT#.*']), case=False, na=False)), 'Exceptions'] = 'PAA-Access:Engie:NotNull:AADGuest:AADGuestOther:CertifiedUser:CertifiedUserSubscription:EXTotal'

    RBAC['PA'] = RBAC['rbacSignInName'].apply(ExtractPA)
    RBAC = RBAC.merge(Certified, how='left', on='PA')

    Total = RBAC.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total')
    TotalUser = RBAC.drop_duplicates(subset=['SubscriptionId', 'rbacSignInName']).groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total-User')
    TotalEXT = RBAC.loc[(RBAC['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))].groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:TotalEXT')
    
    ###KPI TenantId Managed
    # 24139d14-c62c-4c47-8bdd-ce71ea1d50cf (TenantId ENGIE)
    # d3f760fe-d4e9-4891-b0ef-4af359897813 (TenantId ENGIE ?)
    Targets_managed = ['24139d14-c62c-4c47-8bdd-ce71ea1d50cf']#, 'd3f760fe-d4e9-4891-b0ef-4af359897813']
    RBAC_managed = RBAC.loc[(RBAC['TenantId'].isin(Targets_managed))]
    Total_managed = RBAC_managed.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total_managed')

    #|(ADM-.*) removed from regex
    NonCompliant_PAA, Exceptions_PAA = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacId', 'rbacDisplayName'], 'PAA-Access', 'PAA-Access', natest=True)
    NoPAA = KPIFromNonCompliant(NonCompliant_PAA, 'RBAC', 'RBAC:NoPAA', databricks=False)

    s = RBAC_managed.Exceptions.str.len().sort_values().index
    RBAC_managed_USERS = RBAC_managed.reindex(s).reset_index(drop=True).drop_duplicates(subset=['SubscriptionId', 'rbacSignInName'], ignore_index=True)
    NonCompliant_PAA_Users, Exceptions_PAA_Users = NonCompliant_contains(RBAC_managed_USERS, 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'PAA-User', 'PAA-Access', natest=True)
    NoPAA_Users = KPIFromNonCompliant(NonCompliant_PAA_Users, 'RBAC', 'RBAC:NoPAA-User', databricks=False)

    NonCompliant_Engie, Exceptions_Engie = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'.*@engie\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'Engie', 'Engie', natest=True)
    NoEngie = KPIFromNonCompliant(NonCompliant_Engie, 'RBAC', 'RBAC:NoENGIE', databricks=False)

    NonCompliant_AADGuest_managed, Exceptions_AADGuest_managed = NonCompliant_contains(RBAC_managed, 'rbacSignInName', r'.*#EXT#.*', False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'AADGuest', 'AADGuest', natest=False)
    BadAADGuest_managed = KPIFromNonCompliant(NonCompliant_AADGuest_managed, 'RBAC', 'RBAC:BadAADGuest', databricks=False)

    
    Powerusers_roles = ['Owner', 'Contributor', 'User Access Administrator']
    RBAC_powerusers = RBAC.loc[(RBAC['rbacRoleName'].isin(Powerusers_roles))]
    RBAC_powerusers = RBAC_powerusers.drop_duplicates(subset=['SubscriptionId', 'PA'])
    Total_powerusers = RBAC_powerusers.groupby('SubscriptionId')['rbacRoleName', 'Exceptions'].apply(lambda x: ((~(x['Exceptions'].str.contains(r'(^|:)EXTotal(:|$)', regex=True, na=False)))).sum()).reset_index(name='RBAC:Total_powerusers')
    RBAC_powerusers = RBAC_powerusers.fillna({'CertificationLevelAzure': '0'})
    RBAC_powerusers['CertificationLevelAzure'] = pd.to_numeric(RBAC_powerusers['CertificationLevelAzure'].str.replace(',', '.', regex=False))
    NonCompliant_CertifiedUser, Exceptions_CertifiedUser = NonCompliant_operator(RBAC_powerusers, 'CertificationLevelAzure', operator.lt, 0.5, False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'CertifiedUser', 'CertifiedUser')
    NonCompliant_CertifiedUser = NonCompliant_CertifiedUser.drop_duplicates(ignore_index=True)
    NoCertifiedUser = KPIFromNonCompliant(NonCompliant_CertifiedUser, 'RBAC', 'RBAC:NoCertifiedUser', databricks=False)

    RBAC_powerusers = RBAC_powerusers.groupby('SubscriptionId')['CertificationLevelAzure'].sum().reset_index(name='CertificationLevelAggregated')
    RBAC_powerusers = RBAC_powerusers.merge(RBAC[['SubscriptionId']].drop_duplicates(subset=['SubscriptionId']), how='right')
    RBAC_powerusers['rbacSignInName'] = 'CurrentSubscription'
    RBAC_powerusers['rbacDisplayName'] = 'PrivilegedUsers'

    NonCompliant_CertifiedUserSubscription, Exceptions_CertifiedUserSubscription = NonCompliant_operator(RBAC_powerusers, 'CertificationLevelAggregated', operator.lt, 0.5, False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'CertifiedUserSubscription', 'CertifiedUserSubscription')
    NoCertifiedUserSubscription = KPIFromNonCompliant(NonCompliant_CertifiedUserSubscription, 'RBAC', 'RBAC:NoCertifiedUserSubscription', databricks=False)

    NonCompliant_NotNull, Exceptions_NotNull = NonCompliant_isnull(RBAC, 'rbacSignInName', False, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'NotNull', 'EXNotNull')
    NULL = KPIFromNonCompliant(NonCompliant_NotNull, 'RBAC', 'RBAC:NULL', databricks=False)

    RBAC_Other = RBAC.loc[~(RBAC['TenantId'].isin(Targets_managed))]
    NonCompliant_AADGuest, Exceptions_AADGuest = NonCompliant_contains(RBAC_Other.loc[(RBAC_Other['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'.*_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'AADGuestOther', 'AADGuestOther', natest=False)
    BadAADGuest = KPIFromNonCompliant(NonCompliant_AADGuest, 'RBAC', 'RBAC:BadAADGuestOther', databricks=False)
    
    NonCompliant_PAAOther, Exceptions_PAAOther = NonCompliant_contains(RBAC_Other.loc[(RBAC_Other['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacId', 'rbacDisplayName'], 'PAA-Access', 'PAA-Access', natest=False)
    NoPAAOther = KPIFromNonCompliant(NonCompliant_PAAOther, 'RBAC', 'RBAC:NoPAA', databricks=False)

    s = RBAC_Other.Exceptions.str.len().sort_values().index
    RBAC_Other_USERS = RBAC_Other.reindex(s).reset_index(drop=True).drop_duplicates(subset=['SubscriptionId', 'rbacSignInName'], ignore_index=True)
    NonCompliant_PAAOther_Users, Exceptions_PAAOther_Users = NonCompliant_contains(RBAC_Other_USERS.loc[(RBAC_Other_USERS['rbacSignInName'].str.contains(r'.*#EXT#.*', na=False))], 'rbacSignInName', r'[A-Z-0-9]{6}-[A-Z]_engie\.com#EXT#@.*\.onmicrosoft\.com$', True, 'RBAC', ['SubscriptionId','rbacSignInName', 'rbacDisplayName'], 'PAA-User', 'PAA-Access', natest=False)
    NoPAAOther_Users = KPIFromNonCompliant(NonCompliant_PAAOther_Users, 'RBAC', 'RBAC:NoPAA-User', databricks=False)


    NonCompliant_AADGuest = NonCompliant_AADGuest.append(NonCompliant_AADGuest_managed, ignore_index=True)
    Exceptions_AADGuest = Exceptions_AADGuest.append(Exceptions_AADGuest_managed, ignore_index=True)

    BadAADGuest = BadAADGuest.append(BadAADGuest_managed, ignore_index=True)

    # NonCompliant_PAA = NonCompliant_PAA.append(NonCompliant_PAAOther, ignore_index=True)
    # NonCompliant_PAA['NonCompliant'] = 'PAA-Access'
    # NonCompliant_PAA_Users = NonCompliant_PAA.drop_duplicates(ignore_index=True)
    # NonCompliant_PAA_Users['NonCompliant'] = 'PAA-User'
    # NoPAA_Users = NonCompliant_PAA_Users.groupby('SubscriptionId')['NonCompliant'].count().reset_index(name='RBAC:NoPAA-User')
    NonCompliant_PAA = NonCompliant_PAA.append(NonCompliant_PAA_Users, ignore_index=True).append(NonCompliant_PAAOther, ignore_index=True).append(NonCompliant_PAAOther_Users, ignore_index=True)

    Exceptions_PAA = Exceptions_PAA.append(Exceptions_PAA_Users, ignore_index=True).append(Exceptions_PAAOther, ignore_index=True).append(Exceptions_PAAOther_Users, ignore_index=True)

    NoPAA = NoPAA.append(NoPAAOther, ignore_index=True)
    NoPAA_Users = NoPAA_Users.append(NoPAAOther_Users, ignore_index=True)


    ServicePrincipal = RBAC.groupby('SubscriptionId')['rbacObjectType'].apply(lambda x: (x=='ServicePrincipal').sum()).reset_index(name='RBAC:ServicePrincipal')
    Owner = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='Owner').sum()).reset_index(name='RBAC:Owner')
    Contributor = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='Contributor').sum()).reset_index(name='RBAC:Contributor')
    UserAccessAdmin = RBAC.groupby('SubscriptionId')['rbacRoleName'].apply(lambda x: (x=='User Access Administrator').sum()).reset_index(name='RBAC:UserAccessAdmin')
    KPIRBAC_INFO = ServicePrincipal.merge(Owner, how='left', on='SubscriptionId').merge(Contributor, how='left', on='SubscriptionId').merge(UserAccessAdmin, how='left', on='SubscriptionId')
    KPIRBAC = Total.merge(TotalUser, how='left', on='SubscriptionId').merge(TotalEXT, how='left', on='SubscriptionId').merge(Total_managed, how='left', on='SubscriptionId').merge(Total_powerusers, how='left', on='SubscriptionId').merge(NoPAA, how='left', on='SubscriptionId').merge(NoPAA_Users, how='left', on='SubscriptionId').merge(NoEngie, how='left', on='SubscriptionId').merge(NULL, how='left', on='SubscriptionId').merge(BadAADGuest, how='left', on='SubscriptionId').merge(KPIRBAC_INFO, how='left', on='SubscriptionId').merge(NoCertifiedUser, how='left', on='SubscriptionId').merge(NoCertifiedUserSubscription, how='left', on='SubscriptionId')
    KPIRBAC['RBAC:PAA'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NoPAA']
    KPIRBAC['RBAC:PAA-User'] = KPIRBAC['RBAC:Total-User'] - KPIRBAC['RBAC:NoPAA-User']
    KPIRBAC['RBAC:ENGIE'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NoENGIE']
    KPIRBAC['RBAC:NotNULL'] = KPIRBAC['RBAC:Total'] - KPIRBAC['RBAC:NULL']
    KPIRBAC['RBAC:GoodAADGuest'] = 0
    KPIRBAC['RBAC:GoodAADGuestOther'] = KPIRBAC['RBAC:TotalEXT'] - KPIRBAC['RBAC:BadAADGuestOther']
    KPIRBAC['RBAC:CertifiedUser'] = KPIRBAC['RBAC:Total_powerusers'] - KPIRBAC['RBAC:NoCertifiedUser'] 
    KPIRBAC.drop(columns=['RBAC:Total_managed'], inplace=True)
    NonCompliant_KPIRBAC = NonCompliant_PAA.append(NonCompliant_Engie, ignore_index=True).append(NonCompliant_NotNull, ignore_index=True).append(NonCompliant_AADGuest, ignore_index=True).append(NonCompliant_CertifiedUser, ignore_index=True).append(NonCompliant_CertifiedUserSubscription, ignore_index=True)#.append(NonCompliant_x, ignore_index=True)
    
    #NonCompliant_KPIRBAC=NonCompliant_KPIRBAC[~NonCompliant_KPIRBAC['ResourceIdorGroup'].str.contains('Desktop Virtualization User',na=False)]
    
    Exceptions_KPIRBAC = Exceptions_PAA.append(Exceptions_Engie, ignore_index=True).append(Exceptions_NotNull, ignore_index=True).append(Exceptions_AADGuest, ignore_index=True).append(Exceptions_CertifiedUser, ignore_index=True).append(Exceptions_CertifiedUserSubscription, ignore_index=True)#.append(Exceptions_x, ignore_index=True)
    return(KPIRBAC, NonCompliant_KPIRBAC, Exceptions_KPIRBAC)
