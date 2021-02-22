# -*- coding: utf-8 -*-

from time import sleep
import pandas as pd
import io
import os
import requests
import sys
from datetime import datetime, date, time, timedelta
from pprint import pprint
from netaddr import IPNetwork, IPAddress
from socket import gethostbyaddr, herror
import urllib3
from urllib.parse import quote

# Non-essential module for doing a Whois request
try:
    from ipwhois import IPWhois
except ImportError:
    pass

verbose = True


def IDlistToFilter(ids):
    return 'id in (' + ','.join([str(id) for id in ids]) + ')'


def strip_desc(desc, size=80):
    '''Split the offense description to its first line then to a size limit'''
    desc = desc.split('\n')[0].strip()
    return desc[:size]


def formatResult(res, res_type, params):
    '''convert the response to the expected format'''
    try:
        if res_type == 'csv':
            return pd.read_csv(io.StringIO(res.content.decode('utf-8')))
        elif res_type == 'json':
            return res.json()
        else:  # Default return type is dataframe
            json = res.json()
            if 'number_of_elements' in json and json['number_of_elements'] == 0:
                return pd.DataFrame()
            df = pd.DataFrame.from_records(json)
            if len(df) == 0 and 'fields' in params:
                df = pd.DataFrame(columns=params['fields'].split(','))
            return df
    except ValueError:
        print(f'Invalid response: {res}')
        pprint(res.__dict__)
        print('Request was:')
        pprint(res.request.__dict__)
        sys.exit(1)


class QRadar:
    '''Interface to use QRadar REST API with Pandas Dataframe'''

    def __init__(self, url, token_file=None, verify=False, load_cache=True, time_range='NORMAL'):
        self.url_prefix = url
        self.token = open(token_file).readline(
        ).strip() if token_file else None
        self.verify = verify
        self.load_cache = load_cache
        self.time_range = time_range  # { DAILY | HOURLY | NORMAL }
        self.networks = pd.DataFrame()
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def eventCount2EPS(self, event_count):
        if self.time_range == 'NORMAL':
            return event_count/60
        elif self.time_range == 'HOURLY':
            return event_count/3600
        elif self.time_range == 'DAILY':
            return event_count/86400  # 24x3600

    def getHeader(self, res_type):
        '''Returns a proper HTTP header depending on the type of result we want.
        We also add the security token'''
        if res_type == 'dataframe':
            res_type = 'application/json'
        else:
            res_type = 'application/' + res_type
        header = {'Accept': res_type,
                  'Content-Type': res_type}
        if self.token:
            header['SEC'] = self.token
        # header['Version']='11.0'
        return header

    def request(self, method, endpoint, params, data=None, res_type='dataframe', timeout=30):
        headers = self.getHeader(res_type)
        try:
            if method.lower() == 'get':
                req_Data = requests.get(self.url_prefix + endpoint, headers=headers, params=params,
                                        data=data, verify=self.verify, timeout=timeout)
            elif method.lower() == 'post':
                req_Data = requests.post(self.url_prefix + endpoint, headers=headers, params=params,
                                         data=data, verify=self.verify, timeout=timeout)
            elif method.lower() == 'put':
                req_Data = requests.put(self.url_prefix + endpoint, headers=headers, params=params,
                                        data=data, verify=self.verify, timeout=timeout)
            elif method.lower() == 'delete':
                req_Data = requests.delete(
                    self.url_prefix + endpoint, headers=headers,  verify=self.verify, timeout=timeout)
            req_Data.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            print()
            pprint(eval(req_Data.content))
            sys.exit(1)

        return formatResult(req_Data, res_type, params)

    def get(self, endpoint, params=None, **kwargs):
        return self.request('get', endpoint, params, **kwargs)

    def post(self, endpoint, params=None, **kwargs):
        return self.request('post', endpoint, params, **kwargs)

    def put(self, endpoint, params=None, **kwargs):
        return self.request('put', endpoint, params, **kwargs)

    def delete(self, endpoint, params=None, **kwargs):
        return self.request('delete', endpoint, params, **kwargs)

    def getDomainID(self, name):
        '''return the ID of a given domain'''
        params = {'filter': f'name="{name}"', 'fields': 'id'}
        res = self.get('/config/domain_management/domains', params)
        if len(res) < 1:
            print(f'Unable to find ID for domain {name}')
            sys.exit(1)
        return res['id'][0]

    def getDomainIDs(self):
        '''return a dictionary ID=>name of all domains'''
        params = {'filter': f'deleted="False"', 'fields': 'id,name'}
        res = self.get('/config/domain_management/domains', params)
        return res.set_index('id').to_dict()['name']

    def getLogSourceTypeID(self, name):
        res = self.get('/config/event_sources/log_source_management/log_source_types',
                       params={'fields': 'id', 'filter': f'name="{name}"'})
        return res.iloc[0]['id']

    def getRuleID(self, name_or_id):
        try:
            return int(name_or_id)
        except ValueError:
            res = self.get('/analytics/rules',
                           params={'fields': 'id', 'filter': f'name="{name_or_id}"'})
            return res['id'][0]

    def getRule(self, name_or_id):
        rule_id = self.getRuleID(name_or_id)
        return self.get(f'/analytics/rules/{rule_id}', res_type='json')

    def disableRule(self, name_or_id):
        rule_id = self.getRuleID(name_or_id)
        params = pd.Series({'enabled': False}).to_json()
        return self.post(f'/analytics/rules/{rule_id}', data=params, res_type='json')

    def enableRule(self, name_or_id):
        rule_id = self.getRuleID(name_or_id)
        params = pd.Series({'enabled': True}).to_json()
        return self.post(f'/analytics/rules/{rule_id}', data=params, res_type='json')

    def getHighLevelCategory(self, hlc_id):
        res = self.get(f'/data_classification/high_level_categories/{hlc_id}', params={
                       'fields': 'name'}, res_type='json')
        self.high_level_category[hlc_id] = res['name']

    def getCategory(self, llc_id):
        params = {'fields': 'name,high_level_category_id'}
        res = self.get(
            f'/data_classification/low_level_categories/{llc_id}', params=params, res_type='json')
        hlc_id = res['high_level_category_id']
        if hlc_id not in self.high_level_category:
            self.getHighLevelCategory(hlc_id)
        self.qid_category[llc_id] = {'low_level_category': res['name'],
                                     'high_level_category': self.high_level_category[hlc_id]}

    def getQidDef(self, qid):
        params = {'fields': 'name,description,severity,low_level_category_id'}
        res = self.get(
            f'/data_classification/qid_records/{qid}', params=params, res_type='json')
        llc_id = res['low_level_category_id']
        if llc_id not in self.qid_category:
            self.getCategory(llc_id)
        del res['low_level_category_id']
        res.update(self.qid_category[llc_id])
        return pd.Series(res)

    def getDsmMapping(self, name_or_id):
        '''Returns a DataFrame with the event mappings for a given log source type.
        The DataFrame contains the event category and event id used for the mapping,
        high and low level categories, qid, event name and severity'''
        try:
            ls_id = int(name_or_id)
        except ValueError:
            ls_id = self.getLogSourceTypeID(name_or_id)

        self.qid_category = {}
        self.high_level_category = {}
        params = {'fields': 'log_source_event_category, log_source_event_id, qid_record_id, custom_event',
                  'filter': f'log_source_type_id={ls_id}'}
        df_EventMappings = self.get(
            '/data_classification/dsm_event_mappings', params=params)
        qid_events = df_EventMappings['qid_record_id'].apply(self.getQidDef)
        return pd.concat([df_EventMappings, qid_events], 1)

    def getLogSourceTypes(self, ls_type_ids):
        params = {'fields': 'id,name',
                  'filter': IDlistToFilter(ls_type_ids)
                  }
        df_ls_type = self.get(
            '/config/event_sources/log_source_management/log_source_types', params)
        df_ls_type.columns = ['type_id', 'type_name']
        return df_ls_type

    def getLogSourceGroupID(self, group_name):
        """Return the ID of a log source group"""
        params = {'fields': 'id',
                  'filter': f'name="{group_name}"'}
        json = self.get(
            '/config/event_sources/log_source_management/log_source_groups', params, res_type='json')
        group_id = json[0]['id']
        return group_id

    def getLogSourceGroups(self, ls_group_ids):
        """For simplicity, we'll assume only one group per source"""
        params = {'fields': 'id,name',
                  'filter': IDlistToFilter(ls_group_ids)
                  }
        df_ls_group = self.get(
            '/config/event_sources/log_source_management/log_source_groups', params)
        df_ls_group.columns = ['group_ids', 'group_name']
        return df_ls_group

    def getLogSourceIDs(self, group_name):
        """Get the IDs of all log sources in a group"""
        # get the group id
        group_id = self.getLogSourceGroupID(group_name)
        # get all the log sources
        params = {'fields': 'id,group_ids'}
        df_ls = self.get(
            '/config/event_sources/log_source_management/log_sources', params)
        # filter the ones part of the log source group
        df_ls = df_ls[df_ls['group_ids'].apply(lambda g: group_id in g)]
        return df_ls['id']

    def getLogSources(self, group_name_or_id):
        '''Given a log source group name (or ID), returns all the log sources'''
        try:
            group_id = int(group_name_or_id)
        except ValueError:
            group_id = self.getLogSourceGroupID(group_name_or_id)
        params = {'fields': 'name',
                  'filter': f'group_ids contains {group_id}'}
        df_ls = self.get(
            '/config/event_sources/log_source_management/log_sources', params)
        return df_ls

    def getLogSourceInfo(self, df_Data, with_type=False, with_group=False, internal=False):
        '''Given a dataframe with a logSourceId column, it returns another dataframe
        with the name/id mapping for all those Log Sources'''
        params = {
            'fields': 'id,name',
            'filter': f'internal={internal}'
        }
        if with_type:
            params['fields'] += ',type_id'
        if with_group:
            params['fields'] += ',group_ids'

        if len(df_Data) > 0:
            params['filter'] += " and " + \
                IDlistToFilter(df_Data['logSourceId'].unique())

        df_ls = self.get(
            '/config/event_sources/log_source_management/log_sources', params)
        if with_type:
            df_ls = pd.merge(df_ls, self.getLogSourceTypes(
                df_ls['type_id'].unique()), on='type_id')
            df_ls.drop(columns='type_id', inplace=True)
            df_ls.rename(columns={'type_name': 'Type Name'}, inplace=True)
        if with_group:
            # We assume only one group per log source and grab only the first one for simplicity
            df_ls['group_ids'] = df_ls['group_ids'].apply(lambda ids: ids[0])
            df_ls = pd.merge(df_ls, self.getLogSourceGroups(
                df_ls['group_ids'].unique()), on='group_ids')
            df_ls.drop(columns='group_ids', inplace=True)
            df_ls.rename(columns={'group_name': 'Group Name'}, inplace=True)

        df_ls.rename(columns={'id': 'logSourceId',
                              'name': 'Name'}, inplace=True)
        return df_ls

    def getIPSource(self, source_address_id):
        param = {'fields': 'source_ip'}
        source_ip = self.get(
            f'/siem/source_addresses/{source_address_id}', param, res_type='json')
        return source_ip

    def initNetworks(self, domain_id=None, fields=None):
        self.networks = self.getNetworks(domain_id, fields)

    def getNetworks(self, domain_id=None, fields=None):
        '''return the network hierarchy for a domain'''

        params = {}
        if fields:
            params['fields'] = fields
        df = self.get('/config/network_hierarchy/networks', params)
        if domain_id:
            df = df.loc[df['domain_id'] == domain_id]
        return df

    def setNetworks(self, network_hierarchy):
        '''Replaces the current network hierarchy with the input in json'''

        return self.put('/config/network_hierarchy/staged_networks', data=network_hierarchy.encode())

    def getNetwork(self, ip_address):
        '''return the site and network names for an IP address
        we assume the site is the first level subgroup (group = CLIENT.SiteName)
        for public adresses, we try a reverse DNS and a WHOIS lookups'''

        ip = IPAddress(ip_address)
        for _, row in self.networks.iterrows():
            if ip in IPNetwork(row['cidr']):
                return (row['group'].split('.')[1], row['name'])

        # if the IP is not private and hasn't been found in network hierarchy
        # try a reverse DNS lookup
        if ip.is_private():
            return ('', '')
        else:
            try:
                res = gethostbyaddr(ip_address)
                return ('', res[0])
            except herror:
                # Reverse DNS failed, let's do a WHOIS lookup
                try:
                    res = IPWhois(ip).lookup_whois()
                    return (res['asn_country_code'], res['asn_description'][:30])
                except:
                    return ('', '')

    def waitForCompleted(self, endpoint, search_name=None):
        '''Wait for a request to be completed'''
        req_Status = self.get(endpoint, res_type='json')['status']
        duration = 0
        begin = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        search_id = endpoint.split('/')[-1]
        if search_name:
            search_name = f"'{search_name}' "

        while req_Status != 'COMPLETED':
            sleep(1)
            duration += 1
            if verbose:
                print(f"\r[{begin}] {search_name}[{search_id}] query run time: " +
                      str(timedelta(seconds=duration)), end='')
            req_Status = self.get(endpoint, res_type='json')['status']
        if verbose:
            print('. Done')

    def getTimeSeries(self, saved_search, time_interval, time_range=None, force_reload=False):
        '''Get the Time Series data of a saved search in a dataframe which can be used to plot a timeline
        time_interval is any AQL time range specification like "last x days" or "START x STOP y"
        '''
        if not time_range:
            time_range = self.time_range
        if not os.path.isdir('data'):
            os.mkdir('data')
        cache_name = f'data/{saved_search}-{time_range}-{time_interval}.csv'.replace(
            ':', '-')
        if self.load_cache and os.path.isfile(cache_name) and not force_reload:
            return pd.read_csv(cache_name)
        qr_query = f"select * from GLOBALVIEW('{saved_search}','{time_range}') {time_interval}"
        params = {'query_expression': qr_query}

        endpoint = '/ariel/searches'
        req_Data = self.post(endpoint, params, res_type='json')
        # ========================================================
        # Grab the request ID created for the data
        req_ID = req_Data['search_id']

        # ========================================================
        # 2. Establish if the search has finised
        endpoint += '/' + req_ID
        self.waitForCompleted(endpoint, saved_search)

        # ========================================================
        # 3. Grab the data
        endpoint += '/results'
        df = self.get(endpoint, res_type='csv')

        # Cache the result in a csv file
        df.to_csv(cache_name, sep=',', encoding='utf-8', index=False)

        return df

    def runQuery(self, query_name, query, time_interval, force_reload=False):
        '''Run an AQL query and return the result in a Dataframe'''
        if query_name:
            if not os.path.isdir('data'):
                os.mkdir('data')
            cache_name = f'data/{query_name}-{time_interval}.csv'.replace(
                ':', '-')
            if self.load_cache and os.path.isfile(cache_name) and not force_reload:
                return pd.read_csv(cache_name)
        params = {'query_expression': f'{query} {time_interval}'}
        endpoint = '/ariel/searches'

        req_Data = self.post(endpoint, params, res_type='json')
        req_ID = req_Data['search_id']
        endpoint += '/' + req_ID
        self.waitForCompleted(endpoint, query_name)
        df = self.get(endpoint + '/results', res_type='csv')
        if query_name:
            df.to_csv(cache_name, sep=',', encoding='utf-8', index=False)
        return df

    def resumeQuery(self, req_id):
        endpoint = '/ariel/searches/' + req_id
        self.waitForCompleted(endpoint)
        return self.get(endpoint + '/results', res_type='csv')

    def runSavedSearch(self, saved_search):
        '''Run a saved search by name and return the result in a Dataframe'''
        if not os.path.isdir('data'):
            os.mkdir('data')
        cache_name = f'data/{saved_search}.csv'
        if self.load_cache and os.path.isfile(cache_name):
            return pd.read_csv(cache_name)

        # First, we get the saved search ID
        endpoint = '/ariel/saved_searches'
        params = {'filter': f"name='{saved_search}'",
                  'fields': 'id'}

        req_Data = self.get(endpoint, params, res_type='json')
        ss_id = req_Data[0]['id']

        # Next, we actually run the search
        params = {'saved_search_id': ss_id}
        endpoint = '/ariel/searches'
        req_Data = self.post(endpoint, params, res_type='json')
        req_ID = req_Data['search_id']
        endpoint += '/' + req_ID
        self.waitForCompleted(endpoint, saved_search)
        df = self.get(endpoint + '/results', res_type='csv')
        df.to_csv(cache_name, sep=',', encoding='utf-8', index=False)
        return df

    def getOffenses(self, domain_id=0):
        '''get the list of offenses for a domain'''
        # First, get the offense_type mapping
        endpoint = '/siem/offense_types'
        params = {'fields': 'id,name'}
        df_off_type = self.get(endpoint, params)
        df_off_type.rename(
            {'id': 'offense_type_id', 'name': 'offense_type'}, axis='columns', inplace=True)

        # Next, get the offenses
        endpoint = '/siem/offenses'
        params = {'fields': 'id,follow_up,description,offense_type,offense_source,magnitude,event_count,start_time,last_updated_time',
                  'filter': f"status='OPEN' and domain_id={domain_id}"}
        df = self.get(endpoint, params)

        # Merge to get the actual offense type
        df.rename({'offense_type': 'offense_type_id'},
                  axis='columns', inplace=True)
        df = pd.merge(df, df_off_type, on='offense_type_id')

        df['start_time'] = pd.to_datetime(df['start_time'], unit='ms')
        df['last_updated_time'] = pd.to_datetime(
            df['last_updated_time'], unit='ms')
        df['description'] = df['description'].apply(strip_desc)
        # Reorder columns and drop offense_type_id
        ordered_cols = ['id', 'follow_up', 'description', 'offense_type',
                        'offense_source', 'event_count', 'start_time', 'last_updated_time', 'magnitude']
        df = df[ordered_cols]
        df.sort_values(by=['magnitude', 'last_updated_time'],
                       ascending=False, inplace=True)
        return df

    def getOffense(self, offense_id):
        '''get one offense by its id'''
        # Get the offense
        endpoint = '/siem/offenses/'+offense_id
        params = {
            'fields': 'id,follow_up,description,offense_type,offense_source,magnitude,event_count,start_time,last_updated_time'}
        df = self.get(endpoint, params, res_type='json')
        return df

    def getClosedOffenses(self, start_date, end_date, domain_id=0):
        '''get the list of offenses closed during a specific time range'''
        # First, get the offense_type mapping
        df = self.getAllOffenses()
        df = df[(df['last_updated_time'] > pd.Timestamp(start_date))
                & (df['last_updated_time'] <= pd.Timestamp(end_date))
                & (df['status'] == 'CLOSED')]
        ordered_cols = ['id', 'follow_up', 'description', 'offense_type',
                        'offense_source', 'event_count', 'start_time', 'last_updated_time', 'magnitude']
        df = df[ordered_cols]
        return df

    def getAllOffenses(self, force_reload=False):
        '''get the list of all offenses'''
        if not os.path.isdir('data'):
            os.mkdir('data')
        cache_name = f'data/offenses-{date.today().isoformat()}.csv'
        if self.load_cache and os.path.isfile(cache_name) and not force_reload:
            return pd.read_csv(cache_name, parse_dates=['start_time', 'last_updated_time'])
        # First, get the offense_type mapping
        endpoint = '/siem/offense_types'
        params = {'fields': 'id,name'}
        df_off_type = self.get(endpoint, params)
        df_off_type.rename(
            {'id': 'offense_type_id', 'name': 'offense_type'}, axis='columns', inplace=True)

        # Also get the closing_reason mapping
        endpoint = '/siem/offense_closing_reasons'
        params = {'fields': 'id,text'}
        df_closing_reason = self.get(endpoint, params)
        df_closing_reason.rename(
            {'id': 'closing_reason_id', 'text': 'closing_reason'}, axis='columns', inplace=True)

        # Next, get the offenses
        endpoint = '/siem/offenses'
        params = {}
        df = self.get(endpoint, params)

        # Merge to get the actual offense type
        df.rename({'offense_type': 'offense_type_id'},
                  axis='columns', inplace=True)
        df = pd.merge(df, df_off_type, on='offense_type_id')
        df = pd.merge(df, df_closing_reason,
                      on='closing_reason_id', how='left')

        df['start_time'] = pd.to_datetime(df['start_time'], unit='ms')
        df['last_updated_time'] = pd.to_datetime(
            df['last_updated_time'], unit='ms')
        df['description'] = df['description'].apply(strip_desc)
        # Drop offense_type_id
        df.drop(columns=['offense_type_id'], inplace=True)
        df.sort_values(by=['magnitude', 'last_updated_time'],
                       ascending=False, inplace=True)
        df.to_csv(cache_name, sep=',', encoding='utf-8', index=False)
        return df

    def getOffenseCategories(self, domain_id=0):
        '''get the offense categories for a domain'''
        endpoint = '/siem/offenses'
        params = {'fields': 'categories',
                  'filter': f"status='OPEN' and domain_id={domain_id}"}
        df = self.get(endpoint, params)
        cat_count = pd.Series()
        for cat_list in df['categories']:
            for cat in cat_list:
                if cat in cat_count:
                    cat_count[cat] += 1
                else:
                    cat_count[cat] = 1
        return cat_count.to_frame(name='Total').reset_index()

    def CreateRefSet(self, name, data_type='ALN', ttl=None):
        '''data_type must be one of: ALN, NUM, IP, PORT, ALNIC, DATE>'''
        params = {'element_type': data_type, 'name': name}
        if ttl:
            params['time_to_live'] = ttl
        return self.request('post', '/reference_data/sets', params, res_type='json')

    def GetRefSet(self, name, namespace=None, res_type='dataframe'):
        '''get the content of a reference set'''
        params = {'name': name}
        if namespace:
            params['namespace'] = namespace
        return self.request('get', '/reference_data/sets/'+name, params, res_type=res_type)

    def SyncRefSet(self, name, data, namespace=None):
        '''Synchronize the content of a reference set with the data (a list of strings)'''
        current = self.GetRefSet(name, namespace)
        if current.shape[0] == 0:
            current = []
        else:
            current = current['data'].apply(lambda x: x['value']).values

        # remove obsolete entries
        n_removed = 0
        for entry in current:
            if entry not in data:
                self.DeleteRefSet(name, entry)
                n_removed += 1
        if verbose:
            print(f'Removed {n_removed} entries')
        # add new entries
        to_add = []
        for value in data:
            if value not in current:
                to_add.append(value)
        if to_add:
            self.PopulateRefSet(name, to_add)
        if verbose:
            print(f'Added {len(to_add)} entries')

    def SyncRefMap(self, name, data):
        '''Let's keep it simple for now'''
        self.PurgeRefMap(name)
        self.PopulateRefMap(name, data)

    def SyncRefMapOfSets(self, name, data):
        '''Let's keep it simple for now'''
        self.PurgeRefMapOfSets(name)
        self.PopulateRefMapOfSets(name, data)

    def PopulateRefSet(self, name, data):
        ''' the reference set's name must exist
        data is like "['toto', 'tata', ...] or list or Series"
        '''
        if isinstance(data, list):
            data = repr(data)
        elif isinstance(data, pd.Series):
            data = repr(data.tolist())
        return self.request('post', '/reference_data/sets/bulk_load/'+name, params=None, data=data, res_type='json')

    def PopulateRefMap(self, name, data):
        ''' the reference set's name must exist
        data is Dict or Series"
        '''
        if isinstance(data, dict):
            data = repr(data)
        elif isinstance(data, pd.Series):
            data = repr(data.to_dict())
        return self.request('post', '/reference_data/maps/bulk_load/'+name, params=None, data=data, res_type='json')

    def PopulateRefMapOfSets(self, name, data):
        ''' the reference set's name must exist
        data is dictionary or Series of lists"
        '''
        if isinstance(data, dict):
            data = repr(data)
        elif isinstance(data, pd.Series):
            data = repr(data.to_dict())
        return self.request('post', '/reference_data/map_of_sets/bulk_load/'+name, params=None, data=data, res_type='json')

    def PurgeRefSet(self, name):
        return self.delete(f'/reference_data/sets/{name}?purge_only=true', res_type='json')

    def PurgeRefMap(self, name):
        return self.delete(f'/reference_data/maps/{name}?purge_only=true', res_type='json')

    def PurgeRefMapOfSets(self, name):
        return self.delete(f'/reference_data/map_of_sets/{name}?purge_only=true', res_type='json')

    def DeleteRefSet(self, name, value=None, domain_id=None):  # domain_id seems broken
        '''Delete a reference set or a value in a reference set'''
        params = {'name': name}
        endpoint = '/reference_data/sets/'+name
        if value:
            # API requires double URL encoding
            endpoint += '/' + quote(quote(value))
            if domain_id:
                params['domain_id'] = domain_id
        return self.delete(endpoint, params=params, res_type='json')
