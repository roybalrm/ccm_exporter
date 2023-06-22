from zeep import Client
from zeep.cache import SqliteCache
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
from requests import Session
from requests.auth import HTTPBasicAuth
import urllib3
import logging.config
import logging
from lxml.etree import tostring
import tempfile
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def enable_logging():
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class UcmRisPortToolkit:
    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/realtimeservice2/services/RISService70?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_risport.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.create_service("{http://schemas.cisco.com/ast/soap}RisBinding",
                                                  "https://{0}:8443/realtimeservice2/services/RISService70".format(server_ip))

        # enable_logging()

    def get_service(self):
        return self.service


def encode_counter_name(counter_data):
    if 'instance' in counter_data and counter_data['instance'] is not None:
        counter_name = f'\\\\{counter_data["host"]}\\{counter_data["object"]}({counter_data["instance"]})\\{counter_data["counter"]}'
    else:
        counter_name = f'\\\\{counter_data["host"]}\\{counter_data["object"]}\\{counter_data["counter"]}'

    return counter_name


class UcmPerfMonToolkit:
    last_exception = None
    compiled_re = None
    history = HistoryPlugin()

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/perfmonservice2/services/PerfmonService?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_risport.db', timeout=60)

        self.client = Client(wsdl=wsdl, plugins=[self.history], transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.create_service("{http://schemas.cisco.com/ast/soap}PerfmonBinding",
                                                  "https://{0}:8443/perfmonservice2/services/PerfmonService".format(server_ip))

        # enable_logging()

    def get_service(self):
        return self.service

    def last_request_debug(self):
        request_env = tostring(self.history.last_sent['envelope'])
        request_headers = self.history.last_sent['http_headers']
        response_env = tostring(self.history.last_received['envelope'])
        response_headers = self.history.last_received['http_headers']

        return {
            'request': {
                'raw': self.history.last_sent,
                'headers': request_headers,
                'envelope': request_env
            },
            'response': {
                'raw': self.history.last_received,
                'headers': response_headers,
                'envelope': response_env

            }
         }

    def decode_counter_name(self, counter_name_string):
        # Converts string like \\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(BranchRemote->Hub_None)\\BandwidthAvailable
        #  to an object

        decoded_counter = None

        if self.compiled_re is None:
            self.compiled_re = re.compile(r"""\\\\([^\\]*)\\([^()\\]*)(\(([^\\]*)\))?\\([^\\]*)""")

        match_result = self.compiled_re.match(counter_name_string)

        if match_result is not None:
            decoded_counter = {
                'host': match_result.group(1),
                'object': match_result.group(2),
                'instance': match_result.group(4),
                'counter': match_result.group(5)
            }

        return decoded_counter


    def perfmonOpenSession(self):
        session_handle = self.service.perfmonOpenSession()
        return session_handle

    def perfmonAddCounter(self, session_handle, counters):
        '''
        :param session_handle: A session Handle returned from perfmonOpenSession()
        :param counters: An array of counters or a single string for a single counter
        :return: True for Success and False for Failure
        '''

        if isinstance(counters, list):
            counter_data = [
                {
                    'Counter': []
                }
            ]

            for counter in counters:
                new_counter = {
                    'Name': counter
                }
                counter_data[0]['Counter'].append(new_counter)

        elif counters is not None:
            counter_data = [
                {
                    'Counter': [
                        {
                            'Name': counters
                        }
                    ]
                }
            ]

        try:
            self.service.perfmonAddCounter(SessionHandle=session_handle, ArrayOfCounter=counter_data)
            result = True
        except Exception as e:
            result = False

        return result

    def perfmonCollectSessionData(self, session_handle):
        try:
            session_data = self.service.perfmonCollectSessionData(SessionHandle=session_handle)

            result_data = {}

            for data in session_data:
                counter_name_data = self.decode_counter_name(data['Name']['_value_1'])
                if counter_name_data is not None:
                    counter_host = counter_name_data['host']
                    counter_object = counter_name_data['object']
                    counter_instance = counter_name_data['instance']
                    counter_name = counter_name_data['counter']
                    counter_value = data['Value']
                    counter_status = data['CStatus']
                    if counter_status == 0:
                        if counter_host not in result_data:
                            result_data[counter_host] = {}
                        if counter_object not in result_data[counter_host]:
                            result_data[counter_host][counter_object] = {}

                        if counter_instance is None:
                            result_data[counter_host][counter_object]['multi_instance'] = False
                            if 'counters' not in result_data[counter_host][counter_object]:
                                result_data[counter_host][counter_object]['counters'] = {}
                            result_data[counter_host][counter_object]['counters'][counter_name] = counter_value
                        else:
                            result_data[counter_host][counter_object]['multi_instance'] = True
                            if 'instances' not in result_data[counter_host][counter_object]:
                                result_data[counter_host][counter_object]['instances'] = {}
                            if counter_instance not in result_data[counter_host][counter_object]['instances']:
                                result_data[counter_host][counter_object]['instances'][counter_instance] = {}
                            result_data[counter_host][counter_object]['instances'][counter_instance][counter_name] = counter_value
                    else:
                        # TODO: Clean up the session and restart it if we're not getting valid data
                        pass
        except Exception as e:
            print(e)
            result_data = None

        return result_data

    def perfmonCloseSession(self, session_handle):
        try:
            session_handle = self.service.perfmonCloseSession(SessionHandle=session_handle)
        except Exception as e:
            session_handle = None
        return session_handle

    def perfmonListCounter(self, host):
        try:
            counter_list = {}
            counter_data = self.service.perfmonListCounter(Host=host)
            for object_data in counter_data:
                object_name = object_data['Name']['_value_1']
                counter_list[object_name] = {}
                counter_list[object_name]['multi_instance'] = object_data['MultiInstance']
                counter_list[object_name]['counters'] = []
                for counter in object_data['ArrayOfCounter']['item']:
                    counter_list[object_name]['counters'].append(counter['Name']['_value_1'])
        except Exception as e:
            counter_list = None

        return counter_list

    def perfmonListInstance(self, host, object_name):
        try:
            instance_data = self.service.perfmonListInstance(Host=host, Object=object_name)

            instances = []

            for instance in instance_data:
                instances.append(instance['Name']['_value_1'])
        except Exception as e:
            instances = None

        return instances
