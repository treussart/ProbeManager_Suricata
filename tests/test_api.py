""" venv/bin/python probemanager/manage.py test suricata.tests.test_api --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from suricata.models import Suricata, BlackList, ValidationType, AppLayerType, Configuration


class APITest(APITestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-conf', 'test-suricata-suricata']

    def setUp(self):
        self.client = APIClient()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_conf(self):
        response = self.client.get('/api/v1/suricata/configuration/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)
        with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
            CONF_FULL_DEFAULT = f.read()
        conftest_advanced = Configuration.objects.create(
            name='conftest_advanced',
            conf_rules_directory='/etc/suricata/rules',
            conf_iprep_directory='/etc/suricata/iprep',
            conf_file='/etc/suricata/suricata.yaml',
            conf_advanced=True,
            conf_advanced_text=CONF_FULL_DEFAULT,
            conf_HOME_NET="[192.168.0.0/24]",
            conf_EXTERNAL_NET="!$HOME_NET",
            conf_HTTP_SERVERS="$HOME_NET",
            conf_SMTP_SERVERS="$HOME_NET",
            conf_SQL_SERVERS="$HOME_NET",
            conf_DNS_SERVERS="$HOME_NET",
            conf_TELNET_SERVERS="$HOME_NET",
            conf_AIM_SERVERS="$EXTERNAL_NET",
            conf_DNP3_SERVER="$HOME_NET",
            conf_DNP3_CLIENT="$HOME_NET",
            conf_MODBUS_CLIENT="$HOME_NET",
            conf_MODBUS_SERVER="$HOME_NET",
            conf_ENIP_CLIENT="$HOME_NET",
            conf_ENIP_SERVER="$HOME_NET",
            conf_HTTP_PORTS="80",
            conf_SHELLCODE_PORTS="!80",
            conf_ORACLE_PORTS="1521",
            conf_SSH_PORTS="22",
            conf_DNP3_PORTS="20000",
            conf_MODBUS_PORTS="502",
            conf_stats=ValidationType.get_by_id(1),
            conf_afpacket_interface='eth0',
            conf_outputs_fast=ValidationType.get_by_id(1),
            conf_outputs_evelog=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_http=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_tls=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_ssh=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_smtp=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_dnp3=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_taggedpackets=ValidationType.get_by_id(0),
            conf_outputs_evelog_xff=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_query=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_answer=ValidationType.get_by_id(0),
            conf_outputs_evelog_http_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_tls_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_files_forcemagic=ValidationType.get_by_id(1),
            conf_outputs_unified2alert=ValidationType.get_by_id(1),
            conf_lua=ValidationType.get_by_id(1),
            conf_applayer_tls=AppLayerType.get_by_id(0),
            conf_applayer_dcerpc=AppLayerType.get_by_id(0),
            conf_applayer_ftp=AppLayerType.get_by_id(0),
            conf_applayer_ssh=AppLayerType.get_by_id(0),
            conf_applayer_smtp=AppLayerType.get_by_id(0),
            conf_applayer_imap=AppLayerType.get_by_id(1),
            conf_applayer_msn=AppLayerType.get_by_id(1),
            conf_applayer_smb=AppLayerType.get_by_id(0),
            conf_applayer_dns=AppLayerType.get_by_id(0),
            conf_applayer_http=AppLayerType.get_by_id(0)
        )
        response = self.client.get('/api/v1/suricata/configuration/' + str(conftest_advanced.id) + '/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
            CONF_FULL_DEFAULT = f.read()
        conftest = Configuration.objects.create(
            name='conftest',
            conf_rules_directory='/etc/suricata/rules',
            conf_iprep_directory='/etc/suricata/iprep',
            conf_file='/etc/suricata/suricata.yaml',
            conf_advanced=False,
            conf_advanced_text=CONF_FULL_DEFAULT,
            conf_HOME_NET="[192.168.0.0/24]",
            conf_EXTERNAL_NET="!$HOME_NET",
            conf_HTTP_SERVERS="$HOME_NET",
            conf_SMTP_SERVERS="$HOME_NET",
            conf_SQL_SERVERS="$HOME_NET",
            conf_DNS_SERVERS="$HOME_NET",
            conf_TELNET_SERVERS="$HOME_NET",
            conf_AIM_SERVERS="$EXTERNAL_NET",
            conf_DNP3_SERVER="$HOME_NET",
            conf_DNP3_CLIENT="$HOME_NET",
            conf_MODBUS_CLIENT="$HOME_NET",
            conf_MODBUS_SERVER="$HOME_NET",
            conf_ENIP_CLIENT="$HOME_NET",
            conf_ENIP_SERVER="$HOME_NET",
            conf_HTTP_PORTS="80",
            conf_SHELLCODE_PORTS="!80",
            conf_ORACLE_PORTS="1521",
            conf_SSH_PORTS="22",
            conf_DNP3_PORTS="20000",
            conf_MODBUS_PORTS="502",
            conf_stats=ValidationType.get_by_id(1),
            conf_afpacket_interface='eth0',
            conf_outputs_fast=ValidationType.get_by_id(1),
            conf_outputs_evelog=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_http=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_tls=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_ssh=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_smtp=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_dnp3=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_taggedpackets=ValidationType.get_by_id(0),
            conf_outputs_evelog_xff=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_query=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_answer=ValidationType.get_by_id(0),
            conf_outputs_evelog_http_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_tls_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_files_forcemagic=ValidationType.get_by_id(1),
            conf_outputs_unified2alert=ValidationType.get_by_id(1),
            conf_lua=ValidationType.get_by_id(1),
            conf_applayer_tls=AppLayerType.get_by_id(0),
            conf_applayer_dcerpc=AppLayerType.get_by_id(0),
            conf_applayer_ftp=AppLayerType.get_by_id(0),
            conf_applayer_ssh=AppLayerType.get_by_id(0),
            conf_applayer_smtp=AppLayerType.get_by_id(0),
            conf_applayer_imap=AppLayerType.get_by_id(1),
            conf_applayer_msn=AppLayerType.get_by_id(1),
            conf_applayer_smb=AppLayerType.get_by_id(0),
            conf_applayer_dns=AppLayerType.get_by_id(0),
            conf_applayer_http=AppLayerType.get_by_id(0)
        )
        response = self.client.get('/api/v1/suricata/configuration/' + str(conftest.id) + '/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/configuration/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 4)

    def test_suricata(self):
        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        data = {'name': 'test',
                'secure_deployment': True,
                'scheduled_rules_deployment_enabled': True,
                'scheduled_rules_deployment_crontab': 4,
                'scheduled_check_enabled': True,
                'scheduled_check_crontab': 3,
                'server': 1,
                'rulesets': [1, ],
                'configuration': 1,
                'installed': True}

        data_put = {'secure_deployment': True,
                    'server': 1,
                    'rulesets': [1, ],
                    'configuration': 1,
                    'installed': False}

        data_patch = {'installed': True}

        response = self.client.post('/api/v1/suricata/suricata/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post('/api/v1/suricata/suricata/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)

        self.assertTrue(PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4))))
        self.assertTrue(PeriodicTask.objects.get(name="test_check_task"))

        response = self.client.put('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/', data_put)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Suricata.get_by_name('test').installed)

        response = self.client.put('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/',
                                   {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/', data_patch)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Suricata.get_by_name('test').installed)

        response = self.client.patch('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/',
                                     {'scheduled_rules_deployment_enabled': False})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Suricata.get_by_name('test').scheduled_rules_deployment_enabled)

        response = self.client.delete('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4)))
        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_check_task")

        response = self.client.get('/api/v1/suricata/suricata/1/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/start/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/stop/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/restart/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/reload/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/status/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/uptime/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['uptime'])

        response = self.client.get('/api/v1/suricata/suricata/1/deploy_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/deploy_conf/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        # response = self.client.get('/api/v1/suricata/suricata/1/install/')
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])
        #
        # response = self.client.get('/api/v1/suricata/suricata/1/install/?version=' + settings.SURICATA_VERSION)
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])

    def test_signature(self):
        response = self.client.get('/api/v1/suricata/signature/1/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_ruleset(self):
        response = self.client.get('/api/v1/suricata/ruleset/2/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_blacklist(self):
        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)

        data = {'type': 'IP',
                'value': '192.168.0.1',
                'comment': 'test',
                'rulesets': [1, ]
                }
        data2 = {'type': 'MD5',
                 'value': 'ertertert',
                 'comment': 'test',
                 'rulesets': [1, ]
                 }

        response = self.client.post('/api/v1/suricata/blacklist/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post('/api/v1/suricata/blacklist/', {'value': '192.168.0.1'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        response = self.client.delete('/api/v1/suricata/blacklist/' +
                                      str(BlackList.objects.get(value='192.168.0.1').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)

        response = self.client.post('/api/v1/suricata/blacklist/', data2)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.delete('/api/v1/suricata/blacklist/' +
                                      str(BlackList.objects.get(value='ertertert').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
