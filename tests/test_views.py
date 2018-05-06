""" venv/bin/python probemanager/manage.py test suricata.tests.test_views --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.conf import settings

from suricata.models import Suricata, Configuration, AppLayerType, ValidationType


class ViewsSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-conf', 'test-suricata-suricata']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def test_home(self):
        """
        Home Page who list instances of Suricata
        """
        response = self.client.get('/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Home</title>', str(response.content))
        self.assertEqual('core/index.html', response.templates[0].name)
        self.assertIn('core', response.resolver_match.app_names)
        self.assertIn('function index', str(response.resolver_match.func))
        with self.assertTemplateUsed('suricata/home.html'):
            self.client.get('/', follow=True)

    def test_index(self):
        """
         Index Page for an instance of Suricata
        """
        suricata = Suricata.get_by_id(1)
        response = self.client.get('/suricata/' + str(suricata.id))
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Suricata</title>', str(response.content))
        self.assertEqual('suricata/index.html', response.templates[0].name)
        self.assertIn('suricata', response.resolver_match.app_names)
        self.assertIn('function probe_index', str(response.resolver_match.func))
        self.assertEqual(str(response.context['user']), 'testuser')
        with self.assertTemplateUsed('suricata/index.html'):
            self.client.get('/suricata/' + str(suricata.id))
        response = self.client.get('/suricata/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/stop/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe stopped successfully', str(response.content))
        response = self.client.get('/suricata/stop/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/start/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe started successfully', str(response.content))
        response = self.client.get('/suricata/start/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/status/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('get status successfully', str(response.content))
        response = self.client.get('/suricata/status/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/restart/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe restarted successfully', str(response.content))
        response = self.client.get('/suricata/restart/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/reload/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe reloaded successfully', str(response.content))
        response = self.client.get('/suricata/reload/99')
        self.assertEqual(response.status_code, 404)
        with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
            CONF_FULL_DEFAULT = f.read()
        conftest = Configuration.objects.create(
            name='conftest',
            conf_rules_directory='/etc/suricata/rules',
            conf_iprep_directory='/etc/suricata/iprep',
            conf_lua_directory='/etc/suricata/lua-output',
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
        suricata.configuration = conftest
        suricata.save()
        response = self.client.get('/suricata/deploy-conf/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test configuration OK', str(response.content))
        self.assertIn('Deployed configuration successfully', str(response.content))
        response = self.client.get('/suricata/deploy-conf/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/deploy-rules/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Deployed rules launched with succeed', str(response.content))
        response = self.client.get('/suricata/deploy-rules/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/update/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/suricata/update/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/deploy-reputation-list/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/suricata/deploy-reputation-list/99')
        self.assertEqual(response.status_code, 404)

        response = self.client.get('/suricata/install/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/suricata/install/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/suricata/update/' + str(suricata.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/suricata/update/99')
        self.assertEqual(response.status_code, 404)

    def test_admin_index(self):
        # index
        response = self.client.get('/admin/suricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Suricata administration', str(response.content))
