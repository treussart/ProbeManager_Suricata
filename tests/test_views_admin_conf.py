""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_conf --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import ConfSuricata


class ViewsConfAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-source', 'test-suricata-conf',
                'test-suricata-suricata']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))
        self.date_now = timezone.now()

    def tearDown(self):
        self.client.logout()

    def test_conf(self):
        response = self.client.get('/admin/suricata/confsuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(ConfSuricata.get_all()), 2)

        with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
            CONF_FULL_DEFAULT = f.read()
        response = self.client.post('/admin/suricata/confsuricata/add/', {'name': 'conftest',
                                                                          'conf_rules_directory': '/etc/suricata/rules',
                                                                          'conf_script_directory': '/etc/suricata/lua',
                                                                          'conf_file': '/etc/suricata/suricata.yaml',
                                                                          'conf_advanced': True,
                                                                          'conf_advanced_text': CONF_FULL_DEFAULT,
                                                                          'conf_HOME_NET' :"[192.168.0.0/24]",
                                                                          'conf_EXTERNAL_NET' :"!$HOME_NET",
                                                                          'conf_HTTP_SERVERS' :"$HOME_NET",
                                                                          'conf_SMTP_SERVERS' :"$HOME_NET",
                                                                          'conf_SQL_SERVERS' :"$HOME_NET",
                                                                          'conf_DNS_SERVERS' :"$HOME_NET",
                                                                          'conf_TELNET_SERVERS' :"$HOME_NET",
                                                                          'conf_AIM_SERVERS' :"$EXTERNAL_NET",
                                                                          'conf_DNP3_SERVER' :"$HOME_NET",
                                                                          'conf_DNP3_CLIENT' :"$HOME_NET",
                                                                          'conf_MODBUS_CLIENT' :"$HOME_NET",
                                                                          'conf_MODBUS_SERVER' :"$HOME_NET",
                                                                          'conf_ENIP_CLIENT' :"$HOME_NET",
                                                                          'conf_ENIP_SERVER' :"$HOME_NET",
                                                                          'conf_HTTP_PORTS' :"80",
                                                                          'conf_SHELLCODE_PORTS' :"!80",
                                                                          'conf_ORACLE_PORTS' :"1521",
                                                                          'conf_SSH_PORTS' :"22",
                                                                          'conf_DNP3_PORTS' :"20000",
                                                                          'conf_MODBUS_PORTS' :"502",
                                                                          'conf_stats': 1,
                                                                          'conf_afpacket_interface':'eth0',
                                                                          'conf_outputs_fast': 1,
                                                                          'conf_outputs_evelog': 0,
                                                                          'conf_outputs_evelog_alert_http': 0,
                                                                          'conf_outputs_evelog_alert_tls': 0,
                                                                          'conf_outputs_evelog_alert_ssh': 0,
                                                                          'conf_outputs_evelog_alert_smtp': 0,
                                                                          'conf_outputs_evelog_alert_dnp3': 0,
                                                                          'conf_outputs_evelog_alert_taggedpackets': 0,
                                                                          'conf_outputs_evelog_xff': 0,
                                                                          'conf_outputs_evelog_dns_query': 0,
                                                                          'conf_outputs_evelog_dns_answer': 0,
                                                                          'conf_outputs_evelog_http_extended': 0,
                                                                          'conf_outputs_evelog_tls_extended': 0,
                                                                          'conf_outputs_evelog_files_forcemagic': 1,
                                                                          'conf_outputs_unified2alert': 1,
                                                                          'conf_lua': 1,
                                                                          'conf_applayer_tls': 0,
                                                                          'conf_applayer_dcerpc': 0,
                                                                          'conf_applayer_ftp': 0,
                                                                          'conf_applayer_ssh': 0,
                                                                          'conf_applayer_smtp': 0,
                                                                          'conf_applayer_imap': 2,
                                                                          'conf_applayer_msn': 2,
                                                                          'conf_applayer_smb': 0,
                                                                          'conf_applayer_dns': 0,
                                                                          'conf_applayer_http': 0
                                                                          }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        # Problem with travis
        self.assertIn('Test configuration OK', str(response.content))
        response = self.client.post('/admin/suricata/confsuricata/add/', {'name': 'conftest-false',
                                                                          'conf_rules_directory': '/etc/suricata/rules',
                                                                          'conf_script_directory': '/etc/suricata/lua',
                                                                          'conf_file': '/etc/suricata/suricata.yaml',
                                                                          'conf_advanced': False,
                                                                          'conf_advanced_text': CONF_FULL_DEFAULT,
                                                                          'conf_HOME_NET': "[192.168.0.0/24]",
                                                                          'conf_EXTERNAL_NET': "!$HOME_NET",
                                                                          'conf_HTTP_SERVERS': "$HOME_NET",
                                                                          'conf_SMTP_SERVERS': "$HOME_NET",
                                                                          'conf_SQL_SERVERS': "$HOME_NET",
                                                                          'conf_DNS_SERVERS': "$HOME_NET",
                                                                          'conf_TELNET_SERVERS': "$HOME_NET",
                                                                          'conf_AIM_SERVERS': "$EXTERNAL_NET",
                                                                          'conf_DNP3_SERVER': "$HOME_NET",
                                                                          'conf_DNP3_CLIENT': "$HOME_NET",
                                                                          'conf_MODBUS_CLIENT': "$HOME_NET",
                                                                          'conf_MODBUS_SERVER': "$HOME_NET",
                                                                          'conf_ENIP_CLIENT': "$HOME_NET",
                                                                          'conf_ENIP_SERVER': "$HOME_NET",
                                                                          'conf_HTTP_PORTS': "80",
                                                                          'conf_SHELLCODE_PORTS': "!80",
                                                                          'conf_ORACLE_PORTS': "1521",
                                                                          'conf_SSH_PORTS': "22",
                                                                          'conf_DNP3_PORTS': "20000",
                                                                          'conf_MODBUS_PORTS': "502",
                                                                          'conf_stats': 1,
                                                                          'conf_afpacket_interface': 'eth0',
                                                                          'conf_outputs_fast': 1,
                                                                          'conf_outputs_evelog': 0,
                                                                          'conf_outputs_evelog_alert_http': 0,
                                                                          'conf_outputs_evelog_alert_tls': 0,
                                                                          'conf_outputs_evelog_alert_ssh': 0,
                                                                          'conf_outputs_evelog_alert_smtp': 0,
                                                                          'conf_outputs_evelog_alert_dnp3': 0,
                                                                          'conf_outputs_evelog_alert_taggedpackets': 0,
                                                                          'conf_outputs_evelog_xff': 0,
                                                                          'conf_outputs_evelog_dns_query': 0,
                                                                          'conf_outputs_evelog_dns_answer': 0,
                                                                          'conf_outputs_evelog_http_extended': 0,
                                                                          'conf_outputs_evelog_tls_extended': 0,
                                                                          'conf_outputs_evelog_files_forcemagic': 1,
                                                                          'conf_outputs_unified2alert': 1,
                                                                          'conf_lua': 1,
                                                                          'conf_applayer_tls': 0,
                                                                          'conf_applayer_dcerpc': 0,
                                                                          'conf_applayer_ftp': 0,
                                                                          'conf_applayer_ssh': 0,
                                                                          'conf_applayer_smtp': 0,
                                                                          'conf_applayer_imap': 2,
                                                                          'conf_applayer_msn': 2,
                                                                          'conf_applayer_smb': 0,
                                                                          'conf_applayer_dns': 0,
                                                                          'conf_applayer_http': 0
                                                                          }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        self.assertIn('Test configuration OK', str(response.content))
        self.assertEqual(len(ConfSuricata.get_all()), 4)
        response = self.client.post('/admin/suricata/confsuricata/', {'action': 'test_configurations',
                                                                      '_selected_action': '2'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test configurations OK", str(response.content))
        # Conf failed
        response = self.client.post('/admin/suricata/confsuricata/add/', {'name': 'conftest-failed',
                                                                          'conf_rules_directory': '/etc/suricata/rules',
                                                                          'conf_script_directory': '/etc/suricata/lua',
                                                                          'conf_file': '/etc/suricata/suricata.yaml',
                                                                          'conf_advanced': True,
                                                                          'conf_advanced_text': "FAILED",
                                                                          'conf_HOME_NET': "[192.168.0.0/24]",
                                                                          'conf_EXTERNAL_NET': "!$HOME_NET",
                                                                          'conf_HTTP_SERVERS': "$HOME_NET",
                                                                          'conf_SMTP_SERVERS': "$HOME_NET",
                                                                          'conf_SQL_SERVERS': "$HOME_NET",
                                                                          'conf_DNS_SERVERS': "$HOME_NET",
                                                                          'conf_TELNET_SERVERS': "$HOME_NET",
                                                                          'conf_AIM_SERVERS': "$EXTERNAL_NET",
                                                                          'conf_DNP3_SERVER': "$HOME_NET",
                                                                          'conf_DNP3_CLIENT': "$HOME_NET",
                                                                          'conf_MODBUS_CLIENT': "$HOME_NET",
                                                                          'conf_MODBUS_SERVER': "$HOME_NET",
                                                                          'conf_ENIP_CLIENT': "$HOME_NET",
                                                                          'conf_ENIP_SERVER': "$HOME_NET",
                                                                          'conf_HTTP_PORTS': "80",
                                                                          'conf_SHELLCODE_PORTS': "!80",
                                                                          'conf_ORACLE_PORTS': "1521",
                                                                          'conf_SSH_PORTS': "22",
                                                                          'conf_DNP3_PORTS': "20000",
                                                                          'conf_MODBUS_PORTS': "502",
                                                                          'conf_stats': 1,
                                                                          'conf_afpacket_interface': 'eth0',
                                                                          'conf_outputs_fast': 1,
                                                                          'conf_outputs_evelog': 0,
                                                                          'conf_outputs_evelog_alert_http': 0,
                                                                          'conf_outputs_evelog_alert_tls': 0,
                                                                          'conf_outputs_evelog_alert_ssh': 0,
                                                                          'conf_outputs_evelog_alert_smtp': 0,
                                                                          'conf_outputs_evelog_alert_dnp3': 0,
                                                                          'conf_outputs_evelog_alert_taggedpackets': 0,
                                                                          'conf_outputs_evelog_xff': 0,
                                                                          'conf_outputs_evelog_dns_query': 0,
                                                                          'conf_outputs_evelog_dns_answer': 0,
                                                                          'conf_outputs_evelog_http_extended': 0,
                                                                          'conf_outputs_evelog_tls_extended': 0,
                                                                          'conf_outputs_evelog_files_forcemagic': 1,
                                                                          'conf_outputs_unified2alert': 1,
                                                                          'conf_lua': 1,
                                                                          'conf_applayer_tls': 0,
                                                                          'conf_applayer_dcerpc': 0,
                                                                          'conf_applayer_ftp': 0,
                                                                          'conf_applayer_ssh': 0,
                                                                          'conf_applayer_smtp': 0,
                                                                          'conf_applayer_imap': 2,
                                                                          'conf_applayer_msn': 2,
                                                                          'conf_applayer_smb': 0,
                                                                          'conf_applayer_dns': 0,
                                                                          'conf_applayer_http': 0
                                                                          }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        self.assertIn('Test configuration failed !', str(response.content))
        self.assertEqual(len(ConfSuricata.get_all()), 5)
        response = self.client.post('/admin/suricata/confsuricata/', {'action': 'test_configurations',
                                                                      '_selected_action': '5'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test configurations failed !", str(response.content))
