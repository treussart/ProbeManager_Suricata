""" venv/bin/python probemanager/manage.py test suricata.tests.test_views --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from rules.models import DataTypeUpload, MethodUpload
from suricata.models import Suricata, SourceSuricata, SignatureSuricata, ConfSuricata, ScriptSuricata


class ViewsSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-conf', 'test-suricata-suricata']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

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
        response = self.client.get('/suricata/' + str(99))
        self.assertEqual(response.status_code, 404)


class ViewsSuricataAdminTest(TestCase):
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
        pass
        # self.client.logout()

    def test_source_signature(self):
        """ Upload Signature page."""
        response = self.client.get('/admin/suricata/sourcesuricata/add/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Add source suricata | Probe Manager site admin</title>', str(response.content))
        self.assertEqual('admin/change_form.html', response.templates[0].name)
        self.assertIn('admin', response.resolver_match.app_names)
        self.assertIn('function ModelAdmin.add_view', str(response.resolver_match.func))
        self.assertEqual(str(response.context['user']), 'testuser')
        with self.assertTemplateUsed('admin/change_form.html'):
            self.client.get('/admin/suricata/sourcesuricata/add/')

    def test_source_signature_http_multiple_files(self):
        response = self.client.post('/admin/suricata/sourcesuricata/add/',
                                    {'method': MethodUpload.get_by_name("URL HTTP").id,
                                     'uri': 'https://rules.emergingthreats.net/open/suricata-2.0.1/'
                                            'emerging.rules.tar.gz',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'False',
                                     'data_type': DataTypeUpload.get_by_name("multiple files in compressed file").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Upload source in progress.', str(response.content))

    def test_source_signature_http_one_file(self):
        for source in SourceSuricata.objects.all():
            source.delete()
        for p in PeriodicTask.objects.all():
            p.delete()
        response = self.client.post('/admin/suricata/sourcesuricata/add/',
                                    {'method': MethodUpload.get_by_name("URL HTTP").id,
                                     'uri': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'False',
                                     'data_type': DataTypeUpload.get_by_name("one file not compressed").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Upload source in progress.', str(response.content))

    def test_source_signature_http_one_file_deploy(self):
        for source in SourceSuricata.objects.all():
            source.delete()
        for p in PeriodicTask.objects.all():
            p.delete()
        response = self.client.post('/admin/suricata/sourcesuricata/add/',
                                    {'method': MethodUpload.get_by_name("URL HTTP").id,
                                     'uri': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'True',
                                     'rulesets': '1',
                                     'data_type': DataTypeUpload.get_by_name("one file not compressed").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Upload source in progress.', str(response.content))

    def test_source_signature_http_one_file_deploy_with_probe(self):
        for source in SourceSuricata.objects.all():
            source.delete()
        for p in PeriodicTask.objects.all():
            p.delete()
        response = self.client.post('/admin/suricata/sourcesuricata/add/',
                                    {'method': MethodUpload.get_by_name("URL HTTP").id,
                                     'uri': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'True',
                                     'rulesets': '1',
                                     'data_type': DataTypeUpload.get_by_name("one file not compressed").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Upload source in progress.', str(response.content))

    def test_source_signature_file_one_file(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/sslblacklist.rules', encoding='utf_8') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                'method': MethodUpload.get_by_name("Upload file").id,
                'file': fp,
                'scheduled_rules_deployment_enabled': 'False',
                'scheduled_deploy': 'False',
                'data_type': DataTypeUpload.get_by_name("one file not compressed").id
            }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully :', str(response.content))

    def test_source_signature_file_one_file_error(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/error.rules', encoding='utf_8') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                'method': MethodUpload.get_by_name("Upload file").id,
                'file': fp,
                'scheduled_rules_deployment_enabled': 'False',
                'scheduled_deploy': 'False',
                'data_type': DataTypeUpload.get_by_name("one file not compressed").id,
                'rulesets': '1',
            }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully :', str(response.content))

    def test_source_signature_file_multiple_files(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/emerging.rules.tar.gz', 'rb') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                'method': MethodUpload.get_by_name("Upload file").id,
                'file': fp,
                'scheduled_rules_deployment_enabled': 'False',
                'scheduled_deploy': 'False',
                'data_type': DataTypeUpload.get_by_name("multiple files in compressed file").id
            }, follow=True)
        self.assertIn('File uploaded successfully :', str(response.content))

    def test_index(self):
        # index
        response = self.client.get('/admin/suricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Suricata administration', str(response.content))

    def test_rule_set(self):
        response = self.client.get('/admin/suricata/rulesetsuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'test_signatures',
                                                                         '_selected_action': '1'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signatures OK', str(response.content))
        # test fail test signature
        response = self.client.post('/admin/suricata/signaturesuricata/add/', {'rev': '0',
                                                                               'rule_full': '1',
                                                                               'sid': '666',
                                                                               'classtype': '2',
                                                                               'msg': 'fail test',
                                                                               },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/rulesetsuricata/add/', {'name': 'test_signatures',
                                                                             'description': 'test fail',
                                                                             'signatures': str(SignatureSuricata.
                                                                                               get_by_sid(666).id)
                                                                             },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'test_signatures',
                                                                         '_selected_action': '4'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signatures failed !', str(response.content))
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'delete_selected',
                                                                         '_selected_action': '4'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'delete_selected',
                                                                         '_selected_action': '4',
                                                                         'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))

    def test_suricata(self):
        response = self.client.get('/admin/suricata/suricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/suricata/', {'action': 'test_signatures',
                                                                         '_selected_action': '1'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signatures OK', str(response.content))
        response = self.client.get('/admin/suricata/suricata/add/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(Suricata.get_all()), 1)
        response = self.client.post('/admin/suricata/suricata/add/', {'name': 'test',
                                                                      'secure_deployment': True,
                                                                      'scheduled_rules_deployment_enabled': True,
                                                                      'scheduled_rules_deployment_crontab': 4,
                                                                      'scheduled_check_enabled': True,
                                                                      'scheduled_check_crontab': 3,
                                                                      'server': 1,
                                                                      'rulesets': '1',
                                                                      'configuration': 1,
                                                                      'installed': True}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        self.assertEqual(len(Suricata.get_all()), 2)
        response = self.client.post('/admin/suricata/suricata/2/change/', {'installed': False}, follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/suricata/', {'action': 'delete_suricata', '_selected_action': '2'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Suricata instance test deleted", str(response.content))
        self.assertEqual(len(Suricata.get_all()), 1)

        response = self.client.post('/admin/suricata/suricata/add/', {'name': 'test',
                                                                      'secure_deployment': True,
                                                                      'scheduled_rules_deployment_enabled': True,
                                                                      'scheduled_rules_deployment_crontab': 4,
                                                                      'scheduled_check_enabled': True,
                                                                      'scheduled_check_crontab': 3,
                                                                      'server': 1,
                                                                      'rulesets': '1',
                                                                      'configuration': 1,
                                                                      'installed': True}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        response = self.client.get('/admin/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/delete/',
                                   follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure ', str(response.content))
        response = self.client.post('/admin/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/delete/',
                                    {'post': 'yes'}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Suricata instance test deleted", str(response.content))
        self.assertEqual(len(Suricata.get_all()), 1)

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
        self.assertIn('Test conf OK', str(response.content))
        self.assertEqual(len(ConfSuricata.get_all()), 3)
        response = self.client.post('/admin/suricata/confsuricata/', {'action': 'test_configurations',
                                                                      '_selected_action': '2'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test configurations OK", str(response.content))

    def test_script(self):
        self.assertEqual(len(ScriptSuricata.get_all()), 1)
        response = self.client.get('/admin/suricata/scriptsuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_enabled',
                                                                      '_selected_action': str(ScriptSuricata.
                                                                                              get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as enabled", str(response.content))
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_disabled',
                                                                      '_selected_action': str(ScriptSuricata.
                                                                                              get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as disabled", str(response.content))

    def test_signature(self):
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
        response = self.client.get('/admin/suricata/signaturesuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/signaturesuricata/', {'action': 'make_enabled',
                                                                      '_selected_action': str(SignatureSuricata.
                                                                                              get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as enabled", str(response.content))
        response = self.client.post('/admin/suricata/signaturesuricata/', {'action': 'make_disabled',
                                                                      '_selected_action': str(SignatureSuricata.
                                                                                              get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as disabled", str(response.content))
