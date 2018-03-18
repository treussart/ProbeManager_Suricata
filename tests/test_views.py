""" venv/bin/python probemanager/manage.py test suricata.tests.test_views --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from rules.models import ClassType, DataTypeUpload, MethodUpload
from suricata.models import SignatureSuricata
from suricata.models import Suricata


# from unittest import skip


class ViewsSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_index(self):
        """
        Suricata page
        """
        suricata = Suricata.get_by_id(1)
        response = self.client.get('/suricata/' + str(suricata.id))
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Suricata</title>', str(response.content))
        self.assertEqual('suricata/index.html', response.templates[0].name)
        self.assertIn('suricata', response.resolver_match.app_names)
        self.assertIn('function index', str(response.resolver_match.func))
        self.assertEqual(str(response.context['user']), 'testuser')
        with self.assertTemplateUsed('suricata/index.html'):
            self.client.get('/suricata/' + str(suricata.id))
        response = self.client.get('/suricata/' + str(99))
        self.assertEqual(response.status_code, 404)


class ViewsSuricataSourceAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-conf', 'test-suricata-probe']

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
                                     'uri': 'https://rules.emergingthreats.net/open/suricata-2.0.1/emerging.rules.tar.gz',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'False',
                                     'data_type': DataTypeUpload.get_by_name("multiple files in compressed file").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(ClassType.get_by_name('suspicious-login').name, 'suspicious-login')
        self.assertEqual(SignatureSuricata.get_by_sid(2102088).msg, 'GPL RPC ypupdated arbitrary command attempt UDP')
        self.assertEqual(SignatureSuricata.get_by_sid(2008860).msg,
                         'ET TELNET External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Dissalowed Until Password Set)')

    def test_source_signature_http_one_file(self):
        response = self.client.post('/admin/suricata/sourcesuricata/add/',
                                    {'method': MethodUpload.get_by_name("URL HTTP").id,
                                     'uri': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                                     'scheduled_rules_deployment_enabled': 'True',
                                     'scheduled_rules_deployment_crontab': CrontabSchedule.objects.get(id=1).id,
                                     'scheduled_deploy': 'False',
                                     'data_type': DataTypeUpload.get_by_name("one file not compressed").id
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(902332052).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')
        self.assertEqual(SignatureSuricata.get_by_sid(902332065).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')

    def test_source_signature_http_one_file_deploy(self):
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
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(902332052).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')
        self.assertEqual(SignatureSuricata.get_by_sid(902332065).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')

    def test_source_signature_http_one_file_deploy_with_probe(self):
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
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(902332052).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')
        self.assertEqual(SignatureSuricata.get_by_sid(902332065).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')
        self.assertEqual(PeriodicTask.objects.get(id=1).name,
                         "https://sslbl.abuse.ch/blacklist/sslblacklist.rules_upload_task")
        self.assertEqual(PeriodicTask.objects.get(id=2).name,
                         "suricata1_source_deploy_rules_*/40 * * * * (m/h/d/dM/MY)")

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
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(902332052).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')
        self.assertEqual(SignatureSuricata.get_by_sid(902332065).msg,
                         'SSL Fingerprint Blacklist: Malicious SSL certificate detected (Quakbot C&C)')

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
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(2400000).msg,
                         'ET DROP Spamhaus DROP Listed Traffic Inbound group 1')

    def test_source_signature_file_multiple_files(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/emerging.rules.tar.gz', 'rb', encoding='utf_8') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                'method': MethodUpload.get_by_name("Upload file").id,
                'file': fp,
                'scheduled_rules_deployment_enabled': 'False',
                'scheduled_deploy': 'False',
                'data_type': DataTypeUpload.get_by_name("multiple files in compressed file").id
            }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully', str(response.content))
        self.assertEqual(SignatureSuricata.get_by_sid(2102088).msg, 'GPL RPC ypupdated arbitrary command attempt UDP')
        self.assertEqual(SignatureSuricata.get_by_sid(2008860).msg,
                         'ET TELNET External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Dissalowed Until Password Set)')
