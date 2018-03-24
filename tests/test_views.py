""" venv/bin/python probemanager/manage.py test suricata.tests.test_views --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from rules.models import DataTypeUpload, MethodUpload
from suricata.models import Suricata, SourceSuricata


class ViewsSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-conf', 'test-suricata-suricata']

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
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

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
        response = self.client.post('/admin/suricata/suricata/', {'action': 'delete_suricata', '_selected_action': '2'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(Suricata.get_all()), 1)
