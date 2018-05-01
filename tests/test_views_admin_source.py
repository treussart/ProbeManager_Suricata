""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_source --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from rules.models import DataTypeUpload, MethodUpload
from suricata.models import SourceSuricata, SignatureSuricata


class ViewsSourceAdminTest(TestCase):
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

    def test_source_signature_file_misp(self):
        response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                                    'method': MethodUpload.get_by_name("MISP").id,
                                    'scheduled_rules_deployment_enabled': 'False',
                                    'scheduled_deploy': 'False',
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

    def test_source_script_file_one_file(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/test-script.lua', encoding='utf_8') as fp:
                response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                                            'method': MethodUpload.get_by_name("Upload file").id,
                                            'file': fp,
                                            'scheduled_rules_deployment_enabled': 'False',
                                            'scheduled_deploy': 'False',
                                            'data_type': DataTypeUpload.get_by_name("one file not compressed").id
                                            }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully : 0 signature(s) created and 0 signature(s) updated -  1 script(s) '
                      'created and 0 script(s) updated', str(response.content))

    def test_source_signature_file_multiple_files(self):
        with open(settings.BASE_DIR + '/suricata/tests/data/emerging.rules.tar.gz', 'rb') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                                        'method': MethodUpload.get_by_name("Upload file").id,
                                        'file': fp,
                                        'scheduled_rules_deployment_enabled': 'False',
                                        'scheduled_deploy': 'False',
                                        'data_type': DataTypeUpload.get_by_name("multiple files in compressed file").id
                                        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('File uploaded successfully :', str(response.content))

    def test_source_delete(self):
        self.assertEqual(len(SourceSuricata.get_all()), 2)
        for source in SourceSuricata.get_all():
            response = self.client.post('/admin/suricata/sourcesuricata/', {'action': 'delete_selected',
                                                                            '_selected_action': source.id},
                                        follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn('Are you sure you want to delete the selected ', str(response.content))
            response = self.client.post('/admin/suricata/sourcesuricata/',
                                        {'action': 'delete_selected',
                                         '_selected_action': source.id,
                                         'post': 'yes'},
                                        follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SourceSuricata.get_all()), 0)
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
        self.assertEqual(len(SourceSuricata.get_all()), 1)
        response = self.client.post('/admin/suricata/sourcesuricata/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SourceSuricata.get_all()[0].id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/suricata/sourcesuricata/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SourceSuricata.get_all()[0].id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SourceSuricata.get_all()), 0)

    def test_raise_not_found_param(self):
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
        with open(settings.BASE_DIR + '/suricata/tests/data/error-sid.rules', encoding='utf_8') as fp:
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
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
        with open(settings.BASE_DIR + '/suricata/tests/data/error-classtype.rules', encoding='utf_8') as fp:
            response = self.client.post('/admin/suricata/sourcesuricata/add/', {
                'method': MethodUpload.get_by_name("Upload file").id,
                'file': fp,
                'scheduled_rules_deployment_enabled': 'False',
                'scheduled_deploy': 'False',
                'data_type': DataTypeUpload.get_by_name("one file not compressed").id,
                'rulesets': '1',
            }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('SignatureSuricata has no classtype.', str(response.content))
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
