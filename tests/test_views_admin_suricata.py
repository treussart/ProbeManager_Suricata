""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_suricata --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import Suricata, SignatureSuricata, RuleSetSuricata


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
        self.client.logout()

    def test_suricata(self):
        response = self.client.get('/admin/suricata/suricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/suricata/', {'action': 'test_signatures',
                                                                  '_selected_action': '1'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signatures OK', str(response.content))
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
        response = self.client.get('/admin/suricata/suricata/add/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(Suricata.get_all()), 1)
        response = self.client.post('/admin/suricata/suricata/add/',
                                    {'name': 'test',
                                     'secure_deployment': True,
                                     'scheduled_rules_deployment_enabled': True,
                                     'scheduled_rules_deployment_crontab': 4,
                                     'scheduled_check_enabled': True,
                                     'scheduled_check_crontab': 3,
                                     'server': 1,
                                     'rulesets': str(RuleSetSuricata.get_by_name('test_signatures').id),
                                     'configuration': 1,
                                     'installed': True}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(' was added successfully', str(response.content))
        self.assertEqual(len(Suricata.get_all()), 2)
        response = self.client.post('/admin/suricata/suricata/', {'action': 'test_signatures',
                                                                  '_selected_action': '2'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signatures failed !', str(response.content))

        self.assertEqual(Suricata.get_by_id(2).installed, True)
        response = self.client.post('/admin/suricata/suricata/2/change/', {'name': 'test',
                                                                           'secure_deployment': True,
                                                                           'scheduled_rules_deployment_enabled': True,
                                                                           'scheduled_rules_deployment_crontab': 4,
                                                                           'scheduled_check_enabled': True,
                                                                           'scheduled_check_crontab': 3,
                                                                           'server': 1,
                                                                           'rulesets': '1',
                                                                           'configuration': 1,
                                                                           'installed': False}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Suricata.get_by_id(2).installed, False)
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
