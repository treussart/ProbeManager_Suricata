""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_ruleset --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import SignatureSuricata


class ViewsRuleSetAdminTest(TestCase):
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

    def test_rule_set(self):
        response = self.client.get('/admin/suricata/rulesetsuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'test_rules',
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
        response = self.client.post('/admin/suricata/rulesetsuricata/', {'action': 'test_rules',
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
