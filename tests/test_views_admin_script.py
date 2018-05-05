""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_script --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import ScriptSuricata


class ViewsScriptAdminTest(TestCase):
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

    def test_script(self):
        self.assertEqual(len(ScriptSuricata.get_all()), 1)
        response = self.client.get('/admin/suricata/scriptsuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_enabled',
                                                                        '_selected_action': str(ScriptSuricata.
                                                                                                get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as enabled", str(response.content))
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_disabled',
                                                                        '_selected_action': str(ScriptSuricata.
                                                                                                get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as disabled", str(response.content))

        response = self.client.post('/admin/suricata/scriptsuricata/add/', {'rev': '0',
                                                                            'rule_full': '1',
                                                                            'filename': 'fail_script_test.lua',
                                                                            },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_enabled',
                                                                        '_selected_action': [3, 4]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as enabled", str(response.content))
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'make_disabled',
                                                                        '_selected_action': [3, 4]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as disabled", str(response.content))
        self.assertEqual(len(ScriptSuricata.get_all()), 2)
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'delete_selected',
                                                                        '_selected_action': '4'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/suricata/scriptsuricata/', {'action': 'delete_selected',
                                                                        '_selected_action': '4',
                                                                        'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(ScriptSuricata.get_all()), 1)
