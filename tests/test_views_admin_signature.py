""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_signature --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import SignatureSuricata


class ViewsSignatureAdminTest(TestCase):
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

    def test_signature(self):
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
        response = self.client.get('/admin/suricata/signaturesuricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(SignatureSuricata.get_by_sid(20402000).enabled)
        self.assertTrue(SignatureSuricata.get_by_sid(2405001).enabled)
        response = self.client.post('/admin/suricata/signaturesuricata/',
                                    {'action': 'make_disabled',
                                     '_selected_action':  str(SignatureSuricata.get_by_sid(20402000).id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as disabled", str(response.content))
        self.assertFalse(SignatureSuricata.get_by_sid(20402000).enabled)
        response = self.client.post('/admin/suricata/signaturesuricata/',
                                    {'action': 'make_enabled',
                                     '_selected_action': str(SignatureSuricata.get_by_sid(20402000).id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as enabled", str(response.content))
        self.assertTrue(SignatureSuricata.get_by_sid(20402000).enabled)

        response = self.client.post('/admin/suricata/signaturesuricata/',
                                    {'action': 'make_disabled',
                                     '_selected_action': [SignatureSuricata.get_by_sid(20402000).id,
                                                          SignatureSuricata.get_by_sid(2405001).id]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as disabled", str(response.content))
        response = self.client.post('/admin/suricata/signaturesuricata/',
                                    {'action': 'make_enabled',
                                     '_selected_action': [SignatureSuricata.get_by_sid(20402000).id,
                                                          SignatureSuricata.get_by_sid(2405001).id]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as enabled", str(response.content))

        response = self.client.post('/admin/suricata/signaturesuricata/add/', {'rev': '0',
                                                                               'rule_full': '1',
                                                                               'sid': '666',
                                                                               'classtype': '2',
                                                                               'msg': 'fail test',
                                                                               },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(SignatureSuricata.get_all()), 3)
        response = self.client.post('/admin/suricata/signaturesuricata/', {'action': 'delete_selected',
                                                                           '_selected_action': '4'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/suricata/signaturesuricata/', {'action': 'delete_selected',
                                                                           '_selected_action': '4',
                                                                           'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SignatureSuricata.get_all()), 2)
