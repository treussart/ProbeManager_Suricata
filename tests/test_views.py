""" venv/bin/python probemanager/manage.py test suricata.tests.test_views --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from suricata.models import Suricata


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

    def test_admin_index(self):
        # index
        response = self.client.get('/admin/suricata/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Suricata administration', str(response.content))
