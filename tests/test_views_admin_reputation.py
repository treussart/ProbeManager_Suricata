""" venv/bin/python probemanager/manage.py test suricata.tests.test_views_admin_reputation --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from suricata.models import IPReputation, CategoryReputation


class ViewsConfAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-source', 'test-suricata-conf',
                'test-suricata-suricata', 'test-suricata-reputation']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))
        self.date_now = timezone.now()

    def tearDown(self):
        self.client.logout()

    def test_ip_rep(self):
        response = self.client.get('/admin/suricata/ipreputation/', follow=True)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(len(IPReputation.get_all()), 1)
        response = self.client.post('/admin/suricata/ipreputation/add/', {'ip': '1.1.1.1',
                                                                                  'category': '1',
                                                                                  'reputation_score': '10',
                                                                                  },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully.', str(response.content))
        self.assertEqual(len(IPReputation.get_all()), 2)
        response = self.client.post('/admin/suricata/ipreputation/add/', {'ip': '1.1.1.1',
                                                                                  'category': '1',
                                                                                  'reputation_score': '10',
                                                                                  },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Ip reputation with this Ip already exists.', str(response.content))
        self.assertEqual(len(IPReputation.get_all()), 2)

        response = self.client.get('/admin/suricata/ipreputation/import_csv/', follow=True)
        self.assertEqual(response.status_code, 200)
        with open(settings.BASE_DIR + '/suricata/tests/data/ip-rep.csv', encoding='utf_8') as f:
            response = self.client.post('/admin/suricata/ipreputation/import_csv/', {'file': f},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('CSV file imported successfully !', str(response.content))

    def test_cat_rep(self):
        response = self.client.get('/admin/suricata/categoryreputation/', follow=True)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(len(CategoryReputation.get_all()), 1)
        response = self.client.post('/admin/suricata/categoryreputation/add/', {'short_name': 'test',
                                                                                        'description': 'super test',
                                                                                        },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully.',
                      str(response.content))
        self.assertEqual(len(CategoryReputation.get_all()), 2)
        response = self.client.post('/admin/suricata/categoryreputation/add/', {'short_name': 'test',
                                                                                        'description': 'super test',
                                                                                        },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Category reputation with this Short name already exists.', str(response.content))
        self.assertEqual(len(CategoryReputation.get_all()), 2)
        # Import CSV
        response = self.client.get('/admin/suricata/categoryreputation/import_csv/', follow=True)
        self.assertEqual(response.status_code, 200)
        with open(settings.BASE_DIR + '/suricata/tests/data/cat-rep.csv', encoding='utf_8') as f:
            response = self.client.post('/admin/suricata/categoryreputation/import_csv/', {'file': f},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Error during the import : Category id already exist under another short name',
                      str(response.content))
        CategoryReputation.get_by_short_name('test').delete()
        with open(settings.BASE_DIR + '/suricata/tests/data/cat-rep.csv', encoding='utf_8') as f:
            response = self.client.post('/admin/suricata/categoryreputation/import_csv/', {'file': f},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('CSV file imported successfully !', str(response.content))
