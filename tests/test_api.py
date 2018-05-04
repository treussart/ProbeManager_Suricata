""" venv/bin/python probemanager/manage.py test suricata.tests.test_api --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from suricata.models import Suricata, BlackList


class APITest(APITestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset', 'test-suricata-conf', 'test-suricata-suricata']

    def setUp(self):
        self.client = APIClient()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_conf(self):
        response = self.client.get('/api/v1/suricata/configuration/1/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_suricata(self):
        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        data = {'name': 'test',
                'secure_deployment': True,
                'scheduled_rules_deployment_enabled': True,
                'scheduled_rules_deployment_crontab': 4,
                'scheduled_check_enabled': True,
                'scheduled_check_crontab': 3,
                'server': 1,
                'rulesets': [1, ],
                'configuration': 1,
                'installed': True}

        data_put = {'secure_deployment': True,
                    'server': 1,
                    'rulesets': [1, ],
                    'configuration': 1,
                    'installed': False}

        data_patch = {'installed': True}

        response = self.client.post('/api/v1/suricata/suricata/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post('/api/v1/suricata/suricata/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)

        self.assertTrue(PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4))))
        self.assertTrue(PeriodicTask.objects.get(name="test_check_task"))

        response = self.client.put('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/', data_put)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Suricata.get_by_name('test').installed)

        response = self.client.put('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/',
                                   {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/', data_patch)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Suricata.get_by_name('test').installed)

        response = self.client.patch('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/',
                                     {'scheduled_rules_deployment_enabled': False})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Suricata.get_by_name('test').scheduled_rules_deployment_enabled)

        response = self.client.delete('/api/v1/suricata/suricata/' + str(Suricata.get_by_name('test').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/suricata/suricata/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4)))
        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_check_task")

        response = self.client.get('/api/v1/suricata/suricata/1/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/start/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/stop/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/restart/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/reload/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/status/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/uptime/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['uptime'])

        response = self.client.get('/api/v1/suricata/suricata/1/deploy_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/suricata/suricata/1/deploy_conf/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        # response = self.client.get('/api/v1/suricata/suricata/1/install/')
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])
        #
        # response = self.client.get('/api/v1/suricata/suricata/1/install/?version=' + settings.SURICATA_VERSION)
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])

    def test_signature(self):
        response = self.client.get('/api/v1/suricata/signature/1/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    # def test_script(self):
    #     response = self.client.get('/api/v1/suricata/script/3/test/')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertTrue(response.data['status'])

    def test_ruleset(self):
        response = self.client.get('/api/v1/suricata/ruleset/2/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_blacklist(self):
        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)

        data = {'type': 'IP',
                'value': '192.168.0.1',
                'comment': 'test',
                'rulesets': [1, ]
                }
        data2 = {'type': 'MD5',
                 'value': 'ertertert',
                 'comment': 'test',
                 'rulesets': [1, ]
                 }

        response = self.client.post('/api/v1/suricata/blacklist/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post('/api/v1/suricata/blacklist/', {'value': '192.168.0.1'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        response = self.client.delete('/api/v1/suricata/blacklist/' +
                                      str(BlackList.objects.get(value='192.168.0.1').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/suricata/blacklist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)

        response = self.client.post('/api/v1/suricata/blacklist/', data2)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.delete('/api/v1/suricata/blacklist/' +
                                      str(BlackList.objects.get(value='ertertert').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
