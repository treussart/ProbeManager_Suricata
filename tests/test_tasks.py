""" venv/bin/python probemanager/manage.py test suricata.tests.test_tasks --settings=probemanager.settings.dev """
from django.test import TestCase
from django.conf import settings

from core.tasks import reload_probe, deploy_rules
from suricata.tasks import download_from_http
from suricata.models import Suricata, SourceSuricata


class TasksSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    @classmethod
    def setUpTestData(cls):
        settings.CELERY_TASK_ALWAYS_EAGER = True

    def test_deploy_rules(self):
        suricata = Suricata.get_by_id(1)
        response = deploy_rules.delay(suricata.name)
        self.assertEquals(response.get()['message'], 'Probe suricata1 deployed rules successfully')
        self.assertTrue(response.successful())

    def test_reload_probe(self):
        suricata = Suricata.get_by_id(1)
        response = reload_probe.delay(suricata.name)
        self.assertEqual(response.get()['message'], 'Probe suricata1 reloaded successfully')
        self.assertTrue(response.successful())

    def test_download_from_http(self):
        source = SourceSuricata.get_by_id(1)
        response = download_from_http.delay(source.uri)
        self.assertEqual(response.get()['message'], 'Source https://sslbl.abuse.ch/blacklist/sslblacklist.rules uploaded successfully by HTTP')
        self.assertTrue(response.successful())

        source = SourceSuricata.get_by_id(2)
        response = download_from_http.delay(source.uri)
        self.assertEqual(response.get()['message'], 'Source https://rules.emergingthreats.net/open/suricata-3.3.1/emerging.rules.tar.gz uploaded successfully by HTTP')
        self.assertTrue(response.successful())
