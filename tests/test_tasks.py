""" venv/bin/python probemanager/manage.py test suricata.tests.test_tasks --settings=probemanager.settings.dev """
from django.test import TestCase

from core.tasks import reload_probe, deploy_rules
from suricata.tasks import upload_url_http
from suricata.models import Suricata, SourceSuricata


class TasksSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_deploy_rules(self):
        suricata = Suricata.get_by_id(1)
        response = deploy_rules(suricata.name)
        if 'exception' in response:
            print(response['exception'])
        self.assertEqual('Probe suricata1 deployed rules successfully', response['message'])

    def test_reload_probe(self):
        suricata = Suricata.get_by_id(1)
        response = reload_probe(suricata.name)
        if 'exception' in response:
            print(response['exception'])
        self.assertEqual('Probe suricata1 reloaded successfully', response['message'])

    def test_upload_url_http(self):
        source = SourceSuricata.get_by_id(1)
        response = upload_url_http(source.uri)
        if 'exception' in response:
            print(response['exception'])
        self.assertIn('Source https://sslbl.abuse.ch/blacklist/sslblacklist.rules uploaded successfully : ', response['message'])

        source = SourceSuricata.get_by_id(2)
        response = upload_url_http(source.uri)
        if 'exception' in response:
            print(response['exception'])
        self.assertIn('Source https://rules.emergingthreats.net/open/suricata-3.3.1/emerging.rules.tar.gz uploaded successfully by HTTP', response['message'])
