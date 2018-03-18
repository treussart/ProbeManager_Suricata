""" venv/bin/python probemanager/manage.py test suricata.tests.test_models --settings=probemanager.settings.dev """
import os

from django.db.utils import IntegrityError
from django.test import TestCase
from django.utils import timezone

from rules.models import ClassType
from suricata.models import AppLayerType, ConfSuricata, Suricata, SignatureSuricata, ScriptSuricata, RuleSetSuricata, \
    SourceSuricata


class SourceSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_source_suricata(self):
        all_source_suricata = SourceSuricata.get_all()
        source_suricata = SourceSuricata.get_by_id(1)
        self.assertEqual(len(all_source_suricata), 1)
        self.assertEqual(source_suricata.method.name, "URL HTTP")
        self.assertEqual(str(source_suricata), "https://sslbl.abuse.ch/blacklist/sslblacklist.rules")
        source_suricata = SourceSuricata.get_by_id(99)
        self.assertEqual(source_suricata, None)
        with self.assertRaises(AttributeError):
            source_suricata.method
        with self.assertRaises(IntegrityError):
            SourceSuricata.objects.create(uri="https://sslbl.abuse.ch/blacklist/sslblacklist.rules")


class AppLayerTypeTest(TestCase):
    fixtures = ['init', 'init-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_data_type_upload(self):
        all_app_layer_type = AppLayerType.get_all()
        app_layer_type = AppLayerType.get_by_id(1)
        self.assertEqual(len(all_app_layer_type), 3)
        self.assertEqual(app_layer_type.name, "no")
        self.assertEqual(str(app_layer_type), "no")
        app_layer_type = AppLayerType.get_by_id(99)
        self.assertEqual(app_layer_type, None)
        with self.assertRaises(AttributeError):
            app_layer_type.name
        with self.assertRaises(IntegrityError):
            AppLayerType.objects.create(name="no")


class ConfSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-conf']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_conf_suricata(self):
        all_conf_suricata = ConfSuricata.get_all()
        conf_suricata = ConfSuricata.get_by_id(1)
        self.assertEqual(len(all_conf_suricata), 2)
        self.assertEqual(conf_suricata.name, "confSuricata1")
        self.assertEqual(conf_suricata.conf_rules_directory, "/etc/suricata/rules")
        self.assertEqual(conf_suricata.conf_script_directory, "/etc/suricata/lua")
        self.assertEqual(conf_suricata.conf_file, "/etc/suricata/suricata.yaml")
        self.assertTrue(conf_suricata.conf_advanced)
        self.assertEqual(str(conf_suricata), "confSuricata1")
        conf_suricata = ConfSuricata.get_by_id(99)
        self.assertEqual(conf_suricata, None)
        with self.assertRaises(AttributeError):
            conf_suricata.name
        with self.assertRaises(IntegrityError):
            ConfSuricata.objects.create(name="confSuricata1")


class RuleSetSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_ruleset_suricata(self):
        all_ruleset_suricata = RuleSetSuricata.get_all()
        ruleset_suricata = RuleSetSuricata.get_by_id(1)
        self.assertEqual(len(all_ruleset_suricata), 3)
        self.assertEqual(ruleset_suricata.name, "ruleset1")
        self.assertEqual(ruleset_suricata.description, "test")
        self.assertEqual(str(ruleset_suricata), "ruleset1")
        ruleset_suricata = RuleSetSuricata.get_by_id(99)
        self.assertEqual(ruleset_suricata, None)
        with self.assertRaises(AttributeError):
            ruleset_suricata.name
        with self.assertRaises(IntegrityError):
            RuleSetSuricata.objects.create(name="ruleset1",
                                           description="",
                                           created_date=self.date_now
                                           )


class ScriptSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-script']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_script_suricata(self):
        all_script_suricata = ScriptSuricata.get_all()
        script_suricata = ScriptSuricata.get_by_id(3)
        script_suricatas = ScriptSuricata.find(".php")
        self.assertEqual(len(all_script_suricata), 1)
        self.assertEqual(script_suricata.name, "test.lua")
        self.assertEqual(script_suricata.rev, 0)
        self.assertEqual(script_suricata.reference, None)
        self.assertTrue(script_suricata.enabled)
        self.assertEqual(script_suricatas[0].name, "test.lua")
        self.assertEqual(str(script_suricata), "test.lua")
        self.assertEqual(ScriptSuricata.get_by_name("test.lua").rev, 0)
        script_suricata = ScriptSuricata.get_by_id(99)
        self.assertEqual(script_suricata, None)
        with self.assertRaises(AttributeError):
            script_suricata.name
        with self.assertRaises(IntegrityError):
            ScriptSuricata.objects.create(name="test.lua",
                                          rev=0,
                                          reference="http://doc.emergingthreats.net/2000026",
                                          rule_full="""alert dns any any -> any any (msg:"SURICATA DNS flow memcap reached"; flow:to_server; app-layer-event:dns.state_memcap_reached; sid:2240008; rev:2;)""",
                                          enabled=True,
                                          created_date=self.date_now
                                          )


class SignatureSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-signature']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_signature_suricata(self):
        all_signature_suricata = SignatureSuricata.get_all()
        signature_suricata = SignatureSuricata.get_by_id(1)
        signature_suricatas = SignatureSuricata.find("Dshield")
        self.assertEqual(len(all_signature_suricata), 2)
        self.assertEqual(signature_suricata.sid, 20402000)
        self.assertEqual(signature_suricata.rev, 4549)
        self.assertEqual(signature_suricata.msg, "ET DROP Dshield Block Listed Source group 1")
        self.assertEqual(signature_suricata.reference, "http://www.exemple.com")
        self.assertEqual(signature_suricata.classtype, ClassType.get_by_id(29))
        self.assertTrue(signature_suricata.enabled)
        self.assertEqual(SignatureSuricata.get_by_sid(20402000).msg, "ET DROP Dshield Block Listed Source group 1")

        self.assertEqual(signature_suricatas[0].msg, "ET DROP Dshield Block Listed Source group 1")
        self.assertEqual(str(signature_suricata),
                         str(signature_suricata.sid) + " : " + "ET DROP Dshield Block Listed Source group 1")
        signature_suricata = SignatureSuricata.get_by_id(99)
        self.assertEqual(signature_suricata, None)
        with self.assertRaises(AttributeError):
            signature_suricata.sid
        with self.assertRaises(IntegrityError):
            SignatureSuricata.objects.create(sid=20402000,
                                             rev=0,
                                             msg="HTTP attack",
                                             reference="http://doc.emergingthreats.net/2000026",
                                             classtype=ClassType.get_by_id(1),
                                             rule_full="""alert dns any any -> any any (msg:"SURICATA DNS flow memcap reached"; flow:to_server; app-layer-event:dns.state_memcap_reached; sid:2240008; rev:2;)""",
                                             enabled=True,
                                             created_date=self.date_now
                                             )


class SuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature', 'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_suricata(self):
        all_suricata = Suricata.get_all()
        suricata = Suricata.get_by_id(1)
        self.assertEqual(len(all_suricata), 1)
        self.assertEqual(suricata.name, "suricata1")
        self.assertEqual(str(suricata), "suricata1  test")
        suricata = Suricata.get_by_id(99)
        self.assertEqual(suricata, None)
        with self.assertRaises(AttributeError):
            suricata.name
        with self.assertRaises(IntegrityError):
            Suricata.objects.create(name="suricata1")

    def test_test(self):
        suricata = Suricata.get_by_id(1)
        response = suricata.server.test()
        self.assertTrue(response)
        response = suricata.server.test_root()
        self.assertTrue(response)

    def test_reload(self):
        suricata = Suricata.get_by_id(1)
        response = suricata.reload()
        self.assertTrue(response['status'])

    def test_deploy_conf(self):
        suricata = Suricata.get_by_id(1)
        response = suricata.deploy_conf()
        self.assertTrue(response['status'])

    def test_deploy_rules(self):
        suricata = Suricata.get_by_id(1)
        response = suricata.deploy_rules()
        self.assertTrue(response['status'])
