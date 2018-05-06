""" venv/bin/python probemanager/manage.py test suricata.tests.test_models --settings=probemanager.settings.dev """
import subprocess
import os
from django.conf import settings
from django.db.utils import IntegrityError
from django.test import TestCase
from django.utils import timezone

from core.models import Configuration as CoreConfiguration
from rules.models import DataTypeUpload, MethodUpload
from suricata.models import AppLayerType, Configuration, Suricata, SignatureSuricata, ScriptSuricata, RuleSetSuricata, \
    SourceSuricata, IPReputation, CategoryReputation, ClassType, ValidationType


class ClassTypeTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_class_type(self):
        all_class_type = ClassType.get_all()
        class_type = ClassType.get_by_id(1)
        self.assertEqual(len(all_class_type), 34)
        self.assertEqual(class_type.name, "unknown")
        self.assertEqual(str(class_type), "unknown")

        class_type = ClassType.get_by_id(99)
        self.assertEqual(class_type, None)
        with self.assertRaises(AttributeError):
            class_type.name
        with self.assertRaises(IntegrityError):
            ClassType.objects.create(name="unknown")


class SourceSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_source_suricata(self):
        all_source_suricata = SourceSuricata.get_all()
        source_suricata = SourceSuricata.get_by_id(1)
        self.assertEqual(len(all_source_suricata), 2)
        self.assertEqual(source_suricata.method.name, "URL HTTP")
        self.assertEqual(str(source_suricata), "https://sslbl.abuse.ch/blacklist/sslblacklist.rules")
        source_suricata = SourceSuricata.get_by_id(99)
        self.assertEqual(source_suricata, None)
        source_misp = SourceSuricata.objects.create(method=MethodUpload.get_by_name("MISP"),
                                                    scheduled_rules_deployment_enabled=False,
                                                    scheduled_deploy=False,
                                                    data_type=DataTypeUpload.get_by_name("one file not compressed"))
        self.assertEqual((1, 0, 0, 0), source_misp.download_from_misp())
        conf = CoreConfiguration.objects.get(key="MISP_HOST")
        conf.value = ""
        conf.save()
        with self.assertRaisesMessage(Exception, 'Missing MISP Configuration'):
            source_misp.download_from_misp()

        SourceSuricata.get_by_uri('https://sslbl.abuse.ch/blacklist/sslblacklist.rules').delete()
        source = SourceSuricata.objects.create(method=MethodUpload.get_by_name("URL HTTP"),
                                               uri='https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                                               scheduled_rules_deployment_enabled=False,
                                               scheduled_deploy=False,
                                               data_type=DataTypeUpload.get_by_name("one file not compressed"))
        self.assertGreater(source.download_from_http()[0], 2000)
        self.assertGreater(source.download_from_http()[1], 2000)

        SourceSuricata.get_by_uri('https://rules.emergingthreats.net/open/'
                                  'suricata-3.3.1/emerging.rules.tar.gz').delete()
        source = SourceSuricata.objects.create(method=MethodUpload.get_by_name("URL HTTP"),
                                               uri='https://rules.emergingthreats.net/open/'
                                                   'suricata-3.3.1/emerging.rules.tar.gz',
                                               scheduled_rules_deployment_enabled=False,
                                               scheduled_deploy=False,
                                               data_type=DataTypeUpload.get_by_name("multiple files in compressed file")
                                               )
        self.assertGreater(source.download_from_http()[0], 2000)
        self.assertGreater(source.download_from_http()[1], 2000)

        with open(settings.BASE_DIR + '/suricata/tests/data/test.rules', encoding='utf_8') as fp:
            source = SourceSuricata.objects.create(method=MethodUpload.get_by_name("Upload file"),
                                                   uri="test_signature",
                                                   file=fp.name,
                                                   scheduled_rules_deployment_enabled=False,
                                                   scheduled_deploy=False,
                                                   data_type=DataTypeUpload.get_by_name("one file not compressed"))
            self.assertEqual((2, 0, 0, 0), source.download_from_file(fp.name))
        with open(settings.BASE_DIR + '/suricata/tests/data/error.rules', encoding='utf_8') as fp:
            source = SourceSuricata.objects.create(method=MethodUpload.get_by_name("Upload file"),
                                                   uri="test_signature_error",
                                                   file=fp.name,
                                                   scheduled_rules_deployment_enabled=False,
                                                   scheduled_deploy=False,
                                                   data_type=DataTypeUpload.get_by_name("one file not compressed"))
            self.assertEqual((0, 8, 0, 0), source.download_from_file(fp.name))
        with open(settings.BASE_DIR + '/suricata/tests/data/test-script.lua', encoding='utf_8') as fp:
            source = SourceSuricata.objects.create(method=MethodUpload.get_by_name("Upload file"),
                                                   uri="test_script",
                                                   file=fp.name,
                                                   scheduled_rules_deployment_enabled=False,
                                                   scheduled_deploy=False,
                                                   data_type=DataTypeUpload.get_by_name("one file not compressed"))
            self.assertEqual((0, 0, 1, 0), source.download_from_file(fp.name))

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
        with self.assertRaises(IntegrityError):
            AppLayerType.objects.create(name="no")


class ConfigurationTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-conf']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_conf_suricata(self):
        all_conf_suricata = Configuration.get_all()
        conf_suricata = Configuration.get_by_id(1)
        self.assertEqual(len(all_conf_suricata), 2)
        self.assertEqual(conf_suricata.name, "configuration1")
        self.assertEqual(conf_suricata.conf_rules_directory, "/etc/suricata/rules")
        self.assertEqual(conf_suricata.conf_file, "/etc/suricata/suricata.yaml")
        self.assertTrue(conf_suricata.conf_advanced)
        with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
            CONF_FULL_DEFAULT = f.read()
        conftest = Configuration.objects.create(
            name='conftest',
            conf_rules_directory='/etc/suricata/rules',
            conf_iprep_directory='/etc/suricata/iprep',
            conf_lua_directory='/etc/suricata/lua-output',
            conf_file='/etc/suricata/suricata.yaml',
            conf_advanced=False,
            conf_advanced_text=CONF_FULL_DEFAULT,
            conf_HOME_NET="[192.168.0.0/24]",
            conf_EXTERNAL_NET="!$HOME_NET",
            conf_HTTP_SERVERS="$HOME_NET",
            conf_SMTP_SERVERS="$HOME_NET",
            conf_SQL_SERVERS="$HOME_NET",
            conf_DNS_SERVERS="$HOME_NET",
            conf_TELNET_SERVERS="$HOME_NET",
            conf_AIM_SERVERS="$EXTERNAL_NET",
            conf_DNP3_SERVER="$HOME_NET",
            conf_DNP3_CLIENT="$HOME_NET",
            conf_MODBUS_CLIENT="$HOME_NET",
            conf_MODBUS_SERVER="$HOME_NET",
            conf_ENIP_CLIENT="$HOME_NET",
            conf_ENIP_SERVER="$HOME_NET",
            conf_HTTP_PORTS="80",
            conf_SHELLCODE_PORTS="!80",
            conf_ORACLE_PORTS="1521",
            conf_SSH_PORTS="22",
            conf_DNP3_PORTS="20000",
            conf_MODBUS_PORTS="502",
            conf_stats=ValidationType.get_by_id(1),
            conf_afpacket_interface='eth0',
            conf_outputs_fast=ValidationType.get_by_id(1),
            conf_outputs_evelog=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_http=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_tls=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_ssh=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_smtp=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_dnp3=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_taggedpackets=ValidationType.get_by_id(0),
            conf_outputs_evelog_xff=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_query=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_answer=ValidationType.get_by_id(0),
            conf_outputs_evelog_http_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_tls_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_files_forcemagic=ValidationType.get_by_id(1),
            conf_outputs_unified2alert=ValidationType.get_by_id(1),
            conf_lua=ValidationType.get_by_id(1),
            conf_applayer_tls=AppLayerType.get_by_id(0),
            conf_applayer_dcerpc=AppLayerType.get_by_id(0),
            conf_applayer_ftp=AppLayerType.get_by_id(0),
            conf_applayer_ssh=AppLayerType.get_by_id(0),
            conf_applayer_smtp=AppLayerType.get_by_id(0),
            conf_applayer_imap=AppLayerType.get_by_id(1),
            conf_applayer_msn=AppLayerType.get_by_id(1),
            conf_applayer_smb=AppLayerType.get_by_id(0),
            conf_applayer_dns=AppLayerType.get_by_id(0),
            conf_applayer_http=AppLayerType.get_by_id(0)
        )
        self.assertTrue(conftest.test()['status'])
        conftest_advanced = Configuration.objects.create(
            name='conftest_advanced',
            conf_rules_directory='/etc/suricata/rules',
            conf_iprep_directory='/etc/suricata/iprep',
            conf_lua_directory='/etc/suricata/lua-output',
            conf_file='/etc/suricata/suricata.yaml',
            conf_advanced=True,
            conf_advanced_text=CONF_FULL_DEFAULT,
            conf_HOME_NET="[192.168.0.0/24]",
            conf_EXTERNAL_NET="!$HOME_NET",
            conf_HTTP_SERVERS="$HOME_NET",
            conf_SMTP_SERVERS="$HOME_NET",
            conf_SQL_SERVERS="$HOME_NET",
            conf_DNS_SERVERS="$HOME_NET",
            conf_TELNET_SERVERS="$HOME_NET",
            conf_AIM_SERVERS="$EXTERNAL_NET",
            conf_DNP3_SERVER="$HOME_NET",
            conf_DNP3_CLIENT="$HOME_NET",
            conf_MODBUS_CLIENT="$HOME_NET",
            conf_MODBUS_SERVER="$HOME_NET",
            conf_ENIP_CLIENT="$HOME_NET",
            conf_ENIP_SERVER="$HOME_NET",
            conf_HTTP_PORTS="80",
            conf_SHELLCODE_PORTS="!80",
            conf_ORACLE_PORTS="1521",
            conf_SSH_PORTS="22",
            conf_DNP3_PORTS="20000",
            conf_MODBUS_PORTS="502",
            conf_stats=ValidationType.get_by_id(1),
            conf_afpacket_interface='eth0',
            conf_outputs_fast=ValidationType.get_by_id(1),
            conf_outputs_evelog=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_http=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_tls=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_ssh=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_smtp=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_dnp3=ValidationType.get_by_id(0),
            conf_outputs_evelog_alert_taggedpackets=ValidationType.get_by_id(0),
            conf_outputs_evelog_xff=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_query=ValidationType.get_by_id(0),
            conf_outputs_evelog_dns_answer=ValidationType.get_by_id(0),
            conf_outputs_evelog_http_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_tls_extended=ValidationType.get_by_id(0),
            conf_outputs_evelog_files_forcemagic=ValidationType.get_by_id(1),
            conf_outputs_unified2alert=ValidationType.get_by_id(1),
            conf_lua=ValidationType.get_by_id(1),
            conf_applayer_tls=AppLayerType.get_by_id(0),
            conf_applayer_dcerpc=AppLayerType.get_by_id(0),
            conf_applayer_ftp=AppLayerType.get_by_id(0),
            conf_applayer_ssh=AppLayerType.get_by_id(0),
            conf_applayer_smtp=AppLayerType.get_by_id(0),
            conf_applayer_imap=AppLayerType.get_by_id(1),
            conf_applayer_msn=AppLayerType.get_by_id(1),
            conf_applayer_smb=AppLayerType.get_by_id(0),
            conf_applayer_dns=AppLayerType.get_by_id(0),
            conf_applayer_http=AppLayerType.get_by_id(0)
        )
        self.assertTrue(conftest_advanced.test()['status'])
        self.assertEqual(str(conf_suricata), "configuration1")
        conf_suricata = Configuration.get_by_id(99)
        self.assertEqual(conf_suricata, None)
        with self.assertRaises(IntegrityError):
            Configuration.objects.create(name="configuration1")


class RuleSetSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset']

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
        with self.assertRaises(IntegrityError):
            RuleSetSuricata.objects.create(name="ruleset1",
                                           description="",
                                           created_date=self.date_now
                                           )


class ScriptSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-signature', 'test-suricata-script']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_script_suricata(self):
        all_script_suricata = ScriptSuricata.get_all()
        script_suricata = ScriptSuricata.get_by_id(3)
        script_suricatas = ScriptSuricata.find(".php")
        self.assertEqual(len(all_script_suricata), 1)
        self.assertEqual(script_suricata.filename, "test.lua")
        self.assertEqual(script_suricata.rev, 0)
        self.assertEqual(script_suricata.reference, None)
        self.assertTrue(script_suricata.enabled)
        self.assertEqual(script_suricatas[0].filename, "test.lua")
        self.assertEqual(str(script_suricata), "test.lua")
        self.assertEqual(ScriptSuricata.get_by_filename("test.lua").rev, 0)
        script_suricata = ScriptSuricata.get_by_id(99)
        self.assertEqual(script_suricata, None)
        self.assertEqual(ScriptSuricata.get_by_filename('does not exist'), None)
        ScriptSuricata.copy_to_rules_directory_for_test()
        self.assertTrue(os.path.exists(settings.SURICATA_RULES + '/test.lua'))
        with self.assertRaises(IntegrityError):
            ScriptSuricata.objects.create(filename="test.lua",
                                          rev=0,
                                          reference="http://doc.emergingthreats.net/2000026",
                                          rule_full="alert dns any any -> any any (msg:\"SURICATA DNS flow "
                                                    "memcap reached\"; flow:to_server; "
                                                    "app-layer-event:dns.state_memcap_reached; sid:2240008; rev:2;)",
                                          enabled=True,
                                          created_date=self.date_now
                                          )


class SignatureSuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-suricata-signature', 'test-suricata-script']

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
        signature_script = SignatureSuricata.objects.create(sid=2040203,
                                                            rev=0,
                                                            msg="Test script lua",
                                                            reference="http://doc.emergingthreats.net/2000026",
                                                            classtype=ClassType.get_by_id(1),
                                                            rule_full="alert tcp any any −> any any (msg:\"Lua rule\"; "
                                                                      "lua:test.lua; classtype:misc-attack; sid:3011; "
                                                                      "rev:1;)",
                                                            enabled=True,
                                                            created_date=self.date_now
                                                            )
        print(signature_script.test())
        print(subprocess.check_output(['ls', '-l', settings.SURICATA_RULES]))
        print(subprocess.check_output(['cat', settings.SURICATA_RULES + '/test.lua']))
        print(subprocess.check_output([settings.SURICATA_BINARY, '--build-info']))
        self.assertTrue(signature_script.test()['status'])

        with self.assertRaises(IntegrityError):
            SignatureSuricata.objects.create(sid=20402000,
                                             rev=0,
                                             msg="HTTP attack",
                                             reference="http://doc.emergingthreats.net/2000026",
                                             classtype=ClassType.get_by_id(1),
                                             rule_full="alert dns any any -> any any (msg:\"SURICATA DNS flow "
                                                       "memcap reached\"; flow:to_server; "
                                                       "app-layer-event:dns.state_memcap_reached; sid:2240008; rev:2;)",
                                             enabled=True,
                                             created_date=self.date_now
                                             )


class SuricataTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset',
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
        with self.assertRaises(IntegrityError):
            Suricata.objects.create(name="suricata1")

    def test_test(self):
        suricata = Suricata.get_by_id(1)
        response = suricata.server.test()
        self.assertTrue(response)
        response = suricata.server.test_become()
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


class ReputationTest(TestCase):
    fixtures = ['init', 'crontab', 'init-suricata', 'test-core-secrets', 'test-suricata-signature',
                'test-suricata-script', 'test-suricata-ruleset',
                'test-suricata-source', 'test-suricata-conf', 'test-suricata-suricata', 'test-suricata-reputation']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_cat_rep(self):
        all_cat_rep = CategoryReputation.get_all()
        cat_rep = CategoryReputation.get_by_id(1)
        self.assertEqual(len(all_cat_rep), 1)
        self.assertEqual(cat_rep.short_name, "Google")
        self.assertEqual(str(cat_rep), "Google")
        with CategoryReputation.get_tmp_dir() as tmp_dir:
            self.assertEqual(CategoryReputation.store(tmp_dir), tmp_dir + "categories.txt")
        self.assertEqual(str(CategoryReputation.get_by_short_name("Google")), "Google")
        self.assertEqual(CategoryReputation.deploy(Suricata.get_by_id(1)), {'status': True})
        CategoryReputation.import_from_csv(settings.BASE_DIR + '/suricata/tests/data/cat-rep.csv')
        self.assertEqual(str(CategoryReputation.get_by_short_name('Pam')), 'Pam')
        CategoryReputation.get_by_id(2).delete()
        CategoryReputation.get_by_id(3).delete()
        cat_rep = CategoryReputation.get_by_id(99)
        self.assertEqual(cat_rep, None)
        with self.assertRaises(IntegrityError):
            CategoryReputation.objects.create(short_name="Google", description="test")

    def test_ip_rep(self):
        all_ip_rep = IPReputation.get_all()
        ip_rep = IPReputation.get_by_id(1)
        self.assertEqual(len(all_ip_rep), 1)
        self.assertEqual(ip_rep.ip, "8.8.8.8")
        self.assertEqual(str(ip_rep), "8.8.8.8")
        with IPReputation.get_tmp_dir() as tmp_dir:
            self.assertEqual(IPReputation.store(tmp_dir), tmp_dir + "reputation.list")
        self.assertEqual(str(IPReputation.get_by_ip('8.8.8.8')), '8.8.8.8')
        self.assertEqual(IPReputation.deploy(Suricata.get_by_id(1)), {'status': True})
        IPReputation.import_from_csv(settings.BASE_DIR + '/suricata/tests/data/ip-rep.csv')
        self.assertEqual(str(IPReputation.get_by_ip('9.9.9.9')), '9.9.9.9')
        IPReputation.get_by_ip('9.9.9.9').delete()
        IPReputation.get_by_ip('1.2.3.4').delete()
        ip_rep = IPReputation.get_by_id(99)
        self.assertEqual(ip_rep, None)
        with self.assertRaises(IntegrityError):
            IPReputation.objects.create(ip="8.8.8.8", category=CategoryReputation.get_by_id(1), reputation_score=0)
