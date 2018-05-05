import csv
import io
import logging
import os
import re
import ssl
import subprocess
import tarfile
import urllib.request
from string import Template

import select2.fields
from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django_celery_beat.models import PeriodicTask
from pymisp import PyMISP

from core.models import Configuration as CoreConfiguration
from core.models import Probe, ProbeConfiguration
from core.modelsmixins import CommonMixin
from core.notifications import send_notification
from core.ssh import execute, execute_copy
from core.utils import process_cmd, create_deploy_rules_task, create_check_task
from rules.models import RuleSet, Rule, Source
from .exceptions import RuleNotFoundParam
from .utils import create_conf, convert_conf

logger = logging.getLogger('suricata')


class ClassType(CommonMixin, models.Model):
    """
    Set of Classification for a signature.
    The classtype keyword gives information about the classification of rules and alerts.
    """
    name = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.CharField(max_length=1000)
    severity_level = models.IntegerField(default=0)

    def __str__(self):
        return self.name

    @classmethod
    def get_by_name(cls, name):
        try:
            obj = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj


class ValidationType(CommonMixin, models.Model):
    """
    Set of validation value (yes, no).
    """
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name


class AppLayerType(CommonMixin, models.Model):
    """
    Used for the choices for the detection of application protocol. (yes, no, detection-only)
    """
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name


class Configuration(ProbeConfiguration):
    """
    Configuration for Suricata IDS, Allows you to reuse the configuration.
    """
    probeconfiguration = models.OneToOneField(ProbeConfiguration, parent_link=True,
                                              related_name='suricata_configuration',
                                              on_delete=models.CASCADE, editable=False)
    with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
        CONF_FULL_DEFAULT = f.read()
    conf_rules_directory = models.CharField(max_length=400, default="/etc/suricata/rules")
    conf_iprep_directory = models.CharField(max_length=400, default='/etc/suricata/iprep')
    conf_file = models.CharField(max_length=400, default="/etc/suricata/suricata.yaml")
    conf_advanced = models.BooleanField(default=False)
    conf_advanced_text = models.TextField(default=CONF_FULL_DEFAULT)

    conf_HOME_NET = models.CharField(max_length=100, default="[192.168.0.0/24]")
    conf_EXTERNAL_NET = models.CharField(max_length=100, default="!$HOME_NET")
    conf_HTTP_SERVERS = models.CharField(max_length=100, default="$HOME_NET")
    conf_SMTP_SERVERS = models.CharField(max_length=100, default="$HOME_NET")
    conf_SQL_SERVERS = models.CharField(max_length=100, default="$HOME_NET")
    conf_DNS_SERVERS = models.CharField(max_length=100, default="$HOME_NET")
    conf_TELNET_SERVERS = models.CharField(max_length=100, default="$HOME_NET")
    conf_AIM_SERVERS = models.CharField(max_length=100, default="$EXTERNAL_NET")
    conf_DNP3_SERVER = models.CharField(max_length=100, default="$HOME_NET")
    conf_DNP3_CLIENT = models.CharField(max_length=100, default="$HOME_NET")
    conf_MODBUS_CLIENT = models.CharField(max_length=100, default="$HOME_NET")
    conf_MODBUS_SERVER = models.CharField(max_length=100, default="$HOME_NET")
    conf_ENIP_CLIENT = models.CharField(max_length=100, default="$HOME_NET")
    conf_ENIP_SERVER = models.CharField(max_length=100, default="$HOME_NET")
    conf_HTTP_PORTS = models.CharField(max_length=100, default="80")
    conf_SHELLCODE_PORTS = models.CharField(max_length=100, default="!80")
    conf_ORACLE_PORTS = models.CharField(max_length=100, default="1521")
    conf_SSH_PORTS = models.CharField(max_length=100, default="22")
    conf_DNP3_PORTS = models.CharField(max_length=100, default="20000")
    conf_MODBUS_PORTS = models.CharField(max_length=100, default="502")

    conf_stats = models.ForeignKey(ValidationType, related_name="conf_stats", default=1, on_delete=models.CASCADE)
    conf_afpacket_interface = models.CharField(max_length=100, default='eth0')
    conf_outputs_fast = models.ForeignKey(ValidationType, related_name="conf_outputs_fast", default=1,
                                          on_delete=models.CASCADE)
    conf_outputs_evelog = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog", default=0,
                                            on_delete=models.CASCADE)
    conf_outputs_evelog_alert_http = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_http",
                                                       default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_alert_tls = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_tls",
                                                      default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_alert_ssh = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_ssh",
                                                      default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_alert_smtp = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_smtp",
                                                       default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_alert_dnp3 = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_dnp3",
                                                       default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_alert_taggedpackets = models.ForeignKey(ValidationType,
                                                                related_name="conf_outputs_evelog_alert_taggedpackets",
                                                                default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_xff = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_xff", default=1,
                                                on_delete=models.CASCADE)
    conf_outputs_evelog_dns_query = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_dns_query",
                                                      default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_dns_answer = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_dns_answer",
                                                       default=0, on_delete=models.CASCADE)
    conf_outputs_evelog_http_extended = models.ForeignKey(ValidationType,
                                                          related_name="conf_outputs_evelog_http_extended", default=0,
                                                          on_delete=models.CASCADE)
    conf_outputs_evelog_tls_extended = models.ForeignKey(ValidationType,
                                                         related_name="conf_outputs_evelog_tls_extended", default=0,
                                                         on_delete=models.CASCADE)
    conf_outputs_evelog_files_forcemagic = models.ForeignKey(ValidationType,
                                                             related_name="conf_outputs_evelog_files_forcemagic",
                                                             default=1, on_delete=models.CASCADE)
    conf_outputs_unified2alert = models.ForeignKey(ValidationType, related_name="conf_outputs_unified2alert", default=1,
                                                   on_delete=models.CASCADE)
    conf_lua = models.ForeignKey(ValidationType, related_name="conf_lua", default=1, on_delete=models.CASCADE)

    conf_applayer_tls = models.ForeignKey(AppLayerType, related_name="conf_applayer_tls", default=0,
                                          on_delete=models.CASCADE)
    conf_applayer_dcerpc = models.ForeignKey(AppLayerType, related_name="conf_applayer_dcerpc", default=0,
                                             on_delete=models.CASCADE)
    conf_applayer_ftp = models.ForeignKey(AppLayerType, related_name="conf_applayer_ftp", default=0,
                                          on_delete=models.CASCADE)
    conf_applayer_ssh = models.ForeignKey(AppLayerType, related_name="conf_applayer_ssh", default=0,
                                          on_delete=models.CASCADE)
    conf_applayer_smtp = models.ForeignKey(AppLayerType, related_name="conf_applayer_smtp", default=0,
                                           on_delete=models.CASCADE)
    conf_applayer_imap = models.ForeignKey(AppLayerType, related_name="conf_applayer_imap", default=2,
                                           on_delete=models.CASCADE)
    conf_applayer_msn = models.ForeignKey(AppLayerType, related_name="conf_applayer_msn", default=2,
                                          on_delete=models.CASCADE)
    conf_applayer_smb = models.ForeignKey(AppLayerType, related_name="conf_applayer_smb", default=0,
                                          on_delete=models.CASCADE)
    conf_applayer_dns = models.ForeignKey(AppLayerType, related_name="conf_applayer_dns", default=0,
                                          on_delete=models.CASCADE)
    conf_applayer_http = models.ForeignKey(AppLayerType, related_name="conf_applayer_http", default=0,
                                           on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    def save(self, **kwargs):
        if not self.conf_advanced:
            create_conf(self)
        else:
            convert_conf(self)
        super().save(**kwargs)

    def test(self):
        with self.get_tmp_dir(self.pk) as tmp_dir:
            rule_file = settings.BASE_DIR + "/suricata/tests/data/test.rules"
            conf_file = tmp_dir + self.name + ".yaml"
            config = self.conf_advanced_text
            config += """

logging:
  default-log-level: error
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: no
      filename: /var/log/suricata/suricata.log
      level: info
"""
            with open(conf_file, 'w', encoding='utf_8') as f:
                f.write(str(config))
            cmd = [settings.SURICATA_BINARY, '-T',
                   '-l', tmp_dir,
                   '-S', rule_file,
                   '-c', conf_file,
                   '--set', 'classification-file=' + settings.BASE_DIR + '/suricata/tests/data/classification.config',
                   '--set', 'reference-config-file=' + settings.BASE_DIR + '/suricata/tests/data/reference.config',
                   ]
            return process_cmd(cmd, tmp_dir)


class SignatureSuricata(Rule):
    """
    Stores a signature Suricata compatible. (pattern matching),
    see http://suricata.readthedocs.io/en/latest/rules/index.html
    """
    sid = models.IntegerField(unique=True, db_index=True,
                              help_text="<a target='_blank' " +
                                        "href='http://doc.emergingthreats.net/bin/view/Main/SidAllocation'>help</a>")
    classtype = models.ForeignKey(ClassType, on_delete=models.CASCADE)
    msg = models.CharField(max_length=1000)
    file_test_success = models.FileField(name='file_test_success', upload_to='file_test_success', blank=True)

    def __str__(self):
        return str(self.sid) + " : " + str(self.msg)

    @classmethod
    def get_by_sid(cls, sid):
        try:
            obj = cls.objects.get(sid=sid)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the signatures"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_attributs(cls, line, rulesets=None):  # TODO -> too complex
        rule_created = False
        rule_updated = False
        getsid = re.compile("sid *: *(\d+)")
        getrev = re.compile("rev *: *(\d+)")
        getmsg = re.compile("msg *: *\"(.*?)\"")
        getref = re.compile("reference *: *url,(.*?);")
        getct = re.compile("classtype *:(.*?);")
        if "->" in line and "sid" in line and ")" in line:
            try:
                match = getsid.search(line)
                if not match:
                    raise RuleNotFoundParam("SID not found in : " + line)
                # test if exist already -> update
                if SignatureSuricata.get_by_sid(match.groups()[0]):
                    signature = cls.get_by_sid(match.groups()[0])
                    signature.updated_date = timezone.now()
                    rule_updated = True
                else:
                    signature = SignatureSuricata()
                    signature.created_date = timezone.now()
                    signature.sid = match.groups()[0]
                    rule_created = True
                if rule_created:
                    signature.enabled = True
                if line.startswith('#'):
                    line = line.lstrip("# ")
                    if rule_created:
                        signature.enabled = False
                signature.rule_full = line
                match = getrev.search(line)
                if match:
                    signature.rev = int(match.groups()[0])
                    # print("rev : " + str(signature.rev))
                else:
                    signature.rev = 0
                match = getmsg.search(line)
                if not match:
                    signature.msg = ""
                else:
                    signature.msg = match.groups()[0]
                    # print("msg : " + signature.msg)
                match = getref.search(line)
                if not match:
                    signature.reference = ""
                else:
                    signature.reference = match.groups()[0]
                    # print("ref : " + signature.reference)
                match = getct.search(line)
                if not match:
                    # print("ClassType not found in : " + line)
                    signature.classtype = ClassType.get_by_id(1)
                else:
                    # print("classType #" + match.groups()[0].strip() + "#")
                    signature.classtype = ClassType.get_by_name(match.groups()[0].strip())
                    if not signature.classtype:
                        raise RuleNotFoundParam("ClassType not found in : " + line)
                signature.save()
                if rulesets:
                    for ruleset in rulesets:
                        ruleset.signatures.add(signature)
                        ruleset.save()
                # print("rule saved : " + str(signature.sid))
                return rule_created, rule_updated
            except RuleNotFoundParam:
                return rule_created, rule_updated
        return rule_created, rule_updated

    def test(self):
        with self.get_tmp_dir("test_sig") as tmp_dir:
            ScriptSuricata.copy_to_rules_directory_for_test()
            rule_file = tmp_dir + str(self.sid) + ".rules"
            with open(rule_file, 'w', encoding='utf_8') as f:
                f.write(self.rule_full)
            cmd = [settings.SURICATA_BINARY, '-T',
                   '-l', tmp_dir,
                   '-S', rule_file,
                   '-c', settings.SURICATA_CONFIG
                   ]
            return process_cmd(cmd, tmp_dir)

    def test_pcap(self):
        with self.get_tmp_dir("test_pcap") as tmp_dir:
            ScriptSuricata.copy_to_rules_directory_for_test()
            rule_file = tmp_dir + "rule.rules"
            conf_file = tmp_dir + "suricata.yaml"
            with open(rule_file, 'w', encoding='utf_8') as f:
                f.write(self.rule_full)
            with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
                conf_full_default = f.read()
            config = conf_full_default
            config += """

logging:
  default-log-level: error
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: no
      filename: /var/log/suricata/suricata.log
      level: info
"""
            with open(conf_file, 'w', encoding='utf_8') as f:
                f.write(config)
            # test pcap success
            cmd = [settings.SURICATA_BINARY,
                   '-l', tmp_dir,
                   '-S', rule_file,
                   '-c', conf_file,
                   '-r', settings.BASE_DIR + "/" + self.file_test_success.name,
                   '--set', 'outputs.0.fast.enabled=yes',
                   '--set', 'classification-file=' + settings.BASE_DIR + '/suricata/tests/data/classification.config',
                   '--set', 'reference-config-file=' + settings.BASE_DIR + '/suricata/tests/data/reference.config',
                   ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outdata, errdata = process.communicate()
            logger.debug("outdata : " + str(outdata), "errdata : " + str(errdata))
            # test if alert is generated :
            test = False
            if os.path.isfile(tmp_dir + "fast.log"):
                with open(tmp_dir + "fast.log", "r", encoding='utf_8') as f:
                    if self.msg in f.read():
                        test = True
        # if success ok
        if process.returncode == 0 and test:
            return {'status': True}
        # if not -> return error
        errdata += b"Alert not generated"
        return {'status': False, 'errors': errdata}

    def test_all(self):
        test = True
        errors = list()
        response = self.test()
        if not response['status']:
            test = False
            errors.append(str(self) + " : " + str(response['errors']))
        if self.file_test_success:
            response_pcap = self.test_pcap()
            if not response_pcap['status']:
                test = False
                errors.append(str(self) + " : " + str(response_pcap['errors']))
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}


class ScriptSuricata(Rule):
    """
    Stores a script Suricata compatible.
    see : http://suricata.readthedocs.io/en/latest/rules/rule-lua-scripting.html
    """
    filename = models.CharField(max_length=1000, unique=True, db_index=True)

    def __str__(self):
        return str(self.filename)

    @classmethod
    def get_by_filename(cls, filename):
        try:
            obj = cls.objects.get(filename=filename)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the scripts"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_attributs(cls, file, rulesets=None):
        """ A script by file """
        rule_created = False
        rule_updated = False
        if not cls.get_by_filename(os.path.basename(file.name)):
            rule_created = True
            script = ScriptSuricata()
            script.filename = os.path.basename(file.name)
            script.created_date = timezone.now()
            script.rev = 0
            script.rule_full = file.read()
        else:
            rule_updated = True
            script = cls.get_by_filename(file.name)
            script.rule_full = file.read()
            script.rev = script.rev + 1
            script.updated_date = timezone.now()
        script.save()
        if rulesets:
            for ruleset in rulesets:
                ruleset.scripts.add(script)
                ruleset.save()
        return rule_created, rule_updated

    @classmethod
    def copy_to_rules_directory_for_test(cls):
        for script in cls.get_all():
            with open(settings.SURICATA_RULES + '/' + script.filename, 'w') as f:
                f.write(script.rule_full)


class RuleSetSuricata(RuleSet):
    """
    Set of signatures and scripts Suricata compatible
    """
    signatures = select2.fields.ManyToManyField(SignatureSuricata,
                                                blank=True,
                                                ajax=True,
                                                search_field=lambda q: Q(sid__icontains=q) | Q(msg__icontains=q),
                                                sort_field='sid',
                                                js_options={'quiet_millis': 200}
                                                )
    scripts = select2.fields.ManyToManyField(ScriptSuricata,
                                             blank=True,
                                             ajax=True,
                                             search_field=lambda q: Q(sid__icontains=q) | Q(filename__icontains=q),
                                             sort_field='sid',
                                             js_options={'quiet_millis': 200}
                                             )

    def __str__(self):
        return str(self.name)

    def test_rules(self):
        test = True
        errors = list()
        for signature in self.signatures.all():
            response = signature.test()
            if not response['status']:
                test = False
                errors.append(str(signature) + " : " + str(response['errors']))
        if not test:
            return {'status': False, 'errors': str(errors)}
        return {'status': True}


class SourceSuricata(Source):
    """
    Set of Suricata Source. For scheduled upload of signatures.
    """
    rulesets = models.ManyToManyField(RuleSetSuricata, blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def delete(self, **kwargs):
        try:
            periodic_task = PeriodicTask.objects.get(name=self.uri + '_download_from_http_task')
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:
            pass
        try:
            for ruleset in self.rulesets.all():
                for probe in ruleset.suricata_set.all():
                    periodic_task = PeriodicTask.objects.get(
                        name__contains=probe.name + "_" + self.uri + "_deploy_rules_")
                    periodic_task.delete()
                    logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:
            pass
        return super().delete(**kwargs)

    @staticmethod
    def find_rules(file, file_name, rulesets):
        count_signature_created = 0
        count_signature_updated = 0
        count_script_created = 0
        count_script_updated = 0
        if os.path.splitext(file_name)[1] == '.rules':
            for line in file.readlines():
                rule_created, rule_updated = SignatureSuricata.extract_attributs(line, rulesets)
                if rule_created:
                    count_signature_created += 1
                if rule_updated:
                    count_signature_updated += 1
        elif os.path.splitext(file_name)[1] == '.lua':

            rule_created, rule_updated = ScriptSuricata.extract_attributs(file, rulesets)
            if rule_created:
                count_script_created += 1
            if rule_updated:
                count_script_updated += 1
        return count_signature_created, count_signature_updated, count_script_created, count_script_updated

    def extract_files(self, file_downloaded, rulesets=None):
        count = (0, 0, 0, 0)
        with self.get_tmp_dir(self.pk) as tmp_dir:
            with open(tmp_dir + "temp.tar.gz", 'wb') as f:
                f.write(file_downloaded)
            with tarfile.open(tmp_dir + "temp.tar.gz", encoding='utf_8') as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        file = io.TextIOWrapper(tar.extractfile(member))
                        count = tuple(map(sum, zip(count, self.find_rules(file, member.name, rulesets))))
                return count

    def download_from_misp(self, rulesets=None):
        if CoreConfiguration.get_value("MISP_HOST") and CoreConfiguration.get_value("MISP_API_KEY"):
            misp = PyMISP(CoreConfiguration.get_value("MISP_HOST"), CoreConfiguration.get_value("MISP_API_KEY"), True)
            with self.get_tmp_dir(self.pk) as tmp_dir:
                with open(tmp_dir + 'misp.rules', 'w', encoding='utf_8') as f:
                    f.write(misp.download_all_suricata().text)
                with open(tmp_dir + 'misp.rules', 'r', encoding='utf_8') as f:
                    return self.find_rules(f, 'misp.rules', rulesets)
        else:
            logger.error('Missing MISP Configuration')
            raise Exception('Missing MISP Configuration')

    def download_from_file(self, file_name, rulesets=None):
        # Upload file - multiple files in compressed file
        if self.data_type.name == "multiple files in compressed file":
            logger.debug('multiple files in compressed file')
            file_downloaded = self.file.read()
            return self.extract_files(file_downloaded, rulesets)
        # Upload file - one file not compressed
        elif self.data_type.name == "one file not compressed":
            logger.debug('one file not compressed')
            with self.get_tmp_dir(self.pk) as tmp_dir:
                with open(tmp_dir + "temp.rules", 'wb') as f:
                    f.write(self.file.read())
                with open(tmp_dir + "temp.rules", 'r', encoding='utf_8') as f:
                    return self.find_rules(f, file_name, rulesets)
        else:
            logger.error('Data type upload unknown: ' + self.data_type.name)
            raise Exception('Data type upload unknown : ' + self.data_type.name)

    def download_from_http(self, rulesets=None):
        context = ssl._create_unverified_context()
        response = urllib.request.urlopen(self.uri, context=context)
        file_dowloaded = response.read()
        # URL HTTP - multiple files in compressed file
        if self.data_type.name == "multiple files in compressed file":
            logger.debug("multiple files in compressed file")
            if response.info()['Content-type'] == 'application/x-gzip' or \
               response.info()['Content-type'] == 'application/x-tar':
                return self.extract_files(file_dowloaded, rulesets)
            else:
                logger.error('Compression format unknown : ' + str(response.info()['Content-type']))
                raise Exception('Compression format unknown : ' + str(response.info()['Content-type']))
        # URL HTTP - one file not compressed
        elif self.data_type.name == "one file not compressed":
            logger.debug("one file not compressed")
            if response.info()['Content-type'] == 'text/plain':
                with self.get_tmp_dir(self.pk) as tmp_dir:
                    with open(tmp_dir + "temp.rules", 'wb') as f:
                        f.write(file_dowloaded)
                    with open(tmp_dir + "temp.rules", 'r', encoding='utf_8') as f:
                        return self.find_rules(f, 'temp.rules', rulesets)
            else:
                logger.error('Compression format unknown : ' + str(response.info()['Content-type']))
                raise Exception('Compression format unknown : ' + str(response.info()['Content-type']))
        else:
            logger.error('Data type upload unknown.')
            raise Exception('Data type upload unknown.')


class Suricata(Probe):
    """
    Stores an instance of Suricata IDS software.
    """
    rulesets = models.ManyToManyField(RuleSetSuricata, blank=True)
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description

    def save(self, **kwargs):
        super().save(**kwargs)
        create_deploy_rules_task(self)
        create_check_task(self)

    def delete(self, **kwargs):
        try:
            periodic_task = PeriodicTask.objects.get(
                name=self.name + "_deploy_rules_" + str(self.scheduled_rules_deployment_crontab))
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        try:
            periodic_task = PeriodicTask.objects.get(name=self.name + "_check_task")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        return super().delete(**kwargs)

    def install(self, version=settings.SURICATA_VERSION):
        if self.server.os.name == 'debian':
            install_script = """
            if ! type suricata ; then
                echo 'deb http://http.debian.net/debian stretch-backports main' | \
                sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
                apt update
                apt -y -t stretch-backports install suricata
                mkdir /etc/suricata/iprep
                touch /etc/suricata/iprep/categories.txt && touch /etc/suricata/iprep/reputation.list
                chown -R $(whoami) /etc/suricata
                exit 0
            else
                echo "Already installed"
                exit 0
            fi
            """
        elif self.server.os.name == 'ubuntu':
            install_script = """
            if ! type suricata ; then
                add-apt-repository -y ppa:oisf/suricata-stable
                apt update
                apt -y install suricata
                mkdir /etc/suricata/iprep
                touch /etc/suricata/iprep/reputation.list && touch /etc/suricata/iprep/categories.txt
                chown -R $(whoami) /etc/suricata
                exit 0
            else
                echo "Already installed"
                exit 0
            fi
            """
        else:
            raise NotImplementedError
        t = Template(install_script)
        command = "sh -c '" + t.substitute(version=version) + "'"
        tasks = {"install": command}
        try:
            response = execute(self.server, tasks, become=True)
            self.installed = True
            self.save()
        except Exception as e:
            logger.exception('install failed')
            return {'status': False, 'errors': str(e)}
        logger.debug("output : " + str(response))
        return {'status': True}

    def update(self, version=settings.SURICATA_VERSION):
        return self.install(version=version)

    def reload(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = "kill -USR2 $( pidof suricata )"
        else:
            raise NotImplementedError
        tasks = {"reload": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.exception('reload failed')
            return {'status': False, 'errors': str(e)}
        logger.debug("output : " + str(response))
        return {'status': True}

    def test_rules(self):
        # Set blacklists file
        value = ""
        for md5 in Md5.get_all():
            value += md5.value + '\n'
        if not os.path.exists(settings.SURICATA_RULES):
            os.mkdir(settings.SURICATA_RULES)
        with open(settings.SURICATA_RULES + '/md5-blacklist', 'w', encoding='utf_8') as f:
            f.write(value)
        test = True
        errors = list()
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                response = signature.test()
                if not response['status']:
                    test = False
                    errors.append(str(response['errors']))
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}

    def test_pcaps(self):
        test = True
        errors = list()
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                if signature.file_test_success:
                    response_pcap_test = signature.test_pcap()
                    if not response_pcap_test['status']:
                        test = False
                        errors.append(str(signature) + " : " + str(response_pcap_test['errors']))
                else:
                    return {'status': True}
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}

    def deploy_rules(self):
        # Tests
        try:
            response_rules = self.test_rules()
            response_pcaps = self.test_pcaps()
            if self.secure_deployment:
                if not response_rules['status']:
                    if self.secure_deployment:
                        logger.error("Error during the rules test for probe " + str(self.name) + ' : ' +
                                     str(response_rules['errors']))
                        return {"status": False,
                                "message": "Error during the rules test for probe " + str(self.name) + ' : ' +
                                str(response_rules['errors'])}
                    else:
                        logger.error("Error during the rules test for probe " + str(self.name) + ' : ' +
                                     str(response_rules['errors']))
                        send_notification('Error',
                                          'Error during the rules test for probe ' + str(self.name) + ' : ' +
                                          str(response_rules['errors']))
                elif not response_pcaps['status']:
                    if self.secure_deployment:
                        logger.error("Error during the rules test for probe " + str(self.name) + ' : ' +
                                     str(response_pcaps['errors']))
                        return {"status": False,
                                "message": "Error during the pcap test for probe " + str(self.name) + ' : ' +
                                str(response_pcaps['errors'])}
                    else:
                        logger.error("Error during the rules test for probe " + str(self.name) + ' : ' +
                                     str(response_pcaps['errors']))
                        send_notification('Error',
                                          'Error during the pcap test for probe ' + str(self.name) + ' : ' +
                                          str(response_pcaps['errors']))
        except Exception as e:
            logger.exception("Error for probe " + str(self.name) + " during the tests")
            return {"status": False, "message": "Error for probe " + str(self.name) + " during the tests",
                    "exception": str(e)}
        deploy = True
        response = dict()
        errors = list()

        # Signatures
        value = ""
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                if signature.enabled:
                    value += signature.rule_full + '\n'
        with self.get_tmp_dir(self.pk) as tmp_dir:
            with open(tmp_dir + "temp.rules", 'w', encoding='utf_8') as f:
                f.write(value)
            try:
                response = execute_copy(self.server, src=tmp_dir + 'temp.rules',
                                        dest=self.configuration.conf_rules_directory.rstrip('/') + '/deployed.rules',
                                        become=True)
            except Exception as e:
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))

            # Blacklists MD5
            value = ""
            for md5 in Md5.get_all():
                value += md5.value + '\n'
            with open(tmp_dir + "md5-blacklist", 'w', encoding='utf_8') as f:
                f.write(value)
            try:
                response = execute_copy(self.server, src=tmp_dir + 'md5-blacklist',
                                        dest=self.configuration.conf_rules_directory.rstrip('/') + '/md5-blacklist',
                                        become=True)
            except Exception as e:
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))

            # Scripts
            for ruleset in self.rulesets.all():
                for script in ruleset.scripts.all():
                    if script.enabled:
                        with open(tmp_dir + script.filename, 'w', encoding='utf_8') as f:
                            f.write(script.rule_full)
                        try:
                            response = execute_copy(self.server, src=tmp_dir + script.filename,
                                                    dest=self.configuration.conf_rules_directory.rstrip(
                                                        '/') + '/' + script.filename, become=True)
                        except Exception as e:
                            logger.exception('excecute_copy failed')
                            deploy = False
                            errors.append(str(e))
                        logger.debug("output : " + str(response))
        if deploy:
            self.rules_updated_date = timezone.now()
            self.save()
            return {"status": deploy}
        else:
            return {'status': deploy, 'errors': errors}

    def deploy_conf(self):
        with self.get_tmp_dir(self.pk) as tmp_dir:
            value = self.configuration.conf_advanced_text
            with open(tmp_dir + "temp.conf", 'w', encoding='utf_8') as f:
                f.write(value)
            deploy = True
            errors = list()
            response = dict()
            try:
                response = execute_copy(self.server, src=os.path.abspath(tmp_dir + 'temp.conf'),
                                        dest=self.configuration.conf_file, become=True)
            except Exception as e:
                logger.exception('deploy conf failed')
                deploy = False
                errors.append(str(e))
            logger.debug("output : " + str(response))
        if deploy:
            return {'status': deploy}
        else:
            return {'status': deploy, 'errors': errors}


class Md5(models.Model):
    value = models.CharField(max_length=600, unique=True, null=False, blank=False)
    signature = models.ForeignKey(SignatureSuricata, editable=False, on_delete=models.CASCADE)

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_value(cls, value):
        try:
            obj = cls.objects.get(value=value)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj


def increment_sid():
    DEFAULT_LAST_ID = 41000000
    last_sid = BlackList.objects.all().order_by('id').last()
    if not last_sid:
        return DEFAULT_LAST_ID
    else:
        return last_sid.sid + 1


class BlackList(CommonMixin, models.Model):
    """
    Stores an instance of a pattern in blacklist.
    """
    TYPE_CHOICES = (
        ('IP', 'IP'),
        ('MD5', 'MD5'),
        ('HOST', 'HOST'),
    )
    type = models.CharField(max_length=255, choices=TYPE_CHOICES)
    value = models.CharField(max_length=600, unique=True, null=False, blank=False)
    comment = models.CharField(max_length=600, null=True, blank=True)
    sid = models.IntegerField(unique=True, editable=False, null=False, default=increment_sid)
    rulesets = models.ManyToManyField(RuleSetSuricata, blank=True)

    def __str__(self):
        return str(self.type) + "  " + str(self.value)

    def save(self, **kwargs):
        super().save(**kwargs)
        self.create_blacklist()

    def delete(self, **kwargs):
        if self.type == "MD5":
            if Md5.get_by_value(self.value):
                md5_suricata = Md5.get_by_value(self.value)
                md5_suricata.delete()
        else:
            if SignatureSuricata.get_by_sid(self.sid):
                signature = SignatureSuricata.get_by_sid(self.sid)
                signature.delete()
        return super().delete(**kwargs)

    @classmethod
    def get_by_value(cls, value):
        try:
            obj = cls.objects.get(value=value)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    def create_signature(self, t):
        if not self.comment:
            self.comment = str(self.type) + " " + str(self.value) + " in BlackList"
        rule_created = t.safe_substitute(value=self.value,
                                         type=self.type,
                                         comment=self.comment,
                                         sid=self.sid
                                         )
        if SignatureSuricata.get_by_sid(self.sid):
            signature = SignatureSuricata.get_by_sid(self.sid)
            signature.delete()
        if self.type == "MD5":
            signature = SignatureSuricata(sid=self.sid,
                                          classtype=ClassType.get_by_name("misc-attack"),
                                          msg="MD5 in blacklist",
                                          rev=1,
                                          rule_full=rule_created,
                                          enabled=True,
                                          created_date=timezone.now(),
                                          )
        else:
            signature = SignatureSuricata(sid=self.sid,
                                          classtype=ClassType.get_by_name("misc-attack"),
                                          msg=self.comment,
                                          rev=1,
                                          reference=str(self.type) + "," + str(self.value),
                                          rule_full=rule_created,
                                          enabled=True,
                                          created_date=timezone.now(),
                                          )
        return signature

    def create_blacklist(self):
        rule_ip_template = "alert ip $HOME_NET any -> ${value} any (msg:\"${comment}\"; " \
                           "classtype:misc-attack; target:src_ip; sid:${sid}; rev:1;)\n"
        rule_md5_template = "alert ip $HOME_NET any -> any any (msg:\"MD5 in blacklist\"; " \
                            "filemd5:md5-blacklist; classtype:misc-attack; sid:${sid}; rev:1;)\n"
        rule_host_template = "alert http $HOME_NET any -> any any (msg:\"${comment}\"; " \
                             "content:\"${value}\"; http_host; classtype:misc-attack; target:src_ip; " \
                             "sid:${sid}; rev:1;)\n"
        if self.type == "IP":
            signature = self.create_signature(Template(rule_ip_template))
            signature.save()
        elif self.type == "HOST":
            signature = self.create_signature(Template(rule_host_template))
            signature.save()
        elif self.type == "MD5":
            # savoir si signature blacklist existe deja:
            signature = SignatureSuricata.objects.filter(rule_full__icontains="filemd5:md5-blacklist").first()
            if not signature:
                signature = self.create_signature(Template(rule_md5_template))
                signature.save()
            md5_suricata = Md5(value=self.value, signature=signature)
            md5_suricata.save()
        else:  # pragma: no cover
            raise Exception("Blacklist type unknown")
        for ruleset in self.rulesets.all():
            ruleset.signatures.add(signature)
            ruleset.save()


class CategoryReputation(CommonMixin, models.Model):
    """
    Store an instance of a reputation category.
    """
    short_name = models.CharField(max_length=100, unique=True, null=False, blank=False)
    description = models.CharField(max_length=600, null=True, blank=True)

    def __str__(self):
        return str(self.short_name)

    @classmethod
    def get_by_short_name(cls, short_name):
        try:
            obj = cls.objects.get(short_name=short_name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def store(cls, tmp_dir):
        tmp_file = tmp_dir + "categories.txt"
        with open(tmp_file, 'w', encoding='utf_8') as f:
            for category_reputation in cls.get_all():
                f.write(str(category_reputation.id) + "," + category_reputation.short_name +
                        "," + category_reputation.description)
        return tmp_file

    @classmethod
    def deploy(cls, suricata_instance):
        deploy = True
        errors = ""
        response = dict()
        try:
            with cls.get_tmp_dir() as tmp_dir:
                category_file = cls.store(tmp_dir)
                response = execute_copy(suricata_instance.server, src=category_file,
                                        dest=suricata_instance.configuration.conf_iprep_directory.rstrip('/')
                                        + '/' + os.path.basename(category_file),
                                        become=True)
        except Exception as e:
            logger.exception('excecute_copy failed')
            deploy = False
            errors = str(e)
        if deploy:
            return {'status': deploy}
        else:
            return {'status': deploy, 'errors': errors + ' - ' + str(response)}

    @classmethod
    def import_from_csv(cls, csv_file):
        with open(csv_file, newline='') as file:
            reader = csv.DictReader(file, fieldnames=['id', 'short name', 'description'], delimiter=',')
            for row in reader:
                cat_name = cls.get_by_short_name(row['short name'])
                cat_id = cls.get_by_id(row['id'])
                if cat_name:
                    if cat_name.id == row['id']:
                        cls.objects.filter(id=cat_name.id).update(description=row['description'])
                    else:
                        raise Exception("Category already exist under another id")
                elif cat_id and cat_id.short_name != row['short name']:
                    raise Exception("Category id already exist under another short name")
                else:
                    cls.objects.create(id=row['id'], short_name=row['short name'], description=row['description'])


class IPReputation(CommonMixin, models.Model):
    """
    Store an instance of a reputation IP.
    """
    ip = models.GenericIPAddressField(unique=True, null=False, blank=False)
    category = models.ForeignKey(CategoryReputation, on_delete=models.CASCADE)
    reputation_score = models.IntegerField(null=False, default=0, verbose_name='reputation score : a number between '
                                                                               '1 and 127 (0 means no data)')

    def __str__(self):
        return str(self.ip)

    @classmethod
    def get_by_ip(cls, ip):
        try:
            obj = cls.objects.get(ip=ip)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def store(cls, tmp_dir):
        tmp_file = tmp_dir + "reputation.list"
        with open(tmp_file, 'w', encoding='utf_8') as f:
            for ip_reputation in cls.get_all():
                f.write(ip_reputation.ip + "," + str(ip_reputation.category.id) + ","
                        + str(ip_reputation.reputation_score))
        return tmp_file

    @classmethod
    def deploy(cls, suricata_instance):
        deploy = True
        errors = ""
        response = dict()
        try:
            with cls.get_tmp_dir() as tmp_dir:
                ip_file = cls.store(tmp_dir)
                response = execute_copy(suricata_instance.server, src=ip_file,
                                        dest=suricata_instance.configuration.conf_iprep_directory.rstrip('/')
                                        + '/' + os.path.basename(ip_file),
                                        become=True)
        except Exception as e:
            logger.exception('excecute_copy failed')
            deploy = False
            errors = str(e)
        if deploy:
            return {'status': deploy}
        else:
            return {'status': deploy, 'errors': errors + ' - ' + str(response)}

    @classmethod
    def import_from_csv(cls, csv_file):
        with open(csv_file, newline='') as file:
            reader = csv.DictReader(file, fieldnames=['ip', 'category', 'reputation score'], delimiter=',')
            for row in reader:
                same_ip = cls.get_by_ip(row['ip'])
                if same_ip:
                    cls.objects.filter(id=same_ip.id).update(
                        category=CategoryReputation.get_by_id(row['category']),
                        reputation_score=row['reputation score'])
                else:
                    cls.objects.create(ip=row['ip'],
                                       category=CategoryReputation.get_by_id(row['category']),
                                       reputation_score=row['reputation score'])
