from django.db import models
# from home.ansible_tasks import execute
from home.ssh import execute, execute_copy
from home.models import Probe, ProbeConfiguration
from rules.models import RuleSet, Rule, ClassType, Source
import logging
import re
from suricata.exceptions import RuleNotFoundParam
from django.utils import timezone
import urllib.request
import ssl
import os
import glob
import tarfile
import subprocess
from django.conf import settings
from home.utils import update_progress
import select2.fields
from django.db.models import Q


logger = logging.getLogger(__name__)


class ValidationType(models.Model):
    """
    Set of validation value (yes, no).
    """
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class AppLayerType(models.Model):
    """
    Used for the choices for the detection of application protocol. (yes, no, detection-only)
    """
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class ConfSuricata(ProbeConfiguration):
    """
    Configuration for Suricata IDS, Allows you to reuse the configuration.
    """
    with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml") as f:
        CONF_FULL_DEFAULT = f.read()
    f.close()
    conf_rules_directory = models.CharField(max_length=400, default="/etc/suricata/rules")
    conf_script_directory = models.CharField(max_length=400, default='/etc/suricata/lua')
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

    conf_stats = models.ForeignKey(ValidationType, related_name="conf_stats", default=1)
    conf_afpacket_interface = models.CharField(max_length=100, default='eth0')
    conf_outputs_fast = models.ForeignKey(ValidationType, related_name="conf_outputs_fast", default=1)
    conf_outputs_evelog = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog", default=0,)
    conf_outputs_evelog_alert_http = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_http", default=0)
    conf_outputs_evelog_alert_tls = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_tls", default=0)
    conf_outputs_evelog_alert_ssh = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_ssh", default=0)
    conf_outputs_evelog_alert_smtp = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_smtp", default=0)
    conf_outputs_evelog_alert_dnp3 = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_dnp3", default=0)
    conf_outputs_evelog_alert_taggedpackets = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_alert_taggedpackets", default=0)
    conf_outputs_evelog_xff = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_xff", default=1)
    conf_outputs_evelog_dns_query = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_dns_query", default=0)
    conf_outputs_evelog_dns_answer = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_dns_answer", default=0)
    conf_outputs_evelog_http_extended = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_http_extended", default=0)
    conf_outputs_evelog_tls_extended = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_tls_extended", default=0)
    conf_outputs_evelog_files_forcemagic = models.ForeignKey(ValidationType, related_name="conf_outputs_evelog_files_forcemagic", default=1)
    conf_outputs_unified2alert = models.ForeignKey(ValidationType, related_name="conf_outputs_unified2alert", default=1)
    conf_lua = models.ForeignKey(ValidationType, related_name="conf_lua", default=1)

    conf_applayer_tls = models.ForeignKey(AppLayerType, related_name="conf_applayer_tls", default=0)
    conf_applayer_dcerpc = models.ForeignKey(AppLayerType, related_name="conf_applayer_dcerpc", default=0)
    conf_applayer_ftp = models.ForeignKey(AppLayerType, related_name="conf_applayer_ftp", default=0)
    conf_applayer_ssh = models.ForeignKey(AppLayerType, related_name="conf_applayer_ssh", default=0)
    conf_applayer_smtp = models.ForeignKey(AppLayerType, related_name="conf_applayer_smtp", default=0)
    conf_applayer_imap = models.ForeignKey(AppLayerType, related_name="conf_applayer_imap", default=2)
    conf_applayer_msn = models.ForeignKey(AppLayerType, related_name="conf_applayer_msn", default=2)
    conf_applayer_smb = models.ForeignKey(AppLayerType, related_name="conf_applayer_smb", default=0)
    conf_applayer_dns = models.ForeignKey(AppLayerType, related_name="conf_applayer_dns", default=0)
    conf_applayer_http = models.ForeignKey(AppLayerType, related_name="conf_applayer_http", default=0)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def test(self):
        tmpdir = settings.BASE_DIR + "/tmp/test_conf/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        rule_file = settings.BASE_DIR + "/suricata/tests/data/test.rules"
        conf_file = tmpdir + self.name + ".yaml"
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
        with open(conf_file, 'w') as f:
            f.write(config)
        cmd = [settings.SURICATA_BINARY, '-T',
               '-l', tmpdir,
               '-S', rule_file,
               '-c', conf_file,
               '--set', 'classification-file=' + settings.BASE_DIR + '/suricata/tests/data/classification.config',
               '--set', 'reference-config-file=' + settings.BASE_DIR + '/suricata/tests/data/reference.config',
               ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = process.communicate()
        f.close()
        os.remove(conf_file)
        # if success ok
        if process.returncode == 0:
            return {'status': True}
        # if not -> return error
        return {'status': False, 'errors': errdata}


class SignatureSuricata(Rule):
    """
    Stores a signature Suricata compatible. (pattern matching), see http://suricata.readthedocs.io/en/latest/rules/index.html
    """
    sid = models.IntegerField(unique=True, db_index=True, help_text="<a target='_blank' href='http://doc.emergingthreats.net/bin/view/Main/SidAllocation'>help</a>")
    classtype = models.ForeignKey(ClassType)
    msg = models.CharField(max_length=1000)

    def __str__(self):
        return str(self.sid) + " : " + str(self.msg)

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def get_by_sid(cls, sid):
        try:
            object = cls.objects.get(sid=sid)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the signatures"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_signature_attributs(cls, line, rulesets=None):  # TODO -> too complex
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
        tmpdir = settings.BASE_DIR + "/tmp/test_sig/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        rule_file = tmpdir + str(self.sid) + ".rules"
        with open(rule_file, 'w') as f:
            f.write(self.rule_full)
        cmd = [settings.SURICATA_BINARY, '-T',
               '-l', tmpdir,
               '-S', rule_file,
               '-c', settings.SURICATA_CONFIG
               ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = process.communicate()
        logger.debug(outdata)
        f.close()
        os.remove(rule_file)
        # if success ok
        if process.returncode == 0:
            return {'status': True}
        # if not -> return error
        return {'status': False, 'errors': errdata}


class ScriptSuricata(Rule):
    """
    Stores a script Suricata compatible. see : http://suricata.readthedocs.io/en/latest/rules/rule-lua-scripting.html
    """
    name = models.CharField(max_length=100, unique=True, db_index=True)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def get_by_name(cls, name):
        try:
            object = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the scripts"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_script_attributs(cls, file, rulesets=None):
        """ A script by file """
        rule_created = False
        rule_updated = False
        if not cls.get_by_name(file.name):
            rule_created = True
            script = ScriptSuricata()
            script.name = file.name
            script.created_date = timezone.now()
            script.rev = 0
            script.rule_full = file.readlines()
        else:
            rule_updated = True
            script = cls.get_by_name(file.name)
            script.rule_full = file.readlines()
            script.rev = script.rev + 1
            script.updated_date = timezone.now()
        script.save()
        if rulesets:
            for ruleset in rulesets:
                ruleset.scripts.add(script)
                ruleset.save()

        return rule_created, rule_updated


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
                                             search_field=lambda q: Q(sid__icontains=q) | Q(name__icontains=q),
                                             sort_field='sid',
                                             js_options={'quiet_millis': 200}
                                             )
    # signatures = models.ManyToManyField(SignatureSuricata, blank=True)
    # scripts = models.ManyToManyField(ScriptSuricata, blank=True)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class SourceSuricata(Source):
    """
    Set of Suricata Source. For scheduled upload of signatures.
    """
    rulesets = models.ManyToManyField(RuleSetSuricata, blank=True)

    def __init__(self, *args, **kwargs):
        super(Source, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def get_tmpdir(self):
        tmpdir = settings.BASE_DIR + "/tmp/" + str(self.pk) + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        return tmpdir

    def extract_files(self, file_dowloaded, rulesets=None):
        count_created = 0
        count_updated = 0
        tmpdir = self.get_tmpdir()
        f = open(tmpdir + "temp.tar.gz", 'wb')
        f.write(file_dowloaded)
        f.close()
        tar = tarfile.open(tmpdir + "temp.tar.gz")
        update_progress(10)
        progress_value = 10
        total_value = len(tar.getmembers())
        total = int(90 / total_value)
        if total == 0:
            total = 1
        for member in tar.getmembers():
            if member.isfile():
                progress_value = progress_value + total
                update_progress(progress_value)
                file = tar.extractfile(member)
                if os.path.splitext(member.name)[1] == '.rules':
                    for line in file.readlines():
                        line = line.decode('utf-8')
                        rule_created, rule_updated = SignatureSuricata.extract_signature_attributs(line, rulesets)
                        if rule_created:
                            count_created += 1
                        if rule_updated:
                            count_updated += 1
                elif os.path.splitext(member.name)[1] == '.lua':
                    rule_created, rule_updated = ScriptSuricata.extract_script_attributs(file, rulesets)
                    if rule_created:
                        count_created += 1
                    if rule_updated:
                        count_updated += 1
        tar.close()
        os.remove(tmpdir + "temp.tar.gz")
        return count_created, count_updated

    def upload_file(self, request, rulesets=None):
        count_created = 0
        count_updated = 0
        tmpdir = self.get_tmpdir()
        # Upload file - multiple files in compressed file
        if self.data_type.name == "multiple files in compressed file":
            logger.debug('multiple files in compressed file')
            file_dowloaded = self.file.read()
            count_created, count_updated = self.extract_files(file_dowloaded, rulesets)
            logger.debug('signatures : created : ' + str(count_created) + ' updated : ' + str(count_updated))
            return 'File uploaded successfully : ' + str(count_created) + ' signatures created and ' + str(
                count_updated) + ' signatures updated.'
        # Upload file - one file not compressed
        elif self.data_type.name == "one file not compressed":
            logger.debug('one file not compressed')
            f = open(tmpdir + "temp.rules", 'wb')
            f.write(self.file.read())
            f.close()
            f = open(tmpdir + "temp.rules", 'r')
            if os.path.splitext(request.FILES['file'].name)[1] == '.rules':
                for line in f.readlines():
                    rule_created, rule_updated = SignatureSuricata.extract_signature_attributs(line, rulesets)
                    if rule_created:
                        count_created += 1
                    if rule_updated:
                        count_updated += 1
            elif os.path.splitext(request.FILES['file'].name)[1] == '.lua':
                rule_created, rule_updated = ScriptSuricata.extract_script_attributs(f, rulesets)
                if rule_created:
                    count_created += 1
                if rule_updated:
                    count_updated += 1
            f.close()
            os.remove(tmpdir + "temp.rules")
            return 'File uploaded successfully : ' + str(count_created) + ' signatures created and ' + str(
                count_updated) + ' signatures updated.'
        else:
            logger.error('Data type upload unknown: ' + self.data_type.name)
            raise Exception('Data type upload unknown : ' + self.data_type.name)

    def upload(self, rulesets=None):
        tmpdir = self.get_tmpdir()
        count_created = 0
        count_updated = 0
        context = ssl._create_unverified_context()
        response = urllib.request.urlopen(self.uri, context=context)
        file_dowloaded = response.read()
        # URL HTTP - multiple files in compressed file
        if self.data_type.name == "multiple files in compressed file":
            logger.debug("multiple files in compressed file")
            if response.info()['Content-type'] == 'application/x-gzip':
                count_created, count_updated = self.extract_files(file_dowloaded, rulesets)
                logger.debug('File uploaded successfully : ' + str(count_created) + ' signatures created and ' + str(
                    count_updated) + ' signatures updated.')
                return 'File uploaded successfully : ' + str(
                    count_created) + ' signatures created and ' + str(count_updated) + ' signatures updated.'
            else:
                logger.error('Compression format unknown : ' + str(response.info()['Content-type']))
                raise Exception('Compression format unknown : ' + str(response.info()['Content-type']))
        # URL HTTP - one file not compressed
        elif self.data_type.name == "one file not compressed":
            logger.debug("one file not compressed")
            if response.info()['Content-type'] == 'text/plain':
                f = open(tmpdir + "temp.rules", 'wb')
                f.write(file_dowloaded)
                f.close()
                f = open(tmpdir + "temp.rules", 'r')
                if os.path.splitext(self.uri)[1] == '.rules':
                    for line in f.readlines():
                        rule_created, rule_updated = SignatureSuricata.extract_signature_attributs(line, rulesets)
                        if rule_created:
                            count_created += 1
                        if rule_updated:
                            count_updated += 1
                elif os.path.splitext(self.uri)[1] == '.lua':
                    rule_created, rule_updated = ScriptSuricata.extract_script_attributs(f, rulesets)
                    if rule_created:
                        count_created += 1
                    if rule_updated:
                        count_updated += 1
                f.close()
                os.remove(tmpdir + "temp.rules")
                logger.debug('signatures : created : ' + str(count_created) + ' updated : ' + str(count_updated))
                return 'File uploaded successfully : ' + str(
                    count_created) + ' signatures created and ' + str(
                    count_updated) + ' signatures updated.'
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
    configuration = models.ForeignKey(ConfSuricata)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description

    def install(self):
        command1 = "echo 'deb http://http.debian.net/debian stretch-backports main' >> /etc/apt/sources.list.d/stretch-backports.list"
        command2 = "apt update"
        command3 = "apt -t stretch-backports install " + self.__class__.__name__.lower()
        tasks = {"add_repo": command1, "update_repo": command2, "install": command3}
        try:
            response = execute(self, tasks)
        except Exception as e:
            logger.error(e)
            return False
        logger.debug("output : " + str(response))
        return True

    def reload(self):
        # Don't works TODO
        command1 = "kill -USR2 $( pidof suricata )"
        tasks = {"reload": command1}
        try:
            response = execute(self, tasks)
        except Exception as e:
            logger.error(e)
            return False
        logger.debug("output : " + str(response))
        return True

    def test_rules(self):
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

    def deploy_rules(self):
        # Signatures
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        value = ""
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                if signature.enabled:
                    value += signature.rule_full + os.linesep
        f = open(tmpdir + "temp.rules", 'w')
        f.write(value)
        f.close()

        # Scripts
        deploy = True
        response = dict()
        for ruleset in self.rulesets.all():
            for script in ruleset.scripts.all():
                if script.enabled:
                    f = open(tmpdir + script.name, 'w')
                    f.write(script.rule_full)
                    f.close()
                    try:
                        response = execute_copy(self.server, src=tmpdir + script.name,
                                                dest=self.configuration.conf_script_directory.rstrip('/') + '/' + script.name,
                                                owner='root', group='root', mode='0600')
                    except Exception as e:
                        logger.error(e)
                        deploy = False
                    logger.debug("output : " + str(response))
        try:
            response = execute_copy(self.server, src=tmpdir + 'temp.rules',
                                    dest=self.configuration.conf_rules_directory.rstrip('/') + '/deployed.rules',
                                    owner='root', group='root', mode='0600')
        except Exception as e:
            logger.error(e)
            deploy = False
        logger.debug("output : " + str(response))

        for file in glob.glob(tmpdir + '*.lua'):
            os.remove(tmpdir + file)
        if os.path.isfile(tmpdir + 'temp.rules'):
            os.remove(tmpdir + "temp.rules")
        return deploy

    def deploy_conf(self):
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        value = self.configuration.conf_advanced_text
        f = open(tmpdir + "temp.conf", 'w')
        f.write(value)
        f.close()
        deploy = True
        response = dict()
        try:
            response = execute_copy(self.server, src=os.path.abspath(tmpdir + 'temp.conf'),
                                    dest=self.configuration.conf_file,
                                    owner='root', group='root', mode='0600')
        except Exception as e:
            logger.error(e)
            deploy = False
        logger.debug("output : " + str(response))

        if os.path.isfile(tmpdir + 'temp.conf'):
            os.remove(tmpdir + "temp.conf")
        return deploy

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class PcapTestSuricata(models.Model):
    """
    Stores a Pcap file for testing signature or script.
    """
    signature = select2.fields.ForeignKey(SignatureSuricata,
                                          limit_choices_to=models.Q(enabled=True),
                                          ajax=True,
                                          search_field='sid',
                                          overlay="Choose a signature...",
                                          js_options={
                                              'quiet_millis': 200,
                                          },
                                          on_delete=models.CASCADE
                                          )
    probe = models.ForeignKey(Suricata)
    pcap_success = models.FileField(name='pcap_success', upload_to='tmp/pcap/', blank=True)
    # pcap_fail = models.FileField(name='pcap_fail', upload_to=tmpdir, blank=True)

    def __str__(self):
        return str(self.signature) + "  " + str(self.probe)

    def test(self):
        tmpdir = settings.BASE_DIR + "/tmp/pcap/" + str(self.signature.sid) + "/" + self.probe.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        rule_file = tmpdir + "rule.rules"
        conf_file = tmpdir + "suricata.yaml"
        with open(rule_file, 'w') as f:
            f.write(self.signature.rule_full)
        f.close()
        config = self.probe.configuration.conf_advanced_text
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
        with open(conf_file, 'w') as f:
            f.write(config)
        f.close()
        # test pcap success
        cmd = [settings.SURICATA_BINARY,
               '-l', tmpdir,
               '-S', rule_file,
               '-c', conf_file,
               '-r', settings.BASE_DIR + "/" + self.pcap_success.name,
               '--set', 'outputs.0.fast.enabled=yes',
               '--set', 'classification-file=' + settings.BASE_DIR + '/suricata/tests/data/classification.config',
               '--set', 'reference-config-file=' + settings.BASE_DIR + '/suricata/tests/data/reference.config',
               ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = process.communicate()
        # test if alert is generated :
        test = False
        if os.path.isfile(tmpdir + "fast.log"):
            with open(tmpdir + "fast.log", "r") as f:
                if self.signature.msg in f.read():
                    test = True

        # Remove files
        os.remove(rule_file)
        os.remove(conf_file)
        for file in glob.glob(tmpdir + "*.log"):
            os.remove(file)
        # if success ok
        if process.returncode == 0 and test:
            return {'status': True}
        # if not -> return error
        errdata += b"Alert not generated"
        return {'status': False, 'errors': errdata}
