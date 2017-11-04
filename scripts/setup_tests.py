from jinja2 import Template
from home.utils import encrypt
import os
import sys
from getpass import getpass
from shutil import copyfile
from django.conf import settings


template_suricata_test = """
[
{
    "model": "home.sshkey",
    "pk": 2,
    "fields": {
        "name": "test",
        "file": "ssh_keys/{{ ansible_ssh_private_key_file }}"
    }
},
{
    "model": "home.probe",
    "pk": 1,
    "fields": {
        "name": "suricata1",
        "description": "test",
        "created_date": "2017-09-23T21:28:43.849Z",
        "rules_updated_date": null,
        "host": "{{ host }}",
        "os": 1,
        "type": "Suricata",
        "scheduled_enabled": true,
        "scheduled_crontab": 1,
        "ansible_remote_user": "{{ ansible_remote_user }}",
        "ansible_remote_port": {{ ansible_remote_port }},
        "ansible_become": {{ ansible_become }},
        "ansible_become_method": "{{ ansible_become_method }}",
        "ansible_become_user": "{{ ansible_remote_user }}",
        "ansible_become_pass": "{{ ansible_become_pass }}",
        "ansible_ssh_private_key_file": 2
    }
},
{
    "model": "home.probe",
    "pk": 2,
    "fields": {
        "name": "suricata2",
        "description": "",
        "created_date": "2017-09-24T11:57:46.817Z",
        "rules_updated_date": null,
        "host": "localhost",
        "os": 1,
        "type": "Suricata",
        "scheduled_enabled": false,
        "scheduled_crontab": null,
        "ansible_remote_user": "admin",
        "ansible_remote_port": 22,
        "ansible_become": false,
        "ansible_become_method": "sudo",
        "ansible_become_user": "root",
        "ansible_become_pass": null,
        "ansible_ssh_private_key_file": null
    }
},
{
    "model": "suricata.suricata",
    "pk": 1,
    "fields": {
        "configuration": 1,
        "rulesets": [
            1
        ]
    }
},
{
    "model": "suricata.suricata",
    "pk": 2,
    "fields": {
        "configuration": 2,
        "rulesets": []
    }
}
]
"""


def run():
    skip = input('Add datas Tests ? (y/N) ')
    if skip.lower() == 'n' or not skip:
        sys.exit(0)
    else:
        print("Server Suricata for tests")
        host = input('host : ')
        ansible_become = input('ansible_become : (true/false) ')
        ansible_become_method = input('ansible_become_method : ')
        ansible_become_pass = getpass('ansible_become_pass : ')
        ansible_remote_user = input('ansible_remote_user : ')
        ansible_remote_port = input('ansible_remote_port : (0-65535) ')
        ansible_ssh_private_key_file = input('ansible_ssh_private_key_file : (Absolute file path) ')
        ansible_ssh_private_key_file_basename = os.path.basename(ansible_ssh_private_key_file)
        ssh_dir = settings.BASE_DIR + '/ssh_keys/'
        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir)
        try:
            copyfile(ansible_ssh_private_key_file, ssh_dir + ansible_ssh_private_key_file_basename)
            os.chmod(ssh_dir + ansible_ssh_private_key_file_basename, 0o600)
        except Exception as e:
            print("Error in the path of the file : " + e.__str__())
            sys.exit(1)

        t = Template(template_suricata_test)
        suricata_test = t.render(host=host,
                                 ansible_become=ansible_become,
                                 ansible_become_method=ansible_become_method,
                                 ansible_become_pass=encrypt(ansible_become_pass).decode('utf-8'),
                                 ansible_remote_user=ansible_remote_user,
                                 ansible_remote_port=ansible_remote_port,
                                 ansible_ssh_private_key_file=ansible_ssh_private_key_file_basename
                                 )
        with open(settings.BASE_DIR + '/suricata/fixtures/test-suricata-probe.json', 'w') as f:
            f.write(suricata_test)
        f.close()
        sys.exit(0)
