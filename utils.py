import yaml
import json
import os
from django_celery_beat.models import PeriodicTask
from django.conf import settings
from django.shortcuts import render
from django.contrib import messages


def create_upload_task(source):
    PeriodicTask.objects.create(crontab=source.scheduled_rules_deployment_crontab,
                                name=str(source.uri) + "_upload_task",
                                task='suricata.tasks.upload_url_http',
                                args=json.dumps([source.uri, ])
                                )


def convert_conf(configuration):
    conf = yaml.safe_load(configuration.conf_advanced_text)
    configuration.conf_advanced_text = """
%YAML 1.1
---

"""
    configuration.conf_advanced_text += yaml.dump(conf, default_flow_style=False)
    return configuration


def create_conf(configuration):
    with open(settings.BASE_DIR + "/suricata/default-Suricata-conf.yaml", encoding='utf_8') as f:
        conf_full_default = f.read()
    conf = yaml.safe_load(conf_full_default)
    conf['vars']['address-groups']['HOME_NET'] = configuration.conf_HOME_NET
    conf['vars']['address-groups']['EXTERNAL_NET'] = configuration.conf_EXTERNAL_NET
    conf['vars']['address-groups']['HTTP_SERVERS'] = configuration.conf_HTTP_SERVERS
    conf['vars']['address-groups']['SMTP_SERVERS'] = configuration.conf_SMTP_SERVERS
    conf['vars']['address-groups']['SQL_SERVERS'] = configuration.conf_SQL_SERVERS
    conf['vars']['address-groups']['DNS_SERVERS'] = configuration.conf_DNS_SERVERS
    conf['vars']['address-groups']['TELNET_SERVERS'] = configuration.conf_TELNET_SERVERS
    conf['vars']['address-groups']['AIM_SERVERS'] = configuration.conf_AIM_SERVERS
    conf['vars']['address-groups']['DNP3_SERVER'] = configuration.conf_DNP3_SERVER
    conf['vars']['address-groups']['DNP3_CLIENT'] = configuration.conf_DNP3_CLIENT
    conf['vars']['address-groups']['MODBUS_CLIENT'] = configuration.conf_MODBUS_CLIENT
    conf['vars']['address-groups']['MODBUS_SERVER'] = configuration.conf_MODBUS_SERVER
    conf['vars']['address-groups']['ENIP_CLIENT'] = configuration.conf_ENIP_CLIENT
    conf['vars']['address-groups']['ENIP_SERVER'] = configuration.conf_ENIP_SERVER
    conf['vars']['port-groups']['HTTP_PORTS'] = configuration.conf_HTTP_PORTS
    conf['vars']['port-groups']['SHELLCODE_PORTS'] = configuration.conf_SHELLCODE_PORTS
    conf['vars']['port-groups']['ORACLE_PORTS'] = configuration.conf_ORACLE_PORTS
    conf['vars']['port-groups']['SSH_PORTS'] = configuration.conf_SSH_PORTS
    conf['vars']['port-groups']['DNP3_PORTS'] = configuration.conf_DNP3_PORTS
    conf['vars']['port-groups']['MODBUS_PORTS'] = configuration.conf_MODBUS_PORTS

    conf['stats']['enabled'] = str(configuration.conf_stats)
    conf['af-packet'][0]['interface'] = str(configuration.conf_afpacket_interface)
    conf['outputs'][0]['fast']['enabled'] = str(configuration.conf_outputs_fast)
    conf['outputs'][1]['eve-log']['enabled'] = str(configuration.conf_outputs_evelog)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['http'] = str(configuration.conf_outputs_evelog_alert_http)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['tls'] = str(configuration.conf_outputs_evelog_alert_tls)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['ssh'] = str(configuration.conf_outputs_evelog_alert_ssh)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['smtp'] = str(configuration.conf_outputs_evelog_alert_smtp)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['dnp3'] = str(configuration.conf_outputs_evelog_alert_dnp3)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['tagged-packets'] = str(
        configuration.conf_outputs_evelog_alert_taggedpackets)
    conf['outputs'][1]['eve-log']['types'][0]['alert']['xff']['enabled'] = str(configuration.conf_outputs_evelog_xff)
    conf['outputs'][1]['eve-log']['types'][1]['http']['extended'] = str(configuration.conf_outputs_evelog_http_extended)
    conf['outputs'][1]['eve-log']['types'][2]['dns']['query'] = str(configuration.conf_outputs_evelog_dns_query)
    conf['outputs'][1]['eve-log']['types'][2]['dns']['answer'] = str(configuration.conf_outputs_evelog_dns_answer)
    conf['outputs'][1]['eve-log']['types'][3]['tls']['extended'] = str(configuration.conf_outputs_evelog_tls_extended)
    conf['outputs'][1]['eve-log']['types'][4]['files']['force-magic'] = str(
        configuration.conf_outputs_evelog_files_forcemagic)
    conf['outputs'][2]['unified2-alert']['enabled'] = str(configuration.conf_outputs_unified2alert)
    conf['outputs'][17]['lua']['enabled'] = str(configuration.conf_lua)

    conf['app-layer']['protocols']['tls']['enabled'] = str(configuration.conf_applayer_tls)
    conf['app-layer']['protocols']['dcerpc']['enabled'] = str(configuration.conf_applayer_dcerpc)
    conf['app-layer']['protocols']['ftp']['enabled'] = str(configuration.conf_applayer_ftp)
    conf['app-layer']['protocols']['ssh']['enabled'] = str(configuration.conf_applayer_ssh)
    conf['app-layer']['protocols']['smtp']['enabled'] = str(configuration.conf_applayer_smtp)
    conf['app-layer']['protocols']['imap']['enabled'] = str(configuration.conf_applayer_imap)
    conf['app-layer']['protocols']['msn']['enabled'] = str(configuration.conf_applayer_msn)
    conf['app-layer']['protocols']['smb']['enabled'] = str(configuration.conf_applayer_smb)
    conf['app-layer']['protocols']['dns']['enabled'] = str(configuration.conf_applayer_dns)
    conf['app-layer']['protocols']['http']['enabled'] = str(configuration.conf_applayer_http)

    configuration.conf_advanced_text = """%YAML 1.1
---

"""
    configuration.conf_advanced_text += yaml.dump(conf, default_flow_style=False)
    return configuration


def generic_import_csv(cls, request):
    if request.method == 'GET':
        return render(request, 'import_csv.html')
    elif request.method == 'POST':
        if request.FILES['file']:
            try:
                if not os.path.exists(settings.BASE_DIR + '/tmp/'):
                    os.mkdir(settings.BASE_DIR + '/tmp/')
                with open(settings.BASE_DIR + '/tmp/imported.csv', 'wb+') as destination:
                    for chunk in request.FILES['file'].chunks():
                        destination.write(chunk)
                cls.import_from_csv(settings.BASE_DIR + '/tmp/imported.csv')
            except Exception as e:
                messages.add_message(request, messages.ERROR, 'Error during the import : ' + str(e))
                return render(request, 'import_csv.html')
            messages.add_message(request, messages.SUCCESS, 'CSV file imported successfully !')
            return render(request, 'import_csv.html')
        else:
            messages.add_message(request, messages.ERROR, 'No file submitted')
            return render(request, 'import_csv.html')
