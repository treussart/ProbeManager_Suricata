from django.shortcuts import render
from django.http import HttpResponseNotFound
from suricata.models import Suricata
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import logging


logger = logging.getLogger(__name__)


@login_required
def deploy_rules(request, id):
    """
    Deploy the rules of a Suricata instance.
    """
    suricata = Suricata.get_by_id(id)
    if suricata is None:
        return HttpResponseNotFound
    else:
        response_tests = suricata.test_rules()
        test_pcap = True
        errors = list()
        for pcaptest in suricata.pcaptestsuricata_set.all():
            response_pcap_test = pcaptest.test()
            if not response_pcap_test['status']:
                test_pcap = False
                errors.append(str(pcaptest) + " : " + str(response_pcap_test['errors']))
        if suricata.secure_deployment:
            if not response_tests['status']:
                messages.add_message(request, messages.ERROR, 'Error during the rules test')
                return render(request, 'suricata/index.html', {'probe': suricata})
            elif not test_pcap:
                messages.add_message(request, messages.ERROR, "Test pcap failed ! " + str(errors))
                return render(request, 'suricata/index.html', {'probe': suricata})
        if response_tests['status']:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(response_tests['errors']))
        if test_pcap:
            messages.add_message(request, messages.SUCCESS, "Test pcap OK")
        else:
            messages.add_message(request, messages.ERROR, "Test pcap failed ! " + str(errors))
        response_deploy_rules = suricata.deploy_rules()
        response_reload = suricata.reload()
        if response_deploy_rules['result'] == 0 and response_reload['result'] == 0:
            messages.add_message(request, messages.SUCCESS, 'Deployed rules successfully')
        else:
            messages.add_message(request, messages.ERROR, 'Error during the rules deployed')
        return render(request, 'suricata/index.html', {'probe': suricata})
