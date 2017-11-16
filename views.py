from django.shortcuts import render
from django.http import HttpResponseNotFound
from suricata.models import Suricata
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import logging
from suricata.tasks import deploy_rules as deploy_rules_probe


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
        deploy_rules_probe.delay(suricata.name)
        messages.add_message(request, messages.SUCCESS, 'Deployed rules launched with succeed. View Job')
        return render(request, 'suricata/index.html', {'probe': suricata})
