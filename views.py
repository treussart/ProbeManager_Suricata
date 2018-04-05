import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseNotFound
from django.shortcuts import render
from django.utils.safestring import mark_safe

from .tasks import deploy_reputation_list as task_deploy_reputation_list
from .models import Suricata

logger = logging.getLogger(__name__)


@login_required
def deploy_reputation_list(request, pk):
    probe = Suricata.get_by_id(pk)
    if probe is None:
        return HttpResponseNotFound()
    else:
        try:
            task_deploy_reputation_list.delay(probe.name)
            messages.add_message(request, messages.SUCCESS, "Deploy reputation list launched with succeed. " +
                                 mark_safe("<a href='/admin/core/job/'>View Job</a>"))
        except Exception as e:  # pragma: no cover
            logger.exception('Deploy reputation list failed ! ' + str(e))
            messages.add_message(request, messages.ERROR, "Deploy reputation list failed ! " + str(e))
    return render(request, probe.type.lower() + '/index.html', {'probe': probe})
