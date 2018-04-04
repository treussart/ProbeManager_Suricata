from django.conf.urls import url

from core.views import probe_index, start, stop, restart, reload, status, install, update, deploy_conf, deploy_rules, \
    get_progress
from .views import deploy_reputation_list
app_name = 'suricata'

urlpatterns = [
    url(r'^(?P<pk>\d+)$', probe_index, name='probe_index'),
    url(r'^start/(?P<pk>\d+)$', start, name='start'),
    url(r'^stop/(?P<pk>\d+)$', stop, name='stop'),
    url(r'^restart/(?P<pk>\d+)$', restart, name='restart'),
    url(r'^reload/(?P<pk>\d+)$', reload, name='reload'),
    url(r'^status/(?P<pk>\d+)$', status, name='status'),
    url(r'^install/(?P<pk>\d+)$', install, name='install'),
    url(r'^update/(?P<pk>\d+)$', update, name='update'),
    url(r'^deploy-conf/(?P<pk>\d+)$', deploy_conf, name='deploy-conf'),
    url(r'^deploy-rules/(?P<pk>\d+)$', deploy_rules, name='deploy-rules'),
    url(r'^deploy-reputation-list/(?P<pk>\d+)$', deploy_reputation_list, name='deploy-reputation-list'),
    url(r'^get-progress/$', get_progress, name='get-progress'),
]
