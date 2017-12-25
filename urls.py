from django.conf.urls import url
from home.views import probe_index, start, stop, restart, reload, status, install, update, deploy_conf, deploy_rules, get_progress


app_name = 'suricata'

urlpatterns = [
    url(r'^(?P<id>\d+)$', probe_index, name='probe_index'),
    url(r'^start/(?P<id>\d+)$', start, name='start'),
    url(r'^stop/(?P<id>\d+)$', stop, name='stop'),
    url(r'^restart/(?P<id>\d+)$', restart, name='restart'),
    url(r'^reload/(?P<id>\d+)$', reload, name='reload'),
    url(r'^status/(?P<id>\d+)$', status, name='status'),
    url(r'^install/(?P<id>\d+)$', install, name='install'),
    url(r'^update/(?P<id>\d+)$', update, name='update'),
    url(r'^deploy-conf/(?P<id>\d+)$', deploy_conf, name='deploy-conf'),
    url(r'^deploy-rules/(?P<id>\d+)$', deploy_rules, name='deploy-rules'),
    url(r'^get-progress/$', get_progress, name='get-progress'),
]
