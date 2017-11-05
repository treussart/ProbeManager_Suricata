from suricata.api import views


urls_to_register = [
    (r'suricata/conf', views.ConfSuricataViewSet),
    (r'suricata/conf', views.ConfSuricataViewSet),
    (r'suricata/suricata', views.SuricataViewSet),
    (r'suricata/signature', views.SignatureSuricataViewSet),
    (r'suricata/script', views.ScriptSuricataViewSet),
    (r'suricata/source', views.SourceSuricataViewSet),
    (r'suricata/ruleset', views.RuleSetSuricataViewSet),
]
