from suricata.api import views

urls_to_register = [
    (r'suricata/configuration', views.ConfigurationViewSet),
    (r'suricata/suricata', views.SuricataViewSet),
    (r'suricata/signature', views.SignatureSuricataViewSet),
    (r'suricata/script', views.ScriptSuricataViewSet),
    (r'suricata/source', views.SourceSuricataViewSet),
    (r'suricata/ruleset', views.RuleSetSuricataViewSet),
]
