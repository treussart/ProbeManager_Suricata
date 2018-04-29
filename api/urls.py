from suricata.api import views

urls_to_register = [
    (r'^suricata/configuration', views.ConfigurationViewSet),
    (r'^suricata/suricata', views.SuricataViewSet),
    (r'^suricata/suricata', views.SuricataUpdateViewSet),
    (r'^suricata/signature', views.SignatureSuricataViewSet),
    (r'^suricata/script', views.ScriptSuricataViewSet),
    (r'^suricata/source', views.SourceSuricataViewSet),
    (r'^suricata/ruleset', views.RuleSetSuricataViewSet),
    (r'^suricata/blacklist', views.BlackListViewSet),
    (r'^suricata/ipreputation', views.IPReputationViewSet),
    (r'^suricata/categoryreputation', views.CategoryReputationViewSet),
]
