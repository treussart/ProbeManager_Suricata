from rest_framework import serializers

from suricata.models import Configuration, Suricata, SignatureSuricata, ScriptSuricata, SourceSuricata, \
    RuleSetSuricata, AppLayerType


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"


class SuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Suricata
        fields = "__all__"


class SuricataUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Suricata
        fields = 'name', 'description', 'installed', 'secure_deployment', 'server', 'rulesets', 'configuration'


class SignatureSuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignatureSuricata
        fields = "__all__"


class ScriptSuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScriptSuricata
        fields = "__all__"


class SourceSuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SourceSuricata
        fields = "__all__"


class RuleSetSuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleSetSuricata
        fields = "__all__"


class AppLayerTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppLayerType
        fields = "__all__"
