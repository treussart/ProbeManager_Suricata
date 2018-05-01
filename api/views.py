import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from suricata.api import serializers
from suricata.models import Suricata, Configuration, SignatureSuricata, ScriptSuricata, SourceSuricata, \
    RuleSetSuricata, BlackList, IPReputation, CategoryReputation, ClassType

logger = logging.getLogger(__name__)


class ClassTypeViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows class type to be viewed or edited. ex : Not Suspicious Traffic
    """
    queryset = ClassType.objects.all()
    serializer_class = serializers.ClassTypeSerializer


class ConfigurationViewSet(viewsets.ModelViewSet):
    queryset = Configuration.objects.all()
    serializer_class = serializers.ConfigurationSerializer


class SuricataViewSet(viewsets.ModelViewSet):
    queryset = Suricata.objects.all()
    serializer_class = serializers.SuricataSerializer


class SignatureSuricataViewSet(viewsets.ModelViewSet):
    queryset = SignatureSuricata.objects.all()
    serializer_class = serializers.SignatureSuricataSerializer


class ScriptSuricataViewSet(viewsets.ModelViewSet):
    queryset = ScriptSuricata.objects.all()
    serializer_class = serializers.ScriptSuricataSerializer


class SourceSuricataViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = SourceSuricata.objects.all()
    serializer_class = serializers.SourceSuricataSerializer


class RuleSetSuricataViewSet(viewsets.ModelViewSet):
    queryset = RuleSetSuricata.objects.all()
    serializer_class = serializers.RuleSetSuricataSerializer


class BlackListViewSet(viewsets.ModelViewSet):
    queryset = BlackList.objects.all()
    serializer_class = serializers.BlackListSerializer


class IPReputationViewSet(viewsets.ModelViewSet):
    queryset = IPReputation.objects.all()
    serializer_class = serializers.IPReputationSerializer


class CategoryReputationViewSet(viewsets.ModelViewSet):
    queryset = CategoryReputation.objects.all()
    serializer_class = serializers.CategoryReputationSerializer
