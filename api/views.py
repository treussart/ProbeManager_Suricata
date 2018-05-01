import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from core.utils import create_deploy_rules_task, create_check_task
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


class SuricataViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin,
                      viewsets.GenericViewSet):
    queryset = Suricata.objects.all()
    serializer_class = serializers.SuricataSerializer

    def create(self, request):
        serializer = serializers.SuricataSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            suricata = Suricata.get_by_name(request.data['name'])
            logger.debug("create scheduled for " + str(suricata))
            create_deploy_rules_task(suricata)
            create_check_task(suricata)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        suricata = self.get_object()
        serializer = serializers.SuricataUpdateSerializer(suricata, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        suricata = self.get_object()
        serializer = serializers.SuricataUpdateSerializer(suricata, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
