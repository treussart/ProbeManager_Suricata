import logging

from django_celery_beat.models import PeriodicTask
from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from core.utils import create_deploy_rules_task, create_check_task
from suricata.api import serializers
from suricata.models import Suricata, Configuration, SignatureSuricata, ScriptSuricata, SourceSuricata, \
    RuleSetSuricata, BlackList, IPReputation, CategoryReputation, Md5, ClassType

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


class SuricataViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
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

    def destroy(self, request, pk=None):
        suricata = self.get_object()
        try:
            periodic_task = PeriodicTask.objects.get(
                name=suricata.name + "_deploy_rules_" + str(suricata.scheduled_rules_deployment_crontab))
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        try:
            periodic_task = PeriodicTask.objects.get(name=suricata.name + "_check_task")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        suricata.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

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


class BlackListViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = BlackList.objects.all()
    serializer_class = serializers.BlackListSerializer

    def create(self, request):
        serializer = serializers.BlackListSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            blacklist = BlackList.get_by_value(request.data['value'])
            logger.debug("create blacklist for " + str(blacklist))
            blacklist.create_blacklist()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        blacklist = self.get_object()
        if blacklist.type == "MD5":
            if Md5.get_by_value(blacklist.value):
                md5_suricata = Md5.get_by_value(blacklist.value)
                md5_suricata.delete()
        else:
            if SignatureSuricata.get_by_sid(blacklist.sid):
                signature = SignatureSuricata.get_by_sid(blacklist.sid)
                signature.delete()
        blacklist.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class IPReputationViewSet(viewsets.ModelViewSet):
    queryset = IPReputation.objects.all()
    serializer_class = serializers.IPReputationSerializer


class CategoryReputationViewSet(viewsets.ModelViewSet):
    queryset = CategoryReputation.objects.all()
    serializer_class = serializers.CategoryReputationSerializer
