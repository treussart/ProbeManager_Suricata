import logging
import os
import time

from django import forms
from django.conf import settings
from django.shortcuts import render
from django.conf.urls import url
from django.contrib import admin
from django.contrib import messages
from django.contrib.admin.helpers import ActionForm
from django.http import HttpResponseRedirect
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from django.utils.safestring import mark_safe

from suricata.tasks import upload_url_http
from core.utils import create_deploy_rules_task,  add_1_hour, create_check_task
from core.utils import update_progress
from suricata.utils import create_upload_task
from suricata.forms import SuricataChangeForm
from suricata.models import Suricata, SignatureSuricata, ScriptSuricata, RuleSetSuricata, ConfSuricata, \
    SourceSuricata, BlackListSuricata, Md5Suricata, IPReputationSuricata, CategoryReputationSuricata
from suricata.utils import create_conf, convert_conf

logger = logging.getLogger(__name__)


class MarkedRuleMixin(admin.ModelAdmin):
    def make_enabled(self, request, queryset):
        rows_updated = queryset.update(enabled=True)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as enabled." % message_bit)

    def make_disabled(self, request, queryset):
        rows_updated = queryset.update(enabled=False)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as disabled." % message_bit)

    make_enabled.short_description = "Mark rule as enabled"
    make_disabled.short_description = "Mark rule as disabled"


class RuleSetSuricataAdmin(admin.ModelAdmin):

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for ruleset in obj:
            for signature in ruleset.signatures.all():
                response = signature.test()
                if not response['status']:
                    test = False
                    errors.append(str(signature) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    actions = [test_signatures]


class SuricataAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'suricata/js/mask-crontab.js',
        )

    def delete(self, request, obj, probe=None):
        if probe is None:
            probe = obj
        try:
            periodic_task = PeriodicTask.objects.get(
                name=probe.name + "_deploy_rules_" + str(probe.scheduled_rules_deployment_crontab))
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        messages.add_message(request, messages.SUCCESS, "Suricata instance " + probe.name + " deleted")
        super().delete_model(request, obj)

    def get_form(self, request, obj=None, **kwargs):
        """A ModelAdmin that uses a different form class when adding an object."""
        if obj is None:
            return super(SuricataAdmin, self).get_form(request, obj, **kwargs)
        else:
            return SuricataChangeForm

    def save_model(self, request, obj, form, change):
        logger.debug("create scheduled")
        create_deploy_rules_task(obj)
        create_check_task(obj)
        super().save_model(request, obj, form, change)

    def delete_model(self, request, obj):
        self.delete(request, obj)

    def delete_suricata(self, request, obj):
        for probe in obj:
            self.delete(request, obj, probe=probe)

    def get_actions(self, request):
        actions = super(SuricataAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for probe in obj:
            response = probe.test_rules()
            if not response['status']:
                test = False
                errors.append(str(probe) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    actions = [delete_suricata, test_signatures]


class ConfSuricataAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'suricata/js/mask-advanced-fields.js',
        )

    def save_model(self, request, obj, form, change):
        if not obj.conf_advanced:
            obj = create_conf(obj)
        else:
            obj = convert_conf(obj)
        response = obj.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        super().save_model(request, obj, form, change)

    def test_configurations(self, request, obj):
        test = True
        errors = list()
        for conf in obj:
            response = conf.test()
            if not response['status']:
                test = False
                errors.append(str(conf) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test configurations OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configurations failed ! " + str(errors))

    actions = [test_configurations]


class ScriptSuricataAdmin(MarkedRuleMixin, admin.ModelAdmin):

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('id', 'name', 'enabled')
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled]


class SignatureSuricataAdmin(MarkedRuleMixin, admin.ModelAdmin):

    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.add(signature)
            ruleset.save()

    add_ruleset.short_description = 'Add ruleset'

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.remove(signature)
            ruleset.save()

    remove_ruleset.short_description = 'Remove ruleset'

    class UpdateActionForm(ActionForm):
        ruleset = forms.ModelChoiceField(queryset=RuleSetSuricata.get_all(), empty_label="Select a ruleset",
                                         required=False)

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for signature in obj:
            response = signature.test_all()
            if not response['status']:
                test = False
                errors.append(str(signature) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('sid', 'msg', 'enabled')
    action_form = UpdateActionForm
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled, add_ruleset, remove_ruleset, test_signatures]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = obj.test_all()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test signature OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signature failed ! " + str(response['errors']))

    class Media:
        js = (
            'suricata/js/add-link-reference.js',
            'suricata/js/mask-ruleset-field.js',
        )


class SourceSuricataAdmin(admin.ModelAdmin):

    def get_actions(self, request):
        actions = super(SourceSuricataAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def delete_source(self, request, obj):
        for source in obj:
            try:
                periodic_task = PeriodicTask.objects.get(name=source.uri + '_upload_task')
                periodic_task.delete()
                logger.debug(str(periodic_task) + " deleted")
            except PeriodicTask.DoesNotExist:
                pass
            try:
                for ruleset in source.rulesets.all():
                    for probe in ruleset.suricata_set.all():
                        periodic_task = PeriodicTask.objects.get(
                            name__contains=probe.name + "_" + source.uri + "_deploy_rules_")
                        periodic_task.delete()
                        logger.debug(str(periodic_task) + " deleted")
            except PeriodicTask.DoesNotExist:
                pass
            source.delete()
            logger.debug(str(source) + " deleted")
            messages.add_message(request, messages.SUCCESS, str(source) + " deleted")

    actions = [delete_source]
    list_display = ('__str__',)
    list_display_links = None

    def response_add(self, request, obj, post_url_continue=None):
        """
        Determines the HttpResponse for the add_view stage.
        """
        if obj.method.name == "Upload file":
            for source in SourceSuricata.get_all():
                if '_to_delete' in source.uri:
                    source.delete()
            return HttpResponseRedirect('/')
        else:
            return super(SourceSuricataAdmin, self).response_change(request, obj)

    def save_model(self, request, obj, form, change):
        try:
            rulesets = list()
            rulesets_id = list()
            if request.POST.getlist('rulesets'):
                rulesets_id = request.POST.getlist('rulesets')
                for ruleset_id in rulesets_id:
                    rulesets.append(RuleSetSuricata.get_by_id(ruleset_id))
            update_progress(0)
            # URL HTTP
            if obj.method.name == "URL HTTP":
                obj.save()
                if obj.scheduled_rules_deployment_enabled and obj.scheduled_rules_deployment_crontab:
                    create_upload_task(obj)
                    if obj.scheduled_deploy:
                        if rulesets:
                            for ruleset in rulesets:
                                try:
                                    for probe in ruleset.suricata_set.all():
                                        schedule = add_1_hour(obj.scheduled_rules_deployment_crontab)
                                        schedule, _ = CrontabSchedule.objects.\
                                            get_or_create(minute=schedule.minute,
                                                          hour=schedule.hour,
                                                          day_of_week=schedule.day_of_week,
                                                          day_of_month=schedule.day_of_month,
                                                          month_of_year=schedule.month_of_year,
                                                          )
                                        schedule.save()
                                        create_deploy_rules_task(probe, schedule, obj)
                                except Exception as e:  # pragma: no cover
                                    logger.exception(str(e))
                upload_url_http.delay(obj.uri, rulesets_id=rulesets_id)
                messages.add_message(request, messages.SUCCESS, "Upload source in progress. " +
                                     mark_safe("<a href='/admin/core/job/'>View Job</a>"))
            # Upload file
            elif obj.method.name == "Upload file":
                obj.uri = str(time.time()) + "_to_delete"
                obj.save()
                message = obj.upload_file(request, rulesets)
                logger.debug("Upload file: " + str(message))
                messages.add_message(request, messages.SUCCESS, message)
            else:  # pragma: no cover
                logger.error('Upload method unknown : ' + obj.method.name)
                messages.add_message(request, messages.ERROR, 'Upload method unknown : ' + obj.method.name)
        except Exception as e:  # pragma: no cover
            logger.exception(str(e))
            messages.add_message(request, messages.ERROR, str(e))
        finally:
            if os.path.isfile(settings.BASE_DIR + "/" + obj.file.name):
                os.remove(settings.BASE_DIR + "/" + obj.file.name)
            if os.path.isfile(settings.BASE_DIR + "/tmp/" + 'progress.json'):
                os.remove(settings.BASE_DIR + "/tmp/" + 'progress.json')

    class Media:
        js = (
            'suricata/js/add-link-reference.js',
            'suricata/js/method-options.js',
            'suricata/js/progress-bar.js',
        )
        css = {
            'all': ('suricata/css/progress-bar.css',),
        }


class BlackListSuricataAdmin(admin.ModelAdmin):

    def save_model(self, request, obj, form, change):
        obj.save()
        obj.create_blacklist()

    def get_actions(self, request):
        actions = super(BlackListSuricataAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def delete_blacklist(self, request, obj):
        for blacklist in obj:
            if blacklist.type == "MD5":
                if Md5Suricata.get_by_value(blacklist.value):
                    md5_suricata = Md5Suricata.get_by_value(blacklist.value)
                    md5_suricata.delete()
            else:
                if SignatureSuricata.get_by_sid(blacklist.sid):
                    signature = SignatureSuricata.get_by_sid(blacklist.sid)
                    signature.delete()
        super().delete_model(request, obj)
        messages.add_message(request, messages.SUCCESS, "Blacklists deleted")

    list_display = ('__str__',)
    list_display_links = None
    actions = [delete_blacklist]


class IPReputationSuricataAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super(IPReputationSuricataAdmin, self).get_urls()
        my_urls = [url(r'^import_csv/$', self.import_csv, name="import_csv"), ]
        return my_urls + urls

    def import_csv(self, request):
        if request.method == 'GET':
            return render(request, 'import_csv.html')
        elif request.method == 'POST':
            if request.FILES['file']:
                try:
                    if not os.path.exists(settings.BASE_DIR + '/tmp/'):
                        os.mkdir(settings.BASE_DIR + '/tmp/')
                    with open(settings.BASE_DIR + '/tmp/imported.csv', 'wb+') as destination:
                        for chunk in request.FILES['file'].chunks():
                            destination.write(chunk)
                    IPReputationSuricata.import_from_csv(settings.BASE_DIR + '/tmp/imported.csv')
                except Exception as e:
                    messages.add_message(request, messages.ERROR, 'Error during the import : ' + str(e))
                    return render(request, 'import_csv.html')
                messages.add_message(request, messages.SUCCESS, 'CSV file imported successfully !')
                return render(request, 'import_csv.html')
            else:
                messages.add_message(request, messages.ERROR, 'No file submitted')
                return render(request, 'import_csv.html')


class CategoryReputationSuricataAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super(CategoryReputationSuricataAdmin, self).get_urls()
        my_urls = [url(r'^import_csv/$', self.import_csv, name="import_csv_cat_rep"), ]
        return my_urls + urls

    def import_csv(self, request):
        if request.method == 'GET':
            return render(request, 'import_csv.html')
        elif request.method == 'POST':
            if request.FILES['file']:
                try:
                    if not os.path.exists(settings.BASE_DIR + '/tmp/'):
                        os.mkdir(settings.BASE_DIR + '/tmp/')
                    with open(settings.BASE_DIR + '/tmp/imported.csv', 'wb+') as destination:
                        for chunk in request.FILES['file'].chunks():
                            destination.write(chunk)
                    CategoryReputationSuricata.import_from_csv(settings.BASE_DIR + '/tmp/imported.csv')
                except Exception as e:
                    messages.add_message(request, messages.ERROR, 'Error during the import : ' + str(e))
                    return render(request, 'import_csv.html')
                messages.add_message(request, messages.SUCCESS, 'CSV file imported successfully !')
                return render(request, 'import_csv.html')
            else:
                messages.add_message(request, messages.ERROR, 'No file submitted')
                return render(request, 'import_csv.html')


admin.site.register(Suricata, SuricataAdmin)
admin.site.register(SignatureSuricata, SignatureSuricataAdmin)
admin.site.register(ScriptSuricata, ScriptSuricataAdmin)
admin.site.register(RuleSetSuricata, RuleSetSuricataAdmin)
admin.site.register(ConfSuricata, ConfSuricataAdmin)
admin.site.register(SourceSuricata, SourceSuricataAdmin)
admin.site.register(BlackListSuricata, BlackListSuricataAdmin)
admin.site.register(IPReputationSuricata, IPReputationSuricataAdmin)
admin.site.register(CategoryReputationSuricata, CategoryReputationSuricataAdmin)
