function actionRulesDeploymentCrontab() {
    if(django.jQuery("#id_scheduled_rules_deployment_enabled").is(":checked")){
        django.jQuery(".form-row.field-scheduled_rules_deployment_crontab").show();
    } else {
        django.jQuery(".form-row.field-scheduled_rules_deployment_crontab").hide();
    }
}
function actionScheduledCheckCrontab() {
    if(django.jQuery("#id_scheduled_check_enabled").is(":checked")){
        django.jQuery(".form-row.field-scheduled_check_crontab").show();
    } else {
        django.jQuery(".form-row.field-scheduled_check_crontab").hide();
    }
}
django.jQuery(document).ready(function(){
    actionRulesDeploymentCrontab();
    actionScheduledCheckCrontab();
    django.jQuery("#id_scheduled_rules_deployment_enabled").change(function(){
        actionRulesDeploymentCrontab();
    });
    django.jQuery("#id_scheduled_check_enabled").change(function(){
        actionScheduledCheckCrontab();
    });
});
