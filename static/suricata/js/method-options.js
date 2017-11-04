django.jQuery(document).ready(function(){
    django.jQuery('#id_scheduled_enabled').change(function(){
        if(django.jQuery('#id_scheduled_enabled').is(':checked')){
            django.jQuery('.field-scheduled_crontab').fadeIn("slow");
            django.jQuery('.field-scheduled_deploy').fadeIn("slow");
        }else{
            django.jQuery('.field-scheduled_crontab').fadeOut("fast");
            django.jQuery('.field-scheduled_deploy').fadeOut("fast");
            django.jQuery('#id_scheduled_deploy').prop('checked', false);
        }
    });

    if(django.jQuery( "#id_method option:selected" ).text() == 'URL HTTP'){
        django.jQuery('.field-uri').fadeIn("slow");
        django.jQuery('.field-scheduled_enabled').fadeIn("slow");
        django.jQuery('.field-file').fadeOut("fast");
    }else if(django.jQuery( "#id_method option:selected" ).text() == 'Upload file'){
        django.jQuery('.field-file').fadeIn("slow");
        django.jQuery('.field-uri').fadeOut("fast");
        django.jQuery('.field-scheduled_enabled').fadeOut("fast");
        django.jQuery('.field-scheduled_crontab').fadeOut("fast");
        django.jQuery('.field-scheduled_deploy').fadeOut("fast");
        django.jQuery('#id_scheduled_deploy').prop('checked', false);
        django.jQuery('#id_scheduled_enabled').prop('checked', false);
    }else{
        django.jQuery('.field-file').fadeOut("fast");
        django.jQuery('.field-uri').fadeOut("fast");
        django.jQuery('.field-scheduled_enabled').fadeOut("fast");
        django.jQuery('.field-scheduled_crontab').fadeOut("fast");
        django.jQuery('.field-scheduled_deploy').fadeOut("fast");
        django.jQuery('#id_scheduled_deploy').prop('checked', false);
        django.jQuery('#id_scheduled_enabled').prop('checked', false);
    }
    django.jQuery('#id_method').change(function(){
        if(django.jQuery( "#id_method option:selected" ).text() == 'URL HTTP'){
            django.jQuery('.field-uri').fadeIn("slow");
            django.jQuery('.field-scheduled_enabled').fadeIn("slow");
            django.jQuery('.field-file').fadeOut("fast");
        }else if(django.jQuery( "#id_method option:selected" ).text() == 'Upload file'){
            django.jQuery('.field-file').fadeIn("slow");
            django.jQuery('.field-uri').fadeOut("fast");
            django.jQuery('.field-scheduled_enabled').fadeOut("fast");
            django.jQuery('.field-scheduled_crontab').fadeOut("fast");
            django.jQuery('.field-scheduled_deploy').fadeOut("fast");
            django.jQuery('#id_scheduled_deploy').prop('checked', false);
            django.jQuery('#id_scheduled_enabled').prop('checked', false);
        }else{
            django.jQuery('.field-file').fadeOut("fast");
            django.jQuery('.field-uri').fadeOut("fast");
            django.jQuery('.field-scheduled_enabled').fadeOut("fast");
            django.jQuery('.field-scheduled_crontab').fadeOut("fast");
            django.jQuery('.field-scheduled_deploy').fadeOut("fast");
            django.jQuery('#id_scheduled_deploy').prop('checked', false);
            django.jQuery('#id_scheduled_enabled').prop('checked', false);
        }
    });
});