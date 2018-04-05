django.jQuery(document).ready(function(){
    django.jQuery("select[name='ruleset']").fadeOut("fast");
    django.jQuery("label:contains('Ruleset ')").fadeOut("fast");
    django.jQuery(".select-across").after("&nbsp;&nbsp;  ");

    django.jQuery("select[name='action']").change(function(){
        if(django.jQuery("select[name='action'] option:selected").text() === "Add ruleset"){
            django.jQuery("label:contains('Ruleset ')").fadeIn("slow");
            django.jQuery("select[name='ruleset']").fadeIn("slow");
        }else if(django.jQuery("select[name='action'] option:selected").text() === "Remove ruleset"){
            django.jQuery("label:contains('Ruleset ')").fadeIn("slow");
            django.jQuery("select[name='ruleset']").fadeIn("slow");
        }else{
            django.jQuery("label:contains('Ruleset ')").fadeOut("fast");
            django.jQuery("select[name='ruleset']").fadeOut("fast");

        }
    });
});
