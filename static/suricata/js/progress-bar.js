
django.jQuery(document).ready(function(){
    var width = 0;
    django.jQuery(".submit-row").before("<div id='myProgress'><div id='myBar'>0%</div></div>");
    var urlProtocol = window.location.protocol;
    var urlHostname = window.location.hostname;
    var urlPort = window.location.port;
    var url = urlProtocol + "//" + urlHostname + ":" + urlPort;

    setInterval(function(){
            django.jQuery.getJSON(url + "/suricata/get-progress/", function( json ) {
                if(json){
                    var width = json.progress;
                    var elem = document.getElementById("myBar");
                    if (typeof(elem) != "undefined" && elem != null) {
                        //console.log(width);
                        if (width <= 100) {
                            elem.style.width = width + "%";
                            elem.innerHTML = width + "%";
                        }
                    }
                }else{
                    console.log("getJson not succeed !");
                }
            });
        }, 3000);
});


