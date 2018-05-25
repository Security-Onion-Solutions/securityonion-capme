$(document).ready(function(){

  // Logout
  $("#logout").click(function(event) {
    $.get("/logout.html", function(){location.reload()});
  });

    // Force form submit on enter
    document.onkeypress = function (e) {
        if(!e) e=window.event;
        key = e.keyCode ? e.keyCode : e.which;
        if(key == 13) {
            $(".capme_submit").click();
        }
    }

    var loaderImg = "<img id=loader class=loader src=\".css/load.gif\">";
    var err = 0;
    
    $(".capme_body").fadeIn('slow');

    //Check if browser is Chrome/Chromium-based.  If so, hide checkboxes and placeholders.
    var is_chrome = navigator.userAgent.toLowerCase().indexOf('chrome') > -1;
    if (!(is_chrome)){
       $("#stime_checkbox").hide();
       $("#etime_checkbox").hide();
       $("#stime").attr('placeholder', '');
       $("#etime").attr('placeholder', '');
    }

    // We will fire if we have enough arguments otherwise we wait for a submit
    numArgs = parseInt($("#formargs").val());

    if (numArgs >= 1) {
        reqCap("posted");
    }

    //Submit form
    $(".capme_submit").click(function() {

       frmArgs = $('input[value!=""]').length;
       if (frmArgs == 7) {
            reqCap("usefrm");
        } else {
            theMsg("Please complete all form fields");
        }
    });

    // Gather and validate our values then send off to callback
    function reqCap(caller) {

        if ($(".capme_submit").html() == "submit") {

            bOFF('.capme_submit');
            theMsg("Sending request..");

		// esid
		var esid = s2h(($("#esid").val()));

            // Transcript
            var xscript = s2h($('input:radio[name=xscript]:checked').val());

            // SID Source
            var sidsrc = s2h("elastic");

	    // Max TX
            var maxtx = s2h(chkMaxTX($("#maxtx").val()));

            // Continue if no errors
            if (err == 0) {
            
                var urArgs = "d=" + esid + "-" + maxtx + "-" + sidsrc + "-" + xscript;

                $(function(){
                    $.get(".inc/callback-elastic.php?" + urArgs, function(data){cbtx(data)});
                });
                        
                function cbtx(data){
                    eval("txRaw=" + data);
                    
                    txResult = txRaw.tx;
                    txDebug  = txRaw.dbg;
                    txError  = txRaw.err;

                    if (txResult != 0) {
                        var txt = '';
                        txt += "<table class=capme_result align=center width=940 cellpadding=0 cellspacing=0>";
                        txt += "<tr>";
                        txt += "<td class=capme_close>";
                        txt += "<span class=capme_close_button>close</span>";
                        txt += "</td></tr>";
                        txt += "<tr>";
                        txt += "<td class=capme_text>";
			if (txResult.indexOf("Dst Port:") >= 0) {
				txt += txResult;
			}
                        txt += txDebug;
                        txt += txError;
                        txt += "</td></tr></table>";
                        $(".capme_div").after(txt);
                        theMsg("Request was successful");
                        $(".capme_div").hide();
                        $(".capme_result").show();
                        $(".capme_msg").fadeOut('slow');
			if (txResult.indexOf("Dst Port:") == -1) {
				url = "/capme/pcap/" + txResult;
				window.open(url, "_self");
			}
                    } else {
                        theMsg(txError);
                    }
                    
                    bON('.capme_submit');
                }
            }
        }
    }

    $(document).on("click", ".capme_close_button", function() {
        $(".capme_result").remove();
        $(".capme_div").show();
        bON('.capme_submit');
    });

    function theMsg(msg) {
        $(".capme_msg").hide()
        $(".capme_msg").text(msg);
        $(".capme_msg").fadeIn('slow');
    }

    function bON(btn) {
        $(btn).attr('disabled',false);
        $(btn).css('cursor','pointer');
        $(btn).html('submit');    
    }

    function bOFF(btn) {
        $(btn).attr('disabled',true);
        $(btn).html(loaderImg);
    }

    // IP validation
    function chkIP(ip) {
        var valid = /^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
        if (!valid.test(ip)) {
            theMsg("Error: Bad IP");
            bON('.capme_submit');
            err = 1;
        } else {
            return ip;
        }
    }

    // maxtx validation
    function chkMaxTX(maxtx) {
        var valid = /^[0-9]+$\b/;
        if (!valid.test(maxtx) || maxtx < 1000 || maxtx > 100000000 || maxtx.charAt(0) == 0) {
            theMsg("Error: Bad MaxTX");
            bON('.capme_submit');
            err = 1;
        } else {
            return maxtx;
        } 
    }

    // port validation
    function chkPort(port) {
        var valid = /^[0-9]+$\b/;
        if (!valid.test(port) || port > 65535 || port.charAt(0) == 0) {
            theMsg("Error: Bad Port");
            bON('.capme_submit');
            err = 1;
        } else {
            return port;
        } 
    }

    // date validation
    function chkDate(stamp) {
        var n = 0;
        var chk1 = /^\d{10}$\b/;
        if (chk1.test(stamp)) {
            n++;
            var unixTime = parseInt(stamp)
        }
        if (n == 0) {
            theMsg("Error: Bad Timestamp");
            bON('.capme_submit');
            err = 1;
        } else {
            return unixTime;
        } 
    }

    function d2h(d) {
        return d.toString(16);
    }

    function h2d (h) {
        return parseInt(h, 16);
    }

    function s2h (tmp) {
        var str = '', i = 0, tmp_len = tmp.length, c;

        for (; i < tmp_len; i += 1) {
            c = tmp.charCodeAt(i);
            str += d2h(c);
        }
        return str;
    }

    function h2s (tmp) {
        var arr = tmp.split(' '), str = '', i = 0, arr_len = arr.length, c;
        for (; i < arr_len; i += 1) {
            c = String.fromCharCode( h2d( arr[i] ) );
            str += c;
        }
        return str;
    }
});
