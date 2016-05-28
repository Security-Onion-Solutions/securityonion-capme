$(document).ready(function(){

  // Logout
  $("#logout").click(function(event) {
    $.get("logout.php?id=0", function(){location.reload()});
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

    //Set tooltip for checkboxes
    $("#stime_checkbox").attr("title", "Convert to date/time format");
    $("#etime_checkbox").attr("title", "Convert to date/time format");

    //Set checkbox value based on user input
    //When we lose focus of start time input, set checkbox value
    $("#stime").blur(function() {

    var stimeBlur = $("#stime").val();
    var stimeFmt = "-";

        if (stimeBlur.indexOf(stimeFmt) >=0){
	    $("#stime_checkbox").prop('checked', true);
            $("#stime_checkbox").attr("title", "Convert to epoch format");
        }
	else{
	    $("#stime_checkbox").prop('checked', false);
            $("#stime_checkbox").attr("title", "Convert to date/time format");
	}
    });

    //When we lose focus of end time input, set checkbox value
    $("#etime").blur(function() {

    var etimeBlur = $("#etime").val();
    var etimeFmt = "-";

	if (etimeBlur.indexOf(etimeFmt) >=0){
            $("#etime_checkbox").prop('checked', true);
            $("#etime_checkbox").attr("title", "Convert to epoch format");
        }
	else{
	    $("#etime_checkbox").prop('checked', false);
            $("#etime_checkbox").attr("title", "Convert to date/time format");
	}
    });

    //Create toggle for start time checkbox
    $("#stime_checkbox").click(function() {

	if ($("#stime_checkbox").prop("checked")){
            //Get value of start time from input and convert it to human-readable date/time
            var stimeChkd = $("#stime").val();
            var stime_to_ISO = new Date(stimeChkd*1000).toISOString().slice(0,-5).replace('T',' ');

            $("#stime").val(stime_to_ISO);
	    $("#stime_checkbox").attr("title", "Convert to epoch format");
	}
	else{
            //Get start time and convert it to epoch timestamp
            var stimeUnChkd = $("#stime").val();
            var startDate = new Date(stimeUnChkd);
            var start_tz_offset = (startDate.getTimezoneOffset());
            var stimeConverted = startDate.setTime( startDate.getTime()/1000-(start_tz_offset*60) );

            $("#stime").val(stimeConverted);
            $("#stime_checkbox").attr("title", "Convert to date/time format");
        }
    });

    //Create toggle for end time checkbox
    $("#etime_checkbox").click(function() {

	if ($("#etime_checkbox").prop("checked")){
	    //Get value of start time from input and convert it to human-readable date/time
            var etimeChkd = $("#etime").val();
            var etime_to_ISO = new Date(etimeChkd*1000).toISOString().slice(0,-5).replace('T',' ');

            $("#etime").val(etime_to_ISO);
            $("#etime_checkbox").attr("title", "Convert to epoch format");
        }
	else{
	    //Get start time and convert it to epoch timestamp
            var etimeUnChkd = $("#etime").val();
            var endDate = new Date(etimeUnChkd);
            var end_tz_offset = (endDate.getTimezoneOffset());
            var etimeConverted = endDate.setTime( endDate.getTime()/1000-(end_tz_offset*60) );

	    $("#etime").val(etimeConverted);
            $("#etime_checkbox").attr("title", "Convert to date/time format");
        }
    });

    // We will fire if we have enough arguments otherwise we wait for a submit
    numArgs = parseInt($("#formargs").val());

    if (numArgs >= 6) {
        reqCap("posted");
    }

    //Submit form
    $(".capme_submit").click(function() {

	$("#stime_checkbox").prop('checked', false);
        $("#etime_checkbox").prop('checked', false);

        //Get start time value
        var stime = $("#stime").val();
        var stimeSyntax = ":";

        //If start time value contains stimeSyntax, then convert date to epoch timestamp.
        if (stime.indexOf(stimeSyntax) >=0) {
	    var startDate = new Date(stime);
            var start_tz_offset = (startDate.getTimezoneOffset());
            var stimeConverted = startDate.setTime( startDate.getTime()/1000-(start_tz_offset*60) );

            $("#stime").val(stimeConverted);
        }

        //Get end time value
        var etime = $("#etime").val();
        var etimeSyntax = ":";

        //If end time value contains etimeSyntax, then convert date to epoch timestamp.
        if (etime.indexOf(etimeSyntax) >=0) {
	    var endDate = new Date(etime);
            var end_tz_offset = (endDate.getTimezoneOffset());
            var etimeConverted = endDate.setTime( endDate.getTime()/1000-(end_tz_offset*60) );

	    $("#etime").val(etimeConverted);
	}

       frmArgs = $('input[value!=""]').length;
       if (frmArgs == 17) {
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

            // Transcript
            var xscript = s2h($('input:radio[name=xscript]:checked').val());

            // SID Source
            var sidsrc = s2h($('input:radio[name=sidsrc]:checked').val());

            // IPs and ports
            var sip = s2h(chkIP($("#sip").val()));
            var spt = s2h(chkPort($("#spt").val()));
            var dip = s2h(chkIP($("#dip").val()));
            var dpt = s2h(chkPort($("#dpt").val()));

	    // Max TX
            var maxtx = s2h(chkMaxTX($("#maxtx").val()));

            // Timestamps
            if ($("#stime").val().length > 0) {
                var st = chkDate($("#stime").val());
                if (err == 0) {
                    $("#stime").val(st);
                }
            }

            if ($("#etime").val().length > 0) {
                var et = chkDate($("#etime").val());
                if (err == 0) {
                    $("#etime").val(et);
                }
            } 

            if (st > et) {
                err = 1;
                theMsg("Error: Start Time is greater than End Time!");
                bON('.capme_submit');
            }
 
            // Continue if no errors
            if (err == 0) {
            
                var urArgs = "d=" + sip + "-" + spt + "-" + dip + "-" + dpt + "-" + st + "-" + et + "-" + maxtx + "-" + sidsrc + "-" + xscript;

                $(function(){
                    $.get(".inc/callback.php?" + urArgs, function(data){cbtx(data)});
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
                        txt += "<span class=capme_close>close</span>";
                        txt += "</td></tr>";
                        txt += "<tr>";
                        txt += "<td class=capme_text>";
			if (txResult.indexOf("OS Fingerprint:") >= 0) {
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
			if (txResult.indexOf("OS Fingerprint:") == -1) {
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

    $(document).on("click", ".capme_close", function() {
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
