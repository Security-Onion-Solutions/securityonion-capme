<?php

include_once 'functions.php';
$time0 = microtime(true);

if (!isset($_REQUEST['d'])) { 
    exit;
} else { 
    $d = $_REQUEST['d'];
}

$d = explode("-", $d);

function cleanUp($string) {
    if (get_magic_quotes_gpc()) {
        $string = stripslashes($string);
    }
    $string = mysql_real_escape_string($string);
    return $string;
}

// If any input validation fails, return error and exit immediately
function invalid($string) {
	$result = array("tx"  => "",
                  "dbg" => "",
                  "err" => "$string");

	$theJSON = json_encode($result);
	echo $theJSON;
	exit;
}

// Validate user input - source IP address
$sip	= h2s($d[0]);
if (!filter_var($sip, FILTER_VALIDATE_IP)) {
	invalid("Invalid source IP.");
}

// Validate user input - source port
// must be an integer between 0 and 65535
$spt	= h2s($d[1]);
if (filter_var($spt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
	invalid("Invalid source port.");
}

// Validate user input - destination IP address
$dip	= h2s($d[2]);
if (!filter_var($dip, FILTER_VALIDATE_IP)) {
	invalid("Invalid destination IP.");
}

// Validate user input - destination port
// must be an integer between 0 and 65535
$dpt	= h2s($d[3]);
if (filter_var($dpt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
	invalid("Invalid destination port.");
}

// Validate user input - start time
// must be greater than 5 years ago and less than 5 years from today
$st_unix= $d[4];
if (!( ($st_unix >= (time() - 5 * 365 * 24 * 60 * 60)) && ($st_unix <= time() + 5 * 365 * 24 * 60 * 60) )) {
	invalid("Invalid start time.");
}

// Validate user input - end time
// must be greater than 5 years ago and less than 5 years from today
$et_unix= $d[5];
if (!( ($et_unix >= (time() - 5 * 365 * 24 * 60 * 60)) && ($et_unix <= time() + 5 * 365 * 24 * 60 * 60) )) {
	invalid("Invalid end time.");
}

// Validate user input - username
// Username must be alphanumeric
$usr	= cleanUp(h2s($d[6]));
if (!(ctype_alnum($usr))) {
	invalid("The user name or password is incorrect.");
}

// Validate user input - password
$pwd	= h2s($d[7]);
$username = $password = $err = '';

$db = mysql_connect($dbHost,$dbUser,$dbPass);
$link = mysql_select_db($dbName, $db);
if ($link) {
        $query = "SELECT * FROM user_info WHERE username = '$usr'";
        $result = mysql_query($query);
        $numRows = mysql_num_rows($result);

        if ($numRows > 0) {
            while ($row = mysql_fetch_row($result)) {
                $userHash       = $row[3];
            }
            // The first 2 chars are the salt     
            $theSalt = substr($userHash, 0,2);

            // The remainder is the hash
            $theHash = substr($userHash, 2);

            // Now we hash the users input                 
            $testHash = sha1($pwd . $theSalt);

            // Does it match? If not, exit.
            if ($testHash !== $theHash) {
                invalid("The user name or password is incorrect.");
            }
        } else {
            invalid("The user name or password is incorrect.");
        }
} else {
        invalid("Connection Failed.");
}

// Validate user input - sidsrc
// valid values are: sancp, event, and elsa
$sidsrc = h2s($d[8]);
if (!( $sidsrc == 'sancp' || $sidsrc == 'event' || $sidsrc == 'elsa' )) {
	invalid("Invalid sidsrc.");
}

// Validate user input - xscript
// valid values are: auto, tcpflow, bro, and pcap
$xscript = h2s($d[9]);
if (!( $xscript == 'auto' || $xscript == 'tcpflow' || $xscript == 'bro' || $xscript == 'pcap' )) {
	invalid("Invalid xscript.");
}

// Format timestamps
$st = date("Y-m-d H:i:s", $st_unix);
$et = date("Y-m-d H:i:s", $et_unix);

// Fix Snorby timezone
if ($sidsrc == "event") {

	// load the user's timezone setting
	include 'timezone.php';

	// convert the start time from the user's timezone to UTC/GMT
	$st = date_create($st, timezone_open($timezone));
	date_timezone_set($st, timezone_open('Etc/GMT'));
	$st = date_format($st, 'Y-m-d H:i:s');

	// convert the end time from the user's timezone to UTC/GMT
	$et = date_create($et, timezone_open($timezone));
	date_timezone_set($et, timezone_open('Etc/GMT'));
	$et = date_format($et, 'Y-m-d H:i:s');
}

// Defaults
$err = 0;
$fmtd = $debug = $errMsg = $errMsgELSA = '';

/*
We need to determine 3 pieces of data:
sensor	- sensor name (for Security Onion this is HOSTNAME-INTERFACE)
st	- time of the event from the sensor's perspective (may be more accurate than what we were given), in Y-m-d H:i:s format
sid	- sensor id
*/

$sensor = "";
if ($sidsrc == "elsa") {

	/*
	If ELSA is enabled, then we need to:
	- construct the ELSA query and submit it via cli.sh
	- receive the response and parse out the sensor name (HOSTNAME-INTERFACE) and timestamp
	- convert the timestamp to the proper format
	NOTE: This requires that ELSA has access to Bro conn.log AND that the conn.log 
	has been extended to include the sensor name (HOSTNAME-INTERFACE).
	*/

	// Construct the ELSA query
	$elsa_query = "class=bro_conn start:'$st_unix' end:'$et_unix' +$sip +$spt +$dip +$dpt limit:1 timeout:0";

	// Submit the ELSA query via cli.sh
	$elsa_command = "sh /opt/elsa/contrib/securityonion/contrib/cli.sh '$elsa_query' ";
	$elsa_response = shell_exec($elsa_command);

	// Try to decode the response as JSON
	$elsa_response_object = json_decode($elsa_response, true);

	// Check for common error conditions
	if (json_last_error() !== JSON_ERROR_NONE) { 
		$errMsgELSA = "Couldn't decode JSON from ELSA API.";
	} elseif ( $elsa_response_object["recordsReturned"] == "0") {
		$errMsgELSA = "ELSA couldn't find this session in Bro's conn.log.";
	} elseif ( $elsa_response_object["recordsReturned"] != "1") {
		$errMsgELSA = "Invalid results from ELSA API.";
	} elseif ( $elsa_response_object["results"][0]["_fields"][7]["value"] != "TCP") {
		$errMsgELSA = "Not a TCP stream.";
	} else { 

		// Looks good so far, so let's try to parse out the sensor name and timestamp

		// Pull the raw log out of the response object
		$elsa_response_data_raw_log = $elsa_response_object["results"][0]["msg"];

		// Explode the pipe-delimited raw log and pull out the original timestamp and sensor name
		$pieces = explode("|", $elsa_response_data_raw_log);
		$elsa_response_data_raw_log_timestamp = $pieces[0];
		$elsa_response_data_raw_log_sensor = end($pieces);

		// Convert timestamp to proper format
		$st = date("Y-m-d H:i:s", $elsa_response_data_raw_log_timestamp);

		// Clean up $sensor
		$sensor = rtrim($elsa_response_data_raw_log_sensor);

	} 

	// We now have 2 of the 3 pieces of data that we need.
	// Next, we'll use $sensor to look up the $sid in Sguil's sensor table.
}

/*
Query the Sguil database
If the user selected sancp or event, query those tables and get
the 3 pieces of data that we need.
*/
$queries = array(
                 "elsa" => "SELECT sid FROM sensor WHERE hostname='$sensor' AND agent_type='pcap' LIMIT 1",

                 "sancp" => "SELECT sancp.start_time, s2.sid, s2.hostname
                             FROM sancp
                             LEFT JOIN sensor ON sancp.sid = sensor.sid
                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.net_name
                             WHERE sancp.start_time >=  '$st' AND sancp.end_time <= '$et'
                             AND ((src_ip = INET_ATON('$sip') AND src_port = $spt AND dst_ip = INET_ATON('$dip') AND dst_port = $dpt) OR (src_ip = INET_ATON('$dip') AND src_port = $dpt AND dst_ip = INET_ATON('$sip') AND dst_port = $spt))
                             AND s2.agent_type = 'pcap' LIMIT 1",

                 "event" => "SELECT event.timestamp AS start_time, s2.sid, s2.hostname
                             FROM event
                             LEFT JOIN sensor ON event.sid = sensor.sid
                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.net_name
                             WHERE timestamp BETWEEN '$st' AND '$et'
                             AND ((src_ip = INET_ATON('$sip') AND src_port = $spt AND dst_ip = INET_ATON('$dip') AND dst_port = $dpt) OR (src_ip = INET_ATON('$dip') AND src_port = $dpt AND dst_ip = INET_ATON('$sip') AND dst_port = $spt))
                             AND s2.agent_type = 'pcap' LIMIT 1");

$response = mysql_query($queries[$sidsrc]);

if (!$response) {
    $err = 1;
    $errMsg = "Error: The query failed, please verify database connectivity";
    $debug = $queries[$sidsrc];
} else if (mysql_num_rows($response) == 0) {
    $err = 1;
    $debug = $queries[$sidsrc];
    $errMsg = "Failed to find a matching sid. " . $errMsgELSA;
    $response = mysql_query("select * from sensor where agent_type='pcap' and active='Y';");
    if (mysql_num_rows($response) == 0) {
    $errMsg = "Error: No pcap_agent found";
    }
} else {
    $row = mysql_fetch_assoc($response);
    // If using ELSA, we already set $st and $sensor above so don't overwrite that here
    if ($sidsrc != "elsa") {
        $st = $row["start_time"];
    	$sensor = $row["hostname"]; 
    }
    $sid    = $row["sid"];
}

if ($err == 1) {
    $result = array("tx"  => "0",
                    "dbg" => "$debug",
                    "err" => "$errMsg");

} else {

    // We have all the data we need, so pass the parameters to the correct cliscript
    $time1 = microtime(true);
    $script = "cliscript.tcl";
    if ($xscript == "bro") {
	$script = "cliscriptbro.tcl";
    }
    $cmd = "$script -sid $sid -sensor '$sensor' -timestamp '$st' -u '$usr' -pw '$pwd' -sip $sip -spt $spt -dip $dip -dpt $dpt";

    // Request pcap/transcript.
    exec("../.scripts/$cmd",$raw);
    $time2 = microtime(true);

    // If user requested the auto tcpflow/bro transcript, check output
    // for signs of gzip encoding.  If found, resubmit using Bro.
    $foundgzip=0;
    if ($xscript == "auto") {
	foreach ($raw as $line) {
		if (preg_match("/^DST: Content-Encoding: gzip/i", $line)) {
			$foundgzip=1;
			break;
		}
	}
    }
    $time3 = microtime(true);

    // Initialize $raw before requesting pcap again.
    $raw="";

    // If we found gzip encoding, then request Bro transcript.
    if ($foundgzip==1) {
	$script = "cliscriptbro.tcl";
	$cmd = "$script -sid $sid -sensor '$sensor' -timestamp '$st' -u '$usr' -pw '$pwd' -sip $sip -spt $spt -dip $dip -dpt $dpt";
	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Detected gzip encoding.</b></span>";
	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Automatically switched to Bro transcript.</b></span>";
    }

    // Request pcap/transcript.
    // Always request pcap a second time to ensure consistent DEBUG output.
    exec("../.scripts/$cmd",$raw);
    $time4 = microtime(true);

    // To handle large pcaps more gracefully, we only render the first $maxtranscriptbytes.
    $transcriptbytes=0;
    $maxtranscriptbytes=500000;

    // Iterate through all lines and format as necessary
    foreach ($raw as $line) {
	$transcriptbytes += strlen($line);
	if ($transcriptbytes <= $maxtranscriptbytes) {
	        $line = htmlspecialchars($line);
        	$type = substr($line, 0,3);
	        switch ($type) {
        	    case "DEB": $debug .= preg_replace('/^DEBUG:.*$/', "<span class=txtext_dbg>$0</span>", $line) . "<br>"; $line = ''; break;
	            case "HDR": $line = preg_replace('/(^HDR:)(.*$)/', "<span class=txtext_hdr>$2</span>", $line); break;
        	    case "DST": $line = preg_replace('/^DST:.*$/', "<span class=txtext_dst>$0</span>", $line); break;
	            case "SRC": $line = preg_replace('/^SRC:.*$/', "<span class=txtext_src>$0</span>", $line); break;
        	}

        	if (strlen($line) > 0) {
	            $fmtd  .= $line . "<br>";
		}
        }
    }

    // default to sending transcript
    $mytx = $fmtd;

    /*

    On the first pcap request, $debug would have looked like this (although it may have been split up and mislabeled):

    DEBUG: Raw data request sent to doug-virtual-machine-eth1.
    DEBUG: Making a list of local log files.
    DEBUG: Looking in /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08.
    DEBUG: Making a list of local log files in /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08.
    DEBUG: Available log files:
    DEBUG: 1383910121
    DEBUG: Creating unique data file: /usr/sbin/tcpdump -r /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08/snort.log.1383910121 -w /tmp/10.0.2.15:1066_192.168.56.50:80-6.raw (ip and host 10.0.2.15 and host 192.168.56.50 and port 1066 and port 80 and proto 6) or (vlan and host 10.0.2.15 and host 192.168.56.50 and port 1066 and port 80 and proto 6)
    DEBUG: Receiving raw file from sensor.

    Since we now request the pcap twice, $debug SHOULD look like this:

    DEBUG: Using archived data: /nsm/server_data/securityonion/archive/2013-11-08/doug-virtual-machine-eth1/10.0.2.15:1066_192.168.56.50:80-6.raw

    */

    // Find pcap
    $archive = '/DEBUG: Using archived data.*/';
    $unique = '/DEBUG: Creating unique data file.*/';
    $found_pcap = 0;
    if (preg_match($archive, $debug, $matches)) {
    	$found_pcap = 1;
	$match = str_replace("</span><br>", "", $matches[0]);
    	$pieces = explode(" ", $match);
    	$full_filename = $pieces[4];
    	$pieces = explode("/", $full_filename);
    	$filename = $pieces[7];
    } else if (preg_match($unique, $debug, $matches)) {
    	$found_pcap = 1;
	$match = str_replace("</span><br>", "", $matches[0]);
    	$pieces = explode(" ", $match);
    	$sensor_filename = $pieces[7];
    	$server_filename = $pieces[9];
    	$pieces = explode("/", $sensor_filename);
    	$sensorname = $pieces[3];
    	$dailylog = $pieces[5];
    	$pieces = explode("/", $server_filename);
    	$filename = $pieces[2];
    	$full_filename = "/nsm/server_data/securityonion/archive/$dailylog/$sensorname/$filename";
    }	

    // Add query and timer information to debug
    $debug = "<br>" . $debug;
    $debug .= "<span class=txtext_qry>QUERY: " . $queries[$sidsrc] . "</span>";
    $time5 = microtime(true);
    $debug .= "<span class=txtext_dbg>CAPME: Processed transcript in " . number_format(($time5 - $time0), 2) . " seconds.</span><br>";
    // Detailed timers for each part of the process
    // $fmtd .= "CAPME: ($time1 - $time0) . " " . ($time2 - $time1) . " " . ($time3 - $time2) . " " . ($time4 - $time3) . " " . ($time5 - $time4) . "<br>";

    // If we exceeded $maxtranscriptbytes, notify the user and recommend downloading the pcap.
    if ($transcriptbytes > $maxtranscriptbytes) {
	$debug .= "<span class=txtext_dbg>CAPME: <b>Only showing the first " . number_format($maxtranscriptbytes) . " bytes of transcript output.</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>This transcript has a total of " . number_format($transcriptbytes) . " bytes.</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>To see the entire stream, you can download the pcap using the link below.</b></span><br>";
    }

    // if we found the pcap, create a symlink in /var/www/so/capme/pcap/
    // and then create a hyperlink to that symlink
    if ($found_pcap == 1) {
      	$tmpstring = rand();
	$filename_random = str_replace(".raw", "", "$filename-$tmpstring");
	$filename_download = "$filename_random.pcap";
	$link = "/var/www/so/capme/pcap/$filename_download";
	symlink($full_filename, $link);
	$debug .= "<br><br><a href=\"/capme/pcap/$filename_download\">$filename_download</a>";
	$mytx = "<a href=\"/capme/pcap/$filename_download\">$filename_download</a><br><br>$mytx";
	// if the user requested pcap, send the pcap instead of the transcript
	if ($xscript == "pcap") {
	    	$mytx = $filename_download;
	}
    } else {
        $debug .= "<br>WARNING: Unable to find pcap.";
    }


    $result = array("tx"  => "$mytx",
                    "dbg" => "$debug",
                    "err" => "$errMsg");
}

$theJSON = json_encode($result);
echo $theJSON;
?>

