<?php

// Increase memory limit to allow for large streams
ini_set('memory_limit', '350M');

/*
// Terminate if this launches without a valid session
session_start();
if (!(isset($_SESSION['sLogin']) && $_SESSION['sLogin'] != '')) {
    header ("Location: session.php?id=0");
    exit();
}
*/

require_once 'functions.php';

// record starting time so we can see how long the callback takes
$time0 = microtime(true);

// check for data
if (!isset($_REQUEST['d'])) { 
    exit;
} else { 
    $d = $_REQUEST['d'];
}

// pull the individual values out
$d = explode("-", $d);

function cleanUp($string) {
    if (get_magic_quotes_gpc()) {
        $string = stripslashes($string);
    }
    $string = mysql_real_escape_string($string);
    return $string;
}

// If any input validation fails, return error and exit immediately
function invalidCallback($string) {
	$result = array("tx"  => "",
                  "dbg" => "",
                  "err" => "$string");

	$theJSON = json_encode($result);
	echo $theJSON;
	exit;
}

// cliscript requests the pcap/transcript from sguild
function cliscript($cmd, $pwd) {
    $descspec = array(
                 0 => array("pipe", "r"),
                 1 => array("pipe", "w"),
                 2 => array("pipe", "w")
    );
    $proc = proc_open($cmd, $descspec, $pipes);
    $debug = "Process execution failed";
    $_raw = "";
    if (is_resource($proc)) {
        fwrite($pipes[0], $pwd);
        fclose($pipes[0]);
        $_raw = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $debug = fgets($pipes[2]);
        fclose($pipes[2]);
    }
    return explode("\n", $_raw);
}

// Gets the appropriate Bro Conn record from ES and returns a JSON object
function elastic_command($elastic_host, $elastic_port, $type, $bro_query, $st_es, $et_es) {

$ch = curl_init();
$method = "GET";
$url = "$elastic_host/*:logstash-*/_search?";
$headers = ['Content-Type: application/json'];

$query = 
"{
  \"query\": {
    \"bool\": {
      \"must\": [
        {
          \"query_string\": {
            \"query\": \"event_type:$type AND $bro_query\",
            \"analyze_wildcard\": true
          }
        },
        {
          \"range\": {
            \"@timestamp\": {
              \"gte\": $st_es,
              \"lte\": $et_es,
              \"format\": \"epoch_millis\"
            }
          }
        }
      ]
    }
  }
}";
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_PORT, $elastic_port);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

$elastic_response = curl_exec($ch);
curl_close($ch);

// Try to decode the response as JSON.
$elastic_response_object = json_decode($elastic_response, true);

// Return object
return $elastic_response_object;
}

// Validate user input - Elasticsearch ID (numbers, letters, underscores, hyphens)
$esid	= h2s($d[0]);
$aValid = array('-', '_'); 
if(!ctype_alnum(str_replace($aValid, '', $esid))) { 
	invalidCallback("Invalid Elastic ID.");
} 

// Validate user input - maxtxbytes
// must be an integer between 1000 and 100000000
$maxtranscriptbytes	= h2s($d[1]);
if (filter_var($maxtranscriptbytes, FILTER_VALIDATE_INT, array("options" => array("min_range"=>1000, "max_range"=>100000000))) === false) {
	invalidCallback("Invalid maximum transcript bytes.");
}

// Validate user input - sidsrc
// elastic is the only valid value
$sidsrc = h2s($d[2]);
if ( $sidsrc != 'elastic' ) {
	invalidCallback("Invalid sidsrc.");
}

// Validate user input - xscript
// valid values are: auto, tcpflow, bro, and pcap
$xscript = h2s($d[3]);
if (!( $xscript == 'auto' || $xscript == 'tcpflow' || $xscript == 'bro' || $xscript == 'pcap' )) {
	invalidCallback("Invalid xscript.");
}

// Defaults
$err = 0;
$bro_query = $st = $et = $fmtd = $debug = $errMsg = $errMsgElastic = '';

/*
We need to determine 3 pieces of data:
sensor	- sensor name (for Security Onion this is HOSTNAME-INTERFACE)
st	- time of the event from the sensor's perspective (may be more accurate than what we were given), in Y-m-d H:i:s format
sid	- sensor id
*/

$sensor = "";
if ($sidsrc == "elastic") {

	/*
	If Elastic is enabled, then we need to:
	- construct the initial ES query and submit it
	- receive the response and parse out IP addresses, ports, and timestamp
	- construct a second ES query with those details searching for corresponding bro_conn entries
	- receive the response and parse out the sensor name (hostname-interface)
	NOTE: This requires that Elastic has access to Bro conn.log AND that the conn.log 
	has been extended to include the sensor name (HOSTNAME-INTERFACE).
	*/

	// Submit the ES query
	
	// Determine Elastic hostname and port

	// Define file from which to pull our values
	$es_array = file("/etc/nsm/securityonion.conf");
	
	// Define the strings we are looking for
	$host_string = "ELASTICSEARCH_HOST";
	$port_string = "ELASTICSEARCH_PORT";

	// Search for our strings
	foreach($es_array as $line) {
		// If we find a match, retrieve only the value and clean it up
		if(strpos($line, $host_string) !== false) {
			list(, $new_str) = explode("=", $line);
			$rm_whitespace = trim($new_str);
			$elastic_host = trim($rm_whitespace, '"');
		}
		if(strpos($line, $port_string) !== false) {
			list(, $new_str) = explode("=", $line);
			$rm_whitespace = trim($new_str);
			$elastic_port = trim($rm_whitespace, '"');
		}
	}

	$ch = curl_init();
	$method = "GET";
	$url = "$elastic_host/*:logstash-*/_search?";
	$headers = ['Content-Type: application/json'];

	$query = "{\"query\": {\"match\": {\"_id\": {\"query\": \"$esid\"}}}}";

	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_PORT, $elastic_port);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
	curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$elastic_response = curl_exec($ch);
	curl_close($ch);

	// Try to decode the response as JSON.
	$elastic_response_object = json_decode($elastic_response, true);

	// Check for common error conditions.
	if (json_last_error() !== JSON_ERROR_NONE) { 
		$errMsgElastic = "Couldn't decode JSON from initial ES query.";
	} elseif ( ! isset($elastic_response_object["hits"]["total"]) ) {
		$errMsgElastic = "Initial ES query didn't return a total number of hits.";
	} elseif ( $elastic_response_object["hits"]["total"] == "0") {
		$errMsgElastic = "Initial ES query couldn't find this ID.";
	/*} elseif ( $elastic_response_object["hits"]["total"] != "1") {
		$errMsgElastic = "Initial ES query returned multiple results.";*/
	} else { 

		// Looks good so far, so let's try to parse out the connection details.
		// Let's first check to see if it's a Bro log that has a CID in the uid field.
		if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["uid"]) ) {
			$uid = $elastic_response_object["hits"]["hits"][0]["_source"]["uid"];
			// Some bro_files logs are coming back with uid as an array
			// If that's the case here, then grab the first element in that array
			if (is_array($uid)) {
				$uid = $elastic_response_object["hits"]["hits"][0]["_source"]["uid"][0];
			}
			// A Bro CID should be alphanumeric and begin with the letter C
			if (ctype_alnum($uid)) {
				if (substr($uid,0,1)=="C") {
					$type = "bro_conn";
					$bro_query = $uid;
				}
			}
		// Let's check to see if it is a Bro X509 log
		} elseif (isset($elastic_response_object["hits"]["hits"][0]["_source"]["id"]) ) {
			$id = $elastic_response_object["hits"]["hits"][0]["_source"]["id"];
			if (ctype_alnum($id)) {
                                if (substr($id,0,1)=="F") {
                                        $type = "bro_files";
					$bro_query = $id;
                                }
                        }
		} elseif (isset($elastic_response_object["hits"]["hits"][0]["_source"]["fuid"]) ) {
			$fuid = $elastic_response_object["hits"]["hits"][0]["_source"]["fuid"];
                        if (ctype_alnum($fuid)) {
                                if (substr($fuid,0,1)=="F") {
                                        $type = "bro_files";
					$bro_query = $fuid;
                                }
                        }
		}

		// If this is a NIDS alert, try to find the rule that generated the alert
                if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["sid"]) ) {
			$rule_sid = $elastic_response_object["hits"]["hits"][0]["_source"]["sid"];
			if ( $rule_sid > 0 && $rule_sid < 9999999) {
				$rule_command = "grep -h sid:$rule_sid\; /etc/nsm/rules/*.rules |head -1";
				$rule = shell_exec($rule_command);
			}
		}

		// $es_doc is the actual elasticsearch document and it contains all fields relating to the message
		// might revisit this later and pull out more fields
		$es_doc = $elastic_response_object["hits"]["hits"][0]["_source"];
		// $message is the syslog message field (Bro log, NIDS alert, etc.)
		$message = $es_doc["message"];

		// If it wasn't a Bro log with CID, then let's manually parse out
		// source_ip, source_port, destination_ip, and destination_port
		if ( $bro_query == "" ) {
			// source_ip
			if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["source_ip"])) {
				$sip = $elastic_response_object["hits"]["hits"][0]["_source"]["source_ip"];
				if (!filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if (filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						$errMsgElastic = "Source IP is IPV6!  CapMe currently only supports IPV4.";
					} else {
						$errMsgElastic = "Invalid source IP.";
					}
				}
			} else {
				$errMsgElastic = "Missing source IP.";
			}

			// source_port
			if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["source_port"])) {
				$spt = $elastic_response_object["hits"]["hits"][0]["_source"]["source_port"];
				if (filter_var($spt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
				        $errMsgElastic = "Invalid source port.";
				}
			} else {
				$errMsgElastic = "Missing source port.";
			}

			// destination_ip
			if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["destination_ip"])) {
				$dip = $elastic_response_object["hits"]["hits"][0]["_source"]["destination_ip"];
				if (!filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if (filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                                                $errMsgElastic = "Destination IP is IPV6!  CapMe currently only supports IPV4.";
                                        } else {
                                                $errMsgElastic = "Invalid destination IP.";
                                        }
				}
			} else {
				$errMsgElastic = "Missing destination IP.";
			}

			// destination_port
			if (isset($elastic_response_object["hits"]["hits"][0]["_source"]["destination_port"])) {
				$dpt = $elastic_response_object["hits"]["hits"][0]["_source"]["destination_port"];
				if (filter_var($dpt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
				        $errMsgElastic = "Invalid destination port.";
				}
			} else {
				$errMsgElastic = "Missing destination port.";
			}

			// If all four of those fields looked OK, then build a query to send to Elasticsearch
			if ($errMsgElastic == "") {
				$type = "bro_conn";
				$bro_query = "$sip AND $spt AND $dip AND $dpt";
			}
		}
		$timestamp = $elastic_response_object["hits"]["hits"][0]["_source"]["@timestamp"];
		$timestamp_epoch = strtotime($timestamp);
		$mintime=time() - 50 * 365 * 24 * 60 * 60;
		$maxtime=time() + 5 * 365 * 24 * 60 * 60;
		if (filter_var($timestamp_epoch, FILTER_VALIDATE_INT, array("options" => array("min_range"=>$mintime, "max_range"=>$maxtime))) === false) {
		        $errMsgElastic = "Invalid start time.";
		}
		// Set a start time and end time for the search to allow for a little bit of clock drift amongst different log sources
		$st = $timestamp_epoch - 1800;
		$et = $timestamp_epoch + 1800;
		// ES expects timestamps with millisecond precision
		$st_es = $st * 1000;
		$et_es = $et * 1000;
	
		// If bro_files, we need to query Elastic and get the log
		if ($errMsgElastic == "" && $type == "bro_files") {
			$elastic_response_object = elastic_command($elastic_host, $elastic_port, $type, $bro_query, $st_es, $et_es);
			// Check for common error conditions.
			if (json_last_error() !== JSON_ERROR_NONE) { 
				$errMsgElastic = "Couldn't decode JSON from second ES query.";
			} elseif ( ! isset($elastic_response_object["hits"]["total"]) ) {
				$errMsgElastic = "Second ES query didn't return a total number of hits.";
			} elseif ( $elastic_response_object["hits"]["total"] == "0") {
				$errMsgElastic = "Second ES query couldn't find this ID.";
                        } else {
                                // If we received a bro_files record back, we need to grab the CID and get ready to query ES again
				if ( $elastic_response_object["hits"]["hits"][0]["_source"]["event_type"] == "bro_files" ) {
					$type = "bro_conn";
					$bro_query = $elastic_response_object["hits"]["hits"][0]["_source"]["uid"];
				}
			}
		}
		// Now we to send those parameters back to Elastic to see if we can find a matching bro_conn log
		if ($errMsgElastic == "") {
			$elastic_response_object = elastic_command($elastic_host, $elastic_port, $type, $bro_query, $st_es, $et_es);
			// Check for common error conditions.
			if (json_last_error() !== JSON_ERROR_NONE) {
				$errMsgElastic = "Couldn't decode JSON from second ES query.";
			} elseif ( ! isset($elastic_response_object["hits"]["total"]) ) {
				$errMsgElastic = "Second ES query didn't return a total number of hits.";
			} elseif ( $elastic_response_object["hits"]["total"] == "0") {
				$errMsgElastic = "Second ES query couldn't find this ID.";
			} else {
				// Check to see how many hits we got back from our query
				$num_records = $elastic_response_object["hits"]["total"];
				$delta_arr = array();

				// For each hit, we need to compare its timestamp to the timestamp of our original record (from which we pivoted).
				for ( $i =0 ; $i < $num_records; $i++) {
                                        $record_ts = $elastic_response_object["hits"]["hits"][$i]["_source"]["timestamp"];
                                        if ($timestamp_epoch > $record_ts){
                                                $delta = $timestamp_epoch - $record_ts;
					}
                                        elseif ($timestamp_epoch < $record_ts){
                                                $delta = $record_ts - $timestamp_epoch;
                                        }
					else {
						$delta = 0;
					}
                                        $delta_arr[$i] = $delta;
				}
				
				// Get the key for the hit with the smallest delta
				$min_val = min($delta_arr);
				$key = array_search($min_val, $delta_arr);
				
				if ( ! isset($elastic_response_object["hits"]["hits"][$key]["_source"]["protocol"]) ) {
					$errMsgElastic = "Second ES query didn't return a protocol field.";
				} elseif ( !in_array($elastic_response_object["hits"]["hits"][$key]["_source"]["protocol"], array('tcp','udp'), TRUE)) {
					$errMsgElastic = "CapMe currently only supports TCP and UDP.";
				}
				
				// In case we didn't parse out IP addresses and ports above, let's do that now
				// source_ip
				if (isset($elastic_response_object["hits"]["hits"][$key]["_source"]["source_ip"])) {
					$sip = $elastic_response_object["hits"]["hits"][$key]["_source"]["source_ip"];
					if (!filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						if (filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                                                        $errMsgElastic = "Source IP is IPV6!  CapMe currently only supports IPV4.";
                                                } else {
                                                        $errMsgElastic = "Invalid source IP.";
                                                }
					}
				} else {
					$errMsgElastic = "Missing source IP.";
				}

				// source_port
				if (isset($elastic_response_object["hits"]["hits"][$key]["_source"]["source_port"])) {
					$spt = $elastic_response_object["hits"]["hits"][$key]["_source"]["source_port"];
					if (filter_var($spt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
					        $errMsgElastic = "Invalid source port.";
					}
				} else {
					$errMsgElastic = "Missing source port.";
				}

				// destination_ip
				if (isset($elastic_response_object["hits"]["hits"][$key]["_source"]["destination_ip"])) {
					$dip = $elastic_response_object["hits"]["hits"][$key]["_source"]["destination_ip"];
					if (!filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						if (filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
							$errMsgElastic = "Destination IP is IPV6!  CapMe currently only supports IPV4.";
						} else {
							$errMsgElastic = "Invalid destination IP.";
						}
					}
				} else {
					$errMsgElastic = "Missing destination IP.";
				}
	
				// destination_port
				if (isset($elastic_response_object["hits"]["hits"][$key]["_source"]["destination_port"])) {
					$dpt = $elastic_response_object["hits"]["hits"][$key]["_source"]["destination_port"];
					if (filter_var($dpt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
					        $errMsgElastic = "Invalid destination port.";
					}
				} else {
					$errMsgElastic = "Missing destination port.";
				}

				$sensor = $elastic_response_object["hits"]["hits"][$key]["_source"]["sensor_name"];
				$timestamp = str_replace("T", " ", $timestamp);
				$st = substr($timestamp, 0, -5);
			} 
		}
	}
	// We now have 2 of the 3 pieces of data that we need.
	// Next, we'll use $sensor to look up the $sid in Sguil's sensor table.
}

if ($errMsgElastic != "") {
    $err = 1;
    $errMsg = $errMsgElastic;
} else {
	// Query the Sguil database.
	$query = "SELECT sid FROM sensor WHERE hostname='$sensor' AND agent_type='pcap' LIMIT 1";
	$response = mysqli_query($db,$query);
	if (!$response) {
	    $err = 1;
	    $errMsg = "Error: The query failed, please verify database connectivity";
	    $debug = $query;
	} else if (mysqli_num_rows($response) == 0) {
	    $err = 1;
	    $debug = $query;
	    $errMsg = "Failed to find a matching sid. " . $errMsgElastic;

	    // Check for possible error condition: no pcap_agent.
	    $response = mysql_query("select * from sensor where agent_type='pcap' and active='Y';");
	    if (mysql_num_rows($response) == 0) {
		    $errMsg = "Error: No pcap_agent found";
	    }
	} else {
	    $row = mysqli_fetch_assoc($response);
	    $sid    = $row["sid"];
	    $err = 0;
	}
}

if ($err == 1) {
    $result = array("tx"  => "0",
                    "dbg" => "$debug",
                    "err" => "$errMsg");
} else {

    // We passed all error checks, so let's get ready to request the transcript.

    // Apache is handling authentication and passing username and password through
    $usr     = $_SERVER['PHP_AUTH_USER'];
    $pwd     = $_SERVER['PHP_AUTH_PW'];

    $time1 = microtime(true);

    // The original cliscript.tcl assumes TCP (proto 6).
    $script = "cliscript.tcl";
    $proto=6;
    $cmdusr 	= escapeshellarg($usr);
    $cmdsensor 	= escapeshellarg($sensor);
    $cmdst	= escapeshellarg($st);
    $cmdsid 	= escapeshellarg($sid);
    $cmdsip 	= escapeshellarg($sip);
    $cmddip 	= escapeshellarg($dip);
    $cmdspt 	= escapeshellarg($spt);
    $cmddpt 	= escapeshellarg($dpt);
    $cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt";

    // If the request came from Elastic, check to see if the event is UDP.
    if ($elastic_response_object["hits"]["hits"][$key]["_source"]["protocol"] == "udp") {
	$proto=17;
    }

    // If the traffic is UDP or the user chose the Bro transcript, change to cliscriptbro.tcl.
    if ($xscript == "bro" || $proto == "17" ) {
	$script = "cliscriptbro.tcl";
    	$cmdproto 	= escapeshellarg($proto);
	$cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";
    }

    // Request the transcript.
    $raw = cliscript($cmd, $pwd);
    $time2 = microtime(true);

    // Check for errors or signs of gzip encoding.
    $foundgzip=0;
    foreach ($raw as $line) {
	if (preg_match("/^ERROR: Connection failed$/", $line)) {
		invalidCallback("ERROR: Connection to sguild failed!");
	}
	if (preg_match("/^DEBUG: $/", $line)) {
		invalidCallback("ERROR: No data was returned. Check pcap_agent service.");
	}
    	if ($xscript == "auto") {
		if (preg_match("/^DST: Content-Encoding: gzip/i", $line)) {
			$foundgzip=1;
			break;
		}
	}
    }
    $time3 = microtime(true);

    # Insert message so user can see the full message of the log they pivoted from
    $fmtd .= "<span class=txtext_hdr>Log entry:</span>";
    $fmtd .= "<span class=txtext_hdr>" . htmlspecialchars($message) . "</span>";

    # If NIDS alert, show rule that generated the alert
    if (isset($rule) && isset($rule_sid)) {
	$fmtd .= "<span class=txtext_hdr><br></span>";
	$fmtd .= "<span class=txtext_hdr>IDS rule:</span>";
	$fmtd .= "<span class=txtext_hdr>" . htmlspecialchars($rule) . "</span>";
    }

    $fmtd .= "<span class=txtext_hdr><br></span>";

    // If we found gzip encoding, then switch to Bro transcript.
    if ($foundgzip==1) {
    	$cmdproto 	= escapeshellarg($proto);
        $cmd = "../.scripts/cliscriptbro.tcl $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";
	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Detected gzip encoding.</b></span>";
	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Automatically switched to Bro transcript.</b></span>";
    }

    // Always request pcap/transcript a second time to ensure consistent DEBUG output.
    $raw = cliscript($cmd, $pwd);
    $time4 = microtime(true);

    // Initialize $transcriptbytes so we can count the number of bytes in the transcript.
    $transcriptbytes=0;

    // Check for errors and format as necessary.
    foreach ($raw as $line) {
	if (preg_match("/^ERROR: Connection failed$/", $line)) {
		invalidCallback("ERROR: Connection to sguild failed!");
	}
	if (preg_match("/^DEBUG: $/", $line)) {
		invalidCallback("ERROR: No data was returned. Check pcap_agent service.");
	}
    	// To handle large pcaps more gracefully, we only render the first $maxtranscriptbytes.
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


    // Default to sending transcript.
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

    // Find pcap file.
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

    // Add query and timer information to debug section.
    $debug = "<br>" . $debug;
    $debug .= "<span class=txtext_qry>QUERY: " . $query . "</span>";
    $time5 = microtime(true);
    $alltimes  = number_format(($time1 - $time0), 2) . " ";
    $alltimes .= number_format(($time2 - $time1), 2) . " ";
    $alltimes .= number_format(($time3 - $time2), 2) . " ";
    $alltimes .= number_format(($time4 - $time3), 2) . " ";
    $alltimes .= number_format(($time5 - $time4), 2);
    $debug .= "<span class=txtext_dbg>CAPME: Processed transcript in " . number_format(($time5 - $time0), 2) . " seconds: " . $alltimes . "</span><br>";

    // If we exceeded $maxtranscriptbytes, notify the user and recommend downloading the pcap.
    if ($transcriptbytes > $maxtranscriptbytes) {
	$debug .= "<span class=txtext_dbg>CAPME: <b>Only showing the first " . number_format($maxtranscriptbytes) . " bytes of transcript output.</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>This transcript has a total of " . number_format($transcriptbytes) . " bytes.</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>To see the entire stream, you can either:</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>- click the 'close' button, increase Max Xscript Bytes, and resubmit (may take a while)</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>OR</b></span><br>";
	$debug .= "<span class=txtext_dbg>CAPME: <b>- you can download the pcap using the link below.</b></span><br>";
    }

    // if we found the pcap, create a symlink in /var/www/so/capme/pcap/
    // and then create a hyperlink to that symlink.
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

    // Pack the output into an array.
    $result = array("tx"  => "$mytx",
                    "dbg" => "$debug",
                    "err" => "$errMsg");
}

// Encode the array and send it to the browser.
$theJSON = json_encode($result);
echo $theJSON;
?>

