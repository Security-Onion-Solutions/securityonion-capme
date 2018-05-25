<?php

require_once 'config.php';
global $dbHost,$dbName,$dbUser,$dbPass;
$db = mysqli_connect($dbHost,$dbUser,$dbPass) or die(mysql_error());
mysqli_select_db($db,$dbName) or die();

function h2s($x) {
  $s='';
  foreach(explode("\n",trim(chunk_split($x,2))) as $h) $s.=chr(hexdec($h));
  return($s);
}

function s2h($x) {
  $s='';
  foreach(str_split($x) as $c) $s.=sprintf("%02X",ord($c));
  return($s);
}

// If any input validation fails, return error and exit immediately
function invalid($string) {
        echo $string;
        exit;
}

// Check for an active pcap_agent
$response = mysqli_query($db,"select * from sensor where agent_type='pcap' and active='Y';");
if (mysqli_num_rows($response) == 0) {
    invalid("Error: No active pcap_agent found.  Please ensure that pcap_agent and netsniff-ng are enabled and running.");
}

// Argument defaults
$esid = $sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = $elsa = $bro = $tcpflow = $pcap = $maxtx = $filename = $parameters = '';

// Argument counters
$s = 0;

// Check each potential search parameter to see if it exists and if it's valid.
// If valid, increment $s and add the search parameter to the $parameters string.

// Validate user input - id
if (isset($_REQUEST['esid']))      {
                $esid    = $_REQUEST['esid'];      $s++;
		$parameters .= "&esid=" . $esid;
}

// Validate user input - source IP address - sip
if (isset($_REQUEST['sip']))      {
        if (!filter_var($_REQUEST['sip'], FILTER_VALIDATE_IP)) {
                invalid("Invalid source IP.");
        } else {
                $sip    = $_REQUEST['sip'];      $s++;
		$parameters .= "&sip=" . $sip;
        }
}

// Validate user input - source port - spt
// must be an integer between 0 and 65535
if (isset($_REQUEST['spt']))      {
        if (filter_var($_REQUEST['spt'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
                invalid("Invalid source port.");
        } else {
                $spt    = $_REQUEST['spt'];      $s++;
		$parameters .= "&spt=" . $spt;
        }
}

// Validate user input - destination IP address - dip
if (isset($_REQUEST['dip']))      {
        if (!filter_var($_REQUEST['dip'], FILTER_VALIDATE_IP)) {
                invalid("Invalid destination IP.");
        } else {
                $dip    = $_REQUEST['dip'];      $s++;
		$parameters .= "&dip=" . $dip;
        }
}

// Validate user input - destination port - dpt
// must be an integer between 0 and 65535
if (isset($_REQUEST['dpt']))      {
        if (filter_var($_REQUEST['dpt'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
                invalid("Invalid destination port.");
        } else {
                $dpt    = $_REQUEST['dpt'];      $s++;
		$parameters .= "&dpt=" . $dpt;
        }
}

// Validate user input - start time - stime
// must be greater than 5 years ago and less than 5 years from today
$mintime=time() - 5 * 365 * 24 * 60 * 60;
$maxtime=time() + 5 * 365 * 24 * 60 * 60;
if (isset($_REQUEST['stime']))      {
        if (filter_var($_REQUEST['stime'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>$mintime, "max_range"=>$maxtime))) === false) {
                invalid("Invalid start time.");
        } else {
                $stime  = $_REQUEST['stime'];   $s++;
		$parameters .= "&stime=" . $stime;
        }
}

// Validate user input - end time - etime
// must be greater than 5 years ago and less than 5 years from today
if (isset($_REQUEST['etime']))      {
        if (filter_var($_REQUEST['etime'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>$mintime, "max_range"=>$maxtime))) === false) {
                invalid("Invalid end time.");
        } else {
                $etime  = $_REQUEST['etime'];   $s++;
		$parameters .= "&etime=" . $etime;
        }
}

// Validate user input - filename
// must be "squert"
if (isset($_REQUEST['filename']))      {
        if (!( ($_REQUEST['filename'] == "squert") )) {
                invalid("Invalid filename.");
        } else {
                $filename  = $_REQUEST['filename'];
		$parameters .= "&filename=" . $filename;
        }
}

// Validate user input - max transcript bytes - maxtx
// must be an integer between 1000 and 100000000 (100MB)
if (isset($_REQUEST['maxtx']))      {
        if (filter_var($_REQUEST['maxtx'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>1000, "max_range"=>100000000))) === false) {
                invalid("Invalid max transcript bytes.");
        } else {
                $maxtx    = $_REQUEST['maxtx'];
		$parameters .= "&maxtx=" . $maxtx;
        }
} else {
        // Default to Max Xscript Bytes of 500,000
        $maxtx = 500000;
}

?>

