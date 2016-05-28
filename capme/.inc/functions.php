<?php

include_once 'config.php';
global $dbHost,$dbName,$dbUser,$dbPass;
$db = mysql_connect($dbHost,$dbUser,$dbPass) or die(mysql_error());
mysql_select_db($dbName,$db) or die();

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

// Argument defaults
$sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = $elsa = $bro = $tcpflow = $pcap = $maxtx = '';

// Argument counters
$s = 0;

// Validate user input - source IP address - sip
if (isset($_REQUEST['sip']))      {
        if (!filter_var($_REQUEST['sip'], FILTER_VALIDATE_IP)) {
                invalid("Invalid source IP.");
        } else {
                $sip    = $_REQUEST['sip'];      $s++;
        }
}

// Validate user input - source port - spt
// must be an integer between 0 and 65535
if (isset($_REQUEST['spt']))      {
        if (filter_var($_REQUEST['spt'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
                invalid("Invalid source port.");
        } else {
                $spt    = $_REQUEST['spt'];      $s++;
        }
}

// Validate user input - destination IP address - dip
if (isset($_REQUEST['dip']))      {
        if (!filter_var($_REQUEST['dip'], FILTER_VALIDATE_IP)) {
                invalid("Invalid destination IP.");
        } else {
                $dip    = $_REQUEST['dip'];      $s++;
        }
}

// Validate user input - destination port - dpt
// must be an integer between 0 and 65535
if (isset($_REQUEST['dpt']))      {
        if (filter_var($_REQUEST['dpt'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
                invalid("Invalid destination port.");
        } else {
                $dpt    = $_REQUEST['dpt'];      $s++;
        }
}

// Validate user input - start time - stime
// must be greater than 5 years ago and less than 5 years from today
if (isset($_REQUEST['stime']))      {
        if (!( ($_REQUEST['stime'] >= (time() - 5 * 365 * 24 * 60 * 60)) && ($_REQUEST['stime'] <= time() + 5 * 365 * 24 * 60 * 60) )) {
                invalid("Invalid start time.");
        } else {
                $stime  = $_REQUEST['stime'];   $s++;
        }
}

// Validate user input - end time - etime
// must be greater than 5 years ago and less than 5 years from today
if (isset($_REQUEST['etime']))      {
        if (!( ($_REQUEST['etime'] >= (time() - 5 * 365 * 24 * 60 * 60)) && ($_REQUEST['etime'] <= time() + 5 * 365 * 24 * 60 * 60) )) {
                invalid("Invalid end time.");
        } else {
                $etime  = $_REQUEST['etime'];   $s++;
        }
}

// Validate user input - max transcript bytes - maxtx
// must be an integer between 1000 and 100000000 (100MB)
if (isset($_REQUEST['maxtx']))      {
        if (filter_var($_REQUEST['maxtx'], FILTER_VALIDATE_INT, array("options" => array("min_range"=>1000, "max_range"=>100000000))) === false) {
                invalid("Invalid max transcript bytes.");
        } else {
                $maxtx    = $_REQUEST['maxtx'];      $s++;
        }
} else {
        // Default to Max Xscript Bytes of 500,000
        $maxtx = 500000;
}

// If all parameters passed validation, then create a $parameters string that can be appended to URL
$parameters = "sip=" . $sip . "&dip=" . $dip . "&spt=" . $spt . "&dpt=" . $dpt . "&stime=" . $stime . "&etime=" . $etime . "&maxtx=" . $maxtx;

?>

