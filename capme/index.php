<?php
include '.inc/functions.php';
// Argument counters
$s = 0;

// If any input validation fails, return error and exit immediately
function invalid($string) {
        echo $string;
        exit;
}

// Argument defaults
$sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = $elsa = $bro = $tcpflow = $pcap = '';

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
		$stime	= $_REQUEST['stime'];	$s++;
	}
}

// Validate user input - end time - etime
// must be greater than 5 years ago and less than 5 years from today
if (isset($_REQUEST['etime']))      { 
	if (!( ($_REQUEST['etime'] >= (time() - 5 * 365 * 24 * 60 * 60)) && ($_REQUEST['etime'] <= time() + 5 * 365 * 24 * 60 * 60) )) {
        	invalid("Invalid end time.");
	} else {
		$etime	= $_REQUEST['etime'];	$s++;
	}
}

// Validate user input - username and password
if ( isset($_REQUEST['user']) && isset($_REQUEST['password']) )      { 
	// Validate user input - username - user
	// Username must be alphanumeric
	if (!(ctype_alnum($_REQUEST['user']))) {
        	invalid("The user name or password is incorrect.");
	} else {
		$usr	= $_REQUEST['user'];	$s++;
	}

	// Validate user input - password
	$pwd    = $_REQUEST['password'];	$s++;
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
}

// If we see a filename parameter, we know the request came from Snorby
// and if so we can just query the event table since Snorby just has NIDS alerts
// If the referer contains "elsa-query", then it's most likely a Security Onion user 
// pivoting from ELSA, so we should query using ELSA.
// If all else fails, query sancp.
if (isset($_REQUEST['filename'])) { 
    $event = " checked";
} elseif ( isset($_SERVER['HTTP_REFERER']) && (strpos($_SERVER['HTTP_REFERER'],"elsa-query") !== false)) {
    $elsa  = " checked";
} else {
    $sancp = " checked";
}
$tcpflow = " checked";
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<title>
capME!
</title>
<style type="text/css" media="screen">@import ".css/capme.css";</style>
<script type="text/javascript" src=".js/jq.js"></script>
<script type="text/javascript" src=".js/capme.js"></script>
</head>
<body class=capme_body>

<table class=capme_div align=center cellpadding=0 cellspacing=0>
<tr>
<td colspan=2 class=capme_logo>
<h2><span class=capme_l1>cap</span><span class=capme_l2>ME!</span></h2>
</td>
</tr>
<form name=capme_form>

<tr>
<td class=capme_left>Src IP / Port:</td>
<td class=capme_right>
<input type=text maxlength=15 id=sip class=capme_selb value="<?php echo $sip;?>" /> /
<input type=text maxlength=5 id=spt class=capme_sels value="<?php echo $spt;?>" />
</td>
</tr>

<tr>
<td class=capme_left>Dst IP / Port:</td>
<td class=capme_right>
<input type=text maxlength=15 id=dip class=capme_selb value="<?php echo $dip;?>" /> /
<input type=text maxlength=5 id=dpt class=capme_sels value="<?php echo $dpt;?>" />
</td>
</tr>

<tr>
<td class=capme_left id=start_toggle>Start Time:</td>
<td class=capme_right><input type=text maxlength=19 id=stime class=capme_selb value="<?php echo $stime;?>" />
</td>
</tr>

<tr>
<td class=capme_left id=end_toggle>End Time:</td>
<td class=capme_right><input type=text maxlength=19 id=etime class=capme_selb value="<?php echo $etime;?>" />
</td>
</tr>

<tr>
<td class=capme_left>Username:</td>
<td class=capme_right><input type=text maxlength=32 id=username class=capme_selb value="<?php echo $usr;?>" />
</td>
</tr>

<tr>
<td class=capme_left>Password:</td>
<td class=capme_right><input type=password maxlength=32 id=password class=capme_selb value="<?php echo $pwd;?>" />
</td>
</tr>

<tr>
<td class=capme_left>Sid Source:</td>
<td class=capme_right>
<input type=radio name=sidsrc class=capme_rad value="sancp"<?php echo $sancp;?>>sancp
<input type=radio name=sidsrc class=capme_rad value="event"<?php echo $event;?>>event
<input type=radio name=sidsrc class=capme_rad value="elsa"<?php echo $elsa;?>>elsa
</td>
</tr>

<tr>
<td class=capme_left>Output:</td>
<td class=capme_right>
<input type=radio name=xscript class=capme_rad value="tcpflow"<?php echo $tcpflow;?>>tcpflow
<input type=radio name=xscript class=capme_rad value="bro"<?php echo $bro;?>>bro
<input type=radio name=xscript class=capme_rad value="pcap"<?php echo $pcap;?>>pcap
</td>
</tr>

<tr>
<td colspan=2 class=capme_msg_cont>
<span class=capme_msg></span>
</td>
</tr>

<tr>
<td colspan=2 class=capme_button>
<div class=capme_submit>submit</div>
<input id=formargs type=hidden value="<?php echo $s;?>" />
</td>
</tr>
</form>
</table>
</body>
</html>
