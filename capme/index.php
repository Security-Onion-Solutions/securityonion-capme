<?php

include_once '.inc/functions.php';
include_once '.inc/session.php';
include_once '.inc/config.php';

// If we see a filename parameter, we know the request came from Snorby/Squert
// and if so we can just query the event table since they just have NIDS alerts.
// Otherwise, query elsa by default.
if (isset($_REQUEST['filename'])) { 
    $event = " checked";
} else {
    $elsa  = " checked";
}

// Default to the "auto" tcpflow/bro transcript option
$auto = " checked";

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
<div class=top>
<div id=t_usr class=user data-c_usr=<?php echo $sUser;?>>WELCOME&nbsp;&nbsp;<b><?php echo $sUser;?></b>&nbsp;&nbsp;|<span id=logout class=logout>LOGOUT</span></div>
<br>

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
<td class=capme_left>Start Time:</td>
<td class=capme_right><input type=text maxlength=19 id=stime class=capme_selb placeholder="YYYY-MM-DD HH:MM:SS" value="<?php echo $stime;?>" />
<input type=checkbox id=stime_checkbox /></td>
</tr>

<tr>
<td class=capme_left>End Time:</td>
<td class=capme_right><input type=text maxlength=19 id=etime class=capme_selb placeholder="YYYY-MM-DD HH:MM:SS" value="<?php echo $etime;?>" />
<input type=checkbox id=etime_checkbox /></td>
</tr>

<tr>
<td class=capme_left>Max Xscript Bytes:</td>
<td class=capme_right><input type=text maxlength=32 id=maxtx class=capme_selb value="<?php echo $maxtx;?>" />
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
<input type=radio name=xscript class=capme_rad value="auto"<?php echo $auto;?>>auto
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
