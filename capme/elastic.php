<?php

require_once '.inc/functions.php';
//require_once '.inc/session.php';
require_once '.inc/config.php';

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
<script type="text/javascript" src=".js/elastic.js"></script>
</head>
<body class=capme_body>
<div class=top>
<a href="/logout.html">Logout</a>
<br>

<table class=capme_div align=center cellpadding=0 cellspacing=0>
<tr>
<td colspan=2 class=capme_logo>
<h2><span class=capme_l1>cap</span><span class=capme_l2>ME!</span></h2>
</td>
</tr>
<form name=capme_form>

<tr>
<td class=capme_left>ID:</td>
<td class=capme_right>
<input type=text maxlength=20 id=esid class=capme_selb value="<?php echo $esid;?>" /> 
</td>
</tr>

<tr>
<td class=capme_left>Max Xscript Bytes:</td>
<td class=capme_right><input type=text maxlength=32 id=maxtx class=capme_selb value="<?php echo $maxtx;?>" />
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
