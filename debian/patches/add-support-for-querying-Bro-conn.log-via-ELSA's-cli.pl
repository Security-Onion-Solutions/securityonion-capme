Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-capme (20121213-0ubuntu0securityonion3) precise; urgency=low
 .
   * add support for querying Bro conn.log via ELSA's cli.pl
Author: Doug Burks <doug.burks@gmail.com>

---
The information above should follow the Patch Tagging Guidelines, please
checkout http://dep.debian.net/deps/dep3/ to learn about the format. Here
are templates for supplementary fields that you might want to add:

Origin: <vendor|upstream|other>, <url of original patch>
Bug: <url in upstream bugtracker>
Bug-Debian: http://bugs.debian.org/<bugnumber>
Bug-Ubuntu: https://launchpad.net/bugs/<bugnumber>
Forwarded: <no|not-needed|url proving that it has been forwarded>
Reviewed-By: <name and email of someone who approved the patch>
Last-Update: <YYYY-MM-DD>

--- securityonion-capme-20121213.orig/capme/index.php
+++ securityonion-capme-20121213/capme/index.php
@@ -4,7 +4,7 @@ include '.inc/functions.php';
 $s = 0;
 
 // Argument defaults
-$sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = '';
+$sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = $elsa = '';
 // Grab any arguments provided in URI
 if (isset($_REQUEST['sip']))      { $sip    = $_REQUEST['sip'];      $s++; }
 if (isset($_REQUEST['spt']))      { $spt    = $_REQUEST['spt'];      $s++; }
@@ -14,8 +14,15 @@ if (isset($_REQUEST['stime']))    { $sti
 if (isset($_REQUEST['etime']))    { $etime  = $_REQUEST['etime'];    $s++; }
 if (isset($_REQUEST['user']))     { $usr    = $_REQUEST['user'];     $s++; }
 if (isset($_REQUEST['password'])) { $pwd    = $_REQUEST['password']; $s++; }
+// If we see a filename parameter, we know the request came from Snorby
+// and if so we can just query the event table since Snorby just has NIDS alerts
+// If the referer contains ":3154", then it's most likely a Security Onion user 
+// pivoting from ELSA, so we should query using ELSA.
+// If all else fails, query sancp.
 if (isset($_REQUEST['filename'])) { 
     $event = " checked";
+} elseif (strpos($_SERVER['HTTP_REFERER'],":3154") !== false) {
+    $elsa  = " checked";
 } else {
     $sancp = " checked";
 }
@@ -87,6 +94,7 @@ capME!
 <td class=capme_right>
 <input type=radio name=sidsrc class=capme_rad value="sancp"<?php echo $sancp;?>>sancp
 <input type=radio name=sidsrc class=capme_rad value="event"<?php echo $event;?>>event
+<input type=radio name=sidsrc class=capme_rad value="elsa"<?php echo $elsa;?>>elsa
 </td>
 </tr>
 
--- securityonion-capme-20121213.orig/capme/.inc/callback.php
+++ securityonion-capme-20121213/capme/.inc/callback.php
@@ -14,27 +14,80 @@ $sip	= h2s($d[0]);
 $spt	= h2s($d[1]);
 $dip	= h2s($d[2]);
 $dpt	= h2s($d[3]);
-$st	= $d[4];
-$et     = $d[5];
+$st_unix= $d[4];
+$et_unix= $d[5];
 $usr	= h2s($d[6]);
 $pwd	= h2s($d[7]);
 $sidsrc = h2s($d[8]);
 
 // Format timestamps
-$st = date("Y-m-d H:i:s", $st);
-$et = date("Y-m-d H:i:s", $et);
+$st = date("Y-m-d H:i:s", $st_unix);
+$et = date("Y-m-d H:i:s", $et_unix);
 
 // Defaults
 $err = 0;
 $fmtd = $debug = $errMsg = '';
 
-// Find appropriate sensor
+/*
+We need to determine 3 pieces of data:
+sensor	- sensor name (for Security Onion this is HOSTNAME-INTERFACE)
+st	- time of the event from the sensor's perspective (may be more accurate than what we were given), in Y-m-d H:i:s format
+sid	- sensor id
+*/
+
+if ($sidsrc == "elsa") {
+	/*
+	If ELSA is enabled, then we need to:
+	- construct the ELSA query and submit it via cli.pl
+	- receive the response and parse out the sensor name (HOSTNAME-INTERFACE) and timestamp
+	- convert the timestamp to the proper format
+	NOTE: This requires that ELSA has access to Bro conn.log AND that the conn.log 
+	has been extended to include the sensor name (HOSTNAME-INTERFACE).
+	*/
+
+	$elsa_query = "class=bro_conn start:'$st_unix' end:'$et_unix' +$sip +$spt +$dip +$dpt limit:1";
+	$elsa_command = "perl /opt/elsa/web/cli.pl -q '$elsa_query' ";
+	$elsa_response = shell_exec($elsa_command);
+
+	// A successful query response looks like this:
+	// timestamp    class   host    program msg     fields
+	// 1372897204   BRO_CONN        127.0.0.1       bro_conn        original_timestamp|Many|Pipe|Delimited|Fields|etc|sensorIsOffset22
+
+	// Explode the output into separate lines and pull out the data line
+	$pieces = explode("\n", $elsa_response);
+	$elsa_response_data = $pieces[1];
+
+	// Explode the tab-delimited data line and pull out the pipe-delimited raw log
+	$pieces = explode("\t", $elsa_response_data);
+	$elsa_response_data_raw_log = $pieces[4];
+
+	// Explode the pipe-delimited raw log and pull out the original timestamp and sensor name
+	$pieces = explode("|", $elsa_response_data_raw_log);
+	$elsa_response_data_raw_log_timestamp = $pieces[0];
+	$elsa_response_data_raw_log_sensor = $pieces[22];
+
+	// Convert timestamp to proper format
+	$st = date("Y-m-d H:i:s", $elsa_response_data_raw_log_timestamp);
+
+	// Clean up $sensor
+	$sensor = rtrim($elsa_response_data_raw_log_sensor);
+	
+	// We now have 2 of the 3 pieces of data that we need.
+	// Next, we'll use $sensor to look up the $sid in Sguil's sensor table.
+}
 
+/*
+Query the Sguil database
+If the user selected sancp or event, query those tables and get
+the 3 pieces of data that we need.
+*/
 $queries = array(
+                 "elsa" => "SELECT sid FROM sensor WHERE hostname='$sensor' AND agent_type='pcap' LIMIT 1",
+
                  "sancp" => "SELECT sancp.start_time, s2.sid, s2.hostname
                              FROM sancp
                              LEFT JOIN sensor ON sancp.sid = sensor.sid
-                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.hostname
+                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.net_name
                              WHERE sancp.start_time >=  '$st' AND sancp.end_time <= '$et'
                              AND ((src_ip = INET_ATON('$sip') AND src_port = $spt AND dst_ip = INET_ATON('$dip') AND dst_port = $dpt) OR (src_ip = INET_ATON('$dip') AND src_port = $dpt AND dst_ip = INET_ATON('$sip') AND dst_port = $spt))
                              AND s2.agent_type = 'pcap' LIMIT 1",
@@ -42,7 +95,7 @@ $queries = array(
                  "event" => "SELECT event.timestamp AS start_time, s2.sid, s2.hostname
                              FROM event
                              LEFT JOIN sensor ON event.sid = sensor.sid
-                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.hostname
+                             LEFT JOIN sensor AS s2 ON sensor.net_name = s2.net_name
                              WHERE timestamp BETWEEN '$st' AND '$et'
                              AND ((src_ip = INET_ATON('$sip') AND src_port = $spt AND dst_ip = INET_ATON('$dip') AND dst_port = $dpt) OR (src_ip = INET_ATON('$dip') AND src_port = $dpt AND dst_ip = INET_ATON('$sip') AND dst_port = $spt))
                              AND s2.agent_type = 'pcap' LIMIT 1");
@@ -55,12 +108,15 @@ if (!$response) {
     $debug = $queries[$sidsrc];
 } else if (mysql_num_rows($response) == 0) {
     $err = 1;
-    $errMsg = "Failed to find a matching sid, please try again in a few seconds";
     $debug = $queries[$sidsrc];
+    $errMsg = "Failed to find a matching sid, please try again in a few seconds";
 } else {
     $row = mysql_fetch_assoc($response);
-    $st	= $row["start_time"];
-    $sensor = $row["hostname"]; 
+    // If using ELSA, we already set $st and $sensor above so don't overwrite that here
+    if ($sidsrc != "elsa") {
+        $st = $row["start_time"];
+    	$sensor = $row["hostname"]; 
+    }
     $sid    = $row["sid"];
 }
 
@@ -71,7 +127,7 @@ if ($err == 1) {
 
 } else {
 
-    // CLIscript command
+    // We have all the data we need, so pass the parameters to cliscript
     $cmd = "cliscript.tcl -sid $sid -sensor '$sensor' -timestamp '$st' -u '$usr' -pw '$pwd' -sip $sip -spt $spt -dip $dip -dpt $dpt";
 
     exec("../.scripts/$cmd",$raw);
--- securityonion-capme-20121213.orig/capme/.js/capme.js
+++ securityonion-capme-20121213/capme/.js/capme.js
@@ -36,7 +36,7 @@ $(document).ready(function(){
  
     $(".capme_submit").click(function() {
        frmArgs = $('input[value!=""]').length;
-       if (frmArgs == 11) {
+       if (frmArgs == 12) {
             reqCap("usefrm");
         } else {
             theMsg("Please complete all form fields");
@@ -121,8 +121,9 @@ $(document).ready(function(){
                         $(".capme_msg").fadeOut('slow');
                     } else {
                         theMsg(txError);
-                        bON('.capme_submit');
                     }
+                    
+                    bON('.capme_submit');
                 }
             }
         }
