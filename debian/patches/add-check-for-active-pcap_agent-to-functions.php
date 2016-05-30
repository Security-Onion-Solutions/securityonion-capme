Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-capme (20121213-0ubuntu0securityonion53) trusty; urgency=medium
 .
   * add check for active pcap_agent to functions.php
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

--- securityonion-capme-20121213.orig/capme/.inc/functions.php
+++ securityonion-capme-20121213/capme/.inc/functions.php
@@ -23,6 +23,12 @@ function invalid($string) {
         exit;
 }
 
+// Check for an active pcap_agent
+$response = mysql_query("select * from sensor where agent_type='pcap' and active='Y';");
+if (mysql_num_rows($response) == 0) {
+    invalid("Error: No active pcap_agent found.  Please ensure that pcap_agent and netsniff-ng are enabled and running.");
+}
+
 // Argument defaults
 $sip = $spt = $dip = $dpt = $stime = $etime = $usr = $pwd = $sancp = $event = $elsa = $bro = $tcpflow = $pcap = $maxtx = $filename = $parameters = '';
 
