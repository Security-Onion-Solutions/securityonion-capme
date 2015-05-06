Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-capme (20121213-0ubuntu0securityonion19) precise; urgency=low
 .
   * Issue 570:	CapMe: Ignore extra data from ELSA cli.pl
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

--- securityonion-capme-20121213.orig/capme/.inc/callback.php
+++ securityonion-capme-20121213/capme/.inc/callback.php
@@ -74,7 +74,21 @@ if ($sidsrc == "elsa") {
 
 	// Explode the output into separate lines and pull out the data line
 	$pieces = explode("\n", $elsa_response);
-	$elsa_response_data = $pieces[1];
+
+	// Sometimes the response contains a warning - this means that the
+	// expected query response data is not located on the second line.
+	// Iterate through until we find the header line - the next
+	// line is the data line we want. See line 35 of /opt/elsa/web/cli.pl
+	$data_line_n = 1;
+
+	for ($n=0; $n<=count($pieces); $n++) {
+		if ($pieces[$n] === "timestamp\tclass\thost\tprogram\tmsg\tfields") {
+			$data_line_n = $n + 1;
+			break;
+		}
+	}
+
+	$elsa_response_data = $pieces[$data_line_n];
 
 	// Explode the tab-delimited data line and pull out the pipe-delimited raw log
 	$pieces = explode("\t", $elsa_response_data);
