Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-capme (20121213-0ubuntu0securityonion76) xenial; urgency=medium
 .
   * update callback.php
Author: Doug Burks <doug.burks@gmail.com>

---
The information above should follow the Patch Tagging Guidelines, please
checkout http://dep.debian.net/deps/dep3/ to learn about the format. Here
are templates for supplementary fields that you might want to add:

Origin: <vendor|upstream|other>, <url of original patch>
Bug: <url in upstream bugtracker>
Bug-Debian: https://bugs.debian.org/<bugnumber>
Bug-Ubuntu: https://launchpad.net/bugs/<bugnumber>
Forwarded: <no|not-needed|url proving that it has been forwarded>
Reviewed-By: <name and email of someone who approved the patch>
Last-Update: <YYYY-MM-DD>

--- securityonion-capme-20121213.orig/capme/.inc/callback.php
+++ securityonion-capme-20121213/capme/.inc/callback.php
@@ -226,7 +226,15 @@ if ($err == 1) {
     // The original cliscript.tcl assumes TCP (proto 6).
     $script = "cliscript.tcl";
     $proto=6;
-    $cmd = "../.scripts/$script \"$usr\" \"$sensor\" \"$st\" $sid $sip $dip $spt $dpt";
+    $cmdusr     = escapeshellarg($usr);
+    $cmdsensor  = escapeshellarg($sensor);
+    $cmdst      = escapeshellarg($st);
+    $cmdsid     = escapeshellarg($sid);
+    $cmdsip     = escapeshellarg($sip);
+    $cmddip     = escapeshellarg($dip);
+    $cmdspt     = escapeshellarg($spt);
+    $cmddpt     = escapeshellarg($dpt);
+    $cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt";
 
     // check to see if the event is UDP.
     $response = mysqli_query($db, "select * from event WHERE timestamp BETWEEN '$st' AND '$et' AND 
@@ -240,7 +248,7 @@ if ($err == 1) {
     // If the traffic is UDP or the user chose the Bro transcript, change to cliscriptbro.tcl.
     if ($xscript == "bro" || $proto == "17" ) {
 	$script = "cliscriptbro.tcl";
-	$cmd = "../.scripts/$script \"$usr\" \"$sensor\" \"$st\" $sid $sip $dip $spt $dpt $proto";
+        $cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";
     }
 
     // Request the transcript.
@@ -267,7 +275,7 @@ if ($err == 1) {
 
     // If we found gzip encoding, then switch to Bro transcript.
     if ($foundgzip==1) {
-        $cmd = "../.scripts/cliscriptbro.tcl \"$usr\" \"$sensor\" \"$st\" $sid $sip $dip $spt $dpt $proto";
+        $cmd = "../.scripts/cliscriptbro.tcl $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";
 	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Detected gzip encoding.</b></span>";
 	$fmtd .= "<span class=txtext_hdr>CAPME: <b>Automatically switched to Bro transcript.</b></span>";
     }
