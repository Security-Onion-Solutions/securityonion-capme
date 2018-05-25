<?php

//
//
//      Copyright (C) 2016 Paul Halliday <paul.halliday@gmail.com>
//
//      This program is free software: you can redistribute it and/or modify
//      it under the terms of the GNU General Public License as published by
//      the Free Software Foundation, either version 3 of the License, or
//      (at your option) any later version.
//
//      This program is distributed in the hope that it will be useful,
//      but WITHOUT ANY WARRANTY; without even the implied warranty of
//      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//      GNU General Public License for more details.
//
//      You should have received a copy of the GNU General Public License
//      along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//

require_once '.inc/config.php';
require_once '.inc/functions.php';

$username = $password = $err = '';
$focus = 'username';
session_set_cookie_params(0, NULL, NULL, TRUE, TRUE);

function cleanUp($string) {
    if (get_magic_quotes_gpc()) {
        $string = stripslashes($string);
    }
    $string = mysql_real_escape_string($string);
    return $string;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST'){
    // User submitted credentials.
    // First, validate the username (alphanumeric only).
    $username = $_REQUEST['username'];
    if (!(ctype_alnum($username))) {
            $err = 'The user name or password is incorrect.';
            $focus = 'username';     
    } else {
	// Now that we've validated that the username is alphanumeric,
	// we're ready to check the username and password hash in the database.
	$password = $_REQUEST['password'];
	$ua       = $_SERVER['HTTP_USER_AGENT'];
	$rqt      = $_SERVER['REQUEST_TIME'];
	$rqaddr   = $_SERVER['REMOTE_ADDR'];
	$max      = mt_getrandmax();
	$rqt     .= mt_rand(0,$max);
	$rqaddr  .= mt_rand(0,$max);
	$ua      .= mt_rand(0,$max);
	$cmpid    = $rqt . $rqaddr . $ua;
	$id       = md5($cmpid);
	$db = mysql_connect($dbHost,$dbUser,$dbPass);
	$link = mysql_select_db($dbName, $db);
	if ($link) {
        	$user = cleanUp($username);
	        $query = "SELECT * FROM user_info WHERE username = '$user'";
        	$result = mysql_query($query);
	        $numRows = mysql_num_rows($result);

        	if ($numRows > 0) {
	            while ($row = mysql_fetch_row($result)) {
        	        $userName	= $row[1];
                	$lastLogin	= $row[2];
	                $userHash	= $row[3];
        	        $userEmail      = $row[4];
                	$userType       = $row[5];
	                $userTime       = $row[6];
        	        $tzoffset	= $row[7];
	            }
	            // The first 2 chars are the salt     
        	    $theSalt = substr($userHash, 0,2);

	            // The remainder is the hash
        	    $theHash = substr($userHash, 2);

	            // Now we hash the users input                 
        	    $testHash = sha1($password . $theSalt);

	            // Does it match? If yes, start the session.
        	    if ($testHash === $theHash) {
                	session_start();

	                // Protect against session fixation attack
        	        if (!isset($_SESSION['initiated'])) {
                	    session_regenerate_id();
	                    $_SESSION['initiated'] = true;
        	        }

	                $_SESSION['sLogin']	= 1;
        	        $_SESSION['sUser']	= $userName;
                	$_SESSION['sPass']	= $password;        
	                $_SESSION['sEmail']	= $userEmail;
        	        $_SESSION['sType']      = $userType;
                	$_SESSION['sTime']	= $userTime;
	                $_SESSION['tzoffset']   = $tzoffset;
        	        $_SESSION['sTab']       = 't_sum';

			// Store id in session and cookie to compare later
        	        $_SESSION['id']       	= $id;
			setcookie("capmeid", $id, 0, NULL, NULL, TRUE, TRUE);
                
			// Redirect to desired page
			if ( $esid != "") {
			        header ("Location: elastic.php?" . $parameters);
			} else {
			        header ("Location: index.php?" . $parameters);
			}
        	    } else {
	                $err = 'The user name or password is incorrect.';
        	        $focus = 'username';
	            }
	        } else {   
        	    $err = 'The user name or password is incorrect.';
	            $focus = 'username';     
        	}
	    } else {
        	$err = 'Connection Failed';
	    }
	  }
}
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<title>capME! - Please login to continue</title>
<style type="text/css" media="screen">@import ".css/login.css";</style>
<script type="text/javascript" src=".js/jq.js"></script>
</head>
<body>
<form name=credcheck method=post action=login.php?<?php echo $parameters?>>
<br><br><br><br><br>
<table class=boxes width=450 align=center cellpadding=1 cellspacing=0>
<tr><td colspan=2 class=header>
capME! - Please login to continue</td></tr>
<tr><td colspan=2 class=boxes>
Username<br>
<input class=in type=text name=username value="<?php echo htmlentities($username);?>" maxlength="32"></td></tr>
<tr><td colspan=2 class=boxes>
Password<br>
<input class=in type=password name=password value="" maxlength="32"></td></tr>
<tr><td class=boxes>
<input id=logmein name=logmein class=rb type=submit name=login value=submit><br><br></td>
<td class=err><?php echo $err;?></td></tr>
</table>
<div class=cp>Version 1.1.0<span>&copy;2016 Paul Halliday</span></div>
</form>
<script type="text/javascript">document.credcheck.<?php echo $focus;?>.focus();</script>
</body>
</html>
