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

require_once 'functions.php';

// Session init
session_start();

// Define a function to kill the session.
function sKill($parameters) {
    // Destroy all data associated with current session.
    session_destroy();
    // Free all session variables.
    session_unset();
    // Delete PHPSESSID cookie if it exists.
    if(isset($_COOKIE[session_name()])) {
    	setcookie(session_name(), "", time() - 7000000);
    }
    // Delete capmeid cookie if it exists.
    if(isset($_COOKIE['capmeid'])) {
    	setcookie("capmeid", "", time() - 7000000);
    }
    // Redirect to the login page.
    header ("Location: /capme/login.php?" . $parameters);
    exit();
}

// Define a function to initiate a session.
function sInt($parameters) {
     header ("Location: /capme/login.php?" . $parameters);
     exit();
}

if (!(isset($_SESSION['sLogin']) && $_SESSION['sLogin'] != '')) {
     sKill($parameters);
}

// Check to see if session variables exist.
if (!isset($_SESSION['sUser']))    { sInt($parameters);  } else { $sUser    = $_SESSION['sUser'];}
if (!isset($_SESSION['sPass']))    { sInt($parameters);  } else { $sPass    = $_SESSION['sPass'];}
if (!isset($_SESSION['sEmail']))   { sInt($parameters);  } else { $sEmail   = $_SESSION['sEmail'];}
if (!isset($_SESSION['sType']))    { sInt($parameters);  } else { $sType    = $_SESSION['sType'];}
if (!isset($_SESSION['sTab']))     { sInt($parameters);  } else { $sTab     = $_SESSION['sTab'];}
if (!isset($_SESSION['tzoffset'])) { sInt($parameters);  } else { $tzoffset = $_SESSION['tzoffset'];}

// Compare the id in the cookie to the id in the session.
// If they don't match, kill the session.
if (!isset($_COOKIE['capmeid']))   { sInt($parameters);  } else { $id       = $_COOKIE['capmeid'];}
if ($id != $_SESSION['id']) {
    sKill($parameters);
}
?>
