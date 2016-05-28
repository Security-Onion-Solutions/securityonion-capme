<?php

// session.php contains the sKill function to kill the session
include_once '.inc/session.php';

// functions.php validates parameters and builds the $parameters string
include_once '.inc/functions.php';

sKill($parameters);
?>
