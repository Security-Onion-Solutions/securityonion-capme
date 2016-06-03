<?php

// session.php contains the sKill function to kill the session
require_once '.inc/session.php';

// functions.php validates parameters and builds the $parameters string
require_once '.inc/functions.php';

sKill($parameters);
?>
