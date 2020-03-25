<?php
// Include the notifier API
include_once __DIR__ . DIRECTORY_SEPARATOR . "api.php";
// Initialize the base API
API::init();
// Handle notifier calls
Notifier::handle();
// Echo the results
API::echo();