<?php
// Include the authenticate API
include_once __DIR__ . DIRECTORY_SEPARATOR . "Authenticate.php";

// Initialize the API
Authenticate::initialize();

// Handle the API call
Authenticate::handle();