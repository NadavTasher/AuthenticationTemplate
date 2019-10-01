<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/WebAppBase/
 **/

// Include base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

// API hook name
const AUTHENTICATE_API = "authenticate";

// General directory
const AUTHENTICATE_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files" . DIRECTORY_SEPARATOR . "authenticate";

// Configuration file
const AUTHENTICATE_CONFIGURATION_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "configuration.json";

// Sessions file
const AUTHENTICATE_SESSIONS_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "sessions.json";

// Users file
const AUTHENTICATE_USERS_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "users.json";

// Local configuration
$configuration = null;

/**
 * This is the main API hook. It can be used by other APIs to handle authentication.
 */
function authenticate()
{
    // Return the result so that other APIs could use it.
    return api(AUTHENTICATE_API, function ($action, $parameters) {

    }, true);
}

/**
 * This function loads the configuration.
 * @return bool Success
 */
function authenticate_configuration_load()
{
    // Configure scope
    global $configuration;
    // Check if configuration is not loaded yet
    if ($configuration === null) {
        $configuration = json_decode(file_get_contents(AUTHENTICATE_CONFIGURATION_FILE));
        return true;
    }
    return false;
}

/**
 * This function hashes the password with it's salts.
 * @param string $password User's password
 * @param string $salt User's salt
 * @param int $onion Number of layers to hash
 * @return string Hashed password
 */
function authenticate_password_hash($password, $salt, $onion = 0)
{
    // Layer 0 result
    $return = hash("sha256", $password . $salt);
    // Layer > 0 result
    if ($onion !== 0) {
        $layer = authenticate_password_hash($password, $salt, $onion - 1);
        $return = hash("sha256", ($onion % 2 === 0 ? $layer . $salt : $salt . $layer));
    }
    return $return;
}