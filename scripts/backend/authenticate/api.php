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

// Users directory
const AUTHENTICATE_USERS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "users";

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
 * @return stdClass Configuration
 */
function authenticate_configuration_load()
{
    return json_decode(file_get_contents(AUTHENTICATE_CONFIGURATION_FILE));
}

function authenticate_sessions_load()
{
    return json_decode(file_get_contents(AUTHENTICATE_SESSIONS_FILE));
}

function authenticate_sessions_unload($sessions)
{
    file_put_contents(AUTHENTICATE_SESSIONS_FILE, json_encode($sessions));
}

function authenticate_user_load($id)
{
    $user = AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id . ".json";
    if (file_exists($user)) {
        return json_decode(file_get_contents($user));
    }
    return null;
}

function authenticate_user_unload($id, $user)
{

}

function authenticate_user($id, $password)
{
    $user = authenticate_user_load($id);
    if ($user !== null) {
        if (authenticate_hash($password, $user->security->password->salt) === $user->security->password->hashed) {
            return [true, null];
        } else {
            return [false, "Wrong password"];
        }
    }
    return [false, "Failed loading user"];
}

function authenticate_user_add($name, $password)
{

}

function authenticate_session_add($id, $password)
{
    $configuration = authenticate_configuration_load();
    if ($configuration !== null) {
        $lockout = authenticate_user_unlocked($id);
        if ($lockout[0]) {
            $authentication = authenticate_user($id, $password);
            if ($authentication[0]) {
                $session = random($configuration->security->session->length);
                $hashed = authenticate_hash($session, $id);
                $sessions = authenticate_sessions_load();
                $sessions->$hashed = $id;
                authenticate_sessions_unload($sessions);
                return [true, $session];
            }
            return $authentication;
        }
        return $lockout;
    }
    return [false, "Failed loading configuration"];
}

/**
 * This function hashes a secret with a salt.
 * @param string $secret Secret
 * @param string $salt Salt
 * @param int $onion Number of layers to hash
 * @return string Hashed
 */
function authenticate_hash($secret, $salt, $onion = null)
{
    // Load configuration
    $configuration = authenticate_configuration_load();
    // Initialize algorithm
    $algorithm = $configuration->security->hash->algorithm;
    // Initialize onion if null
    if ($onion === null)
        $onion = $configuration->security->hash->onion;
    // Layer 0 result
    $return = hash($algorithm, $secret . $salt);
    // Layer > 0 result
    if ($onion > 0) {
        $layer = authenticate_hash($secret, $salt, $onion - 1);
        $return = hash($algorithm, ($onion % 2 === 0 ? $layer . $salt : $salt . $layer));
    }
    return $return;
}