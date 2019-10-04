<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemploate/
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

// IDs directory
const AUTHENTICATE_IDS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "ids";

// Users directory
const AUTHENTICATE_USERS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "users";

/**
 * This is the main API hook. It can be used by other APIs to handle authentication.
 */
function authenticate()
{
    // Return the result so that other APIs could use it.
    return api(AUTHENTICATE_API, function ($action, $parameters) {
        $configuration = authenticate_configuration_load();
        if ($configuration !== null) {
            $hooks = $configuration->hooks;
            if ($hooks->$action === true) {
                if ($action === "authenticate") {
                    // Authenticate the user using the session
                    if (isset($parameters->session)) {
                        return authenticate_session($parameters->session);
                    }
                    return [false, "Missing parameters"];
                } else if ($action === "signin") {
                    // Authenticate the user using the password, return the new session
                    if (isset($parameters->name) &&
                        isset($parameters->password)) {
                        $id = authenticate_id_load($parameters->name);
                        if ($id !== null) {
                            return authenticate_session_add($id, $parameters->password);
                        }
                        return [false, "User not found"];
                    }
                    return [false, "Missing parameters"];
                } else if ($action === "signup") {
                    // Create a new user
                    if (isset($parameters->name) &&
                        isset($parameters->password)) {
                        return authenticate_user_add($parameters->name, $parameters->password);
                    }
                    return [false, "Missing parameters"];
                }
            }
            return [false, "Locked hook"];
        }
        return [false, "Failed to load configuration"];
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

/**
 * This function loads the sessions database.
 * @return stdClass Sessions Database
 */
function authenticate_sessions_load()
{
    return json_decode(file_get_contents(AUTHENTICATE_SESSIONS_FILE));
}

/**
 * This function saves the sessions database.
 * @param stdClass $sessions Sessions Database
 */
function authenticate_sessions_unload($sessions)
{
    file_put_contents(AUTHENTICATE_SESSIONS_FILE, json_encode($sessions));
}

/**
 * This function loads the users database.
 * @param string $name User's Name
 * @return string User's ID
 */
function authenticate_id_load($name)
{
    if (file_exists(AUTHENTICATE_IDS_DIRECTORY . DIRECTORY_SEPARATOR . $name))
        return file_get_contents(AUTHENTICATE_IDS_DIRECTORY . DIRECTORY_SEPARATOR . $name);
    return null;
}

/**
 * This function saves the users database.
 * @param string $name User's Name
 * @param string $id User's ID
 */
function authenticate_id_unload($name, $id)
{
    file_put_contents(AUTHENTICATE_IDS_DIRECTORY . DIRECTORY_SEPARATOR . $name, $id);
}

/**
 * This function loads a user from it's file.
 * @param string $id User ID
 * @return stdClass User
 */
function authenticate_user_load($id)
{
    $file = AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id . ".json";
    if (file_exists($file)) {
        return json_decode(file_get_contents($file));
    }
    return null;
}

/**
 * This function saves a user to it's file.
 * @param string $id User ID
 * @param stdClass $user User
 */
function authenticate_user_unload($id, $user)
{
    $file = AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id . ".json";
    file_put_contents($file, json_encode($user));
}

/**
 * This function authenticates the user using $id and $password, then returns the User's ID.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_user($id, $password)
{
    $configuration = authenticate_configuration_load();
    $user = authenticate_user_load($id);
    if ($configuration !== null) {
        if ($user !== null) {
            if ($user->security->lock->time < time()) {
                if (authenticate_hash($password, $user->security->password->salt) === $user->security->password->hashed) {
                    return [true, null];
                }
                $user->security->lock->time = time() + $configuration->security->lockTimeout;
                authenticate_user_unload($id, $user);
                return [false, "Wrong password"];
            }
            return [false, "User is locked"];
        }
        return [false, "Failed loading user"];
    }
    return [false, "Failed loading configuration"];
}

/**
 * This function creates a new user.
 * @param string $name User Name
 * @param string $password User Password
 * @return array Action Results
 */
function authenticate_user_add($name, $password)
{
    $configuration = authenticate_configuration_load();
    if ($configuration !== null) {
        // Generate a unique user id
        $id = random($configuration->security->userIDLength);
        while (file_exists(AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id . ".json"))
            $id = random($configuration->security->userIDLength);
        // Add a Name-ID file
        if (authenticate_id_load($name) === null) {
            authenticate_id_unload($name, $id);
        } else {
            return [false, "User already exists"];
        }
        // Initialize the user
        $user = new stdClass();
        $user->name = $name;
        $user->security = new stdClass();
        $user->security->password = new stdClass();
        $user->security->password->salt = random($configuration->security->hash->saltLength);
        $user->security->password->hashed = authenticate_hash($password, $user->security->password->salt);
        $user->security->lock = new stdClass();
        $user->security->lock->time = 0;
        // Save user
        authenticate_user_unload($id, $user);
        return [true, null];
    }
    return [false, "Failed loading configuration"];
}

/**
 * This function authenticates the user using $session then returns the User's ID.
 * @param string $session Session
 * @return array Action Result
 */
function authenticate_session($session)
{
    $sessions = authenticate_sessions_load();
    if ($sessions !== null) {
        foreach ($sessions as $hashed => $id) {
            if (authenticate_hash($session, $id) === $hashed) {
                return [true, $id];
            }
        }
        return [false, "Invalid session"];
    }
    return [false, "Failed loading sessions"];
}

/**
 * This function authenticates the user and creates a new session.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_session_add($id, $password)
{
    $configuration = authenticate_configuration_load();
    if ($configuration !== null) {
        $authentication = authenticate_user($id, $password);
        if ($authentication[0]) {
            $session = random($configuration->security->sessionLength);
            $hashed = authenticate_hash($session, $id);
            $sessions = authenticate_sessions_load();
            $sessions->$hashed = $id;
            authenticate_sessions_unload($sessions);
            return [true, $session];
        }
        return $authentication;
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
        $onion = $configuration->security->hash->onionLayers;
    // Layer 0 result
    $return = hash($algorithm, $secret . $salt);
    // Layer > 0 result
    if ($onion > 0) {
        $layer = authenticate_hash($secret, $salt, $onion - 1);
        $return = hash($algorithm, ($onion % 2 === 0 ? $layer . $salt : $salt . $layer));
    }
    return $return;
}