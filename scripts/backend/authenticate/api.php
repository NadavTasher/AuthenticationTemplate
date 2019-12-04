<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

// API hook name
const AUTHENTICATE_API = "authenticate";

// General directory
const AUTHENTICATE_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files" . DIRECTORY_SEPARATOR . "authenticate";

// Configuration file
const AUTHENTICATE_CONFIGURATION_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "configuration.json";

// Sessions directory
const AUTHENTICATE_SESSIONS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "sessions";

// Names directory
const AUTHENTICATE_NAMES_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "names";

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
                    return [false, "Missing parameters", null];
                } else if ($action === "signin") {
                    // Authenticate the user using the password, return the new session
                    if (isset($parameters->name) &&
                        isset($parameters->password)) {
                        $id = authenticate_name_load($parameters->name);
                        if ($id !== null) {
                            return authenticate_session_add($id, $parameters->password);
                        }
                        return [false, "User not found", null];
                    }
                    return [false, "Missing parameters", null];
                } else if ($action === "signup") {
                    // Create a new user
                    if (isset($parameters->name) &&
                        isset($parameters->password)) {
                        return authenticate_user_add($parameters->name, $parameters->password);
                    }
                    return [false, "Missing parameters", null];
                }
            }
            return [false, "Locked hook", null];
        }
        return [false, "Failed to load configuration", null];
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
 * This function loads a session by its $session id.
 * @param string $session Session ID
 * @return string User's ID
 */
function authenticate_session_load($session)
{
    if (file_exists(AUTHENTICATE_SESSIONS_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($session)))
        return file_get_contents(AUTHENTICATE_SESSIONS_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($session));
    return null;
}

/**
 * This function saves a session by its $session id.
 * @param string $session Session ID
 * @param string $id User ID
 */
function authenticate_session_unload($session, $id)
{
    file_put_contents(AUTHENTICATE_SESSIONS_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($session), $id);
}

/**
 * This function loads a User ID by its $name name.
 * @param string $name User Name
 * @return string User ID
 */
function authenticate_name_load($name)
{
    if (file_exists(AUTHENTICATE_NAMES_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($name)))
        return file_get_contents(AUTHENTICATE_NAMES_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($name));
    return null;
}

/**
 * This function saves a User ID by its $name name.
 * @param string $name User Name
 * @param string $id User ID
 */
function authenticate_name_unload($name, $id)
{
    file_put_contents(AUTHENTICATE_NAMES_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($name), $id);
}

/**
 * This function loads a user by its $id id.
 * @param string $id User ID
 * @return stdClass User
 */
function authenticate_user_load($id)
{
    if (file_exists(AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id)) {
        return json_decode(file_get_contents(AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id));
    }
    return null;
}

/**
 * This function saves a user by its $id id.
 * @param string $id User ID
 * @param stdClass $user User
 */
function authenticate_user_unload($id, $user)
{
    file_put_contents(AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id, json_encode($user));
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
                if (authenticate_hash_salted($password, $user->security->password->salt) === $user->security->password->hashed) {
                    return [true, null, null];
                }
                $user->security->lock->time = time() + $configuration->security->lock;
                authenticate_user_unload($id, $user);
                return [false, "Wrong password", null];
            }
            return [false, "User is locked", null];
        }
        return [false, "Failed loading user", null];
    }
    return [false, "Failed loading configuration", null];
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
        // Check user name
        if (authenticate_name_load($name) === null) {
            // Check password length
            if (strlen($password) >= $configuration->security->password) {
                // Generate a unique user id
                $id = random($configuration->security->id);
                while (authenticate_user_load($id) !== null)
                    $id = random($configuration->security->id);
                // Initialize the user
                $user = new stdClass();
                $user->name = $name;
                $user->security = new stdClass();
                $user->security->password = new stdClass();
                $user->security->password->salt = random($configuration->security->salt);
                $user->security->password->hashed = authenticate_hash_salted($password, $user->security->password->salt);
                $user->security->lock = new stdClass();
                $user->security->lock->time = 0;
                // Save user
                authenticate_name_unload($name, $id);
                authenticate_user_unload($id, $user);
                return [true, null, null];

            }
            return [false, "Password too short", null];
        }
        return [false, "User already exists", null];
    }
    return [false, "Failed loading configuration", null];
}

/**
 * This function authenticates the user using $session then returns the User's ID.
 * @param string $session Session
 * @return array Action Result
 */
function authenticate_session($session)
{
    $id = authenticate_session_load($session);
    if ($id !== null) {
        return [true, null, $id];
    }
    return [false, "Invalid session", null];
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
            $session = random($configuration->security->session);
            authenticate_session_unload($session, $id);
            return [true, $session, null];
        }
        return $authentication;
    }
    return [false, "Failed loading configuration", null];
}

/**
 * This function hashes a secret.
 * @param string $secret Secret
 * @param int $onion Number of layers to hash
 * @return string Hashed
 */
function authenticate_hash($secret, $onion = null)
{
    // Load configuration
    $configuration = authenticate_configuration_load();
    // Initialize algorithm
    $algorithm = $configuration->security->algorithm;
    // Initialize onion if null
    if ($onion === null)
        $onion = $configuration->security->rounds;
    // Layer > 0 result
    if ($onion > 0) {
        $layer = authenticate_hash($secret, $onion - 1);
        $return = hash($algorithm, $layer);
    } else {
        // Layer 0 result
        $return = hash($algorithm, $secret);
    }
    return $return;
}

/**
 * This function hashes a secret with a salt.
 * @param string $secret Secret
 * @param string $salt Salt
 * @param int $onion Number of layers to hash
 * @return string Hashed
 */
function authenticate_hash_salted($secret, $salt, $onion = null)
{
    // Load configuration
    $configuration = authenticate_configuration_load();
    // Initialize algorithm
    $algorithm = $configuration->security->algorithm;
    // Initialize onion if null
    if ($onion === null)
        $onion = $configuration->security->onionLayers;
    // Layer > 0 result
    if ($onion > 0) {
        $layer = authenticate_hash_salted($secret, $salt, $onion - 1);
        $return = hash($algorithm, ($onion % 2 === 0 ? $layer . $salt : $salt . $layer));
    } else {
        // Layer 0 result
        $return = hash($algorithm, $secret . $salt);
    }
    return $return;
}