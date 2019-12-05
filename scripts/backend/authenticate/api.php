<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

// API name
const AUTHENTICATE_API = "authenticate";

// Directories
const AUTHENTICATE_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files" . DIRECTORY_SEPARATOR . "authenticate";
const AUTHENTICATE_SESSIONS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "sessions";
const AUTHENTICATE_NAMES_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "names";
const AUTHENTICATE_USERS_DIRECTORY = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "users";

// Hooks configuration file
const AUTHENTICATE_HOOKS_CONFIGURATION_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "hooks.json";

// Configuration constants

const AUTHENTICATE_HASHING_ALGORITHM = "sha256";
const AUTHENTICATE_HASHING_ROUNDS = 1024;
const AUTHENTICATE_LENGTH_SALT = 512;
const AUTHENTICATE_LENGTH_ID_SESSION = 512;
const AUTHENTICATE_LENGTH_ID_USER = 20;
const AUTHENTICATE_LENGTH_PASSWORD = 8;
const AUTHENTICATE_LOCKOUT_TIMEOUT = 10;

/**
 * This is the main API hook. It can be used by other APIs to handle authentication.
 */
function authenticate()
{
    // Return the result so that other APIs could use it.
    return api(AUTHENTICATE_API, function ($action, $parameters) {
        $configuration = authenticate_hooks_configuration_load();
        if ($configuration !== null) {
            if (isset($configuration->$action)) {
                if ($configuration->$action === true) {
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
            return [false, "Undefined hook", null];
        }
        return [false, "Failed to load configuration", null];
    }, true);
}

/**
 * This function loads the hooks configurations.
 * @return stdClass Hooks Configuration
 */
function authenticate_hooks_configuration_load()
{
    return json_decode(file_get_contents(AUTHENTICATE_HOOKS_CONFIGURATION_FILE));
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
 * This function saves a session by its id.
 * @param string $session Session ID
 * @param string $id User ID
 */
function authenticate_session_unload($session, $id)
{
    file_put_contents(AUTHENTICATE_SESSIONS_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($session), $id);
}

/**
 * This function loads a User ID by its name.
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
 * This function saves a User ID by its name.
 * @param string $name User Name
 * @param string $id User ID
 */
function authenticate_name_unload($name, $id)
{
    file_put_contents(AUTHENTICATE_NAMES_DIRECTORY . DIRECTORY_SEPARATOR . authenticate_hash($name), $id);
}

/**
 * This function loads a user by its id.
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
 * This function saves a user by its id.
 * @param string $id User ID
 * @param stdClass $user User
 */
function authenticate_user_unload($id, $user)
{
    file_put_contents(AUTHENTICATE_USERS_DIRECTORY . DIRECTORY_SEPARATOR . $id, json_encode($user));
}

/**
 * This function authenticates a user using $id and $password, then returns a User ID.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_user($id, $password)
{
    $user = authenticate_user_load($id);
    if ($user !== null) {
        if ($user->security->lockout->time < time()) {
            if (authenticate_hash_salted($password, $user->security->password->salt) === $user->security->password->hashed) {
                return [true, null, null];
            } else {
                $user->security->lockout->time = time() + AUTHENTICATE_LOCKOUT_TIMEOUT;
                authenticate_user_unload($id, $user);
                return [false, "Wrong password", null];
            }
        }
        return [false, "User is locked", null];
    }
    return [false, "Failed loading user", null];
}

/**
 * This function creates a new user.
 * @param string $name User Name
 * @param string $password User Password
 * @return array Action Results
 */
function authenticate_user_add($name, $password)
{
    // Check user name
    if (authenticate_name_load($name) === null) {
        // Check password length
        if (strlen($password) >= AUTHENTICATE_LENGTH_PASSWORD) {
            // Generate a unique user id
            $id = random(AUTHENTICATE_LENGTH_ID_USER);
            while (authenticate_user_load($id) !== null)
                $id = random(AUTHENTICATE_LENGTH_ID_USER);
            // Initialize the user
            $user = new stdClass();
            $user->name = $name;
            $user->security = new stdClass();
            $user->security->password = new stdClass();
            $user->security->password->salt = random(AUTHENTICATE_LENGTH_SALT);
            $user->security->password->hashed = authenticate_hash_salted($password, $user->security->password->salt);
            $user->security->lockout = new stdClass();
            $user->security->lockout->time = 0;
            // Save user
            authenticate_name_unload($name, $id);
            authenticate_user_unload($id, $user);
            return [true, null, null];

        }
        return [false, "Password too short", null];
    }
    return [false, "User already exists", null];
}

/**
 * This function authenticates a user using $session then returns a User ID.
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
 * This function authenticates a user and creates a new session for that user.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_session_add($id, $password)
{
    $authentication = authenticate_user($id, $password);
    if ($authentication[0]) {
        $session = random(AUTHENTICATE_LENGTH_ID_SESSION);
        authenticate_session_unload($session, $id);
        return [true, $session, null];
    }
    return $authentication;
}

/**
 * This function hashes a secret.
 * @param string $secret Secret
 * @param int $rounds Number of rounds to hash
 * @return string Hashed
 */
function authenticate_hash($secret, $rounds = AUTHENTICATE_HASHING_ROUNDS)
{
    // Layer > 0 result
    if ($rounds > 0) {
        $layer = authenticate_hash($secret, $rounds - 1);
        $return = hash(AUTHENTICATE_HASHING_ALGORITHM, $layer);
    } else {
        // Layer 0 result
        $return = hash(AUTHENTICATE_HASHING_ALGORITHM, $secret);
    }
    return $return;
}

/**
 * This function hashes a secret with a salt.
 * @param string $secret Secret
 * @param string $salt Salt
 * @param int $rounds Number of rounds to hash
 * @return string Hashed
 */
function authenticate_hash_salted($secret, $salt, $rounds = AUTHENTICATE_HASHING_ROUNDS)
{
    // Layer > 0 result
    if ($rounds > 0) {
        $layer = authenticate_hash_salted($secret, $salt, $rounds - 1);
        $return = hash(AUTHENTICATE_HASHING_ALGORITHM, ($rounds % 2 === 0 ? $layer . $salt : $salt . $layer));
    } else {
        // Layer 0 result
        $return = hash(AUTHENTICATE_HASHING_ALGORITHM, $secret . $salt);
    }
    return $return;
}