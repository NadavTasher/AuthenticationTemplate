<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

// API name
const AUTHENTICATE_API = "authenticate";

// Paths
const AUTHENTICATE_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR;
const AUTHENTICATE_HOOKS_CONFIGURATION_FILE = AUTHENTICATE_DIRECTORY . DIRECTORY_SEPARATOR . "hooks.json";

// Database columns
const AUTHENTICATE_COLUMN_NAME = "name";
const AUTHENTICATE_COLUMN_SALT = "salt";
const AUTHENTICATE_COLUMN_HASH = "hash";
const AUTHENTICATE_COLUMN_LOCK = "lock";

// Configuration constants

const AUTHENTICATE_HASHING_ALGORITHM = "sha256";
const AUTHENTICATE_HASHING_ROUNDS = 1024;
const AUTHENTICATE_LENGTH_SALT = 512;
const AUTHENTICATE_LENGTH_SESSION = 512;
const AUTHENTICATE_LENGTH_PASSWORD = 8;
const AUTHENTICATE_LOCKOUT_TIMEOUT = 10;

/**
 * Main API hook. Can be used by other APIs to handle authentication.
 */
function authenticate()
{
    // Make sure the database is initiated.
    // Name column
    if (!database_has_column(AUTHENTICATE_COLUMN_NAME))
        database_create_column(AUTHENTICATE_COLUMN_NAME);
    // Salt column
    if (!database_has_column(AUTHENTICATE_COLUMN_SALT))
        database_create_column(AUTHENTICATE_COLUMN_SALT);
    // Hash column
    if (!database_has_column(AUTHENTICATE_COLUMN_HASH))
        database_create_column(AUTHENTICATE_COLUMN_HASH);
    // Lock column
    if (!database_has_column(AUTHENTICATE_COLUMN_LOCK))
        database_create_column(AUTHENTICATE_COLUMN_LOCK);
    // Return the result so that other APIs could use it.
    return api(AUTHENTICATE_API, function ($action, $parameters) {
        $configuration = authenticate_hooks_configuration_load();
        if ($configuration !== null) {
            if (isset($configuration->$action)) {
                if ($configuration->$action === true) {
                    if ($action === "authenticate") {
                        // Authenticate the user using the session
                        if (isset($parameters->session)) {
                            if (is_string($parameters->session)) {
                                return authenticate_session($parameters->session);
                            }
                            return [false, "Incorrect type", null];
                        }
                        return [false, "Missing parameters", null];
                    } else if ($action === "signin") {
                        // Authenticate the user using the password, return the new session
                        if (isset($parameters->name) &&
                            isset($parameters->password)) {
                            if (is_string($parameters->name) &&
                                is_string($parameters->password)) {
                                if (count($ids = database_search(AUTHENTICATE_COLUMN_NAME, $parameters->name)) === 1) {
                                    return authenticate_session_add($ids[0], $parameters->password);
                                }
                                return [false, "User not found", null];
                            }
                            return [false, "Incorrect type", null];
                        }
                        return [false, "Missing parameters", null];
                    } else if ($action === "signup") {
                        // Create a new user
                        if (isset($parameters->name) &&
                            isset($parameters->password)) {
                            if (is_string($parameters->name) &&
                                is_string($parameters->password)) {
                                return authenticate_user_add($parameters->name, $parameters->password);
                            }
                            return [false, "Incorrect type", null];
                        }
                        return [false, "Missing parameters", null];
                    }
                    return [false, "Unhandled hook", null];
                }
                return [false, "Locked hook", null];
            }
            return [false, "Undefined hook", null];
        }
        return [false, "Failed to load configuration", null];
    }, true);
}

/**
 * Loads the hooks configurations.
 * @return stdClass Hooks Configuration
 */
function authenticate_hooks_configuration_load()
{
    return json_decode(file_get_contents(AUTHENTICATE_HOOKS_CONFIGURATION_FILE));
}

/**
 * Authenticates a user using $id and $password, then returns a User ID.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_user($id, $password)
{
    // Check if the user's row exists
    if (database_has_row($id)) {
        // Retrieve the lock value
        $lock = intval(database_get($id, AUTHENTICATE_COLUMN_LOCK));
        // Verify that the user isn't locked
        if ($lock < time()) {
            // Retrieve the salt and hash
            $salt = database_get($id, AUTHENTICATE_COLUMN_SALT);
            $hash = database_get($id, AUTHENTICATE_COLUMN_HASH);
            // Check password match
            if (authenticate_hash_salted($password, $salt) === $hash) {
                // Return a success result
                return [true, null, null];
            } else {
                // Lock the user
                database_set($id, AUTHENTICATE_COLUMN_LOCK, strval(time() + AUTHENTICATE_LOCKOUT_TIMEOUT));
                // Return a failure result
                return [false, "Wrong password", null];
            }
        }
        // Fallback result
        return [false, "User is locked", null];
    }
    // Fallback result
    return [false, "User doesn't exist", null];
}

/**
 * Creates a new user.
 * @param string $name User Name
 * @param string $password User Password
 * @return array Action Results
 */
function authenticate_user_add($name, $password)
{
    // Check user name
    if (count(database_search(AUTHENTICATE_COLUMN_NAME, $name)) === 0) {
        // Check password length
        if (strlen($password) >= AUTHENTICATE_LENGTH_PASSWORD) {
            // Generate a unique user id
            $id = database_create_row();
            // Generate salt and hash
            $salt = authenticate_random(AUTHENTICATE_LENGTH_SALT);
            $hash = authenticate_hash_salted($password, $salt);
            // Set user information
            database_set($id, AUTHENTICATE_COLUMN_NAME, $name);
            database_set($id, AUTHENTICATE_COLUMN_SALT, $salt);
            database_set($id, AUTHENTICATE_COLUMN_HASH, $hash);
            database_set($id, AUTHENTICATE_COLUMN_LOCK, strval("0"));
            // Return a success result
            return [true, null, null];
        }
        // Fallback result
        return [false, "Password too short", null];
    }
    // Fallback result
    return [false, "User already exists", null];
}

/**
 * Authenticates a user using $session then returns a User ID.
 * @param string $session Session
 * @return array Action Result
 */
function authenticate_session($session)
{
    // Check if a link with the session's hash value
    if (database_has_link(authenticate_hash($session))) {
        // Return a success result with a server result of the user's ID
        return [true, null, database_follow_link(authenticate_hash($session))];
    }
    // Fallback result
    return [false, "Invalid session", null];
}

/**
 * Authenticates a user and creates a new session for that user.
 * @param string $id User ID
 * @param string $password User Password
 * @return array Action Result
 */
function authenticate_session_add($id, $password)
{
    // Authenticate the user by an ID and password
    $authentication = authenticate_user($id, $password);
    // Check authentication result
    if ($authentication[0]) {
        // Generate a new session ID
        $session = authenticate_random(AUTHENTICATE_LENGTH_SESSION);
        // Create a database link with the session's hash
        database_create_link($id, authenticate_hash($session));
        // Return a success result
        return [true, $session, null];
    }
    // Fallback result
    return $authentication;
}

/**
 * Hashes a secret.
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
 * Hashes a secret with a salt.
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

/**
 * Creates a random string.
 * @param int $length String length
 * @return string String
 */
function authenticate_random($length = 0)
{
    if ($length > 0) {
        return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . database_id($length - 1);
    }
    return "";
}