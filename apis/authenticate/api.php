<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "token" . DIRECTORY_SEPARATOR . "api.php";

/**
 * Authenticate API for user authentication.
 */
class Authenticate
{
    // API string
    private const API = "authenticate";
    // Configuration properties
    private const CONFIGURATION_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . "configuration";
    private const HOOKS_FILE = self::CONFIGURATION_DIRECTORY . DIRECTORY_SEPARATOR . "hooks.json";
    // Column names
    private const COLUMN_NAME = "name";
    private const COLUMN_SALT = "salt";
    private const COLUMN_HASH = "hash";
    private const COLUMN_LOCK = "lock";
    // Hashing properties
    private const HASHING_ALGORITHM = "sha256";
    private const HASHING_ROUNDS = 1024;
    // Lengths
    private const LENGTH_SALT = 512;
    private const LENGTH_SESSION = 512;
    private const LENGTH_PASSWORD = 8;
    // Lock timeout
    private const TIMEOUT_LOCK = 10;
    // API mode
    private const TOKENS = true;
    // Database
    private static $database = null;

    /**
     * Main API hook. Can be used by other APIs to handle authentication.
     */
    public static function init()
    {
        // Make sure the database is initiated.
        self::$database = new Database(__DIR__);
        self::$database->create();
        self::$database->create_column(self::COLUMN_NAME);
        self::$database->create_column(self::COLUMN_SALT);
        self::$database->create_column(self::COLUMN_HASH);
        self::$database->create_column(self::COLUMN_LOCK);
        // Return the result so that other APIs could use it.
        return API::handle(self::API, function ($action, $parameters) {
            $configuration = self::hooks();
            if ($configuration !== null) {
                if (isset($configuration->$action)) {
                    if ($configuration->$action === true) {
                        if ($action === "authenticate") {
                            if (isset($parameters->token)) {
                                if (is_string($parameters->token)) {
                                    if (self::TOKENS) {
                                        // Authenticate the user using tokens
                                        return self::token($parameters->token);
                                    } else {
                                        // Authenticate the user using sessions
                                        return self::session($parameters->token);
                                    }
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
                                    if (count($ids = self::$database->search(self::COLUMN_NAME, $parameters->name)) === 1) {
                                        if (self::TOKENS) {
                                            return self::token_add($ids[0], $parameters->password);
                                        } else {
                                            return self::session_add($ids[0], $parameters->password);
                                        }
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
                                    return self::user_add($parameters->name, $parameters->password);
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
    private static function hooks()
    {
        return json_decode(file_get_contents(self::HOOKS_FILE));
    }

    /**
     * Authenticates a user using $id and $password, then returns a User ID.
     * @param string $id User ID
     * @param string $password User Password
     * @return array Result
     */
    private static function user($id, $password)
    {
        // Check if the user's row exists
        if (self::$database->has_row($id)) {
            // Retrieve the lock value
            $lock = intval(self::$database->get($id, self::COLUMN_LOCK));
            // Verify that the user isn't locked
            if ($lock < time()) {
                // Retrieve the salt and hash
                $salt = self::$database->get($id, self::COLUMN_SALT);
                $hash = self::$database->get($id, self::COLUMN_HASH);
                // Check password match
                if (self::hash_salted($password, $salt) === $hash) {
                    // Return a success result
                    return [true, null, null];
                } else {
                    // Lock the user
                    self::$database->set($id, self::COLUMN_LOCK, strval(time() + self::TIMEOUT_LOCK));
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
     * @return array Results
     */
    private static function user_add($name, $password)
    {
        // Check user name
        if (count(self::$database->search(self::COLUMN_NAME, $name)) === 0) {
            // Check password length
            if (strlen($password) >= self::LENGTH_PASSWORD) {
                // Generate a unique user id
                $id = self::$database->create_row();
                // Generate salt and hash
                $salt = self::random(self::LENGTH_SALT);
                $hash = self::hash_salted($password, $salt);
                // Set user information
                self::$database->set($id, self::COLUMN_NAME, $name);
                self::$database->set($id, self::COLUMN_SALT, $salt);
                self::$database->set($id, self::COLUMN_HASH, $hash);
                self::$database->set($id, self::COLUMN_LOCK, strval("0"));
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
     * Authenticates a user using $token then returns a User ID.
     * @param string $token Token
     * @return array Result
     */
    private static function token($token)
    {
        // Check if the token is valid
        $result = Token::validate(self::API, $token);
        if ($result[0]) {
            // Token is valid
            return [true, null, $result[1]];
        }
        // Return fallback with error
        return [false, $result[1], null];
    }

    /**
     * Authenticates a user and creates a new token for that user.
     * @param string $id User ID
     * @param string $password User password
     * @return array Result
     */
    private static function token_add($id, $password)
    {
        // Authenticate the user by an ID and password
        $authentication = self::user($id, $password);
        // Check authentication result
        if ($authentication[0]) {
            $token = Token::issue(self::API, $id);
            // Return a success result
            return [true, $token, null];
        }
        // Fallback result
        return $authentication;
    }

    /**
     * Authenticates a user using $session then returns a User ID.
     * @param string $session Session
     * @return array Result
     */
    private static function session($session)
    {
        // Check if a link with the session's hash value
        if (self::$database->has_link(self::hash($session))) {
            // Return a success result with a server result of the user's ID
            return [true, null, self::$database->follow_link(self::hash($session))];
        }
        // Fallback result
        return [false, "Invalid session", null];
    }

    /**
     * Authenticates a user and creates a new session for that user.
     * @param string $id User ID
     * @param string $password User password
     * @return array Result
     */
    private static function session_add($id, $password)
    {
        // Authenticate the user by an ID and password
        $authentication = self::user($id, $password);
        // Check authentication result
        if ($authentication[0]) {
            // Generate a new session ID
            $session = self::random(self::LENGTH_SESSION);
            // Create a database link with the session's hash
            self::$database->create_link($id, self::hash($session));
            // Return a success result
            return [true, $session, null];
        }
        // Fallback result
        return $authentication;
    }

    /**
     * Hashes a secret.
     * @param string $message Message
     * @param int $rounds Number of rounds
     * @return string Hashed
     */
    private static function hash($message, $rounds = self::HASHING_ROUNDS)
    {
        // Layer > 0 result
        if ($rounds > 0) {
            $layer = self::hash($message, $rounds - 1);
            $return = hash(self::HASHING_ALGORITHM, $layer);
        } else {
            // Layer 0 result
            $return = hash(self::HASHING_ALGORITHM, $message);
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
    private static function hash_salted($secret, $salt, $rounds = self::HASHING_ROUNDS)
    {
        // Layer > 0 result
        if ($rounds > 0) {
            $layer = self::hash_salted($secret, $salt, $rounds - 1);
            $return = hash(self::HASHING_ALGORITHM, ($rounds % 2 === 0 ? $layer . $salt : $salt . $layer));
        } else {
            // Layer 0 result
            $return = hash(self::HASHING_ALGORITHM, $secret . $salt);
        }
        return $return;
    }

    /**
     * Creates a random string.
     * @param int $length String length
     * @return string String
     */
    private static function random($length = 0)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::random($length - 1);
        }
        return "";
    }
}