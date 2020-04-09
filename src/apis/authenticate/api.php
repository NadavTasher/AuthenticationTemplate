<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

/**
 * Authenticate API for user initialize.
 */
class Authenticate
{
    // API string
    public const API = "authenticate";

    // Column names
    private const COLUMN_NAME = "name";
    private const COLUMN_SALT = "salt";
    private const COLUMN_HASH = "hash";
    private const COLUMN_LOCK = "lock";

    // API mode
    private const TOKENS = true;

    // Configuration
    private static stdClass $configuration;

    // Base APIs
    private static Database $database;
    private static Authority $authority;

    /**
     * API initializer.
     */
    public static function initialize()
    {
        // Load configuration
        self::$configuration = new stdClass();
        self::$configuration->hooks = json_decode(file_get_contents(Utils::hostDirectory(self::API) . DIRECTORY_SEPARATOR . "hooks.json"));
        self::$configuration->locks = json_decode(file_get_contents(Utils::hostDirectory(self::API) . DIRECTORY_SEPARATOR . "locks.json"));
        self::$configuration->lengths = json_decode(file_get_contents(Utils::hostDirectory(self::API) . DIRECTORY_SEPARATOR . "lengths.json"));
        self::$configuration->permissions = json_decode(file_get_contents(Utils::hostDirectory(self::API) . DIRECTORY_SEPARATOR . "permissions.json"));
        // Make sure the database is initiated.
        self::$database = new Database(self::API);
        self::$database->createColumn(self::COLUMN_NAME);
        self::$database->createColumn(self::COLUMN_SALT);
        self::$database->createColumn(self::COLUMN_HASH);
        self::$database->createColumn(self::COLUMN_LOCK);
        // Make sure the authority is set-up
        self::$authority = new Authority(self::API);
    }

    /**
     * Main API hook.
     */
    public static function handle()
    {
        // Handle the request
        Base::handle(function ($action, $parameters) {
            if (isset(self::$configuration->hooks->$action)) {
                if (self::$configuration->hooks->$action === true) {
                    if ($action === "validate") {
                        if (isset($parameters->token)) {
                            if (is_string($parameters->token)) {
                                return self::validate($parameters->token);
                            }
                            return [false, "Invalid parameters"];
                        }
                        return [false, "Missing parameters"];
                    } else if ($action === "signIn") {
                        // Authenticate the user using the password, return the new session
                        if (isset($parameters->name) &&
                            isset($parameters->password)) {
                            if (is_string($parameters->name) &&
                                is_string($parameters->password)) {
                                return self::signIn($parameters->name, $parameters->password);
                            }
                            return [false, "Invalid parameters"];
                        }
                        return [false, "Missing parameters"];
                    } else if ($action === "signUp") {
                        // Create a new user
                        if (isset($parameters->name) &&
                            isset($parameters->password)) {
                            if (is_string($parameters->name) &&
                                is_string($parameters->password)) {
                                return self::signUp($parameters->name, $parameters->password);
                            }
                            return [false, "Invalid parameters"];
                        }
                        return [false, "Missing parameters"];
                    }
                    return [false, "Unhandled hook"];
                }
                return [false, "Locked hook"];
            }
            return [false, "Undefined hook"];
        });
    }

    /**
     * Finds a user's name by its ID.
     * @param string $id User ID
     * @return array Results
     */
    public static function findName($id)
    {
        // Check if the user's row exists
        if (self::$database->hasRow($id)[0]) {
            // Retrieve the name value
            return self::$database->get($id, self::COLUMN_NAME);
        }
        // Fallback result
        return [false, "User doesn't exist"];
    }

    /**
     * Finds a user's ID by its name.
     * @param string $name User Name
     * @return array Result
     */
    public static function findID($name)
    {
        $search = self::$database->search(self::COLUMN_NAME, $name);
        if ($search[0]) {
            if (count($search[1]) > 0) {
                return [true, $search[1][0]];
            }
            return [false, "User doesn't exist"];
        }
        // Fallback result
        return $search;
    }

    /**
     * Authenticate a user.
     * @param string $token Token
     * @return array Results
     */
    public static function validate($token)
    {
        if (self::TOKENS) {
            // Authenticate the user using tokens
            return self::$authority->validate($token, self::$configuration->permissions->validating);
        } else {
            // Authenticate the user using sessions
            return self::$database->hasLink($token);
        }
    }

    /**
     * Creates a new user.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Results
     */
    public static function signUp($name, $password)
    {
        // Check user name
        $search = self::$database->search(self::COLUMN_NAME, $name);
        if ($search[0]) {
            if (count($search[1]) === 0) {
                // Check password length
                if (strlen($password) >= self::$configuration->lengths->password) {
                    // Generate a unique user id
                    $id = self::$database->createRow();
                    if ($id[0]) {
                        // Generate salt and hash
                        $salt = Utils::randomString(self::$configuration->lengths->salt);
                        $hash = Utils::hashMessage($password . $salt);
                        // Set user information
                        self::$database->set($id[1], self::COLUMN_NAME, $name);
                        self::$database->set($id[1], self::COLUMN_SALT, $salt);
                        self::$database->set($id[1], self::COLUMN_HASH, $hash);
                        self::$database->set($id[1], self::COLUMN_LOCK, strval(0));
                        // Return a success result
                        return [true, $id[1]];
                    }
                    // Fallback result
                    return $id;
                }
                // Fallback result
                return [false, "Password too short"];
            }
            // Fallback result
            return [false, "User already exists"];
        }
        // Fallback result
        return $search;
    }

    /**
     * Create a new user token.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Result
     */
    public static function signIn($name, $password)
    {
        // Check if the user exists
        $id = self::findID($name);
        if ($id[0]) {
            // Retrieve the lock value
            $lock = self::$database->get($id[1], self::COLUMN_LOCK);
            if ($lock[0]) {
                // Verify that the user isn't locked
                if (intval($lock[1]) < time()) {
                    // Retrieve the salt and hash
                    $salt = self::$database->get($id[1], self::COLUMN_SALT);
                    $hash = self::$database->get($id[1], self::COLUMN_HASH);
                    if ($salt[0] && $hash[0]) {
                        // Check password match
                        if (Utils::hashMessage($password . $salt[1]) === $hash[1]) {
                            // Correct credentials
                            if (self::TOKENS) {
                                // Issue a new token
                                return self::$authority->issue($id[1], self::$configuration->permissions->issuing);
                            } else {
                                // Create a new session
                                return self::$database->createLink($id[1], Utils::randomString(self::$configuration->lengths->session));
                            }
                        } else {
                            // Lock the user
                            self::$database->set($id, self::COLUMN_LOCK, strval(time() + self::$configuration->lock->timeout));
                            // Return a failure result
                            return [false, "Wrong password"];
                        }
                    }
                    // Fallback result
                    return [false, "Internal error"];
                }
                // Fallback result
                return [false, "User is locked"];
            }
            // Fallback result
            return $lock;
        }
        // Fallback result
        return $id;
    }
}

/**
 * Authenticate API for notification delivery.
 */
class Manager
{
    // API string
    public const API = "manager";

    // Column names
    private const COLUMN_MESSAGES = "messages";

    // Base APIs
    private static Database $database;

    /**
     * API initializer.
     */
    public static function initialize()
    {
        // Initialize database
        self::$database = new Database(self::API);
        self::$database->createColumn(self::COLUMN_MESSAGES);
    }

    /**
     * Pushes a new message to the user.
     * @param string $id User ID
     * @param string $title Title
     * @param string $message Message
     * @return array Results
     */
    public static function push($id, $title = null, $message = null)
    {
        // Make sure the ID exists
        if (!self::$database->hasRow($id)[0]) {
            self::$database->createRow($id);
        }
        // Initialize messages array
        $messages = array();
        // Check the database
        if (self::$database->isset($id, self::COLUMN_MESSAGES)[0]) {
            $messages = json_decode(self::$database->get($id, self::COLUMN_MESSAGES)[1]);
        }
        // Create a new message object
        $messageObject = new stdClass();
        $messageObject->title = $title;
        $messageObject->message = $message;
        $messageObject->timestamp = time();
        // Push into array
        array_push($messages, $messageObject);
        // Set the messages array
        return self::$database->set($id, self::COLUMN_MESSAGES, json_encode($messages));
    }

    /**
     * Pulls the messages to the user.
     * @param string $id User ID
     * @return array Results
     */
    public static function pull($id)
    {
        // Make sure the ID exists
        if (!self::$database->hasRow($id)[0]) {
            self::$database->createRow($id);
        }
        // Initialize messages array
        $messages = array();
        // Check the database
        if (self::$database->isset($id, self::COLUMN_MESSAGES)[0]) {
            $messages = json_decode(self::$database->get($id, self::COLUMN_MESSAGES)[1]);
        }
        // Clear the messages array
        $set = self::$database->set($id, self::COLUMN_MESSAGES, json_encode(array()));
        // Check the result
        if ($set[0]) {
            return [true, $messages];
        }
        // Fallback error
        return $set;
    }
}