<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "Base.php";

/**
 * Authenticate API for user initialize.
 */
class Authenticate
{
    // API string
    public const API = "authenticate";

    // Column names
    private const COLUMN_SALT = "salt";
    private const COLUMN_HASH = "hash";
    private const COLUMN_LOCK = "lock";

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
        self::$configuration = json_decode(file_get_contents(Base::file("configuration.json", self::API)));
        // Make sure the database is initiated.
        self::$database = new Database(self::API);
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
                        if (isset($parameters->token) &&
                            is_string($parameters->token)) {
                            return self::validate($parameters->token);
                        }
                        return [false, "Parameter error"];
                    } else if ($action === "signIn") {
                        // Authenticate the user using the password, return the new session
                        if (isset($parameters->name) &&
                            isset($parameters->password) &&
                            is_string($parameters->name) &&
                            is_string($parameters->password)) {
                            return self::signIn($parameters->name, $parameters->password);
                        }
                        return [false, "Parameter error"];
                    } else if ($action === "signUp") {
                        // Create a new user
                        if (isset($parameters->name) && isset($parameters->password) && is_string($parameters->name) && is_string($parameters->password)) {
                            return self::signUp($parameters->name, $parameters->password);
                        }
                        return [false, "Parameter error"];
                    }
                    return [false, "Unhandled hook"];
                }
                return [false, "Locked hook"];
            }
            return [false, "Undefined hook"];
        });
    }

    /**
     * Authenticate a user.
     * @param string $token token
     * @return array Results
     */
    public static function validate($token)
    {
        // Authenticate the user using tokens
        return self::$authority->validate($token);
    }

    /**
     * Creates a new user.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Results
     */
    public static function signUp($name, $password)
    {
        // Validate inputs
        if (strlen($name) >= self::$configuration->lengths->name) {
            if (strlen($password) >= self::$configuration->lengths->password) {
                // Create user ID
                $userID = bin2hex($name);
                // Try inserting a row
                if (self::$database->insertEntry($userID)[0]) {
                    // Generate salt and hash
                    $salt = Base::random(self::$configuration->lengths->salt);
                    $hash = hash("sha256", $password . $salt);
                    $time = strval(0);
                    // Set user information
                    self::$database->insertValue($userID, self::COLUMN_SALT, $salt);
                    self::$database->insertValue($userID, self::COLUMN_HASH, $hash);
                    self::$database->insertValue($userID, self::COLUMN_LOCK, $time);
                    // Return a success result
                    return [true, $userID];
                }
                // Fallback result
                return [false, "User already exists"];
            }
            // Fallback result
            return [false, "Password too short"];
        }
        // Fallback result
        return [false, "Name too short"];
    }

    /**
     * Create a new user token.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Result
     */
    public static function signIn($name, $password)
    {
        // Create user ID
        $userID = bin2hex($name);
        // Check if the user exists
        if (self::$database->checkEntry($userID)[0]) {
            // Fetch database values
            $lock = self::$database->fetchValue($userID, self::COLUMN_LOCK);
            $salt = self::$database->fetchValue($userID, self::COLUMN_SALT);
            $hash = self::$database->fetchValue($userID, self::COLUMN_HASH);
            // Validate answers
            if ($lock[0] && $salt[0] && $hash[0]) {
                // Verify that the user isn't locked
                if (intval($lock[1]) < time()) {
                    // Check password match
                    if (hash("sha256", $password . $salt[1]) === $hash[1]) {
                        // Issue a new token
                        return self::$authority->issue($userID);
                    } else {
                        // Calculate new lock time
                        $time = strval(time() + 10);
                        // Lock the user
                        self::$database->insertValue($userID, self::COLUMN_LOCK, $time);
                        // Return a failure result
                        return [false, "Wrong password"];
                    }
                }
                // Fallback result
                return [false, "User is locked"];
            }
            // Fallback result
            return [false, "User is invalid"];
        }
        // Fallback result
        return [false, "User does not exist"];
    }
}