<?php

/**
 * Copyright (c) 2020 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

/**
 * Base API for notification delivery.
 */
class Notifier
{
    // API string
    private const API = "notifier";
    // Column names
    private const COLUMN_MESSAGES = "messages";
    // Base APIs
    private static Database $database;
    private static Authority $authority;

    /**
     * API initializer.
     */
    public static function init()
    {
        // Initialize database
        self::$database = new Database(self::API);
        self::$database->create_column(self::COLUMN_MESSAGES);
        // Initialize authority
        self::$authority = new Authority(self::API);
    }

    /**
     * Main API hook.
     */
    public static function handle()
    {
        // Init API
        self::init();
        // Return the result
        return API::handle(Notifier::API, function ($action, $parameters) {
            // Handle actions
            if ($action === "register") {
                $id = self::register();
                // Make sure we got an ID
                if ($id[0]) {
                    // Issue a new token
                    return self::issue($id[1]);
                }
                // Fallback error
                return $id;
            } else if ($action === "checkout") {
                if (isset($parameters->token)) {
                    if (is_string($parameters->token)) {
                        // Make sure the token is valid
                        $id = self::validate($parameters->token);
                        // Check validation
                        if ($id[0]) {
                            // Checkout
                            return self::checkout($id[1]);
                        }
                        // Fallback error
                        return $id;
                    }
                    return [false, "Incorrect type"];
                }
                return [false, "Missing parameters"];
            }
            // Fallback error
            return [false, "Undefined hook"];
        }, true);
    }

    /**
     * Registers a new ID.
     */
    public static function register()
    {
        // Create a new database row
        $id = self::$database->create_row();
        // Make sure we got an ID
        if ($id[0]) {
            // Checkout
            $checkout = self::checkout($id[1]);
            // Make sure we set the value
            if ($checkout[0]) {
                // Issue a token
                return [true, $id[1]];
            }
            // Return fallback error
            return $checkout;
        }
        // Return fallback error
        return $id;
    }

    /**
     * Notify the ID with a new message.
     * @param string $id Registration ID
     * @param string $message Message
     * @return array Results
     */
    public static function notify($id, $message)
    {
        // Initialize messages array
        $messages = array();
        // Check the database
        if (self::$database->isset($id, self::COLUMN_MESSAGES)[0]) {
            $messages = json_decode(self::$database->get($id, self::COLUMN_MESSAGES)[1]);
        }
        // Push into array
        array_push($messages, $message);
        // Set the messages array
        return self::$database->set($id, self::COLUMN_MESSAGES, json_encode($messages));
    }

    /**
     * Fetches the latest messages for the ID and clears the database.
     * @param string $id Registration ID
     * @return array Results
     */
    public static function checkout($id)
    {
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

    /**
     * Issue a new valid checkout token.
     * @param string $id Registration ID
     * @return array Results
     */
    public static function issue($id)
    {
        return self::$authority->issue($id);
    }

    /**
     * Validate an existing checkout token.
     * @param string $token Token
     * @return array Results
     */
    public static function validate($token)
    {
        return self::$authority->validate($token);
    }
}