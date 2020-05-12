<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

include_once __DIR__ . DIRECTORY_SEPARATOR . "Authority.php";
include_once __DIR__ . DIRECTORY_SEPARATOR . "Database.php";

/**
 * Base API for general utilities.
 */
class Base
{

    // Constants
    public const API = "base";

    // Directory root
    private const DIRECTORY_ROOT = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files";

    // Directory delimiter
    private const DIRECTORY_DELIMITER = ":";

    /**
     * Handles API calls by handing them over to the callback.
     * @param callable $callback Callback to handle the request
     */
    public static function handle($callback)
    {
        // Initialize the response
        $result = new stdClass();
        // Initialize the action
        if (count($_GET) > 0) {
            // Get the action
            $requestAction = array_key_first($_GET);
            // Parse the parameters
            $requestParameters = new stdClass();
            // Loop over GET parameters
            foreach ($_GET as $name => $value) {
                if (is_string($value))
                    $requestParameters->$name = $value;
            }
            // Loop over POST parameters
            foreach ($_POST as $name => $value) {
                if (is_string($value))
                    $requestParameters->$name = $value;
            }
            // Unset the action
            unset($requestParameters->$requestAction);
            // Execute the call
            $requestResult = $callback($requestAction, $requestParameters);
            // Parse the results
            if (is_array($requestResult)) {
                if (count($requestResult) === 2) {
                    if (is_bool($requestResult[0])) {
                        // Set status
                        $result->status = $requestResult[0];
                        // Set result
                        $result->result = $requestResult[1];
                    }
                }
            }
        }
        // Change the response type
        header("Content-Type: application/json");
        // Echo response
        echo json_encode($result);
    }

    /**
     * Returns a writable path for a name.
     * @param string $name Path name
     * @param string $base Base directory
     * @return string Path
     */
    public static function path($name, $base = self::DIRECTORY_ROOT)
    {
        // Split name
        $split = explode(self::DIRECTORY_DELIMITER, $name, 2);
        // Check if we have to create a sub-path
        if (count($split) > 1) {
            // Append first path to the base
            $base = $base . DIRECTORY_SEPARATOR . $split[0];
            // Make sure the path exists
            if (!file_exists($base)) {
                mkdir($base);
            }
            // Return the path
            return self::path($split[1], realpath($base));
        }
        // Return the last path
        return $base . DIRECTORY_SEPARATOR . $name;
    }

    /**
     * Returns a writable file path for a name.
     * @param string $name File name
     * @param string $hostAPI Host API
     * @param string $guestAPI Guest API
     * @return string File path
     */
    public static function file($name = "", $hostAPI = self::API, $guestAPI = null)
    {
        // Add APIs
        $name = implode(self::DIRECTORY_DELIMITER, [$hostAPI, $guestAPI, $name]);
        // Return the path
        return self::path($name);
    }

    /**
     * Returns a writable directory path for a name.
     * @param string $name Directory name
     * @param string $hostAPI Host API
     * @param string $guestAPI Guest API
     * @return string Directory path
     */
    public static function directory($name = "", $hostAPI = self::API, $guestAPI = null)
    {
        // Find parent directory
        $directory = self::file($name, $hostAPI, $guestAPI);
        // Make sure the subdirectory exists
        if (!file_exists($directory)) mkdir($directory);
        // Return the directory path
        return $directory;
    }

    /**
     * Creates a random string.
     * @param int $length String length
     * @return string String
     */
    public static function random($length = 0)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::random($length - 1);
        }
        return "";
    }
}