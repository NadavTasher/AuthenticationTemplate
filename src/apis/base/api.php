<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Base API for handling requests.
 */
class Base
{
    // Constants
    public const API = "base";

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
}

/**
 * Base API for utility functions.
 */
class Utility
{
    // Directory root
    private const DIRECTORY_ROOT = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files";

    // Directory delimiter
    private const DIRECTORY_DELIMITER = ":";

    /**
     * Returns a writable path for a name.
     * @param string $name Path name
     * @param string $base Base directory
     * @return string Path
     */
    public static function evaluatePath($name, $base = self::DIRECTORY_ROOT)
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
            return self::evaluatePath($split[1], realpath($base));
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
    public static function evaluateFile($name = "", $hostAPI = Base::API, $guestAPI = null)
    {
        // Add APIs
        $name = implode(self::DIRECTORY_DELIMITER, [$hostAPI, $guestAPI, $name]);
        // Return the path
        return self::evaluatePath($name);
    }

    /**
     * Returns a writable directory path for a name.
     * @param string $name Directory name
     * @param string $hostAPI Host API
     * @param string $guestAPI Guest API
     * @return string Directory path
     */
    public static function evaluateDirectory($name = "", $hostAPI = Base::API, $guestAPI = null)
    {
        // Find parent directory
        $directory = self::evaluateFile($name, $hostAPI, $guestAPI);
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

/**
 * Base API for storing user data.
 */
class Database
{
    // Constants
    public const API = "database";

    private const LENGTH = 32;

    // Guest API
    private string $API;

    /**
     * Database constructor.
     * @param string $API API name
     */
    public function __construct($API = Base::API)
    {
        $this->API = $API;
    }

    /**
     * Inserts a new database entry.
     * @param null $entry Entry ID
     * @return array Result
     */
    public function insertEntry($entry = null)
    {
        // Generate a row ID
        if ($entry === null) {
            $entry = Utility::random(self::LENGTH);
        }
        // Check existence
        $entryCheck = $this->checkEntry($entry);
        // Make sure the entry does not exist
        if (!$entryCheck[0]) {
            // Extract the path
            $entryPath = Utility::evaluateFile("$entry", self::API, $this->API);
            // Create the path
            mkdir($entryPath);
            // Return success
            return [true, $entry];
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Check whether a database entry exists.
     * @param string $entry Row ID
     * @return array Result
     */
    public function checkEntry($entry)
    {
        // Create the path
        $entryPath = Utility::evaluateFile("$entry", self::API, $this->API);
        // Check existence
        if (file_exists($entryPath) && is_dir($entryPath)) {
            // Return success
            return [true, null];
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Removes a database entry.
     * @param string $entry Entry ID
     * @return array Results
     */
    public function removeEntry($entry)
    {
        // Check existence
        $entryCheck = $this->checkEntry($entry);
        // Make sure the entry exists
        if ($entryCheck[0]) {
            // Create entry path
            $entryPath = Utility::evaluateFile("$entry", self::API, $this->API);
            // Scan entry directory
            $values = array_slice(scandir($entryPath), 2);
            // Loop over set columns
            foreach ($values as $value) {
                // Unset value
                unlink(Utility::evaluatePath($value, $entryPath));
            }
            // Remove the path
            rmdir($entryPath);
            // Return success
            return [true, null];
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Sets a database value.
     * @param string $entry Entry ID
     * @param string $key Key
     * @param string $value Value
     * @return array Result
     */
    public function insertValue($entry, $key, $value)
    {
        // Check existence
        $entryCheck = $this->checkEntry($entry);
        // Make sure the entry exists
        if ($entryCheck[0]) {
            // Extract entry path
            $valuePath = Utility::evaluateFile("$entry:$key", self::API, $this->API);
            // Write value
            file_put_contents($valuePath, $value);
            // Return success
            return [true, null];
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Fetches a database value.
     * @param string $entry Entry ID
     * @param string $key Key
     * @return array Result
     */
    public function fetchValue($entry, $key)
    {
        // Check existence
        $entryCheck = $this->checkEntry($entry);
        // Make sure the entry exists
        if ($entryCheck[0]) {
            // Create value path
            $valuePath = Utility::evaluateFile("$entry:$key", self::API, $this->API);
            // Make sure the value path exists
            if (file_exists($valuePath) && is_file($valuePath)) {
                // Return success
                return [true, file_get_contents($valuePath)];
            }
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Removes a database value.
     * @param string $entry Entry ID
     * @param string $key Key
     * @return array Result
     */
    public function removeValue($entry, $key)
    {
        // Check existence
        $rowCheck = $this->checkEntry($entry);
        // Make sure the entry exists
        if ($rowCheck[0]) {
            // Create value path
            $valuePath = Utility::evaluateFile("$entry:$key", self::API, $this->API);
            // Make sure the value path exists
            if (file_exists($valuePath) && is_file($valuePath)) {
                // Remove value
                unlink($valuePath);
                // Return success
                return [true, null];
            }
        }
        // Fallback result
        return [false, null];
    }

    /**
     * Searches for entries by values.
     * @param string $key Key
     * @param string $value Value
     * @return array Results
     */
    public function searchEntry($key, $value)
    {
        // Initialize the results array
        $array = array();
        // List rows
        $entries = scandir(Utility::evaluateFile("", self::API, $this->API));
        $entries = array_slice($entries, 2);
        // Loop through
        foreach ($entries as $entry) {
            // Check value match
            $fetch = $this->fetchValue($entry, $key);
            // Make sure fetch was successful
            if ($fetch[0]) {
                if ($value === $fetch[1]) {
                    array_push($array, $entry);
                }
            }
        }
        // Return success
        return [true, $array];
    }
}

/**
 * Base API for issuing and validating tokens.
 */
class Authority
{
    // Constants
    public const API = "authority";

    private const LENGTH = 512;
    private const VALIDITY = 31 * 24 * 60 * 60;
    private const SEPARATOR = ":";

    // Guest API
    private string $API;

    /**
     * Authority constructor.
     * @param string $API API name
     */
    public function __construct($API = Base::API)
    {
        $this->API = $API;
        // Create secret
        $keyPath = Utility::evaluateFile($this->API, self::API);
        // Check existence
        if (!(file_exists($keyPath) && is_file($keyPath))) {
            // Create the secret file
            file_put_contents($keyPath, Utility::random(self::LENGTH));
        }
    }

    /**
     * Creates a token.
     * @param string | stdClass | array $data Data
     * @param float | int $validity Validity time
     * @return array Result
     */
    public function issue($data, $validity = self::VALIDITY)
    {
        // Create token object
        $tokenObject = new stdClass();
        $tokenObject->data = $data;
        $tokenObject->expiry = time() + intval($validity);
        // Create token string
        $tokenString = bin2hex(json_encode($tokenObject));
        // Calculate signature
        $tokenSignature = hash_hmac("sha256", $tokenString, file_get_contents(Utility::evaluateFile($this->API, self::API)));
        // Create parts
        $tokenSlices = [$tokenString, $tokenSignature];
        // Combine all into token
        $token = implode(self::SEPARATOR, $tokenSlices);
        // Return combined message
        return [true, $token];
    }

    /**
     * Validates a token.
     * @param string $token Token
     * @return array Validation result
     */
    public function validate($token)
    {
        // Separate string
        $tokenSlices = explode(self::SEPARATOR, $token);
        // Validate content count
        if (count($tokenSlices) === 2) {
            // Store parts
            $tokenString = $tokenSlices[0];
            $tokenSignature = $tokenSlices[1];
            // Validate signature
            if (hash_hmac("sha256", $tokenString, file_get_contents(Utility::evaluateFile($this->API, self::API))) === $tokenSignature) {
                // Parse token object
                $tokenObject = json_decode(hex2bin($tokenString));
                // Validate existence
                if (isset($tokenObject->data) &&
                    isset($tokenObject->expiry)) {
                    // Validate expiry
                    if (time() < $tokenObject->expiry) {
                        // Return token
                        return [true, $tokenObject->data];
                    }
                    // Fallback error
                    return [false, "Invalid token expiry"];
                }
                // Fallback error
                return [false, "Invalid token structure"];
            }
            // Fallback error
            return [false, "Invalid token signature"];
        }
        // Fallback error
        return [false, "Invalid token format"];
    }
}