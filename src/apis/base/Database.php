<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Base API for storing user data.
 */
class Database
{
    // Constants
    public const API = "database";

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
            $entry = Base::random(32);
        }
        // Check existence
        $entryCheck = $this->checkEntry($entry);
        // Make sure the entry does not exist
        if (!$entryCheck[0]) {
            // Extract the path
            $entryPath = Base::file("$entry", self::API, $this->API);
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
        $entryPath = Base::file("$entry", self::API, $this->API);
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
            $entryPath = Base::file("$entry", self::API, $this->API);
            // Scan entry directory
            $values = array_slice(scandir($entryPath), 2);
            // Loop over set columns
            foreach ($values as $value) {
                // Unset value
                unlink(Base::path($value, $entryPath));
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
            $valuePath = Base::file("$entry:$key", self::API, $this->API);
            // Write value
            file_put_contents($valuePath, json_encode($value));
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
            $valuePath = Base::file("$entry:$key", self::API, $this->API);
            // Make sure the value path exists
            if (file_exists($valuePath) && is_file($valuePath)) {
                // Return success
                return [true, json_decode(file_get_contents($valuePath))];
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
            $valuePath = Base::file("$entry:$key", self::API, $this->API);
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
        $entries = scandir(Base::file("", self::API, $this->API));
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