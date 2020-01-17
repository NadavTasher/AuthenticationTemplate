<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Base API for handling requests.
 */
class API
{
    private static $result = null;

    /**
     * Creates the result JSON.
     */
    public static function init()
    {
        self::$result = new stdClass();
    }

    /**
     * Echos the result JSON.
     */
    public static function echo()
    {
        echo json_encode(self::$result);
    }

    /**
     * Handles API calls by handing them over to the callback.
     * @param string $API The API to listen to
     * @param callable $callback The callback to be called with action and parameters
     * @param bool $filter Whether to filter XSS characters
     * @return mixed|null A result array with [success, result|error]
     */
    public static function handle($API, $callback, $filter = true)
    {
        if (isset($_POST["api"])) {
            $request = $_POST["api"];
            if ($filter) {
                $request = str_replace("<", "", $request);
                $request = str_replace(">", "", $request);
            }
            $APIs = json_decode($request);
            if (isset($APIs->$API)) {
                if (isset($APIs->$API->action) &&
                    isset($APIs->$API->parameters)) {
                    if (is_string($APIs->$API->action) &&
                        is_object($APIs->$API->parameters)) {
                        $action = $APIs->$API->action;
                        $action_parameters = $APIs->$API->parameters;
                        $action_result = $callback($action, $action_parameters);
                        if (is_array($action_result)) {
                            if (count($action_result) >= 2) {
                                if (is_bool($action_result[0])) {
                                    self::$result->$API = new stdClass();
                                    self::$result->$API->success = $action_result[0];
                                    self::$result->$API->result = $action_result[1];
                                    if (count($action_result) >= 3) {
                                        return $action_result[2];
                                    } else {
                                        return $action_result;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
}

/**
 * Base API for storing user data.
 */
class Database
{
    // Root directory
    private const DIRECTORY = "database";
    // Subdirectories
    private const DIRECTORY_ROWS = self::DIRECTORY . DIRECTORY_SEPARATOR . "rows";
    private const DIRECTORY_COLUMNS = self::DIRECTORY . DIRECTORY_SEPARATOR . "columns";
    private const DIRECTORY_LINKS = self::DIRECTORY . DIRECTORY_SEPARATOR . "links";
    private const ACCESS_FILE = self::DIRECTORY . DIRECTORY_SEPARATOR . ".htaccess";
    // Properties
    private const LENGTH_ID = 32;
    private const SEPARATOR = "\n";
    // Hashing properties
    private const HASHING_ALGORITHM = "sha256";
    private const HASHING_ROUNDS = 16;

    /**
     * Validates existence of database files and directories.
     */
    public static function create()
    {
        // Check if database directories exists
        foreach ([self::DIRECTORY, self::DIRECTORY_COLUMNS, self::DIRECTORY_LINKS, self::DIRECTORY_ROWS] as $directory) {
            if (!file_exists($directory)) {
                // Create the directory
                mkdir($directory);
            } else {
                // Make sure it is a directory
                if (!is_dir($directory)) {
                    // Remove the path
                    unlink($directory);
                    // Redo the whole thing
                    self::create();
                    // Finish
                    return;
                }
            }
        }
        // Make sure the .htaccess exists
        if (!file_exists(self::ACCESS_FILE)) {
            // Write contents
            file_put_contents(self::ACCESS_FILE, "Deny from all");
        }
    }

    /**
     * Creates a new database row.
     * @return string Row ID
     */
    public static function create_row()
    {
        // Generate a row ID
        $id = self::id(32);
        // Check if the row already exists
        if (self::has_row($id)) {
            return self::create_row();
        } else {
            // Create row directory
            mkdir(self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $id);
            return $id;
        }
    }

    /**
     * Creates a new database column.
     * @param string $name Column name
     */
    public static function create_column($name)
    {
        // Generate hashed string
        $hashed = self::hash($name);
        // Check if the column already exists
        if (!self::has_column($name)) {
            // Create column directory
            mkdir(self::DIRECTORY_COLUMNS . DIRECTORY_SEPARATOR . $hashed);
        }
    }

    /**
     * Creates a new database link.
     * @param string $row Row ID
     * @param string $link Link value
     */
    public static function create_link($row, $link)
    {
        // Generate hashed string
        $hashed = self::hash($link);
        // Check if the link already exists
        if (!self::has_link($link)) {
            // Make sure the row exists
            if (self::has_row($row)) {
                // Generate link file
                file_put_contents(self::DIRECTORY_LINKS . DIRECTORY_SEPARATOR . $hashed, $row);
            }
        }
    }

    /**
     * Check whether a database row exists.
     * @param string $id Row ID
     * @return bool Exists
     */
    public static function has_row($id)
    {
        // Store path
        $path = self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $id;
        // Check if path exists and is a directory
        return file_exists($path) && is_dir($path);
    }

    /**
     * Check whether a database column exists.
     * @param string $name Column name
     * @return bool Exists
     */
    public static function has_column($name)
    {
        // Generate hashed string
        $hashed = self::hash($name);
        // Store path
        $path = self:: DIRECTORY_COLUMNS . DIRECTORY_SEPARATOR . $hashed;
        // Check if path exists and is a directory
        return file_exists($path) && is_dir($path);
    }

    /**
     * Check whether a database link exists.
     * @param string $link Link value
     * @return bool Exists
     */
    public static function has_link($link)
    {
        // Generate hashed string
        $hashed = self::hash($link);
        // Store path
        $path = self::DIRECTORY_LINKS . DIRECTORY_SEPARATOR . $hashed;
        // Check if path exists and is a file
        return file_exists($path) && is_file($path);
    }

    /**
     * Follows a link and retrieves the row ID it points to.
     * @param string $link Link value
     * @return string | null Row ID
     */
    public static function follow_link($link)
    {
        // Check if link exists
        if (self::has_link($link)) {
            // Generate hashed string
            $hashed = self::hash($link);
            // Store path
            $path = self::DIRECTORY_LINKS . DIRECTORY_SEPARATOR . $hashed;
            // Read link
            return file_get_contents($path);
        }
        return null;
    }

    /**
     * Check whether a database value exists.
     * @param string $row Row ID
     * @param string $column Column name
     * @return bool Exists
     */
    public static function isset($row, $column)
    {
        // Check if row exists
        if (self::has_row($row)) {
            // Check if the column exists
            if (self::has_column($column)) {
                // Generate hashed string
                $hashed = self::hash($column);
                // Store path
                $path = self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
                // Check if path exists and is a file
                return file_exists($path) && is_file($path);
            }
        }
        return false;
    }

    /**
     * Sets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     * @param string $value Value
     */
    public static function set($row, $column, $value)
    {
        // Remove previous values
        if (self::isset($row, $column)) {
            self::unset($row, $column);
        }
        // Check if the column exists
        if (self::has_column($column)) {
            // Create hashed string
            $hashed_name = self::hash($column);
            // Store path
            $value_path = self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
            // Create hashed string
            $hashed_value = self::hash($value);
            // Write path
            file_put_contents($value_path, $value);
            // Store new path
            $index_path = self::DIRECTORY_COLUMNS . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
            // Create rows array
            $rows = array();
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::SEPARATOR, $contents);
            }
            // Insert row to rows
            array_push($rows, $row);
            // Write contents
            file_put_contents($index_path, implode($rows, self::SEPARATOR));
        }
    }

    /**
     * Unsets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     */
    public static function unset($row, $column)
    {
        // Check if a value is already set
        if (self::isset($row, $column)) {
            // Check if the column exists
            if (self::has_column($column)) {
                // Create hashed string
                $hashed_name = self::hash($column);
                // Store path
                $value_path = self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
                // Get value & Hash it
                $value = file_get_contents($value_path);
                $hashed_value = self::hash($value);
                // Remove path
                unlink($value_path);
                // Store new path
                $index_path = self::DIRECTORY_COLUMNS . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
                // Make sure the index file exists
                if (file_exists($index_path) && is_file($index_path)) {
                    // Read contents
                    $contents = file_get_contents($index_path);
                    // Separate lines
                    $rows = explode(self::SEPARATOR, $contents);
                    // Remove row from rows
                    unset($rows[array_search($row, $rows)]);
                    // Write contents
                    file_put_contents($index_path, implode($rows, self::SEPARATOR));
                }
            }
        }
    }

    /**
     * Gets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     * @return string | null Value
     */
    public static function get($row, $column)
    {
        // Check if a value is set
        if (self::isset($row, $column)) {
            // Generate hashed string
            $hashed = self::hash($column);
            // Store path
            $path = self::DIRECTORY_ROWS . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
            // Read path
            return file_get_contents($path);
        }
        return null;
    }

    /**
     * Searches rows by column values.
     * @param string $column Column name
     * @param string $value Value
     * @return array Matching rows
     */
    public static function search($column, $value)
    {
        // Create rows array
        $rows = array();
        // Check if the column exists
        if (self::has_column($column)) {
            // Create hashed string
            $hashed_name = self::hash($column);
            // Create hashed string
            $hashed_value = self::hash($value);
            // Store new path
            $index_path = self::DIRECTORY_COLUMNS . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::SEPARATOR, $contents);
            }
        }
        return $rows;
    }

    /**
     * Creates a random ID.
     * @param int $length ID length
     * @return string ID
     */
    public static function id($length = self::LENGTH_ID)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::id($length - 1);
        }
        return "";
    }

    /**
     * Creates a hash for a given message.
     * @param string $message Message
     * @param int $layers Layers
     * @return string Hash
     */
    public static function hash($message, $layers = self::HASHING_ROUNDS)
    {
        if ($layers === 0) {
            return hash(self::HASHING_ALGORITHM, $message);
        } else {
            return hash(self::HASHING_ALGORITHM, self::hash($message, $layers - 1));
        }
    }
}