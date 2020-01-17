<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

$result = new stdClass();

/**
 * Base API for handling requests.
 */
class API
{
    /**
     * Handles API calls by handing them over to the callback.
     * @param string $API The API to listen to
     * @param callable $callback The callback to be called with action and parameters
     * @param bool $filter Whether to filter XSS characters
     * @return mixed|null A result array with [success, result|error]
     */
    public static function handle($API, $callback, $filter = true)
    {
        global $result;
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
                                    $result->$API = new stdClass();
                                    $result->$API->success = $action_result[0];
                                    $result->$API->result = $action_result[1];
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
    private const DATABASE_DIRECTORY = "database";
    // Subdirectories
    private const DATABASE_ROWS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "rows";
    private const DATABASE_COLUMNS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "columns";
    private const DATABASE_LINKS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "links";
    private const DATABASE_ACCESS_FILE = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . ".htaccess";
    // Properties
    private const DATABASE_ID_LENGTH = 32;
    private const DATABASE_SEPARATOR = "\n";
    // Hashing properties
    private const DATABASE_HASHING_ALGORITHM = "sha256";
    private const DATABASE_HASHING_LAYERS = 16;

    /**
     * Validates existence of database files and directories.
     */
    public static function database_create()
    {
        // Check if database directories exists
        foreach ([self::DATABASE_DIRECTORY, self::DATABASE_COLUMNS_DIRECTORY, self::DATABASE_LINKS_DIRECTORY, self::DATABASE_ROWS_DIRECTORY] as $directory) {
            if (!file_exists($directory)) {
                // Create the directory
                mkdir($directory);
            } else {
                // Make sure it is a directory
                if (!is_dir($directory)) {
                    // Remove the path
                    unlink($directory);
                    // Redo the whole thing
                    self::database_create();
                    // Finish
                    return;
                }
            }
        }
        // Make sure the .htaccess exists
        if (!file_exists(self::DATABASE_ACCESS_FILE)) {
            // Write contents
            file_put_contents(self::DATABASE_ACCESS_FILE, "Deny from all");
        }
    }

    /**
     * Creates a new database row.
     * @return string Row ID
     */
    public static function database_create_row()
    {
        // Generate a row ID
        $id = self::database_id(32);
        // Check if the row already exists
        if (self::database_has_row($id)) {
            return self::database_create_row();
        } else {
            // Create row directory
            mkdir(self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $id);
            return $id;
        }
    }

    /**
     * Creates a new database column.
     * @param string $name Column name
     */
    public static function database_create_column($name)
    {
        // Generate hashed string
        $hashed = self::database_hash($name);
        // Check if the column already exists
        if (!self::database_has_column($name)) {
            // Create column directory
            mkdir(self::DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed);
        }
    }

    /**
     * Creates a new database link.
     * @param string $row Row ID
     * @param string $link Link value
     */
    public static function database_create_link($row, $link)
    {
        // Generate hashed string
        $hashed = self::database_hash($link);
        // Check if the link already exists
        if (!self::database_has_link($link)) {
            // Make sure the row exists
            if (self::database_has_row($row)) {
                // Generate link file
                file_put_contents(self::DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed, $row);
            }
        }
    }

    /**
     * Check whether a database row exists.
     * @param string $id Row ID
     * @return bool Exists
     */
    public static function database_has_row($id)
    {
        // Store path
        $path = self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $id;
        // Check if path exists and is a directory
        return file_exists($path) && is_dir($path);
    }

    /**
     * Check whether a database column exists.
     * @param string $name Column name
     * @return bool Exists
     */
    public static function database_has_column($name)
    {
        // Generate hashed string
        $hashed = self::database_hash($name);
        // Store path
        $path = self:: DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
        // Check if path exists and is a directory
        return file_exists($path) && is_dir($path);
    }

    /**
     * Check whether a database link exists.
     * @param string $link Link value
     * @return bool Exists
     */
    public static function database_has_link($link)
    {
        // Generate hashed string
        $hashed = self::database_hash($link);
        // Store path
        $path = self::DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
        // Check if path exists and is a file
        return file_exists($path) && is_file($path);
    }

    /**
     * Follows a link and retrieves the row ID it points to.
     * @param string $link Link value
     * @return string | null Row ID
     */
    public static function database_follow_link($link)
    {
        // Check if link exists
        if (self::database_has_link($link)) {
            // Generate hashed string
            $hashed = self::database_hash($link);
            // Store path
            $path = self::DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
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
    public static function database_isset($row, $column)
    {
        // Check if row exists
        if (self::database_has_row($row)) {
            // Check if the column exists
            if (self::database_has_column($column)) {
                // Generate hashed string
                $hashed = self::database_hash($column);
                // Store path
                $path = self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
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
    public static function database_set($row, $column, $value)
    {
        // Remove previous values
        if (self::database_isset($row, $column)) {
            self::database_unset($row, $column);
        }
        // Check if the column exists
        if (self::database_has_column($column)) {
            // Create hashed string
            $hashed_name = self::database_hash($column);
            // Store path
            $value_path = self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
            // Create hashed string
            $hashed_value = self::database_hash($value);
            // Write path
            file_put_contents($value_path, $value);
            // Store new path
            $index_path = self::DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
            // Create rows array
            $rows = array();
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::DATABASE_SEPARATOR, $contents);
            }
            // Insert row to rows
            array_push($rows, $row);
            // Write contents
            file_put_contents($index_path, implode($rows, self::DATABASE_SEPARATOR));
        }
    }

    /**
     * Unsets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     */
    public static function database_unset($row, $column)
    {
        // Check if a value is already set
        if (self::database_isset($row, $column)) {
            // Check if the column exists
            if (self::database_has_column($column)) {
                // Create hashed string
                $hashed_name = self::database_hash($column);
                // Store path
                $value_path = self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
                // Get value & Hash it
                $value = file_get_contents($value_path);
                $hashed_value = self::database_hash($value);
                // Remove path
                unlink($value_path);
                // Store new path
                $index_path = self::DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
                // Make sure the index file exists
                if (file_exists($index_path) && is_file($index_path)) {
                    // Read contents
                    $contents = file_get_contents($index_path);
                    // Separate lines
                    $rows = explode(self::DATABASE_SEPARATOR, $contents);
                    // Remove row from rows
                    unset($rows[array_search($row, $rows)]);
                    // Write contents
                    file_put_contents($index_path, implode($rows, self::DATABASE_SEPARATOR));
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
    public static function database_get($row, $column)
    {
        // Check if a value is set
        if (self::database_isset($row, $column)) {
            // Generate hashed string
            $hashed = self::database_hash($column);
            // Store path
            $path = self::DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
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
    public static function database_search($column, $value)
    {
        // Create rows array
        $rows = array();
        // Check if the column exists
        if (self::database_has_column($column)) {
            // Create hashed string
            $hashed_name = self::database_hash($column);
            // Create hashed string
            $hashed_value = self::database_hash($value);
            // Store new path
            $index_path = self::DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::DATABASE_SEPARATOR, $contents);
            }
        }
        return $rows;
    }

    /**
     * Creates a random ID.
     * @param int $length ID length
     * @return string ID
     */
    public static function database_id($length = self::DATABASE_ID_LENGTH)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::database_id($length - 1);
        }
        return "";
    }

    /**
     * Creates a hash for a given message.
     * @param string $message Message
     * @param int $layers Layers
     * @return string Hash
     */
    public static function database_hash($message, $layers = self::DATABASE_HASHING_LAYERS)
    {
        if ($layers === 0) {
            return hash(DATABASE_HASHING_ALGORITHM, $message);
        } else {
            return hash(DATABASE_HASHING_ALGORITHM, self::database_hash($message, $layers - 1));
        }
    }
}