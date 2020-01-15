<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Base API for handling requests.
 */

$result = new stdClass();

/**
 * Handles API calls by handing them over to the callback.
 * @param string $API The API to listen to
 * @param callable $callback The callback to be called with action and parameters
 * @param bool $filter Whether to filter XSS characters
 * @return mixed|null A result array with [success, result|error]
 */
function api($API, $callback, $filter = true)
{
    global $result;
    if (isset($_POST["api"])) {
        $request = $_POST["api"];
        if ($filter)
            $request = filter($request);
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

/**
 * Filters XSS characters.
 * @param string $source Source
 * @return string Filtered source
 */
function filter($source)
{
    $source = str_replace("<", "", $source);
    $source = str_replace(">", "", $source);
    return $source;
}

/**
 * Database API for storing user data.
 */

const DATABASE_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files" . DIRECTORY_SEPARATOR . "database";

const DATABASE_ROWS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "rows";
const DATABASE_COLUMNS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "columns";
const DATABASE_LINKS_DIRECTORY = DATABASE_DIRECTORY . DIRECTORY_SEPARATOR . "links";

const DATABASE_ID_LENGTH = 32;
const DATABASE_SEPARATOR = "\n";

const DATABASE_HASHING_ALGORITHM = "sha256";
const DATABASE_HASHING_LAYERS = 16;

/**
 * Creates a new database row.
 * @return string Row ID
 */
function database_create_row()
{
    // Generate a row ID
    $id = database_id(32);
    // Check if the row already exists
    if (database_has_row($id)) {
        return database_create_row();
    } else {
        // Create row directory
        mkdir(DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $id);
        return $id;
    }
}

/**
 * Creates a new database column.
 * @param string $name Column name
 */
function database_create_column($name)
{
    // Generate hashed string
    $hashed = database_hash($name);
    // Check if the column already exists
    if (!database_has_column($name)) {
        // Create column directory
        mkdir(DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed);
    }
}

/**
 * Creates a new database link.
 * @param string $row Row ID
 * @param string $link Link value
 */
function database_create_link($row, $link)
{
    // Generate hashed string
    $hashed = database_hash($link);
    // Check if the link already exists
    if (!database_has_link($link)) {
        // Make sure the row exists
        if (database_has_row($row)) {
            // Generate link file
            file_put_contents(DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed, $row);
        }
    }
}

/**
 * Check whether a database row exists.
 * @param string $id Row ID
 * @return bool Exists
 */
function database_has_row($id)
{
    // Store path
    $path = DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $id;
    // Check if path exists and is a directory
    return file_exists($path) && is_dir($path);
}

/**
 * Check whether a database column exists.
 * @param string $name Column name
 * @return bool Exists
 */
function database_has_column($name)
{
    // Generate hashed string
    $hashed = database_hash($name);
    // Store path
    $path = DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
    // Check if path exists and is a directory
    return file_exists($path) && is_dir($path);
}

/**
 * Check whether a database link exists.
 * @param string $link Link value
 * @return bool Exists
 */
function database_has_link($link)
{
    // Generate hashed string
    $hashed = database_hash($link);
    // Store path
    $path = DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
    // Check if path exists and is a file
    return file_exists($path) && is_file($path);
}

/**
 * Follows a link and retrieves the row ID it points to.
 * @param string $link Link value
 * @return string | null Row ID
 */
function database_follow_link($link)
{
    // Check if link exists
    if (database_has_link($link)) {
        // Generate hashed string
        $hashed = database_hash($link);
        // Store path
        $path = DATABASE_LINKS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed;
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
function database_isset($row, $column)
{
    // Check if row exists
    if (database_has_row($row)) {
        // Check if the column exists
        if (database_has_column($column)) {
            // Generate hashed string
            $hashed = database_hash($column);
            // Store path
            $path = DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
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
function database_set($row, $column, $value)
{
    // Remove previous values
    if (database_isset($row, $column)) {
        database_unset($row, $column);
    }
    // Check if the column exists
    if (database_has_column($column)) {
        // Create hashed string
        $hashed_name = database_hash($column);
        // Store path
        $value_path = DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
        // Create hashed string
        $hashed_value = database_hash($value);
        // Write path
        file_put_contents($value_path, $value);
        // Store new path
        $index_path = DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
        // Create rows array
        $rows = array();
        // Make sure the index file exists
        if (file_exists($index_path) && is_file($index_path)) {
            // Read contents
            $contents = file_get_contents($index_path);
            // Separate lines
            $rows = explode(DATABASE_SEPARATOR, $contents);
        }
        // Insert row to rows
        array_push($rows, $row);
        // Write contents
        file_put_contents($index_path, implode($rows, DATABASE_SEPARATOR));
    }
}

/**
 * Unsets a database value.
 * @param string $row Row ID
 * @param string $column Column name
 */
function database_unset($row, $column)
{
    // Check if a value is already set
    if (database_isset($row, $column)) {
        // Check if the column exists
        if (database_has_column($column)) {
            // Create hashed string
            $hashed_name = database_hash($column);
            // Store path
            $value_path = DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed_name;
            // Get value & Hash it
            $value = file_get_contents($value_path);
            $hashed_value = database_hash($value);
            // Remove path
            unlink($value_path);
            // Store new path
            $index_path = DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(DATABASE_SEPARATOR, $contents);
                // Remove row from rows
                unset($rows[array_search($row, $rows)]);
                // Write contents
                file_put_contents($index_path, implode($rows, DATABASE_SEPARATOR));
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
function database_get($row, $column)
{
    // Check if a value is set
    if (database_isset($row, $column)) {
        // Generate hashed string
        $hashed = database_hash($column);
        // Store path
        $path = DATABASE_ROWS_DIRECTORY . DIRECTORY_SEPARATOR . $row . DIRECTORY_SEPARATOR . $hashed;
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
function database_search($column, $value)
{
    // Create rows array
    $rows = array();
    // Check if the column exists
    if (database_has_column($column)) {
        // Create hashed string
        $hashed_name = database_hash($column);
        // Create hashed string
        $hashed_value = database_hash($value);
        // Store new path
        $index_path = DATABASE_COLUMNS_DIRECTORY . DIRECTORY_SEPARATOR . $hashed_name . DIRECTORY_SEPARATOR . $hashed_value;
        // Make sure the index file exists
        if (file_exists($index_path) && is_file($index_path)) {
            // Read contents
            $contents = file_get_contents($index_path);
            // Separate lines
            $rows = explode(DATABASE_SEPARATOR, $contents);
        }
    }
    return $rows;
}

/**
 * Creates a random ID.
 * @param int $length ID length
 * @return string ID
 */
function database_id($length = DATABASE_ID_LENGTH)
{
    if ($length > 0) {
        return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . database_id($length - 1);
    }
    return "";
}

/**
 * Creates a hash for a given message.
 * @param string $message Message
 * @param int $layers Layers
 * @return string Hash
 */
function database_hash($message, $layers = DATABASE_HASHING_LAYERS)
{
    if ($layers === 0) {
        return hash(DATABASE_HASHING_ALGORITHM, $message);
    } else {
        return hash(DATABASE_HASHING_ALGORITHM, database_hash($message, $layers - 1));
    }
}