<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

$result = new stdClass();

/**
 * This function handles API calls by handing them over to the callback.
 * @param string $api The API to listen to
 * @param callable $callback The callback to be called with action and parameters
 * @param bool $filter Whether to filter XSS characters
 * @return mixed|null A result array with [success, result|error]
 */
function api($api, $callback, $filter = true)
{
    if (isset($_POST[$api])) {
        $content = $_POST[$api];
        if ($filter) $content = filter($content);
        $information = json_decode($content);
        if (isset($information->action) && isset($information->parameters)) {
            $action = $information->action;
            $parameters = $information->parameters;
            $return = $callback($action, $parameters);
            if (is_array($return)) {
                if (count($return) >= 2) {
                    $success = $return[0];
                    $clientResult = $return[1];
                    $serverResult = count($return) >= 3 ? $return[2] : null;
                    if (is_bool($success)) {
                        if ($success) {
                            success($api, $action, true);
                            result($api, $action, $clientResult);
                            return $serverResult !== null ? $serverResult : $clientResult;
                        } else {
                            success($api, $action, false, $clientResult);
                            result($api, $action, null);
                            return $serverResult !== null ? $serverResult : null;
                        }
                    }
                }
            }
        }
    }
    return null;
}

/**
 * This function filters XSS characters.
 * @param string $source The original string
 * @return string The filtered string
 */
function filter($source)
{
    $source = str_replace("<", "", $source);
    $source = str_replace(">", "", $source);
    return $source;
}

/**
 * This function writes to the $result object.
 * @param string $api The API to write to
 * @param string $type The data type to write
 * @param string $key The data key
 * @param string $value The data value
 */
function put($api, $type, $key, $value)
{
    global $result;
    if (!isset($result->$api)) $result->$api = new stdClass();
    if (!isset($result->$api->$type)) $result->$api->$type = new stdClass();
    $result->$api->$type->$key = $value;
}

/**
 * This function generates a random string by the given length, with a complexity of 36^$length.
 * @param int $length Length of random
 * @return string Random string
 */
function random($length)
{
    $current = str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0];
    if ($length > 0) {
        return $current . random($length - 1);
    }
    return "";
}

/**
 * This function reports the result of the action.
 * @param string $api The API to write to
 * @param string $action The API call's action
 * @param mixed|null $result The API call's result
 */
function result($api, $action, $result)
{
    put($api, "result", $action, $result);
}

/**
 * This function reports the success of the action.
 * @param string $api The API to write to
 * @param string $action The API call's action
 * @param bool $success Whether the API call was successful
 * @param string $error The API call's error
 */
function success($api, $action, $success = true, $error = "Unknown Error")
{
    if ($success) {
        put($api, "status", $action, true);
    } else {
        put($api, "status", $action, $error);
    }
}