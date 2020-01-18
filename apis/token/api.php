<?php

/**
 * Copyright (c) 2020 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

/**
 * Authenticate API for creating and verifying tokens.
 */
class Token
{
    // Configuration properties
    private const CONFIGURATION_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . "configuration";
    private const ACCESS_FILE = self::CONFIGURATION_DIRECTORY . DIRECTORY_SEPARATOR . ".htaccess";
    // Secret properties
    private const SECRET_FILE = self::CONFIGURATION_DIRECTORY . DIRECTORY_SEPARATOR . "secret";
    private const LENGTH_SECRET = 512;
    // Token properties
    private const VALIDITY_TOKEN = 31 * 24 * 60 * 60;
    private const SEPARATOR_PARTS = "&";
    private const SEPARATOR_HASH = "#";
    // Hashing properties
    private const HASHING_ALGORITHM = "sha256";
    private const HASHING_ROUNDS = 1024;

    /**
     * Makes sure a configuration directory exists, and creates a shared secret.
     */
    private static function prepare()
    {
        // Make sure configuration directory exists
        if (!file_exists(self::CONFIGURATION_DIRECTORY)) {
            // Create the directory
            mkdir(self::CONFIGURATION_DIRECTORY);
        } else {
            // Make sure it is a directory
            if (!is_dir(self::CONFIGURATION_DIRECTORY)) {
                // Remove the path
                unlink(self::CONFIGURATION_DIRECTORY);
                // Redo the whole thing
                self::prepare();
                // Finish
                return;
            }
        }
        // Make sure a shared secret exists
        if (!file_exists(self::SECRET_FILE)) {
            // Create the secret file
            file_put_contents(self::SECRET_FILE, self::random(self::LENGTH_SECRET));
        }
        // Make sure the .htaccess exists
        if (!file_exists(self::ACCESS_FILE)) {
            // Write contents
            file_put_contents(self::ACCESS_FILE, "Deny from all");
        }
    }

    /**
     * Returns the shared secret.
     * @return string Secret
     */
    private static function secret()
    {
        // Make sure the secret file exists
        self::prepare();
        // Read secret file
        return file_get_contents(self::SECRET_FILE);
    }

    /**
     * Creates a token.
     * @param string $API Issuing API
     * @param string $contents Token contents
     * @param float | int $validity Token validity time
     * @return string Token
     */
    public static function issue($API, $contents, $validity = self::VALIDITY_TOKEN)
    {
        // Prepare secret
        self::prepare();
        // Calculate expiry time
        $time = time() + intval($validity);
        // Create token string
        $string = bin2hex($API) . self::SEPARATOR_PARTS . bin2hex($contents) . self::SEPARATOR_PARTS . bin2hex(strval($time));
        // Calculate signature
        $signature = self::hash($string, self::secret());
        // Return combined message
        return $string . self::SEPARATOR_HASH . $signature;
    }

    /**
     * Validates a token.
     * @param string $API Issuing API
     * @param string $token Token
     * @return array Validation result
     */
    public static function validate($API, $token)
    {
        // Prepare secret
        self::prepare();
        // Separate string
        $contents = explode(self::SEPARATOR_HASH, $token);
        // Validate content count
        if (count($contents) === 2) {
            // Validate signature
            if (self::hash($contents[0], self::secret()) === $contents[1]) {
                // Validate time
                $parts = explode(self::SEPARATOR_PARTS, $contents[0]);
                // Validate part count
                if (count($parts) === 3) {
                    // Validate issuer
                    if (hex2bin($parts[0]) === $API) {
                        // Check against time
                        $time = intval(hex2bin($parts[2]));
                        if ($time > time()) {
                            // Return token contents
                            return [true, hex2bin($parts[1])];
                        }
                        return [false, "Token expired"];
                    }
                    return [false, "Invalid token issuer"];
                }
                return [false, "Invalid token format"];
            }
            return [false, "Invalid token signature"];
        }
        return [false, "Invalid token format"];
    }

    /**
     * HMACs a message.
     * @param string $message Message
     * @param string $secret Shared secret
     * @param int $rounds Number of rounds
     * @return string HMACed
     */
    private static function hash($message, $secret, $rounds = self::HASHING_ROUNDS)
    {
        // Layer > 0 result
        if ($rounds > 0) {
            $layer = self::hash($message, $secret, $rounds - 1);
            $return = hash_hmac(self::HASHING_ALGORITHM, $layer, $secret);
        } else {
            // Layer 0 result
            $return = hash_hmac(self::HASHING_ALGORITHM, $message, $secret);
        }
        return $return;
    }

    /**
     * Creates a random string.
     * @param int $length String length
     * @return string String
     */
    private static function random($length = 0)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::random($length - 1);
        }
        return "";
    }
}