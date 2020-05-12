<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

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
        $keyPath = Base::file($this->API, self::API);
        // Check existence
        if (!(file_exists($keyPath) && is_file($keyPath))) {
            // Create the secret file
            file_put_contents($keyPath, Base::random(self::LENGTH));
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
        $tokenSignature = hash_hmac("sha256", $tokenString, file_get_contents(Base::file($this->API, self::API)));
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
            if (hash_hmac("sha256", $tokenString, file_get_contents(Base::file($this->API, self::API))) === $tokenSignature) {
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