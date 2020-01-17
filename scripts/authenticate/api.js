/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

/**
 * Authenticate API for user authentication.
 */
class Authenticate {

    static AUTHENTICATE_API = "authenticate";

    static AUTHENTICATE_SESSION_COOKIE = "session";

    static last_callback = null;

    /**
     * Authenticates the user by requiring signup, signin and session validation.
     * @param callback Post authentication callback
     */
    static authentication(callback = Authenticate.last_callback) {
        // Setup last_callback
        Authenticate.last_callback = callback;
        // View the authentication panel
        UI.page("authenticate");
        // Check authentication
        if (Authenticate.authenticate_cookie_exists(Authenticate.AUTHENTICATE_SESSION_COOKIE)) {
            // Hide the inputs
            UI.hide("authenticate-inputs");
            // Change the output message
            Authenticate.authenticate_output("Hold on - Authenticating...");
            // Send the API call
            API.send(Authenticate.AUTHENTICATE_API, "authenticate", {}, (success, result) => {
                if (success) {
                    // Change the page
                    UI.page("authenticated");
                    // Run the callback
                    if (callback !== null) {
                        callback();
                    }
                } else {
                    // Show the inputs
                    UI.show("authenticate-inputs");
                    // Change the output message
                    Authenticate.authenticate_output(result, true);
                }
            }, Authenticate.authenticate());
        }
    }

    /**
     * Compiles an authenticated API hook.
     * @param APIs Inherited APIs
     * @return {Object} API list
     */
    static authenticate(APIs = API.hook()) {
        // Check if the session cookie exists
        if (Authenticate.authenticate_cookie_exists(Authenticate.AUTHENTICATE_SESSION_COOKIE)) {
            // Compile the API hook
            APIs = API.hook(Authenticate.AUTHENTICATE_API, "authenticate", {
                session: Authenticate.authenticate_cookie_pull(Authenticate.AUTHENTICATE_SESSION_COOKIE)
            }, APIs);
        }
        return APIs;
    }

    /**
     * Sends a signup API call and handles the results.
     */
    static authenticate_sign_up() {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        Authenticate.authenticate_output("Hold on - Signing you up...");
        // Send the API call
        API.send(Authenticate.AUTHENTICATE_API, "signup", {
            name: UI.get("authenticate-name").value,
            password: UI.get("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Call the signin function
                Authenticate.authenticate_sign_in();
            } else {
                // Show the inputs
                UI.show("authenticate-inputs");
                // Change the output message
                Authenticate.authenticate_output(result, true);
            }
        });
    }

    /**
     * Sends a signin API call and handles the results.
     */
    static authenticate_sign_in() {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        Authenticate.authenticate_output("Hold on - Signing you in...");
        // Send the API call
        API.send(Authenticate.AUTHENTICATE_API, "signin", {
            name: UI.get("authenticate-name").value,
            password: UI.get("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Push the session cookie
                Authenticate.authenticate_cookie_push(Authenticate.AUTHENTICATE_SESSION_COOKIE, result);
                // Call the authentication function
                Authenticate.authentication();
            } else {
                // Show the inputs
                UI.show("authenticate-inputs");
                // Change the output message
                Authenticate.authenticate_output(result, true);
            }
        });
    }

    /**
     * Signs the user out.
     */
    static authenticate_sign_out() {
        // Push 'undefined' to the session cookie
        Authenticate.authenticate_cookie_push(Authenticate.AUTHENTICATE_SESSION_COOKIE, undefined);
    }

    /**
     * Changes the output message.
     * @param text Output message
     * @param error Is the message an error?
     */
    static authenticate_output(text, error = false) {
        // Store the output view
        let output = UI.get("authenticate-output");
        // Set the output message
        output.innerText = text;
        // Check if the message is an error
        if (error) {
            // Set the text color to red
            output.style.setProperty("color", "red");
        } else {
            // Clear the text color
            output.style.removeProperty("color");
        }
    }

    /**
     * Pulls a cookie.
     * @param name Cookie name
     * @return {string|undefined} Cookie value
     */
    static authenticate_cookie_pull(name) {
        // Create a handle
        let handle = name + "=";
        // Loop over cookies
        for (let cookie of document.cookie.split(";")) {
            // Remove whitespaces
            while (cookie.charAt(0) === " ")
                cookie = cookie.substring(1);
            // Check if the cookie begins with our handle
            if (cookie.indexOf(handle) === 0) {
                // Substring our cookie
                cookie = cookie.substring(handle.length, cookie.length);
                // Decode and return
                return decodeURIComponent(cookie);
            }
        }
        // Return the default 'undefined'
        return undefined;
    }

    /**
     * Pushes a cookie.
     * @param name Cookie name
     * @param value Cookie value
     */
    static authenticate_cookie_push(name, value) {
        let date = new Date();
        if (value !== undefined) {
            // Expires in one year
            date.setTime(date.getTime() + (365 * 24 * 60 * 60 * 1000));
        } else {
            // Expired already
            date.setTime(0);
        }
        // Push the cookie
        document.cookie = name + "=" + encodeURIComponent(value) + ";expires=" + date.toUTCString() + ";domain=" + window.location.hostname + ";";
    }

    /**
     * Returns whether a cookie exists.
     * @param name Cookie name
     * @return {boolean} Exists
     */
    static authenticate_cookie_exists(name) {
        // Check if the value of the cookie is different then 'undefined'
        return Authenticate.authenticate_cookie_pull(name) !== undefined;
    }
}