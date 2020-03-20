/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

/**
 * Authenticate API for user authentication.
 */
class Authenticate {
    /**
     * Authenticates the user by requiring signup, signin and session validation.
     * @param callback Post authentication callback
     */
    static authentication(callback = null) {
        // View the authentication panel
        UI.page("authenticate");
        // Check authentication
        let token = window.localStorage.getItem("token");
        if (token !== null) {
            // Hide the inputs
            UI.hide("authenticate-inputs");
            // Change the output message
            Authenticate.output("Hold on - Authenticating...");
            // Send the API call
            API.call("authenticate", Authenticate.authenticate((success, result) => {
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
                    Authenticate.output(result, true);
                }
            }));
        }
    }

    /**
     * Compiles an authenticated API hook.
     * @param callback Callback
     * @param APIs Inherited APIs
     * @return API list
     */
    static authenticate(callback = null, APIs = API.hook()) {
        // Check if the session cookie exists
        let token = window.localStorage.getItem("token");
        if (token !== null) {
            // Compile the API hook
            APIs = API.hook("authenticate", "authenticate", {
                token: token
            }, callback, APIs);
        }
        return APIs;
    }

    /**
     * Sends a signup API call and handles the results.
     */
    static sign_up(callback = null) {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        Authenticate.output("Hold on - Signing you up...");
        // Send the API call
        API.send("authenticate", "signup", {
            name: UI.get("authenticate-name").value,
            password: UI.get("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Call the signin function
                Authenticate.sign_in(callback);
            } else {
                // Show the inputs
                UI.show("authenticate-inputs");
                // Change the output message
                Authenticate.output(result, true);
            }
        });
    }

    /**
     * Sends a signin API call and handles the results.
     */
    static sign_in(callback = null) {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        Authenticate.output("Hold on - Signing you in...");
        // Send the API call
        API.send("authenticate", "signin", {
            name: UI.get("authenticate-name").value,
            password: UI.get("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Push the session cookie
                window.localStorage.setItem("token", result);
                // Call the authentication function
                Authenticate.authentication(callback);
            } else {
                // Show the inputs
                UI.show("authenticate-inputs");
                // Change the output message
                Authenticate.output(result, true);
            }
        });
    }

    /**
     * Signs the user out.
     */
    static sign_out() {
        // Push 'undefined' to the session cookie
        window.localStorage.removeItem("token");
    }

    /**
     * Changes the output message.
     * @param text Output message
     * @param error Is the message an error?
     */
    static output(text, error = false) {
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
}