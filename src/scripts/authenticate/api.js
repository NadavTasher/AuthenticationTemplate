/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

/**
 * Authenticate API for user authentication.
 */
window.Authenticate = class {

    /**
     * Authenticates the user by requiring signup, signin and session validation.
     * @param callback Post authentication callback
     */
    static authentication(callback = null) {
        // View the authentication panel
        window.UI.page("authenticate");
        // Check authentication
        let token = window.PathStorage.getItem("authenticate");
        if (token !== null) {
            // Hide the inputs
            window.UI.hide("authenticate-inputs");
            // Change the output message
            this.output("Hold on - Authenticating...");
            // Send the API call
            window.API.call("authenticate", this.authenticate((success, result) => {
                if (success) {
                    // Change the page
                    window.UI.page("authenticated");
                    // Run the callback
                    if (callback !== null) {
                        callback();
                    }
                } else {
                    // Show the inputs
                    window.UI.show("authenticate-inputs");
                    // Change the output message
                    this.output(result, true);
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
        let token = window.PathStorage.getItem("authenticate");
        if (token !== null) {
            // Compile the API hook
            APIs = window.API.hook("authenticate", "authenticate", {
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
        window.UI.hide("authenticate-inputs");
        // Change the output message
        this.output("Hold on - Signing you up...");
        // Send the API call
        window.API.send("authenticate", "signup", {
            name: window.UI.find("authenticate-name").value,
            password: window.UI.find("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Call the signin function
                this.sign_in(callback);
            } else {
                // Show the inputs
                window.UI.show("authenticate-inputs");
                // Change the output message
                this.output(result, true);
            }
        });
    }

    /**
     * Sends a signin API call and handles the results.
     */
    static sign_in(callback = null) {
        // Hide the inputs
        window.UI.hide("authenticate-inputs");
        // Change the output message
        this.output("Hold on - Signing you in...");
        // Send the API call
        window.API.send("authenticate", "signin", {
            name: window.UI.find("authenticate-name").value,
            password: window.UI.find("authenticate-password").value
        }, (success, result) => {
            if (success) {
                // Push the session cookie
                window.PathStorage.setItem("authenticate", result);
                // Call the authentication function
                this.authentication(callback);
            } else {
                // Show the inputs
                window.UI.show("authenticate-inputs");
                // Change the output message
                this.output(result, true);
            }
        });
    }

    /**
     * Signs the user out.
     */
    static sign_out() {
        // Push 'undefined' to the session cookie
        window.PathStorage.removeItem("authenticate");
    }

    /**
     * Changes the output message.
     * @param text Output message
     * @param error Is the message an error?
     */
    static output(text, error = false) {
        // Store the output view
        let output = window.UI.find("authenticate-output");
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

};