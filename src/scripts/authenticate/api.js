/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

const AUTHENTICATE_API = "authenticate";

/**
 * Authenticate API for user initialize.
 */
class Authenticate {

    static token = null;

    /**
     * Authenticates the user by requiring signup, signin and session validation.
     * @param callback Post initialize callback
     */
    static initialize(callback = null) {
        // Load the token
        this.token = localStorage.getItem(AUTHENTICATE_API);
        // View the initialize panel
        UI.page("authenticate");
        // Check initialize
        if (this.token !== null) {
            // Hide the inputs
            UI.hide("authenticate-inputs");
            // Change the output message
            this.output("Hold on - Authenticating...");
            // Send the API call
            API.call(AUTHENTICATE_API, "validate", {
                token: this.token
            }).then(result => {
                // Change the page
                UI.page("authenticated");
                // Run the callback
                if (callback !== null) {
                    callback();
                }
            }).catch(result => {
                // Show the inputs
                UI.show("authenticate-inputs");
                // Change the output message
                this.output(result, true);
            });
        }
    }

    /**
     * Sends a signup API call and handles the results.
     */
    static signUp(callback = null) {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        this.output("Hold on - Signing you up...");
        // Send the API call
        API.call(AUTHENTICATE_API, "signUp", {
            name: UI.find("authenticate-name").value,
            password: UI.find("authenticate-password").value
        }).then(result => {
            // Call the signin function
            this.signIn(callback);
        }).catch(result => {
            // Show the inputs
            UI.show("authenticate-inputs");
            // Change the output message
            this.output(result, true);
        });
    }

    /**
     * Sends a signin API call and handles the results.
     */
    static signIn(callback = null) {
        // Hide the inputs
        UI.hide("authenticate-inputs");
        // Change the output message
        this.output("Hold on - Signing you in...");
        // Send the API call
        API.call(AUTHENTICATE_API, "signIn", {
            name: UI.find("authenticate-name").value,
            password: UI.find("authenticate-password").value
        }).then(result => {
            // Push the token
            localStorage.setItem(AUTHENTICATE_API, this.token = result);
            // Call the initialize function
            this.initialize(callback);
        }).catch(result => {
            // Show the inputs
            UI.show("authenticate-inputs");
            // Change the output message
            this.output(result, true);
        });
    }

    /**
     * Signs the user out.
     */
    static signOut() {
        // Push 'undefined' to the session cookie
        localStorage.removeItem(AUTHENTICATE_API);
    }

    /**
     * Changes the output message.
     * @param text Output message
     * @param error Is the message an error?
     */
    static output(text, error = false) {
        // Store the output view
        let output = UI.find("authenticate-output");
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