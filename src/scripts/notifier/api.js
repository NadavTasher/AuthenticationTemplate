/**
 * Copyright (c) 2020 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Base API for notification delivery.
 */
class Notifier {

    /**
     * Start the push loop.
     */
    static init(callback = null) {
        // Start the interval
        setInterval(() => {
            this.checkout(callback);
        }, 60 * 1000);
    }

    /**
     * Sends an API call to register a new ID for notification delivery.
     */
    static register() {
        // Send a call
        API.send("notifier", "register", {}, (success, result) => {
            if (success) {
                // Save to path storage
                PathStorage.setItem("notifier", result);
            }
        });
    }

    /**
     * Fetches the latest messages from the notification delivery API.
     */
    static checkout(callback = null) {
        // Fetch token
        let token = PathStorage.getItem("notifier");
        // Validate the token
        if (token !== null && Authority.validate(token)[0]) {
            // Checkout
            API.send("notifier", "checkout", {
                token: token
            }, (success, result) => {
                if (success) {
                    // Send notifications
                    if (callback !== null) {
                        for (let message of result) {
                            callback(message);
                        }
                    }
                } else {
                    this.register();
                }
            });
        } else {
            // Register
            this.register();
        }
    }

}