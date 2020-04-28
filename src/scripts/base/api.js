/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/BaseTemplate/
 **/

/**
 * Prepares the web page (loads ServiceWorker).
 * @param callback Function to be executed when loading finishes
 */
if (typeof window !== typeof undefined) {
    window.prepare = function (callback = null) {
        // Register worker
        if ("serviceWorker" in navigator) {
            navigator.serviceWorker.register("worker.js", {scope: "./"}).then((registration) => {
                window.worker = registration.active;
            });
        }
        // Callback
        if (callback !== null)
            callback();
    };
}

/**
 * Base API for sending requests.
 */
class API {

    /**
     * Sends an API call.
     * @param endpoint API to call
     * @param action Action
     * @param parameters Parameters
     * @param callback Callback
     */
    static call(endpoint = null, action = null, parameters = null, callback = null) {
        // Create a form
        let form = new FormData();
        // Append parameters to form
        for (let key in parameters) {
            if (parameters.hasOwnProperty(key))
                form.append(key, parameters[key]);
        }
        // Perform the request
        fetch("apis/" + endpoint + "/" + "?" + action, {
            method: "post",
            body: form
        }).then(response => response.text().then((result) => {
            // Try to parse the result as JSON
            try {
                let API = JSON.parse(result);
                // Check the result's integrity
                if (API.hasOwnProperty("status") && API.hasOwnProperty("result")) {
                    // Call the callback with the result
                    callback(API["status"] === true, API["result"]);
                } else {
                    // Call the callback with an error
                    callback(false, "API response malformed");
                }
            } catch (ignored) {
            }
        }));
    }

}

/**
 * Base API for creating the UI.
 */
class UI {

    /**
     * Returns a view by its ID or by it's own value.
     * @param v View
     * @returns {HTMLElement} View
     */
    static find(v) {
        if (typeof "" === typeof v || typeof '' === typeof v) {
            // ID lookup
            if (document.getElementById(v) !== undefined) {
                return document.getElementById(v);
            }
            // Query lookup
            if (document.querySelector(v) !== undefined) {
                return document.querySelector(v);
            }
        }
        // Return the input
        return v;
    }

    /**
     * Hides a given view.
     * @param v View
     */
    static hide(v) {
        // Set style to none
        this.find(v).setAttribute("hidden", "true");
    }

    /**
     * Shows a given view.
     * @param v View
     */
    static show(v) {
        // Set style to original value
        this.find(v).setAttribute("hidden", "false");
    }

    /**
     * Shows a given view while hiding it's brothers.
     * @param v View
     */
    static view(v) {
        // Store view
        let element = this.find(v);
        // Store parent
        let parent = element.parentNode;
        // Hide all
        for (let child of parent.children) {
            this.hide(child);
        }
        // Show view
        this.show(element);
    }

    /**
     * Sets a given target as the only visible part of the page.
     * @param target View
     */
    static page(target) {
        // Store current target
        let temporary = this.find(target);
        // Recursively get parent
        while (temporary.parentNode !== document.body && temporary.parentNode !== document.body) {
            // View temporary
            this.view(temporary);
            // Set temporary to it's parent
            temporary = temporary.parentNode;
        }
        // View temporary
        this.view(temporary);
    }

    /**
     * Removes all children of a given view.
     * @param v View
     */
    static clear(v) {
        // Store view
        let view = this.find(v);
        // Remove all views
        view.innerHTML = "";
    }

    /**
     * Finds a template and populates a clone of it.
     * @param template Template name
     * @param parameters Cloning parameters
     */
    static populate(template, parameters = {}) {
        // Find the template
        let templateElement = this.find(template);
        // Create the element
        let created = templateElement.cloneNode(true);
        // Add the HTML
        let html = created.innerHTML;
        // Replace parameters
        for (let key in parameters) {
            if (key in parameters) {
                let search = "${" + key + "}";
                let value = parameters[key];
                // Sanitize value
                let sanitizer = document.createElement("p");
                sanitizer.innerText = value;
                value = sanitizer.innerHTML;
                // Replace
                while (html.includes(search))
                    html = html.replace(search, value);
            }
        }
        created.innerHTML = html;
        // Return created element
        return created.content;
    }

}