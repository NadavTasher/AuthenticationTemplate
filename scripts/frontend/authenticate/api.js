/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Initialize endpoint
const AUTHENTICATE_ENDPOINT = "scripts/backend/authenticate/authenticate.php";

// Initialize api
const AUTHENTICATE_API = "authenticate";

// Initialize session cookie
const AUTHENTICATE_SESSION_COOKIE = "session";

let last_callback = null;

function authentication(callback = last_callback) {
    // Setup last_callback
    last_callback = callback;
    // View the authentication panel
    view("authenticate");
    // Check authentication
    if (authenticate_cookie_exists(AUTHENTICATE_SESSION_COOKIE)) {
        hide("authenticate-inputs");
        authenticate_output("Hold on - Authenticating...");
        api(AUTHENTICATE_ENDPOINT, AUTHENTICATE_API, "authenticate", {}, (success, result, error) => {
            if (success) {
                hide("authenticate");
                if (callback !== null) {
                    callback();
                }
            } else {
                show("authenticate-inputs");
                authenticate_output(error, true);
            }
        }, authenticate());
    }
}

function authenticate(form = body()) {
    if (authenticate_cookie_exists(AUTHENTICATE_SESSION_COOKIE)) {
        form = body(AUTHENTICATE_API, "authenticate", {
            session: authenticate_cookie_pull(AUTHENTICATE_SESSION_COOKIE)
        }, form);
    }
    return form;
}

function authenticate_sign_up() {
    hide("authenticate-inputs");
    authenticate_output("Hold on - Signing you up...");
    api(AUTHENTICATE_ENDPOINT, AUTHENTICATE_API, "signup", {
        name: get("authenticate-name").value,
        password: get("authenticate-password").value
    }, (success, result, error) => {
        if (success) {
            authenticate_sign_in();
        } else {
            show("authenticate-inputs");
            authenticate_output(error, true);
        }
    });
}

function authenticate_sign_in() {
    hide("authenticate-inputs");
    authenticate_output("Hold on - Signing you in...");
    api(AUTHENTICATE_ENDPOINT, AUTHENTICATE_API, "signin", {
        name: get("authenticate-name").value,
        password: get("authenticate-password").value
    }, (success, result, error) => {
        if (success) {
            authenticate_cookie_push(AUTHENTICATE_SESSION_COOKIE, result);
            authentication();
        } else {
            show("authenticate-inputs");
            authenticate_output(error, true);
        }
    });
}

function authenticate_sign_out() {
    authenticate_cookie_push(AUTHENTICATE_SESSION_COOKIE, undefined);
}

function authenticate_output(text, error = false) {
    let output = get("authenticate-output");
    output.innerText = text;
    if (error) {
        output.style.setProperty("color", "red");
    } else {
        output.style.removeProperty("color");
    }
}

function authenticate_cookie_pull(name) {
    name += "=";
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
        let cookie = cookies[i];
        while (cookie.charAt(0) === " ") {
            cookie = cookie.substring(1);
        }
        if (cookie.indexOf(name) === 0) {
            return decodeURIComponent(cookie.substring(name.length, cookie.length));
        }
    }
    return undefined;
}

function authenticate_cookie_push(name, value) {
    const date = new Date();
    date.setTime(value !== undefined ? date.getTime() + (365 * 24 * 60 * 60 * 1000) : 0);
    document.cookie = name + "=" + encodeURIComponent(value) + ";expires=" + date.toUTCString() + ";domain=" + window.location.hostname + ";path=/";
}

function authenticate_cookie_exists(name) {
    return authenticate_cookie_pull(name) !== undefined;
}