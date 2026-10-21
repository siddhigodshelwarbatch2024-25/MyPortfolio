const bcrypt = require("bcryptjs");

if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    console.error("Run this in an interactive terminal so password input stays hidden.");
    process.exit(1);
}

process.stdout.write("Owner password (input hidden): ");
process.stdin.setEncoding("utf8");
process.stdin.setRawMode(true);
process.stdin.resume();
let password = "";

function finish() {
    process.stdin.setRawMode(false);
    process.stdin.pause();
    process.stdin.removeListener("data", onData);
}

function onData(character) {
    if (character === "\u0003") {
        finish();
        process.stdout.write("\nCancelled.\n");
        process.exit(1);
    }
    if (character === "\r" || character === "\n") {
        finish();
        process.stdout.write("\n");
        if (password.length < 12) {
            console.error("Use a password with at least 12 characters.");
            process.exit(1);
        }
        console.log(bcrypt.hashSync(password, 12));
        password = "";
        return;
    }
    if (character === "\u007f" || character === "\b") {
        password = password.slice(0, -1);
    } else if (character >= " ") {
        password += character;
    }
}

process.stdin.on("data", onData);