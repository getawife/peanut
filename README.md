# Peanut

```
 ████████_,------,
 ████████_|   /\_/\     Hi, I am peanut!
 ████████^|__( ^.^ )    :3 purrr nyan
           ""  ""
```

## Install

    1. Download `peanut.exe` from the Releases page, or build it yourself (see below).
    2. Open PowerShell in the folder that holds it and run `.\peanut.exe install`.
    4. Open a new terminal. Now `peanut` works from anywhere.

## Use

| Command                        | What it does                                               |
| ------------------------------ | ---------------------------------------------------------- |
| `peanut allow_apps [app name]` | Search your Start Menu and allow an app (password needed)  |
| `peanut remove_apps`           | Take an app off the list (password needed)                 |
| `peanut open`                  | Start one of your allowed apps                             |
| `peanut lock`                  | Lock. Other apps close after 20 seconds, so save your work |
| `peanut unlock`                | Unlock (password needed)                                   |
| `peanut reset_password`        | Change your password (old password needed)                 |
| `peanut force_unlock`          | Forgot your password? Unlocks after a 5 minute wait        |
| `peanut security_question`     | Add or change your security question (password needed)     |
| `peanut status`                | Show what is going on                                      |
| `peanut uninstall`             | Remove Peanut (password needed, must be unlocked)          |

## Build

Needs Go 1.22 or newer.

```
.\build.ps1
```

## License

MIT
