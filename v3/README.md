# Student Record Management System

A console-based student management system built in C.

## Features
- Account gate — username AND password are both chosen at setup and both hashed with SHA-256
- Student data encrypted at rest with AES-256-CBC (no more plaintext StudentData.txt)
- Encryption key derived from your login password via PBKDF2 (100000 iterations) — never stored anywhere
- Add student records (rejects duplicate roll numbers)
- Display all records
- Search student by roll number
- Edit and delete student records
- Change password (re-encrypts all existing data with the new key automatically)
- Menu loop — program stays open until you choose Exit
- Marks validated between 0 and 100
- NULL checks on all file operations (no crash on missing files)

## What's New in v3
- Added account gate — username is chosen at first-time setup, no more hardcoded "admin"
- Wrong username and wrong password now give one combined error (stops username enumeration)
- Student data is now AES-256-CBC encrypted in data.enc instead of stored as plaintext in StudentData.txt
- Encryption key is derived from your password with PBKDF2, never written to disk
- Fresh random IV generated on every save
- Decryption failure (wrong password / corrupted file) is now detected and reported, not silently accepted
- Records are now held in memory during the session and encrypted as one block on save — this also removes the double fclose() risk that was still lurking around the old fseek-based edit/delete flow
- Changing your password now re-encrypts existing data with the new key, so you're never locked out by a stale key

## How to Compile and Run

### Linux
Install OpenSSL dev headers if you don't already have them:

sudo apt install libssl-dev

Compile:

gcc SRM_v3.c -o SRM_v3 -lssl -lcrypto

Run:

./SRM_v3

### Windows (MSYS2 / MinGW)
Plain MinGW does not ship OpenSSL, so install MSYS2 first: https://www.msys2.org
Then, from the "MSYS2 MINGW64" terminal (not the plain MSYS2 terminal):

pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl

Compile:

gcc SRM_v3.c -o SRM_v3.exe -lssl -lcrypto

Run:

./SRM_v3.exe

## First-Time Setup
There is no default login anymore. On first run (when password.dat doesn't exist), the program asks you to
choose a username and a password. Both are hashed with SHA-256 and saved to password.dat, and a random
salt is generated and saved to data.salt for deriving the AES key on future logins.

Remember your password. It is never stored anywhere, and it's the only thing your encrypted data can be
recovered with — if you forget it, the records in data.enc cannot be recovered by anyone, including you.

## Troubleshooting

### Linux
Problem: undefined reference to SHA256 (or EVP_EncryptInit_ex / PKCS5_PBKDF2_HMAC)
Fix: -lssl -lcrypto is missing from the gcc command. It must come after the source file.

Problem: openssl/sha.h or openssl/evp.h: No such file or directory
Fix: sudo apt install libssl-dev

Problem: Upgrading from v2 and login/setup behaves strangely
Fix: v2's password.dat only holds one hash, v3's holds two (username + password). Delete the old files first:
rm password.dat StudentData.txt

### Windows
Problem: openssl/sha.h or openssl/evp.h: No such file or directory
Fix: You're compiling with plain MinGW, which doesn't include OpenSSL. Install it through MSYS2 (pacman -S mingw-w64-x86_64-openssl) and compile from the MINGW64 shell.

Problem: cannot find -lssl or -lcrypto
Fix: You're in the wrong MSYS2 shell. Use "MSYS2 MINGW64", not "MSYS2 MSYS" — the linker paths differ.

Problem: The console window flashes and closes immediately
Fix: Don't double-click SRM_v3.exe. Run it from Command Prompt or PowerShell so the window stays open and you can read the output.

Problem: Upgrading from v2 and login/setup behaves strangely
Fix: Same as Linux — delete the old password.dat and StudentData.txt before running v3.

### Both platforms
Problem: "Decryption failed - data may be corrupted or password incorrect"
Fix: Almost always a wrong password. Can also mean data.salt or data.enc got mixed up between two different
setups — they must belong to the same account. If neither applies, the file may genuinely be corrupted.

Problem: "Error: salt file missing. Cannot decrypt data."
Fix: data.salt was deleted or moved. Without it the AES key can't be regenerated and data.enc is unreadable —
there is no way around this by design.

Problem: Records look corrupted or go missing after adding a student
Fix: Close data.enc if it's open in another program. Windows can lock the file while it's open elsewhere. Also
avoid killing the program mid-save.

Problem: Compiled fine but crashes immediately on first run
Fix: Make sure the program has write access to its own folder — it needs to create password.dat, data.salt,
and data.enc there.

Problem: I forgot my password
Fix: There is no recovery. You can delete password.dat and data.salt to start a fresh account, but the old
data.enc will be unreadable forever — that's the trade-off of real encryption, not a bug.

## Developer
Obaidur Rahman
Jamia Millia Islamia, New Delhi
2nd Year Diploma - Computer Engineering
