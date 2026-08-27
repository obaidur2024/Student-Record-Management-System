# Student Record Management System

A console-based student management system built in C.

## Features
- First-time account setup gate — forced to create admin password on first run
- SHA-256 hashed login password (never stored as plaintext)
- AES-256-CBC encryption of the student data file
- PBKDF2 (100,000 iterations) key derivation — data key is never written to disk
- Add, display, search, edit, and delete student records
- Duplicate roll number detection
- Marks validated between 0 and 100
- Login lockout: 3 failed attempts → 30-second cooldown
- Auto backup of previous encrypted file (data.enc.bak) before every save
- CSV export of current records (decrypted, on-demand only)
- Record count displayed at the top of every menu
- Menu loop — program stays open until you choose Exit
- NULL checks on all file operations (no crash on missing files)
- Wrong-key / corruption detection via AES padding check — no silent garbage reads

## What's New in v3
- Added explicit account gate — separate first-time setup flow vs login
- Added AES-256-CBC encryption for the student data file
- Added PBKDF2 key derivation from the admin password
- Moved all student records into an in-memory array; encrypt/decrypt as one block
- Rewrote addstudent, showall, searchstudent for in-memory storage
- Added login attempt lockout (3 fails → 30s wait)
- Added CSV export (menu option 5)
- Added automatic backup-before-save (data.enc.bak)
- Added record count display at the top of every menu
- Decryption failures are now detected and reported, not silently accepted
- Password change now re-encrypts the data file with the new key
- Username is fixed as "admin" — no edit option exists, by design

## What's New in v2 (carried forward)
- Fixed double fclose() crash in searchstudent() delete flow
- Fixed segfault when StudentData.txt is missing
- Password is now stored as a SHA-256 hash instead of plaintext
- Added menu loop (v1 exited after a single action)
- Added duplicate roll number check
- Added marks range validation

## How to Compile and Run

### Linux
Install OpenSSL dev headers if you don't already have them:

```
sudo apt install libssl-dev
```

Compile:

```
gcc SRM_v3.c -o SRM_v3 -lssl -lcrypto
```

Run:

```
./SRM_v3
```

### Windows (MSYS2 / MinGW)
Plain MinGW does not ship OpenSSL, so install MSYS2 first: https://www.msys2.org
Then, from the "MSYS2 MINGW64" terminal (not the plain MSYS2 terminal):

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

Compile:

```
gcc SRM_v3.c -o SRM_v3.exe -lssl -lcrypto
```

Run:

```
./SRM_v3.exe
```

## First Run
The first time you launch v3, no `password.dat` is present, so the program
forces you through first-time setup:

1. Create a new admin password (min a few characters — pick something real)
2. Confirm the password
3. A random 16-byte salt is generated and saved to `data.salt`
4. The SHA-256 hash of the password is saved to `password.dat`
5. You are sent to the normal login screen

Subsequent runs go straight to the login screen.

## Login
- User ID: `admin` (fixed, cannot be changed by design)
- Password: whatever you set during first-time setup
- 3 wrong attempts in a row → 30-second lockout, then retry

## Files Created by the Program
| File | Contents | Secret? |
| --- | --- | --- |
| `password.dat` | 65-byte SHA-256 hash of the login password | Keep private |
| `data.salt` | 16 random bytes (PBKDF2 salt) | No — public |
| `data.enc` | 16-byte IV + AES-256-CBC ciphertext of all records | Ciphertext is useless without the password |
| `data.enc.bak` | Previous version of `data.enc`, rotated on every save | Same as above |
| `students_export.csv` | Created only when you choose menu option 5 | Plaintext, your responsibility |

## About the Password
- There is no "default" password in v3. You create it on first run.
- There is no password recovery. If you forget the admin password, the
  encrypted data is unrecoverable by design. This is expected behavior
  for real encryption, not a bug.
- If you want to reset the system, delete `password.dat`, `data.salt`,
  and `data.enc` — next launch will go through first-time setup again.

## Troubleshooting

### Linux
Problem: undefined reference to `SHA256`, `PKCS5_PBKDF2_HMAC`, or `EVP_aes_256_cbc`
Fix: `-lssl -lcrypto` is missing from the gcc command. It must come after the source file.

Problem: `openssl/sha.h: No such file or directory`
Fix: `sudo apt install libssl-dev`

Problem: Login fails no matter what after upgrading from v2
Fix: v2 stored the password as plaintext. v2's `password.dat` is NOT
     compatible with v3 (different hash format). Delete the old
     `password.dat` and let v3 run first-time setup again.

### Windows
Problem: `openssl/sha.h: No such file or directory`
Fix: You're compiling with plain MinGW, which doesn't include OpenSSL.
     Install it through MSYS2 (`pacman -S mingw-w64-x86_64-openssl`) and
     compile from the MINGW64 shell.

Problem: cannot find `-lssl` or `-lcrypto`
Fix: You're in the wrong MSYS2 shell. Use "MSYS2 MINGW64", not
     "MSYS2 MSYS" — the linker paths differ.

Problem: The console window flashes and closes immediately
Fix: Don't double-click `SRM_v3.exe`. Run it from Command Prompt or
     PowerShell so the window stays open and you can read the output.

### Both platforms
Problem: "Decryption failed - data may be corrupted or password incorrect"
Fix: The salt in `data.salt` does not match the password you typed.
     Either you typed the wrong password, or `data.salt` was edited or
     replaced. If you forgot the password, the data is unrecoverable —
     delete `password.dat`, `data.salt`, and `data.enc` and start over.

Problem: "Login failed" but I'm sure the password is right
Fix: The most common cause is a leftover plaintext `password.dat` from
     v1 / v2. Delete it, then log in via first-time setup.

Problem: "Storage full. Cannot add more students."
Fix: v3 holds up to 500 students in a fixed in-memory array. This is
     a hardcoded project limit, not a bug. Edit `MAX_STUDENTS` in
     `SRM_v3.c` and recompile to raise it.

Problem: Records look corrupted or go missing after adding a student
Fix: v3 rewrites the whole encrypted file on every change. If the program
     is killed mid-write (power loss, force-quit), restore from
     `data.enc.bak` (the auto backup) and relaunch.

Problem: Compiled fine but crashes immediately on first run
Fix: Make sure the program has write access to its own folder — it
     needs to create `password.dat`, `data.salt`, and `data.enc` there.

## Security Notes
- The login password is hashed with SHA-256, never stored as plaintext.
- The student data is encrypted with AES-256-CBC.
- The data encryption key is derived from the password using PBKDF2
  (100,000 iterations) and is held only in memory for the current
  session. It is never written to any file.
- A fresh random IV is generated for every save — never reused.
- The salt (`data.salt`) and IV (inside `data.enc`) are public by design.
  Only the password is secret.
- 3 failed logins trigger a 30-second cooldown to slow brute-force guessing.
- `data.enc.bak` is rotated on every save as a one-file safety net.
- The derived key is zeroed in memory on program exit.

## Developer
Obaidur Rahman
Jamia Millia Islamia, New Delhi
Diploma - Computer Engineering
