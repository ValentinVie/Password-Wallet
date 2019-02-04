# swallet443

In this assignment you will build an encrypted password wallet program. The user will enter and modify passwords.

```
USAGE: swallet [-h] [-v]  [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - verbose output

     - wallet file to manage
    [create|add|del|show|chpw] - is a command to execute, where

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)
```

Program notes:
- The wallet is secured through the use of a single master password. It should be initially supplied and confirmed by the user entering it twice and comparing the results during the create operation. All HMACs and encryption of data will be performed using this password.

- The user should be prompted to enter the password before performing any action on a previously created wallet. The program should read the wallet file and check the HMAC using the entered password. If the HMAC does not validate using the entered password, then the program should abort with an error saying bad password.
- You should used "encoding/base64" package for encoding and the "crypto" package for all cryptographic functions (hashing, encrypting, etc.).
- The wallet password (wk) is converted into a 128-bit AES key by taking the top most 128 bits (16 bytes) of a SHA1 hash of the password, e.g., wk = trunc(16,SHA1(password)).
- All passwords to be included in the wallet should be encrypted using 128-bit AES. To encrypt, the password should be left-padded with a unique salt value and right-padded out to 32 bytes with null characters (for example, if the password was 10 characters long, you should pad 22 null (char(0x0)) on the right. More specifically, the password should look like AES(wk,saltn|pwd_n|0x0|0x0...).
- The wallet itself must only contain printable ASCII characters. Thus, all salts and encrypted passwords must be base-64 encoded in the file.
- All input should use the some text based UI library. When input is required, the terminal should blank and each input datum should be entered, with appropriate prompt, one per line, starting from the first line. For a sampling of UIs, see Go language text UIs (Links to an external site.)Links to an external site..
- Password characters should not be echoed to the terminal.
- Each time the wallet is modified, the system time and generation number should be updated. The system time is the local system time (as returned by {time.Now()). The generation number is the number of times the file has been modified. This number should begin at 1 and incremented by 1 for each modification. The wallet file will print these value as in plaintext (human readable text) on the first line.
The fields of the file are separated using a pair of pipe symbols (ASCII 0x7c), e.g., "||''.
- The HMAC for the file should appear as the last line of the file and be base 64 encoded.
