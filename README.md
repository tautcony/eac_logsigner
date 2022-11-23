# EAC Log Signer

This is a transparent implementation of the Exact Audio Copy log checksum algorithm in C#. Includes an option to fix those pesky edited logs.

# Installation

Download from the [releases page](https://github.com/tautcony/eac_logsigner/releases) and extract the zip file. Run the executable.

# Usage

```
EAC Log Signer 1.0.0
Copyright (c) 2022 TautCony

  verify     Verify a log

  sign       Sign or fix an existing log

  help       Display more information on a specific command.

  version    Display version information.
```

# Example

    $ eac_logsigner sign bad.log good.log
    $ eac_logsigner verify *.log
    log1.log:  OK
    log2.log:  OK
    log3.log:  Malformed


# Algorithm

 1. Strip the log file of newlines and BOMs.
 2. Cut off the existing signature block and (re-)encode the log text back into little-endian UTF-16
 3. Encrypt the log file with Rijndael-256:
    - in CBC mode
    - with a 256-bit block size (most AES implementations hard-code a 128-bit block size)
    - all-zeroes IV
    - zero-padding
    - the hex key `9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9`
 4. XOR together all of the resulting 256-bit ciphertext blocks. You can do it byte-by-byte, it doesn't matter in the end.
 5. Output the little-endian representation of the above number, in uppercase hex.
