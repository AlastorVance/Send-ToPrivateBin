# Send-ToPrivateBin

A PowerShell script containing functions to interact with a PrivateBin instance

## Description

This script provides a set of tools for creating and deleting pastes on a PrivateBin server.  
It includes functions for sending text as a new paste and for deleting an existing paste using its deletion token.  
The script handles the necessary client-side encryption (AES-256-GCM) required by the PrivateBin API (v2).

It can use native .NET cryptographic libraries (PowerShell 7.0+) or fall back to the BouncyCastle library for older PowerShell versions.

## Usage

To use the functions in your current PowerShell session, you can "dot-source" the script file:

```powershell
. .\Send-ToPrivateBin.ps1
```

After dot-sourcing, the following functions will be available:

- Send-ToPrivateBin: Creates a new encrypted paste.
- Remove-PrivateBinPaste: Deletes a paste.
- ConvertTo-Base58: A helper function for URL key encoding (generally not called directly).

Example of creating a paste:

```powershell
Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "This is a secret message."
```

Example of creating and then deleting a paste:

```powershell
$myPaste = Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "This will be deleted."
$myPaste.RemovePaste()
```

## Notes

- License: This script is released under the GNU General Public License (GPL).
- Inspiration: This implementation is heavily inspired by the proposal from user **lyra-edmundson** on the PrivateBin GitHub issue: https://github.com/PrivateBin/PrivateBin/issues/827
A warm thank you to them for their valuable contribution!
