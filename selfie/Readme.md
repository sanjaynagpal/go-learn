## Generate SHA26 on windows

```sh
Get-FileHash -Algorithm SHA256 selfie.exe | Select-Object Hash
```