# Seclogon Race Condition LSASS Dump

**A tool to exploit a race condition in the Seclogon service to obtain handles to the `lsass.exe` process and create a memory dump, which is encrypted using XOR. The dump can later be decrypted using a provided Python script.**

## 🔑 Key Features:
- 🛠 **Seclogon Race Condition Exploit**: Exploits a race condition in the Seclogon service to obtain handles to the `lsass.exe` process.
- 🧑‍💻 **MiniDump Creation**: Uses the MiniDumpWriteDump API to create a memory dump of `lsass.exe` once access is gained.
- 🔐 **XOR Encryption**: The memory dump is encrypted in memory using XOR before being written to disk.
- 🐍 **Python Decryption Script**: A Python script is included to decrypt the XOR-encrypted memory dump.

## 📝 Usage:

### Dump LSASS:
```bash
SeclogonLsassDump.exe <path_to_dump_file>

```
### Decrypt Dump
```bash
python3 decrypt_dump.py <encrypted_dump_path>
```

![image](https://github.com/zer0antisec/LsaDumpRace/assets/20486087/ac881a8f-7c6e-4a37-acf1-b2e062de4136)

![image](https://github.com/zer0antisec/LsaDumpRace/assets/20486087/53655941-99e9-4177-9795-1433ae043517)

![image](https://github.com/user-attachments/assets/e044d6fc-762b-4cb0-8c37-2a9678a1b014)
