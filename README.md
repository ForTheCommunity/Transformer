# 🛠 Transformer

A command-line utility for splitting large files into chunks/pieces and merging them back together.

-> Join [Matrix Room](https://matrix.to/#/#transformer:matrix.org)


# ❖ File Splitting Demo :
![transformer file splitting](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_split.gif?raw=true)

# ❖ File Merging Demo :
![transformer file merging](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_merge.gif?raw=true)


## ❖ Usage

## ✦ Splitting a File
Use the `split` subcommand to break a file into smaller pieces.

```bash
transformer split --file-path <PATH> --piece-size <SIZE> --output <DIRECTORY>
```

**Example:**
```bash
transformer split -f large_video.mp4 -p 100MB -o ./fragments
```

## ✦ Merging Pieces
Use the `merge` subcommand to reconstruct the original file from a directory of pieces.
> Note : All Pieces should be in same folder/directory.

```bash
transformer merge --piece <Any Piece> --folder <FOLDER_PATH>
```

**Example:**
```bash
transformer merge -p ~/Downloads/pieces/piece_000 -f ~/Downloads/
```

## ✦ Supported Units

The `--piece-size` (`-p`) flag supports the following case-insensitive units:

| Unit | Description |
| :--- | :--- |
| `B`  | Bytes |
| `KB` | Kilobytes |
| `MB` | Megabytes |
| `GB` | Gigabytes |
| `TB` | Terabytes |


## ❖ Encrypting/Decrypting File:

## ❖ 1. En/De-crypting file with a password:

## ✦ Encrypting file with a password:
Use the `encrypt-pass` subcommand to encrypt a file with password.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of file to encrypt |
| `-o` | `--output` | Path where encrypted file will be saved |
| `-p` | `--password` | Pass Password via argument |
| `-c` | `--chunk-size` | Set Buffer/Chunk Size, setting higher size encrypts fast |
| `-h` | `--help` | View details about this subcommand |



⥏ **Examples:** ⥑
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/
```


⥏ **give password via argument:** ⥑
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/ -p secret_password
```

⥏ **Set Buffer/Chunk Size (MB):** ⥑
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/ -c 100
```
> The default Chunk Size (Buffer) is 1 MB. When encrypting large files, increase this value (up to 100 MB) for significantly faster performance. Max Chunk Size is 100MB.

> Note: For security reasons, avoid passing your password directly as a command-line argument, as it will be saved in your shell history. If you omit the argument, the tool will automatically display a secure password prompt.


## ✦ Decrypting file with a password:
Use the `decrypt-pass` subcommand to decrypt a file with password.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of file to decrypt |
| `-o` | `--output` | Path where decrypted file will be saved |
| `-p` | `--password` | Pass Password via argument |
| `-h` | `--help` | View details about this subcommand |


⥏ **Examples:** ⥑
```bash
transformer decrypt-pass -f sd3gdvs6.encrypted -o ./decrypted_files/
```


⥏ **give password via argument:** ⥑
```bash
transformer decrypt-pass -f sd3gdvs6.encrypted -o ./decrypted_files/ -p secret_password
```

> Note: For security reasons, avoid passing your password directly as a command-line argument, as it will be saved in your shell history. If you omit the argument, the tool will automatically display a secure password prompt.

## ❖ 2. En/De-crypting file with a Keystore:




## --> Download | Install :

## # Download binaries from [releases](https://gitlab.com/ForTheCommunity/transformer/-/releases) Page.

[![Download for Windows](https://img.shields.io/badge/download-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/ForTheCommunity/Transformer/releases)

[![Download for Linux](https://img.shields.io/badge/download-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://gitlab.com/ForTheCommunity/Transformer/-/releases)

## # Install using [AppMan](https://github.com/ivan-hc/AppMan)/[AM](https://github.com/ivan-hc/AM).
```
appman install transformer
```

## Support
If you find this project useful, consider supporting its development.
<br>
**Monero (XMR):**
`83eg4LiD5PEWGu6JpU2mfQVmVdNJQfKzGAi5GUGZKBkBdWBaGxxUrifCj1WyiUEtUfLNaxQjcfHDaDtxfZhr7RboPCVvTYf`


## License

This project is licensed under the **[Unlicense](https://unlicense.org)**. You can view the full license text in the [UNLICENSE](./UNLICENSE) file.
