# Transformer

A command-line utility for splitting large files into chunks/pieces and merging them back together.


## Usage

### Splitting a File
Use the `split` subcommand to break a file into smaller pieces.

```bash
transformer split --file-path <PATH> --piece-size <SIZE> --output <DIRECTORY>
```

**Example:**
```bash
transformer split -f large_video.mp4 -p 100MB -o ./fragments
```

### Merging Pieces
Use the `merge` subcommand to reconstruct the original file from a directory of pieces.
> Note : All Pieces should be in same folder/directory.

```bash
transformer merge --piece <Any Piece> --folder <FOLDER_PATH>
```

**Example:**
```bash
transformer merge -p ~/Downloads/pieces/piece_000 -f ~/Downloads/
```

## Supported Units

The `--piece-size` (`-p`) flag supports the following case-insensitive units:

| Unit | Description |
| :--- | :--- |
| `B`  | Bytes |
| `KB` | Kilobytes |
| `MB` | Megabytes |
| `GB` | Gigabytes |
| `TB` | Terabytes |

## --> Download | Install :

### 1. --> Install using [AppMan](https://github.com/ivan-hc/AppMan)/[AM](https://github.com/ivan-hc/AM).
```
appman install transformer
```

### 2. Download binaries from [releases](https://gitlab.com/ForTheCommunity/transformer/-/releases) Page.


## Support
If you find this project useful, consider supporting its development.
<br>
**Monero (XMR):**
`83eg4LiD5PEWGu6JpU2mfQVmVdNJQfKzGAi5GUGZKBkBdWBaGxxUrifCj1WyiUEtUfLNaxQjcfHDaDtxfZhr7RboPCVvTYf`


## License

This project is licensed under the **[Unlicense](https://unlicense.org)**. You can view the full license text in the [UNLICENSE](./UNLICENSE) file.

