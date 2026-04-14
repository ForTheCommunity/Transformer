# Transformer

A command-line utility for splitting large files into chunks/pieces and merging them back together.

> Note : Project is in Beta stage. Use it for testing purpose only.


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
| `KB` | Kilobytes (1,024 Bytes) |
| `MB` | Megabytes (1,048,576 Bytes) |
| `GB` | Gigabytes |
| `TB` | Terabytes |


