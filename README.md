# ghget.py

`ghget.py` is a small tool for downloading individual files from GitHub. It converts
GitHub file page URLs to `raw.githubusercontent.com` URLs and then runs `wget` via `exec`. Except
for the URLs, all command-line arguments are passed to `wget` unchanged and in their
original order.

## Initial Download

```bash
wget https://raw.githubusercontent.com/yeads/tools/main/ghget.py
```

## Requirements

- Python 3
- `requests`
- `wget`

Install the Python dependency:

```bash
python3 -m pip install requests
```

## Usage

```bash
python3 ghget.py [wget options] GITHUB_FILE_URL
```

For example:

```bash
python3 ghget.py -O basic.rs \
  https://github.com/yeads/rrid/tree/main/examples/basic.rs
```

The URL above is converted to:

```text
https://raw.githubusercontent.com/yeads/rrid/main/examples/basic.rs
```

Standard GitHub file URLs using `/blob/` are also supported:

```bash
python3 ghget.py -q --show-progress \
  https://github.com/OWNER/REPOSITORY/blob/BRANCH/PATH/FILE
```

Options such as `-O`, `-q`, and `--show-progress` are not processed by `ghget.py`;
they are passed to `wget` unchanged. If a URL on the command line is not a
`github.com` file URL, the program reports an error and exits. When no URL is
provided, the arguments are also passed to `wget` unchanged, so you can use
`python3 ghget.py --help` to view the `wget` help text.

> If a branch or tag name contains `/`, a GitHub page URL cannot unambiguously
> distinguish the name from the file path. In this case, use a tag without `/`
> or a commit hash.
