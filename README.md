# Tools

Small, standalone command-line utilities.

## ghget.py

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

## dnspod.py

`dnspod.py` manages DNS records hosted by Tencent Cloud DNSPod. It can create or
update a record with `set`, query a hostname with `get`, list a domain with `ls`,
and remove a record with `delete`.

Set your Tencent Cloud credentials before use:

```bash
export TENCENTCLOUD_SECRET_ID="your-secret-id"
export TENCENTCLOUD_SECRET_KEY="your-secret-key"
```

Then run commands such as:

```bash
python3 dnspod.py set www.example.com 192.0.2.1
python3 dnspod.py get www.example.com
python3 dnspod.py ls example.com
python3 dnspod.py delete www.example.com
```

Use options such as `--type`, `--line`, `--line-id`, and `--ttl` to select or
configure a record. Run `python3 dnspod.py --help` for all options. Temporary
credentials can also use `TENCENTCLOUD_SESSION_TOKEN`.

## alidns.py

`alidns.py` manages DNS records hosted by Alibaba Cloud DNS. Like the DNSPod
tool, it supports `set`, `get`, `ls`, and `delete` operations.

Set your Alibaba Cloud credentials before use:

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
```

Then run commands such as:

```bash
python3 alidns.py set www.example.com 192.0.2.1
python3 alidns.py get www.example.com
python3 alidns.py ls example.com
python3 alidns.py delete www.example.com
```

Use options such as `--type`, `--line`, and `--ttl` to select or configure a
record. Run `python3 alidns.py --help` for all options. The aliases
`ALIYUN_ACCESS_KEY_ID` and `ALIYUN_ACCESS_KEY_SECRET` are also accepted, and
temporary credentials can use `ALIBABA_CLOUD_SECURITY_TOKEN` or
`ALIYUN_SECURITY_TOKEN`.
