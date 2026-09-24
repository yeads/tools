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

## gptdump.py

`gptdump.py` downloads a public ChatGPT shared conversation and saves it as a
Markdown file. It preserves headings, lists, tables, code blocks, links, and
image references, and converts ChatGPT citation and entity annotations into
readable Markdown.

Run it with a public `chatgpt.com/share` URL:

```bash
python3 gptdump.py \
  'https://chatgpt.com/share/6aa79994-820c-83e9-a91c-592e2dbd70a4'
```

By default, the output filename is based on the conversation title. Use `-o`
to choose a path:

```bash
python3 gptdump.py SHARE_URL -o conversation.md
```

The script automatically honors the standard `http_proxy` and `https_proxy`
environment variables. A proxy can also be provided explicitly:

```bash
python3 gptdump.py SHARE_URL --proxy http://127.0.0.1:7890
```

Existing files are not overwritten unless `--force` is used with `-o`. Use
`--timeout SECONDS` to change the default 30-second request timeout, or run
`python3 gptdump.py --help` to see all options.

## dnspod.py

`dnspod.py` manages DNS records hosted by Tencent Cloud DNSPod. It supports
`add`, `set`, `get`, `ls`, and `delete` operations.

Set your Tencent Cloud credentials before use:

```bash
export TENCENTCLOUD_SECRET_ID="your-secret-id"
export TENCENTCLOUD_SECRET_KEY="your-secret-key"
```

Then run commands such as:

```bash
python3 dnspod.py add www.example.com 192.0.2.1
python3 dnspod.py get www.example.com
python3 dnspod.py ls
python3 dnspod.py ls example.com
python3 dnspod.py set 123456789 192.0.2.2
python3 dnspod.py rm 123456789 987654321
```

`ls` without a domain lists account domains. `ls example.com` lists that domain's
records with record IDs in the first column. `show` is an alias for `ls`.
`add hostname value` creates a new
record. `set id value` updates an existing record and preserves its other
attributes unless options explicitly override them. `rm id [id ...]` deletes
one or more records, including records across domains; `delete` and `del` are
aliases. Duplicate IDs are deleted once. Deletion stops on the first error and
reports IDs already deleted.

DNSPod requires a domain for record updates and deletions, so the tool looks up
IDs by listing account domains and their records. Credentials must allow these
list operations as well as the requested update or deletion. Accounts with many
domains may take longer to search. API fields follow the
[official Tencent Cloud SDK](https://github.com/TencentCloud/tencentcloud-sdk-python/blob/master/tencentcloud/dnspod/v20210323/models.py).

Use options such as `--type`, `--line`, `--line-id`, and `--ttl` to select or
configure a record. Run `python3 dnspod.py --help` for all options. Temporary
credentials can also use `TENCENTCLOUD_SESSION_TOKEN`.

## alidns.py

`alidns.py` manages DNS records hosted by Alibaba Cloud DNS. It supports
`add`, `set`, `get`, `ls`, and `delete` operations.

Set your Alibaba Cloud credentials before use:

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
```

Then run commands such as:

```bash
python3 alidns.py add www.example.com 192.0.2.1
python3 alidns.py get www.example.com
python3 alidns.py ls
python3 alidns.py ls example.com
python3 alidns.py set 123456789 192.0.2.2
python3 alidns.py rm 123456789 987654321
```

`ls` without a domain lists account domains. `ls example.com` lists that domain's
records with record IDs in the first column. `show` is an alias for `ls`.
`add hostname value` creates a new
record. `set id value` updates an existing record and preserves its type, route,
TTL, and MX priority unless options explicitly override them. It reads the
existing fields using [DescribeDomainRecordInfo](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecordinfo).
`rm id [id ...]` deletes one or more records; `delete` and `del` are aliases.
Deletion stops on the first error and reports IDs already deleted.

Use options such as `--type`, `--line`, and `--ttl` to select or configure a
record. Run `python3 alidns.py --help` for all options. The aliases
`ALIYUN_ACCESS_KEY_ID` and `ALIYUN_ACCESS_KEY_SECRET` are also accepted, and
temporary credentials can use `ALIBABA_CLOUD_SECURITY_TOKEN` or
`ALIYUN_SECURITY_TOKEN`.
