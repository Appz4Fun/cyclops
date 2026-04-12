# nzbcyclops

Fast async NZB verification against one or more NNTP servers.

`nzbcyclops` reads an `.nzb`, extracts every article `Message-ID`, and checks article availability with persistent async NNTP connections. The default path is optimized for speed and low bandwidth: it uses `STAT` only, keeps all configured servers active from the start, and marks an article missing only after every server returns `430`.

It also supports an optional deeper validation pass that samples present articles, downloads their `BODY`, and validates yEnc size, `crc32`/`pcrc32`, and multipart `=ypart begin/end` ranges.

## Features

- Async NNTP verification with persistent connection pools
- Active-active load balancing across multiple NNTP servers
- `STAT`-only verification in normal mode
- Missing detection only after all configured servers return `430`
- Optional sampled deep checks with yEnc validation
- Streaming NZB parsing
- Real-time progress output
- Standard library only

## Requirements

- Python 3.10+

No external Python packages are required.

## Quick Start

1. Clone the repo:

```bash
git clone git@github.com:xbmc4lyfe/cyclops.git
cd cyclops
```

2. Create your NNTP config:

```bash
cp config.ini.example config.ini
```

3. Edit `config.ini` with your server details.

4. Run a verification:

```bash
python3 verify_nzb.py path/to/file.nzb --config config.ini
```

## Configuration

NNTP servers are defined in an INI file with one section per server:

```ini
[server.primary]
host = news.example.com
port = 563
ssl = true
username = your_username
password = your_password
max_connections = 50
timeout = 10

[server.backup]
host = news2.example.com
port = 563
ssl = true
username = your_username
password = your_password
max_connections = 25
timeout = 10
```

### Notes

- All configured servers participate immediately.
- Total concurrency is the sum of `max_connections` across all servers.
- `max_connections` must be at least `1`.
- `timeout` is per network operation.

## Usage

```text
usage: verify_nzb.py [-h] --config CONFIG [--retries RETRIES]
                     [--missing-output MISSING_OUTPUT] [--deep-check]
                     [--sample-percent SAMPLE_PERCENT]
                     [--sample-seed SAMPLE_SEED] [--deep-output DEEP_OUTPUT]
                     nzb_path
```

### Common commands

Basic verification:

```bash
python3 verify_nzb.py nzbs/example.nzb --config config.ini
```

Write missing or indeterminate articles to a file:

```bash
python3 verify_nzb.py nzbs/example.nzb \
  --config config.ini \
  --missing-output missing.txt
```

Retry transient failures:

```bash
python3 verify_nzb.py nzbs/example.nzb \
  --config config.ini \
  --retries 2
```

Run the optional deep check on a sampled subset of present articles:

```bash
python3 verify_nzb.py nzbs/example.nzb \
  --config config.ini \
  --deep-check \
  --sample-percent 2 \
  --sample-seed 123 \
  --deep-output deep.txt
```

## How Verification Works

### Normal mode

- Parses `Message-ID`s from the NZB
- Sends `STAT <message-id>` over persistent NNTP connections
- Marks an article `present` as soon as any server returns `223`
- Marks an article `missing` only when every configured server returns `430`
- Marks an article `error/indeterminate` when all attempts are exhausted and at least one server failed transiently

This is the fastest mode and uses minimal bandwidth.

### Deep check mode

When `--deep-check` is enabled:

- Only articles already confirmed present are eligible
- A sample is chosen with `--sample-percent`
- Sampled articles are fetched with `BODY`
- The body is validated as yEnc:
  - `=ybegin` / `=yend`
  - decoded size
  - `crc32` or `pcrc32`
  - multipart `=ypart begin/end` range consistency

Deep check is useful for spotting corrupted segments, but it is intentionally sample-based unless you set `--sample-percent 100`.

## Output

The script prints a live progress line during execution and a final summary like:

```text
summary: checked=85716 present=85716 missing=0 error/indeterminate=0 stat_requests=85716 elapsed=504.425s
```

If deep check is enabled, it also prints:

```text
deep: sampled=858 ok=858 corrupt=0 error=0 body_requests=858 elapsed=12.345s
```

### Optional output files

- `--missing-output`: writes missing and indeterminate article IDs
- `--deep-output`: writes one line per sampled deep-check result

## Testing

Run the test suite with:

```bash
python3 -B -m unittest -v
```

## Limitations

- Normal mode verifies availability, not payload integrity
- Deep mode validates sampled yEnc articles, but it is not a PAR2 verifier
- Deep corruption checks use `BODY`, so they are slower and consume more bandwidth than `STAT`
