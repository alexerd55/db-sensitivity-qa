# db-sensitivity-qa

PostgreSQL PII & sensitive data scanner + privilege checker.

## What it does

- Scans PostgreSQL schemas for columns that may contain **PII or sensitive data**
- Uses name-based heuristics (column names like `email`, `password`, `jmbg`) and regex/value analysis on sampled data
- Checks **DB role privileges** (superuser, CREATEDB, CREATEROLE, CREATE on database)
- Generates a **JSON report** and a **styled HTML report**
- **Never stores raw values** — evidence is always masked (`a***@d***.com`, `****1234`, etc.)

## Quickstart

```bash
# Install
pip install -e .

# Run scan
dbqa scan --dsn "postgresql+psycopg2://user:pass@localhost:5432/mydb"

# With options
dbqa scan \
  --dsn "postgresql+psycopg2://appuser:secret@localhost:5432/prod" \
  --schemas "public,app" \
  --sample-rows 300 \
  --output report.json \
  --html report.html

# Via environment variable
export DBQA_DSN="postgresql+psycopg2://user:pass@localhost:5432/mydb"
dbqa scan
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan OK, no HIGH severity findings |
| `1`  | Runtime error |
| `2`  | Scan OK, but HIGH severity findings found |

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--dsn` | `$DBQA_DSN` | PostgreSQL connection string |
| `--schemas` | `public` | Comma-separated schema list |
| `--include-tables` | — | Regex to include tables |
| `--exclude-tables` | — | Regex to exclude tables |
| `--sample-rows` | `200` | Max rows sampled per column |
| `--max-columns` | `5000` | Safety limit on total columns |
| `--timeout-seconds` | `10` | Statement and connection timeout |
| `--output` | `report.json` | JSON output path |
| `--html` | `report.html` | HTML output path |
| `--no-html` | — | Skip HTML generation |

## Detection rules

### Name heuristics (high signal)
Column names are matched against patterns for: `EMAIL`, `PHONE`, `NAME`, `ADDRESS`, `DOB`, `GOV_ID`, `PAYMENT`, `AUTH`

### Value analysis (medium/high)
Sampled values are checked with regex for: email addresses, phone numbers, IBANs, card numbers (Luhn), UUIDs, JWTs, hashes (MD5/SHA1/SHA256/base64)

### Scoring
| Score | Severity |
|-------|---------|
| 80–100 | HIGH |
| 50–79  | MEDIUM |
| 20–49  | LOW |
| 0–19   | INFO |

Score components:
- +40 if column name matches a sensitive pattern
- +10 if in an audit/log table
- +10 if text column with AUTH-type name
- +0–50 based on hit rate in sampled values

## Running tests

```bash
pip install pytest
pytest tests/
```

## Security notes

- DSN passwords are never logged
- Raw values from the DB are never stored or displayed
- Statement timeout is enforced per query (`SET statement_timeout`)
- Columns of type `bytea`, `json`, `jsonb`, `xml` are not sampled
- String values are truncated to 256 chars in memory before analysis

## Limitations

This is a **QA heuristic scanner**, not a security audit tool.
- Heuristics have false positives and false negatives
- "Plaintext password" detection is a suspicion only, not a proof
- Results depend on sample size and data distribution
