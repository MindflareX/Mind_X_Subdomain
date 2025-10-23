# Mind_X Subdomain - Command Reference

## Quick Commands

### 1. Single Domain Scan

```bash
python3 Mind_X_Subdomain.py -d paypal.com -o paypal_results.txt
```

### 2. Multiple Domains from File (RECOMMENDED)

```bash
python3 Mind_X_Subdomain.py -l domain -o subdomain_results/
```

This will:
- Read all domains from `domain` file
- Create `subdomain_results/` directory
- Save individual results for each domain
- Generate combined results file
- Create summary report

### 3. With Specific Modules

```bash
# Single domain
python3 Mind_X_Subdomain.py -d paypal.com -m email cloud ct javascript -o results.txt

# Multiple domains
python3 Mind_X_Subdomain.py -l domain -m email cloud ct javascript -o results/
```

### 4. With Existing Subdomains Filter

```bash
# Single domain - filter out already known subdomains
python3 Mind_X_Subdomain.py -d paypal.com -f existing_subs.txt -o new_only.txt

# Multiple domains - filter out already known subdomains
python3 Mind_X_Subdomain.py -l domain -f existing_subs.txt -o results/
```

### 5. Full Advanced Scan (All Modules)

```bash
# Single domain
python3 Mind_X_Subdomain.py \
  -d paypal.com \
  -o paypal_full_scan.txt \
  -m email reverse_ip cloud permutations asn ct javascript acquisitions \
  -r 1.5

# Multiple domains
python3 Mind_X_Subdomain.py \
  -l domain \
  -o subdomain_results/ \
  -m email reverse_ip cloud permutations asn ct javascript acquisitions \
  -r 1.5
```

## Options Explained

| Flag | Description | Example |
|------|-------------|---------|
| `-d` | Single domain target | `-d paypal.com` |
| `-l` | File with multiple domains | `-l domain` |
| `-f` | File with existing subdomains to filter | `-f known_subs.txt` |
| `-o` | Output file (single) or directory (multiple) | `-o results.txt` or `-o results/` |
| `-m` | Specific modules to run | `-m cloud ct javascript` |
| `-r` | Rate limit in seconds | `-r 1.5` |
| `-c` | Config file with API keys | `-c config.json` |

## Available Modules

- `email` - Mine SPF/DKIM/DMARC records
- `reverse_ip` - Find neighbors on same IP
- `cloud` - S3, Azure, GCP bucket enumeration
- `permutations` - Smart DNS permutations
- `asn` - ASN enumeration
- `ct` - Certificate Transparency logs
- `javascript` - Extract from JS files
- `acquisitions` - Map acquisition domains
- `historical` - Historical DNS (requires API key)
- `http_probe` - HTTP probing & tech detection
- `wayback` - Wayback Machine mining
- `favicon` - Favicon hash hunting
- `dns_deep` - Deep DNS analysis
- `recursive` - Recursive subdomain discovery
- `vhost` - Virtual host discovery
- `dorking` - Search engine dorking

## Output Structure

### Single Domain Mode
```
paypal_results.txt
```

### Multiple Domain Mode
```
subdomain_results/
├── paypal.com_subdomains.txt
├── venmo.com_subdomains.txt
├── xoom.com_subdomains.txt
├── ... (all domains)
├── ALL_SUBDOMAINS_COMBINED.txt
└── SUMMARY.txt
```

## Real-World Examples

### Example 1: Quick scan for your PayPal domains
```bash
python3 Mind_X_Subdomain.py -l domain -o paypal_scan/
```

### Example 2: Focus on cloud assets only
```bash
python3 Mind_X_Subdomain.py -l domain -m cloud -o cloud_findings/
```

### Example 3: Deep scan with existing data
```bash
# First, combine your existing findings
cat subfinder_results.txt amass_results.txt | sort -u > known.txt

# Then scan for new ones
python3 Mind_X_Subdomain.py -l domain -f known.txt -o new_discoveries/
```

### Example 4: Fast scan (aggressive)
```bash
python3 Mind_X_Subdomain.py -l domain -o results/ -r 0.5
```

### Example 5: Slow scan (polite for bug bounty)
```bash
python3 Mind_X_Subdomain.py -l domain -o results/ -r 2.5
```

## Important Notes

1. **Cannot use both `-d` and `-l` together** - Choose one:
   - `-d` for single domain
   - `-l` for multiple domains from file

2. **The `-f` flag is for filtering** - It's for existing subdomains you want to exclude, not for domain lists

3. **Output behavior**:
   - Single domain (`-d`): Creates a single output file
   - Multiple domains (`-l`): Creates a directory with individual files

4. **Domain list format** (for `-l`):
```
paypal.com
venmo.com
xoom.com
# Comments are allowed
braintree.com
```

5. **Rate limiting**: Default is 1.0 second. Adjust based on:
   - Your infrastructure: `-r 0.5` (faster)
   - Bug bounty programs: `-r 1.5` to `-r 3.0` (polite)
