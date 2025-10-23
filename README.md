# Mind_X_Subdomain 🎯

An advanced subdomain discovery tool that goes **beyond standard enumeration** to find hidden assets missed by other bug bounty hunters.

## What Makes This Different?

While tools like `subfinder` and `amass` are great for standard discovery, this tool implements **creative techniques** to find:

- 📧 Mail infrastructure from SPF/DKIM records
- 🔄 Neighbor domains via reverse IP lookups
- ☁️ Cloud storage buckets (S3, Azure, GCP)
- 🧬 Smart DNS permutations based on discovered patterns
- 🔍 Deep certificate transparency analysis
- 📱 Hidden endpoints from JavaScript files
- 🏢 Acquisition company infrastructure
- 🌐 ASN-based IP range discovery

## Quick Start (Easiest Method)

### Option 1: Automated Hunt (Recommended)

```bash
# Make it executable
chmod +x run_advanced_hunt.sh

# Run everything automatically
./run_advanced_hunt.sh
```

This will:
1. Combine your existing subdomain files
2. Run all discovery modules
3. Save results to `advanced_results/` directory
4. Show you a summary of findings

### Option 2: Manual Control

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run with your existing data
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f subfinder.txt \
    -o new_discoveries.txt
```

## Current Status of Your Data

You have:
- ✅ **subfinder.txt**: 38,467 domains
- ✅ **cero_domains.txt**: 17,829 domains
- 🎯 **Total unique**: ~50,000+ subdomains

This tool will use your existing data as a **base** to find new hidden assets.

## Usage Examples

### Example 1: Find Everything
```bash
# Combine existing files and run all modules
cat subfinder.txt cero_domains.txt | sort -u > known_domains.txt

python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f known_domains.txt \
    -o complete_discovery.txt
```

### Example 2: Focus on High-Value Targets
```bash
# Focus on cloud buckets and JavaScript endpoints
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f known_domains.txt \
    -m cloud javascript \
    -o high_value.txt
```

### Example 3: Acquisition Hunting
```bash
# Find infrastructure from PayPal's acquisitions
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f known_domains.txt \
    -m acquisitions permutations \
    -o acquisition_targets.txt
```

### Example 4: Single Domain (No Existing Data)
```bash
# Start from scratch with a single domain
python3 Mind_X_Subdomain.py \
    -d target.com \
    -o fresh_discovery.txt
```

## Available Modules

| Module | Description | Use Case |
|--------|-------------|----------|
| `email` | Mine SPF/DKIM/DMARC records | Find mail infrastructure |
| `reverse_ip` | Reverse IP lookups | Find neighbor domains |
| `cloud` | S3/Azure/GCP enumeration | Find exposed storage |
| `permutations` | Smart DNS permutations | Find dev/staging envs |
| `ct` | Certificate transparency | Find historical domains |
| `javascript` | JS endpoint extraction | Find internal APIs |
| `acquisitions` | Map acquisitions | Find legacy systems |
| `asn` | ASN enumeration | Find IP ranges |

## Rate Limiting

Adjust speed based on your needs:

```bash
# Slower (more polite) - Good for bug bounty
python3 Mind_X_Subdomain.py -d paypal.com -f known_domains.txt -r 2.0

# Default speed
python3 Mind_X_Subdomain.py -d paypal.com -f known_domains.txt -r 1.0

# Faster (use with caution)
python3 Mind_X_Subdomain.py -d paypal.com -f known_domains.txt -r 0.5
```

## Optional: API Keys for Enhanced Features

Edit `config.json` to add API keys (all optional but recommended):

### Free API Keys:

1. **SecurityTrails** (50 queries/month free)
   - Sign up: https://securitytrails.com/app/signup
   - Provides: Historical DNS records

2. **VirusTotal** (Free tier available)
   - Sign up: https://www.virustotal.com/gui/join-us
   - Provides: Passive DNS data

3. **GitHub** (Free)
   - Generate token: https://github.com/settings/tokens
   - Provides: Find subdomains in public repos

4. **Shodan** (Free tier: 100 results/month)
   - Sign up: https://account.shodan.io/register
   - Provides: IP and domain info

### Paid API Keys (Optional):

- **Censys** - Enhanced IP/domain data
- **BinaryEdge** - More comprehensive scans

Add keys to `config.json`:
```json
{
  "securitytrails_api_key": "YOUR_KEY_HERE",
  "virustotal_api_key": "YOUR_KEY_HERE",
  "github_token": "YOUR_TOKEN_HERE"
}
```

## Output & Results

The tool displays:
- 🟢 **GREEN**: Newly discovered subdomains
- 🟡 **YELLOW**: Cloud buckets found
- 🔵 **CYAN**: Module progress
- 📊 **Summary**: Total discoveries at the end

All discoveries are saved to your specified output file.

## Next Steps After Discovery

### 1. Validate Alive Domains
```bash
cat new_discoveries.txt | httpx -mc 200,301,302,403 -o alive.txt
```

### 2. Screenshot Everything
```bash
cat alive.txt | aquatone -out screenshots/
```

### 3. Look for Interesting Patterns
```bash
# Find admin/internal panels
grep -E '(admin|internal|dev|stage|jenkins|gitlab)' alive.txt

# Find API endpoints
grep -E 'api' alive.txt

# Find sandbox/test environments
grep -E '(sandbox|sb\d+|test|qa|uat)' alive.txt
```

### 4. Technology Detection
```bash
cat alive.txt | httpx -tech-detect -o tech_stack.txt
```

### 5. Port Scanning
```bash
# Extract IPs from new domains
cat new_discoveries.txt | dnsx -a -resp-only > new_ips.txt

# Port scan
nmap -iL new_ips.txt -oA scan_results
```

## Pro Tips for Bug Bounty

### 1. **Focus on Acquisitions**
PayPal has acquired many companies. Look for:
- Venmo, Braintree, Xoom, Honey infrastructure
- Legacy domain patterns
- Cross-integration points

### 2. **Look for Staging/Dev Environments**
```bash
grep -E '(stage|staging|dev|sandbox|test|qa|uat|preprod)' new_discoveries.txt
```

### 3. **Check Cloud Buckets Thoroughly**
```bash
# The tool finds buckets, but you need to test access
aws s3 ls s3://bucket-name --no-sign-request
```

### 4. **Analyze JavaScript Files**
Manually review JavaScript for:
- Internal API endpoints
- API keys (accidentally committed)
- Debug endpoints
- Admin functionality

### 5. **Monitor for Changes**
Run this tool regularly (weekly) to catch new infrastructure:
```bash
# Compare with previous results
comm -13 old_discoveries.txt new_discoveries.txt > truly_new.txt
```

## Troubleshooting

### DNS Resolution Errors
```bash
# Use public DNS resolvers
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

### Rate Limiting Issues
```bash
# Increase delay between requests
python3 Mind_X_Subdomain.py -d domain.com -f file.txt -r 3.0
```

### Python Package Errors
```bash
# Install dependencies
pip3 install -r requirements.txt

# Or use system packages flag (Kali Linux)
pip3 install -r requirements.txt --break-system-packages
```

## Files Overview

```
.
├── Mind_X_Subdomain.py  # Main tool
├── run_advanced_hunt.sh          # Automated runner
├── config.json                   # API keys configuration
├── requirements.txt              # Python dependencies
├── USAGE.md                      # Detailed usage guide
├── README.md                     # This file
├── subfinder.txt                 # Your existing data (38k domains)
├── cero_domains.txt              # Your existing data (17k domains)
└── advanced_results/             # Output directory (created on run)
```

## Examples for PayPal Bug Bounty

### Workflow 1: Quick Win - Cloud Buckets
```bash
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -m cloud \
    -o paypal_buckets.txt
```
Then manually test each bucket for public access or sensitive data.

### Workflow 2: Find Internal APIs
```bash
# First find domains
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f known_domains.txt \
    -m javascript permutations \
    -o internal_apis.txt

# Validate which respond
cat internal_apis.txt | httpx -o alive_apis.txt

# Test for vulnerabilities
ffuf -w alive_apis.txt:DOMAIN -u https://DOMAIN/api/v1/FUZZ -w wordlist.txt
```

### Workflow 3: Acquisition Deep Dive
```bash
# Run acquisition module
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -m acquisitions \
    -o acquisition_domains.txt

# Check each acquisition domain individually
for domain in venmo.com xoom.com braintreegateway.com; do
    python3 Mind_X_Subdomain.py -d $domain -o ${domain}_discoveries.txt
done
```

## Performance Notes

- **Small dataset (<1000 domains)**: ~2-5 minutes
- **Medium dataset (1000-10000)**: ~10-20 minutes
- **Large dataset (10000+)**: ~30-60 minutes

Your dataset (~50k domains) will take approximately **45-90 minutes** to fully process with all modules.

## Support

- Check `USAGE.md` for detailed documentation
- Review examples in this README
- Adjust rate limiting if you hit issues

## Credits

Built for bug bounty hunters who want to find assets that others miss.

Happy Hunting! 🎯
