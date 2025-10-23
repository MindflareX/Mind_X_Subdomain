# Enhanced Smart Permutation Module Guide

## 🔥 What's New in Mind_X_Subdomain v1.0

The permutation module has been **massively enhanced** with altdns-style creativity and optional puredns integration.

---

## 🎯 Overview

### Standard Tools (subfinder, amass)
- ❌ Only passive sources
- ❌ Generic wordlists
- ❌ No learning from your data

### Mind_X_Subdomain Enhanced Permutations
- ✅ **Altdns-style** creative permutations
- ✅ **Learns from YOUR** 50k+ existing domains
- ✅ **Built-in comprehensive wordlist** (150+ terms)
- ✅ **Smart combinations** (not just bruteforce)
- ✅ **Number-based permutations** (api1, api2, etc.)
- ✅ **Optional puredns** integration for speed
- ✅ **Rate limiting** to avoid detection

---

## 🧠 How It Works

### Phase 1: Pattern Learning
```python
Analyzes your existing 50,000+ domains to extract:

Environments found:
- prod, production, staging, stage, dev, development
- qa, uat, test, testing, sandbox, sb12, sb15

Prefixes discovered:
- merchant, checkout, payment, jenkins, gitlab
- api, admin, portal, internal, mobile

Patterns identified:
- multi-part: merchant.api.paypal.com
- numbered: sb12.paypal.com, app03.paypal.com
- versioned: api-v2.paypal.com
```

### Phase 2: Built-in Wordlist
```python
150+ carefully selected terms covering:
- Environments: dev, prod, staging, qa, uat, sandbox
- Infrastructure: api, app, web, gateway, proxy, cdn
- DevOps: jenkins, gitlab, docker, k8s, ci, cd
- Security: sso, auth, oauth, ldap, waf, iam
- Business: payment, checkout, merchant, wallet
- Monitoring: grafana, kibana, prometheus, elk
- Databases: mysql, postgres, mongo, redis
- Regions: us, eu, uk, apac, asia
```

### Phase 3: Altdns-Style Generation

**Example: From `api.paypal.com`**

**Insertion (prepend/append):**
```
dev-api.paypal.com
api-dev.paypal.com
staging.api.paypal.com
api.staging.paypal.com
devapi.paypal.com
```

**Multi-part manipulation (`merchant.api.paypal.com`):**
```
Insert:
- dev.merchant.api.paypal.com
- merchant.dev.api.paypal.com
- merchant.api.dev.paypal.com

Replace:
- internal.api.paypal.com (replaced merchant)
- merchant.gateway.paypal.com (replaced api)
```

**Number variations:**
```
api1.paypal.com
api-2.paypal.com
api03.paypal.com (zero-padded)
api-10.paypal.com
```

### Phase 4: Smart Combinations
```python
Discovered prefix: merchant
Discovered env: staging

Generates:
- merchant-staging.paypal.com
- staging-merchant.paypal.com
- merchant.staging.paypal.com
- staging.merchant.paypal.com
```

### Phase 5: DNS Resolution

**Standard Mode (Built-in):**
- Rate limited DNS queries
- Tests up to 2000 permutations
- Progress indicators every 100 tests
- 1-2 second delay between queries (configurable)

**Fast Mode (puredns - optional):**
- Uses puredns if installed
- Can test 10,000+ permutations quickly
- Requires resolvers.txt
- Much faster but needs external tool

---

## 🚀 Usage Examples

### Basic: Smart Permutations (Recommended)
```bash
cd Mind_X_Subdomain

# Uses your existing data to learn patterns
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f ../subfinder.txt \
    -m permutations \
    -o permutation_results.txt

# What happens:
# 1. Analyzes your 50k+ domains for patterns
# 2. Generates 5,000-10,000 intelligent permutations
# 3. Tests 2,000 most likely permutations (rate limited)
# 4. Saves validated results
```

### Slower/Polite (Bug Bounty Safe)
```bash
# Increase delay to 2 seconds (very polite)
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f ../subfinder.txt \
    -m permutations \
    -r 2.0
```

### Faster (Use with caution)
```bash
# Decrease delay to 0.5 seconds
python3 Mind_X_Subdomain.py \
    -d paypal.com \
    -f ../subfinder.txt \
    -m permutations \
    -r 0.5
```

---

## ⚡ Optional: puredns Integration (FAST MODE)

### What is puredns?
- Fast DNS resolver using massdns
- Can test 10,000+ domains in minutes
- Requires Go and resolvers.txt

### Setup puredns

**1. Install puredns:**
```bash
# Install Go if needed
sudo apt install golang-go -y

# Install puredns
go install github.com/d3mondev/puredns/v2@latest

# Add to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

**2. Get resolvers.txt:**
```bash
cd Mind_X_Subdomain

# Option A: Use SecLists
sudo apt install seclists -y
# Located at: /usr/share/seclists/Discovery/DNS/resolvers.txt

# Option B: Download directly
wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt

# Option C: Use public DNS
cat > resolvers.txt << EOF
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
EOF
```

### How Mind_X_Subdomain Uses puredns

**Automatic Detection:**
```python
Tool checks for puredns automatically:
1. Generates permutations
2. Checks if puredns is installed (which puredns)
3. Looks for resolvers.txt in:
   - /usr/share/seclists/Discovery/DNS/resolvers.txt
   - ./resolvers.txt
   - ../resolvers.txt
4. If found: uses puredns for fast resolution
5. If not found: uses standard rate-limited DNS
```

**Manual puredns workflow:**
```bash
# 1. Generate permutations to file
python3 Mind_X_Subdomain.py -d paypal.com -f ../subfinder.txt -m permutations

# 2. Run puredns separately for even more control
puredns resolve permutation_results.txt -r resolvers.txt -w validated.txt
```

---

## 📊 Expected Results

### With Your 50k Domain Dataset:

**Standard Mode (built-in):**
- Generates: 5,000-10,000 permutations
- Tests: 2,000 permutations (rate limited)
- Time: 30-60 minutes (with rate limiting)
- Expected finds: 50-200 new subdomains

**Fast Mode (with puredns):**
- Generates: 10,000-50,000 permutations
- Tests: All permutations
- Time: 5-15 minutes
- Expected finds: 100-500 new subdomains

---

## 🎯 Real-World Example

**Input:**
```
Your existing domains include:
- merchant-api.paypal.com
- api.sandbox.paypal.com
- jenkins.internal.paypal.com
```

**Tool Learns:**
```
Patterns: merchant, api, sandbox, jenkins, internal
Environments: sandbox
Numbers: none detected yet
```

**Tool Generates:**
```
Altdns-style from merchant-api:
✓ merchant-api-dev.paypal.com
✓ merchant-api-staging.paypal.com
✓ merchant-api-v2.paypal.com
✓ internal-merchant-api.paypal.com
✓ merchant-admin.paypal.com

Altdns-style from api.sandbox:
✓ api.staging.paypal.com
✓ api.prod.paypal.com
✓ gateway.sandbox.paypal.com
✓ internal.sandbox.paypal.com

Number variations:
✓ api1.paypal.com
✓ api2.paypal.com
✓ merchant-api-01.paypal.com
✓ jenkins02.internal.paypal.com

Smart combinations:
✓ payment-api.paypal.com
✓ kyc-api.paypal.com
✓ fraud-api.paypal.com
```

**Tool Validates via DNS:**
```
Testing 2000 permutations...
[*] Progress: 100/2000 tested, 5 found
[*] Progress: 200/2000 tested, 12 found
...
[+] Found: merchant-api-dev.paypal.com
[+] Found: internal.sandbox.paypal.com
[+] Found: api2.paypal.com
```

---

## 🔥 Comparison: altdns vs puredns

### Altdns
**What it does:** Generates creative permutations
**Pros:**
- Creative variations
- Multi-pattern combinations
- Word insertions/replacements

**Cons:**
- Python-based (slower resolution)
- No mass DNS resolution

### Puredns
**What it does:** Fast DNS resolution
**Pros:**
- Uses massdns (very fast)
- Can test 100k+ domains
- Parallel resolution

**Cons:**
- Requires Go + setup
- Needs resolvers.txt
- Doesn't generate permutations (just resolves)

### Mind_X_Subdomain Approach
**Best of both:**
- ✅ Altdns-style permutation generation
- ✅ Learns from YOUR data (not generic wordlist)
- ✅ Built-in comprehensive wordlist
- ✅ Standard rate-limited DNS (always works)
- ✅ Optional puredns integration (if you want speed)
- ✅ No external dependencies required

**You get:**
- Smart permutations like altdns
- Fast resolution option like puredns
- Works out of the box (no setup needed)
- Optionally faster if you install puredns

---

## 💡 Pro Tips

### 1. Start with Standard Mode
```bash
# First run: let tool learn patterns
python3 Mind_X_Subdomain.py -d paypal.com -f ../subfinder.txt -m permutations
```

### 2. Combine with Other Modules
```bash
# Permutations + Cloud + JS (high value!)
python3 Mind_X_Subdomain.py -d paypal.com \
    -f ../subfinder.txt \
    -m permutations cloud javascript
```

### 3. Adjust Rate Limiting
```bash
# Bug bounty: be polite
-r 2.0  # 2 second delay

# Your own infrastructure: faster
-r 0.5  # 0.5 second delay

# Paranoid: very slow
-r 3.0  # 3 second delay
```

### 4. Run Regularly
```bash
# Infrastructure changes, run weekly
python3 Mind_X_Subdomain.py -d paypal.com -f ../subfinder.txt -m permutations

# Compare with last week
comm -13 old_perms.txt new_perms.txt > truly_new.txt
```

### 5. Install puredns for Big Jobs
```bash
# For massive permutation testing
go install github.com/d3mondev/puredns/v2@latest
```

---

## 🛡️ Rate Limiting Details

### Built-in Protection
```python
Default: 1.0 second + random(0, 0.5)
- Prevents pattern detection
- Avoids rate limiting
- Respectful to target

Configurable: -r flag
- -r 0.5 = faster
- -r 1.0 = default
- -r 2.0 = polite
- -r 3.0 = very polite
```

### Why Rate Limiting Matters
- ❌ Too fast: Triggers IDS/WAF
- ❌ Too fast: Gets you blocked
- ❌ Too fast: Looks like attack
- ✅ Proper rate: Looks like normal traffic
- ✅ Proper rate: Won't get blocked
- ✅ Proper rate: Bug bounty friendly

---

## 📚 Built-in Wordlist Coverage

**Total: 150+ terms**

- Environments: 15 terms
- Infrastructure: 20 terms
- DevOps/CI/CD: 15 terms
- Monitoring: 12 terms
- Databases: 10 terms
- Security: 10 terms
- Business/Fintech: 20 terms
- API versions: 8 terms
- Regions: 15 terms
- Other: 25 terms

**No external wordlist needed!**

---

## ✅ Summary

| Feature | Standard Tools | Mind_X_Subdomain |
|---------|---------------|------------------|
| Learns from your data | ❌ | ✅ |
| Altdns-style perms | ❌ | ✅ |
| Built-in wordlist | ❌ | ✅ (150+ terms) |
| Number permutations | ❌ | ✅ |
| Rate limiting | ❌ | ✅ Configurable |
| puredns support | N/A | ✅ Optional |
| Works standalone | ✅ | ✅ |

---

**TL;DR:**
- Enhanced permutations = altdns creativity + your data patterns + built-in wordlist
- No external tools required (works out of box)
- Optional puredns for speed (if you want)
- Rate limiting keeps you safe
- Finds hidden subdomains others miss

Happy Hunting! 🎯
