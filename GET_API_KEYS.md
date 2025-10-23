# How to Get Free API Keys (5-Minute Setup)

These API keys are **optional** but will enhance your subdomain discovery significantly.

## Priority 1: Most Useful (Get These First)

### 1. SecurityTrails (⭐⭐⭐⭐⭐ - Highly Recommended)
**Free Tier**: 50 API calls/month

**Steps**:
1. Go to: https://securitytrails.com/app/signup
2. Sign up with email (or GitHub/Google)
3. Verify your email
4. Go to: https://securitytrails.com/app/account/credentials
5. Click "Create API Key"
6. Copy the key

**Add to config.json**:
```json
{
  "securitytrails_api_key": "YOUR_KEY_HERE"
}
```

**What it gives you**:
- Historical DNS records (find old/forgotten subdomains)
- Subdomain history
- DNS record changes over time

---

### 2. GitHub Token (⭐⭐⭐⭐ - Very Useful)
**Free**: Unlimited for public repos

**Steps**:
1. Log into GitHub
2. Go to: https://github.com/settings/tokens
3. Click "Generate new token" → "Generate new token (classic)"
4. Give it a name: "Subdomain Hunter"
5. Select scope: `public_repo` (read public repositories)
6. Click "Generate token"
7. **Copy immediately** (you won't see it again)

**Add to config.json**:
```json
{
  "github_token": "ghp_xxxxxxxxxxxxxxxxxxxxx"
}
```

**What it gives you**:
- Find subdomains mentioned in public code
- Find subdomains in commit messages
- Discover internal infrastructure references

---

### 3. VirusTotal (⭐⭐⭐⭐ - Good for Passive DNS)
**Free Tier**: 500 requests/day

**Steps**:
1. Go to: https://www.virustotal.com/gui/join-us
2. Sign up with email
3. Verify email and log in
4. Click your profile icon → "API Key"
5. Copy your API key

**Add to config.json**:
```json
{
  "virustotal_api_key": "YOUR_KEY_HERE"
}
```

**What it gives you**:
- Passive DNS records
- Historical domain resolutions
- Related domains

---

## Priority 2: Nice to Have

### 4. Shodan (⭐⭐⭐ - Good for IP Research)
**Free Tier**: 100 results/month

**Steps**:
1. Go to: https://account.shodan.io/register
2. Sign up with email
3. Verify email
4. Go to: https://account.shodan.io
5. Your API key is shown on the account page

**Add to config.json**:
```json
{
  "shodan_api_key": "YOUR_KEY_HERE"
}
```

**What it gives you**:
- IP address information
- Open ports and services
- SSL certificate data

---

### 5. Censys (⭐⭐⭐ - Good for Certificate Search)
**Free Tier**: 250 queries/month

**Steps**:
1. Go to: https://search.censys.io/register
2. Sign up with email
3. Verify email and log in
4. Go to: https://search.censys.io/account/api
5. Copy both API ID and Secret

**Add to config.json**:
```json
{
  "censys_api_id": "YOUR_API_ID",
  "censys_api_secret": "YOUR_API_SECRET"
}
```

**What it gives you**:
- Certificate transparency data
- Host information
- Service detection

---

## Priority 3: Advanced (Optional)

### 6. BinaryEdge (⭐⭐ - Advanced Features)
**Free Tier**: 250 queries/month

**Steps**:
1. Go to: https://app.binaryedge.io/sign-up
2. Sign up with email
3. Verify email
4. Go to: https://app.binaryedge.io/account/api
5. Copy API key

**Add to config.json**:
```json
{
  "binaryedge_api_key": "YOUR_KEY_HERE"
}
```

---

## Quick Setup (All at Once)

**Time Required**: ~10-15 minutes for all 6 keys

**Recommended minimum**:
1. SecurityTrails (2 minutes)
2. GitHub Token (1 minute)
3. VirusTotal (2 minutes)

These three will give you 80% of the value.

---

## After Getting Keys

1. Edit your `config.json` file:
```bash
nano config.json
```

2. Add your keys:
```json
{
  "securitytrails_api_key": "abc123...",
  "github_token": "ghp_xyz789...",
  "virustotal_api_key": "def456...",
  "shodan_api_key": "ghi789...",
  "censys_api_id": "jkl012...",
  "censys_api_secret": "mno345...",
  "binaryedge_api_key": "pqr678..."
}
```

3. Save and exit (Ctrl+X, then Y, then Enter)

4. Run the tool - it will automatically use available keys:
```bash
./run_advanced_hunt.sh
```

---

## Verification

To verify your keys are working:

```bash
# Test SecurityTrails
curl "https://api.securitytrails.com/v1/ping" -H "APIKEY: YOUR_KEY"

# Test VirusTotal
curl "https://www.virustotal.com/api/v3/domains/google.com" \
  -H "x-apikey: YOUR_KEY"

# Test GitHub
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
```

---

## Cost Comparison

| Service | Free Tier | Paid Plans | Best For |
|---------|-----------|------------|----------|
| SecurityTrails | 50/month | $49/month | Historical DNS |
| GitHub | Unlimited | N/A | Code search |
| VirusTotal | 500/day | $460/month | Passive DNS |
| Shodan | 100/month | $59/month | IP research |
| Censys | 250/month | $99/month | Certificates |
| BinaryEdge | 250/month | $100/month | Advanced scans |

**For bug bounty**: The free tiers are usually sufficient!

---

## Rate Limiting Tips

Even with free tiers, you can be very effective:

1. **SecurityTrails** (50/month): Use for your most important targets
2. **GitHub** (unlimited): Use freely for all searches
3. **VirusTotal** (500/day): Plenty for multiple domains
4. **Shodan** (100/month): Use for interesting IPs you discover

---

## No API Keys?

The tool still works great without API keys! You'll still get:
- ✅ Email infrastructure mining
- ✅ Cloud bucket enumeration
- ✅ Smart permutations
- ✅ JavaScript endpoint extraction
- ✅ Certificate transparency (crt.sh - no key needed)
- ✅ Acquisition mapping

API keys just add **bonus data sources**.

---

## Questions?

- Keys not working? Check you copied them correctly (no extra spaces)
- Rate limited? The tool handles this automatically with delays
- Want to upgrade? Most services offer month-to-month paid plans

Happy Hunting! 🎯
