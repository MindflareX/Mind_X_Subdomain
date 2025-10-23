#!/bin/bash
# Mind_X_Subdomain - Automated Hunting Script
# Usage: ./run_advanced_hunt.sh

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "    ╔═══════════════════════════════════════════════════════════╗"
echo "    ║         Mind_X_Subdomain - Automated Workflow             ║"
echo "    ║         Advanced Subdomain Discovery & Analysis           ║"
echo "    ║                                                           ║"
echo "    ║                 Created by: MindFlare                     ║"
echo "    ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Step 1: Combine existing subdomains
echo -e "${CYAN}[*] Step 1: Combining existing subdomain files...${NC}"
if [ -f "../subfinder.txt" ] && [ -f "../cero_domains.txt" ]; then
    cat ../subfinder.txt ../cero_domains.txt | sort -u > all_known_subdomains.txt
    COUNT=$(wc -l < all_known_subdomains.txt)
    echo -e "${GREEN}[+] Combined: $COUNT unique subdomains${NC}"
else
    echo -e "${YELLOW}[!] Warning: subfinder.txt or cero_domains.txt not found in parent directory${NC}"
    echo "[*] Looking for other .txt files..."
    if [ -f "../subfinder.txt" ]; then
        cp ../subfinder.txt all_known_subdomains.txt
    elif [ -f "../cero_domains.txt" ]; then
        cp ../cero_domains.txt all_known_subdomains.txt
    else
        echo "[!] No subdomain files found. Run with empty dataset."
        touch all_known_subdomains.txt
    fi
fi

# Step 2: Extract main domain
echo ""
echo -e "${CYAN}[*] Step 2: Detecting target domain...${NC}"
if [ -s "all_known_subdomains.txt" ]; then
    DOMAIN=$(head -1 all_known_subdomains.txt | rev | cut -d'.' -f1,2 | rev)
else
    DOMAIN="paypal.com"
fi
echo -e "${GREEN}[+] Target domain: $DOMAIN${NC}"

# Step 3: Run advanced discovery modules
echo ""
echo -e "${CYAN}[*] Step 3: Running advanced discovery modules...${NC}"
echo "[*] This may take a while depending on your dataset size"
echo ""

# Create output directory
mkdir -p advanced_results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Run different module combinations

# Module 1: Email & DNS Infrastructure
echo -e "${YELLOW}[>] Running: Email Infrastructure Mining${NC}"
python3 Mind_X_Subdomain.py \
    -d $DOMAIN \
    -f all_known_subdomains.txt \
    -m email \
    -o advanced_results/email_discoveries_${TIMESTAMP}.txt \
    -r 1.5

# Module 2: Cloud Storage
echo ""
echo -e "${YELLOW}[>] Running: Cloud Storage Enumeration${NC}"
python3 Mind_X_Subdomain.py \
    -d $DOMAIN \
    -f all_known_subdomains.txt \
    -m cloud \
    -o advanced_results/cloud_discoveries_${TIMESTAMP}.txt \
    -r 1.0

# Module 3: Certificate Transparency Deep Dive
echo ""
echo -e "${YELLOW}[>] Running: Certificate Transparency Analysis${NC}"
python3 Mind_X_Subdomain.py \
    -d $DOMAIN \
    -f all_known_subdomains.txt \
    -m ct \
    -o advanced_results/ct_discoveries_${TIMESTAMP}.txt \
    -r 2.0

# Module 4: Smart Permutations
echo ""
echo -e "${YELLOW}[>] Running: Smart Permutation Generation${NC}"
python3 Mind_X_Subdomain.py \
    -d $DOMAIN \
    -f all_known_subdomains.txt \
    -m permutations \
    -o advanced_results/permutation_discoveries_${TIMESTAMP}.txt \
    -r 1.5

# Module 5: JavaScript Mining
echo ""
echo -e "${YELLOW}[>] Running: JavaScript Endpoint Extraction${NC}"
python3 Mind_X_Subdomain.py \
    -d $DOMAIN \
    -f all_known_subdomains.txt \
    -m javascript \
    -o advanced_results/js_discoveries_${TIMESTAMP}.txt \
    -r 2.0

# Module 6: Acquisition Mapping (PayPal specific)
if [[ "$DOMAIN" == *"paypal"* ]] || [[ "$DOMAIN" == *"venmo"* ]] || [[ "$DOMAIN" == *"xoom"* ]]; then
    echo ""
    echo -e "${YELLOW}[>] Running: Acquisition Domain Mapping${NC}"
    python3 Mind_X_Subdomain.py \
        -d $DOMAIN \
        -f all_known_subdomains.txt \
        -m acquisitions \
        -o advanced_results/acquisition_discoveries_${TIMESTAMP}.txt \
        -r 1.5
fi

# Step 4: Combine all discoveries
echo ""
echo -e "${CYAN}[*] Step 4: Combining all discoveries...${NC}"
cat advanced_results/*_discoveries_${TIMESTAMP}.txt 2>/dev/null | sort -u > advanced_results/ALL_NEW_DISCOVERIES_${TIMESTAMP}.txt

NEW_COUNT=$(wc -l < advanced_results/ALL_NEW_DISCOVERIES_${TIMESTAMP}.txt 2>/dev/null || echo "0")

# Step 5: Summary
echo ""
echo "================================================================"
echo -e "${GREEN}           DISCOVERY COMPLETE!${NC}"
echo "================================================================"
echo -e "${GREEN}[+] New Subdomains Found: $NEW_COUNT${NC}"
echo -e "${GREEN}[+] Results saved to: advanced_results/ALL_NEW_DISCOVERIES_${TIMESTAMP}.txt${NC}"
echo ""

if [ "$NEW_COUNT" -gt 0 ]; then
    echo -e "${CYAN}[*] Next Steps:${NC}"
    echo "1. Validate which domains are alive:"
    echo "   cat advanced_results/ALL_NEW_DISCOVERIES_${TIMESTAMP}.txt | httpx -o alive_new.txt"
    echo ""
    echo "2. Check for interesting patterns:"
    echo "   grep -E '(admin|internal|dev|stage|api|test)' advanced_results/ALL_NEW_DISCOVERIES_${TIMESTAMP}.txt"
    echo ""
    echo "3. Take screenshots of alive domains:"
    echo "   cat alive_new.txt | aquatone"
    echo ""
fi

# Cleanup
rm -f test_sample.txt test_output.txt 2>/dev/null

echo -e "${GREEN}[+] Happy Hunting!${NC}"
