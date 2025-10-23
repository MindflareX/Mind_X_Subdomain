#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN_FILE="domain"
OUTPUT_DIR="subdomain_results"
RATE_LIMIT="1.5"
MODULES="email reverse_ip cloud permutations asn ct javascript acquisitions"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Mind_X Subdomain - Bulk Domain Scanner            ║"
echo "║              Processing Multiple Domains                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if domain file exists
if [ ! -f "$DOMAIN_FILE" ]; then
    echo -e "${RED}[!] Error: $DOMAIN_FILE not found!${NC}"
    exit 1
fi

# Count total domains
TOTAL_DOMAINS=$(grep -v '^$' "$DOMAIN_FILE" | wc -l)
CURRENT=0

echo -e "${GREEN}[+] Found $TOTAL_DOMAINS domains to scan${NC}"
echo -e "${YELLOW}[*] Output directory: $OUTPUT_DIR${NC}"
echo -e "${YELLOW}[*] Rate limit: $RATE_LIMIT seconds${NC}"
echo ""

# Process each domain
while IFS= read -r domain || [ -n "$domain" ]; do
    # Skip empty lines
    [ -z "$(echo $domain | xargs)" ] && continue

    # Clean domain name
    domain=$(echo "$domain" | xargs)
    CURRENT=$((CURRENT + 1))

    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}[*] [$CURRENT/$TOTAL_DOMAINS] Processing: $domain${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

    # Create domain-specific output file
    OUTPUT_FILE="$OUTPUT_DIR/${domain}_subdomains.txt"

    # Run the subdomain scanner
    python3 Mind_X_Subdomain.py \
        -d "$domain" \
        -o "$OUTPUT_FILE" \
        -m $MODULES \
        -r "$RATE_LIMIT"

    # Check if scan was successful
    if [ $? -eq 0 ]; then
        if [ -f "$OUTPUT_FILE" ]; then
            COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo "0")
            echo -e "${GREEN}[✓] Completed $domain - Found $COUNT subdomains${NC}"
            echo -e "${GREEN}[✓] Saved to: $OUTPUT_FILE${NC}"
        else
            echo -e "${YELLOW}[!] Completed $domain - No new subdomains found${NC}"
        fi
    else
        echo -e "${RED}[✗] Error processing $domain${NC}"
    fi

    # Small delay between domains
    sleep 2

done < "$DOMAIN_FILE"

# Summary
echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] All domains processed!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

# Generate summary report
SUMMARY_FILE="$OUTPUT_DIR/SUMMARY.txt"
echo "Mind_X Subdomain Discovery - Summary Report" > "$SUMMARY_FILE"
echo "Generated: $(date)" >> "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

TOTAL_SUBDOMAINS=0
for file in "$OUTPUT_DIR"/*.txt; do
    [ "$file" = "$SUMMARY_FILE" ] && continue
    [ -f "$file" ] || continue

    filename=$(basename "$file")
    count=$(wc -l < "$file" 2>/dev/null || echo "0")
    TOTAL_SUBDOMAINS=$((TOTAL_SUBDOMAINS + count))
    printf "%-40s : %6d subdomains\n" "$filename" "$count" >> "$SUMMARY_FILE"
done

echo "" >> "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "TOTAL SUBDOMAINS DISCOVERED: $TOTAL_SUBDOMAINS" >> "$SUMMARY_FILE"

# Display summary
echo -e "${YELLOW}[*] Summary Report:${NC}"
cat "$SUMMARY_FILE"

echo -e "\n${GREEN}[+] Results saved in: $OUTPUT_DIR/${NC}"
echo -e "${GREEN}[+] Summary report: $SUMMARY_FILE${NC}"

# Combine all results
COMBINED_FILE="$OUTPUT_DIR/ALL_SUBDOMAINS_COMBINED.txt"
cat "$OUTPUT_DIR"/*_subdomains.txt 2>/dev/null | sort -u > "$COMBINED_FILE"
COMBINED_COUNT=$(wc -l < "$COMBINED_FILE" 2>/dev/null || echo "0")
echo -e "${GREEN}[+] Combined unique subdomains: $COMBINED_FILE ($COMBINED_COUNT total)${NC}\n"
