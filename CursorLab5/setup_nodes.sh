#!/bin/bash
# Script to create nodes_main.txt for Bitcoin Lab 5

echo "Creating nodes_main.txt for Bitcoin Lab 5..."
echo ""

# Check if we're in the right directory
if [ ! -f "makeseeds.py" ]; then
    echo "Error: makeseeds.py not found. Please run this script from the CursorLab5 directory."
    exit 1
fi

# Step 1: Download seeds file
echo "Step 1: Downloading seeds_main.txt..."
curl -s https://bitcoin.sipa.be/seeds.txt.gz | gzip -dc > seeds_main.txt
if [ $? -eq 0 ]; then
    echo "✓ Downloaded seeds_main.txt"
else
    echo "✗ Failed to download seeds_main.txt"
    exit 1
fi

# Step 2: Download ASMap file
echo "Step 2: Downloading asmap-filled.dat..."
curl -s https://bitcoin.sipa.be/asmap-filled.dat > asmap-filled.dat
if [ $? -eq 0 ]; then
    echo "✓ Downloaded asmap-filled.dat"
else
    echo "✗ Failed to download asmap-filled.dat"
    exit 1
fi

# Step 3: Generate nodes_main.txt
echo "Step 3: Generating nodes_main.txt (this may take a few minutes)..."
python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Generated nodes_main.txt"
    echo ""
    echo "First 10 nodes:"
    head -10 nodes_main.txt
    echo ""
    echo "Total nodes: $(wc -l < nodes_main.txt)"
    echo ""
    echo "✓ Setup complete! Now update BTC_HOST in lab5.py with one of these IP addresses."
else
    echo "✗ Failed to generate nodes_main.txt"
    exit 1
fi
