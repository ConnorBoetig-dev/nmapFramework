#!/bin/bash
# Network Scanner Launch Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found!${NC}"
    echo -e "${YELLOW}Please run: python3 setup_dependencies.py${NC}"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Run the pipeline
echo -e "${GREEN}Starting Network Scanner...${NC}"
python3 pipeline.py "$@"
