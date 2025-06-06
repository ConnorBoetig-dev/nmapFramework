#!/bin/bash

# Network Mapper - Dependency Discovery and Installation Script
# This script will find all Python imports and create a comprehensive requirements.txt

echo "🔍 Network Mapper Dependency Discovery"
echo "======================================"

# Method 1: Find all Python imports in your project
echo "📋 Finding all Python imports in your project..."
find . -name "*.py" -not -path "./venv/*" -exec grep -h "^import\|^from" {} \; | sort | uniq > found_imports.txt

echo "📋 All imports found:"
cat found_imports.txt

echo ""
echo "🔧 Extracting module names..."

# Extract just the module names (this is a simplified extraction)
grep -E "^(import|from)" found_imports.txt | \
    sed 's/^import //' | \
    sed 's/^from //' | \
    sed 's/ import.*$//' | \
    sed 's/\..*$//' | \
    sort | uniq > module_names.txt

echo "📦 Modules identified:"
cat module_names.txt

# Method 2: Check what's already installed in your venv
echo ""
echo "🔍 Checking what's currently installed in your virtual environment..."
pip list --format=freeze > current_packages.txt
echo "Current packages:"
cat current_packages.txt

# Method 3: Create a comprehensive requirements.txt based on your project needs
echo ""
echo "📝 Creating comprehensive requirements.txt..."

cat > requirements.txt << 'EOF'
# Network Mapper - Python Dependencies
# Core network scanning and analysis tools

# Network scanning
python-nmap>=1.6.0

# XML and HTML parsing
lxml>=4.9.0
beautifulsoup4>=4.11.0

# Template rendering for reports
jinja2>=3.1.0

# Data analysis and manipulation
pandas>=1.5.0
numpy>=1.24.0

# JSON handling (usually built-in, but explicit for clarity)
# json - built-in module

# System and file operations
# os, sys, subprocess, pathlib - built-in modules

# Date and time handling
# datetime - built-in module

# Argument parsing
# argparse - built-in module

# Progress bars and CLI enhancements
tqdm>=4.64.0

# Logging enhancements
colorlog>=6.7.0

# Network utilities
requests>=2.28.0

# Report generation utilities
matplotlib>=3.6.0
seaborn>=0.12.0

# Development and testing (optional)
pytest>=7.2.0
black>=22.10.0
flake8>=5.0.0
EOF

echo "✅ Created requirements.txt with comprehensive dependencies"
echo ""
echo "🚀 Now installing all dependencies..."
echo "======================================"

# Install all requirements
pip install -r requirements.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "🔍 Verifying installation..."
echo "=============================="

# Verify key modules are installed
python3 -c "
import sys
modules_to_check = [
    'nmap', 'lxml', 'bs4', 'jinja2', 'pandas', 
    'numpy', 'tqdm', 'colorlog', 'requests', 'matplotlib'
]

print('🔍 Module verification:')
for module in modules_to_check:
    try:
        __import__(module)
        print(f'✅ {module} - OK')
    except ImportError as e:
        print(f'❌ {module} - MISSING ({e})')
"

echo ""
echo "🎯 Quick fix commands if issues persist:"
echo "========================================"
echo "# Force reinstall problematic packages:"
echo "pip install --force-reinstall jinja2"
echo "pip install --force-reinstall python-nmap"
echo "pip install --force-reinstall lxml"
echo ""
echo "# If you get permission errors:"
echo "pip install --user -r requirements.txt"
echo ""
echo "# If you want to upgrade all packages:"
echo "pip install --upgrade -r requirements.txt"
echo ""
echo "# Clean install (nuclear option):"
echo "pip freeze | xargs pip uninstall -y"
echo "pip install -r requirements.txt"

# Cleanup temporary files
rm -f found_imports.txt module_names.txt current_packages.txt

echo ""
echo "🎉 Setup complete! Your network mapper should now work without module errors."
