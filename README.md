# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
source venv/bin/activate

# 3. Install dependencies (FIXED: requirements.txt, not requirement.txt)
pip install -r requirements.txt

# 4. Run with sudo (for full features)
sudo ./venv/bin/python main.py
