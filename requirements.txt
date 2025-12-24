#!/bin/bash

# 1. System Updates & Dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git wget curl unzip nikto golang-go -y

# 2. Python Libraries
pip3 install -r python_requirements.txt
playwright install

# 3. Go Tools Setup
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
export PATH=$PATH:$(go env GOPATH)/bin

# 4. Install Recon Tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# 5. Install Findomain
wget https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

# 6. Install Bettercap
sudo apt install bettercap -y

echo "Setup Complete! Restart your terminal."

# Bettercap: Download the .zip from Bettercap Releases. Extract bettercap.exe into the same folder as your script. https://github.com/bettercap/bettercap/releases
# Findomain: Download the Windows binary from Findomain Releases. Place findomain.exe in the script folder. https://github.com/Findomain/Findomain/releases

