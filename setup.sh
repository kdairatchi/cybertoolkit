#!/bin/bash

echo "Setting up the environment for Cybersecurity Toolkit..."

# Update system and install required system packages
sudo apt-get update
sudo apt-get install -y python3 python3-pip sqlite3 chromium-browser

# Install ChromeDriver
echo "Installing ChromeDriver..."
CHROME_DRIVER_VERSION=$(curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE)
wget -N https://chromedriver.storage.googleapis.com/$CHROME_DRIVER_VERSION/chromedriver_linux64.zip -P ~/
unzip ~/chromedriver_linux64.zip -d ~/
sudo mv -f ~/chromedriver /usr/local/bin/chromedriver
sudo chmod +x /usr/local/bin/chromedriver
rm ~/chromedriver_linux64.zip

# Install required Python libraries
echo "Installing Python libraries..."
pip3 install -r requirements.txt

echo "Setup complete!"
