import requests
from bs4 import BeautifulSoup
import json

# Scrape Wikipedia page                                                
url = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers" 
response = requests.get(url)                                           
soup = BeautifulSoup(response.content, 'html.parser')                  
                                                                       
# Find all relevant tables                                             
tables = soup.find_all("table", {"class": "wikitable"})                
                                                                       
# Initialize a dictionary for storing port data                        
port_data = {}                                                         

# Function to clean description: remove references and handle hyperlinks
def clean_description(description):
    # Remove <sup> elements (references)
    for sup in description.find_all('sup', class_='reference'):
        sup.decompose()

    # Replace all <a> tags (including 'a href') with their inner text and ensure spaces around them
    for a in description.find_all('a', href=True):
        a.replace_with(" " + a.get_text(strip=True) + " ")  # Replace <a> with inner text

    return description.get_text(" ", strip=True)  # Return cleaned text

# Function to add multiple ports for ranges like "20-25" or "20–25" (using en dash)
def add_port_range(port_range, protocol, description):
    port_range = port_range.replace('\u2013', '-')  # Replace en dash with hyphen if present
    start, end = map(int, port_range.split('-'))  # Split the range and convert to integers
    for port in range(start, end + 1):
        port_data[str(port)] = {
            "protocol": protocol,
            "service": description
        }

# Function to check if the string contains only ASCII characters
def is_ascii(s):
    return all(c.isascii() for c in s)

# Process each table
for table in tables:
    rows = table.find_all('tr')[1:]  # Skip header row

    # Process each row
    for row in rows:
        cols = row.find_all('td')
        if len(cols) >= 4:
            port = cols[0].get_text(strip=True).replace('\u2013', '-')  # Handle en dash in port range
            description_html = cols[-1]  # Get HTML for description column

            # Clean description: remove references and add spaces around links
            description = clean_description(description_html)

            # Exclude if the description contains non-ASCII characters
            if not is_ascii(description):
                continue

            # Check if TCP and UDP columns are merged using colspan
            if 'colspan' in cols[1].attrs and cols[1].attrs['colspan'] == '2':
                tcp = udp = cols[1].get_text(strip=True).lower()
            else:
                tcp = cols[1].get_text(strip=True).lower()
                udp = cols[2].get_text(strip=True).lower()

            # Determine protocol
            if any(x in tcp for x in ['yes', 'assigned', 'unofficial']) and any(x in udp for x in ['yes', 'assigned', 'unofficial']):
                protocol = "TCP/UDP"
            elif any(x in tcp for x in ['yes', 'assigned', 'unofficial']) and (udp == "" or udp == "no"):
                protocol = "TCP"
            elif any(x in udp for x in ['yes', 'assigned', 'unofficial']) and (tcp == "" or tcp == "no"):
                protocol = "UDP"
            elif tcp == "reserved" and udp != "reserved":
                protocol = "UDP"
            elif udp == "reserved" and tcp != "reserved":
                protocol = "TCP"
            else:
                continue  # Skip if not valid for either protocol

            # Check for port ranges like "20-25" or "20–25"
            if '-' in port:
                add_port_range(port, protocol, description)
            else:
                # Add single port to JSON data
                port_data[port] = {
                    "protocol": protocol,
                    "service": description
                }

# Save to JSON file
with open('port_data.json', 'w') as json_file:
    json.dump(port_data, json_file, indent=4)

