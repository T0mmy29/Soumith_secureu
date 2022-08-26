# Subdomain enumerating tool

## Requirements
- We need nmap. If you are using Kali Linux, then you already have nmap. If not, then click on the link to [install nmap](https://nmap.org/download). <br/>
- If you dont have python installed, you can install the latest version of python from [here](https://www.python.org/downloads/). <br/>
- You also need to have following modules. If you do not have any of the following modules, install them by pasting the pip command in your terminal. <br/>
      - requests - https://pypi.org/project/requests/<br/>
      - nmap - https://pypi.org/project/python-nmap/<br/>
      - dnspython - https://pypi.org/project/dnspython/
      


## Usage
-> In your command line, type the following command.
```
python3 (path to subdomain.py) domain name
python3 subdomain.py example.com
```

## What it does
Output subdomains of a website URL and the HTTP response code with a given wordlist . We can use socket to print the subdomains but I used nmap. <br/>
Checks for a valid SSL Certificate.<br/>
Capture ports with their status in the range of 1 to 250.<br/>
Determines if 'X-XSS-Protection' header is enabled or not.<br/>
