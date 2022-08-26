import requests
import nmap
import socket
import dns.resolver
import sys

# The domain Input is taken from the command line with the sys.argv[1].
domain = sys.argv[1]

# Here I used a 100 wordlist. I also added a 1000 wordlist for subdomains.
subdomain_wordlist = ['www','mail','ftp','localhost','webmail','smtp','pop','ns1','webdisk','ns2','cpanel','whm','autodiscover','autoconfig','m','imap','test','ns','blog','pop3','dev','www2','admin','forum','news','vpn','ns3','mail2','new','mysql','old','lists','support','mobile','mx','static','docs','beta','shop','sql','secure','demo','cp','calendar','wiki','web','media','email','images','img','www1','intranet','portal','video','sip','dns2','api','cdn','stats','dns1','ns4','www3','dns','search','staging','server','mx1','chat','wap','my','svn','mail1','sites','proxy','ads','host','crm','cms','backup','mx2','lyncdiscover','info','apps','download','remote','db','forums','store','relay','files','newsletter','app','live','owa','en','start','sms','office','exchange','ipv4']
    
def subdomain_enum():
    subdomains = []
    print('-'*30)
    print('Subdomains :')
    for subdomain in subdomain_wordlist:
        try:
            
            # Only 'A' records are being checked here we can go through all the dnsrecords with a list.
            # ['A','CNAME','PTR','NS','MX','AAAA','TXT','SOA']
            ip_add = dns.resolver.resolve(f'{subdomain}.{domain}','A')
            if ip_add:
                # Appending the subdomain to get the total count.
                subdomains.append(f'{subdomain}.{domain}')
                # r is HTTP repsonse code of the subdomain.
                r = requests.get(f'http://{subdomain}.{domain}').status_code
                
                if f'{subdomain}.{domain}' in subdomains and r == 200:
                    print(f' - [200 OK] {subdomain}.{domain}')
                else:
                    print(f' - [200 Not OK] {subdomain}.{domain}')
                    # Printing [200 Not OK] for response codes other than 200. 
                    # For example: 403 Forbidden is also shown as [200 Not OK]
                # Code for printing the status code. Just need to comment out the above code and uncomment the below.
                # else:
                #     print(f' - [{r}] {subdomain}.{domain}')

            else: 
                print(f' - [200 Not OK] {subdomain}.{domain}')

        except KeyboardInterrupt:
            # If we want to terminate the process, the program will quit by Ctrl + C.
            quit()
        except dns.resolver.NXDOMAIN:
            # The domain does not exist.
            pass
        except dns.resolver.NoAnswer:
            # the response did not contain any answer.
            pass
    print(f' The Subdomains found : {len(subdomains)}') 

def sslverify():
    temp = domain
    print('-'*30)
    print('SSL Details :')
    
    try:
        # If the domain is given as example.com, we will concatenate the domain with 'http://' to get the response.   
        if 'http' not in domain:
            temp = 'http://' + temp
        response = requests.get(temp)
        
        if response:
            print(" - SSL : Enabled")
            print(f' - issued to {domain}')
    except requests.exceptions.SSLError:
        # The response will throw an error if SSL Certificate is not verified.
        print('SSL CERTIFICATE VERIFY FAILED')



def getports():
    print('-'*30)
    print('Ports')
    # target variable to get the ip address of the domain.
    target = socket.gethostbyname(domain)
    print(target)
    #  Here we use nmap for port scanning.
    nm = nmap.PortScanner()
    for port in range(1,251):
        try:
            result = nm.scan(target,str(port))
            # The result will be a dictionary.
            # print(result)
            port_status = result['scan'][target]['tcp'][port]['state']
            print(f'Port {port} : {port_status}')
        except:
            pass

def headers():
    temp = domain
    if 'http' not in temp:
        temp = 'http://' + temp
    print('-'*30)
    print(' X-XXS-Protection Header : ')
    response = requests.get(temp)

    # X-XSS-Protection = 1: Enabled. The browser will sanitize the page if an xss attack is detected (remove the unsafe parts). 
    if response.headers['X-XSS-Protection'] == 1:
        print("Enabled")
    else:
        print("Disabled")



def main():
    print(f'URL : {domain}')
    subdomain_enum()
    sslverify()
    getports()
    headers()


main()


