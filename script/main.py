# This is a sample Python script.
# from hacking.hack import *
import nmap
from scapy.all import *
import os
import hashlib

sc = nmap.PortScanner()


# Press Maj+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def menu():
    print(""" _____ _               _          _____ _ _ _\n       
|  __ \ |             | |        |  ___| (_) |      \n
| |  \/ |__   ___  ___| |_ ______| |__ | |_| |_ ___ \n
| | __| '_ \ / _ \/ __| __|______|  __|| | | __/ _ \\
| |_\ \ | | | (_) \__ \ |_       | |___| | | ||  __/\n
 \____/_| |_|\___/|___/\__|      \____/|_|_|\__\___|\n""")
    print("************************ Script hacking en python *************************")
    n = input("1 :Nmap Scanner\n"
              "2 :Scan Vulnerability\n"
              "3 :Exploit\n"
              "4 :Scapy\n"
              "5 :Password Cracking"
              "\nEntre votre numero :\n"
              )
    if n == '1':
        nmap()
    if n == '2':
        vul()
    if n == '3':
        exploit()
    if n == '4':
        scapy()
    if n == '5':
        password_cracking()
    else:
        print("Default choice")


def nmap():
    print("============================Network Scanner=====================")
    ip = input("Entre votre adresse ip \n")
    sc.scan(ip, '1-1024')
    print(sc.scaninfo())
    print(sc[ip]['tcp'].keys())


def vul():
    print("============================Network Vulnerability==================")
    ip = input("Entre votre adresse ip \n")
    print(os.system('nmap --script nmap-vulners -sV' + ip))


def exploit():
    print("============================Network Exploit=====================")
    print(os.system('msfconsole'))


def scapy():
    print("============================Network Scapy=======================")
    print(os.system('scapy'))


def password_cracking():
    pass_hash = input("Entre le md5 hash : \n")
    worldList = input("Nom du fichier : \n")
    try:
        pass_file = open(worldList, "r")
    except:
        print("Fichier incorrect")
        quit()
    for word in pass_file:
        enc_word = word.encode('utf-8')
        digest = hashlib.md5(enc_word.strip()).hexdigest()
        if digest == pass_hash:
            print("Password incorrect ")
            print("password is " + word)
            flag = 1
            break
    if flag == 0:
        print("password/passphrase is not in the list")


# def hack():
#     print("============================Network Scapy=======================")
#     print(arp_monitor_callback())


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    menu()
