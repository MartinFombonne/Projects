
import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

requirements=["pymysql","tqdm","pycryptodome"]

for package in requirements :
    install(package)



import pymysql
import subprocess
import sys
import re

username=input("Database's user : ")
password=input("Database's password : ")

f = open(".databaseAccess", "w")
f.write(username+" "+password)
f.close()
try :
    #Create the Dataower's Database
    connection = pymysql.connect(user=username, passwd=password,host='localhost')
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE SID")
    connection.commit()
    connection = pymysql.connect(user=username, passwd=password,host='localhost',database='SID')
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE sse_user(keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT, keyword varchar(255), keyword_numfiles int, keyword_numsearch int)")
    connection.commit()

    #Create the TA's Database
    connection = pymysql.connect(user=username, passwd=password,host='localhost')
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE TA")
    connection.commit()
    connection = pymysql.connect(user=username, passwd=password,host='localhost',database='TA')
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE sse_TA(TA_keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT, TA_keyword varchar(255), TA_keyword_numfiles int, TA_keyword_numsearch int);")
    connection.commit()


    #Create the CSP's Databases 
    connection = pymysql.connect(user=username, passwd=password,host='localhost')
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE CSP")
    connection.commit()
    connection = pymysql.connect(user=username, passwd=password,host='localhost',database='CSP')
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE CSP_dict(id int PRIMARY KEY NOT NULL AUTO_INCREMENT, csp_keywords_address varchar(255), csp_keywords_value varchar(255));")
    connection.commit()
    cursor.execute("CREATE TABLE library(id varchar(255) PRIMARY KEY, file longtext);")
    connection.commit()
except:
    print("The Databases already exist")


