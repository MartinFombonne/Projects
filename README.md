# SSE Scheme

The following project has for purpose to set up and test a Searchable symmetric encryption scheme (SSE). 

I-How does it work ? 

The project is composed of 5 scripts : SID.py, Owner.py, TA.py, CSP.py and User.py. The SID.py is the selection menu. For the others each script represents an entity (DataOwner, User, TA or CSP). 
But what is SSE exactly about ? A data owner wants to store his file on a CSP and allows queries on the files but cannot trust the CSP to received the files in plaintext. So the dataowner use the SSE scheme to stored encrypted indexes in the CSP and a Trusted Authority (TA) to do that. Once the files has been sent to the CSP. A user with the secret key should be able to queries for files that contains specific words and retrieved files from the CSP. All this process is done without the CSP being able to learn what kind of text is stored in his database, what words are the users searching for and what files name it returns.


II- How to try it ? 

-First, you need to complete the requirements.
-Then, simply add you dataset (TXT texts) to the IniFiles folder.
-You are now ready to go, you simply run the SID.py script 
-That would pop a selection menu where you can choose between actions as a Data Owner or a simple user. Here we don't talk about authentication but obviously in a real word application there should be a way to be identify as a Dataowner or a user. 
-The first think you want to do the is to send you initial dataset to the CSP(Press 1 ). This operation can take some times depends on how many files and their sizes.
-When the initialisation part is over you know have different choices : 
    * Add a new file to the CSP as a Dataowner (Simply make sure that the file you want to add can be found in the "addfiles" folder and Press 2)
    * Search as a simple user for a the files that contains a specific word (Press 3 and enter the word you want to query for)
    * Retrieved a file as a simple user from the CSP. If you already know the name of the file you are looking for you can simply press 4 and enter it. If not you will first need to use the Search option. All the files retrieved using this option can be found in the "Retrieved folder" 

III-Requirements

First you need to set up the mysql databases that the script will use :

A- DataOwner database definition :

>CREATE DATABASE SID; 

>CREATE TABLE sse_TA(TA_keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
TA_keyword varchar(255), TA_keyword_numfiles int, TA_keyword_numsearch int)

mysql> SHOW COLUMNS from sse_TA;  
+----------------------+--------------+------+-----+---------+----------------+    
| Field                 | Type         | Null | Key | Default | Extra          |    
+----------------------+--------------+------+-----+---------+----------------+    
| TA_keyword_id         | int          | NO   | PRI | NULL    | auto_increment |    
| TA_keyword            | varchar(255) | YES  |     | NULL    |                |    
| TA_keyword_numfiles   | int          | YES  |     | NULL    |                |    
| TA_keyword_numsearch  | int          | YES  |     | NULL    |                |    
+----------------------+--------------+------+-----+---------+----------------+    

B- CSP database definition :  

>CREATE DATABASE CSP;   

>TABLE CSP_dict :   

>CREATE TABLE CSP_dict(id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
csp_keywords_address varchar(255), csp_keywords_value varchar(255));

>mysql> SHOW COLUMNS FROM CSP_dict;  
+----------------------+--------------+------+-----+---------+----------------+  
| Field                | Type         | Null | Key | Default | Extra          |  
+----------------------+--------------+------+-----+---------+----------------+  
| id                   | int          | NO   | PRI | NULL    | auto_increment |  
| csp_keywords_address | varchar(255) | YES  |     | NULL    |                |  
| csp_keywords_value   | varchar(255) | YES  |     | NULL    |                |  
+----------------------+--------------+------+-----+---------+----------------+  

TABLE library :   

>CREATE TABLE library(id varchar(255) PRIMARY KEY,
file longtext);  

>mysql> SHOW COLUMNS FROM library;  
+-------+--------------+------+-----+---------+-------+  
| Field | Type         | Null | Key | Default | Extra |  
+-------+--------------+------+-----+---------+-------+  
| id    | varchar(255) | NO   | PRI | NULL    |       |  
| file  | longtext     | YES  |     | NULL    |       |  
+-------+--------------+------+-----+---------+-------+  

C- TA database definition :   

>CREATE DATABASE TA;   

>CREATE DATABASE TA;  

>CREATE TABLE sse_TA(TA_keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
TA_keyword varchar(255), TA_keyword_numfiles int, TA_keyword_numsearch int);    

>mysql> SHOW COLUMNS from sse_TA;  
+----------------------+--------------+------+-----+---------+----------------+  
| Field                | Type         | Null | Key | Default | Extra          |  
+----------------------+--------------+------+-----+---------+----------------+  
| TA_id                | int          | NO   | PRI | NULL    | auto_increment |  
| TA_keyword           | varchar(255) | YES  |     | NULL    |                |  
| TA_keyword_numfiles  | int          | YES  |     | NULL    |                |  
| TA_keyword_numsearch | int          | YES  |     | NULL    |                |  
+----------------------+--------------+------+-----+---------+----------------+  


D- Final steps  

-Make sure to use "Password123? as password to connect to the database or to modify the script Owner.py,TA.py and CSP.py  
-Be sure to install the packet for the following list :   

    * pymysql
    * hashlib
    * time
    * ast
    * Cryptodome
    * base64
    * tqdm
    * re
    * os
    * glob

> pip install pymysql hashlib time ast Cryptodome base64 tqdm re os glob
