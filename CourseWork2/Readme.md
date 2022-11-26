# SSE Scheme

The following project has for purpose to set up and test a Searchable symmetric encryption scheme (SSE). 

__Demo__:  https://youtu.be/6tEFJJ8vhvM  

__I-What is SSE ?__

Searchable symmetric encryption scheme allows a data owner who needs to store files on a Cloud service provider (CSP) to stored them securely. Indeed, the data owner do not trust the CSP but need it to allows search queries on the stored files. In order to make that possible the owner need to stored encrypted indexes in the CSP and in a Trusted Authority (TA) to be able to safely recover some informations about the encrypted file. Once the files have been sent to the CSP. A user with the secret key is able to queries for files that contains specific words and retrieved files from the CSP. All this process is done without the CSP being able to learn what kind of text is stored in his database, what words are the users searching for and what files name it returns.


__II-How does it work ?__ 

The project is composed of 5 scripts : SID.py, Owner.py, TA.py, CSP.py and User.py. 
The SID.py is the selection menu. The other script correspond what would run on the different entities (DataOwner, User, TA or CSP). 
Note that in this experience the Key is stored locally in the same file for everyone. But in the real world application only the owner and user have access to the full secret key and the TA only has access to the Kta symmetrical key. So the Dataowner have to find a way to transmit securely the secret key to the user and the symetrical key Kta to the Trusted Authority for them to store their own copies. 

Initiazation : 

The Dataowner process all the words in all the files the initialization file and stored the correspondinf tuples in his database. Then he copy the indexes in the TA and send the encrypted files and address/value tuples for the CSP to store. The tuples addresses allows the users to indentify specific information whithout the CSP being able to give sense to the addresses and the values are encrypted data that the users with the corresponding key can decrypt in order to learn in which file can be found the searched word. 

Search : 

The users that have the same secret key as the one used for encryption can query the CSP for a specific word. The CSP return all the files that cotnains this specific word. In order to do that the user need to reach the TA to learn in how many files the searched word exist and how many time it has been searched. Thank to this information the user can compute the addresses needed to recover values from the CSP. Once this values are retrieved the user can use the secret key to decrypt the value and recover the name of the files.

Retrieve Files :  

Once the user has learned some files that exist on the CSP he can download them directly from the CSP by send a retrieve request with the encrypted name of the file to the CSP using the secret key. The CSP simply return the files on a specific folder



__III- How to try it ?__ 

>- First, you need to run the setup.py script in order to create the Mysql Databases and to verify that you have downloaded all the requiered python modules (if there is an issue check section IV. D) 
>- Then, simply add files you want to store in the IniFiles folder.  
>- You are now ready to go, you simply run the SID.py script.   
>- A selection menu should appears where you can choose between actions as a Data Owner or a simple user. Here we don't talk about authentication but obviously in a real word application there should be a way to be identify as a Dataowner or a user.   
>- The first think you want to do the is to send you initial dataset to the CSP(Press 1 ). This operation can take some times depends on how many files and their sizes.  
>- When the initialisation part is over you know have different choices :   
>   - Add a new file to the CSP as a Dataowner (Simply make sure that the file you want to add can be found in the "addfiles" folder and Press 2)  
>   - Search as a simple user for a the files that contains a specific word (Press 3 and enter the word you want to query for)  
>   - Retrieved a file as a simple user from the CSP. If you already know the name of the file you are looking for you can simply press 4 and enter it. If not you will first need to use the Search option. All the files retrieved using this option can be found in the "Retrieved" folder.   

__IV-Requirements__

-First you need to install mysql and to ensure that the service is running (sudo service mysqld start).
-Then the script Setup.py will be used to create the databases use in the SSE scheme, verify if all the need python modules are installed and finally to stored the credentials to access to the databases. 

*A- DataOwner database definition*

>Definition sse_user :
>CREATE TABLE sse_user(keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
keyword varchar(255), keyword_numfiles int, keyword_numsearch int)  

  
>| Field | Type| Null | Key | Default | Extra |    
>| :----- | :----- | :----- | :----- | :----- | :----- |     
>| TA_keyword_id         | int          | NO   | PRI | NULL    | auto_increment |    
>| TA_keyword            | varchar(255) | YES  |     | NULL    |                |    
>| TA_keyword_numfiles   | int          | YES  |     | NULL    |                |    
>| TA_keyword_numsearch  | int          | YES  |     | NULL    |                |    
   

*B- CSP database definition*  


>Definition CSP_dict:  
>CREATE TABLE CSP_dict(id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
csp_keywords_address varchar(255), csp_keywords_value varchar(255));

>mysql> SHOW COLUMNS FROM CSP_dict;  
 
>| Field                | Type         | Null | Key | Default | Extra          |  
>| :----- | :----- | :----- | :----- | :----- | :----- |  
>| id                   | int          | NO   | PRI | NULL    | auto_increment |  
>| csp_keywords_address | varchar(255) | YES  |     | NULL    |                |  
>| csp_keywords_value   | varchar(255) | YES  |     | NULL    |                |  

Definition library:   
>CREATE TABLE library(id varchar(255) PRIMARY KEY,
file longtext);  

>mysql> SHOW COLUMNS FROM library;  

>| Field | Type         | Null | Key | Default | Extra |  
>| :----- | :----- | :----- | :----- | :----- | :----- |    
>| id    | varchar(255) | NO   | PRI | NULL    |       |  
>| file  | longtext     | YES  |     | NULL    |       |  
    

*C- TA database definition*  

>Definition sse_TA :  
>Csudo service mysqld start
REATE TABLE sse_TA(TA_keyword_id int PRIMARY KEY NOT NULL AUTO_INCREMENT,
TA_keyword varchar(255), TA_keyword_numfiles int, TA_keyword_numsearch int);    
  
>| Field                | Type         | Null | Key | Default | Extra          |  
>| :----- | :----- | :----- | :----- | :----- | :----- |    
>| TA_id                | int          | NO   | PRI | NULL    | auto_increment |  
>| TA_keyword           | varchar(255) | YES  |     | NULL    |                |  
>| TA_keyword_numfiles  | int          | YES  |     | NULL    |                |  
>| TA_keyword_numsearch | int          | YES  |     | NULL    |                |  


*D- Final steps*  

-Make sure that all the database have been correctly create. 
-Make sure that you are able to import all this module :   

    - pymysql
    - hashlib
    - time
    - ast
    - Cryptodome
    - base64
    - tqdm
    - re
    - os
    - glob
