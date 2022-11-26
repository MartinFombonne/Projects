
from Cryptodome.Cipher import AES
import hashlib
from Cryptodome.Util.Padding import pad, unpad
import pymysql
import ast
#from CSP import InsertCSP
from TA import IniTa,TaAck
from Cryptodome.Random import get_random_bytes
from tqdm import tqdm
from time import time
import re
import base64
import os

with open(".databaseAccess",'r') as cred:
    credentials=cred.read()
    username=credentials.split()[0]
    password=credentials.split()[1]

connection = pymysql.connect(user=username, passwd=password,host='localhost', database='SID',client_flag= pymysql.constants.CLIENT.MULTI_STATEMENTS)
cursor = connection.cursor()

def KeyTA(): 
    f = open("KEY_SSE","r")
    K=f.read()
    Kta=K[:64]
    return Kta



#This function stored a file in the dictionnary. 
#Input : the key, the name of the file and flag which is a variable that indicate if this function is used during initialisation or not
def AddFile(K,f,flag=0):
    #The function is imported locally to avoid a loop
    from CSP import InsertCSP
    #List of excluded words to optimize the process
    excluded_words=["A","AN","THE","OR","IN","FOR","SO","TO","IF","If","OF","NT","NOR","BY","AND"]
    cipherKta = AES.new(bytes.fromhex(K[0]), AES.MODE_ECB)
    cipherKske = AES.new(bytes.fromhex(K[1]), AES.MODE_ECB)

    #If the function is called during Initialisation it reads the file in the directory Inifiles and if not it read the file in addfiles 
    if flag==1:
        path="./IniFiles/"
    else :
        path="./addfiles/"
    #It opens the file
    with open(path+f,'r') as file:
        #It stores the content of the file in a variable 
        text=file.read()
        MAP={}
        UpdateTA=[]
        InsertString="INSERT INTO sse_user (keyword, keyword_numfiles, keyword_numsearch) VALUES "
        UpdateString=""
        count=0
        #We delete non alphabetical characters from the text
        text=re.sub(r'[\,\"\'\*\~\,\(\)\.\[\]\?\!]','',text.upper())
        #The data is retrieved from the dataowner table 
        if flag==0:
            #If the function is not called during Initialization phase then the data has to be retrieve from the MysqlDatabase
            cursor.execute("""SELECT keyword, keyword_numfiles, keyword_numsearch FROM sse_user""")
            file_index = cursor.fetchall()
            #The data is formated in a dictionnary object to be manipulated more easily
            file_index=dict((a,(b,c)) for a,b,c in file_index)
        elif flag==1:
            #If the function is called from during the Initialization phase the function look at temporary local file that stores the data because it is quicker 
            try:
            #It stores the content of the "database" file in a variable 
                with open("localDatabase",'r') as lDB: 
                    #The data is formated in a dictionnary object to be manipulated more easily
                    file_index=eval(lDB.read())
                    lDB.close()
            except:
            #If it the first file of the Initialization phase the database is empty
                file_index={}
        #The file name is encrypted using AES 
        fID=str(cipherKske.encrypt(pad(f.encode("utf-8"),16)))
        #Each word is processed using a loop if it is not one of the excluded word or if it has already appeared in this file  
        for word in text.split():
            if word not in excluded_words:
                #The word is hashed using SHA-256 to retrive the "keyword"  
                hash=hashlib.sha256(word.encode("utf-8")).hexdigest()
                count+=1                 
                if hash not in UpdateTA:
                    #It tries retrieved the numfile and numsearch value of the word from the database dictionnary if there is an error that mean that the word doesn't not already exist in the database 
                    try :
                        #THE WORD EXISTS IN THE DATABASE 
                        numsearch=file_index[hash][1]
                        numfiles=int(file_index[hash][0])+1
                        UpdateTA.append(hash)
                        #It computes the associated key using the keyword and the numbersearch 
                        Kw=str(cipherKta.encrypt(pad((hash+str(numsearch)).encode("utf-8"),16)))
                        #It then computes the CSP address using SHA-256 for this specific keyword and the number of file the keyword appears in 
                        csp_keywords_address=hashlib.sha256((Kw+str(numfiles)+str(0)).encode("utf-8")).hexdigest()
                        #It encrypts using AES and the key Kske the ID of the file (name of the file) and the number of file 
                        csp_keywords_value=str(base64.b64encode(cipherKske.encrypt(pad((fID+str(numfiles)).encode("utf-8"),16))))[2:-1]
                        newmap={csp_keywords_address:csp_keywords_value}
                        MAP.update(newmap)
                        #It add the Update query for this word to a queue
                        if flag == 1 :
                            ##If the function is called from during the Initialization phase we simply update numfile for the corresonding word in the database
                            file_index[hash][0]=file_index[hash][0]+1  
                        elif flag == 0 :
                            #If the function is not called from during the Initialization phase generate the current word corresponding Update query
                            UpdateString+=f"UPDATE sse_user SET keyword_numfiles='{numfiles}' WHERE keyword='{hash}'; "
                    except:
                        #THE WORD DOESN'T EXIST IN THE DATABASE 
                        UpdateTA.append(hash)
                        numsearch=0
                        numfiles=1
                        #It computes the associated key using the keyword and the numbersearch (which is 0 in this case because it's the initialisation)
                        Kw=str(cipherKta.encrypt(pad((hash+str(numsearch)).encode("utf-8"),16)))
                        #It computes the CSP address using SHA-256 for this specific keyword and the number of file the keyword appears in 
                        csp_keywords_address=hashlib.sha256((Kw+str(numfiles)+str(0)).encode("utf-8")).hexdigest()                
                        #It encrypts using AES and the key KSke the ID of the file (name of the file) and the number of file 
                        csp_keywords_value=str(base64.b64encode(cipherKske.encrypt(pad((fID+str(numfiles)).encode("utf-8"),16))))[2:-1]
                        newmap={csp_keywords_address:csp_keywords_value}
                        MAP.update(newmap)
                        #The new tuples value is added to a INSERT query
                        if flag == 1 :
                            file_index.update({(hash,"[1,0]")})
                        else:
                            InsertString+=f'("{hash}","{numfiles}","{numsearch}"), '
    if flag ==0 : 
        if len(InsertString)!=75:
            #All new tuples are Insert in the Data Owner's Database 
            cursor.execute(InsertString[:-2])
            connection.commit()
        if len(UpdateString)!=0:
            #All the tuples corresponding to one the text's words are updated 
            cursor.execute((UpdateString))
            connection.commit()
    elif flag==1:
        with open("localDatabase",'w') as lDB:
            file_index=re.sub("\'\[","[",str(file_index))
            file_index=re.sub("\]\'","]",str(file_index))
            lDB.write(str(file_index))
    #When all the words have been process it encrypts the file's content using aes and encode the result in base64
    ci=str(base64.b64encode(cipherKske.encrypt(pad(text.encode("utf-8"),16))))[2:-1]
    #It creates the token that will be send to the CSP. It contains the cipher text, the encrypted and encoded file name and the mapping addresses/values
    Ta=((ci,str(base64.b64encode(ast.literal_eval(fID)))[2:-1]),MAP)
    #If the AddFile function has not been called during Initialisation phase 
    if flag != 1:
        c=[]
        c.append((ci,str(base64.b64encode(ast.literal_eval(fID)))[2:-1]))
        Ta=(c,MAP)
        #The owner send a encrypted list of the keywords in the file to the TA that will decrypt it using the symetrical key KTa and update his database 
        UpdateTA=str(cipherKta.encrypt(pad(str(UpdateTA).encode("utf-8"),16)))
        TaAck(UpdateTA)
        #The owner send the token to the CSP that contains an encrypted version of the file and the address/value pairs that the CSP has to stored in his dictionary 
        InsertCSP(Ta)
        return
    #If this this is the Initialisation file we return the token to the InGen function 
    return Ta,UpdateTA





def InGen(K):
    #The function is imported locally to avoid a loop
    from CSP import InsertCSP
    #We store the list of all the file that we want to store during the initialisation process
    files_list=os.listdir("./IniFiles")
    InsertString="INSERT INTO sse_user (keyword, keyword_numfiles, keyword_numsearch) VALUES "
    AllMap={}
    Allc=[""]*len(files_list)
    i=0
    AllUpdateTa=[]
    #Each file pass trhough the Addfile function with th flag set to 1 to indicate to the function to return the CSP mapping list and the Update list for the TA 
    start = time()
    for f in tqdm(files_list):
        Ta,UpdateTa=AddFile(K,f,1)
        Allc[i]=Ta[0]
        AllMap.update(Ta[1])
        AllUpdateTa+=UpdateTa
        i+=1
    #It computes a "super" token that stored all the encrypted file and the address/value pairs that the CSP has to stored
    InCSP=(Allc,AllMap)
    #InTa keep track of the keywords list dans their corresponding numfiles value during all the initialisation phase
    InTa={}
    #It uses a loop on AllUpdateTa to set up IniTa before forward it to the TA
    for keyword in AllUpdateTa:
        #If a tuple with the corresponding keyword already exist we increment by 1 the number of files for this keyword (right part)
        try :
            InTa.update({keyword:InTa[keyword]+1})
        #If it fails we it means that it is the first occurence so we create a tuple for the keyword and initialize the numfiles to 1
        except:
             InTa.update({keyword:1})
    #When all the keyword/numfiles pairs has been processed Inta is crypted using the Kta symetrical key
    cipherKta = AES.new(bytes.fromhex(K[0]), AES.MODE_ECB)
    #We apply AES encryption on InTA to avoid the possibility of spying 
    InTa=str(cipherKta.encrypt(pad(str((InTa)).encode("utf-8"),16)))
    
    with open("localDatabase",'r') as lDB: 
                    file_index=eval(lDB.read())
                    lDB.close()
    #We format the Insert query with all the tuples stored during the Initialization Phase
    for hash in file_index:
        InsertString+=f'("{hash}","{file_index[hash][0]}","{file_index[hash][1]}"), '
    if len(InsertString)!=75:
            #All new tuples are Insert in the Data Owner's Database 
            cursor.execute(InsertString[:-2])
            connection.commit()
    #we delete the local database
    os.remove("localDatabase")
    #Finally Inta and InCSP are respectly send to the TA and the CSP 
    IniTa(InTa)
    InsertCSP(InCSP)
    end = time()
    print("Time for initialization : "+str(end-start))
    return

def GenK():
    #The script generates the two parts of the secret key K 
    λ = get_random_bytes(16)
    Kta=hashlib.sha256(λ).hexdigest()
    λ = get_random_bytes(16)
    Kske=hashlib.sha256(λ).hexdigest()
    return Kta,Kske

def OwnerSearchUpdate(Kw):
    Kta = KeyTA()
    #The Owner decrypt the key Kw 
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    decipheredKw=cipherKta.decrypt(ast.literal_eval(Kw))
    decipheredKw=unpad(decipheredKw,16).decode("utf-8").split()
    #It allows the Owner to recover the keyword and the numsearch value
    hash=decipheredKw[0][:64]
    numsearch=int(decipheredKw[0][64:])+1
    #Finally the owner simply update the numsearch value for this keyword by incrementing the received value by 1
    cursor.execute("""UPDATE sse_user SET keyword_numsearch=%s WHERE keyword=%s""", (str(numsearch),hash))
    connection.commit()
   


