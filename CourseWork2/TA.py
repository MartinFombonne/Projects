import pymysql
import ast
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib
from time import time
#from SID import Kta
connection = pymysql.connect(user='root', passwd='Password123?',host='localhost', database='TA',client_flag= pymysql.constants.CLIENT.MULTI_STATEMENTS)
cursor = connection.cursor()



def KeyTA(): 
    f = open("KEY_SSE","r")
    K=f.read()
    Kta=K[:64]
    return Kta

def TaAck(UpdateTA):
    Kta = KeyTA()
    #Recover Inta from the AES encryption
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    UpdateTA=cipherKta.decrypt(ast.literal_eval(UpdateTA))
    UpdateTA=unpad(UpdateTA,16)
    UpdateTA=str(UpdateTA)[2:-1]
    UpdateTA=eval(UpdateTA)
    InsertString="INSERT INTO sse_TA (TA_keyword, TA_keyword_numfiles, TA_keyword_numsearch) VALUES "
    UpdateString=""
    #The data is retrieved from the TA database
    cursor.execute("""SELECT TA_keyword, TA_keyword_numfiles, TA_keyword_numsearch FROM sse_TA""")
    file_index = cursor.fetchall()
    #The data is formated in a dictionnary object to be manipulated more easily
    file_index=dict((a,(b,c)) for a,b,c in file_index)
    for keyword in UpdateTA:
        try :
            #THE WORD ALREADY EXSTS IN THE DATABASE 
            numfiles=file_index[keyword][0]
            numsearch=file_index[keyword][1]
            #The corresponding update query is added to a queue 
            UpdateString+=f"UPDATE sse_TA SET TA_keyword_numfiles='{numfiles+1}',TA_keyword_numsearch='{numsearch}' WHERE TA_keyword='{keyword}'; "
        except : 
            #THE WORD DOESN'T EXIST IN THE DATA BASE 
            #The corresponding tuple is added to an INSERT query 
            InsertString+=f'("{keyword}","1","0"), '
            
    if len(InsertString)!=75:
        #All new tuples are Insert in the Data Owner's Database 
        cursor.execute(InsertString[:-2])
        connection.commit()
    if len(UpdateString)!=0:
        #It Processes all the Update Queries 
        cursor.execute((UpdateString))
        connection.commit()
    return

def IniTa(InTa):
    Kta = KeyTA()
    print("====COMMIT TA====")
    start = time()
    #Recover Inta from the AES encryption
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    InTa=cipherKta.decrypt(ast.literal_eval(InTa))
    InTa=unpad(InTa,16)
    InTa=str(InTa)[2:-1]
    InTa=eval(InTa)
    InsertString="INSERT INTO sse_TA (TA_keyword, TA_keyword_numfiles, TA_keyword_numsearch) VALUES "
    #It loops on the received tuples 
    for keyword,numfiles in InTa.items():
            #The tuples are added to an INSERT query
            InsertString+=f'("{keyword}","{numfiles}","0"), '
    #It sends the query to the TA's Database 
    cursor.execute(InsertString[:-2]) 
    connection.commit()
    end = time()
    print("Commit's time to the TA : "+str(end -start))

def askTA(Ts): 
    #The TA retrieve the Kta value that it is supposed to be know 
    Kta = KeyTA()
    cursor = connection.cursor()
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    #It decrypt the token send by the shared symmetrical key Kta
    hash=eval(str(unpad(cipherKta.decrypt(ast.literal_eval(Ts)),16))[1:])
    #It looks for the corresponding value in its database
    cursor.execute("""SELECT TA_keyword_numfiles,TA_keyword_numsearch FROM sse_TA WHERE TA_keyword= %s""",hash)
    Index = cursor.fetchall()
    #Returns the corresponding value to the user 
    if len(Index) == 0:
        return (0,0)
    else:
        return Index[0]





def TA_Search(Kw,numfiles):
    Kta = KeyTA()
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    #Ta decrypt the Kw using that Kta key
    decipheredKw=cipherKta.decrypt(ast.literal_eval(Kw))
    decipheredKw=unpad(decipheredKw,16).decode("utf-8").split()
    #It allows the TA to recover the keyword and the number of search for this keyword
    hash=decipheredKw[0][:64]
    numsearch=int(decipheredKw[0][64:])+1
    #The TA computed also the new Kw value 
    new_Kw=str(cipherKta.encrypt(pad((hash+str(numsearch)).encode("utf-8"),16)))
    Lta=[]
    #Same as the user, the TA will generated the corresponding CSP address for this keyword
    for i in range(numfiles):
        csp_keywords_address=hashlib.sha256((new_Kw+str(i+1)+str(0)).encode("utf-8")).hexdigest()
        Lta.append(csp_keywords_address)
    #The TA finally return the list of computed addresses to the CSP 
    return Lta

def TASearchUpdate(Kw):
    Kta = KeyTA()
    #The TA decrypt the key Kw 
    cipherKta = AES.new(bytes.fromhex(Kta), AES.MODE_ECB)
    decipheredKw=cipherKta.decrypt(ast.literal_eval(Kw))
    decipheredKw=unpad(decipheredKw,16).decode("utf-8").split()
    #It allows the TA to recover the keyword and the numsearch value
    hash=decipheredKw[0][:64]
    numsearch=int(decipheredKw[0][64:])+1
    #Finally the TA simply update the numsearch value for this keyword by incrementing the received value by 1
    cursor.execute("""UPDATE sse_TA SET TA_keyword_numsearch=%s WHERE TA_keyword=%s""", (str(numsearch),hash))
    connection.commit()

