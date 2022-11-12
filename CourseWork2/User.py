from Cryptodome.Cipher import AES
import hashlib
from Cryptodome.Util.Padding import pad, unpad
import ast 
from TA import askTA
from CSP import CSP_Search,retrieveFileCSP
import base64

def KeyTA(): 
    f = open("KEY_SSE","r")
    K=f.read()
    Kta=K[:64]
    Kske=K[64:]
    return (Kta,Kske)



def Search():
    #Retrieve the symetrical key K that the user is supposed to know
    K=KeyTA()
    cipherKta = AES.new(bytes.fromhex(K[0]), AES.MODE_ECB)
    cipherKske = AES.new(bytes.fromhex(K[1]), AES.MODE_ECB)
    #It ask the user to search for a word
    word=input("Enter the word you want to search : ").upper()
    #It hashes the inputed word to generate the "keyword" using SHA-256
    hash=hashlib.sha256(word.encode("utf-8")).hexdigest()
    #The user encrypted the keyword using the TA symetrical key Kta
    Ts=str(cipherKta.encrypt(pad((hash).encode("utf-8"),16)))
    #Then send it to the TA to retrieve the corresponding numfiles and numsearch value
    numfiles, numsearch = askTA(Ts)
    #If numfiles = 0 that mean that the word does not exist in any file
    if numfiles == 0 :
        print("This words doesn't exist in any stored file")
        return
    #If numfiles is different from 0 the user can recover in which files the word appears 

    #First it generates the key Kw using the keyword and the number of search for this keyword
    Kw=str(cipherKta.encrypt(pad((hash+str(numsearch)).encode("utf-8"),16)))
    numsearch+=1
    #Then it generated a new key Kw by incrementing the numsearch by 1 wich correspond to the current search
    new_Kw=str(cipherKta.encrypt(pad((hash+str(numsearch)).encode("utf-8"),16)))
    Lu=[]
    #Using the the number of file the word exists in it computes all the CSP addresses at which are stored the value !
    for i in range(numfiles):
        csp_keywords_address=hashlib.sha256((new_Kw+str(i+1)+str(0)).encode("utf-8")).hexdigest()
        Lu.append(csp_keywords_address)
    #It generated a search token using the old kw key, the number of file the word exists in it and the list of addresses for this specific keyword
    Ts=(Kw,numfiles,Lu)
    Iw=CSP_Search(Ts)
    count=0
    fileList =[""]*len(Iw)
    #The user use a loop to decrypt every file he received 
    for file in Iw:
        decipheredFile=cipherKske.decrypt(base64.b64decode(file))
        fileList[count]=unpad(decipheredFile,16).decode("utf-8")[:-len(str(count+1))]
        count+=1
    #Print the list of the files where you can find the searched word 
    print("The word "+ word +" appear in this files : ")
    for file in fileList : 
        print(unpad(cipherKske.decrypt(ast.literal_eval(file)),16).decode("utf-8"))



def retrieveFile(file_name):
    K=KeyTA()
    cipherKske = AES.new(bytes.fromhex(K[1]), AES.MODE_ECB)
    #Encrypts and encodes the file name to compute the file ID 
    fID=str(base64.b64encode(cipherKske.encrypt(pad(file_name.encode("utf-8"),16))))[2:-1]
    #Send the the file ID to the CSP to retrieved a file 
    file=retrieveFileCSP(fID)[0][0]
    #Decode the received ciphertext
    file=base64.b64decode(file)
    #Decrypt the ciphertext using the secret 
    file=unpad(cipherKske.decrypt(file),16).decode("utf-8")
    #Write the received data to a file ! 
    f = open(f'./Retrieved/{file_name}',"w")
    f.write(file)
    f.close()
    

    