import pymysql
from TA import TA_Search,TASearchUpdate
import hashlib
from time import time


connection = pymysql.connect(user='root', passwd='Password123?',host='localhost', database='CSP',client_flag= pymysql.constants.CLIENT.MULTI_STATEMENTS)
cursor = connection.cursor()

def CSP_Search(Ts):
    #The function is imported locally to avoid a loop
    from Owner import OwnerSearchUpdate
    #The CSP retrieve the sended values 
    Kw=Ts[0]
    numfiles=Ts[1]
    Lu=Ts[2]
    #The CSP forward the Kw key and the numfiles values to the TA in order to check if the received list of address has not been corrupted
    Lta=TA_Search(Kw,numfiles)
    #The CSP check if the list send by the client is the same that the one computed bu the trusted authority 
    if Lu == Lta:
        Iw=[]
        count=0
        UpdateString=""
        #The data is retrieved from the CSP Dict table 
        cursor.execute("""SELECT csp_keywords_address, csp_keywords_value FROM CSP_dict""")
        file_index = cursor.fetchall()
        file_index=dict(file_index)
        #Each tuple is processed 
        for i in range(numfiles):
            address=hashlib.sha256((Kw+str(i+1)+"0").encode("utf-8")).hexdigest()
            Iw.append(file_index[address])
            #Once it finished, it updates the corresponding tuple and add the query to a queue
            UpdateString+=f"UPDATE CSP_dict SET csp_keywords_address='{Lu[count]}' WHERE csp_keywords_address='{address}'; "
            count+=1
        #It send all the update queries to the CSP database 
        if len(UpdateString)!=0:
            cursor.execute(UpdateString) 
            connection.commit()
        #The CSP forward the key Kw to the owner and the TA in order for them to update the numsearch value for the crresponding keyword
        OwnerSearchUpdate(Kw)
        TASearchUpdate(Kw)
        #Finally the CSP return the encrypted corresponding file to the user 
        return Iw
    #If the check is not correct the CSP abort the process
    else:
        print("ERROR : ⊥")
        exit()



def InsertCSP(Ta):
    print("====COMMIT CSP====")
    start = time()
    MAP=Ta[1]
    c=Ta[0]
    #The CSP loops on the received tuples (address/value pairs) and add them to an INSERT query 
    InsertString="INSERT INTO CSP_dict (csp_keywords_address,csp_keywords_value) VALUES "
    for address, value in MAP.items():
        InsertString+=f"('{address}','{value}'), "    
    #Same operation for the others received tuples (ciphertext, file id)
    InsertString=InsertString[:-2]+"; "+"INSERT INTO library (id,file) VALUES "
    for file,fID in c:
        InsertString+=f"('{fID}','{file}'), "
        
    #Send the two INSERT request to the CSP tables 
    if len(InsertString)!=75:
        cursor.execute(InsertString[:-2])
        connection.commit() 
    end = time()
    print("Commit's time to the CSP : "+str(end -start))
    


#Retrieved and send back a ciphertext using the corresponding ID 
def retrieveFileCSP(fID):
    query=f'SELECT file FROM library WHERE id="{fID}"'
    cursor.execute(query)
    file = cursor.fetchall()
    return file