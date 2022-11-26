from Owner import InGen,AddFile,GenK
from User import Search,retrieveFile
import glob
#Selection Menu : The user can decide what he want to do. 
def menu():
    print("\n==========What do you want to do ?==========")
    print("||                                        ||")
    print("||      1. Initialisation (DataOwner)     ||")
    print("||      2. Add File   (Dataowner)         ||")
    print("||      3. Search for a keyword  (Users)  ||")
    print("||      4. Retrieve files  (Users)        ||")
    print("||      5. Exit                           ||")
    print("||                                        ||")
    print("============================================")
    print("")
    choice = int(input(">>> "))
    return choice


choice=0

while choice != 5 :
    choice = menu()
        #Choice Initialisation 
    if choice == 1:
        #Generate the secret key 
        Kta,Kske=GenK()
        K=(Kta,Kske)
        #In this case we create a file to store the key and make it accessible but the TA and OWner Script that are suppose to know the key
        f = open("KEY_SSE", "w")
        f.write(K[0]+K[1])
        f.close()
        #Fonction that stored all the files in the dictionnary 
        InGen(K)
    #Choice add a File 
    elif choice == 2 : 
        #we retrieve the key used by the datauser for initialisation
        f = open("KEY_SSE","r")
        K=f.read()
        K=(K[:64],K[64:])
        #The DataOwner enter the name of the file he wants to Add to the dictionnary 
        file=input("Enter the name of the file : ")
        #Function that add a specific file to the dictionnary 
        AddFile(K,file) 
    #Choice Search for a Keyword in the dictionnary 
    elif choice == 3 :
        #Search Function 
        Search()
    #Choice Exit 
    elif choice == 4 :
        #Retrieved a file 
        file_name=input("\nEnter the file name of the file you want to retrieve : ") 
        retrieveFile(file_name)
    elif choice == 5:
        print("\nEXIT...")
    else :
        print("\n====Please enter a value between 1 and 5====\n")



