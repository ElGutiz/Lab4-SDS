import pefile
import pandas as pd
from os import listdir
import os

relative_path = os.getcwd()+'/MALWR'

malware_files = [f for f in listdir(relative_path)]

df = []

for malware in malware_files:
	#print(malware)
    #Each file is a malware, except the file .DS_Store so is important to exclude it because if not, PEFILE won't be able to analize it
	if malware != '.DS_Store':
		information= {}

        #PEFILE is going to analize the malware
		pe = pefile.PE(relative_path+'/'+malware)
		
        #Get each section of the file from PEFILE and save them in a dictionary so in that way is easier to get the information
		for section in pe.sections:		
			information  = {
				section.Name.strip(b'\00').decode(): True,
				section.Name.strip(b'\00').decode()+'vAddress':section.VirtualAddress,
				section.Name.strip(b'\00').decode()+'vSize':section.Misc_VirtualSize,
				section.Name.strip(b'\00').decode()+'rSize': section.SizeOfRawData
			}

		#Get all DLLs from the information dictionary
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			information[entry.dll.decode()] = True

        #Get all API Calls from the information dictionary
		for function in entry.imports:
			information[function.name.decode()] = True

        #Add all the information in df
		df.append(information)

#Create Dataframe from the list
df = pd.DataFrame(df)

#Convert Dataframe to CSV
df.to_csv('MALWRE_dataset.csv', index=False)