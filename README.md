
# ISI-Mini-CTF-Forensics-Writeup
A beginner friendly Capture The Flag (CTF) where I created a windows7 Memory Dump in order to investigate an attack on a computer using the volatility tool, the tasks were guided to introduce new comers into the world of cybersecurity to dive into memory analysis.

#### Download the memory dump file via this [link](https://drive.google.com/file/d/1hlxiV4N9y_7RvjyjkBtUdm2ZCUQUcXYK/view?usp=sharing)

## Task 01 : 
For the first tasks the players were introducesd to some concepts such as : What is volatile data ? what is Memory forensics ? what are the tools used to conduct the analysis ?
The Answers to these questions were provided in [this doc file](https://docs.google.com/document/d/1vAC9tJZMKjT2bFU-GxcbnGEJO1Zxh-1-YmhqNOvGFNM/edit?usp=sharing) along with an intro flag as a reward.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/c50f0e2c-93c8-4462-b70a-d0ab09c9fd7f" width="400" height="400">

`Flag 01 : Securinets{Lets_Get_Started_With_Memory_Analysis}`
## Task 02 :
<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/8dc833e4-6cc0-4706-ab1f-b8b6ea4b005d" width="400" height="400">

Running the imageinfo command can grant us the profile that we will use for the investigation : ``` python2 vol.py -f lasten.raw imageinfo  ```

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/717da395-5429-4d2b-9af7-234f41b2b5c1"> 


`Flag 02 : Securinets{Win7SP1x64}`

## Task 03 : 
For the third one we were asked for the OS and Computer Name.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/3ff68ab9-0fca-4561-b160-a24c788ef8c6" width="400" height="600">

 since we have the operating system from the profile, all we need is the Computer Name which we can either obtain by running the envars plugin
in the volatility ``` python2 vol.py -f lasten.raw --profile=Win7SP1x64 envars ``` or grep for it from the memory dump file using Strings command.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/d41ff098-e8fd-4d72-9a23-77d67f4ce09c">

`Flag : Securinets{WINDOWS_GASTRA-WIN7}`
## Task 04 :
The 4th task mission was to extract salah source code and his logs to unravel the two parts of the flag.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/13bc498a-5b88-4ab6-a5b5-787318836288" width="400" height="400">

if we run the ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 pslist (or pstree) ``` plugin we notice that Salah was using Wampserver which is Apache web server. We can find his applications under the www directory : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/9d06044c-7f25-492d-ae81-5e94d7ffd0a5">
<br>
Let's us check the files under these directories by scanning for files using ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 filescan```  :
<br>
<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/6ae49e92-223b-4214-9903-5100d0a5d8a3">


We notice the index.php file let's dump it using the dumpfiles plugin ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007fd82b70 -D ~/Desktop``` the -Q is the virtual address of the memory you want to extract  and the -D is to specify in which directory to dump the file once we read his source code we get the first part of the flag : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/edb46f8e-e2c7-4edb-81f4-183556eaca68">

We will do the same steps to extract his log files : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/1d98b799-82c9-4178-8e97-0aef84feb251">

`Securinets{always_check_source_code_and_logs_master!}`

## Task 05 : 
For the next one the player should be familiar with dumping files so it's getting easier.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/60fab62e-273c-423c-ada7-83b283eb9080" width="400" height="400">

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/8e9322e0-8c75-41a2-9781-a88c865ddbd8">

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/62c4d26b-e285-44b9-bad2-a8aac98a9600">

Flag : <br> <img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/8531cc39-f7c6-4a2d-acec-e31d57609f46" width="700" height="400">

## Task 06 : 
Now the attack has took place let's investigate more through this task :

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/b7d28529-9484-4134-9c0c-b1ced58d95f3" width="400" height="400">

In Order to find Salah's ip we could scan the network by using the netscan plugin ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 netscan -v``` : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/af9b183b-d876-474d-9937-80af6e1f392f">

For the Sus application he installed we have many ways the best one is to use the chromehistory plugin which needs to be installed it gives you his web browser history and find out that he downloaded FIFA23 , or we can just check his downlaods / Google History files or the working processes to know this information.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/4ea15fcd-a9b5-44f5-8be4-ea45e1edcf49">

Flag : `Securinets{192.168.1.21_FIFA23}`

## Task 07 :

now we are gonna gather some informations about the attack.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/ff0a242c-8491-4a84-98c4-e02802b733da">

running the pslist command we notice ther's a sus process named `notapadd.exe`

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/5a0a53f6-b0f6-4f7b-b2e7-199880b00e07" width="400" height="400">


after investigation we found the file was located on the victim's desktop the moment the attack happend let us dump this file and gather more information : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/60ff4ab6-bf34-400c-8705-9e91408fc49d" width="400" height="400">



a lot of interesting files were found `zipped_flag.zip` `decryption.exe` `InfoBank.txt` but we will dig through these ones later in the tasks for now let us focus on the `notapadd.exe` which seems to be the malicious file, we are not gonna dive into reversing this file since this is a guided CTF but let us scan the file in VirusTotal. <br>
<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/dd76724d-54dc-4ce4-8078-c37e489242fc" width="400" height="400">
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/6a649dcf-00be-4547-b06b-41e6ef66668c)

from the Behaviour we notice that it is a compiled go code that is encrypting the victim's important data using AES256, this is known as a Ransomware,
The Vhash is basically an in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. Having all these information we can gather the puzzles for our  flag.

`Flag : {notapadd.exe_ 0260f6151d1515150505bz2d!z_ransomware}`

## Task 08 : 

For this challenge we have to help salah infected file : <br>
<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/0565b196-1d4b-4351-8af6-60afefc7b83a" width="400" height="400">

after revealing in the Task 07 the files on salah's dektop `InfoBank.txt` & `decryption.exe` and knowing that the attacker used AES with base64, we just need to decrypt the Infected file file, let's dump the file as usual.

file content :  <br>
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/1c4e6284-5732-42ee-8ce4-8d5edc9c7f4f)

However for AES256 is a symmetric encryption which means that the same key is used for both the encryption and decryption processes,so
we have to find that key in order to decrypt our file content, the naive attacker however copied the key while setting up his malicious file, for this the volatility tool contains a plugin that dumps whatever was on the clipboard at the time of the attack using (Well this was supposed to be a hint but since the previous challenges weren't solved i didn't post it) 
```python2 vol.py -f lasten.raw --profile=Win7SP1x64 clipboard```

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/92dccfce-900e-4329-8526-8c18be922737)

There you go having all these you can easily use an online decryption tool to decrypt the file which is obviously the flag.

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/9eddd03b-cd32-46d8-9ee5-ad05cca7b47c)

decrypting the base64 Flag gives : `Securinets{A3S_Encryp7i0n_1s_1n53CUR3}`

## Task 09 :

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/f17db2d2-a96c-4665-b47e-4a1fcd6959af" width="400" height="400">

One of the files we discovered in the Task 07 was named `zipped_flag.zip` let us try to dump it and check its content : 
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/89484e23-edb0-4143-ad46-0e0f7a0fe3bc)

The file seems to be corrupted by the attacker which means some header bytes were modified , every file type(png,jpg,zip...etc) have a unique bytes signature let us see how we can fix this file by giving it the right signature, Google is our friend : 
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/1645843d-25a7-4d20-8e73-a51fcca0537e)
Let us check if our header bytes match by running xxd command on the zip file : <br>

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/ca6b3066-c1ba-4863-9038-e6a22206d81a)

We can see that the first 4 bytes aren't as they supposed to be for that wel will use Hexedit tool to fix the file header and exporting it again : <br>
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/7514acf9-ebcb-4c84-a813-ec9c0907c040)

The file is fixed let's get our flag now, however the zip was password secure while trying to open the file : <br>
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/383dbb46-febf-404a-9f2d-5ccae133ed19)

you can try to bruteforce attack the password but it won't work since the naive hacker hid the password somewhere on this machine which he did in the windows registry (again  this was supposed to be a hint but since the previous challenges weren't solved i didn't post it),
we can check the hives on the victim's machine by using the hivelist plugin ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 hivelist````: 
![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/c52c67f5-b618-495c-91af-397d567e335e)

The password was a registry key a in the Software branch which is a specific branch within the user's registry where application and system software settings are storedunder `\SystemRoot\System32\Config\SOFTWARE`, let us see the registries under this branch using the `printkey` plugin with the virtual address of that branch using ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 printkey -o 0xfffff8a000b54010```

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/60527788-1301-4f46-b586-ddba23b879ff)

that's it for task 09 let's reveal the zip file with that password `a7la_securinets_isi`.

Flag : `Securinets{Reg1stry_h0ld5_50_MuCh!}`

## Task 10 : 
the attacker set up a technique in order to gain access to salah's machine in the future using a well known windows feature, we have to gather information about what was the attacker strategy for revenge.<br>

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/bd2b5e7f-4f3e-409c-85ba-3fe5ec42010b" width="400" height="400">

Ife we keep on investigating the files we will notice that the user Appdata directory contains some Sus filesprofile since it's less likely for the to visit this hidden folder we found that the attacker left two powershell Scripts : 

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/d9863850-b197-4684-8def-4d5a520f72d4)

The Createback.ps1 file was basically setting up a schedulked task using the Task scheduler feature to run the backagainn.ps1 script daily :

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/0ad90315-51df-49e6-839f-46e8759c83b2)

The Backagainn.ps1 file was a reverse shell connection that runs daily on Salah's machine,a reverse shell is basically a type of shell in which the target machine initiates a connection to the attacker’s machine, allowing the attacker to execute commands on the target machine remotely. 

![image](https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/e15a0991-9eb9-4205-8779-95d919309069)

Having all of the information necessary let's assemble our flag : `Securinets{Task_Scheduler_149.100.50.25_4444}`

# Final Thoughts : 
Hope you enjoyed this set of tasks,however after I completed the creation of this task i realized it wasn't very beginner friendly except for the first ones, you can always try to solve this at your own and ask if you need any help, it is a bit challenging for a first timer but it's definetly a beneficial skill to acquire in the journey of learning cybersecurity.













































