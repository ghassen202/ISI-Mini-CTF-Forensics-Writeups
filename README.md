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

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/3ff68ab9-0fca-4561-b160-a24c788ef8c6" width="400" height="400">

 since we have the operating system from the profile, all we need is the Computer Name which we can either obtain by running the envars plugin
in the volatility ``` python2 vol.py -f lasten.raw --profile=Win7SP1x64 envars ``` or grep for it from the memory dump file using Strings command.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/d41ff098-e8fd-4d72-9a23-77d67f4ce09c">

## Task 04 :
The 4th task mission was to extract salah source code and his logs to unravel the two parts of the flag.

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/13bc498a-5b88-4ab6-a5b5-787318836288" width="400" height="400">

if we run the ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 pslist (or pstree) ``` plugin we notice that Salah was using Wampserver which is Apache web server. We can find his applications under the www directory : 

<img src="https://github.com/ghassen202/ISI-Mini-CTF-Forensics-Writeups/assets/74879627/9d06044c-7f25-492d-ae81-5e94d7ffd0a5">

Let's us check the files under these directories by scanning for files using ```python2 vol.py -f lasten.raw --profile=Win7SP1x64 filescan```  :

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













