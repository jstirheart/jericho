# GUIDE
This project is to provide a script/executable which checks all files recursively on a computer/targetdir for matches against a collection of [VILE] hashes (designed for detection of CSAM or other malicious content).
Given a trigger match, the application then works to gather forensic artifacts and logs which may aid in an investigation.

###Example Report:
Generated report results will perform acquisition to results directory of Registry Hives, Event Logs, Hashes of all scanned content, special reporting of matched VILE content, and jeArtifacts.txt containing useful command results

    jeResults
    |acq
    	|Default
    		NTUSER.DAT
    	|Default User
    		NTUSER.DAT                                      
    	|explo
    		NTUSER.DAT                                      
    	 |winevt                                          
    		Security.evtx                                   
    		System.evtx                                     
    	 SAM                                             
    	 SECURITY                                        
    	 setupapi.dev.log                                
    	 SOFTWARE                                        
    jeArtifacts.txt
    jeLogTime.csv                                   
    jeResults.csv                                   



# INSTALLATION
Available packaged as .exe through releases. Otherwise, available as python script given necessary pip installs

# USAGE
    jericho.exe -h
    jericho.exe //executes on debug hash data, recurses all partition mount points
    jericho.exe --loadHashFileP //loads db of hash data, recurses all partition mount points
    jericho.exe --path --loadHashFileP //loads db of hash data, recurses from path

### Fileformat of hash.db.txt: 1 MD5 hash per line
    b9ab94fd6a2e6b3f0d841529851f8db8
    ba51c40c5eb8fdc2f9a98a28470b09fb
    098f6bcd4621d373cade4e832627b4f6

# License
  Copyright JST 2024 GPLv3
