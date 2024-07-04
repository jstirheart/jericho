#GUIDE
This project is to provide a script/executable which checks all files recursively on a computer/targetdir for matches against a collection of [VILE] hashes (designed for detection of CSAM or other malicious content).
Given a trigger match, the application then works to gather forensic artifacts and logs which may aid in an investigation.

#INSTALLATION
Available packaged as .exe through releases. Otherwise, available as python script given necessary pip installs

#USAGE
jeenc.exe -h
jeenc.exe //executes on debug hash data, recurses all partition mount points
jeenc.exe --loadHashFileP //loads db of hash data, recurses all partition mount points
jeenc.exe --path --loadHashFileP //loads db of hash data, recurses from path

Fileformat of hash.db.txt: 1 MD5 hash per line
  b9ab94fd6a2e6b3f0d841529851f8db8
  ba51c40c5eb8fdc2f9a98a28470b09fb
  098f6bcd4621d373cade4e832627b4f6
