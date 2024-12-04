# dff - Duplicate File Finder
Find dupes quick and easy.

---
## Usage
*  -blocksize int  
    *    size of the block in bytes to read from each file for hashing (default 4096)  
*  -deepthroat  
    *    do a full file compare to ensure it is not just a partial match  
*  -flat  
    *    do not inspect subfolders recursively
*  -minfilesize value  
    *    filter out pointless small files. format is human readable for example 1mb or 2gigabyte
*  -slaves int  
    *    amount of parallel file inspectors (default 128)
