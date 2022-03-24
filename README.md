
### Steps to run

1. Open command prompt window
2. Navigate to project directory where the python file "mainapp.py" exists.
3. Install project libaries by executing below command:
    `pip install -r requirements.txt`
4. Execute command:
    `python mainapp.py`
5. Open separate command window from project directory.
6. Run below command:
    `python test.py`
    
### Approach

1. Made call to Identities API and maintained dictionary for known identities.
2. Called Incidents API for all possible incident types.
    - Stored the incidents into different lists according to priority.
3. Sorted all the priority lists.
4. Iterated over all priority lists in sequence to create result json.

Other considerations involved: Directly updating result dictionary during calls to incident apis. 
creating internal database and maintaining records.

Note: It logs incidents from unidentified IPs in the console.

### Further Enhancements

1. Enhance code for better time complexity.
2. Maintain pandas dataframe for all operations.
3. Simplify and Isolate few code blocks to create functions.
4. Parallelize some of the calls and processing.

Thanks for reading :)
