#Rudimentary console logging dependant on ES_LOG_LEVEL setting, if not set defaults to only reporting ERROR messages. 
def consoleLog(log_message,log_message_level,log_report_level):
    """
    Description: Dependant on the log report level (DEBUG, INFO, ERROR) print message to the console.
    Function: consoleLog(log_message,log_message_level,log_report_level="")
    Parameters:
            log_message - string - the message you want to send to the console.
            log_message_level - string - the level of the message you are logging, can be DEBUG, INFO, ERROR.
            log_report_level - string - the level of the message the function is configured to report on based on environment variables, can be DEBUG, INFO, ERROR.
    """
    
    #Dependant on log level set in environment variables, send message to the console.
    #Errors only.
    if log_report_level == "ERROR" and log_message_level == "ERROR":
        print(log_message_level+" : "+log_message)
    #Errors and Info.
    elif log_report_level == "INFO" and log_message_level in ("ERROR", "INFO"):
        print(log_message_level+" : "+log_message)
    #Errors, Info and Debug.
    elif log_report_level == "DEBUG" and log_message_level in ("DEBUG","ERROR", "INFO"):
        #Print debug, error and info messages to console.
        print(log_message_level+" : "+log_message)
    return