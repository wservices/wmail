import time

log_file = None

def open_log(filename):
    global log_file
    log_file = open(filename, 'a')

def close_log():
    global log_file
    log_file.close()
    log_file = None

def log(buffer, type):
    t = time.localtime()
    logformat = "[%d.%m.%y %H:%M:%S] [" + type + "] " + buffer
    data = time.strftime(logformat, t)
    if log_file:
        log_file.write(data+'\n')
    else:
        print data

def error(buffer):
    log(buffer, "error")

def warning(buffer):
    log(buffer, "warning")

def notice(buffer):
    log(buffer, "notice")

def debug(buffer):
    log(buffer, "debug")
