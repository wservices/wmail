#!/usr/bin/python

import sys
import WSQL


try:
    sql = WSQL.WSQL()
    type = sys.argv[1]
    mail = sys.argv[2]

    if type == '[SPAM]':
        print sql.execute('SELECT spam_dir FROM mail_users WHERE email=%s', mail, True)[0][0],
    elif type == '[VIRUS]':
        print sql.execute('SELECT virus_dir FROM mail_users WHERE email=%s', mail, True)[0][0],
    else:
        print sql.execute('SELECT delivery_dir FROM mail_maildrop WHERE user=%s and sender=%s', (mail, type), True)[0][0],

except:
    pass

