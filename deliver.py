#!/usr/bin/python

from decimal import Decimal
import sys
import os
import traceback
import subprocess
import email
import operator

from WConfig import WConfig

import WLog # seperat WLog for spam_tracker
import WSQL


# Paths to binaries
CLAMSCAN = '/usr/bin/clamdscan'
SPAMC = '/usr/bin/spamc'
REFORMAIL = '/usr/bin/reformail'
DOVECOT_DELIVER = '/usr/lib/dovecot/deliver'
POSTFIX_DELIVER = '/usr/lib/postfix/virtual'
DELIMITER = '+'
MAILER_DAEMON = '<mailer@wservices.ch>'


# Files which are bigger than this size (in bytes) will not be checked for spam.
MAX_SPAM_SIZE=1000000

# The following headers will be removed from the mail body before applying the new headers.
RESERVED_HEADERS = ['X-Virus-Checker-Version', 'X-Virus-Status', 'X-Virus-Report', 
                    'X-Spam-Checker-Version', 'X-Spam-Level', 'X-Spam-Status', 'X-Spam-Report', 'X-Spam-Flag']


def setuid(uid, gid, environ=None):
    if environ:
        for key in environ.keys():
            os.environ[key] = environ[key]
    if gid:
        os.setgid(gid)
    if uid:
        os.setuid(uid)


def print_error(e):
    try:
        #sys.stderr.write('Exception: %s' % e)
        if WLog.log_file:
            WLog.error('Exception: %s' % e)
            traceback.print_exc(file=WLog.log_file)
            WLog.close()
    except:
        # File silently, as we can't log or print the error
        pass


class Mail():
    def __init__(self, data):
        self.data = data
        self.is_virus = None
        self.is_spam = None
        self.required_spam_score = 5.0

        self.uid = 200
        self.gid = 200

        if not self.data:
            return

        self.sql = WSQL.WSQL()

        # get account
        self.parse()

    def parse(self):
        # Split the data into headers and body
        split = data.find('\n\n')
        self.header_data = '%s\n\n' % data[:split]
        self.body_data = data[split+2:]

        # parse the e-mail header
        WLog.debug('Parsing e-mail')
        message = email.message_from_string(self.header_data)
        try:
            self.mail_to = sys.argv[sys.argv.index('-d')+1]
        except (IndexError, ValueError):
            WLog.error('no recipient found')
            sys.stderr.write('no recipient found')
            sys.exit(2)
        try:
            self.mail_from = sys.argv[sys.argv.index('-f')+1]
        except (IndexError, ValueError):
            self.mail_from = 'unknown'
        if not self.mail_from:
            self.mail_from = message.get('From')
        if not self.mail_to:
            self.mail_to = message.get('Delivered-To')
        WLog.debug('e-mail from %s to %s' % (self.mail_from, self.mail_to))

        try:
            (self.user, self.domain) = self.mail_to.split('@')
        except:
            WLog.error('no valid destination mail address %s' % self.mail_to)
            sys.stderr.write('no valid destination mail address %s' % self.mail_to)
            sys.exit(3)

        try:
            self.extensions = sys.argv[sys.argv.index('-e')+1]
        except (IndexError, ValueError):
            self.extensions = ''

        # set dovecot as default deliver
        self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-f', self.mail_from]

        # replace Return-Path: <MAILER-DAEMON>
        try:
            if message.get('Return-Path') == '<MAILER-DAEMON>':
                WLog.notice('replace Return-Path: <MAILER-DAEMON> to %s' % MAILER_DAEMON)
                status, result = run([REFORMAIL, '-I', 'Return-Path:%s' % MAILER_DAEMON], self.header_data)
                if status == 0:
                    self.header_data = result
        except Exception, e:
            WLog.error('%s' % e)

    def check(self):
        # get account settings
        try:
            result = self.sql.execute('SELECT check_virus, virus_dir, check_spam, spam_dir, required_spam_score, uid, gid FROM mail_users WHERE email=%s', (self.mail_to.lower(),), True)
            check_virus_bool = result[0][0]
            self.virus_dir = result[0][1]
            check_spam_bool = result[0][2]
            self.spam_dir = result[0][3]
            self.required_spam_score = Decimal(result[0][4])
            self.uid = int(result[0][5])
            self.gid = int(result[0][6])
        except Exception, e: # any errors
            WLog.warning('Can not fetch spam settings %s' % e)
            check_virus_bool = True
            self.virus_dir = 'Junk'
            check_spam_bool = True
            self.spam_dir = 'Junk'
            self.required_spam_score = 5.0

        """
        try:
            setuid(self.uid, self.gid)
        except OSError, e:
            WLog.warning('Can not set uid/gid %s' % e)
            pass
        """

        if check_virus_bool:
            # Check for viruses
            self.is_virus, virus_headers = self.check_virus()
        else:
            virus_headers = []

        # Only check for spam if there's no virus, check_spam_bool=True and if the mail is smaller than MAX_SPAM_SIZE
        if not self.is_virus and len(data) <= MAX_SPAM_SIZE and check_spam_bool:
            self.is_spam, spam_headers = self.check_spam()
        else:
            spam_headers = []

        if self.is_virus:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-f', self.mail_from, '-m', self.virus_dir]
        elif self.is_spam:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-f', self.mail_from, '-m', self.spam_dir]
        elif self.extensions:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-f', self.mail_from, '-m', self.extensions]

        headers = virus_headers + spam_headers

        if headers:
            args = reduce(operator.add, [['-I', header] for header in ['%s:'%h for h in RESERVED_HEADERS]+headers])
            status, result = run([REFORMAIL]+args, self.header_data)
            assert status == 0, 'Could not run %s (exit code %d)' % (REFORMAIL, status)
            self.data = result+self.body_data
            WLog.debug('New headers set')

    def check_virus(self):
        headers = []

        # Get the version
        status, version = run([CLAMSCAN, '-V'])
        assert status == 0, 'Could not run %s (exit code %d)' % (CLAMSCAN, status)

        headers.append('X-Virus-Checker-Version: %s' % version.split('\n')[0])

        # Scan the message
        status, message = run([CLAMSCAN, '-', '--stdout'], self.data)
        
        if status == 0:
            # No virus
            headers.append('X-Virus-Status: No')
        elif status == 1:
            # Virus found
            headers.append('X-Virus-Status: Yes')
            try:
                # Note: There may be multiple status lines. Do we want to parse them?
                headers.append('X-Virus-Report: %s' % message.split()[1])
            except IndexError:
                headers.append('X-Virus-Report: Failed')
        else:
            # Failed
            headers.append('X-Virus-Status: Failed')

        return (status == 1, headers)

    def check_spam(self):
        headers = []

        # Scan the message
        #status, result = run([SPAMC, '-R', '-u', 'vmail'], self.data)
        # If spam returncode is 1, else returncode is 0
        #assert status == 0 or status == 1, 'Could not run %s (exit code %d)' % (SPAMC, status)
        p = subprocess.Popen([SPAMC, '-R', '-u', 'vmail', '-s', str(MAX_SPAM_SIZE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, stderrdata) = p.communicate(self.data)
        if stderrdata:
            log.error('Spamc error: %s' % stderrdata)
        if p.returncode and p.returncode != 1:
            log.error('Spamc error: returncode: %s' % p.returncode)

        # No try/except here, as there shouldn't be any errors
        try:
            ignore, version, score, tests, summary = result.split('\n', 4)
        except ValueError:
            WLog.error('Result unknown spamc format, result: %s' % result)
            version = 'error'
            score = '3'
            summary = 'Error during spam check'
            tests = ''
        try:
            spam_score, spam_level = score.split(' ')
        except ValueError:
            spam_score = score
            spam_level = ''

        spam_score_float = Decimal(str(spam_score))
        is_spam = spam_score_float >= self.required_spam_score

        # Set the headers
        headers.append('X-Spam-Checker-Version: %s' % version)
        if spam_level:
            headers.append('X-Spam-Level: %s' % spam_level)
        headers.append('X-Spam-Status: %s, score=%s required=%s %s' % \
                (is_spam and 'Yes' or 'No', spam_score, self.required_spam_score, tests))
        if is_spam:
            headers.append('X-Spam-Flag: YES')
            headers.append('X-Spam-Report: ---- Start SpamAssassin results\n\t* %s\n\t---- End of SpamAssassin results' % \
                    summary.replace('\n', '\n\t').strip().replace('\t', '\t* ')
                )

        return (is_spam, headers)

    def deliver(self):
        WLog.debug('User %s Group %s' % (os.getuid(), os.getgid()))
        WLog.debug('Deliver with: %s' % self.deliver_application)
        p = subprocess.Popen(self.deliver_application, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdoutdata, stderrdata) = p.communicate(self.data)
        if p.returncode:
            WLog.error('Delivery error: %s %s %s' % (p.returncode, stderrdata,stdoutdata))
            sys.exit(p.returncode)
        WLog.debug('Delivered')
        #p = subprocess.Popen(self.deliver_application, stdin=subprocess.PIPE)
        #p.stdin.write(self.data)
        #p.stdin.close()


def run(cmd, data=None):
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    try:
        if data:
            proc.stdin.write(data)
        proc.stdin.close()
        result = proc.stdout.read()
        proc.stdout.close()
    except IOError: # The child closed the file too early. Don't return anything in that case.
        result = ''

    status = os.waitpid(proc.pid, 0)[1]/256

    return (status, result)

def dummy_deliver(data):
    p = subprocess.Popen([DUMMY_DELIVER], stdin=subprocess.PIPE)
    p.stdin.write(data)
    p.stdin.close()

    sys.exit(1)

if __name__ == '__main__':
    try:
        WLog.open_log(WConfig.LOGFILE)
    except Exception, e:
        pass
    
    data = sys.stdin.read()

    try:
        mail = Mail(data) # parse mail
    except Exception, e:
        print_error(e)
        sys.exit(1)
    try:
        mail.check()      # check mail for spam and viruses
    except Exception, e:
        print_error(e)
    try:
        mail.deliver()    # deliver the mail
    except Exception, e:
        print_error(e)

