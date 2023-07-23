#!/usr/bin/python3

import argparse
from decimal import Decimal
import email
import functools
import logging
import MySQLdb
import operator
import os
import re
import sys
import subprocess
import traceback

import WConfig


# Paths to binaries
CLAMSCAN = '/usr/bin/clamdscan'
SPAMC = '/usr/bin/spamc'
RSPAMC = '/usr/bin/rspamc'
RSPAMC_SCORE_REGEX = re.compile('^Score:\s+([\d.-]+) ?/ ?([\d.-])+')
RSPAMC_IS_SPAM_REGEX = re.compile('^Spam:\s+(true|false)+')
DOVECOT_DELIVER = '/usr/lib/dovecot/deliver'
POSTFIX_DELIVER = '/usr/lib/postfix/virtual'
MAILER_DAEMON = '<mailer@wservices.ch>'

LOG_FILE = '/var/log/vmail/vmail.log'


# Files which are bigger than this size (in bytes) will not be checked for spam.
MAX_SPAM_SIZE=1000000

# The following headers will be removed from the mail body before applying the new headers.
RESERVED_HEADERS = ['X-Virus-Checker-Version', 'X-Virus-Status', 'X-Virus-Report', 
                    'X-Spam-Checker-Version', 'X-Spam-Level', 'X-Spam-Status', 'X-Spam-Report', 'X-Spam-Flag',
                    'X-Rspam-Status', 'X-Rspam-Flag']

log = logging.getLogger('wcenter-lda')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
log.addHandler(fh)


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
        log.error('Exception: %s' % e)
        traceback.print_exc(file=open(LOG_FILE, 'a'))
        sys.stderr.write(str(e))
    except:
        # File silently, as we can't log or print the error
        pass


class Mail():
    def __init__(self, data, mail_from, mail_to, extension, queue_id):
        self.data = data
        self.mail_from = mail_from
        self.mail_to = mail_to
        self.extension = extension
        self.queue_id = queue_id

        self.is_virus = None
        self.is_spam = None
        self.is_rspam = None
        self.required_spam_score = Decimal(5.0)

        self.spam_dir = 'Junk'
        self.virus_dir = 'Junk'
        self.uid = None
        self.gid = None

        if not self.data:
            raise ValueError('Message is empty')

        # get account
        self.parse()

    def parse(self):
        log.debug('Parsing e-mail')
        self.message = email.message_from_bytes(self.data)

        if not self.mail_to:
            self.mail_to = self.message.get('Delivered-To')
            if not self.mail_to:
                log.error('no recipient found')
                sys.stderr.write('no recipient found\n')
                sys.exit(75)

        self.mail_from = self.message.get('From')
        if not self.mail_from:
            self.mail_from = 'unknown'

        log.debug('e-mail from %s to %s' % (self.mail_from, self.mail_to))

        try:
            (self.user, self.domain) = self.mail_to.split('@')
        except ValueError:
            log.error('no valid destination mail address %s' % self.mail_to)
            sys.stderr.write('no valid destination mail address %s\n' % self.mail_to)
            sys.exit(75)

        # set dovecot as default deliver
        self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to]

        # replace Return-Path: <MAILER-DAEMON>
        if self.message.get('Return-Path') == '<MAILER-DAEMON>':
            log.info('replace Return-Path: <MAILER-DAEMON> to %s' % MAILER_DAEMON)
            del self.message['Return-Path']
            self.message['Return-Path'] = MAILER_DAEMON

    def check(self):
        check_virus_bool = True
        check_spam_bool = True

        # get account settings
        try:
            conn = MySQLdb.connect(host=WConfig.MYSQL_HOST, port=WConfig.MYSQL_PORT, user=WConfig.MYSQL_USER, passwd=WConfig.MYSQL_PASSWD, db=WConfig.MYSQL_DB)
            cursor = conn.cursor()
            cursor.execute('SELECT check_virus, virus_dir, check_spam, spam_dir, required_spam_score, uid, gid FROM mail_users WHERE email LIKE %s', (self.mail_to.lower(),))
            result = cursor.fetchone()
            if result:
                check_virus_bool = result[0]
                self.virus_dir = result[1]
                check_spam_bool = result[2]
                self.spam_dir = result[3]
                self.required_spam_score = Decimal(result[4])
                #self.uid = int(result[5])
                #self.gid = int(result[6])
            cursor.close()
            conn.close()
        except Exception as e: # any errors
            log.warning('Can not fetch spam settings %s' % e)

        if self.uid and self.gid:
            try:
                setuid(self.uid, self.gid)
            except OSError as e:
                log.warning('Can not set uid/gid %s' % e)
                pass

        virus_headers = {}
        if check_virus_bool:
            # Check for viruses
            self.is_virus, virus_headers = self.check_virus()

        spam_headers = {}
        rspam_headers = {}
        if not self.is_virus and check_spam_bool and len(self.data) <= MAX_SPAM_SIZE:
            # Only check for spam if there's no virus, check_spam_bool=True and if the mail is smaller than MAX_SPAM_SIZE
            log.debug('X-SMTP-Auth: {}'.format(self.message.get('X-SMTP-Auth')))
            if self.message.get('X-SMTP-Auth') == 'no':
                #self.is_spam, spam_headers = self.check_spam()
                self.is_rspam, rspam_headers = self.check_rspam()

        if self.is_virus:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-m', self.virus_dir]
        elif self.is_spam or self.is_rspam:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-m', self.spam_dir]
        elif self.extension:
            self.deliver_application = [DOVECOT_DELIVER, '-d', self.mail_to, '-m', self.extension]

        headers = {**virus_headers, **spam_headers, **rspam_headers}

        for header_name in RESERVED_HEADERS:
            del self.message[header_name]
        for header_name,header_value in headers.items():
            self.message[header_name] = header_value

    def check_virus(self):
        headers = {}

        # Get the version
        status, version = run([CLAMSCAN, '-V'])
        assert status == 0, 'Could not run %s (exit code %d)' % (CLAMSCAN, status)

        headers['X-Virus-Checker-Version'] = version.split(b'\n')[0].decode()

        # Scan the message
        status, report = run([CLAMSCAN, '-', '--stdout'], self.data)

        if status == 0:
            # No virus
            headers['X-Virus-Status'] = 'No'
        elif status == 1:
            # Virus found
            headers['X-Virus-Status'] = 'Yes'

            try:
                # Note: There may be multiple status lines. Do we want to parse them?
                headers['X-Virus-Report'] = report.split()[1].decode()
            except IndexError as e:
                log.warning('Set X-Virus-Report failed: {}'.format(e))
                headers['X-Virus-Report'] = 'Failed'
        else:
            headers['X-Virus-Status'] = 'Failed'
        log.debug('Virus status: {} ({})'.format(headers.get('X-Virus-Status'), status))

        try:
            status = int(status)
        except ValueError:
            log.warning('Virus status is not an integer: {}'.format(status))
            pass

        return (status == 1, headers)

    def check_rspam(self):
        headers = {}

        p = subprocess.Popen([RSPAMC], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(self.data)
        if stderr:
            log.error('rspamc stderr: %s' % stderr)
            return (False, {})

        # If spam returncode is 1, else returncode is 0
        if p.returncode and p.returncode != 1:
            log.error('rspamc error: returncode: %s' % p.returncode)
            return (False, {})

        spam_score = None
        required_spam_score = None
        is_rspam = False
        result = stdout.decode()
        for line in result.split('\n'):
            is_rspam_match = RSPAMC_IS_SPAM_REGEX.match(line)
            if is_rspam_match:
                is_rspam = is_rspam_match[1] == 'true'
            score_match = RSPAMC_SCORE_REGEX.match(line)
            if score_match:
                spam_score = score_match[1]
                required_spam_score = score_match[2]
            ham_match = re.match('^Symbol:\s+(\S+)\s+(.*)$', line)
            if ham_match:
                if ham_match[1] in ['BAYES_HAM', 'BAYES_SPAM']:
                    log.debug('Symbol: {} {}'.format(ham_match[1], ham_match[2]))

        if spam_score != None:
            headers['X-Rspam-Status'] = '%s, score=%s' % (is_rspam and 'Yes' or 'No', spam_score)
        if is_rspam:
            headers['X-Rspam-Flag'] = 'YES'

        log.debug('Rspam status: {}'.format(headers.get('X-Rspam-Status')))
        log.debug('Rspam flag: {}'.format(headers.get('X-Rspam-Flag')))
        return (is_rspam, headers)

    def check_spam(self):
        headers = {}

        p = subprocess.Popen([SPAMC, '-R', '-u', 'vmail', '-s', str(MAX_SPAM_SIZE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(self.data)
        if stderr:
            log.error('Spamc stderr: %s' % stderr)
            return (False, {})

        # If spam returncode is 1, else returncode is 0
        if p.returncode and p.returncode != 1:
            log.error('Spamc error: returncode: %s' % p.returncode)
            return (False, {})

        result = stdout.decode()

        # No try/except here, as there shouldn't be any errors
        try:
            ignore, version, score, tests, summary = result.split('\n', 4)
        except ValueError:
            log.error('Unknown spamc format: {}'.format(result))
            version = 'error'
            score = '3 ***'
            summary = 'Error during spam check'
            tests = ''
        try:
            spam_score, spam_level = score.split(' ')
        except ValueError:
            log.warning('Unknown spamc score format: {}'.format(score))
            spam_score = score
            spam_level = ''

        is_spam = Decimal(spam_score) >= self.required_spam_score

        # Set the headers
        headers['X-Spam-Checker-Version'] = version
        if spam_level:
            headers['X-Spam-Level'] = spam_level
        headers['X-Spam-Status'] = '%s, score=%s required=%s %s' % \
                (is_spam and 'Yes' or 'No', spam_score, self.required_spam_score, tests)
        if is_spam:
            headers['X-Spam-Flag'] = 'YES'
            headers['X-Spam-Report'] = '---- Start SpamAssassin results\n\t* %s\n\t---- End of SpamAssassin results' % \
                    summary.replace('\n', '\n\t').strip().replace('\t', '\t* ')
        log.debug('Spam status: {}'.format(headers.get('X-Spam-Status')))

        return (is_spam, headers)

    def deliver(self):
        #log.debug('User %s Group %s' % (os.getuid(), os.getgid()))
        log.debug('Deliver with: %s' % self.deliver_application)
        message = self.message.as_bytes()

        p = subprocess.Popen(self.deliver_application, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(message)
        if p.returncode:
            log.error('Delivery error: %s %s %s' % (p.returncode, stderr, stdout))
            sys.exit(p.returncode)
        else:
            log.debug('Delivered')


def run(cmd, data=None):
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    try:
        if data:
            proc.stdin.write(data)
        proc.stdin.close()
        result = proc.stdout.read()
        proc.stdout.close()
    except IOError as e: # The child closed the file too early. Don't return anything in that case.
        log.error('{}: {}'.format(cmd, e))
        result = ''

    status = os.waitpid(proc.pid, 0)[1]/256

    return (status, result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='wcenter local delivery agent')
    parser.add_argument('mail_from', nargs='?', help='MAIL FROM (Mail received from)', default='unkown')
    parser.add_argument('mail_to', nargs='?', help='RCPT TO (Recipient email address)')
    parser.add_argument('extension', nargs='?', help='Mail extension', default='')
    parser.add_argument('queue_id', nargs='?', help='Postfix queue ID', default='')
    args = parser.parse_args()

    data = sys.stdin.buffer.read()

    formatter = logging.Formatter(
        fmt='%(asctime)s %(name)s[%(process)d] {} %(levelname)s: %(message)s'.format(args.queue_id),
        #datefmt='%Y-%m-%d %H:%M:%S',
    )
    fh.setFormatter(formatter)

    try:
        mail = Mail(data, args.mail_from, args.mail_to, args.extension, args.queue_id) # parse mail
    except Exception as e:
        log.error('parsing error')
        print_error(e)
        sys.exit(75)    # EX_TEMPFAIL: A temporary failure.
    try:
        mail.check()    # check mail for spam and viruses
    except Exception as e:
        log.error('mail check error')
        print_error(e)
    try:
        mail.deliver()  # deliver the mail
    except Exception as e:
        log.error('mail delivery error')
        print_error(e)
        sys.exit(75)    # EX_TEMPFAIL: A temporary failure.

