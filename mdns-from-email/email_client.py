#!/usr/bin/env python3

import re
import imaplib
import email
import email.utils
import time
import datetime
import threading
import enum
import queue



def datetime2imapdate(datetimeobj):
    day = datetimeobj.day
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
            "Oct", "Nov", "Dec"][datetimeobj.month-1]
    year = datetimeobj.year
    return "%d-%s-%d" % (day, month, year)


class EmailSearch:


    def __init__(self, email_config, search_config):
        self.email_config = email_config
        self.search_config = search_config

        self.updates = queue.Queue()

        self.ip_table = {}

        self._event_start = threading.Event()
        self._heart = threading.Thread(target=self._work)
        self._heart.start()

    def _decode_bytes_by_charsets(self, charsets, data):
        for charset in charsets:
            if charset == None:
                charset = "utf-8"
            try:
                return data.decode(charset)
            except:
                pass
        return None

    def check_email(self):
        # Ask the background to check email once.
        self._event_start.set()

    def _check_once(self, conn, past_days=3):
        """Check for emails in the given timespan. Synchronize emails to local
        database."""

        sentsince = datetime2imapdate(
            datetime.datetime.now() - 
            datetime.timedelta(days=past_days)
        )
        search_str = " ".join([
            #("SUBJECT \"%s\"" % subject) if subject else "",
            "SENTSINCE %s" % sentsince,
            #("FROM \"%s\"" % from) if from else "",
        ])

        typ, data = conn.search(None, search_str)
        if typ != "OK": return

        results_per_domain = {}

        mail_uids = [int(e) for e in data[0].split(b" ")]
        for uid in mail_uids:
            result = self._search_mail(uid, conn=conn)
            for domain in result:
                if not domain in results_per_domain:
                    results_per_domain[domain] = []
                results_per_domain[domain].append(result[domain])

        # sort domain records
        self.ip_table = {}
        for domain in results_per_domain:
            results_per_domain[domain].sort(key=lambda e: e[1])
            results_per_domain[domain].reverse()
            self.ip_table[domain] = results_per_domain[domain][0][0]

        print(self.ip_table)


    def _search_mail(self, uid, conn):
        typ, data = conn.fetch(bytes(str(uid), "ascii"), '(RFC822)' )
        raw_email = data[0][1]
        email_message = email.message_from_bytes(raw_email)
        # record charsets
        charsets = set(email_message.get_charsets())

        email_ts = time.mktime(email.utils.parsedate(email_message["Date"]))
        email_subject = email_message["Subject"]
        email_body = str(email_message)
        email_from = email_message["From"]

        result_per_domain = {}
        for domain in self.search_config:
            profile = self.search_config[domain]

            filter_subject = profile["subject"] if "subject" in profile else None
            filter_body = profile["body"] if "body" in profile else ".+"
            filter_from = profile["from"] if "from" in profile else None

            if filter_subject:  
                if not re.search(filter_subject, email_subject):
                    continue
            if not re.search(filter_body, email_body):
                continue
            if filter_from:
                if not re.search(filter_from, email_from):
                    continue

            # fetch IP
            f_ip_r = re.search(filter_body, email_body)

            if f_ip_r:
                f_ip = re.search(
                    '([0-9]{1,3}\.){3}([0-9]{1,3})', f_ip_r.group(0))
                if f_ip:
                    result_per_domain[domain] = (f_ip.group(0), email_ts)
        return result_per_domain

    def _work(self):
        """Starts a one-shot checking process, when self._event_start is
        set. After this process, wait for the next."""
        
        while True:
            self._event_start.wait()

            try:
                host = self.email_config["host"]
                port = self.email_config["port"]
                print("Email client running.")

                with imaplib.IMAP4_SSL(host=host, port=port) as conn:
                    conn.login(
                        self.email_config["username"],
                        self.email_config["password"])

                    conn.select() # INBOX
                    self._check_once(conn=conn)
                
            except Exception as e:
                print("MailClient Exception:", e)
            finally:
                self._event_start.clear()
