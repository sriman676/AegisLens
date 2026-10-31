"""Writes sample-data/labelled-events.csv: synthetic, reserved addresses only, each line labelled attack (with the rule
that should fire for its source address) or benign. Deterministic so the evaluation numbers are reproducible."""
import csv
import random
import sys

random.seed(2026)
rows = []


def ssh(t, msg, label, rule=''):
    rows.append(('ssh', f'Oct 30 {t} srv sshd[{random.randint(100, 999)}]: {msg}', label, rule))


def web(ip, t, req, status, ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64)', label='benign', rule=''):
    rows.append(('web', f'{ip} - - [30/Oct/2026:{t} +0000] "{req} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "{ua}"',
                 label, rule))


# --- SSH attacks
for i in range(6):
    ssh(f'14:00:0{i}', f'Failed password for root from 203.0.113.10 port {50000 + i} ssh2', 'attack', 'NET-001')
for i in range(6):
    ssh(f'14:05:1{i}', f'Failed password for admin from 203.0.113.11 port {51000 + i} ssh2', 'attack', 'NET-001')
ssh('14:05:20', 'Accepted password for admin from 203.0.113.11 port 51010 ssh2', 'attack', 'NET-001')
for i, user in enumerate(['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace']):
    ssh(f'14:10:1{i}', f'Failed password for invalid user {user} from 203.0.113.12 port {52000 + i} ssh2', 'attack', 'NET-007')
ssh('03:12:44', 'Accepted password for carol from 192.0.2.30 port 53001 ssh2', 'attack', 'NET-003')

# --- SSH benign
for i in range(40):
    ssh(f'{random.randint(9, 17):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}',
        f'Accepted publickey for user{i % 12} from 198.51.100.{random.randint(1, 60)} port {40000 + i} ssh2', 'benign')
ssh('11:00:01', 'Failed password for priya from 198.51.100.77 port 41001 ssh2', 'benign')       # a typo, twice
ssh('11:00:09', 'Failed password for priya from 198.51.100.77 port 41002 ssh2', 'benign')
ssh('11:00:15', 'Accepted password for priya from 198.51.100.77 port 41003 ssh2', 'benign')
ssh('12:30:00', 'Connection closed by 198.51.100.5 port 41100 [preauth]', 'benign')

# --- web attacks
for i, path in enumerate(['/admin', '/wp-login.php', '/.env', '/backup.zip', '/phpmyadmin', '/config.php', '/.git/config',
                          '/server-status', '/old/', '/test.php', '/db.sql', '/api/v1/debug', '/console', '/shell.php',
                          '/xmlrpc.php', '/cgi-bin/test.cgi']):
    web('203.0.113.20', f'14:20:{i:02d}', f'GET {path}', 404, label='attack', rule='NET-002')
web('203.0.113.21', '14:30:01', 'GET /item?id=1%20UNION%20SELECT%20password%20FROM%20users', 200, label='attack', rule='WEB-002')
web('203.0.113.22', '14:31:01', 'GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E', 200, label='attack', rule='WEB-002')
web('203.0.113.24', '14:32:01', 'GET /download?file=../../etc/passwd', 400, label='attack', rule='WEB-002')
web('203.0.113.23', '14:33:01', 'GET /index.html', 200, ua='sqlmap/1.7.2#stable (https://sqlmap.org)', label='attack', rule='NET-006')
web('203.0.113.25', '14:34:01', 'GET /index.html', 200, ua='Nikto/2.5.0', label='attack', rule='NET-006')

# --- web benign (including tricky ones that look a bit like attacks)
pages = ['/', '/index.html', '/about.html', '/products?id=7', '/products?id=12', '/contact', '/static/app.css',
         '/static/logo.png', '/search?q=red+shoes', '/cart', '/checkout', '/blog/how-to-choose']
for i in range(60):
    web(f'198.51.100.{random.randint(1, 60)}', f'{random.randint(9, 17):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}',
        f'GET {random.choice(pages)}', 200)
web('198.51.100.90', '10:00:01', 'GET /favicon.ico', 404)
web('198.51.100.90', '10:00:02', 'GET /apple-touch-icon.png', 404)
web('198.51.100.91', '10:05:00', 'GET /blog/2026--year-in-review', 200)
web('198.51.100.92', '10:06:00', 'GET /search?q=rock+%27n%27+or+%27roll%27', 200)
web('198.51.100.93', '10:07:00', 'GET /search?q=select+a+gift', 200)
web('198.51.100.94', '10:08:00', 'POST /login', 200, ua='curl/8.5.0')

with open(sys.argv[1], 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f, lineterminator='\n')
    w.writerow(['source', 'line', 'label', 'expected_rule'])
    w.writerows(rows)
print(len(rows), 'rows,', sum(1 for r in rows if r[2] == 'attack'), 'attack')
