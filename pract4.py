#!/usr/bin/env python3

import requests
import json
import re
import hashlib

def do_md5():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.md5(str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def do_SHA1():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.sha1(str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def do_SHA256():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.sha256(str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def do_SHA384():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.sha384(str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def do_SHA512():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.sha512(str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def do_RMD160():
    result = []
    for i in range(1000, 10000):
        tmp = hashlib.new('ripemd160', str(i).encode('utf-8')).hexdigest()
        result.append(tmp)
    return result

def reg(url, name, passwd, headers):
    data = {"user": {"login": "725_mmr", "password":"barkbarkgo"}}
    resp = requests.post(url + 'users', data=json.dumps(data), headers=headers)
    print(resp)

def get_token(url, name, passwd, headers):
    data = {"login": "725_mmr", "password":"barkbarkgo"}
    tmp = requests.post(url + 'auth', data=json.dumps(data), headers=headers)
    token = tmp.json()['token']
    return token

def get_tasks(url, headers):
    req = requests.get(url + 'tasks', headers=headers)
    id_tasks = re.findall(r'oid":"(\w{24})', req.text)
    return id_tasks

def delete(url, token): # just for fun
    userid = '5ad72e133a25745bae7c7631'
    headers = {'Content-type': 'application/json', 'Authorization': token}
    resp = requests.delete(url + 'users/' + userid, headers=headers)

def one_task(url, headers, id_tasks):
    tasks = []
    rainbow_md5 = []
    rainbow_sha1 = []
    rainbow_sha256 = []
    rainbow_sha384 = []
    rainbow_sha512 = []
    rainbow_rmd160 = []
    resolve = []

    for i in range(len(id_tasks)):
        req = requests.get(url + 'tasks/' + id_tasks[i], headers=headers)
        tasks.append(req.json()['tasks']['digest'])

    for i in range(len(tasks)):
        if len(tasks[i]) == 32: #md5
            if not rainbow_md5:
                rainbow_md5 = do_md5()
            if tasks[i] in rainbow_md5:
                resolve.append(rainbow_md5.index(tasks[i]) + 1000)
            else: print("Такого хэша md5 нет")
        elif len(tasks[i]) == 40: #sha1 or rmd160
            if not rainbow_sha1:
                rainbow_sha1 = do_SHA1()
            if not rainbow_rmd160:
                rainbow_rmd160 = do_RMD160()

            if tasks[i] in rainbow_sha1:
                resolve.append(rainbow_sha1.index(tasks[i]) + 1000)
            elif tasks[i] in rainbow_rmd160:
                resolve.append(rainbow_rmd160.index(tasks[i]) + 1000)
            else: print("Такого хэша SHA1 или RMD160 нет")
        elif len(tasks[i]) == 64: #sha256
            if not rainbow_sha256:
                rainbow_sha256 = do_SHA256()
            if tasks[i] in rainbow_sha256:
                resolve.append(rainbow_sha256.index(tasks[i]) + 1000)
            else: print("Такого хэша SHA256 нет")
        elif len(tasks[i]) == 96: #sha384
            if not rainbow_sha384:
                rainbow_sha384 = do_SHA384()
            if tasks[i] in rainbow_sha384:
                resolve.append(rainbow_sha384.index(tasks[i]) + 1000)
            else: print("Такого хэша SHA384 нет")
        elif len(tasks[i]) == 128: #sha512
            if not rainbow_sha512:
                rainbow_sha512 = do_SHA512()
            if tasks[i] in rainbow_sha512:
                resolve.append(rainbow_sha512.index(tasks[i]) + 1000)
            else: print("Такого хэша SHA512 нет")
        else:
            print("Это не хэш")

    return resolve        

def send_resolve(url, token, id_tasks, tasks):
    headers = {'Content-type': 'application/json', 'Authorization': token}
    for i in range(len(id_tasks)):
        data = {"task": {"decode": tasks[i]}}
        req = requests.patch(url + 'tasks/' + id_tasks[i], data = json.dumps(data), headers=headers)
        print(req.json())

def main():
    url = 'http://185.40.31.149:8888/api/'
    headers = {'Content-type': 'application/json'}
    login = "725_mmr"
    password = "barkbarkgo"

    # reg(url, login, password, headers)
    id_tasks = get_tasks(url, headers) # список id
    tasks = one_task(url, headers, id_tasks) # список решений тасков
    token = get_token(url, login, password, headers) # токен
    send_resolve(url, token, id_tasks, tasks) # отправка ответов на таски

main()