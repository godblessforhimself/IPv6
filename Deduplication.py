#coding:utf-8
'''
python Deduplication.py -A datas/predict.hex -B datas/IP_100000_for_APD.txt -C 
python Deduplication.py -A ~/datas/2019-04-12/AS_result/AS6057.hex -B ~/datas/2019-04-12/AS_result/6057eui.hex -C ~/datas/2019-04-12/AS_result/6057.noeui.hex
python Deduplication.py -A ~/datas/2019-04-12/AS_result/9146.hex -B ~/datas/2019-04-12/AS_result/9146eui.hex -C ~/datas/2019-04-12/AS_result/9146.noeui.hex
return A-B
print A-B & time 
sudo zmap --ipv6-target-file=predict.txt --ipv6-source-ip=2402:f000:9:8401:487d:379f:270a:1760 -M icmp6_echoscan -f saddr,daddr,ipid,ttl,timestamp_str -O json -o eip_scanResult.txt
'''
import os
import numpy as np
import matplotlib.pyplot as plt
import argparse,code,time,sqlite3
flag_list=['x']
hex_str=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('-A',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('-B',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('-C',type=str,help='filename with hex IPv6 addresses.')
    
    args=p.parse_args()
    t0=time.time()
    size_A=os.path.getsize(args.A)
    size_B=os.path.getsize(args.B)
    print('file {} size is {} MB, file {} size is {} MB'.format(args.A, size_A/2.0**20, args.B, size_B/2.0**20))
    choice=raw_input('Y to continue, no to exit, DB to use database\n')
    if choice=='no':
        exit(0)
    elif choice=='Y':
        if size_A > size_B:
            B_IPs=set()
            for line in open(args.B):
                if line and line[0] != '#':
                    B_IPs.add(line.strip())
            print('load {} use {} seconds'.format(args.B,time.time() - t0))
            t0=time.time()
            with open(args.C, 'w') as f:
                for line in open(args.A):
                    if line and line[0]!='#':
                        IP=line.strip()
                        if not IP in B_IPs:
                            f.write(IP+'\n')
            print('output {} use {} seconds'.format(args.C, time.time() - t0))
        else:
            A_IPs=set()
            for line in open(args.A):
                if line and line[0] != '#':
                    A_IPs.add(line.strip())
            print('load {} use {} seconds'.format(args.A,time.time() - t0))
            t0=time.time()
            for line in open(args.B):
                if line and line[0]!='#':
                    IP=line.strip()
                    if IP in A_IPs:
                        A_IPs.remove(IP)
            print('remove IP in {} from {} use {} seconds'.format(args.B, args.A, time.time() - t0))
            t0=time.time()
            with open(args.C, 'w') as f:
                for IP in A_IPs:
                    f.write(IP+'\n')
            print('output {} use {} seconds'.format(args.C, time.time() - t0))
    elif choice=='DB':
        t0=time.time()
        connection=sqlite3.connect('Deduplication_temp.db')
        connection.executescript('DROP TABLE IF EXISTS A;DROP TABLE IF EXISTS B;DROP TABLE IF EXISTS C;')
        connection.executescript('CREATE TABLE A(IP TEXT, NOT_IN_B INTEGER);CREATE TABLE B(IP TEXT);CREATE TABLE C(IP TEXT);')
        batches,max_count=[],1000000
        for line in open(args.A):
            if line and line[0] != '#':
                IP=line.strip()
                batches.append((IP, 1))
                if len(batches)==max_count:
                    connection.executemany('INSERT INTO A VALUES (?,?)', batches)
                    batches=[]
                    print('{} use {} seconds'.format(max_count, time.time() - t0))
        connection.executemany('INSERT INTO A VALUES (?,?)', batches)
        print('insert {} into database use {} seconds'.format(args.A, time.time() - t0))
        t0=time.time()
        batches=[]
        for line in open(args.B):
            if line and line[0] != '#':
                IP=line.strip()
                batches.append((IP,))
                if len(batches)==max_count:
                    connection.executemany('INSERT INTO B VALUES (?)', batches)
                    batches=[]
        connection.executemany('INSERT INTO B VALUES (?)', batches)
        print('insert {} into database use {} seconds'.format(args.B, time.time() - t0))
        t0=time.time()
        connection.execute('CREATE INDEX E_INDEX ON A(IP);')
        print('CREATE INDEX use {} seconds'.format(time.time() - t0))
        t0=time.time()
        c1,c2=connection.cursor(),connection.cursor()
        count=0
        for item in c1.execute('SELECT IP FROM B;'):
            IP=item[0]
            c2.execute('UPDATE A SET NOT_IN_B=0 WHERE IP=?;',(IP,))
            count+=1
            if count%1000000==0:
                print('{} use {} seconds'.format(count, time.time() - t0))
        print('update NOT_IN_B in database use {} seconds'.format(time.time() - t0))
        t0=time.time()
        for item in c1.execute('SELECT IP FROM A WHERE NOT_IN_B=1;'):
            IP=item[0]
            c2.execute('INSERT INTO C VALUES (?);', (IP,))
        print('insert C into database use {} seconds'.format(time.time() - t0))
        t0=time.time()
        with open(args.C, 'w') as f:
            for item in connection.execute('SELECT IP FROM C'):
                IP=item[0]
                f.write(IP+'\n')
        print('write to {} use {} seconds'.format(args.C, time.time() - t0))
        connection.commit()
        connection.close()
        