#coding:utf-8
'''
python Deduplication.py -A [file] -B [file] -C [file]
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
def main(A,B,C,size_A,size_B):
    t0 = time.time()
    if size_A > size_B:
        B_IPs=set()
        for line in open(B):
            if line and line[0] != '#':
                B_IPs.add(line.strip())
        print('load {} use {} seconds'.format(B,time.time() - t0))
        t0=time.time()
        with open(C, 'w') as f:
            for line in open(A):
                if line and line[0]!='#':
                    IP=line.strip()
                    if not IP in B_IPs:
                        f.write(IP+'\n')
        print('output {} use {} seconds'.format(C, time.time() - t0))
    else:
        A_IPs=set()
        for line in open(A):
            if line and line[0] != '#':
                A_IPs.add(line.strip())
        print('load {} use {} seconds'.format(A,time.time() - t0))
        t0=time.time()
        for line in open(B):
            if line and line[0]!='#':
                IP=line.strip()
                if IP in A_IPs:
                    A_IPs.remove(IP)
        print('remove IP in {} from {} use {} seconds'.format(B, A, time.time() - t0))
        t0=time.time()
        with open(C, 'w') as f:
            for IP in A_IPs:
                f.write(IP+'\n')
        print('output {} use {} seconds'.format(C, time.time() - t0))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('-A',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('-B',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('-C',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('--silent',action='store_true',help='silent mode')
    args=p.parse_args()
    size_A=os.path.getsize(args.A)
    size_B=os.path.getsize(args.B)
    print('file {} size is {} MB, file {} size is {} MB'.format(args.A, size_A/2.0**20, args.B, size_B/2.0**20))

    if args.silent:
        main(args.A, args.B, args.C, size_A, size_B)
        exit(0)

    choice=raw_input('Y to continue, no to exit, DB to use database\n')    
    if choice=='no':
        exit(0)
    elif choice=='Y' or args.silent:
        main(args.A, args.B, args.C, size_A, size_B)
    elif choice=='DB':
        print('start')
        t0=time.time()
        connection=sqlite3.connect('Deduplication_temp.db')
        connection.execute('PRAGMA temp_store_directory = \'{}\';'.format(os.path.dirname(args.C)))
        connection.executescript('DROP TABLE IF EXISTS A;DROP TABLE IF EXISTS B;DROP TABLE IF EXISTS C;')
        connection.executescript('CREATE TABLE A(IP TEXT, NOT_IN_B INTEGER);CREATE TABLE B(IP TEXT);CREATE TABLE C(IP TEXT);')
        batches,max_count=[],1000000
        print('lent')
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
        connection.execute('CREATE INDEX E_INDEX ON A(IP);')
        print('CREATE INDEX use {} seconds'.format(time.time() - t0))

        t0=time.time()
        for line in open(args.B):
            if line and line[0] != '#':
                IP=line.strip()
                connection.execute('UPDATE A SET NOT_IN_B=0 WHERE IP=?;',(IP,))
        print('dedup use {} seconds'.format(time.time() - t0))

        t0=time.time()
        with open(args.C, 'w') as f:
            for item in connection.execute('SELECT IP FROM A WHERE NOT_IN_B=1;'):
                IP=item[0]
                f.write(IP+'\n')
        print('write to {} use {} seconds'.format(args.C, time.time() - t0))
        connection.commit()
        connection.close()
        