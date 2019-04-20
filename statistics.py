#coding: utf-8
'''
    统计non aliased address 比例并输出
    python statistics.py -i ~/datas/2019-04-12/classify.txt
'''
import argparse

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input','-i',type=str,help='filename with IPv6 addresses.')
    args=p.parse_args()
    count=0
    for line in open(args.input):
        if line and line[0]!='#':
            parts=line.split(',')
            if parts[2][0]=='0':
                count+=1
                print(parts[0])
    print(count)