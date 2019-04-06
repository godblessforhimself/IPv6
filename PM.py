#coding:utf-8
'''
PATTERN
    a.连续c位相同 continuous
        c=[4，5，6，7，8]
    b.只有c位不同 only
        c=5
1.get patterns
2.
3.
python PM.py -i datas/input.hex -s 1000 > results/PM.txt.0
python PM.py -i datas/exception.txt -s 1000 > results/PM.txt.0
'''
import numpy as np
import matplotlib.pyplot as plt
import argparse,code,time,bisect
def continuous_filter(IID, l, r):
    # IID [l,r]
    return 'x'*l+IID[l:(r+1)]+'x'*(15-r)
def only_filter(IID, l, r):
    # IID [l,r]
    return IID[:l]+'x'*(r-l+1)+IID[(r+1):16]
def continuous_pattern(IPs, begin, end):
    # IID 16+[0,16)
    # [start, start+c)
    patterns=[]
    for c in range(begin,end+1):
        for start in range(0, 16-c+1):
            insertion_sort_list=[]
            for IP in IPs:
                patternIP=continuous_filter(IP[16:], start, start+c-1)
                bisect.insort(insertion_sort_list, patternIP)
            pattern,count='',0
            for pattern_ in insertion_sort_list:
                if pattern!=pattern_:
                    if count>0:
                        patterns.append([pattern, count])
                    pattern,count=pattern_,1
                elif pattern==pattern_:
                    count+=1
            patterns.append([pattern, count])
    return patterns
def only_pattern(IPs, c):
    # IID 16+[0,16)
    # [start, start+c)
    patterns=[]
    for start in range(0, 16-c+1):
        insertion_sort_list=[]
        for IP in IPs:
            patternIP=only_filter(IP[16:], start, start+c-1)
            bisect.insort(insertion_sort_list, patternIP)
        pattern,count='',0
        for pattern_ in insertion_sort_list:
            if pattern!=pattern_:
                if count>0:
                    patterns.append([pattern, count])
                pattern,count=pattern_,1
            elif pattern==pattern_:
                count+=1
        patterns.append([pattern, count])
    return patterns
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input','-i',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('--epsilon','-e',type=int,default=5,help='c for continuous range length.')
    p.add_argument('--size','-s',type=int,help='max train size')
    args=p.parse_args()
    print('input file {} size {}.'.format(args.input, args.size))
    with open(args.input,'r') as f:
        data=f.read()
    lines=data.split('\n')
    lines.remove('')
    IPs=[]
    for line in open(args.input,'r'):
        if line and line[0]!='#' and line[0]!='\n':
            IPs.append(line[:-1])
    if args.size!=None:
        IPs=IPs[:args.size]
    t0=time.time()
    continuous_patterns=continuous_pattern(IPs, 4, 5)
    continuous_patterns.sort(key=lambda x:x[1], reverse=True)
    for pattern_count in continuous_patterns:
        if pattern_count[1] > 1:
            print('{} {}'.format(pattern_count[0], pattern_count[1]))
    print('continuous_pattern use {} seconds'.format(time.time() - t0))

    t0=time.time()
    only_patterns=only_pattern(IPs, 5)
    only_patterns.sort(key=lambda x:x[1], reverse=True)
    for pattern_count in only_patterns:
        if pattern_count[1] > 1:
            print('{} {}'.format(pattern_count[0], pattern_count[1]))
    print('only_pattern use {} seconds'.format(time.time() - t0))

    #code.interact(banner = "", local = locals())