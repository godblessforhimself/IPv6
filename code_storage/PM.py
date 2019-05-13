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
python PM.py -i ~/datas/2019-04-12/AS_result/9146_REST.hex > ~/datas/2019-04-12/AS_result/9146_REST.pattern
interactive test
python PM.py -i datas/exception.txt -s 1000
'''
import numpy as np
import matplotlib.pyplot as plt
import argparse,code,time,bisect
flag_list=['x']
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
            pattern_list,pattern,count=[],'',0
            for IP in IPs:
                patternIP=continuous_filter(IP[16:], start, start+c-1)
                pattern_list.append(patternIP)
            pattern_list.sort()
            for pattern_ in pattern_list:
                if pattern!=pattern_:
                    if count>1:
                        patterns.append([pattern, count])
                    pattern,count=pattern_,1
                elif pattern==pattern_:
                    count+=1
            if count>1:
                patterns.append([pattern, count])
        return patterns
def check_pattern(pattern):
    #if len(pattern) != 16:
    #   code.interact(banner = "", local = locals())
    return
def only_pattern(IPs, c):
    # IID 16+[0,16)
    # [start, start+c)
    patterns=[]
    for start in range(0, 16-c+1):
        pattern_list,pattern,count=[],'',0
        for IP in IPs:
            patternIP=only_filter(IP[16:], start, start+c-1)
            check_pattern(patternIP)
            pattern_list.append(patternIP)
        pattern_list.sort()
        for pattern_ in pattern_list:
            if pattern!=pattern_:
                if count>1:
                    patterns.append([pattern, count])
                pattern,count=pattern_,1
            elif pattern==pattern_:
                count+=1
        if count>1:
            patterns.append([pattern, count])
    return patterns

def get_specify(pattern, IPs):
    '''
    消除确定位
    '''
    bit_set=[]
    for _ in xrange(16):
        bit_set.append(set())
    for IP in IPs:
        for i in xrange(16):
            if pattern[i] in flag_list:
                bit_set[i].add(IP[16+i])
    new_pattern=''
    for i in xrange(16):
        if len(bit_set[i])==1:
            new_pattern+=list(bit_set[i])[0]
        else:
            new_pattern+=pattern[i]
    return new_pattern
def is_covering(parent, son):
    l=16
    for i in xrange(l):
        if parent[i] in flag_list: continue
        if parent[i]==son[i]: continue
        return False
    return True
def eliminate_covering(patterns):
    remove_patterns=[]
    for pattern_a in patterns:
        for pattern_b in patterns:
            if pattern_a==pattern_b: continue
            if is_covering(pattern_a, pattern_b):
                remove_patterns.append(pattern_b)
    for pattern in remove_patterns:
        patterns.remove(pattern)
    return patterns
def eliminate_similar(patterns):
    '''
        xxxxx00
        0xxxxx0
        00xxxxx
        -> 
        xxxxxxx
    '''
    skipped_patterns,new_patterns=set(),[]
    for pattern in patterns:
        if pattern in skipped_patterns: continue
        begin_index=pattern.find('x')
        end_index=pattern.rfind('x')
        new_pattern, max_count, replaced_list = '', 0, []
        possible_patterns=[]
        if begin_index>=2:
            possible_patterns.append(pattern[:(begin_index-2)]+'xx'+pattern[begin_index:])
        if begin_index>=1 and end_index<=14:
            possible_patterns.append(pattern[:(begin_index-1)]+'x'+pattern[begin_index:(end_index+1)]+'x'+pattern[(end_index+2):])
        if end_index<=13:
            possible_patterns.append(pattern[:(end_index+1)]+'xx'+pattern[(end_index+3):])
        for possible_pattern in possible_patterns:
            check_pattern(possible_pattern)
            cover_count=0
            temp_replace=[pattern]
            for other_pattern in patterns:
                if other_pattern==pattern: continue
                if is_covering(possible_pattern, other_pattern): 
                    cover_count+=1
                    temp_replace.append(other_pattern)
            if cover_count > max_count:
                new_pattern=possible_pattern
                max_count=cover_count
                replaced_list=temp_replace
        if max_count >= 1:
            for pattern_i in replaced_list:
                skipped_patterns.add(pattern_i)
            new_patterns.append(new_pattern)
    for skipped_pattern in skipped_patterns:
        patterns.remove(skipped_pattern)
    patterns.extend(new_patterns)
    return patterns
            
def is_matching(pattern, IP):
    for i in xrange(16):
        if pattern[i] in flag_list: continue
        if pattern[i] != IP[16+i]: return False
    return True
def classify(patterns, IPs):
    size=len(patterns)
    ret=[]
    for _ in xrange(size + 1): ret.append([])
    for IP in IPs:
        remain=True
        for i,pattern in enumerate(patterns):
            check_pattern(pattern)
            if is_matching(pattern, IP):
                ret[i].append(IP)
                remain=False
                break
        if remain:
            ret[-1].append(IP)
    return ret
        
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input','-i',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('--epsilon','-e',type=int,default=5,help='c for continuous range length.')
    p.add_argument('--size','-s',type=int,help='max train size')
    args=p.parse_args()
    with open(args.input,'r') as f:
        data=f.read()
    lines=data.split('\n')
    lines.remove('')
    IPs,IID=[],set()
    t0=time.time()
    for line in open(args.input,'r'):
        if line and line[0]!='#' and line[0]!='\n':
            IP=line[:-1]
            if IP[16:] in IID:
                continue
            IID.add(IP[16:])
            IPs.append(IP)
    if args.size!=None:
        IPs=IPs[:args.size]
    IP_count=len(IPs)
    print('input file {} size {}.'.format(args.input, IP_count))
    print('IP use {} seconds'.format(time.time() - t0))
    
    t0=time.time()
    continuous_patterns=continuous_pattern(IPs, 4, 5)
    continuous_patterns.sort(key=lambda x:x[1], reverse=True)
    #for pattern_count in continuous_patterns:
     #   if pattern_count[1] > 1:
      #      print('{} {}'.format(pattern_count[0], pattern_count[1]))
    print('continuous_pattern use {} seconds'.format(time.time() - t0))
    '''
        get top 10 pattern
    '''
    t0=time.time()
    continuous_patterns=[i[0] for i in continuous_patterns[:100]]
    #for pattern in continuous_patterns:
     #   pattern=get_specify(pattern, IPs)
    eliminate_covering(continuous_patterns)
    classify_list=classify(continuous_patterns, IPs)
    for i, pattern in enumerate(continuous_patterns):
        m_c=len(classify_list[i])
        print('pattern={}, match count={}, percentage={}'.format(pattern, m_c, m_c/(float)(IP_count)))
    remain_count=len(classify_list[-1])
    print('remain count={}, percentage={}'.format(remain_count, remain_count/(float)(IP_count)))
    print('classify use {} seconds'.format(time.time() - t0))
    exit(0)
    t0=time.time()
    only_patterns=only_pattern(IPs, 10)
    only_patterns.sort(key=lambda x:x[1], reverse=True)
    print('only_pattern use {} seconds'.format(time.time() - t0))
    t0=time.time()
    remain_pattern_count=150
    print('total {} patterns, use {} patterns'.format(len(only_patterns), remain_pattern_count))
    only_patterns=[i[0] for i in only_patterns[:remain_pattern_count]]
    #for pattern in only_patterns:
        #pattern=get_specify(pattern, IPs)
    only_patterns=eliminate_covering(only_patterns)
    print('specify and eliminate_covering use {} seconds'.format(time.time() - t0))
    t0=time.time()
    only_patterns=eliminate_similar(only_patterns)
    print('eliminate_similar remain {} patterns, use {} seconds'.format(len(only_patterns), time.time() - t0))
    t0=time.time()
    classify_list=classify(only_patterns, IPs)
    for i, pattern in enumerate(only_patterns):
        m_c=len(classify_list[i])
        print('pattern={}, match count={}, percentage={}'.format(pattern, m_c, m_c/(float)(IP_count)))
    remain_count=len(classify_list[-1])
    print('remain count={}, percentage={}'.format(remain_count, remain_count/(float)(IP_count)))
    print('classify use {} seconds'.format(time.time() - t0))
    classify_list[-1].sort(key=lambda x:x[16:])
    for IP in classify_list[-1]:
        print(IP[:16]+' '+IP[16:])
    #code.interact(banner = "", local = locals())
