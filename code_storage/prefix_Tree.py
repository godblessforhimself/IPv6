#coding:utf-8
'''
大数据
python prefix_Tree.py -i datas/exception.txt > datas/prefix_result.txt
小数据
python prefix_Tree.py -i datas/head_exception_100.txt > datas/prefix_small_result.txt
'''
from __future__ import print_function
import numpy as np
import matplotlib.pyplot as plt
import argparse,code,time,bisect
import resource

flag_list=['x']
hex_str=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
class _IID:
    __slot__='iidstr'
    def __init__(self, IID):
        self.iidstr=IID
        assert(len(self.iidstr)==16)
    def get(self, index):
        assert(index >= 0 and index < 16)
        return self.iidstr[index]
def limit_memory(maxsize):
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))
def printJson(collection):
    stack=[[0, collection[0][2]]]
    indent=0
    moving_ahead=True
    while True:
        current_index, print_index = stack[-1][0], stack[-1][1]
        current_node = collection[current_index]
        if moving_ahead:
            print('{{\'prefix\':{}, \'count\':{}, \'children\':['.format(current_node[0], current_node[1]), end='')
        else:
            print(']}', end='')
        if print_index==current_node[3]+1 or print_index==0:
            stack.pop()
            indent-=1
            moving_ahead=False
        else:
            moving_ahead=True
            stack[-1][1]+=1
            indent+=1
            new_print=collection[print_index][2]
            stack.append([print_index, new_print])
        if len(stack)==0: break
def printTree(collection):
    stack=[[0, collection[0][2]]]
    indent=0
    moving_ahead=True
    while True:
        current_index, print_index = stack[-1][0], stack[-1][1]
        current_node = collection[current_index]
        if moving_ahead:
            print('\t'*indent, end='')
            print("{} '{}' {}".format(current_index, current_node[0], current_node[1]))
        if print_index==current_node[3]+1 or print_index==0:
            stack.pop()
            indent-=1
            moving_ahead=False
        else:
            moving_ahead=True
            stack[-1][1]+=1
            indent+=1
            new_print=collection[print_index][2]
            stack.append([print_index, new_print])
        if len(stack)==0: break
if __name__=='__main__':
    limit_memory(4*2**30)

    p=argparse.ArgumentParser()
    p.add_argument('--input','-i',type=str,help='filename with hex IPv6 addresses.')
    args=p.parse_args()
    IPs,IID=[],set()
    t0=time.time()
    for line in open(args.input,'r'):
        if line and line[0]!='#' and line[0]!='\n':
            IP=line[:-1]
            if IP[16:] in IID:
                continue
            IID.add(IP[16:])
            IPs.append(IP)
            #print(len(IPs))
    IP_count=len(IPs)
    IP_count=(float)(IP_count)
    print('input file {} size {}.'.format(args.input, IP_count))
    print('IP use {} seconds'.format(time.time() - t0))
    IPs=IPs[:]
    result=[]
    init_list=[]
    for IP in IPs:
        init_list.append(_IID(IP[16:]))
    result.append([0, init_list, 0, 0])
    t0,w_count=time.time(),0
    current=0
    while True:
        if current<len(result):
            prefix_len=result[current][0]
            IID_List=result[current][1]
            current+=1
            if type(prefix_len)==str: continue
            if len(IID_List)<=1 or prefix_len>=15:
                print('error')
                continue
            temp=[]
            for i in xrange(16):
                temp.append([prefix_len+1, [], 0, 0])
                #result.append([prefix_len+1, []])
            for IID_ in IID_List:
                index=int(IID_.get(prefix_len), 16)
                temp[index][1].append(IID_)
                #result[index-16][1].append(IID_)
            start,end=0,0
            for i in xrange(16):
                #L,pL=len(result[i-16][1]),result[i-16][0]
                L,pL=len(temp[i][1]),temp[i][0]
                if L > 0:
                    if L==1 or pL>=15:
                        temp[i][0],temp[i][1]=temp[i][1][0].iidstr[:pL],L
                    result.append(temp[i])
                    if start==0:
                        start=len(result)-1
                    end = len(result) - 1
            result[current-1][2]=start
            result[current-1][3]=end
            prefix=IID_List[0].iidstr[:prefix_len]
            result[current-1][0]=prefix
            result[current-1][1]=len(IID_List)
        else:
            break
        w_count+=1
        #if w_count%100000==0:
            #print('{} use {} seconds'.format(w_count, time.time() - t0))
    print('loop {} use {} seconds'.format(w_count, time.time() - t0))
    count_list=[0 for _ in xrange(16)]
    for i in result:
        pL=len(i[0])
        assert(pL>=0 and pL<16)
        count_list[pL]+=1
    prefix_count, min_percentage=100, 0.9
    result.sort(key=lambda x: len(x[0]) - x[1]/IP_count)
    prefix_segments=[]
    current, L = 0, 0
    while True:
        pL=len(result[current][0])
        if pL!=L:
            L=pL
            prefix_segments.append(current)
        current+=1
        if current==len(result): break
    L = 0
    while True:
        if count_list[L] > prefix_count: break
        L+=1
    print('min len is {}'.format(L))
    current=0
    while True:
        Len=len(result[current][0])
        if Len==L:
            break
        current+=1
    percentage=0.0
    for i in xrange(prefix_count):
        percentage+=result[current+i][1]/IP_count
    print('percentage is {}'.format(percentage))

    #result.sort(key=lambda x: len(x[0])-x[1]/16.0**(16-len(x[0])))
    #result.sort(key=lambda x: x[1]/16.0**(16-len(x[0]))/count_list[len(x[0])], reverse=True)
    #for index,i in enumerate(result):
    #print('{} \'{}\' {} {}-{} {}'.format(index, i[0], i[1], i[2], i[3], i[1]/16.0**(16-len(i[0]))))
    #for i in result:
    #    pL=len(i[0])
    #    density=i[1]/16.0**(16-pL)
    #    print('{} {} 密度={} 密度/个数={}'.format(i[0], i[1], density, density/count_list[pL]))
    
    code.interact(banner = "", local = locals())
    exit(1)
    