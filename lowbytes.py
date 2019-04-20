#coding:utf-8
'''
    lowbytes pattern ~ 2**32
    8|8
    4|4|4|4
    python lowbytes.py -i ~/datas/2019-04-12/AS_result/9146.hex
    python lowbytes.py -i ~/datas/2019-04-12/AS_result/6057.hex
    python lowbytes.py -i ~/datas/2019-04-12/AS_result/7922.hex
    
'''
import argparse,time
def pattern_match(IID, patterns, fix_bit):
    match_index=-1
    for index,pattern in enumerate(patterns):
        match_index=index
        for i,fix in enumerate(pattern):
            if fix=='0': continue
            for j in xrange(4):
                if not IID[j+i*4] in fix_bit:
                    match_index=-1
                    break
            if match_index==-1:
                break
        if match_index!=-1:
            return match_index
    return -1
if __name__=='__main__':

    parse=argparse.ArgumentParser()
    parse.add_argument('--input','-i',type=str,help='input hex IPv6 addresses. # to comment \\n to split')
    
    args=parse.parse_args()

    fix_bit=['0','f']
    patterns=['0011','1100','1001','0101','1010','0110'] #1 is fixed
    counts=[0]*6
    t0=time.time()
    count=0
    for line in open(args.input):
        if line and line[0]!='#':
            IP=line.strip()
            count+=1
            match_index=pattern_match(IP[16:], patterns, fix_bit)
            if match_index!=-1:
                counts[match_index]+=1
    print('{} use {} seconds'.format(count, time.time() - t0))
    for i,pattern in enumerate(patterns):
        print('{} {}'.format(pattern, counts[i]))