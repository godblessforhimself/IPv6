#coding: utf-8
# python test.py --read ~/datas/2019-04-12/AS_result/9146_REST.hex
from __future__ import print_function
from collections import deque
import argparse, code, time, math
def get_distribution(IPs, skip=None):
    assert(len(IPs) > 0)
    distribution = []
    for i in xrange(32):
        distribution.append([0] * 16)
    pattern = ''
    length = 0 # x count
    if skip == None:
        for IP in IPs:
            for i, s in enumerate(IP):
                j = int(s, 16)
                distribution[i][j] += 1
        j_ = 0
        for i in xrange(32):
            nonzerocount = 0
            for j in xrange(16):
                if distribution[i][j] != 0:
                    nonzerocount += 1
                    j_ = j
            if nonzerocount > 1:
                length += 1
                pattern += 'x'
            else:
                pattern += hex(j_)[-1]
    else:
        checkindex=[]
        for i, v in enumerate(skip):
            if v == 'x':
                checkindex.append(i)
                length += 1
        for IP in IPs:
            for index in checkindex:
                j = int(IP[index], 16)
                distribution[index][j] += 1
        for i in xrange(32):
            if skip[i] != 'x':
                pattern += skip[i]
            else:
                nonzerocount = 0
                for j in xrange(16):
                    if distribution[i][j] != 0:
                        nonzerocount += 1
                        j_ = j
                if nonzerocount > 1:
                    pattern += 'x'
                else:
                    pattern += hex(j_)[-1]
                    length -= 1
    return distribution, pattern, length
def get_top_value(distribution, N):
    i_, j_ = -1, -1
    maxn = 0
    for i in xrange(32):
        for j in xrange(16):
            if distribution[i][j] < N and distribution[i][j] >= maxn:
                i_, j_ = i, j
                maxn = distribution[i][j]
    return i_, j_, maxn
def simple_init(A, B, IPs):
    A.append(IPs)
    distribution, pattern, length = get_distribution(IPs)
    density = len(IPs) / (float)(16**length)
    i_, j_, maxn = get_top_value(distribution, len(IPs))
    B.append([0, length, density, pattern, i_, j_, maxn])
    return
def splitIPs(IPs, i_, j_):
    newIPs, oldIPs = [], []
    for IP in IPs:
        if int(IP[i_], 16) == j_:
            newIPs.append(IP)
        else:
            oldIPs.append(IP)
    return oldIPs, newIPs
def calculate_entropy(distribution, column):
    total = 0.0
    for j in xrange(16):
        total += distribution[column][j]
    ret = 0.0
    for j in xrange(16):
        prob = distribution[column][j] / total
        if prob > 0:
            ret -= math.log(prob) * prob
    return ret
def iteration(A, B, C):
    index = B[0][0]
    skip = B[0][3]
    IPs = A[index]
    IP_count = len(IPs)
    oldL = B[0][1]
    i_, j_, maxn = B[0][4], B[0][5], B[0][6]
    #print('maxn {}'.format(maxn))
    if maxn <= 1: return False
    # find best hex at most 20 times
    loop_count, loop_limit = 0, 1
    if len(IPs) == 1:
        code.interact(banner = "out", local = dict(globals(), **locals()))
        exit(0)
    while True:
        #split to two parts
        IPs, newIPs = splitIPs(IPs, i_, j_)
        #prepare data for B
        newdistribution, newpattern, newlength = get_distribution(newIPs, skip)
        newi, newj, newmaxn = get_top_value(newdistribution, len(newIPs))
        olddistribution, oldpattern, oldlength = get_distribution(IPs, skip)
        i_, j_, oldmaxn = get_top_value(olddistribution, len(IPs))
        newdensity, olddensity = len(newIPs) / (float)(16**newlength), len(IPs) / (float)(16**oldlength)
        
        #update A
        A[index] = IPs
        A.append(newIPs)
        #update B
        newitem = [len(A) - 1, newlength, newdensity, newpattern, newi, newj, newmaxn]
        if newmaxn > 1:
            B.append(newitem)
        elif newmaxn <= 1 and len(newIPs) > 1:
            C.append(newitem)

        olditem = [index, oldlength, olddensity, oldpattern, i_, j_, oldmaxn]
        remain = False
        IP_count_ = len(IPs)
        if oldmaxn > 1 and IP_count_ > 1:
            # 保留
            remain = True
            B[0] = olditem
        elif oldmaxn <= 1 and IP_count_ > 1:
            # 存储结果
            C.append(olditem)
            B.popleft()
            break
        elif IP_count_ <= 1 or oldmaxn <= 1:
            # 舍弃
            B.popleft()
            break
        else:
            print('else {} IP count {}'.format(oldmaxn, len(IPs)))
            code.interact(banner = "", local = dict(globals(), **locals()))
        if oldlength < oldL:
            break
        loop_count += 1
        if loop_count >= loop_limit:
            # find low entropy hex
            varis=[]
            for i in xrange(32):
                if oldpattern[i] == 'x':
                    varis.append(i)
            min_entropy, index_ = float("inf"), -1
            for i in varis:
                entropy = calculate_entropy(olddistribution, i)
                if entropy < min_entropy:
                    min_entropy = entropy
                    index_ = i
            tempIPs=[]
            for i in xrange(16):
                tempIPs.append([])
            for IP in IPs:
                i = int(IP[index_], 16)
                tempIPs[i].append(IP)
            for IPs in tempIPs:
                count_ = len(IPs)
                if count_ == 0: continue
                skip = oldpattern[:index_] + IPs[0][index_] + oldpattern[index_+1:]
                distribution, pattern, length = get_distribution(IPs, skip)
                i_, j_, maxn = get_top_value(distribution, count_)
                A.append(IPs)
                item = [len(A) - 1, length, count_ / (16.0**length), pattern, i_, j_, maxn]
                if maxn > 1 and count_ > 1:
                    B.append(item)
                elif maxn <= 1 and count_ > 1:
                    C.append(item)
            B.popleft()
            print('loop count {}'.format(loop_count))
            #code.interact(banner = "", local = dict(globals(), **locals()))
            break
    return True
def PM(IPs, budget):
    A,B,C=[],deque(),[]
    simple_init(A, B, IPs)
    t0 = time.time()
    lpct = 0
    while True:
        #ranges=sum([16**item[1] for item in B])
        #if ranges < budget: break
        if len(B) == 0:
            break
        if not iteration(A, B, C):
            break
        lpct += 1
        if lpct % 1000 == 0:
            print('{} use {} seconds'.format(lpct, time.time() - t0))
            #t0= time.time()
        #code.interact(banner = "", local = dict(globals(), **locals()))
    print('{} use {} seconds'.format(lpct, time.time() - t0))
    code.interact(banner = "", local = dict(globals(), **locals()))
def addupPattern(PatternList):
    currentPattern = ''
    count=0
    ret = []
    for pattern in PatternList:
        if currentPattern == '':
            currentPattern = pattern
            count = 1
        else:
            if currentPattern != pattern:
                ret.append([count, currentPattern])
                currentPattern = pattern
                count = 1
            else:
                count += 1
    ret.append([count, currentPattern])
    return ret
def hexDistribution(IPs, index):
    ret={}
    for IP in IPs:
        s=IP[index]
        if s not in ret:
            ret[s] = 1
        else:
            ret[s] += 1
    retList = []
    for k, v in ret.items():
        retList.append([v, k])
    return retList
def Pattern_Finding(IPs, Length):
    Total = len(IPs)
    t0 = time.time()
    simple_pattern=''
    for index in xrange(32):
        hexDis = hexDistribution(IPs, index)
        if len(hexDis) == 1:
            simple_pattern += hexDis[0][1]
        else:
            simple_pattern += 'x'
    print(simple_pattern)
    print('use {} seconds'.format(time.time() - t0))
    t0 = time.time()
    Record = []
    for i in range(0, 32 - Length + 1):
        skipFlag=False
        for index in range(i, i + Length):
            if simple_pattern[index] != 'x':
                skipFlag = True
                continue
        if skipFlag: continue
        PatternList = []
        for IP in IPs:
            PatternList.append(IP[i: i + Length])
        PatternList.sort()
        Patterns = addupPattern(PatternList)
        Patterns.sort(key=lambda x:x[0],reverse=True)
        print('range [{},{}]'.format(i, i+Length-1))
        for item in Patterns:
            print('pattern: {}, count: {}, percent: {}'.format(item[1], item[0], item[0] / (float)(Total)))
        if i == 8:
            Record = Patterns
    print('use {} seconds'.format(time.time() - t0))
    newIPs=[]
    for i in xrange(len(Record)):
        newIPs.append([])
    for IP in IPs:
        for index_,item in enumerate(Record):
            pattern_ = item[1]
            if IP[i:i+Length] == pattern_:
                newIPs[i].append(IP)

if __name__=='__main__':
    parse=argparse.ArgumentParser()
    parse.add_argument('--read',type=str,help='input hex IPv6 . # to comment \\n to split')
    args=parse.parse_args()

    IPs=[]
    t0=time.time()
    for line in open(args.read):
        if line and line[0]!='#':
            IP=line.strip()
            IPs.append(IP)
    print('read {} IP use {} seconds'.format(len(IPs), time.time() - t0))
    #PM(IPs, 100000)
    Pattern_Finding(IPs, 8)