#coding: utf-8

# python patternMining.py --read [filename] --write [filename] --budgets [budgetlist] --depth [depth] --experience=[True/False]
from __future__ import print_function
from collections import deque
import argparse, code, time, math, resource
bit_list=['0','f']
def isLowBytes(IP):
    # 返回是LB，LB的类型
    compress=[]
    count=0
    for i in xrange(4):
        former_f=IP[16+i*4]
        bit_=former_f
        for j in xrange(4):
            f=IP[16+i*4+j]
            if f not in bit_list:
                bit_='2'
                break
            elif j!=0:
                if f!=former_f:
                    bit_='2'
                    break
        if bit_=='0':
            compress.append('0')
            count+=1
        elif bit_=='f':
            compress.append('1')
            count+=1
        elif bit_=='2':
            compress.append('2')
    tagvalue=int(''.join(compress), 3)
    return (count>=2), tagvalue

def reverseOUI(OUI):
    v = int(OUI[1], 16)
    if v & 2 != 0: v-=2
    else: v+=2
    return OUI[0]+hex(v)[-1]+OUI[2:]

EUIbegin, EUIend, EUIfffe = 22, 26, 'fffe'
OUIbegin, OUIend = 16, 22
def isEUI(IP, EUIdist, OUIs, threshold = 2):
    if IP[EUIbegin : EUIend] != EUIfffe: return False
    OUI_unprocessed = IP[OUIbegin : OUIend]
    OUI_processed = reverseOUI(OUI_unprocessed)
    if OUI_unprocessed not in EUIdist and OUI_processed not in OUIs: 
        return False
    elif OUI_processed not in OUIs and OUI_unprocessed in EUIdist and EUIdist[OUI_unprocessed] < threshold: 
        return False
    return True
def init_EUI_dist(IPs, EUIdist):
    for IP in IPs:
        if IP[EUIbegin : EUIend] == EUIfffe:
            OUI_unprocessed = IP[OUIbegin : OUIend]
            if OUI_unprocessed not in EUIdist:
                EUIdist[OUI_unprocessed] = 1
            else:
                EUIdist[OUI_unprocessed] += 1
def read_OUIFile(OUIFile):
    ret = set()
    for line in open(OUIFile):
        if line and 'base 16' in line:
            OUI=line.split(' ')[0]
            ret.add(OUI.lower())
    return ret

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
def getPattern(IPs):
    if len(IPs) == 1:
        return IPs[0], 32
    pattern, fixLength = '', 0
    for i in xrange(32):
        hexDist = hexDistribution(IPs, i)
        if len(hexDist) == 1:
            pattern += hexDist[0][1]
            fixLength += 1
        else:
            pattern += 'x'
    return pattern, fixLength
def getRange(pattern):
    varLength = sum([1 if i == 'x' else 0 for i in pattern])
    return 16 ** varLength
def getEntropy(problist):
    entropy = 0.0
    for prob in problist:
        if prob != 0:
            entropy -= prob * math.log(prob)
    return entropy
def findMaxLength(pattern, limit = 4):
    def findNext(pattern, begin):
        pos = str.find(pattern, 'x', begin)
        beg = pos
        while pos + 1 < 32 and pattern[pos + 1] == 'x':
            pos += 1
        return beg, pos
    temp = []
    begin = 0
    while True:
        beg, end = findNext(pattern, begin)
        if beg == -1: break
        temp.append([beg, end - beg + 1])
        begin = end + 1
    temp.sort(key=lambda item: item[1], reverse=True)
    Length = min(temp[0][1], limit)
    ret = []
    for item in temp:
        if item[1] > Length: 
            for i in xrange(item[1] - Length + 1):
                ret.append(item[0] + i)
            continue
        if item[1] < Length: break
        ret.append(item[0])
    return ret, Length
def get_pattern_count(patterns):
    ret = []
    p, count = '', 0
    for pattern in patterns:
        if p == '':
            p = pattern
            count = 1
        else:
            if p == pattern:
                count += 1
            else:
                ret.append([p, count])
                p = pattern
                count = 1
    ret.append([p, count])
    return ret
def findBestBegin(IPs, begins, length):
    # 统计每个区间的熵
    Total = (float)(len(IPs))
    best_begin = -1
    best_entropy = float('inf')
    best_patterns = []
    for begin in begins:
        patterns_ = []
        for IP in IPs:
            string = IP[begin: begin+length]
            patterns_.append(string)
        patterns_.sort()
        pattern_count = get_pattern_count(patterns_)
        problist = []
        for p_c in pattern_count:
            problist.append(p_c[1] / Total)
        entropy = getEntropy(problist)
        if entropy < best_entropy:
            best_entropy = entropy
            best_patterns = pattern_count
            best_begin = begin
    #best_patterns.sort(key=lambda item: item[1], reverse = True)
    pattern_Index = {}
    current_ = 0
    pcount = 0
    for v in best_patterns:
        if v[1] <= 1:
            pattern_Index[v[0]] = -1
            current_ -= 1
        else:
            pattern_Index[v[0]] = current_
            pcount += 1
        current_ += 1
    return best_begin, pattern_Index, pcount
def expand(item, buckets, currentRange):
    IPs = item[0]
    currentPattern = item[1]
    #print('expanding {}'.format(currentPattern))
    varLength = sum([1 if i == 'x' else 0 for i in currentPattern])
    deRange = 16 ** varLength
    currentRange -= deRange
    # 待展开项过小
    if len(IPs) < 2:
        return currentRange, True
    inRange = 0
    # 计算Len最长的可选位置
    if varLength >= 16:
        limit = 4
    elif varLength >= 8:
        limit = 2
    else:
        limit = 1
    limit = 1
    array, maxLength = findMaxLength(currentPattern, limit)
    #print('findMaxLength result {} {}'.format(array, maxLength))
    bestBegin, patternIndex, patternCount = findBestBegin(IPs, array, maxLength)
    # [bestBegin, bestBegin + maxLength - 1]
    splitIPs = []
    singleIPs = []
    for i in xrange(patternCount):
        splitIPs.append([])
    for IP in IPs:
        segment = IP[bestBegin: bestBegin + maxLength]
        index = patternIndex[segment]
        if index >= 0:
            splitIPs[index].append(IP)
        else:
            singleIPs.append(IP)
    for arr in splitIPs:
        pattern, length = getPattern(arr)
        inRange += 16 ** (32 - length)
        buckets[length].append([arr, pattern])
    if len(singleIPs) > 0:
        #print('singleIPs {} add'.format(len(singleIPs)))
        buckets[-1].extend(singleIPs)
    currentRange += inRange
    return currentRange, False

def expandPattern(pattern):
    varLength = sum([1 if i == 'x' else 0 for i in pattern])
    total = 16 ** varLength
    IPs = []
    i = 0
    while True:
        if i >= total:
            raise StopIteration
        hexstr = hex(i)[2:]
        hexstr = '0' * (varLength - len(hexstr)) + hexstr
        IP = ''
        index = 0
        for j in xrange(32):
            if pattern[j] == 'x':
                IP += hexstr[index]
                index += 1
            else:
                IP += pattern[j]
        yield IP
        i += 1
'''
def expandPattern(pattern):
    varLength = sum([1 if i == 'x' else 0 for i in pattern])
    total = 16 ** varLength
    IPs = []
    t0 = time.time()
    for i in xrange(total):
        hexstr = hex(i)[2:]
        hexstr = '0' * (varLength - len(hexstr)) + hexstr
        IP = ''
        index = 0
        for j in xrange(32):
            if pattern[j] == 'x':
                IP += hexstr[index]
                index += 1
            else:
                IP += pattern[j]
        IPs.append(IP)
    #print('expanding {} {} use {} seconds'.format(pattern, varLength, time.time() - t0))
    return IPs
'''

def splitUsingExperience(IPs, filename='oui.txt'):
    LB, EUI, Other = [], [], []
    EUIdist = {}
    init_EUI_dist(IPs, EUIdist)
    OUIs = read_OUIFile(filename)
    for IP in IPs:
        if isLowBytes(IP)[0]:
            LB.append(IP)
        elif isEUI(IP, EUIdist, OUIs, 2):
            EUI.append(IP)
        else:
            Other.append(IP)
    return [LB, EUI, Other]

def target_gen(TargetList, buckets):
    for i, bucket in enumerate(buckets):
        if i == 33: break
        for item in bucket:
            pattern = item[1]
            count_ = len(item[0])
            if count_ <= 1: continue
            density = (float)(count_) / getRange(pattern)
            TargetList.append([density, pattern])
    TargetList.sort(key = lambda item: item[0], reverse=True)

def predict(filename, budget, TargetList):
    print('=============\npredict for {} at budget {}'.format(filename, budget))
    f=open(filename, 'w')
    f2=open(filename+'.pattern', 'w')
    writecount = 0
    for item in TargetList:
        pattern = item[1]
        print(pattern)
        f2.write('{} {}\n'.format(pattern, item[0]))
        for IP in expandPattern(pattern):
            f.write(IP+'\n')
            writecount+=1
            if writecount > budget:
                break
        if writecount > budget:
            break
    f.close()
    f2.close()
    print('============')

def limit_memory(maxsize):
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

def process(IPs, budgets, depth, filename, prior_experience=False):
    # depth 展开到多少位
    budgets.sort(reverse=True)
    budget_index = 0
    budget = budgets[budget_index]
    buckets = []
    for i in xrange(33):
        buckets.append(deque())
    buckets.append([])
    if prior_experience:
        t0 = time.time()
        split_IPs = splitUsingExperience(IPs)
        currentBucket = 34
        currentRange = 0
        for IPList in split_IPs:
            currentPattern, fixLength = getPattern(IPList)
            buckets[fixLength].append([IPList, currentPattern])
            currentRange += 16 ** (32 - fixLength)
            if currentBucket > fixLength:
                currentBucket = fixLength
            print('pattern {}, fixlength {}, include {} IPs'.format(currentPattern, fixLength, len(IPList)))
        print('using experience {} seconds'.format(time.time() - t0))
    else:
        currentPattern, fixLength = getPattern(IPs)
        buckets[fixLength].append([IPs, currentPattern])
        currentRange = 16 ** (32 - fixLength)
        currentBucket = fixLength
        print('no experience {} {}'.format(currentPattern, fixLength))
    t0=time.time()
    changed_flag = True
    while True:
        # 展开 结束条件： currentRange < budget || currentBucket >= 32
        if currentRange < budget:
            print('Range {} < budget {}'.format(currentRange, budget))
            if changed_flag:
                #print('changed')
                TargetList=[]
                target_gen(TargetList, buckets)
            changed_flag = False
            predict(filename + '.' + str(budget), budget, TargetList)
            budget_index += 1
            if budget_index >= len(budgets):
                #code.interact(banner = "", local = dict(globals(), **locals()))
                return
            budget = budgets[budget_index]
            continue
        if currentBucket >= 32 - depth:
            print('Bucket {}'.format(currentBucket))
            break
        bucketCount = len(buckets[currentBucket])
        if bucketCount == 0:
            currentBucket += 1
            time_cost = time.time() - t0
            if time_cost > 1:
                print('{} use {} seconds'.format(currentBucket, time_cost))
            t0 = time.time()
        else:
            currentRange, skipped = expand(buckets[currentBucket][0], buckets, currentRange)
            changed_flag = True
            removed = buckets[currentBucket].popleft()
            if skipped:
                singleIP = removed[0]
                buckets[-1].extend(singleIP)
                #print('singleIP add {}'.format(singleIP))
    if budget_index >= len(budgets):
        #code.interact(banner = "", local = dict(globals(), **locals()))
        return
    TargetList=[]
    target_gen(TargetList, buckets)
    for i in range(budget_index, len(budgets)):
        budget = budgets[i]
        predict(filename+'.'+str(budget), budget, TargetList)
    #code.interact(banner = "", local = dict(globals(), **locals()))

if __name__=='__main__':
    limit_memory(4*2**30)
    parse=argparse.ArgumentParser()
    parse.add_argument('--read',type=str,help='input hex IPv6 . # to comment \\n to split')
    parse.add_argument('--budgets',type=int,nargs='+',help='input budget list')
    parse.add_argument('--depth',type=int,default=4,help='input budget')
    parse.add_argument('--write',type=str,help='input hex IPv6 . # to comment \\n to split')
    parse.add_argument('--experience',type=str,help='True:use LB and EUI64, False: simple one.')
    args=parse.parse_args()
    remain_count = 10000000

    IPs=[]
    t0=time.time()
    count_ = 0
    for line in open(args.read):
        if line and line[0]!='#':
            IP=line.strip()
            count_ += 1
            if count_ < remain_count:
                IPs.append(IP)
            else:
                break
    print('read {} IP use {} seconds'.format(len(IPs), time.time() - t0))

    t0=time.time()
    process(IPs, args.budgets, args.depth, args.write, (args.experience == 'True'))
    print('total use {} seconds'.format(time.time() - t0))






