#coding:utf-8
'''
    使用LB EUI 进行分类
    * read
        build database
        python classify_PM.py --read ~/datas/2019-04-12/AS_result/9146.hex --save ~/datas/2019-04-12/AS_result/9146.db --distribution ~/datas/2019-04-12/AS_result/classify_result.txt
        python classify_PM.py --read ~/datas/2019-04-12/AS_result/6057.hex --save ~/datas/2019-04-12/AS_result/6057.db --distribution ~/datas/2019-04-12/AS_result/classify_6057.txt
        * add into command
    
    * focus
        extract specific type IP
        python classify_PM.py --EXTRACT --DB ~/datas/2019-04-12/AS_result/9146.db --Type LowBytes --Tag 20 --save ~/datas/2019-04-12/AS_result/9146_LB_20.hex
        python classify_PM.py --EXTRACT --DB ~/datas/2019-04-12/AS_result/9146.db --Type EUI64 --save ~/datas/2019-04-12/AS_result/9146_EUI.hex
        python classify_PM.py --EXTRACT --DB ~/datas/2019-04-12/AS_result/9146.db --Type REST --Tag -1 --save ~/datas/2019-04-12/AS_result/9146_REST.hex
        python classify_PM.py --EXTRACT --DB ~/datas/2019-04-12/AS_result/6057.db --Type LowBytes --Tag 2 --save ~/datas/2019-04-12/AS_result/6057_LB_2.hex
    * PM
        dig out which range of each class form
        * to do
        python classify_PM.py --file ~/datas/2019-04-12/AS_result/9146_LB_20.hex --save ~/datas/2019-04-12/AS_result/9146_LB_20_simple.hex
        python classify_PM.py --file ~/datas/2019-04-12/AS_result/6057_LB_2.hex --save ~/datas/2019-04-12/AS_result/6057_LB_2_simple.hex
        python classify_PM.py --file ~/datas/2019-04-12/AS_result/9146_EUI.hex --save ~/datas/2019-04-12/AS_result/9146_EUI_simple.hex
        python classify_PM.py --PM --DB ~/datas/2019-04-12/AS_result/9146.db --Type LowBytes --Tag 20 --save ~/datas/2019-04-12/AS_result/9146_LB_20_simple.hex
        python classify_PM.py --PM --DB ~/datas/2019-04-12/AS_result/9146.db --Type LowBytes --Tag 20 --save ~/datas/2019-04-12/AS_result/9146_LB_20_simple.hex > ~/datas/2019-04-12/AS_result/close_range.txt

'''
from __future__ import print_function
import argparse,time,sys,sqlite3,os,math,code
import numpy as np
from collections import deque
from datetime import datetime
standardOUIs, OUIDistribution=set(),{}
extendedOUIs=set()
bit_list=['0','f']
TYPE_LOWBYTE='LowBytes'
TYPE_EUI64='EUI64'
TYPE_REST='REST'
def initStandardOUIs(OUIFile):
    for line in open(OUIFile):
        if line and 'base 16' in line:
            OUI=line.split(' ')[0]
            standardOUIs.add(OUI.lower())
def reverse(x):
    assert(len(x)==1)
    v = int(x, 16)
    if v & 2 != 0:
        v-=2
    else:
        v+=2
    return hex(v)[-1]
def reverseOUI(OUI):
    return OUI[0]+reverse(OUI[1])+OUI[2:]
def isLowBytes(IP):
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
def convert_3(tagValue):
    #convert tagValue in isLowBytes to '0120' 4 digit in base 3
    ret=''
    for i in xrange(4):
        r=str(tagValue / (3**(3-i)) % 3)
        if r=='2': r='x'
        ret+=r
    return ret
def build_DB(filename, DB, command, distribution_filename):
    # read IP from filename and write into DB IP
    # write command , start , end into DB   COMMANDS
    StartTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print('\nbuild DB {} based on {} at {}'.format(DB, filename, StartTime))
    if os.path.exists(DB):
        os.remove(DB) #删除旧的数据
    connection = sqlite3.connect(DB)
    connection.executescript('DROP TABLE IF EXISTS IP;DROP TABLE IF EXISTS COMMANDS;')
    connection.executescript('create table IP (Prefix TEXT, IID TEXT, Type TEXT, Tag INTEGER);create table COMMANDS (Command TEXT, StartTime TEXT, EndTime TEXT);')
    IP_count, lowbytes_count, eui64standard_count, eui64extended_count, rest_count=0,0,0,0,0
    lowbytes_distribution={}
    OUIFile=raw_input('input OUI file:(default ./oui.txt)\n')
    OUIThreshold=raw_input('input non-standard OUI threshold:(default 2)\n')
    if OUIThreshold=='':
        OUIThreshold=2
    else:
        OUIThreshold=int(OUIThreshold)
    if OUIFile=='':
        OUIFile='oui.txt'
    initStandardOUIs(OUIFile)
    t0=time.time()
    print('start read {}'.format(filename))
    for line in open(filename):
        if line and line[0] != '#':
            IP=line.strip()
            if len(IP) != 32:
                print('{} is not a valid hex IP'.format(IP))
                continue
            IP_count+=1
            if IP[22:26]=='fffe':
                OUI=reverseOUI(IP[16:22])
                if OUI not in OUIDistribution:
                    OUIDistribution[OUI]=1
                else:
                    OUIDistribution[OUI]+=1
    print('scan {} IP use {} seconds'.format(IP_count, time.time() - t0))
    t0=time.time()
    for k,v in OUIDistribution.items():
        if v>=OUIThreshold:
            extendedOUIs.add(k)
    print('standard {}, extended {}'.format(len(standardOUIs), len(extendedOUIs)))
    print('start classify and insert')
    IP_count=0
    for line in open(filename):
        if line and line[0]!='#':
            IP=line.strip()
            if len(IP) != 32: continue
            IP_count+=1
            if IP_count%1000000==0:
                print('{} use {} seconds'.format(IP_count, time.time() - t0))
            IsLB, tagValue = isLowBytes(IP)
            if IsLB:
                connection.execute('INSERT INTO IP VALUES (?,?,?,?);', (IP[:16], IP[16:], TYPE_LOWBYTE, tagValue))
                lowbytes_count+=1
                if tagValue not in lowbytes_distribution:
                    lowbytes_distribution[tagValue] = 1
                else:
                    lowbytes_distribution[tagValue] += 1
                continue
            if IP[22:26]=='fffe':
                OUI=reverseOUI(IP[16:22])
                if OUI in standardOUIs:
                    index_OUI=int(OUI, 16)
                    eui64standard_count+=1
                    connection.execute('INSERT INTO IP VALUES (?,?,?,?);', (IP[:16], IP[16:], TYPE_EUI64, index_OUI))
                    continue
                if OUI in extendedOUIs:                
                    index_OUI=int(OUI, 16)
                    eui64extended_count+=1
                    connection.execute('INSERT INTO IP VALUES (?,?,?,?);', (IP[:16], IP[16:], TYPE_EUI64, -index_OUI))
                    continue           
            rest_count+=1
            connection.execute('INSERT INTO IP VALUES (?,?,?,?);', (IP[:16], IP[16:], TYPE_REST, -1))
    print('classify and insert use {} seconds'.format(time.time() - t0))
    EndTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection.execute('INSERT INTO COMMANDS VALUES (?,?,?);', (command, StartTime, EndTime))
    connection.commit()
    connection.close()
    if distribution_filename==None: return
    t0=time.time()
    f=open(distribution_filename,'w')
    f.write('total {}, lowbytes {}, eui64 {} {}, rest {}.\n'.format(\
        IP_count, lowbytes_count, eui64standard_count, eui64extended_count, rest_count))
    f.write('EUI distribution:\n')
    for k,v in OUIDistribution.items():
        if v>=OUIThreshold or k in standardOUIs:
            if k in standardOUIs: index_OUI=int(k, 16)
            else: index_OUI = -int(k, 16)
            f.write('OUI {} count {} index {}\n'.format(k, v, index_OUI))
    f.write('LowBytes distribution:\n')
    for k,v in lowbytes_distribution.items():
        type_=convert_3(k)
        f.write('LowBytes {} count {} tagValue {}\n'.format(type_, v, k))
    f.close()
    print('write to {} use {} seconds'.format(distribution_filename, time.time() - t0))
def extract(DB, Type, Tag, filename, command):
    if Type==TYPE_REST: Tag=-1
    StartTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection = sqlite3.connect(DB)
    t0=time.time()
    f=open(filename, 'w')
    if Tag!=None:
        for item in connection.execute('SELECT Prefix, IID FROM IP WHERE Type=? and Tag=? ORDER BY IID, Prefix;', (Type, Tag)):
            IP=item[0]+item[1]
            f.write(IP+'\n')
    else:
        for item in connection.execute('SELECT Prefix, IID FROM IP WHERE Type=? ORDER BY IID, Prefix;', (Type,)):
            IP=item[0] + item[1]
            f.write(IP+'\n')
    f.close()
    print('extract DB {} {} {} save to {} use {} seconds'.format(DB, Type, Tag, filename, time.time() - t0))
    EndTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection.execute('INSERT INTO COMMANDS VALUES (?,?,?);', (command, StartTime, EndTime))
    connection.commit()
    connection.close()
def entropy_oflist(li):
    entropy=0.0
    for prob in li:
        if prob != 0:
            entropy-=prob*math.log(prob)
    return entropy
def analyze(filename, save):
    IPs=[]
    for line in open(filename):
        if line and line[0]!='#':
            IP = line.strip()
            if len(IPs)==0 or IP[16:] != IPs[-1][16:]:
                IPs.append(IP)
    if save!=None:
        f=open(save,'w')
        for IP in IPs:
            f.write(IP[16:]+'\n')
        f.close()

    IIDs=[IP[16:] for IP in IPs]
    #points=[[int(IID[4:8],16),int(IID[12:16],16)] for IID in IIDs]
    points=[[int(IID[:6],16),int(IID[10:16],16)] for IID in IIDs]
    ID = [it[1] for it in points]
    '''
    A=[int(IID[4:8],16) for IID in IIDs]
    B=[int(IID[12:16],16) for IID in IIDs]
    for i in range(1, 5):
        retHigh=scan_clusters(A, i)
        print('4~8 distance {}, include {} / {}, {} range count.'.format(i, sum([item[2] for item in retHigh]), len(IPs), len(retHigh)))
    delta=[item[0] - item[1] for item in points]
    x=get_close_ranges(delta, 5)
    print(len(x))
    lengths = np.array([i[0] for i in x])
    for i in [2, 3, 4, 5, 6]:
        son=lengths[lengths >= i]
        s = sum(son)
        print('cluster count above {} include {} IP / {} IP, for {} pattern.'.format(i, s, len(IPs), len(son)))
    '''
    code.interact(banner = "", local = dict(globals(), **locals()))
def scan_clusters(array, dist, kind='int'):
    # scan continuous clusters
    # if array is not sorted, it is useless
    # dist 越大， cluster 数量越少， 包含的点越多
    result=[]
    i,count,current,start=0,0,array[0],array[0]
    j = 0
    while i < len(array):
        delta=array[i]-current if kind=='int' else int(array[i], 16) - int(current, 16)
        if i==0:
            count+=1
        elif delta>dist:
            #if count>1:
            result.append([j, i - 1, count])
            count=1
            start=array[i]
            j=i
        else:
            count+=1
        current=array[i]
        i+=1
    #if count>1:
    result.append([j, i - 1, count])
    #result.sort(key=lambda x:x[2], reverse=True)
    return result
def get_close_ranges(array, dist):
    '''
        最大值-最小值<=dist的所有最大子区间
        [count,left,right,min,Max]
    '''
    ret=[]
    L=len(array)
    i,j=0,0 #区间范围 [i,j]
    qmax,qmin=deque([0]),deque([0]) #
    while True:
        j+=1
        OMax,OMin = array[qmax[0]],array[qmin[0]]
        range_count=j - 1 - i + 1
        if j==L:
            ret.append([range_count, i, j - 1, OMin, OMax])
            break
        nvalue=array[j]
        #更新max,min
        while len(qmax) > 0 and array[qmax[-1]] <= nvalue:
            qmax.pop()
        qmax.append(j)
        while len(qmin) > 0 and array[qmin[-1]] >= nvalue:
            qmin.pop()
        qmin.append(j)
        #判断是否满足max-min<=dist
        Max,Min=array[qmax[0]],array[qmin[0]]
        if Max - Min <= dist:
        #是，继续扩大
            continue
        else:
        #否，输出当前；寻找下一个满足条件的i
            ret.append([range_count, i, j - 1, OMin, OMax])
            while True:
                if i == qmax[0]:
                    qmax.popleft()
                if i == qmin[0]:
                    qmin.popleft()
                i += 1
                Max,Min=array[qmax[0]],array[qmin[0]]
                if Max - Min <= dist: break
    def cross(a,b):
        return not (a[2] < b[1] or a[1] > b[2])
    i = 0
    remain=[True] * len(ret)
    while True:
        if i + 1 == len(ret): break
        next_=i+1
        while next_ < len(ret) and not remain[next_]: next_+=1
        if cross(ret[i], ret[next_]):
            #print('find cross: ({} {}-{} {}-{}),({} {}-{} {}-{})'.format(ret[i][0], ret[i][1], ret[i][2], ret[i][3], ret[i][4], ret[next_][0], ret[next_][1], ret[next_][2], ret[next_][3], ret[next_][4]))
            if ret[i][0] >= ret[next_][0]:
                remain[next_] = False
                continue
            else:
                remain[i] = False
                i = next_
                continue
        else:
            i = next_
    ret2 = []
    for i in xrange(len(ret)):
        if remain[i]: ret2.append(ret[i])
    return ret2
def concat(a, d):
    ret = []
    i = 0
    while True:
        if i+1>=len(a): return ret
        current=a[i]
        if current[2] + d >= a[i+1][1]:
            while i+1<len(a) and current[2] + d >= a[i+1][1]:
                current[0] += a[i+1][0]
                current[2] = a[i+1][2]
                current[3] = min(current[3], a[i+1][3])
                current[4] = max(current[4], a[i+1][4])
                i+=1
            ret.append(current)
            i+=1
        else:
            ret.append(a[i])
            i+=1
def get_valid_clusters(array, distance, kind, th1):
    valid_clusters, valid_count = [], 0
    clusters = scan_clusters(array, distance, kind)
    for cluster in clusters:
        cnt = (float)(cluster[2])
        if cnt >= th1:
            valid_clusters.append(cluster)
            valid_count += cnt
    return valid_clusters, valid_count
def get_valid_close_ranges(array, distance, threshold):
    valid_clusters, valid_count = [], 0
    clusters = get_close_ranges(array, distance)
    for cluster in clusters:
        cnt = (float)(cluster[0])
        if cnt >= threshold:
            valid_clusters.append(cluster)
            valid_count += cnt
    return valid_clusters, valid_count
def get_most_range(data, rsize):
    ret=[]
    sorted_data=sorted(data)
    i = 1
    current = sorted_data[0]
    count = 1
    while True:
        if i >= len(data): break
        if sorted_data[i] != current:
            ret.append([count, current])
            current = sorted_data[i]
            count = 1
        else:
            count += 1
        i+=1
    i = 0
    res=[]
    maxR=[0]
    while i < len(ret):
        count = 0
        j = i
        while j < len(ret) and (ret[j][1] - ret[i][1]) <= rsize:
            count += ret[j][0]
            j += 1
        newRange=[count, ret[i][1], ret[i][1] + rsize]
        res.append(newRange)
        if count > maxR[0]:
            maxR=newRange
        i+=1
    return maxR
def LowBytes_PM(DB, Type, Tag):
    t0=time.time()
    connection = sqlite3.connect(DB)
    if Tag == 20:
        # '0202'
        # 3seg prefix, part1, part2
        prefix, A, B = [], [], []
        countAll = connection.execute('SELECT COUNT(*) FROM IP WHERE Type = ? AND Tag = ?;', (Type, Tag)).fetchone()[0]
        print(countAll)
        if countAll < 3e7: # 10M IP
            for item_ in connection.execute('SELECT DISTINCT IID FROM IP WHERE Type = ? AND Tag = ? ORDER BY IID;', (Type, Tag)):
                iid = item_[0]
                A.append(iid[4:8])
                B.append(iid[12:16])
        else:
            print('too much to load in memory: {}'.format(countAll))
            return
        countDistinct = len(A)

        values = [(int(A[i], 16) << 16) + int(B[i], 16) for i in xrange(countDistinct)]
        for distance in [1, 5, 10, 100]:
            valid_clusters, valid_count = get_valid_clusters(values, distance, 'int', 0.02 * countDistinct)
            pattern_count, percent = len(valid_clusters), valid_count / countDistinct
            print('distance {} for A,B find {} patterns, include {} '.format(distance, pattern_count, percent))
            if valid_count / countAll >= 0.40:
                break
        values = [int(A[i], 16) + (int(B[i], 16) << 16) for i in xrange(countDistinct)]
        values.sort()
        for distance in [1, 5, 10, 100]:
            valid_clusters, valid_count = get_valid_clusters(values, distance, 'int', 0.02 * countDistinct)
            pattern_count, percent = len(valid_clusters), valid_count / countDistinct
            print('distance {} for B,A find {} patterns, include {} '.format(distance, pattern_count, percent))
            if valid_count / countAll >= 0.40:
                break
        
        values = [int(i, 16) for i in A]
        for distance in [1, 5, 10, 100]:
            valid_clusters, valid_count = get_valid_clusters(values, distance, 'int', 0.02 * countDistinct)
            pattern_count, percent = len(valid_clusters), valid_count / countDistinct
            print('distance {} for A find {} patterns, include {} '.format(distance, pattern_count, percent))
            if valid_count / countAll >= 0.40:
                break
        
        for cluster in valid_clusters:
            begin, end = cluster[0], cluster[1]
            data = [int(B[i], 16) - int(A[i], 16) for i in range(begin, end + 1)]
            for distance in [1, 5, 10, 100]:
                maxRange = get_most_range(data, distance)
                count, percent = maxRange[0], (float)(maxRange[0]) / len(data)
                print('range size {}, {}-{} include {}, {}'.format(distance, maxRange[1], maxRange[2], count, percent))
        print('use {} seconds'.format(time.time() - t0))
        code.interact(banner = "", local = dict(globals(), **locals()))
    elif Tag == 0:
        # '0000'
        print(Tag)
    elif Tag == 2:
        # '0002'
        print(Tag)
    elif Tag == 8:
        # 0022
        print(Tag)
    elif Tag == 18:
        # 0200
        print(Tag)
    else:
        print('LB Tag is {}'.format(Tag))
    connection.commit()
    connection.close()
def pattern_mining(DB, Type, Tag):
    #connection = sqlite3.connect(DB)
    print('pm')
    if Type == TYPE_LOWBYTE:
        LowBytes_PM(DB, Type, Tag)
       
if __name__=='__main__':

    parse=argparse.ArgumentParser()
    parse.add_argument('--read',type=str,help='input hex IPv6 addresses. # to comment \\n to split')
    parse.add_argument('--file',type=str,help='file to analyze')
    parse.add_argument('--Type',type=str,help='Type: LowBytes|EUI64|REST')
    parse.add_argument('--Tag',type=int,help='TagValue')
    parse.add_argument('--save',type=str,help='string of the save place')
    parse.add_argument('--DB',type=str,help='the given database')
    parse.add_argument('--distribution',type=str,help='filename ')
    parse.add_argument('--PM',action='store_true',help='pattern mining')
    parse.add_argument('--EXTRACT',action='store_true',help='pattern mining')
    args=parse.parse_args()
    full_command=' '.join(sys.argv)
    if args.read!=None and args.save!=None:
        build_DB(args.read, args.save, full_command, args.distribution)
    elif args.EXTRACT and args.DB!=None and args.Type!=None and args.save!=None:
        extract(args.DB, args.Type, args.Tag, args.save, full_command)
    elif args.file != None :
        analyze(args.file, args.save)
    elif args.PM:
        pattern_mining(args.DB, args.Type, args.Tag)