#coding:utf-8
'''
    * read
        build database
        python classify_PM.py --read ~/datas/2019-04-12/AS_result/9146.hex --save ~/datas/2019-04-12/AS_result/9146.db --distribution ~/datas/2019-04-12/AS_result/classify_result.txt
        * add into command
         
    * PM
        dig out which range of each class form
        * to do
    
'''
import argparse,time,sys,sqlite3,os
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
def build_DB(filename, DB, command, distribution_filename):
    # read IP from filename and write into DB IP
    # write command , start , end into DB   COMMANDS
    StartTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print('build DB {} based on {} at {}'.format(DB, filename, StartTime))
    t0=time.time()
    if os.path.exists(DB):
        os.remove(DB) #删除旧的数据
    connection = sqlite3.connect(DB)
    connection.executescript('DROP TABLE IF EXISTS IP;DROP TABLE IF EXISTS COMMANDS;')
    connection.executescript('create table IP (Address TEXT, Type TEXT, Tag INTEGER);create table COMMANDS (Command TEXT, StartTime TEXT, EndTime TEXT);')
    IP_count, lowbytes_count, eui64standard_count, eui64extended_count, rest_count=0,0,0,0,0
    OUIFile=raw_input('input OUI file:(default ./oui.txt)\n')
    OUIThreshold=raw_input('input non-standard OUI threshold:(default 2)\n')
    if OUIThreshold=='':
        OUIThreshold=2
    else:
        OUIThreshold=int(OUIThreshold)
    if OUIFile=='':
        OUIFile='oui.txt'
    initStandardOUIs(OUIFile)
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
                connection.execute('INSERT INTO IP VALUES (?,?,?);', (IP, TYPE_LOWBYTE, tagValue))
                lowbytes_count+=1
                continue
            if IP[22:26]=='fffe':
                OUI=reverseOUI(IP[16:22])
                if OUI in standardOUIs:
                    index_OUI=int(OUI, 16)
                    eui64standard_count+=1
                    connection.execute('INSERT INTO IP VALUES (?,?,?);', (IP, TYPE_EUI64, index_OUI))
                    continue
                if OUI in extendedOUIs:                
                    index_OUI=int(OUI, 16)
                    eui64extended_count+=1
                    connection.execute('INSERT INTO IP VALUES (?,?,?);', (IP, TYPE_EUI64, -index_OUI))
                    continue           
            rest_count+=1
            connection.execute('INSERT INTO IP VALUES (?,?,?);', (IP, TYPE_REST, -1))
    print('classify and insert use {} seconds'.format(time.time() - t0))
    #t1=time.time()
    #connection.execute('CREATE INDEX AINDEX ON IP(Address);')
    #print('Create Index use {} seconds'.format(time.time() - t0))
    EndTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection.execute('INSERT INTO COMMANDS VALUES (?,?,?);', (command, StartTime, EndTime))
    connection.commit()
    connection.close()
    if distribution_filename==None: return
    t0=time.time()
    f=open(distribution_filename,'w')
    f.write('total {}, lowbytes {}, eui64 {} {}, rest {}.\n'.format(\
        IP_count, lowbytes_count, eui64standard_count, eui64extended_count, rest_count))
    for k,v in OUIDistribution.items():
        if v>=OUIThreshold or k in standardOUIs:
            f.write('OUI {} count {}\n'.format(k, v))
    f.close()
    print('write to {} use {} seconds'.format(filename, time.time() - t0))

def classify_DB(DB, filename, command):
    #try classify every IP in DB and update it
    t0=time.time()
    StartTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection = sqlite3.connect(DB)
    IP_count=0
    lowbytes_count=0
    eui64standard_count,eui64extended_count=0,0
    c1=connection.cursor()
    OUIFile=raw_input('input OUI file:(default ./oui.txt)\n')
    OUIThreshold=raw_input('input non-standard OUI threshold:(default 2)\n')
    if OUIThreshold=='':
        OUIThreshold=2
    else:
        OUIThreshold=int(OUIThreshold)
    if OUIFile=='':
        OUIFile='oui.txt'
    initStandardOUIs(OUIFile)
    print('begin LOWBYTE judge after {} seconds'.format(time.time() - t0))
    t0=time.time()
    for item in connection.execute('SELECT Address FROM IP;'):
        IP=item[0]
        IP_count+=1
        if IP_count%10000==0:
            print('use {} seconds'.format(time.time() - t0))
        IsLB, tagValue = isLowBytes(IP)
        if IsLB:
            c1.execute('UPDATE IP SET Type=?, Tag=? WHERE Address=?;', (TYPE_LOWBYTE, tagValue, IP))
            lowbytes_count+=1
            continue
        if IP[22:26]=='fffe':
            OUI=reverseOUI(IP[16:22])
            if OUI not in OUIDistribution:
                OUIDistribution[OUI]=1
            else:
                OUIDistribution[OUI]+=1
    print('{} IP use {} seconds'.format(IP_count, time.time() - t0))
    t0=time.time()
    for k,v in OUIDistribution:
        if v>=OUIThreshold:
            extendedOUIs.append(k)
    for item in connection.execute('SELECT Address FROM IP WHERE Type!=\'{}\';'.format(TYPE_LOWBYTE)):
        IP=item[0]
        if IP[22:26]!='fffe': continue
        OUI=reverseOUI(IP[16:22])
        index_OUI=-1
        for i,OUI_ in enumerate(standardOUIs):
            if OUI_==OUI:
                index_OUI=i
                eui64standard_count+=1
                break
        if index_OUI!=-1:
            c1.execute('UPDATE IP SET Type=?, Tag=? WHERE Address=?;', (TYPE_EUI64, index_OUI, IP))
            continue
        index_OUI=-1
        for i,OUI_ in enumerate(extendedOUIs):
            if OUI_==OUI:
                index_OUI=i
                eui64extended_count+=1
                break
        if index_OUI!=-1:
            c1.execute('UPDATE IP SET Type=?, Tag=? WHERE Address=?;', (TYPE_EUI64, -1-index_OUI, IP))
            continue
    print('EUI judge use {} seconds'.format(time.time() - t0))
    t0=time.time()
    EndTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection.execute('INSERT INTO COMMANDS VALUES (?,?,?);', (command, StartTime, EndTime))
    connection.commit()
    connection.close()
    f=open(filename,'w')
    f.write('total {}, lowbytes {}, eui64 {} {}, rest {}.\n'.format(\
        IP_count, lowbytes_count, eui64standard_count, eui64extended_count, IP_count - lowbytes_count - eui64standard_count - eui64extended_count))
    for k,v in OUIDistribution.items():
        if v>=OUIThreshold or k in standardOUIs:
            f.write('OUI {} count {}\n'.format(k, v))
    f.close()
    print('write to {} use {} seconds'.format(filename, time.time() - t0))
if __name__=='__main__':

    parse=argparse.ArgumentParser()
    parse.add_argument('--read',type=str,help='input hex IPv6 addresses. # to comment \\n to split')
    parse.add_argument('--save',type=str,help='string of the save place')
    parse.add_argument('--classify',type=str,help='do classify on the given database')
    parse.add_argument('--distribution',type=str,help='filename ')
    args=parse.parse_args()
    full_command=' '.join(sys.argv)
    if args.read!=None and args.save!=None:
        build_DB(args.read, args.save, full_command, args.distribution)
    elif args.classify!=None and args.save!=None:
        classify_DB(args.classify, args.save, full_command)
    else:
        print('todo')