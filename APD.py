#coding:utf-8
'''
    APD别名前缀消除
    数据库两个表
    prefix
    predictIP
    1.前缀提取
        range threshold
        /32-/96 = 16
        python APD.py -i responsive-addresses.txt -db APD_db1.db -extract
        python APD.py -i ~/Downloads/2018-08-01-input.txt -db APD_db1.db -extract
        python APD.py -i datas/IP_100000_for_APD.txt -db APD_db.db -t 10 -extract > datas/APD_prefix.txt
        建立表prefixTable
        输出standardprefix
    2.随机地址生成 build prefix & predict database compress IP to int
        prefix file
        python APD.py -db APD_db.db -generate -t 10 > datas/APD_scanTargetHex.txt
        建表predictTable
        输出预测目标
cat APD_scanTargetHex.txt|ipv6-hex2addr > APD_scanTarget.txt
sudo zmap --ipv6-target-file=APD_scanTarget.txt -B 10M --ipv6-source-ip=2402:f000:9:8401:487d:379f:270a:1760 -M icmp6_echoscan -f saddr,daddr,ipid,ttl,timestamp_str -O json -o APD_scanResult.txt
    3.结果统计
        一行是一个响应ip
        哪些前缀的响应率为100%
        python APD.py -statistics -i datas/APD_scanResult.txt -db APD_db.db > datas/APD_alias_prefix.txt
        输出16个响应的前缀
    4.前缀响应分布比例 直方图 + 饼图
        python APD.py -db APD_db.db -draw
'''
import argparse,code,sqlite3,random,json,time
hex_list=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
def get_rawIP(IP):
    seglist=IP.split(':')
    if seglist[0]=='':
        seglist.pop(0)
    if seglist[-1]=='':
        seglist.pop()
    sup=8-len(seglist)
    if '' in seglist:
        sup+=1
    ret=[]
    for i in seglist:
        if i=='':
            for j in range(0,sup):
                ret.append('0'*4)
        else:
            ret.append('{:0>4}'.format(i))
    rawIP=''.join(ret)
    assert(len(rawIP)==32)
    return rawIP
def get_standardPrefix(prefix):
    length=len(prefix)
    return ':'.join([prefix[i:i+4] for i in range(0,length,4)])+'::/'+str(length*4)
def generateTargets(prefix):
    length=len(prefix)
    comp_len=32-length-1
    # 32=length+1+()
    ret=[]
    for i in range(0,16):
        target=prefix+hex_list[i]
        for _ in xrange(comp_len):
            target+=hex_list[random.randint(0,15)]
        ret.append(target)
        assert(len(target)==32)
    return ret
if __name__=='__main__':
    parse=argparse.ArgumentParser()
    parse.add_argument('--input','-i',type=str,help='input IPv6 addresses. # to comment \\n to split. or dbfile or prefix file')
    parse.add_argument('--database','-db',type=str,help='output database name')
    parse.add_argument('-extract', action='store_true', help='extract prefix to db file')
    parse.add_argument('--threshold','-t',default=100,type=int,help='threshold, min prefix count')
    parse.add_argument('--begin','-b',default=64,type=int,help='prefix range')
    parse.add_argument('--end','-e',default=124,type=int,help='prefix range')
    parse.add_argument('-generate', action='store_true', help='read prefix from input or database.')
    
    parse.add_argument('-statistics', action='store_true', help='execute result analysis')
    parse.add_argument('-draw', action='store_true', help='histogram')
    args=parse.parse_args()

    prefixTable='prefixTable'
    predictTable='predictTable'

    if args.extract:
        t0,IP_count=time.time(),0
        begin,end,threshold=args.begin,args.end,args.threshold
        # create new database
        connection=sqlite3.connect(args.database)
        connection.execute('DROP TABLE IF EXISTS {};'.format(prefixTable))
        connection.execute('create table {} (prefix TEXT primary key, count INTEGER DEFAULT 0, response_count INTEGER);'.format(prefixTable))
        c1,c2=connection.cursor(),connection.cursor()
        for line in open(args.input,'r'):
            if line and line[0]!='#':
                IP=line[:-1]
                raw_IP=get_rawIP(IP)
                IP_count+=1
                if IP_count%100000==0:
                    print('{} {} seconds'.format(IP_count, time.time()-t0))
                for i in range(begin/4,end/4+1):
                    prefix=raw_IP[:i]
                    if c1.execute('select * from {} where prefix=?;'.format(prefixTable),(prefix,)).fetchone()!=None:
                        c2.execute('update {} set count=count+1 where prefix=?;'.format(prefixTable),(prefix,))
                    else:
                        c1.execute('insert into {} values(?,0,0);'.format(prefixTable),(prefix,))
        connection.commit()
        for prefix_ in connection.execute('select prefix from {} where count>=?;'.format(prefixTable),(threshold,)):
            standard_prefix=get_standardPrefix(prefix_[0])
            print(standard_prefix)
        connection.close()
        print('total {} seconds for {} lines'.format(time.time()-t0, IP_count))
    if args.generate:
        if args.input and args.database:
            #read from file and create database
            print(args.input)
        elif args.database:
            #read from database and create table in database
            connection=sqlite3.connect(args.database)
            connection.execute('DROP TABLE IF EXISTS {}'.format(predictTable))
            connection.execute('create table {} (IP TEXT primary key, prefix TEXT, responsive NUMERIC);'.format(predictTable))
            for prefix_ in connection.execute('select prefix from {} where count>=?'.format(prefixTable), (args.threshold,)):
                targets=generateTargets(prefix_[0])
                for target in targets:
                    print(target)
                    connection.execute('insert into {} values(?,?,0);'.format(predictTable),(target,prefix_[0]))
            connection.commit()
            connection.close()
    
    if args.statistics:
        connection=sqlite3.connect(args.database)
        for line in open(args.input):
            #{'saddr':''}
            responsive_IP=json.loads(line)['saddr']
            raw_IP=get_rawIP(responsive_IP)
            #print(raw_IP)
            #print('above')
            prefix=connection.execute('select prefix from {} where IP=?'.format(predictTable),(raw_IP,)).fetchone()[0]
            connection.execute('update {} set responsive=1 where IP=?'.format(predictTable),(raw_IP,))
            connection.execute('update {} set response_count=response_count+1 where prefix=?'.format(prefixTable),(prefix,))
        for prefix_ in connection.execute('select prefix from {} where response_count=16'.format(prefixTable)):
            print(get_standardPrefix(prefix_[0]))
        connection.commit()
        connection.close()

    if args.draw:
        connection=sqlite3.connect(args.database)
        X=range(0,16+1)
        Y=[]
        for i in range(0,16+1):
            count=connection.execute('select count(*) from {} where response_count=?'.format(prefixTable),(i,)).fetchone()[0]
            Y.append(count)
        import matplotlib.pyplot as plt
        plt.bar(x=X, height=Y, width=0.8)
        plt.xlim(0,16)
        plt.xlabel('response IP count')
        plt.ylabel('prefix count')
        plt.savefig('response_.jpg')
        plt.close('all')
        plt.pie(Y,labels=[str(i) for i in X])
        plt.savefig('percentage.jpg')
        connection.close()