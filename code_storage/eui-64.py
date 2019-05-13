#coding:utf-8
'''
    prefix(16)+oui(6)+fffe(4)+id(6)
    python eui-64.py -i ~/datas/2019-04-12/AS_result/6057.hex --save ~/datas/2019-04-12/AS_result/6057eui.hex> ~/datas/2019-04-12/AS_result/6057.euidistribution.txt
    python eui-64.py -i ~/datas/2019-04-12/AS_result/9146.hex --mode B --save ~/datas/2019-04-12/AS_result/9146eui.hex > ~/datas/2019-04-12/AS_result/9146.euidistribution.txt
    71M
    A: 完全符合定义的EUI-64地址
    B: OUI 不存在于数据库的EUI-64地址 
        OUI熵低，ID熵高的特征 设定阈值，如果大于阈值认为不是随机的，阈值取2
    C: 完全随机的地址
        fffe是随机得到的，概率是1/2**16 
    -mode A,B,C

'''
import argparse,time
def loadOUIFile(filepath):
    OUIs=set()
    for line in open(filepath):
        if line and 'base 16' in line:
            OUI=line.split(' ')[0]
            OUIs.add(OUI.lower())
    return OUIs
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
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input','-i',type=str,help='filename with hex IPv6 addresses.')
    p.add_argument('--save',type=str,help='filename to save EUI IPs.')
    p.add_argument('--mode',default='A',type=str,help='mode A or B or C')
    p.add_argument('--threshold',default=2,type=int,help='threshold for mode B')
    args=p.parse_args()
    count=0.0
    counta,countb,countc=0,0,0
    OUIs=loadOUIFile('oui.txt')
    oui_distribution={}
    t0=time.time()
    for line in open(args.input):
        if line and line[0]!='#':
            IP=line.strip()
            assert(len(IP)==32)
            if IP[22:26]=='fffe':
                OUI=reverseOUI(IP[16:22])
                if OUI not in oui_distribution:
                    oui_distribution[OUI] = 1
                else:
                    oui_distribution[OUI] += 1
    mode=args.mode
    if args.save!=None:
        f=open(args.save, 'w')
        for line in open(args.input):
            if line and line[0]!='#':
                IP=line.strip()
                count+=1
                if IP[22:26]=='fffe':
                    OUI=reverseOUI(IP[16:22])
                    if OUI in OUIs:
                        counta+=1
                        ouiT='A'
                    elif oui_distribution[OUI] >= args.threshold:
                        countb+=1
                        ouiT='B'
                    else: 
                        countc+=1
                        ouiT='C'
                    if mode=='A': 
                        if ouiT=='A':
                            f.write(IP+'\n')
                    elif mode=='B':
                        if ouiT=='A' or ouiT=='B':
                            f.write(IP+'\n')
                    elif mode=='C':
                        f.write(IP+'\n')
                if count%10000000==0:
                    print('{} use {} seconds'.format(count, time.time() - t0))
        f.close()
    print('eui {} {} {} total {}, oui {}'.format(counta, countb, countc, count, len(oui_distribution)))
    print('{} use {} seconds'.format(count, time.time() - t0))
    oui_result=[]
    for key, val in oui_distribution.items():
        oui_result.append([key, val])
    oui_result.sort(key=lambda x:x[1], reverse=True)
    for item in oui_result:
        print('oui: {}  count: {}'.format(item[0], item[1]))