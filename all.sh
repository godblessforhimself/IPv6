#!/bin/bash
funAliveDetection() {
    sudo python AliveDetection.py --input=$1 --filename=alive.txt --dir=$2 --IPv6=$3 > /dev/null
}
funAPD() {
    ALIVEIPS="$2/alive.txt"
    APDDB="$2/apd.db"
    ALIASEDPREFIX="$2/AliasedPrefix.txt"
    sudo python APD.py --extract --input=$ALIVEIPS --database=$APDDB > /dev/null
    sudo python APD.py --detectAll --database=$APDDB --threshold=10 --IPv6=$3 --directory=$2/APD > /dev/null
    sudo python APD.py --output --database=$APDDB | sudo tee $ALIASEDPREFIX > /dev/null
}
funASSplit() {
    ASDIR="$2/AS"
    NONALIASEDIPS="$2/non-aliased.txt"
    ALIASEDIPS="$2/aliased.txt"
    sudo python AS_split.py --src=$NONALIASEDIPS --dst=$ASDIR --dat ipasn.dat > /dev/null
    sudo python AS_split.py -analyze --min 2 --dst $ASDIR > /dev/null
    sudo python AS_split.py -split --dst $ASDIR --mode AS --value 2 > /dev/null
}
funAddr2Hex() {
    ASDIR="$2/AS"
    for filename in `ls $ASDIR/AS[0-9]*.txt`;do
        hexname=${filename/txt/hex}
        sudo cat $filename | sudo ipv6-addr2hex | sudo tee $hexname > /dev/null
        sudo rm -f $filename
    done
}
funPatternDiscover() {
    ASDIR="$2/AS"
    PRDIR="$2/Predict"
    TARDIR="$2/Target"
    RESDIR="$2/Result"
    ZMAPDIR="$2/Zmap"
    sudo mkdir -p $PRDIR $RESDIR $ZMAPDIR $TARDIR
    for hexname in `ls $ASDIR/AS[0-9]*.hex`;do
        echo "mining $hexname"
        TargetPrefix="${hexname/$ASDIR/$PRDIR}.noex"
        time sudo python patternMining.py --read $hexname --write $TargetPrefix --budgets 10000 100000 1000000 10000000 --depth 4 --experience=False >> patternMining.result.txt
        for budget in 10000 100000 1000000 10000000;do
            hexfilename="$TargetPrefix.$budget"
            deduphexfile="$hexfilename.deduped"
            echo "dedup $deduphexfile"
            sudo python Deduplication.py -A $hexfilename -B $hexname -C $deduphexfile --silent > /dev/null
            scanaddress=${deduphexfile/$PRDIR/$TARDIR}
            scanaddress=${scanaddress/hex/txt}
            sudo cat $deduphexfile | sudo ipv6-hex2addr | sudo tee $scanaddress > /dev/null
            sudo rm $deduphexfile
            echo "scan $scanaddress"
            resultfilename="${scanaddress/$TARDIR/$RESDIR}.result"
            sudo zmap -q -L $ZMAPDIR --ipv6-target-file=$scanaddress --ipv6-source-ip=$3 -M icmp6_echoscan -f saddr,daddr,ipid,ttl,timestamp_str -O json -o $resultfilename
        done
        TargetPrefix="${hexname/$ASDIR/$PRDIR}.ex"
        time sudo python patternMining.py --read $hexname --write $TargetPrefix --budgets 10000 100000 1000000 10000000 --depth 4 --experience=True >> patternMining.result.txt
        for budget in 10000 100000 1000000 10000000;do
            hexfilename="$TargetPrefix.$budget"
            deduphexfile="$hexfilename.deduped"
            echo "dedup $deduphexfile"
            sudo python Deduplication.py -A $hexfilename -B $hexname -C $deduphexfile --silent > /dev/null
            scanaddress=${deduphexfile/$PRDIR/$TARDIR}
            scanaddress=${scanaddress/hex/txt}
            sudo cat $deduphexfile | sudo ipv6-hex2addr | sudo tee $scanaddress > /dev/null
            sudo rm $deduphexfile
            echo "scan $scanaddress"
            resultfilename="${scanaddress/$TARDIR/$RESDIR}.result"
            sudo zmap -q -L $ZMAPDIR --ipv6-target-file=$scanaddress --ipv6-source-ip=$3 -M icmp6_echoscan -f saddr,daddr,ipid,ttl,timestamp_str -O json -o $resultfilename
        done
    done
}
if [ $# -ne 3 ]; then
    if [[ $# -eq 4 && $4 -eq 5 ]]; then
        echo "patternDiscover"
        funPatternDiscover $1 $2 $3
        exit 0
    fi
    if [[ $# -eq 4 && $4 -eq 4 ]]; then
        echo "AS split"
        funASSplit $1 $2 $3
        exit 0
    fi
    echo "usage: all.sh input.txt outputdirname localIPv6"
	exit 1
fi >&2

echo "1. alive detection"
time funAliveDetection $1 $2 $3

echo "2. apd"
funAPD $1 $2 $3

echo "3. non-aliased"
NONALIASEDIPS="$2/non-aliased.txt"
ALIASEDIPS="$2/aliased.txt"
sudo python aliases-lpm.py -a $ALIASEDPREFIX -i $ALIVEIPS --non-aliased-result=$NONALIASEDIPS --aliased-result=$ALIASEDIPS

echo "4. AS split"
funASSplit $1 $2 $3
funAddr2Hex $1 $2 $3

echo "5. Pattern Discovery"
funPatternDiscover $1 $2 $3

echo "6. Veri"
TARDIR="$2/Target"
RESDIR="$2/Result"
wc -l $TARDIR > $2/targetlines.txt
wc -l $RESDIR > $2/resultlines.txt