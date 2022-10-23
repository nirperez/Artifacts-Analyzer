                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
#!/bin/bash

########################### Welcom to the Artifacts Analyzer by NIR-PEREZ  #####################

echo " Welcome to the Artifacts Analyzer by NIR-PEREZ "
sleep 2
echo " plese enter one file at the time "
sleep 2
echo " MEMORY and HDD ONLY "
echo " First file :"
read firstfile
echo "HHD=1"
echo "MEM=2"
read HM
echo " Second file :"
read secondfile
echo "HHD=1"
echo "MEM=2"
read HM2

############################## formost and bulk_extractor  #####################

function formost1()
{
        for i in $(locate volatility_2.6_lin64_standalone | head -1);do cd $i ;done
        formost -t all $firsfile -o outformost1
        bulk_extractor $firstfile -o bulk-out1
}

function formost2()
{
        for i in $(locate volatility_2.6_lin64_standalone | head -1);do cd $i ;done
        formost -t all $secondfile -o outformost2
        bulk_extractor $secondfile -o bulk-out2
}

formost1

formost2

######################################### strings ########################

if  [$HM -eq 2]
then
        strings $firstfile
fi

if [$HM2 -eq 2]
then
        strings $secondfile
fi

################################ volatility options menu ###################################################

echo "Here is a menu of volatility options for the FIRST FILE"
echo "Pick the number ONLY"
echo "1- imageinfo"
echo "2- pslist"
echo "3- Connection/CONNSCAN"
echo "4- The options to parser MFT " 
echo "5- Hashdump"
echo "6- Extract commands from cmd"
read vol
if [$vol -eq 4]
then
        echo"do you want to enter a specific EXE file ?"
        echo" exe file name :"
fi
read exefile
echo "for the PPID (if exists) enter the PID"
read PID 

cd $(locate volatility_2.6_lin64_standalone | head -1) | ./volatility_2.6_lin64_standalone -f $firstfile pslist | awk '{print $2," | ",$3, " | ", $4 }'| grep $PID


for i in $(locate volatility_2.6_lin64_standalone | head -1)
do

        case $vol in
           "1") cd $i | ./volatility_2.6_lin64_standalone imageinfo -f $firstfile
           ;;
           "2") cd $i | ./volatility_2.6_lin64_standalone pslist -f $firstfile
           ;;
           "3") cd $i | ./volatility_2.6_lin64_standalone connscan -f $firstfile
           ;;
           "4") cd $i | ./volatility_2.6_lin64_standalone mftparser -f $firstfile | grep $exefile
           ;;
           "5") cd $i | ./volatility_2.6_lin64_standalone hashdump -f $firstfile --output-file=$PWD/hashes.txt
           ;;
           "6") cd $i | ./volatility_2.6_lin64_standalone cmdscan -f $firstfile
           ;;

        esac
done



echo "Here is a menu of volatility options for the SECOND FILE"
echo "Pick the number ONLY"
echo "1- imageinfo"
echo "2- pslist"
echo "3- Connection/CONNSCAN"
echo "4- The options to parser MFT " 
echo "5- Hashdump"
echo "6- Extract commands from cmd"
read vol2
if [$vol2 -eq 4]
then
        echo"do you want to enter a specific EXE file ?"
        echo" exe file name :"
fi
read exefile2
echo "for the PPID (if exists) enter the PID"
read PID2 

cd $i | ./volatility_2.6_lin64_standalone -f $secondfile pslist | awk '{print $2," | ",$3, " | ", $4 }'| grep $PID2


for i in $(locate volatility_2.6_lin64_standalone | head -1)
do

        case $vol2 in
           "1") cd $i | ./volatility_2.6_lin64_standalone imageinfo -f $secondfile
           ;;
           "2") cd $i | ./volatility_2.6_lin64_standalone pslist -f $secondfile
           ;;
           "3") cd $i | ./volatility_2.6_lin64_standalone connscan -f $secondfile
           ;;
           "4") cd $i | ./volatility_2.6_lin64_standalone mftparser -f $secondfile | grep $exefile2
           ;;
           "5") cd $i | ./volatility_2.6_lin64_standalone hashdump -f $secondfile --output-file= hashes.txt
           ;;
           "6") cd $i | ./volatility_2.6_lin64_standalone cmdscan -f $secondfile
           ;;

        esac
done




#################### bruteforce for the hashes if you chose hashdump ######################
function bruteforce()
{
        john --format=NT $PWD/hashes.txt -o cracked.txt
        echo -e "The hashes are: $(cat cracked.txt)\n"
}

if [[ $v == '5' ]]
then
        bruteforce
fi



