# sudo crontab -e
# */2 * * * * /usr/local/OpenSprinkler/health_check.sh >> /usr/local/OpenSprinkler/health_check.log

echo -e "GET http://192.168.1.2 HTTP/1.0\n\n" | nc 127.0.0.1 8080 | grep "200 OK" > nul

if [ $? -ne 0 ] ; then
        pkill -f /usr/local/OpenSprinkler/OpenSprinkler -9
        cd /usr/local/OpenSprinkler && /usr/local/OpenSprinkler/OpenSprinkler &
        echo $(date "+%Y-%m-%d %H:%M:%S.%3N) OpenSprinkler restarted
else
        echo $(date "+%Y-%m-%d %H:%M:%S.%3N) " OK"
fi
