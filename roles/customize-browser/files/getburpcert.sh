#!/bin/bash
/bin/bash -c "timeout 450 /usr/lib/jvm/java-17-openjdk-amd64/bin/java -Djava.awt.headless=true -jar /usr/share/burpsuite/burpsuite_community.jar < <(echo y) &" 
sleep 30
curl http://localhost:8080/cert -o /tmp/cacert.der
exit
