#!/bin/bash
#Description
#Autor: Antônio Santana
#Data: 07032026

#Removendo containers
docker rm -f harbor-teams-webhook

#Realiza novo buid
 docker build -t harbor-teams-webhook .

#Start Container
 docker run -d \
-p 5000:5000 \
-e NODE_TLS_REJECT_UNAUTHORIZED=0 \
-e HARBOR_URL=https://{URL} \
-e HARBOR_USER='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' \
-e HARBOR_PASSWORD=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
-e TEAMS_WEBHOOK=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
--name harbor-teams-webhook \
harbor-teams-webhook
