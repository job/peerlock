#!/usr/bin/env bash

########
#
#    use as following to generate nice PDFs:
#    ./make.sh NAME_OF_PEER AS_NUMBER
#
########

NAME=$1
AS=$2
DATE=$(date)

cat template-email.txt | sed "s/XXX/${AS}/g" | sed "s/YYY/${NAME}/" | tee ${NAME}-email.txt
cat template-pdf.txt | sed "s/XXX/${AS}/g" | sed "s/YYY/${NAME}/" | sed "s/DDD/${DATE}/" | tee ${NAME}-pdf.md

md2pdf ${NAME}-pdf.md NTT_peerlock_for_${NAME}_2020.pdf
#rm ${NAME}-pdf.md

#cupsfilter -t "NTT Peerlock Protection for ${NAME} / AS${AS}" -D ${NAME}-pdf.txt > NTT_peerlock_for_${NAME}_2020.pdf
