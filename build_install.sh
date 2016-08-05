#!/bin/sh
#make FLAVOUR=kamailio PREFIX=/opt/kamailio include_modules="cnxcc db_mysql utils dialplan regex rtpengine tcpops tls tsilo" cfg && make && make modules && make utils && sudo make install
make FLAVOUR=kamailio PREFIX=/opt/kamailio include_modules="cnxcc db_mysql utils dialplan regex rtpengine tcpops tls tsilo" cfg && make && make modules && make utils 
