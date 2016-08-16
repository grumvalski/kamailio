include ../../Makefile.defs
auto_gen=
NAME:=lost_client
MAJOR_VER=0
MINOR_VER=1
BUGFIX_VER=0
DEFS+=-DSER

ifeq ($(CROSS_COMPILE),)
XML2CFG=$(shell which xml2-config)
endif

ifneq ($(XML2CFG),)
	libxml2_includes = $(shell $(XML2CFG) --cflags)
	libxml2_libs = $(shell $(XML2CFG) --libs)
else
	libxml2_includes = -I$(LOCALBASE)/include/libxml2 -I$(LOCALBASE)/include
	libxml2_libs = -L$(LOCALBASE)/lib -lxml2
endif

ifeq ($(CROSS_COMPILE),)
CURL_BUILDER=$(shell \
    if pkg-config --exists libcurl; then \
        echo 'pkg-config libcurl'; \
    else \
        which curl-config; \
    fi)
endif


ifneq ($(CURL_BUILDER),)
    CURLDEFS += $(shell $(CURL_BUILDER) --cflags)
    CURLLIBS += $(shell $(CURL_BUILDER) --libs)
else
    CURLDEFS+=-I$(LOCALBASE)/include -I$(SYSBASE)/include
    CURLLIBS+=-L$(LOCALBASE)/lib -L$(SYSBASE)/lib -lcurl -levent
endif

INCLUDES= -I$(CURDIR)/.. -I$(CURDIR)/../.. $(libxml2_includes) $(CURLDEFS)
LIBS=$(libxml2_libs) $(CURLLIBS)

include ../../Makefile.libs

