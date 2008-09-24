ALL=eap_example

all: $(ALL)

ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

CONFIG_TLS=openssl
#CONFIG_TLS=internal
#CONFIG_INTERNAL_LIBTOMMATH=y


CFLAGS += -I.
CFLAGS += -I../src
CFLAGS += -I../src/crypto
CFLAGS += -I../src/utils
CFLAGS += -I../src/common

# at least for now, need to include config_ssid.h and config_blob.h from
# wpa_supplicant directory
CFLAGS += -I../wpa_supplicant


OBJS_both += ../src/utils/common.o
OBJS_both += ../src/utils/os_unix.o
OBJS_both += ../src/utils/wpa_debug.o
OBJS_both += ../src/utils/base64.o
OBJS_both += ../src/utils/wpabuf.o
OBJS_both += ../src/crypto/md5.o
OBJS_both += ../src/crypto/rc4.o
OBJS_both += ../src/crypto/md4.o
OBJS_both += ../src/crypto/sha1.o
OBJS_both += ../src/crypto/des.o
OBJS_both += ../src/crypto/aes_wrap.o
OBJS_both += ../src/crypto/aes.o
OBJS_both += ../src/crypto/ms_funcs.o
OBJS_both += ../src/crypto/sha256.o


OBJS_both += ../src/eap_common/eap_peap_common.o
OBJS_both += ../src/eap_common/eap_psk_common.o
OBJS_both += ../src/eap_common/eap_pax_common.o
OBJS_both += ../src/eap_common/eap_sake_common.o
OBJS_both += ../src/eap_common/eap_gpsk_common.o
OBJS_both += ../src/eap_common/chap.o

OBJS_peer += ../src/eap_peer/eap_tls.o
OBJS_peer += ../src/eap_peer/eap_peap.o
OBJS_peer += ../src/eap_peer/eap_ttls.o
OBJS_peer += ../src/eap_peer/eap_md5.o
OBJS_peer += ../src/eap_peer/eap_mschapv2.o
OBJS_peer += ../src/eap_peer/mschapv2.o
OBJS_peer += ../src/eap_peer/eap_otp.o
OBJS_peer += ../src/eap_peer/eap_gtc.o
OBJS_peer += ../src/eap_peer/eap_leap.o
OBJS_peer += ../src/eap_peer/eap_psk.o
OBJS_peer += ../src/eap_peer/eap_pax.o
OBJS_peer += ../src/eap_peer/eap_sake.o
OBJS_peer += ../src/eap_peer/eap_gpsk.o
OBJS_peer += ../src/eap_peer/eap.o
OBJS_peer += ../src/eap_common/eap_common.o
OBJS_peer += ../src/eap_peer/eap_methods.o
OBJS_peer += ../src/eap_peer/eap_tls_common.o

CFLAGS += -DEAP_TLS
CFLAGS += -DEAP_PEAP
CFLAGS += -DEAP_TTLS
CFLAGS += -DEAP_MD5
CFLAGS += -DEAP_MSCHAPv2
CFLAGS += -DEAP_GTC
CFLAGS += -DEAP_OTP
CFLAGS += -DEAP_LEAP
CFLAGS += -DEAP_PSK
CFLAGS += -DEAP_PAX
CFLAGS += -DEAP_SAKE
CFLAGS += -DEAP_GPSK -DEAP_GPSK_SHA256
CFLAGS += -DEAP_TLS_FUNCS

CFLAGS += -DIEEE8021X_EAPOL

ifeq ($(CONFIG_TLS), openssl)
CFLAGS += -DEAP_TLS_OPENSSL
OBJS_both += ../src/crypto/tls_openssl.o
OBJS_both += ../src/crypto/crypto_openssl.o
LIBS += -lssl -lcrypto
CFLAGS += -DINTERNAL_SHA256
endif

ifeq ($(CONFIG_TLS), internal)
OBJS_both += ../src/crypto/tls_internal.o
OBJS_both += ../src/tls/tlsv1_common.o ../src/tls/tlsv1_record.o
OBJS_both += ../src/tls/tlsv1_cred.o
OBJS_both += ../src/tls/asn1.o ../src/tls/x509v3.o
OBJS_both += ../src/crypto/crypto_internal.o ../src/tls/rsa.o ../src/tls/bignum.o

OBJS_peer += ../src/tls/tlsv1_client.o
OBJS_peer += ../src/tls/tlsv1_client_write.o ../src/tls/tlsv1_client_read.o
CFLAGS += -DCONFIG_TLS_INTERNAL_CLIENT

OBJS_server += ../src/tls/tlsv1_server.o
OBJS_server += ../src/tls/tlsv1_server_write.o ../src/tls/tlsv1_server_read.o
CFLAGS += -DCONFIG_TLS_INTERNAL_SERVER

CFLAGS += -DCONFIG_TLS_INTERNAL
CFLAGS += -DCONFIG_CRYPTO_INTERNAL
CFLAGS += -DCONFIG_INTERNAL_X509
CFLAGS += -DINTERNAL_AES
CFLAGS += -DINTERNAL_SHA1
CFLAGS += -DINTERNAL_SHA256
CFLAGS += -DINTERNAL_MD5
CFLAGS += -DINTERNAL_MD4
CFLAGS += -DINTERNAL_DES
ifdef CONFIG_INTERNAL_LIBTOMMATH
CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
else
LIBS += -ltommath
endif
endif



# Optional components to add EAP server support
OBJS_server += ../src/eap_server/eap_tls.o
OBJS_server += ../src/eap_server/eap_peap.o
OBJS_server += ../src/eap_server/eap_ttls.o
OBJS_server += ../src/eap_server/eap_md5.o
OBJS_server += ../src/eap_server/eap_mschapv2.o
OBJS_server += ../src/eap_server/eap_gtc.o
OBJS_server += ../src/eap_server/eap_psk.o
OBJS_server += ../src/eap_server/eap_pax.o
OBJS_server += ../src/eap_server/eap_sake.o
OBJS_server += ../src/eap_server/eap_gpsk.o
OBJS_server += ../src/eap_server/eap.o
OBJS_server += ../src/eap_server/eap_identity.o
OBJS_server += ../src/eap_server/eap_methods.o
OBJS_server += ../src/eap_server/eap_tls_common.o
CFLAGS += -DEAP_SERVER


ifndef LDO
LDO=$(CC)
endif


OBJS_lib=$(OBJS_both) $(OBJS_peer) $(OBJS_server)

OBJS_ex = eap_example.o eap_example_peer.o eap_example_server.o

ifneq ($(CONFIG_SOLIB), yes)
LIBEAP = libeap.a
libeap.a: $(OBJS_lib)
	ar rc libeap.a $(OBJS_lib)
	ranlib libeap.a

else
CFLAGS  += -fPIC -DPIC
LDFLAGS += -shared

LIBEAP  = libeap.so
libeap.so: $(OBJS_lib)
	$(LDO) $(LDFLAGS) $(OBJS_lib) -o $(LIBEAP)

endif

eap_example: $(OBJS_ex) $(LIBEAP)
	$(LDO) $(LDFLAGS) -o eap_example $(OBJS_ex) -L. -leap $(LIBS)

clean:
	$(MAKE) -C ../src clean
	rm -f core *~ *.o *.d libeap.a libeap.so $(ALL)

-include $(OBJS:%.o=%.d)
