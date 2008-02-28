SUBDIRS=common crypto drivers hlr_auc_gw eapol_supp eap_common eap_peer eap_server l2_packet radius rsn_supp tls utils

all:
	@echo Nothing to be made.

clean:
	for d in $(SUBDIRS); do [ -d $$d ] && $(MAKE) -C $$d clean; done
	rm -f *~
