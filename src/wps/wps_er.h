#ifndef WPS_ER_H
#define WPS_ER_H

struct wps_er_sta {
	struct wps_er_sta *next;
	struct wps_er_ap *ap;
	u8 addr[ETH_ALEN];
	u16 config_methods;
	u8 uuid[WPS_UUID_LEN];
	u8 pri_dev_type[8];
	u16 dev_passwd_id;
	int m1_received;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	char *dev_name;
	struct wps_data *wps;
	struct http_client *http;
};

struct wps_er_ap {
	struct wps_er_ap *next;
	struct wps_er *er;
	struct wps_er_sta *sta; /* list of STAs/Enrollees using this AP */
	struct in_addr addr;
	char *location;
	struct http_client *http;
	struct wps_data *wps;

	u8 uuid[WPS_UUID_LEN];
	u8 pri_dev_type[8];
	u8 wps_state;
	u8 mac_addr[ETH_ALEN];
	char *friendly_name;
	char *manufacturer;
	char *manufacturer_url;
	char *model_description;
	char *model_name;
	char *model_number;
	char *model_url;
	char *serial_number;
	char *udn;
	char *upc;

	char *scpd_url;
	char *control_url;
	char *event_sub_url;

	int subscribed;
	unsigned int id;

	struct wps_credential *ap_settings;

	void (*m1_handler)(struct wps_er_ap *ap, struct wpabuf *m1);
};

struct wps_er {
	struct wps_context *wps;
	char ifname[17];
	char *mac_addr_text; /* mac addr of network i.f. we use */
	u8 mac_addr[ETH_ALEN]; /* mac addr of network i.f. we use */
	char *ip_addr_text; /* IP address of network i.f. we use */
	unsigned ip_addr; /* IP address of network i.f. we use (host order) */
	int multicast_sd;
	int ssdp_sd;
	struct wps_er_ap *ap;
	struct http_server *http_srv;
	int http_port;
	unsigned int next_ap_id;
	unsigned int event_id;
};


/* wps_er.c */
void wps_er_ap_add(struct wps_er *er, const u8 *uuid, struct in_addr *addr,
		   const char *location, int max_age);
void wps_er_ap_remove(struct wps_er *er, struct in_addr *addr);

/* wps_er_ssdp.c */
int wps_er_ssdp_init(struct wps_er *er);
void wps_er_ssdp_deinit(struct wps_er *er);
void wps_er_send_ssdp_msearch(struct wps_er *er);

#endif /* WPS_ER_H */
