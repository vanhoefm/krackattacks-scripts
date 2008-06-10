/*
 * mac80211_hwsim - software simulator of 802.11 radio(s) for mac80211
 * Copyright (c) 2008, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * TODO:
 * - periodic Beacon transmission in AP mode
 * - IBSS mode simulation (Beacon transmission with competion for "air time")
 * - IEEE 802.11a and 802.11n modes
 */

#include <net/mac80211.h>

MODULE_AUTHOR("Jouni Malinen");
MODULE_DESCRIPTION("Software simulator of 802.11 radio(s) for mac80211");
MODULE_LICENSE("GPL");

static int radios = 2;
module_param(radios, int, 0444);
MODULE_PARM_DESC(radios, "Number of simulated radios");


static struct class *hwsim_class;

static struct ieee80211_hw **hwsim_radios;
static int hwsim_radio_count;


static const struct ieee80211_channel hwsim_channels[] = {
	{ .chan = 1, .freq = 2412, .val = 1 },
	{ .chan = 2, .freq = 2417, .val = 2 },
	{ .chan = 3, .freq = 2422, .val = 3 },
	{ .chan = 4, .freq = 2427, .val = 4 },
	{ .chan = 5, .freq = 2432, .val = 5 },
	{ .chan = 6, .freq = 2437, .val = 6 },
	{ .chan = 7, .freq = 2442, .val = 7 },
	{ .chan = 8, .freq = 2447, .val = 8 },
	{ .chan = 9, .freq = 2452, .val = 9 },
	{ .chan = 10, .freq = 2457, .val = 10 },
	{ .chan = 11, .freq = 2462, .val = 11 },
	{ .chan = 12, .freq = 2467, .val = 12 },
	{ .chan = 13, .freq = 2472, .val = 13 },
	{ .chan = 14, .freq = 2484, .val = 14 },
};

static const struct ieee80211_rate hwsim_rates[] = {
	{ .rate = 10, .val = 10, .flags = IEEE80211_RATE_CCK },
	{ .rate = 20, .val = 20, .val2 = 21, .flags = IEEE80211_RATE_CCK_2 },
	{ .rate = 55, .val = 55, .val2 = 56, .flags = IEEE80211_RATE_CCK_2 },
	{ .rate = 110, .val = 110, .val2 = 111,
	  .flags = IEEE80211_RATE_CCK_2 },
	{ .rate = 60, .val = 60, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 90, .val = 90, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 120, .val = 120, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 180, .val = 180, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 240, .val = 240, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 360, .val = 360, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 480, .val = 480, .flags = IEEE80211_RATE_OFDM },
	{ .rate = 540, .val = 540, .flags = IEEE80211_RATE_OFDM }
};

struct mac80211_hwsim_data {
	struct device *dev;
	struct ieee80211_hw_mode modes[1];
	struct ieee80211_channel channels[ARRAY_SIZE(hwsim_channels)];
	struct ieee80211_rate rates[ARRAY_SIZE(hwsim_rates)];

	int freq;
	int channel;
	enum ieee80211_phymode phymode;
	int radio_enabled;
	int beacon_int;
	unsigned int rx_filter;
};


static int mac80211_hwsim_tx(struct ieee80211_hw *hw, struct sk_buff *skb,
			     struct ieee80211_tx_control *control)
{
	struct mac80211_hwsim_data *data = hw->priv;
	struct ieee80211_tx_status tx_status;
	struct ieee80211_rx_status rx_status;
	int i;

	if (!data->radio_enabled) {
		printk(KERN_DEBUG "%s: dropped TX frame since radio "
		       "disabled\n", wiphy_name(hw->wiphy));
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	memset(&rx_status, 0, sizeof(rx_status));
	/* TODO: set mactime */
	rx_status.freq = data->freq;
	rx_status.channel = data->channel;
	rx_status.phymode = data->phymode;
	rx_status.rate = control->tx_rate;
	/* TODO: simulate signal strength (and optional packet drop) */

	/* Copy skb to all enabled radios that are on the current frequency */
	for (i = 0; i < hwsim_radio_count; i++) {
		struct mac80211_hwsim_data *data2;
		struct sk_buff *nskb;

		if (hwsim_radios[i] == NULL || hwsim_radios[i] == hw)
			continue;
		data2 = hwsim_radios[i]->priv;
		if (!data2->radio_enabled || data->freq != data2->freq)
			continue;

		nskb = skb_copy(skb, GFP_ATOMIC);
		if (nskb == NULL)
			continue;

		ieee80211_rx(hwsim_radios[i], nskb, &rx_status);
	}

	memset(&tx_status, 0, sizeof(tx_status));
	memcpy(&tx_status.control, control, sizeof(*control));
	/* TODO: proper ACK determination */
	tx_status.flags = IEEE80211_TX_STATUS_ACK;
	ieee80211_tx_status(hw, skb, &tx_status);
	return NETDEV_TX_OK;
}


static int mac80211_hwsim_start(struct ieee80211_hw *hw)
{
	printk(KERN_DEBUG "%s:%s\n", wiphy_name(hw->wiphy), __func__);
	return 0;
}


static void mac80211_hwsim_stop(struct ieee80211_hw *hw)
{
	printk(KERN_DEBUG "%s:%s\n", wiphy_name(hw->wiphy), __func__);
}


static int mac80211_hwsim_add_interface(struct ieee80211_hw *hw,
					struct ieee80211_if_init_conf *conf)
{
	printk(KERN_DEBUG "%s:%s\n", wiphy_name(hw->wiphy), __func__);
	return 0;
}


static void mac80211_hwsim_remove_interface(
	struct ieee80211_hw *hw, struct ieee80211_if_init_conf *conf)
{
	printk(KERN_DEBUG "%s:%s\n", wiphy_name(hw->wiphy), __func__);
}


static int mac80211_hwsim_config(struct ieee80211_hw *hw,
				 struct ieee80211_conf *conf)
{
	struct mac80211_hwsim_data *data = hw->priv;

	printk(KERN_DEBUG "%s:%s (freq=%d radio_enabled=%d beacon_int=%d)\n",
	       wiphy_name(hw->wiphy), __func__,
	       conf->freq, conf->radio_enabled, conf->beacon_int);

	data->freq = conf->freq;
	data->channel = conf->channel;
	data->phymode = conf->phymode;
	data->radio_enabled = conf->radio_enabled;
	data->beacon_int = conf->beacon_int;

	return 0;
}


static void mac80211_hwsim_configure_filter(struct ieee80211_hw *hw,
					    unsigned int changed_flags,
					    unsigned int *total_flags,
					    int mc_count,
					    struct dev_addr_list *mc_list)
{
	struct mac80211_hwsim_data *data = hw->priv;

	printk(KERN_DEBUG "%s:%s\n", wiphy_name(hw->wiphy), __func__);

	data->rx_filter = 0;
	if (*total_flags & FIF_PROMISC_IN_BSS)
		data->rx_filter |= FIF_PROMISC_IN_BSS;
	if (*total_flags & FIF_ALLMULTI)
		data->rx_filter |= FIF_ALLMULTI;

	*total_flags = data->rx_filter;
}



static const struct ieee80211_ops mac80211_hwsim_ops =
{
	.tx = mac80211_hwsim_tx,
	.start = mac80211_hwsim_start,
	.stop = mac80211_hwsim_stop,
	.add_interface = mac80211_hwsim_add_interface,
	.remove_interface = mac80211_hwsim_remove_interface,
	.config = mac80211_hwsim_config,
	.configure_filter = mac80211_hwsim_configure_filter,
};


static void mac80211_hwsim_free(void)
{
	int i;

	for (i = 0; i < hwsim_radio_count; i++) {
		if (hwsim_radios[i]) {
			struct mac80211_hwsim_data *data;
			data = hwsim_radios[i]->priv;
			ieee80211_unregister_hw(hwsim_radios[i]);
			if (!IS_ERR(data->dev))
				device_unregister(data->dev);
			ieee80211_free_hw(hwsim_radios[i]);
		}
	}
	kfree(hwsim_radios);
	class_destroy(hwsim_class);
}


static struct device_driver mac80211_hwsim_driver = {
	.name = "mac80211_hwsim"
};


static int __init init_mac80211_hwsim(void)
{
	int i, err = 0;
	u8 addr[ETH_ALEN];
	struct mac80211_hwsim_data *data;
	struct ieee80211_hw *hw;
	DECLARE_MAC_BUF(mac);

	if (radios < 1 || radios > 65535)
		return -EINVAL;

	hwsim_radio_count = radios;
	hwsim_radios = kcalloc(hwsim_radio_count,
			       sizeof(struct ieee80211_hw *), GFP_KERNEL);
	if (hwsim_radios == NULL)
		return -ENOMEM;

	hwsim_class = class_create(THIS_MODULE, "mac80211_hwsim");
	if (IS_ERR(hwsim_class)) {
		kfree(hwsim_radios);
		return PTR_ERR(hwsim_class);
	}

	memset(addr, 0, ETH_ALEN);
	addr[0] = 0x02;

	for (i = 0; i < hwsim_radio_count; i++) {
		printk(KERN_DEBUG "mac80211_hwsim: Initializing radio %d\n",
		       i);
		hw = ieee80211_alloc_hw(sizeof(*data), &mac80211_hwsim_ops);
		if (hw == NULL) {
			printk(KERN_DEBUG "mac80211_hwsim: ieee80211_alloc_hw "
			       "failed\n");
			err = -ENOMEM;
			goto failed;
		}
		hwsim_radios[i] = hw;

		data = hw->priv;
		data->dev = device_create(hwsim_class, NULL, 0, "hwsim%d", i);
		if (IS_ERR(data->dev)) {
			printk(KERN_DEBUG "mac80211_hwsim: device_create "
			       "failed (%ld)\n", PTR_ERR(data->dev));
			err = -ENOMEM;
			goto failed;
		}
		data->dev->driver = &mac80211_hwsim_driver;
		dev_set_drvdata(data->dev, hw);

		SET_IEEE80211_DEV(hw, data->dev);
		addr[3] = i >> 8;
		addr[4] = i;
		SET_IEEE80211_PERM_ADDR(hw, addr);

		hw->channel_change_time = 1;
		hw->queues = 1;

		memcpy(data->channels, hwsim_channels, sizeof(hwsim_channels));
		memcpy(data->rates, hwsim_rates, sizeof(hwsim_rates));
		data->modes[0].channels = data->channels;
		data->modes[0].rates = data->rates;
		data->modes[0].mode = MODE_IEEE80211G;
		data->modes[0].num_channels = ARRAY_SIZE(hwsim_channels);
		data->modes[0].num_rates = ARRAY_SIZE(hwsim_rates);

		err = ieee80211_register_hwmode(hw, data->modes);
		if (err < 0) {
			printk(KERN_DEBUG "mac80211_hwsim: "
			       "ieee80211_register_hwmode failed (%d)\n", err);
			goto failed;
		}

		err = ieee80211_register_hw(hw);
		if (err < 0) {
			printk(KERN_DEBUG "mac80211_hwsim: "
			       "ieee80211_register_hw failed (%d)\n", err);
			goto failed;
		}

		printk(KERN_DEBUG "%s: hwaddr %s registered\n",
		       wiphy_name(hw->wiphy),
		       print_mac(mac, hw->wiphy->perm_addr));
	}

	return 0;

failed:
	mac80211_hwsim_free();
	return err;
}


static void __exit exit_mac80211_hwsim(void)
{
	printk(KERN_DEBUG "mac80211_hwsim: unregister %d radios\n",
	       hwsim_radio_count);

	mac80211_hwsim_free();
}


module_init(init_mac80211_hwsim);
module_exit(exit_mac80211_hwsim);
