/*
 * This file define a set of standard wireless extensions
 *
 * Version :	7	23.4.99
 *
 * Authors :	Jean Tourrilhes - HPLB - <jt@hplb.hpl.hp.com>
 */

#ifndef _LINUX_WIRELESS_H
#define _LINUX_WIRELESS_H

/************************** DOCUMENTATION **************************/
/*
 * Basically, the wireless extensions are for now a set of standard ioctl
 * call + /proc/net/wireless
 *
 * The entry /proc/net/wireless give statistics and information on the
 * driver.
 * This is better than having each driver having its entry because
 * its centralised and we may remove the driver module safely.
 *
 * Ioctl are used to configure the driver and issue commands.  This is
 * better than command line options of insmod because we may want to
 * change dynamically (while the driver is running) some parameters.
 *
 * The ioctl mechanimsm are copied from standard devices ioctl.
 * We have the list of command plus a structure descibing the
 * data exchanged...
 * Note that to add these ioctl, I was obliged to modify :
 *	net/core/dev.c (two place + add include)
 *	net/ipv4/af_inet.c (one place + add include)
 *
 * /proc/net/wireless is a copy of /proc/net/dev.
 * We have a structure for data passed from the driver to /proc/net/wireless
 * Too add this, I've modified :
 *	net/core/dev.c (two other places)
 *	include/linux/netdevice.h (one place)
 *	include/linux/proc_fs.h (one place)
 *
 * Do not add here things that are redundant with other mechanisms
 * (drivers init, ifconfig, /proc/net/dev, ...) and with are not
 * wireless specific.
 *
 * These wireless extensions are not magic : each driver has to provide
 * support for them...
 *
 * IMPORTANT NOTE : As everything in the kernel, this is very much a
 * work in progress. Contact me if you have ideas of improvements...
 */

/***************************** INCLUDES *****************************/

#if 0
#include <linux/types.h>		/* for "caddr_t" et al		*/
#include <linux/socket.h>		/* for "struct sockaddr" et al	*/
#include <linux/if.h>			/* for IFNAMSIZ and co... */
#endif

/**************************** CONSTANTS ****************************/

/* --------------------------- VERSION --------------------------- */
/*
 * This constant is used to know the availability of the wireless
 * extensions and to know which version of wireless extensions it is
 * (there is some stuff that will be added in the future...)
 * I just plan to increment with each new version.
 */
#define WIRELESS_EXT	6

/*
 * Changes :
 *
 * V2 to V3
 * --------
 *	Alan Cox start some incompatibles changes. I've integrated a bit more.
 *	- Encryption renamed to Encode to avoid US regulation problems
 *	- Frequency changed from float to struct to avoid problems on old 386
 *
 * V3 to V4
 * --------
 *	- Add sensitivity
 *
 * V4 to V5
 * --------
 *	- Missing encoding definitions in range
 *	- Access points stuff
 *
 * V5 to V6
 * --------
 *	- 802.11 support (ESSID ioctls)
 *
 * V6 to V7
 * --------
 *	- define IW_ESSID_MAX_SIZE and IW_MAX_AP
 */

/* -------------------------- IOCTL LIST -------------------------- */

/* Basic operations */
#define SIOCSIWNAME	0x8B00		/* Unused ??? */
#define SIOCGIWNAME	0x8B01		/* get name */
#define SIOCSIWNWID	0x8B02		/* set network id */
#define SIOCGIWNWID	0x8B03		/* get network id */
#define SIOCSIWFREQ	0x8B04		/* set channel/frequency */
#define SIOCGIWFREQ	0x8B05		/* get channel/frequency */
#define SIOCSIWENCODE	0x8B06		/* set encoding info */
#define SIOCGIWENCODE	0x8B07		/* get encoding info */
#define SIOCSIWSENS	0x8B08		/* set sensitivity */
#define SIOCGIWSENS	0x8B09		/* get sensitivity */

/* Informative stuff */
#define SIOCSIWRANGE	0x8B0A		/* Unused ??? */
#define SIOCGIWRANGE	0x8B0B		/* Get range of parameters */
#define SIOCSIWPRIV	0x8B0C		/* Unused ??? */
#define SIOCGIWPRIV	0x8B0D		/* get private ioctl interface info */

/* Mobile IP support */
#define SIOCSIWSPY	0x8B10		/* set spy addresses */
#define SIOCGIWSPY	0x8B11		/* get spy info (quality of link) */

/* Access Point manipulation */
#define SIOCSIWAP	0x8B14		/* set access point hardware addresses */
#define SIOCGIWAP	0x8B15		/* get access point hardware addresses */
#define SIOCGIWAPLIST	0x8B17		/* get list of access point in range */

/* 802.11 specific support */
#define SIOCSIWESSID	0x8B1A		/* set ESSID (network name) */
#define SIOCGIWESSID	0x8B1B		/* get ESSID */
/* As the ESSID is a string up to 32 bytes long, it doesn't fit within the
 * 'iwreq' structure, so we need to use the 'data' member to point to a
 * string in user space, like it is done for RANGE...
 * The "flags" member indicate if the ESSID is active or not.
 */

/* ------------------------- IOCTL STUFF ------------------------- */

/* The first and the last (range) */
#define SIOCIWFIRST	0x8B00
#define SIOCIWLAST	0x8B1B

/* Even : get (world access), odd : set (root access) */
#define IW_IS_SET(cmd)	(!((cmd) & 0x1))
#define IW_IS_GET(cmd)	((cmd) & 0x1)

/* ------------------------- PRIVATE INFO ------------------------- */
/*
 * The following is used with SIOCGIWPRIV. It allow a driver to define
 * the interface (name, type of data) for its private ioctl.
 * Privates ioctl are SIOCDEVPRIVATE -> SIOCDEVPRIVATE + 0xF
 */

#define IW_PRIV_TYPE_MASK	0x7000	/* Type of arguments */
#define IW_PRIV_TYPE_NONE	0x0000
#define IW_PRIV_TYPE_BYTE	0x1000	/* Char as number */
#define IW_PRIV_TYPE_CHAR	0x2000	/* Char as character */
#define IW_PRIV_TYPE_INT	0x4000	/* 32 bits int */
#define IW_PRIV_TYPE_FLOAT	0x5000

#define IW_PRIV_SIZE_FIXED	0x0800	/* Variable or fixed nuber of args */

#define IW_PRIV_SIZE_MASK	0x07FF	/* Max number of those args */

/*
 * Note : if the number of args is fixed and the size < 16 octets,
 * instead of passing a pointer we will put args in the iwreq struct...
 */

/* ----------------------- OTHER CONSTANTS ----------------------- */

/* Maximum frequencies in the range struct */
#define IW_MAX_FREQUENCIES	16
/* Note : if you have something like 80 frequencies,
 * don't increase this constant and don't fill the frequency list.
 * The user will be able to set by channel anyway... */

/* Maximum of address that you may set with SPY */
#define IW_MAX_SPY		8

/* Maximum of address that you may get in the
   list of access points in range */
#define IW_MAX_AP		8

/* Maximum size of the ESSID string */
#define IW_ESSID_MAX_SIZE	32

/****************************** TYPES ******************************/

/* --------------------------- SUBTYPES --------------------------- */
/*
 *	A frequency
 *	For numbers lower than 10^9, we encode the number in 'mant' and
 *	set 'exp' to 0
 *	For number greater than 10^9, we divide it by a power of 10.
 *	The power of 10 is in 'exp', the result is in 'mant'.
 */
struct	iw_freq
{
	__u32		m;		/* Mantissa */
	__u16		e;		/* Exponent */
};

/*
 *	Quality of the link
 */
struct	iw_quality
{
	__u8		qual;		/* link quality (SNR or better...) */
	__u8		level;		/* signal level */
	__u8		noise;		/* noise level */
	__u8		updated;	/* Flags to know if updated */
};

/*
 *	Packet discarded in the wireless adapter due to
 *	"wireless" specific problems...
 */
struct	iw_discarded
{
	__u32		nwid;		/* Wrong nwid */
	__u32		code;		/* Unable to code/decode */
	__u32		misc;		/* Others cases */
};

/*
 *	Encoding information (setting and so on)
 *	Encoding might be hardware encryption, scrambing or others
 */
struct	iw_encoding
{
  __u8	method;			/* Algorithm number / key used */
  __u64	code;			/* Data/key used for algorithm */
};


/* ------------------------ WIRELESS STATS ------------------------ */
/*
 * Wireless statistics (used for /proc/net/wireless)
 */
struct	iw_statistics
{
	__u8		status;		/* Status
					 * - device dependent for now */

	struct iw_quality	qual;		/* Quality of the link
						 * (instant/mean/max) */
	struct iw_discarded	discard;	/* Packet discarded counts */
};

/* ------------------------ IOCTL REQUEST ------------------------ */
/*
 * The structure to exchange data for ioctl.
 * This structure is the same as 'struct ifreq', but (re)defined for
 * convenience...
 *
 * Note that it should fit on the same memory footprint !
 * You should check this when increasing the above structures (16 octets)
 * 16 octets = 128 bits. Warning, pointers might be 64 bits wide...
 */
struct	iwreq 
{
	union
	{
		char	ifrn_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	} ifr_ifrn;

	/* Data part */
	union
	{
		/* Config - generic */
		char	name[IFNAMSIZ];
		/* Name : used to verify the presence of  wireless extensions.
		 * Name of the protocol/provider... */

		struct		/* network id (or domain) : used to to */
		{		/* create logical channels on the air */
			__u32	nwid;		/* value */
			__u8	on;		/* active/unactive nwid */
		}	nwid;

		struct iw_freq	freq;	/* frequency or channel :
					 * 0-1000 = channel
					 * > 1000 = frequency in Hz */

		struct iw_encoding	encoding;	/* Encoding stuff */

		__u32	sensitivity;		/* signal level threshold */

		struct sockaddr	ap_addr;	/* Access point address */

		struct		/* For all data bigger than 16 octets */
		{
			caddr_t	pointer;	/* Pointer to the data
						 * (in user space) */
			__u16	length;		/* fields or byte size */
			__u16	flags;		/* Optional params */
		}	data;
	}	u;
};

/* -------------------------- IOCTL DATA -------------------------- */
/*
 *	For those ioctl which want to exchange mode data that what could
 *	fit in the above structure...
 */

/*
 *	Range of parameters
 */

struct	iw_range
{
	/* Informative stuff (to choose between different interface) */
	__u32		throughput;	/* To give an idea... */

	/* NWID (or domain id) */
	__u32		min_nwid;	/* Minimal NWID we are able to set */
	__u32		max_nwid;	/* Maximal NWID we are able to set */

	/* Frequency */
	__u16		num_channels;	/* Number of channels [0; num - 1] */
	__u8		num_frequency;	/* Number of entry in the list */
	struct iw_freq	freq[IW_MAX_FREQUENCIES];	/* list */
	/* Note : this frequency list doesn't need to fit channel numbers */

	/* signal level threshold range */
	__u32	sensitivity;

	/* Quality of link & SNR stuff */
	struct iw_quality	max_qual;	/* Quality of the link */

	/* Encoder stuff */
	struct iw_encoding	max_encoding;	/* Encoding max range */
};

/*
 * Private ioctl interface information
 */
 
struct	iw_priv_args
{
	__u32		cmd;		/* Number of the ioctl to issue */
	__u16		set_args;	/* Type and number of args */
	__u16		get_args;	/* Type and number of args */
	char		name[IFNAMSIZ];	/* Name of the extension */
};

#endif	/* _LINUX_WIRELESS_H */
