/* SPDX-License-Identifier: GPL-2.0-only */
/*
################################################################################
#
# r8125 is the Linux device driver released for Realtek 2.5 Gigabit Ethernet
# controllers with PCI-Express interface.
#
# Copyright(c) 2025 Realtek Semiconductor Corp. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>.
#
# Author:
# Realtek NIC software team <nicfae@realtek.com>
# No. 2, Innovation Road II, Hsinchu Science Park, Hsinchu 300, Taiwan
#
################################################################################
*/

/************************************************************************************
 *  This product is covered by one or more of the following patents:
 *  US6,570,884, US6,115,776, and US6,327,625.
 ***********************************************************************************/

#ifndef __R8125_H
#define __R8125_H

//#include <linux/pci.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include "r8125_dash.h"
#include "r8125_realwow.h"
#ifdef ENABLE_FIBER_SUPPORT
#include "r8125_fiber.h"
#endif /* ENABLE_FIBER_SUPPORT */
#ifdef ENABLE_PTP_SUPPORT
#include "r8125_ptp.h"
#endif
#include "r8125_rss.h"
#ifdef ENABLE_LIB_SUPPORT
#include "r8125_lib.h"
#endif

#ifndef fallthrough
#define fallthrough
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#define netif_xmit_stopped netif_tx_queue_stopped
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#ifndef MDIO_AN_EEE_ADV_100TX
#define MDIO_AN_EEE_ADV_100TX	0x0002	/* Advertise 100TX EEE cap */
#endif
#ifndef MDIO_AN_EEE_ADV_1000T
#define MDIO_AN_EEE_ADV_1000T	0x0004	/* Advertise 1000T EEE cap */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
#define MDIO_EEE_100TX		MDIO_AN_EEE_ADV_100TX	/* 100TX EEE cap */
#define MDIO_EEE_1000T		MDIO_AN_EEE_ADV_1000T	/* 1000T EEE cap */
#define MDIO_EEE_10GT		0x0008	/* 10GT EEE cap */
#define MDIO_EEE_1000KX		0x0010	/* 1000KX EEE cap */
#define MDIO_EEE_10GKX4		0x0020	/* 10G KX4 EEE cap */
#define MDIO_EEE_10GKR		0x0040	/* 10G KR EEE cap */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0) */

static inline u32 mmd_eee_adv_to_ethtool_adv_t(u16 eee_adv)
{
        u32 adv = 0;

        if (eee_adv & MDIO_EEE_100TX)
                adv |= ADVERTISED_100baseT_Full;
        if (eee_adv & MDIO_EEE_1000T)
                adv |= ADVERTISED_1000baseT_Full;
        if (eee_adv & MDIO_EEE_10GT)
                adv |= ADVERTISED_10000baseT_Full;
        if (eee_adv & MDIO_EEE_1000KX)
                adv |= ADVERTISED_1000baseKX_Full;
        if (eee_adv & MDIO_EEE_10GKX4)
                adv |= ADVERTISED_10000baseKX4_Full;
        if (eee_adv & MDIO_EEE_10GKR)
                adv |= ADVERTISED_10000baseKR_Full;

        return adv;
}

static inline u16 ethtool_adv_to_mmd_eee_adv_t(u32 adv)
{
        u16 reg = 0;

        if (adv & ADVERTISED_100baseT_Full)
                reg |= MDIO_EEE_100TX;
        if (adv & ADVERTISED_1000baseT_Full)
                reg |= MDIO_EEE_1000T;
        if (adv & ADVERTISED_10000baseT_Full)
                reg |= MDIO_EEE_10GT;
        if (adv & ADVERTISED_1000baseKX_Full)
                reg |= MDIO_EEE_1000KX;
        if (adv & ADVERTISED_10000baseKX4_Full)
                reg |= MDIO_EEE_10GKX4;
        if (adv & ADVERTISED_10000baseKR_Full)
                reg |= MDIO_EEE_10GKR;

        return reg;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static inline bool skb_transport_header_was_set(const struct sk_buff *skb)
{
        return skb->transport_header != ~0U;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
static inline
ssize_t strscpy(char *dest, const char *src, size_t count)
{
        long res = 0;

        if (count == 0)
                return -E2BIG;

        while (count) {
                char c;

                c = src[res];
                dest[res] = c;
                if (!c)
                        return res;
                res++;
                count--;
        }

        /* Hit buffer length without finding a NUL; force NUL-termination. */
        if (res)
                dest[res-1] = '\0';

        return -E2BIG;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0))
static inline unsigned char *skb_checksum_start(const struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
        return skb->head + skb->csum_start;
#else /* < 2.6.22 */
        return skb_transport_header(skb);
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
                                        unsigned int bytes)
{}
static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
                unsigned int pkts,
                unsigned int bytes)
{}
static inline void netdev_tx_reset_queue(struct netdev_queue *q) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
static inline void fsleep(unsigned long usecs)
{
        if (usecs <= 10)
                udelay(usecs);
        else if (usecs <= 20000)
                usleep_range(usecs, 2 * usecs);
        else
                msleep(DIV_ROUND_UP(usecs, 1000));
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
#define netdev_xmit_more() (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
#define netif_testing_on(dev)
#define netif_testing_off(dev)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
#define netdev_sw_irq_coalesce_default_on(dev)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
typedef int netdev_tx_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,9)
static inline bool page_is_pfmemalloc(struct page *page)
{
        /*
         * Page index cannot be this large so this must be
         * a pfmemalloc page.
         */
        return page->index == -1UL;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,1,9) */
static inline bool dev_page_is_reusable(struct page *page)
{
        return likely(page_to_nid(page) == numa_mem_id() &&
                      !page_is_pfmemalloc(page));
}
#endif

/*
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)&& !defined(ENABLE_LIB_SUPPORT)
#define RTL_USE_NEW_INTR_API
#endif
*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#define dma_map_page_attrs(dev, page, offset, size, dir, attrs) \
	dma_map_page(dev, page, offset, size, dir)
#define dma_unmap_page_attrs(dev, page, size, dir, attrs) \
	 dma_unmap_page(dev, page, size, dir)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
#define page_ref_inc(page) atomic_inc(&page->_count)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,216)
#define page_ref_count(page) atomic_read(&page->_count)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,4,216)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define skb_transport_offset(skb) (skb->h.raw - skb->data)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#define device_set_wakeup_enable(dev, val)	do {} while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
        u16 *a = (u16 *)dst;
        const u16 *b = (const u16 *)src;

        a[0] = b[0];
        a[1] = b[1];
        a[2] = b[2];
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define IS_ERR_OR_NULL(ptr)			(!ptr)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
#define reinit_completion(x)			((x)->done = 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define pm_runtime_mark_last_busy(x)
#define pm_runtime_put_autosuspend(x)		pm_runtime_put(x)
#define pm_runtime_put_sync_autosuspend(x)	pm_runtime_put_sync(x)

static inline bool pm_runtime_suspended(struct device *dev)
{
        return dev->power.runtime_status == RPM_SUSPENDED
               && !dev->power.disable_depth;
}

static inline bool pm_runtime_active(struct device *dev)
{
        return dev->power.runtime_status == RPM_ACTIVE
               || dev->power.disable_depth;
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define queue_delayed_work(long_wq, work, delay)	schedule_delayed_work(work, delay)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define netif_printk(priv, type, level, netdev, fmt, args...)	\
	do {								\
		if (netif_msg_##type(priv))				\
			printk(level "%s: " fmt,(netdev)->name , ##args); \
	} while (0)

#define netif_emerg(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_EMERG, netdev, fmt, ##args)
#define netif_alert(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_ALERT, netdev, fmt, ##args)
#define netif_crit(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_CRIT, netdev, fmt, ##args)
#define netif_err(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_ERR, netdev, fmt, ##args)
#define netif_warn(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_WARNING, netdev, fmt, ##args)
#define netif_notice(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_NOTICE, netdev, fmt, ##args)
#define netif_info(priv, type, netdev, fmt, args...)		\
		netif_printk(priv, type, KERN_INFO, (netdev), fmt, ##args)
#endif
#endif
#endif
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define setup_timer(_timer, _function, _data) \
do { \
	(_timer)->function = _function; \
	(_timer)->data = _data; \
	init_timer(_timer); \
} while (0)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#if defined(skb_vlan_tag_present) && !defined(vlan_tx_tag_present)
#define vlan_tx_tag_present skb_vlan_tag_present
#endif
#if defined(skb_vlan_tag_get) && !defined(vlan_tx_tag_get)
#define vlan_tx_tag_get skb_vlan_tag_get
#endif
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)

#define RTL_ALLOC_SKB_INTR(napi, length) dev_alloc_skb(length)
#define R8125_USE_NAPI_ALLOC_SKB 0
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#undef RTL_ALLOC_SKB_INTR
#define RTL_ALLOC_SKB_INTR(napi, length) napi_alloc_skb(napi, length)
#undef R8125_USE_NAPI_ALLOC_SKB
#define R8125_USE_NAPI_ALLOC_SKB 1
#endif
#endif

#define RTL_BUILD_SKB_INTR(data, frag_size) build_skb(data, frag_size)
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#undef RTL_BUILD_SKB_INTR
#define RTL_BUILD_SKB_INTR(data, frag_size) napi_build_skb(data, frag_size)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
#define eth_random_addr(addr) random_ether_addr(addr)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#define netdev_features_t  u32
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
#define NETIF_F_ALL_CSUM        NETIF_F_CSUM_MASK
#else
#ifndef NETIF_F_ALL_CSUM
#define NETIF_F_ALL_CSUM        NETIF_F_CSUM_MASK
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
#define ENABLE_R8125_PROCFS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#define ENABLE_R8125_SYSFS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define NETIF_F_HW_VLAN_RX	NETIF_F_HW_VLAN_CTAG_RX
#define NETIF_F_HW_VLAN_TX	NETIF_F_HW_VLAN_CTAG_TX
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#define __devinit
#define __devexit
#define __devexit_p(func)   func
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define irqreturn_t void
#define IRQ_HANDLED    1
#define IRQ_NONE   0
#define IRQ_RETVAL(x)
#endif

#ifndef NETIF_F_RXALL
#define NETIF_F_RXALL  0
#endif

#ifndef NETIF_F_RXFCS
#define NETIF_F_RXFCS  0
#endif

#if !defined(HAVE_FREE_NETDEV) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0))
#define free_netdev(x)  kfree(x)
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

#ifndef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev)
#endif

#ifndef SA_SHIRQ
#define SA_SHIRQ IRQF_SHARED
#endif

#ifndef NETIF_F_GSO
#define gso_size    tso_size
#define gso_segs    tso_segs
#endif

#ifndef PCI_VENDOR_ID_DLINK
#define PCI_VENDOR_ID_DLINK 0x1186
#endif

#ifndef dma_mapping_error
#define dma_mapping_error(a,b) 0
#endif

#ifndef netif_err
#define netif_err(a,b,c,d)
#endif

#ifndef AUTONEG_DISABLE
#define AUTONEG_DISABLE   0x00
#endif

#ifndef AUTONEG_ENABLE
#define AUTONEG_ENABLE    0x01
#endif

#ifndef BMCR_SPEED1000
#define BMCR_SPEED1000  0x0040
#endif

#ifndef BMCR_SPEED100
#define BMCR_SPEED100   0x2000
#endif

#ifndef BMCR_SPEED10
#define BMCR_SPEED10    0x0000
#endif

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN   -1
#endif

#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN  0xff
#endif

#ifndef SUPPORTED_Pause
#define SUPPORTED_Pause  (1 << 13)
#endif

#ifndef SUPPORTED_Asym_Pause
#define SUPPORTED_Asym_Pause  (1 << 14)
#endif

#ifndef  MDIO_EEE_100TX
#define  MDIO_EEE_100TX  0x0002
#endif

#ifndef  MDIO_EEE_1000T
#define  MDIO_EEE_1000T  0x0004
#endif

#ifndef  MDIO_EEE_2_5GT
#define  MDIO_EEE_2_5GT  0x0001
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
#define ethtool_keee ethtool_eee
#define rtl8125_ethtool_adv_to_mmd_eee_adv_cap1_t ethtool_adv_to_mmd_eee_adv_t
static inline u32 rtl8125_ethtool_adv_to_mmd_eee_adv_cap2_t(u32 adv)
{
        u32 result = 0;

        if (adv & SUPPORTED_2500baseX_Full)
                result |= MDIO_EEE_2_5GT;

        return result;
}
#else
#define rtl8125_ethtool_adv_to_mmd_eee_adv_cap1_t linkmode_to_mii_eee_cap1_t
#define rtl8125_ethtool_adv_to_mmd_eee_adv_cap2_t linkmode_to_mii_eee_cap2_t
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#ifdef CONFIG_NET_POLL_CONTROLLER
#define RTL_NET_POLL_CONTROLLER dev->poll_controller=rtl8125_netpoll
#else
#define RTL_NET_POLL_CONTROLLER
#endif

#ifdef CONFIG_R8125_VLAN
#define RTL_SET_VLAN dev->vlan_rx_register=rtl8125_vlan_rx_register
#else
#define RTL_SET_VLAN
#endif

#define RTL_NET_DEVICE_OPS(ops) dev->open=rtl8125_open; \
                    dev->hard_start_xmit=rtl8125_start_xmit; \
                    dev->get_stats=rtl8125_get_stats; \
                    dev->stop=rtl8125_close; \
                    dev->tx_timeout=rtl8125_tx_timeout; \
                    dev->set_multicast_list=rtl8125_set_rx_mode; \
                    dev->change_mtu=rtl8125_change_mtu; \
                    dev->set_mac_address=rtl8125_set_mac_address; \
                    dev->do_ioctl=rtl8125_do_ioctl; \
                    RTL_NET_POLL_CONTROLLER; \
                    RTL_SET_VLAN;
#else
#define RTL_NET_DEVICE_OPS(ops) dev->netdev_ops=&ops
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef false
#define false 0
#endif

#ifndef true
#define true  1
#endif

//Hardware will continue interrupt 10 times after interrupt finished.
#define RTK_KEEP_INTERRUPT_COUNT (10)

//the low 32 bit address of receive buffer must be 8-byte alignment.
#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN        2
#endif
#define R8125_RX_ALIGN        NET_IP_ALIGN

#ifdef CONFIG_R8125_NAPI
#define NAPI_SUFFIX "-NAPI"
#else
#define NAPI_SUFFIX ""
#endif

#if defined(ENABLE_REALWOW_SUPPORT)
#define REALWOW_SUFFIX "-REALWOW"
#else
#define REALWOW_SUFFIX ""
#endif

#if defined(ENABLE_DASH_SUPPORT)
#define DASH_SUFFIX "-DASH"
#else
#define DASH_SUFFIX ""
#endif

#if defined(ENABLE_PTP_SUPPORT)
#define PTP_SUFFIX "-PTP"
#else
#define PTP_SUFFIX ""
#endif

#if defined(ENABLE_RSS_SUPPORT)
#define RSS_SUFFIX "-RSS"
#else
#define RSS_SUFFIX ""
#endif

#define RTL8125_VERSION "9.016.01" NAPI_SUFFIX DASH_SUFFIX REALWOW_SUFFIX PTP_SUFFIX RSS_SUFFIX
#define MODULENAME "r8125"
#define PFX MODULENAME ": "

#define GPL_CLAIM "\
r8125  Copyright (C) 2025 Realtek NIC software team <nicfae@realtek.com> \n \
This program comes with ABSOLUTELY NO WARRANTY; for details, please see <http://www.gnu.org/licenses/>. \n \
This is free software, and you are welcome to redistribute it under certain conditions; see <http://www.gnu.org/licenses/>. \n"

#ifdef RTL8125_DEBUG
#define assert(expr) \
        if(!(expr)) {                   \
            printk("Assertion failed! %s,%s,%s,line=%d\n", \
            #expr,__FILE__,__FUNCTION__,__LINE__);      \
        }
#define dprintk(fmt, args...)   do { printk(PFX fmt, ## args); } while (0)
#else
#define assert(expr) do {} while (0)
#define dprintk(fmt, args...)   do {} while (0)
#endif /* RTL8125_DEBUG */

#define R8125_MSG_DEFAULT \
    (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_IFUP | NETIF_MSG_IFDOWN)

#ifdef CONFIG_R8125_NAPI
#define rtl8125_rx_hwaccel_skb      vlan_hwaccel_receive_skb
#define rtl8125_rx_quota(count, quota)  min(count, quota)
#else
#define rtl8125_rx_hwaccel_skb      vlan_hwaccel_rx
#define rtl8125_rx_quota(count, quota)  count
#endif

#ifdef CONFIG_R8125_NAPI
#define r8125_spin_lock(lock, flags)  (void)flags;spin_lock_bh(lock)
#define r8125_spin_unlock(lock, flags)  (void)flags;spin_unlock_bh(lock)
#else
#define r8125_spin_lock(lock, flags)  spin_lock_irqsave(lock, flags)
#define r8125_spin_unlock(lock, flags)  spin_unlock_irqrestore(lock, flags)
#endif

/* MAC address length */
#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN    6
#endif

#ifndef MAC_PROTOCOL_LEN
#define MAC_PROTOCOL_LEN    2
#endif

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN	  4
#endif

#ifndef NETIF_F_TSO6
#define NETIF_F_TSO6  0
#endif

#define Reserved2_data  7
#define RX_DMA_BURST_unlimited  7   /* Maximum PCI burst, '7' is unlimited */
#define RX_DMA_BURST_512    5
#define RX_DMA_BURST_256    4
#define TX_DMA_BURST_unlimited  7
#define TX_DMA_BURST_1024   6
#define TX_DMA_BURST_512    5
#define TX_DMA_BURST_256    4
#define TX_DMA_BURST_128    3
#define TX_DMA_BURST_64     2
#define TX_DMA_BURST_32     1
#define TX_DMA_BURST_16     0
#define Reserved1_data  0x3F
#define RxPacketMaxSize 0x3FE8  /* 16K - 1 - ETH_HLEN - VLAN - CRC... */
#define Jumbo_Frame_1k  ETH_DATA_LEN
#define Jumbo_Frame_2k  (2*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_3k  (3*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_4k  (4*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_5k  (5*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_6k  (6*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_7k  (7*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_8k  (8*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define Jumbo_Frame_9k  (9*1024 - ETH_HLEN - VLAN_HLEN - ETH_FCS_LEN)
#define InterFrameGap   0x03    /* 3 means InterFrameGap = the shortest one */
#define RxEarly_off_V1 (0x07 << 11)
#define RxEarly_off_V2 (1 << 11)
#define Rx_Single_fetch_V2 (1 << 14)
#define Rx_Close_Multiple (1 << 21)
#define Rx_Fetch_Number_8 (1 << 30)

#define R8125_REGS_SIZE     (256)
#define R8125_MAC_REGS_SIZE     (256)
#define R8125_PHY_REGS_SIZE     (16*2)
#define R8125_EPHY_REGS_SIZE  	(31*2)
#define R8125_ERI_REGS_SIZE  	(0x100)
#define R8125_REGS_DUMP_SIZE     (0x400)
#define R8125_PCI_REGS_SIZE  	(0x100)
#define R8125_NAPI_WEIGHT   64

#define R8125_MAX_MSIX_VEC_8125A   4
#define R8125_MAX_MSIX_VEC_8125B   32
#define R8125_MAX_MSIX_VEC_8125D   32
#define R8125_MIN_MSIX_VEC_8125B   22
#define R8125_MIN_MSIX_VEC_8125BP  32
#define R8125_MIN_MSIX_VEC_8125CP  31
#define R8125_MIN_MSIX_VEC_8125D   20
#define R8125_MAX_MSIX_VEC   32
#define R8125_MAX_RX_QUEUES_VEC_V3 (16)

#define RTL8125_TX_TIMEOUT  (6 * HZ)
#define RTL8125_LINK_TIMEOUT    (1 * HZ)
#define RTL8125_ESD_TIMEOUT (2 * HZ)
#define RTL8125_DASH_TIMEOUT    (0)

#define rtl8125_rx_page_size(order) (PAGE_SIZE << order)

#define MAX_NUM_TX_DESC 1024    /* Maximum number of Tx descriptor registers */
#define MAX_NUM_RX_DESC 1024    /* Maximum number of Rx descriptor registers */

#define MIN_NUM_TX_DESC 256    /* Minimum number of Tx descriptor registers */
#define MIN_NUM_RX_DESC 256    /* Minimum number of Rx descriptor registers */

#define NUM_TX_DESC MAX_NUM_TX_DESC    /* Number of Tx descriptor registers */
#define NUM_RX_DESC MAX_NUM_RX_DESC    /* Number of Rx descriptor registers */

#ifdef ENABLE_DOUBLE_VLAN
#define RX_BUF_SIZE 0x05F6  /* 0x05F6(1526) = 1514 + 8(double vlan) + 4(crc) bytes */
#define RT_VALN_HLEN 8      /* 8(double vlan) bytes */
#else
#define RX_BUF_SIZE 0x05F2  /* 0x05F2(1522) = 1514 + 4(single vlan) + 4(crc) bytes */
#define RT_VALN_HLEN 4      /* 4(single vlan) bytes */
#endif

#define R8125_MAX_TX_QUEUES (2)
#define R8125_MAX_RX_QUEUES_V2 (4)
#define R8125_MAX_RX_QUEUES_V3 (16)
#define R8125_MAX_RX_QUEUES R8125_MAX_RX_QUEUES_V3
#define R8125_MAX_QUEUES R8125_MAX_RX_QUEUES

#define OCP_STD_PHY_BASE	0xa400

//Channel Wait Count
#define R8125_CHANNEL_WAIT_COUNT (20000)
#define R8125_CHANNEL_WAIT_TIME (1)  // 1us
#define R8125_CHANNEL_EXIT_DELAY_TIME (20)  //20us

#ifdef ENABLE_LIB_SUPPORT
#define R8125_MULTI_RX_Q(tp) 0
#else
#define R8125_MULTI_RX_Q(tp) (tp->num_rx_rings > 1)
#endif

#define NODE_ADDRESS_SIZE 6

#define SHORT_PACKET_PADDING_BUF_SIZE 256

#define RTK_MAGIC_DEBUG_VALUE 0x0badbeef

/* write/read MMIO register */
#define RTL_W8(tp, reg, val8)	writeb((val8), tp->mmio_addr + (reg))
#define RTL_W16(tp, reg, val16)	writew((val16), tp->mmio_addr + (reg))
#define RTL_W32(tp, reg, val32)	writel((val32), tp->mmio_addr + (reg))
#define RTL_R8(tp, reg)		readb(tp->mmio_addr + (reg))
#define RTL_R16(tp, reg)		readw(tp->mmio_addr + (reg))
#define RTL_R32(tp, reg)		((unsigned long) readl(tp->mmio_addr + (reg)))

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0      /* driver took care of packet */
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1    /* driver tx path was busy*/
#endif

#ifndef NETDEV_TX_LOCKED
#define NETDEV_TX_LOCKED -1t /* driver tx lock was already taken */
#endif

#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause    (1 << 13)
#endif

#ifndef ADVERTISED_Asym_Pause
#define ADVERTISED_Asym_Pause   (1 << 14)
#endif

#ifndef ADVERTISE_PAUSE_CAP
#define ADVERTISE_PAUSE_CAP 0x400
#endif

#ifndef ADVERTISE_PAUSE_ASYM
#define ADVERTISE_PAUSE_ASYM    0x800
#endif

#ifndef MII_CTRL1000
#define MII_CTRL1000        0x09
#endif

#ifndef ADVERTISE_1000FULL
#define ADVERTISE_1000FULL  0x200
#endif

#ifndef ADVERTISE_1000HALF
#define ADVERTISE_1000HALF  0x100
#endif

#ifndef ADVERTISED_2500baseX_Full
#define ADVERTISED_2500baseX_Full  0x8000
#endif

#define RTK_ADVERTISE_2500FULL  0x80
#define RTK_ADVERTISE_5000FULL  0x100
#define RTK_ADVERTISE_10000FULL  0x1000
#define RTK_LPA_ADVERTISE_2500FULL  0x20
#define RTK_LPA_ADVERTISE_5000FULL  0x40
#define RTK_LPA_ADVERTISE_10000FULL  0x800

#define RTK_EEE_ADVERTISE_2500FULL  BIT(0)
#define RTK_EEE_ADVERTISE_5000FULL  BIT(1)
#define RTK_LPA_EEE_ADVERTISE_2500FULL  BIT(0)
#define RTK_LPA_EEE_ADVERTISE_5000FULL  BIT(1)

/* Tx NO CLOSE */
#define MAX_TX_NO_CLOSE_DESC_PTR_V2 0x10000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V2 0xFFFF
#define MAX_TX_NO_CLOSE_DESC_PTR_V3 0x100000000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V3 0xFFFFFFFF
#define MAX_TX_NO_CLOSE_DESC_PTR_V4 0x80000000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4 0x7FFFFFFF
#define TX_NO_CLOSE_SW_PTR_MASK_V2 0x1FFFF

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU  68
#endif

#define D0_SPEED_UP_SPEED_DISABLE    0
#define D0_SPEED_UP_SPEED_1000       1
#define D0_SPEED_UP_SPEED_2500       2

#define RTL8125_MAC_MCU_PAGE_SIZE 256 //256 words

#ifndef WRITE_ONCE
#define WRITE_ONCE(var, val) (*((volatile typeof(val) *)(&(var))) = (val))
#endif
#ifndef READ_ONCE
#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))
#endif

#define R8125_LINK_STATE_OFF 0
#define R8125_LINK_STATE_ON 1
#define R8125_LINK_STATE_UNKNOWN 2

/*****************************************************************************/

//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,3)
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(2,4,27)) || \
     ((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)) && \
      (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,3))))
/* copied from linux kernel 2.6.20 include/linux/netdev.h */
#define NETDEV_ALIGN        32
#define NETDEV_ALIGN_CONST  (NETDEV_ALIGN - 1)

static inline void *netdev_priv(struct net_device *dev)
{
        return (char *)dev + ((sizeof(struct net_device)
                               + NETDEV_ALIGN_CONST)
                              & ~NETDEV_ALIGN_CONST);
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,3)

/*****************************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define RTLDEV  tp
#else
#define RTLDEV  dev
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/*****************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
typedef struct net_device *napi_ptr;
typedef int *napi_budget;

#define napi dev
#define RTL_NAPI_CONFIG(ndev, priv, function, weig) ndev->poll=function;    \
                                ndev->weight=weig;
#define RTL_NAPI_QUOTA(budget, ndev)            min(*budget, ndev->quota)
#define RTL_GET_PRIV(stuct_ptr, priv_struct)        netdev_priv(stuct_ptr)
#define RTL_GET_NETDEV(priv_ptr)
#define RTL_RX_QUOTA(budget)          *budget
#define RTL_NAPI_QUOTA_UPDATE(ndev, work_done, budget)  *budget -= work_done;   \
                                ndev->quota -= work_done;
#define RTL_NETIF_RX_COMPLETE(dev, napi, work_done)        netif_rx_complete(dev)
#define RTL_NETIF_RX_SCHEDULE_PREP(dev, napi)       netif_rx_schedule_prep(dev)
#define __RTL_NETIF_RX_SCHEDULE(dev, napi)      __netif_rx_schedule(dev)
#define RTL_NAPI_RETURN_VALUE               work_done >= work_to_do
#define RTL_NAPI_ENABLE(dev, napi)          netif_poll_enable(dev)
#define RTL_NAPI_DISABLE(dev, napi)         netif_poll_disable(dev)
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#else
typedef struct napi_struct *napi_ptr;
typedef int napi_budget;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#define RTL_NAPI_CONFIG(ndev, priv, function, weight)   netif_napi_add_weight(ndev, &priv->napi, function, weight)
#else
#define RTL_NAPI_CONFIG(ndev, priv, function, weight)   netif_napi_add(ndev, &priv->napi, function, weight)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#define RTL_NAPI_QUOTA(budget, ndev)            min(budget, budget)
#define RTL_GET_PRIV(stuct_ptr, priv_struct)        container_of(stuct_ptr, priv_struct, stuct_ptr)
#define RTL_GET_NETDEV(priv_ptr)            struct net_device *dev = priv_ptr->dev;
#define RTL_RX_QUOTA(budget)          budget
#define RTL_NAPI_QUOTA_UPDATE(ndev, work_done, budget)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define RTL_NETIF_RX_COMPLETE(dev, napi, work_done)        netif_rx_complete(dev, napi)
#define RTL_NETIF_RX_SCHEDULE_PREP(dev, napi)       netif_rx_schedule_prep(dev, napi)
#define __RTL_NETIF_RX_SCHEDULE(dev, napi)      __netif_rx_schedule(dev, napi)
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,29)
#define RTL_NETIF_RX_COMPLETE(dev, napi, work_done)        netif_rx_complete(napi)
#define RTL_NETIF_RX_SCHEDULE_PREP(dev, napi)       netif_rx_schedule_prep(napi)
#define __RTL_NETIF_RX_SCHEDULE(dev, napi)      __netif_rx_schedule(napi)
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,29)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#define RTL_NETIF_RX_COMPLETE(dev, napi, work_done)        napi_complete_done(napi, work_done)
#else
#define RTL_NETIF_RX_COMPLETE(dev, napi, work_done)        napi_complete(napi)
#endif
#define RTL_NETIF_RX_SCHEDULE_PREP(dev, napi)       napi_schedule_prep(napi)
#define __RTL_NETIF_RX_SCHEDULE(dev, napi)      __napi_schedule(napi)
#endif
#define RTL_NAPI_RETURN_VALUE work_done
#define RTL_NAPI_ENABLE(dev, napi)          napi_enable(napi)
#define RTL_NAPI_DISABLE(dev, napi)         napi_disable(napi)
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define RTL_NAPI_DEL(priv)
#else
#define RTL_NAPI_DEL(priv)   netif_napi_del(&priv->napi)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

/*****************************************************************************/
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define RTL_NAPI_CONSUME_SKB_ANY(skb, budget)          napi_consume_skb(skb, budget)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define RTL_NAPI_CONSUME_SKB_ANY(skb, budget)          dev_consume_skb_any(skb);
#else
#define RTL_NAPI_CONSUME_SKB_ANY(skb, budget)          dev_kfree_skb_any(skb);
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#else   //CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define RTL_NAPI_CONSUME_SKB_ANY(skb, budget)          dev_consume_skb_any(skb);
#else
#define RTL_NAPI_CONSUME_SKB_ANY(skb, budget)          dev_kfree_skb_any(skb);
#endif
#endif  //CONFIG_R8125_NAPI

/*****************************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#ifdef __CHECKER__
#define __iomem __attribute__((noderef, address_space(2)))
extern void __chk_io_ptr(void __iomem *);
#define __bitwise __attribute__((bitwise))
#else
#define __iomem
#define __chk_io_ptr(x) (void)0
#define __bitwise
#endif
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)

/*****************************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#ifdef __CHECKER__
#define __force __attribute__((force))
#else
#define __force
#endif
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)

#ifndef module_param
#define module_param(v,t,p) MODULE_PARM(v, "i");
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
    .vendor = (vend), .device = (dev), \
    .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

/*****************************************************************************/
/* 2.5.28 => 2.4.23 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,28))

static inline void _kc_synchronize_irq(void)
{
        synchronize_irq();
}
#undef synchronize_irq
#define synchronize_irq(X) _kc_synchronize_irq()

#include <linux/tqueue.h>
#define work_struct tq_struct
#undef INIT_WORK
#define INIT_WORK(a,b,c) INIT_TQUEUE(a,(void (*)(void *))b,c)
#undef container_of
#define container_of list_entry
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
#endif /* 2.5.28 => 2.4.17 */

/*****************************************************************************/
/* 2.6.4 => 2.6.0 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4))
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#endif /* 2.6.4 => 2.6.0 */
/*****************************************************************************/
/* 2.6.0 => 2.5.28 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
#define MODULE_INFO(version, _version)
#ifndef CONFIG_E1000_DISABLE_PACKET_SPLIT
#define CONFIG_E1000_DISABLE_PACKET_SPLIT 1
#endif

#define pci_set_consistent_dma_mask(dev,mask) 1

#undef dev_put
#define dev_put(dev) __dev_put(dev)

#ifndef skb_fill_page_desc
#define skb_fill_page_desc _kc_skb_fill_page_desc
extern void _kc_skb_fill_page_desc(struct sk_buff *skb, int i, struct page *page, int off, int size);
#endif

#ifndef pci_dma_mapping_error
#define pci_dma_mapping_error _kc_pci_dma_mapping_error
static inline int _kc_pci_dma_mapping_error(dma_addr_t dma_addr)
{
        return dma_addr == 0;
}
#endif

#undef ALIGN
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#endif /* 2.6.0 => 2.5.28 */

/*****************************************************************************/
/* 2.4.22 => 2.4.17 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,22))
#define pci_name(x) ((x)->slot_name)
#endif /* 2.4.22 => 2.4.17 */

/*****************************************************************************/
/* 2.6.5 => 2.6.0 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5))
#define pci_dma_sync_single_for_cpu pci_dma_sync_single
#define pci_dma_sync_single_for_device  pci_dma_sync_single_for_cpu
#endif /* 2.6.5 => 2.6.0 */

/*****************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
/*
 * initialize a work-struct's func and data pointers:
 */
#define PREPARE_WORK(_work, _func, _data)           \
    do {                            \
        (_work)->func = _func;              \
        (_work)->data = _data;              \
    } while (0)

#endif
/*****************************************************************************/
/* 2.6.4 => 2.6.0 */
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(2,4,25) && \
     LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && \
      LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)))
#define ETHTOOL_OPS_COMPAT
#endif /* 2.6.4 => 2.6.0 */

/*****************************************************************************/
/* Installations with ethtool version without eeprom, adapter id, or statistics
 * support */

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x1d
#undef ethtool_drvinfo
#define ethtool_drvinfo k_ethtool_drvinfo
struct k_ethtool_drvinfo {
        u32 cmd;
        char driver[32];
        char version[32];
        char fw_version[32];
        char bus_info[32];
        char reserved1[32];
        char reserved2[16];
        u32 n_stats;
        u32 testinfo_len;
        u32 eedump_len;
        u32 regdump_len;
};

struct ethtool_stats {
        u32 cmd;
        u32 n_stats;
        u64 data[0];
};
#endif /* ETHTOOL_GSTATS */

#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID 0x1c
#endif /* ETHTOOL_PHYS_ID */

#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x1b
enum ethtool_stringset {
        ETH_SS_TEST             = 0,
        ETH_SS_STATS,
};
struct ethtool_gstrings {
        u32 cmd;            /* ETHTOOL_GSTRINGS */
        u32 string_set;     /* string set id e.c. ETH_SS_TEST, etc*/
        u32 len;            /* number of strings in the string set */
        u8 data[0];
};
#endif /* ETHTOOL_GSTRINGS */

#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x1a
enum ethtool_test_flags {
        ETH_TEST_FL_OFFLINE = (1 << 0),
        ETH_TEST_FL_FAILED  = (1 << 1),
};
struct ethtool_test {
        u32 cmd;
        u32 flags;
        u32 reserved;
        u32 len;
        u64 data[0];
};
#endif /* ETHTOOL_TEST */

#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0xb
#undef ETHTOOL_GREGS
struct ethtool_eeprom {
        u32 cmd;
        u32 magic;
        u32 offset;
        u32 len;
        u8 data[0];
};

struct ethtool_value {
        u32 cmd;
        u32 data;
};
#endif /* ETHTOOL_GEEPROM */

#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0xa
#endif /* ETHTOOL_GLINK */

#ifndef ETHTOOL_GREGS
#define ETHTOOL_GREGS       0x00000004 /* Get NIC registers */
#define ethtool_regs _kc_ethtool_regs
/* for passing big chunks of data */
struct _kc_ethtool_regs {
        u32 cmd;
        u32 version; /* driver-specific, indicates different chips/revs */
        u32 len; /* bytes */
        u8 data[0];
};
#endif /* ETHTOOL_GREGS */

#ifndef ETHTOOL_GMSGLVL
#define ETHTOOL_GMSGLVL     0x00000007 /* Get driver message level */
#endif
#ifndef ETHTOOL_SMSGLVL
#define ETHTOOL_SMSGLVL     0x00000008 /* Set driver msg level, priv. */
#endif
#ifndef ETHTOOL_NWAY_RST
#define ETHTOOL_NWAY_RST    0x00000009 /* Restart autonegotiation, priv */
#endif
#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK       0x0000000a /* Get link status */
#endif
#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM     0x0000000b /* Get EEPROM data */
#endif
#ifndef ETHTOOL_SEEPROM
#define ETHTOOL_SEEPROM     0x0000000c /* Set EEPROM data */
#endif
#ifndef ETHTOOL_GCOALESCE
#define ETHTOOL_GCOALESCE   0x0000000e /* Get coalesce config */
/* for configuring coalescing parameters of chip */
#define ethtool_coalesce _kc_ethtool_coalesce
struct _kc_ethtool_coalesce {
        u32 cmd;    /* ETHTOOL_{G,S}COALESCE */

        /* How many usecs to delay an RX interrupt after
         * a packet arrives.  If 0, only rx_max_coalesced_frames
         * is used.
         */
        u32 rx_coalesce_usecs;

        /* How many packets to delay an RX interrupt after
         * a packet arrives.  If 0, only rx_coalesce_usecs is
         * used.  It is illegal to set both usecs and max frames
         * to zero as this would cause RX interrupts to never be
         * generated.
         */
        u32 rx_max_coalesced_frames;

        /* Same as above two parameters, except that these values
         * apply while an IRQ is being serviced by the host.  Not
         * all cards support this feature and the values are ignored
         * in that case.
         */
        u32 rx_coalesce_usecs_irq;
        u32 rx_max_coalesced_frames_irq;

        /* How many usecs to delay a TX interrupt after
         * a packet is sent.  If 0, only tx_max_coalesced_frames
         * is used.
         */
        u32 tx_coalesce_usecs;

        /* How many packets to delay a TX interrupt after
         * a packet is sent.  If 0, only tx_coalesce_usecs is
         * used.  It is illegal to set both usecs and max frames
         * to zero as this would cause TX interrupts to never be
         * generated.
         */
        u32 tx_max_coalesced_frames;

        /* Same as above two parameters, except that these values
         * apply while an IRQ is being serviced by the host.  Not
         * all cards support this feature and the values are ignored
         * in that case.
         */
        u32 tx_coalesce_usecs_irq;
        u32 tx_max_coalesced_frames_irq;

        /* How many usecs to delay in-memory statistics
         * block updates.  Some drivers do not have an in-memory
         * statistic block, and in such cases this value is ignored.
         * This value must not be zero.
         */
        u32 stats_block_coalesce_usecs;

        /* Adaptive RX/TX coalescing is an algorithm implemented by
         * some drivers to improve latency under low packet rates and
         * improve throughput under high packet rates.  Some drivers
         * only implement one of RX or TX adaptive coalescing.  Anything
         * not implemented by the driver causes these values to be
         * silently ignored.
         */
        u32 use_adaptive_rx_coalesce;
        u32 use_adaptive_tx_coalesce;

        /* When the packet rate (measured in packets per second)
         * is below pkt_rate_low, the {rx,tx}_*_low parameters are
         * used.
         */
        u32 pkt_rate_low;
        u32 rx_coalesce_usecs_low;
        u32 rx_max_coalesced_frames_low;
        u32 tx_coalesce_usecs_low;
        u32 tx_max_coalesced_frames_low;

        /* When the packet rate is below pkt_rate_high but above
         * pkt_rate_low (both measured in packets per second) the
         * normal {rx,tx}_* coalescing parameters are used.
         */

        /* When the packet rate is (measured in packets per second)
         * is above pkt_rate_high, the {rx,tx}_*_high parameters are
         * used.
         */
        u32 pkt_rate_high;
        u32 rx_coalesce_usecs_high;
        u32 rx_max_coalesced_frames_high;
        u32 tx_coalesce_usecs_high;
        u32 tx_max_coalesced_frames_high;

        /* How often to do adaptive coalescing packet rate sampling,
         * measured in seconds.  Must not be zero.
         */
        u32 rate_sample_interval;
};
#endif /* ETHTOOL_GCOALESCE */

#ifndef ETHTOOL_SCOALESCE
#define ETHTOOL_SCOALESCE   0x0000000f /* Set coalesce config. */
#endif
#ifndef ETHTOOL_GRINGPARAM
#define ETHTOOL_GRINGPARAM  0x00000010 /* Get ring parameters */
/* for configuring RX/TX ring parameters */
#define ethtool_ringparam _kc_ethtool_ringparam
struct _kc_ethtool_ringparam {
        u32 cmd;    /* ETHTOOL_{G,S}RINGPARAM */

        /* Read only attributes.  These indicate the maximum number
         * of pending RX/TX ring entries the driver will allow the
         * user to set.
         */
        u32 rx_max_pending;
        u32 rx_mini_max_pending;
        u32 rx_jumbo_max_pending;
        u32 tx_max_pending;

        /* Values changeable by the user.  The valid values are
         * in the range 1 to the "*_max_pending" counterpart above.
         */
        u32 rx_pending;
        u32 rx_mini_pending;
        u32 rx_jumbo_pending;
        u32 tx_pending;
};
#endif /* ETHTOOL_GRINGPARAM */

#ifndef ETHTOOL_SRINGPARAM
#define ETHTOOL_SRINGPARAM  0x00000011 /* Set ring parameters, priv. */
#endif
#ifndef ETHTOOL_GPAUSEPARAM
#define ETHTOOL_GPAUSEPARAM 0x00000012 /* Get pause parameters */
/* for configuring link flow control parameters */
#define ethtool_pauseparam _kc_ethtool_pauseparam
struct _kc_ethtool_pauseparam {
        u32 cmd;    /* ETHTOOL_{G,S}PAUSEPARAM */

        /* If the link is being auto-negotiated (via ethtool_cmd.autoneg
         * being true) the user may set 'autonet' here non-zero to have the
         * pause parameters be auto-negotiated too.  In such a case, the
         * {rx,tx}_pause values below determine what capabilities are
         * advertised.
         *
         * If 'autoneg' is zero or the link is not being auto-negotiated,
         * then {rx,tx}_pause force the driver to use/not-use pause
         * flow control.
         */
        u32 autoneg;
        u32 rx_pause;
        u32 tx_pause;
};
#endif /* ETHTOOL_GPAUSEPARAM */

#ifndef ETHTOOL_SPAUSEPARAM
#define ETHTOOL_SPAUSEPARAM 0x00000013 /* Set pause parameters. */
#endif
#ifndef ETHTOOL_GRXCSUM
#define ETHTOOL_GRXCSUM     0x00000014 /* Get RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_SRXCSUM
#define ETHTOOL_SRXCSUM     0x00000015 /* Set RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GTXCSUM
#define ETHTOOL_GTXCSUM     0x00000016 /* Get TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STXCSUM
#define ETHTOOL_STXCSUM     0x00000017 /* Set TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GSG
#define ETHTOOL_GSG     0x00000018 /* Get scatter-gather enable
* (ethtool_value) */
#endif
#ifndef ETHTOOL_SSG
#define ETHTOOL_SSG     0x00000019 /* Set scatter-gather enable
* (ethtool_value). */
#endif
#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST        0x0000001a /* execute NIC self-test, priv. */
#endif
#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS    0x0000001b /* get specified string set */
#endif
#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID     0x0000001c /* identify the NIC */
#endif
#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS      0x0000001d /* get NIC-specific statistics */
#endif
#ifndef ETHTOOL_GTSO
#define ETHTOOL_GTSO        0x0000001e /* Get TSO enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STSO
#define ETHTOOL_STSO        0x0000001f /* Set TSO enable (ethtool_value) */
#endif

#ifndef ETHTOOL_BUSINFO_LEN
#define ETHTOOL_BUSINFO_LEN 32
#endif

/*****************************************************************************/

enum RTL8125_registers {
        MAC0            = 0x00,     /* Ethernet hardware address. */
        MAC4            = 0x04,
        MAR0            = 0x08,     /* Multicast filter. */
        CounterAddrLow      = 0x10,
        CounterAddrHigh     = 0x14,
        CustomLED       = 0x18,
        TxDescStartAddrLow  = 0x20,
        TxDescStartAddrHigh = 0x24,
        TxHDescStartAddrLow = 0x28,
        TxHDescStartAddrHigh    = 0x2c,
        FLASH           = 0x30,
        INT_CFG0_8125   = 0x34,
        ERSR            = 0x36,
        ChipCmd         = 0x37,
        TxPoll          = 0x38,
        IntrMask        = 0x3C,
        IntrStatus      = 0x3E,
        TxConfig        = 0x40,
        RxConfig        = 0x44,
        TCTR            = 0x48,
        Cfg9346         = 0x50,
        Config0         = 0x51,
        Config1         = 0x52,
        Config2         = 0x53,
        Config3         = 0x54,
        Config4         = 0x55,
        Config5         = 0x56,
        TDFNR           = 0x57,
        TimeInt0        = 0x58,
        TimeInt1        = 0x5C,
        PHYAR           = 0x60,
        CSIDR           = 0x64,
        CSIAR           = 0x68,
        PHYstatus       = 0x6C,
        MACDBG          = 0x6D,
        GPIO            = 0x6E,
        PMCH            = 0x6F,
        ERIDR           = 0x70,
        ERIAR           = 0x74,
        INT_CFG1_8125   = 0x7A,
        EPHY_RXER_NUM   = 0x7C,
        EPHYAR          = 0x80,
        LEDSEL_2_8125   = 0x84,
        LEDSEL_1_8125   = 0x86,
        TimeInt2        = 0x8C,
        LEDSEL_3_8125   = 0x96,
        OCPDR           = 0xB0,
        MACOCP          = 0xB0,
        OCPAR           = 0xB4,
        SecMAC0         = 0xB4,
        SecMAC4         = 0xB8,
        PHYOCP          = 0xB8,
        DBG_reg         = 0xD1,
        TwiCmdReg       = 0xD2,
        MCUCmd_reg      = 0xD3,
        RxMaxSize       = 0xDA,
        EFUSEAR         = 0xDC,
        CPlusCmd        = 0xE0,
        IntrMitigate    = 0xE2,
        RxDescAddrLow   = 0xE4,
        RxDescAddrHigh  = 0xE8,
        MTPS            = 0xEC,
        FuncEvent       = 0xF0,
        PPSW            = 0xF2,
        FuncEventMask   = 0xF4,
        TimeInt3        = 0xF4,
        FuncPresetState = 0xF8,
        CMAC_IBCR0      = 0xF8,
        CMAC_IBCR2      = 0xF9,
        CMAC_IBIMR0     = 0xFA,
        CMAC_IBISR0     = 0xFB,
        FuncForceEvent  = 0xFC,
        //8125
        IMR0_8125          = 0x38,
        ISR0_8125          = 0x3C,
        TPPOLL_8125        = 0x90,
        IMR1_8125          = 0x800,
        ISR1_8125          = 0x802,
        IMR2_8125          = 0x804,
        ISR2_8125          = 0x806,
        IMR3_8125          = 0x808,
        ISR3_8125          = 0x80A,
        BACKUP_ADDR0_8125  = 0x19E0,
        BACKUP_ADDR1_8125  = 0X19E4,
        TCTR0_8125         = 0x0048,
        TCTR1_8125         = 0x004C,
        TCTR2_8125         = 0x0088,
        TCTR3_8125         = 0x001C,
        TIMER_INT0_8125    = 0x0058,
        TIMER_INT1_8125    = 0x005C,
        TIMER_INT2_8125    = 0x008C,
        TIMER_INT3_8125    = 0x00F4,
        INT_MITI_V2_0_RX   = 0x0A00,
        INT_MITI_V2_0_TX   = 0x0A02,
        INT_MITI_V2_1_RX   = 0x0A08,
        INT_MITI_V2_1_TX   = 0x0A0A,
        IMR_V2_CLEAR_REG_8125 = 0x0D00,
        ISR_V2_8125           = 0x0D04,
        IMR_V2_SET_REG_8125   = 0x0D0C,
        TDU_STA_8125       = 0x0D08,
        RDU_STA_8125       = 0x0D0A,
        IMR_V4_L2_CLEAR_REG_8125 = 0x0D10,
        IMR_V4_L2_SET_REG_8125   = 0x0D18,
        ISR_V4_L2_8125     = 0x0D14,
        SW_TAIL_PTR0_8125BP = 0x0D30,
        SW_TAIL_PTR1_8125BP = 0x0D38,
        HW_CLO_PTR0_8125BP = 0x0D34,
        HW_CLO_PTR1_8125BP = 0x0D3C,
        DOUBLE_VLAN_CONFIG = 0x1000,
        TX_NEW_CTRL        = 0x203E,
        TNPDS_Q1_LOW_8125  = 0x2100,
        PLA_TXQ0_IDLE_CREDIT = 0x2500,
        PLA_TXQ1_IDLE_CREDIT = 0x2504,
        SW_TAIL_PTR0_8125  = 0x2800,
        HW_CLO_PTR0_8125   = 0x2802,
        SW_TAIL_PTR0_8126  = 0x2800,
        HW_CLO_PTR0_8126   = 0x2800,
        RDSAR_Q1_LOW_8125  = 0x4000,
        RSS_CTRL_8125      = 0x4500,
        Q_NUM_CTRL_8125    = 0x4800,
        RSS_KEY_8125       = 0x4600,
        RSS_INDIRECTION_TBL_8125_V2 = 0x4700,
        EEE_TXIDLE_TIMER_8125   = 0x6048,
        /* mac ptp */
        PTP_CTRL_8125      = 0x6800,
        PTP_STATUS_8125    = 0x6802,
        PTP_ISR_8125       = 0x6804,
        PTP_IMR_8125       = 0x6805,
        PTP_TIME_CORRECT_CMD_8125    = 0x6806,
        PTP_SOFT_CONFIG_Time_NS_8125 = 0x6808,
        PTP_SOFT_CONFIG_Time_S_8125  = 0x680C,
        PTP_SOFT_CONFIG_Time_Sign    = 0x6812,
        PTP_LOCAL_Time_SUB_NS_8125   = 0x6814,
        PTP_LOCAL_Time_NS_8125       = 0x6818,
        PTP_LOCAL_Time_S_8125        = 0x681C,
        PTP_Time_SHIFTER_S_8125      = 0x6856,
        PPS_RISE_TIME_NS_8125        = 0x68A0,
        PPS_RISE_TIME_S_8125         = 0x68A4,
        PTP_EGRESS_TIME_BASE_NS_8125 = 0XCF20,
        PTP_EGRESS_TIME_BASE_S_8125  = 0XCF24,
        /* phy ptp */
        PTP_CTL                 = 0xE400,
        PTP_INER                = 0xE402,
        PTP_INSR                = 0xE404,
        PTP_SYNCE_CTL           = 0xE406,
        PTP_GEN_CFG             = 0xE408,
        PTP_CLK_CFG_8126        = 0xE410,
        PTP_CFG_NS_LO_8126      = 0xE412,
        PTP_CFG_NS_HI_8126      = 0xE414,
        PTP_CFG_S_LO_8126       = 0xE416,
        PTP_CFG_S_MI_8126       = 0xE418,
        PTP_CFG_S_HI_8126       = 0xE41A,
        PTP_TAI_CFG             = 0xE420,
        PTP_TAI_TS_S_LO         = 0xE42A,
        PTP_TAI_TS_S_HI         = 0xE42C,
        PTP_TRX_TS_STA          = 0xE430,
        PTP_TRX_TS_NS_LO        = 0xE446,
        PTP_TRX_TS_NS_HI        = 0xE448,
        PTP_TRX_TS_S_LO         = 0xE44A,
        PTP_TRX_TS_S_MI         = 0xE44C,
        PTP_TRX_TS_S_HI         = 0xE44E,


        //TCAM
        TCAM_NOTVALID_ADDR           = 0xA000,
        TCAM_VALID_ADDR              = 0xA800,
        TCAM_MAC_ADDR                = 448,
        TCAM_VLAN_TAG                = 496,
        //TCAM V2
        TCAM_NOTVALID_ADDR_V2           = 0xA000,
        TCAM_VALID_ADDR_V2              = 0xB000,
        TCAM_MAC_ADDR_V2                = 0x00,
        TCAM_VLAN_TAG_V2                = 0x03,
        //ipc2
        IB2SOC_SET     = 0x0010,
        IB2SOC_DATA    = 0x0014,
        IB2SOC_CMD     = 0x0018,
        IB2SOC_IMR     = 0x001C,

        RISC_IMR_8125BP     = 0x0D20,
        RISC_ISR_8125BP     = 0x0D22,
};

enum RTL8125_register_content {
        /* InterruptStatusBits */
        SYSErr      = 0x8000,
        PCSTimeout  = 0x4000,
        SWInt       = 0x0100,
        TxDescUnavail   = 0x0080,
        RxFIFOOver  = 0x0040,
        LinkChg     = 0x0020,
        RxDescUnavail   = 0x0010,
        TxErr       = 0x0008,
        TxOK        = 0x0004,
        RxErr       = 0x0002,
        RxOK        = 0x0001,
        RxDU1       = 0x0002,
        RxOK1       = 0x0001,

        /* RxStatusDesc */
        RxRWT = (1 << 22),
        RxRES = (1 << 21),
        RxRUNT = (1 << 20),
        RxCRC = (1 << 19),

        RxRWT_V3 = (1 << 18),
        RxRES_V3 = (1 << 20),
        RxRUNT_V3 = (1 << 19),
        RxCRC_V3 = (1 << 17),

        RxRES_V4 = (1 << 22),
        RxRUNT_V4 = (1 << 21),
        RxCRC_V4 = (1 << 20),

        /* ChipCmdBits */
        StopReq  = 0x80,
        CmdReset = 0x10,
        CmdRxEnb = 0x08,
        CmdTxEnb = 0x04,
        RxBufEmpty = 0x01,

        /* Cfg9346Bits */
        Cfg9346_EEM_MASK = 0xC0,
        Cfg9346_Lock = 0x00,
        Cfg9346_Unlock = 0xC0,
        Cfg9346_EEDO = (1 << 0),
        Cfg9346_EEDI = (1 << 1),
        Cfg9346_EESK = (1 << 2),
        Cfg9346_EECS = (1 << 3),
        Cfg9346_EEM0 = (1 << 6),
        Cfg9346_EEM1 = (1 << 7),

        /* rx_mode_bits */
        AcceptErr = 0x20,
        AcceptRunt = 0x10,
        AcceptBroadcast = 0x08,
        AcceptMulticast = 0x04,
        AcceptMyPhys = 0x02,
        AcceptAllPhys = 0x01,
        AcceppVlanPhys = 0x8000,

        /* Transmit Priority Polling*/
        HPQ = 0x80,
        NPQ = 0x40,
        FSWInt = 0x01,

        /* RxConfigBits */
        Reserved2_shift = 13,
        RxCfgDMAShift = 8,
        EnableRxDescV3 = (1 << 24),
        EnableRxDescV4_1 = (1 << 24),
        EnableOuterVlan = (1 << 23),
        EnableInnerVlan = (1 << 22),
        RxCfg_128_int_en = (1 << 15),
        RxCfg_fet_multi_en = (1 << 14),
        RxCfg_half_refetch = (1 << 13),
        RxCfg_pause_slot_en = (1 << 11),
        RxCfg_9356SEL = (1 << 6),
        EnableRxDescV4_0 = (1 << 1), //not in rcr

        /* TxConfigBits */
        TxInterFrameGapShift = 24,
        TxDMAShift = 8, /* DMA burst value (0-7) is shift this many bits */
        TxMACLoopBack = (1 << 17),  /* MAC loopback */

        /* Config1 register */
        LEDS1       = (1 << 7),
        LEDS0       = (1 << 6),
        Speed_down  = (1 << 4),
        MEMMAP      = (1 << 3),
        IOMAP       = (1 << 2),
        VPD         = (1 << 1),
        PMEnable    = (1 << 0), /* Power Management Enable */

        /* Config2 register */
        PMSTS_En    = (1 << 5),

        /* Config3 register */
        Isolate_en  = (1 << 12), /* Isolate enable */
        MagicPacket = (1 << 5), /* Wake up when receives a Magic Packet */
        LinkUp      = (1 << 4), /* This bit is reserved in RTL8125B.*/
        /* Wake up when the cable connection is re-established */
        ECRCEN      = (1 << 3), /* This bit is reserved in RTL8125B*/
        Jumbo_En0   = (1 << 2), /* This bit is reserved in RTL8125B*/
        RDY_TO_L23  = (1 << 1), /* This bit is reserved in RTL8125B*/
        Beacon_en   = (1 << 0), /* This bit is reserved in RTL8125B*/

        /* Config4 register */
        Jumbo_En1   = (1 << 1), /* This bit is reserved in RTL8125B*/

        /* Config5 register */
        BWF     = (1 << 6), /* Accept Broadcast wakeup frame */
        MWF     = (1 << 5), /* Accept Multicast wakeup frame */
        UWF     = (1 << 4), /* Accept Unicast wakeup frame */
        LanWake     = (1 << 1), /* LanWake enable/disable */
        PMEStatus   = (1 << 0), /* PME status can be reset by PCI RST# */

        /* CPlusCmd */
        EnableBist  = (1 << 15),
        Macdbgo_oe  = (1 << 14),
        Normal_mode = (1 << 13),
        Force_halfdup   = (1 << 12),
        Force_rxflow_en = (1 << 11),
        Force_txflow_en = (1 << 10),
        Cxpl_dbg_sel    = (1 << 9),//This bit is reserved in RTL8125B
        ASF     = (1 << 8),//This bit is reserved in RTL8125C
        PktCntrDisable  = (1 << 7),
        RxVlan      = (1 << 6),
        RxChkSum    = (1 << 5),
        Macdbgo_sel = 0x001C,
        INTT_0      = 0x0000,
        INTT_1      = 0x0001,
        INTT_2      = 0x0002,
        INTT_3      = 0x0003,

        /* rtl8125_PHYstatus */
        PowerSaveStatus = 0x80,
        _1000bpsL = 0x80000,
        _5000bpsF = 0x1000,
        _2500bpsF = 0x400,
        _2500bpsL = 0x200,
        TxFlowCtrl = 0x40,
        RxFlowCtrl = 0x20,
        _1000bpsF = 0x10,
        _100bps = 0x08,
        _10bps = 0x04,
        LinkStatus = 0x02,
        FullDup = 0x01,

        /* DBG_reg */
        Fix_Nak_1 = (1 << 4),
        Fix_Nak_2 = (1 << 3),
        DBGPIN_E2 = (1 << 0),

        /* ResetCounterCommand */
        CounterReset = 0x1,
        /* DumpCounterCommand */
        CounterDump = 0x8,

        /* PHY access */
        PHYAR_Flag = 0x80000000,
        PHYAR_Write = 0x80000000,
        PHYAR_Read = 0x00000000,
        PHYAR_Reg_Mask = 0x1f,
        PHYAR_Reg_shift = 16,
        PHYAR_Data_Mask = 0xffff,

        /* EPHY access */
        EPHYAR_Flag = 0x80000000,
        EPHYAR_Write = 0x80000000,
        EPHYAR_Read = 0x00000000,
        EPHYAR_Reg_Mask = 0x3f,
        EPHYAR_Reg_Mask_v2 = 0x7f,
        EPHYAR_Reg_shift = 16,
        EPHYAR_Data_Mask = 0xffff,

        /* CSI access */
        CSIAR_Flag = 0x80000000,
        CSIAR_Write = 0x80000000,
        CSIAR_Read = 0x00000000,
        CSIAR_ByteEn = 0x0f,
        CSIAR_ByteEn_shift = 12,
        CSIAR_Addr_Mask = 0x0fff,

        /* ERI access */
        ERIAR_Flag = 0x80000000,
        ERIAR_Write = 0x80000000,
        ERIAR_Read = 0x00000000,
        ERIAR_Addr_Align = 4, /* ERI access register address must be 4 byte alignment */
        ERIAR_ExGMAC = 0,
        ERIAR_MSIX = 1,
        ERIAR_ASF = 2,
        ERIAR_OOB = 2,
        ERIAR_Type_shift = 16,
        ERIAR_ByteEn = 0x0f,
        ERIAR_ByteEn_shift = 12,

        /* OCP GPHY access */
        OCPDR_Write = 0x80000000,
        OCPDR_Read = 0x00000000,
        OCPDR_Reg_Mask = 0xFF,
        OCPDR_Data_Mask = 0xFFFF,
        OCPDR_GPHY_Reg_shift = 16,
        OCPAR_Flag = 0x80000000,
        OCPAR_GPHY_Write = 0x8000F060,
        OCPAR_GPHY_Read = 0x0000F060,
        OCPR_Write = 0x80000000,
        OCPR_Read = 0x00000000,
        OCPR_Addr_Reg_shift = 16,
        OCPR_Flag = 0x80000000,
        OCP_STD_PHY_BASE_PAGE = 0x0A40,

        /* MCU Command */
        Now_is_oob = (1 << 7),
        Txfifo_empty = (1 << 5),
        Rxfifo_empty = (1 << 4),

        /* E-FUSE access */
        EFUSE_WRITE = 0x80000000,
        EFUSE_WRITE_OK  = 0x00000000,
        EFUSE_READ  = 0x00000000,
        EFUSE_READ_OK   = 0x80000000,
        EFUSE_WRITE_V3 = 0x40000000,
        EFUSE_WRITE_OK_V3  = 0x00000000,
        EFUSE_READ_V3  = 0x80000000,
        EFUSE_READ_OK_V3   = 0x00000000,
        EFUSE_Reg_Mask  = 0x03FF,
        EFUSE_Reg_Shift = 8,
        EFUSE_Check_Cnt = 300,
        EFUSE_READ_FAIL = 0xFF,
        EFUSE_Data_Mask = 0x000000FF,

        /* GPIO */
        GPIO_en = (1 << 0),

        /* PTP */
        PTP_ISR_TOK = (1 << 1),
        PTP_ISR_TER = (1 << 2),
        PTP_EXEC_CMD = (1 << 7),
        PTP_ADJUST_TIME_NS_NEGATIVE = (1 << 30),
        PTP_ADJUST_TIME_S_NEGATIVE = (1ULL << 48),
        PTP_SOFT_CONFIG_TIME_NS_NEGATIVE = (1 << 30),
        PTP_SOFT_CONFIG_TIME_S_NEGATIVE = (1ULL << 48),

        /* New Interrupt Bits */
        INT_CFG0_ENABLE_8125 = (1 << 0),
        INT_CFG0_TIMEOUT0_BYPASS_8125 = (1 << 1),
        INT_CFG0_MITIGATION_BYPASS_8125 = (1 << 2),
        INT_CFG0_RDU_BYPASS_8126 = (1 << 4),
        INT_CFG0_MSIX_ENTRY_NUM_MODE = (1 << 5),
        INT_CFG0_AUTO_CLEAR_IMR = (1 << 5),
        INT_CFG0_AVOID_MISS_INTR = (1 << 6),
        ISRIMR_V2_ROK_Q0     = (1 << 0),
        ISRIMR_TOK_Q0        = (1 << 16),
        ISRIMR_TOK_Q1        = (1 << 18),
        ISRIMR_V2_LINKCHG    = (1 << 21),

        ISRIMR_V4_ROK_Q0     = (1 << 0),
        ISRIMR_V4_LINKCHG    = (1 << 29),
        ISRIMR_V4_LAYER2_INTR_STS = (1 << 31),
        ISRIMR_V4_L2_IPC2    = (1 << 17),

        ISRIMR_V5_ROK_Q0     = (1 << 0),
        ISRIMR_V5_TOK_Q0     = (1 << 16),
        ISRIMR_V5_TOK_Q1     = (1 << 17),
        ISRIMR_V5_LINKCHG    = (1 << 18),

        ISRIMR_V7_ROK_Q0     = (1 << 0),
        ISRIMR_V7_TOK_Q0     = (1 << 27),
        ISRIMR_V7_TOK_Q1     = (1 << 28),
        ISRIMR_V7_LINKCHG    = (1 << 29),

        /* IPC2 */
        RISC_IPC2_INTR    = (1 << 1),

        /* Magic Number */
        RTL8125_MAGIC_NUMBER = 0x0badbadbadbadbadull,
};

enum _DescStatusBit {
        DescOwn     = (1 << 31), /* Descriptor is owned by NIC */
        RingEnd     = (1 << 30), /* End of descriptor ring */
        FirstFrag   = (1 << 29), /* First segment of a packet */
        LastFrag    = (1 << 28), /* Final segment of a packet */

        DescOwn_V3     = (DescOwn), /* Descriptor is owned by NIC */
        RingEnd_V3     = (RingEnd), /* End of descriptor ring */
        FirstFrag_V3   = (1 << 25), /* First segment of a packet */
        LastFrag_V3    = (1 << 24), /* Final segment of a packet */

        DescOwn_V4     = (DescOwn), /* Descriptor is owned by NIC */
        RingEnd_V4     = (RingEnd), /* End of descriptor ring */
        FirstFrag_V4   = (FirstFrag), /* First segment of a packet */
        LastFrag_V4    = (LastFrag), /* Final segment of a packet */

        /* Tx private */
        /*------ offset 0 of tx descriptor ------*/
        LargeSend   = (1 << 27), /* TCP Large Send Offload (TSO) */
        GiantSendv4 = (1 << 26), /* TCP Giant Send Offload V4 (GSOv4) */
        GiantSendv6 = (1 << 25), /* TCP Giant Send Offload V6 (GSOv6) */
        LargeSend_DP = (1 << 16), /* TCP Large Send Offload (TSO) */
        MSSShift    = 16,        /* MSS value position */
        MSSMask     = 0x7FFU,    /* MSS value 11 bits */
        TxIPCS      = (1 << 18), /* Calculate IP checksum */
        TxUDPCS     = (1 << 17), /* Calculate UDP/IP checksum */
        TxTCPCS     = (1 << 16), /* Calculate TCP/IP checksum */
        TxVlanTag   = (1 << 17), /* Add VLAN tag */

        /*@@@@@@ offset 4 of tx descriptor => bits for RTL8125 only     begin @@@@@@*/
        TxUDPCS_C   = (1 << 31), /* Calculate UDP/IP checksum */
        TxTCPCS_C   = (1 << 30), /* Calculate TCP/IP checksum */
        TxIPCS_C    = (1 << 29), /* Calculate IP checksum */
        TxIPV6F_C   = (1 << 28), /* Indicate it is an IPv6 packet */
        /*@@@@@@ offset 4 of tx descriptor => bits for RTL8125 only     end @@@@@@*/


        /* Rx private */
        /*------ offset 0 of rx descriptor ------*/
        PID1        = (1 << 18), /* Protocol ID bit 1/2 */
        PID0        = (1 << 17), /* Protocol ID bit 2/2 */

#define RxProtoUDP  (PID1)
#define RxProtoTCP  (PID0)
#define RxProtoIP   (PID1 | PID0)
#define RxProtoMask RxProtoIP

        RxIPF       = (1 << 16), /* IP checksum failed */
        RxUDPF      = (1 << 15), /* UDP/IP checksum failed */
        RxTCPF      = (1 << 14), /* TCP/IP checksum failed */
        RxVlanTag   = (1 << 16), /* VLAN tag available */

        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxUDPT      = (1 << 18),
        RxTCPT      = (1 << 17),
        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     end @@@@@@*/

        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxV6F       = (1 << 31),
        RxV4F       = (1 << 30),
        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     end @@@@@@*/


        PID1_v3        = (1 << 29), /* Protocol ID bit 1/2 */
        PID0_v3        = (1 << 28), /* Protocol ID bit 2/2 */

#define RxProtoUDP_v3  (PID1_v3)
#define RxProtoTCP_v3  (PID0_v3)
#define RxProtoIP_v3   (PID1_v3 | PID0_v3)
#define RxProtoMask_v3 RxProtoIP_v3

        RxIPF_v3       = (1 << 26), /* IP checksum failed */
        RxUDPF_v3      = (1 << 25), /* UDP/IP checksum failed */
        RxTCPF_v3      = (1 << 24), /* TCP/IP checksum failed */
        RxSCTPF_v3     = (1 << 23), /* SCTP checksum failed */
        RxVlanTag_v3   = (RxVlanTag), /* VLAN tag available */

        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxUDPT_v3      = (1 << 29),
        RxTCPT_v3      = (1 << 28),
        RxSCTP_v3      = (1 << 27),
        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     end @@@@@@*/

        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxV6F_v3       = (RxV6F),
        RxV4F_v3       = (RxV4F),
        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     end @@@@@@*/

        RxIPF_v4       = (1 << 17), /* IP checksum failed */
        RxUDPF_v4      = (1 << 16), /* UDP/IP checksum failed */
        RxTCPF_v4      = (1 << 15), /* TCP/IP checksum failed */
        RxSCTPF_v4     = (1 << 19), /* SCTP checksum failed */
        RxVlanTag_v4   = (RxVlanTag), /* VLAN tag available */

        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxUDPT_v4      = (1 << 19),
        RxTCPT_v4      = (1 << 18),
        RxSCTP_v4      = (1 << 19),
        /*@@@@@@ offset 0 of rx descriptor => bits for RTL8125 only     end @@@@@@*/

        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     begin @@@@@@*/
        RxV6F_v4       = (RxV6F),
        RxV4F_v4       = (RxV4F),
        /*@@@@@@ offset 4 of rx descriptor => bits for RTL8125 only     end @@@@@@*/
};

enum features {
//  RTL_FEATURE_WOL = (1 << 0),
        RTL_FEATURE_MSI = (1 << 1),
        RTL_FEATURE_MSIX = (1 << 2),
};

enum wol_capability {
        WOL_DISABLED = 0,
        WOL_ENABLED = 1
};

enum bits {
        BIT_0 = (1 << 0),
        BIT_1 = (1 << 1),
        BIT_2 = (1 << 2),
        BIT_3 = (1 << 3),
        BIT_4 = (1 << 4),
        BIT_5 = (1 << 5),
        BIT_6 = (1 << 6),
        BIT_7 = (1 << 7),
        BIT_8 = (1 << 8),
        BIT_9 = (1 << 9),
        BIT_10 = (1 << 10),
        BIT_11 = (1 << 11),
        BIT_12 = (1 << 12),
        BIT_13 = (1 << 13),
        BIT_14 = (1 << 14),
        BIT_15 = (1 << 15),
        BIT_16 = (1 << 16),
        BIT_17 = (1 << 17),
        BIT_18 = (1 << 18),
        BIT_19 = (1 << 19),
        BIT_20 = (1 << 20),
        BIT_21 = (1 << 21),
        BIT_22 = (1 << 22),
        BIT_23 = (1 << 23),
        BIT_24 = (1 << 24),
        BIT_25 = (1 << 25),
        BIT_26 = (1 << 26),
        BIT_27 = (1 << 27),
        BIT_28 = (1 << 28),
        BIT_29 = (1 << 29),
        BIT_30 = (1 << 30),
        BIT_31 = (1 << 31)
};

/* Phy Fuse Dout */
#define R8125_PHY_FUSE_DOUT_NUM (32)
#define R8125_MAX_PHY_FUSE_DOUT_NUM R8125_PHY_FUSE_DOUT_NUM

#define RTL8125_CP_NUM 4
#define RTL8125_MAX_SUPPORT_CP_LEN 110

enum rtl8125_cp_status {
        rtl8125_cp_normal = 0,
        rtl8125_cp_short,
        rtl8125_cp_open,
        rtl8125_cp_mismatch,
        rtl8125_cp_unknown
};

enum efuse {
        EFUSE_NOT_SUPPORT = 0,
        EFUSE_SUPPORT_V1,
        EFUSE_SUPPORT_V2,
        EFUSE_SUPPORT_V3,
        EFUSE_SUPPORT_V4,
};
#define RsvdMask    0x3fffc000
#define RsvdMaskV3  0x3fff8000
#define RsvdMaskV4  RsvdMaskV3

struct TxDesc {
        u32 opts1;
        u32 opts2;
        u64 addr;
        u32 reserved0;
        u32 reserved1;
        u32 reserved2;
        u32 reserved3;
};

struct RxDesc {
        u32 opts1;
        u32 opts2;
        u64 addr;
};

struct RxDescV3 {
        union {
                struct {
                        u32 rsv1;
                        u32 rsv2;
                } RxDescDDWord1;
        };

        union {
                struct {
                        u32 RSSResult;
                        u16 HeaderBufferLen;
                        u16 HeaderInfo;
                } RxDescNormalDDWord2;

                struct {
                        u32 rsv5;
                        u32 rsv6;
                } RxDescDDWord2;
        };

        union {
                u64   addr;

                struct {
                        u32 TimeStampLow;
                        u32 TimeStampHigh;
                } RxDescTimeStamp;

                struct {
                        u32 rsv8;
                        u32 rsv9;
                } RxDescDDWord3;
        };

        union {
                struct {
                        u32 opts2;
                        u32 opts1;
                } RxDescNormalDDWord4;

                struct {
                        u16 TimeStampHHigh;
                        u16 rsv11;
                        u32 opts1;
                } RxDescPTPDDWord4;
        };
};

struct RxDescV4 {
        union {
                u64   addr;

                struct {
                        u32 RSSInfo;
                        u32 RSSResult;
                } RxDescNormalDDWord1;
        };

        struct {
                u32 opts2;
                u32 opts1;
        } RxDescNormalDDWord2;
};

enum rxdesc_type {
        RXDESC_TYPE_NORMAL=0,
        RXDESC_TYPE_NEXT,
        RXDESC_TYPE_PTP,
        RXDESC_TYPE_MAX
};

//Rx Desc Type
enum rx_desc_ring_type {
        RX_DESC_RING_TYPE_UNKNOWN=0,
        RX_DESC_RING_TYPE_1,
        RX_DESC_RING_TYPE_2,
        RX_DESC_RING_TYPE_3,
        RX_DESC_RING_TYPE_4,
        RX_DESC_RING_TYPE_MAX
};

enum rx_desc_len {
        RX_DESC_LEN_TYPE_1 = (sizeof(struct RxDesc)),
        RX_DESC_LEN_TYPE_3 = (sizeof(struct RxDescV3)),
        RX_DESC_LEN_TYPE_4 = (sizeof(struct RxDescV4))
};

struct ring_info {
        struct sk_buff  *skb;
        u32     len;
        unsigned int   bytecount;
        unsigned short gso_segs;
        u8      __pad[sizeof(void *) - sizeof(u32)];
};

struct pci_resource {
        u8  cmd;
        u8  cls;
        u16 io_base_h;
        u16 io_base_l;
        u16 mem_base_h;
        u16 mem_base_l;
        u8  ilr;
        u16 resv_0x1c_h;
        u16 resv_0x1c_l;
        u16 resv_0x20_h;
        u16 resv_0x20_l;
        u16 resv_0x24_h;
        u16 resv_0x24_l;
        u16 resv_0x2c_h;
        u16 resv_0x2c_l;
        u32 pci_sn_l;
        u32 pci_sn_h;
};

enum r8125_dash_req_flag {
        R8125_RCV_REQ_SYS_OK = 0,
        R8125_RCV_REQ_DASH_OK,
        R8125_SEND_REQ_HOST_OK,
        R8125_CMAC_RESET,
        R8125_CMAC_DISALE_RX_FLAG_MAX,
        R8125_DASH_REQ_FLAG_MAX
};

enum r8125_flag {
        R8125_FLAG_DOWN = 0,
        R8125_FLAG_TASK_RESET_PENDING,
        R8125_FLAG_TASK_ESD_CHECK_PENDING,
        R8125_FLAG_TASK_LINKCHG_CHECK_PENDING,
        R8125_FLAG_TASK_LINK_CHECK_PENDING,
        R8125_FLAG_TASK_DASH_CHECK_PENDING,
        R8125_FLAG_MAX
};

enum r8125_sysfs_flag {
        R8125_SYSFS_RTL_ADV = 0,
        R8125_SYSFS_FLAG_MAX
};

struct rtl8125_tx_ring {
        void* priv;
        struct net_device *netdev;
        u32 index;
        u32 cur_tx; /* Index into the Tx descriptor buffer of next Rx pkt. */
        u32 dirty_tx;
        u32 num_tx_desc; /* Number of Tx descriptor registers */
        struct TxDesc *TxDescArray; /* 256-aligned Tx descriptor ring */
        dma_addr_t TxPhyAddr;
        u32 TxDescAllocSize;
        struct ring_info tx_skb[MAX_NUM_TX_DESC]; /* Tx data buffers */

        u32 NextHwDesCloPtr;
        u32 BeginHwDesCloPtr;

        u16 hw_clo_ptr_reg;
        u16 sw_tail_ptr_reg;

        u16 tdsar_reg; /* Transmit Descriptor Start Address */
};

struct rtl8125_rx_buffer {
        struct page *page;
        u32 page_offset;
        dma_addr_t dma;
        void* data;
        struct sk_buff *skb;
};

struct rtl8125_rx_ring {
        void* priv;
        struct net_device *netdev;
        u32 index;
        u32 cur_rx; /* Index into the Rx descriptor buffer of next Rx pkt. */
        u32 dirty_rx;
        u32 num_rx_desc; /* Number of Rx descriptor registers */
        struct RxDesc *RxDescArray; /* 256-aligned Rx descriptor ring */
        u32 RxDescAllocSize;
        u64 RxDescPhyAddr[MAX_NUM_RX_DESC]; /* Rx desc physical address*/
        dma_addr_t RxPhyAddr;
#ifdef ENABLE_PAGE_REUSE
        struct rtl8125_rx_buffer rx_buffer[MAX_NUM_RX_DESC];
        u16 rx_offset;
#else
        struct sk_buff *Rx_skbuff[MAX_NUM_RX_DESC]; /* Rx data buffers */
#endif //ENABLE_PAGE_REUSE

        u16 rdsar_reg; /* Receive Descriptor Start Address */
};

struct r8125_napi {
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
        struct napi_struct napi;
#endif
#endif
        void* priv;
        int index;
};

struct r8125_irq {
        irq_handler_t	handler;
        unsigned int	vector;
        u8		requested;
        char		name[IFNAMSIZ + 10];
};

#pragma pack(1)
struct rtl8125_regs {
        //00
        u8 mac_id[6];
        u16 reg_06;
        u8 mar[8];
        //10
        u64 dtccr;
        u16 ledsel0;
        u16 legreg;
        u32 tctr3;
        //20
        u32 txq0_dsc_st_addr_0;
        u32 txq0_dsc_st_addr_2;
        u64 reg_28;
        //30
        u16 rit;
        u16 ritc;
        u16 reg_34;
        u8 reg_36;
        u8 command;
        u32 imr0;
        u32 isr0;
        //40
        u32 tcr;
        u32 rcr;
        u32 tctr0;
        u32 tctr1;
        //50
        u8 cr93c46;
        u8 config0;
        u8 config1;
        u8 config2;
        u8 config3;
        u8 config4;
        u8 config5;
        u8 tdfnr;
        u32 timer_int0;
        u32 timer_int1;
        //60
        u32 gphy_mdcmdio;
        u32 csidr;
        u32 csiar;
        u16 phy_status;
        u8 config6;
        u8 pmch;
        //70
        u32 eridr;
        u32 eriar;
        u16 config7;
        u16 reg_7a;
        u32 ephy_rxerr_cnt;
        //80
        u32 ephy_mdcmdio;
        u16 ledsel2;
        u16 ledsel1;
        u32 tctr2;
        u32 timer_int2;
        //90
        u8 tppoll0;
        u8 reg_91;
        u16 reg_92;
        u16 led_feature;
        u16 ledsel3;
        u16 eee_led_config;
        u16 reg_9a;
        u32 reg_9c;
        //a0
        u32 reg_a0;
        u32 reg_a4;
        u32 reg_a8;
        u32 reg_ac;
        //b0
        u32 patch_dbg;
        u32 reg_b4;
        u32 gphy_ocp;
        u32 reg_bc;
        //c0
        u32 reg_c0;
        u32 reg_c4;
        u32 reg_c8;
        u16 otp_cmd;
        u16 otp_pg_config;
        //d0
        u16 phy_pwr;
        u8 twsi_ctrl;
        u8 oob_ctrl;
        u16 mac_dbgo;
        u16 mac_dbg;
        u16 reg_d8;
        u16 rms;
        u32 efuse_data;
        //e0
        u16 cplus_cmd;
        u16 reg_e2;
        u32 rxq0_dsc_st_addr_0;
        u32 rxq0_dsc_st_addr_2;
        u16 reg_ec;
        u16 tx10midle_cnt;
        //f0
        u16 misc0;
        u16 misc1;
        u32 timer_int3;
        u32 cmac_ib;
        u16 reg_fc;
        u16 sw_rst;
};
#pragma pack()

struct rtl8125_regs_save {
        union {
                u8 mac_io[R8125_MAC_REGS_SIZE];

                struct rtl8125_regs mac_reg;
        };
        u16 pcie_phy[R8125_EPHY_REGS_SIZE/2];
        u16 eth_phy[R8125_PHY_REGS_SIZE/2];
        u32 eri_reg[R8125_ERI_REGS_SIZE/4];
        u32 pci_reg[R8125_PCI_REGS_SIZE/4];
        u16 sw_tail_ptr_reg[R8125_MAX_TX_QUEUES];
        u16 hw_clo_ptr_reg[R8125_MAX_TX_QUEUES];

        //ktime_t begin_ktime;
        //ktime_t end_ktime;
        //u64 duration_ns;

        u16 sw0_tail_ptr;
        u16 next_hwq0_clo_ptr;
        u16 sw1_tail_ptr;
        u16 next_hwq1_clo_ptr;

        u16 int_miti_rxq0;
        u16 int_miti_txq0;
        u16 int_miti_rxq1;
        u16 int_miti_txq1;
        u8 int_config;
        u32 imr_new;
        u32 isr_new;

        u8 tdu_status;
        u16 rdu_status;

        u16 tc_mode;

        u32 txq1_dsc_st_addr_0;
        u32 txq1_dsc_st_addr_2;

        u32 pla_tx_q0_idle_credit;
        u32 pla_tx_q1_idle_credit;

        u32 rxq1_dsc_st_addr_0;
        u32 rxq1_dsc_st_addr_2;

        u32 rss_ctrl;
        u8 rss_key[RTL8125_RSS_KEY_SIZE];
        u8 rss_i_table[RTL8125_MAX_INDIRECTION_TABLE_ENTRIES];
        u16 rss_queue_num_sel_r;
};

struct rtl8125_counters {
        /* legacy */
        u64 tx_packets;
        u64 rx_packets;
        u64 tx_errors;
        u32 rx_errors;
        u16 rx_missed;
        u16 align_errors;
        u32 tx_one_collision;
        u32 tx_multi_collision;
        u64 rx_unicast;
        u64 rx_broadcast;
        u32 rx_multicast;
        u16 tx_aborted;
        u16 tx_underrun;

        /* extended */
        u64 tx_octets;
        u64 rx_octets;
        u64 rx_multicast64;
        u64 tx_unicast64;
        u64 tx_broadcast64;
        u64 tx_multicast64;
        u32 tx_pause_on;
        u32 tx_pause_off;
        u32 tx_pause_all;
        u32 tx_deferred;
        u32 tx_late_collision;
        u32 tx_all_collision;
        u32 tx_aborted32;
        u32 align_errors32;
        u32 rx_frame_too_long;
        u32 rx_runt;
        u32 rx_pause_on;
        u32 rx_pause_off;
        u32 rx_pause_all;
        u32 rx_unknown_opcode;
        u32 rx_mac_error;
        u32 tx_underrun32;
        u32 rx_mac_missed;
        u32 rx_tcam_dropped;
        u32 tdu;
        u32 rdu;
};

/* Flow Control Settings */
enum rtl8125_fc_mode {
        rtl8125_fc_none = 0,
        rtl8125_fc_rx_pause,
        rtl8125_fc_tx_pause,
        rtl8125_fc_full,
        rtl8125_fc_default
};

enum rtl8125_state_t {
        __RTL8125_TESTING = 0,
        __RTL8125_RESETTING,
        __RTL8125_DOWN,
        __RTL8125_PTP_TX_IN_PROGRESS,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
struct ethtool_eee {
        __u32	cmd;
        __u32	supported;
        __u32	advertised;
        __u32	lp_advertised;
        __u32	eee_active;
        __u32	eee_enabled;
        __u32	tx_lpi_enabled;
        __u32	tx_lpi_timer;
        __u32	reserved[2];
};
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0) */

struct rtl8125_private {
        void __iomem *mmio_addr;    /* memory map physical address */
        struct pci_dev *pci_dev;    /* Index of PCI device */
        struct net_device *dev;
        struct r8125_napi r8125napi[R8125_MAX_MSIX_VEC];
        struct r8125_irq irq_tbl[R8125_MAX_MSIX_VEC];
        unsigned int irq_nvecs;
        unsigned int max_irq_nvecs;
        unsigned int min_irq_nvecs;
        unsigned int hw_supp_irq_nvecs;
        //struct msix_entry msix_entries[R8125_MAX_MSIX_VEC];
        struct net_device_stats stats;  /* statistics of net device */
        unsigned long state;
        u8 flags;

        u32 msg_enable;
        u32 tx_tcp_csum_cmd;
        u32 tx_udp_csum_cmd;
        u32 tx_ip_csum_cmd;
        u32 tx_ipv6_csum_cmd;
        int max_jumbo_frame_size;
        int chipset;
        u32 mcfg;
        //u32 cur_rx; /* Index into the Rx descriptor buffer of next Rx pkt. */
        //u32 cur_tx; /* Index into the Tx descriptor buffer of next Rx pkt. */
        //u32 dirty_rx;
        //u32 dirty_tx;
        //struct TxDesc *TxDescArray; /* 256-aligned Tx descriptor ring */
        //struct RxDesc *RxDescArray; /* 256-aligned Rx descriptor ring */
        //dma_addr_t TxPhyAddr;
        //dma_addr_t RxPhyAddr;
        //struct sk_buff *Rx_skbuff[MAX_NUM_RX_DESC]; /* Rx data buffers */
        //struct ring_info tx_skb[MAX_NUM_TX_DESC];   /* Tx data buffers */
        unsigned rx_buf_sz;
#ifdef ENABLE_PAGE_REUSE
        unsigned rx_buf_page_order;
        unsigned rx_buf_page_size;
        u32 page_reuse_fail_cnt;
#endif //ENABLE_PAGE_REUSE
        u16 HwSuppNumTxQueues;
        u16 HwSuppNumRxQueues;
        unsigned int num_tx_rings;
        unsigned int num_rx_rings;
        struct rtl8125_tx_ring tx_ring[R8125_MAX_TX_QUEUES];
        struct rtl8125_rx_ring rx_ring[R8125_MAX_RX_QUEUES];
#ifdef ENABLE_LIB_SUPPORT
        struct blocking_notifier_head lib_nh;
        struct rtl8125_ring lib_tx_ring[R8125_MAX_TX_QUEUES];
        struct rtl8125_ring lib_rx_ring[R8125_MAX_RX_QUEUES];
#endif
        //struct timer_list esd_timer;
        //struct timer_list link_timer;
        struct pci_resource pci_cfg_space;
        unsigned int esd_flag;
        unsigned int pci_cfg_is_read;
        unsigned int rtl8125_rx_config;
        u16 rms;
        u16 cp_cmd;
        u32 intr_mask;
        u32 intr_l2_mask;
        u32 timer_intr_mask;
        u16 isr_reg[R8125_MAX_MSIX_VEC];
        u16 imr_reg[R8125_MAX_MSIX_VEC];
        int phy_auto_nego_reg;
        int phy_1000_ctrl_reg;
        int phy_2500_ctrl_reg;
        u8 org_mac_addr[NODE_ADDRESS_SIZE];
        struct rtl8125_counters *tally_vaddr;
        dma_addr_t tally_paddr;

#ifdef CONFIG_R8125_VLAN
        struct vlan_group *vlgrp;
#endif
        u8  wol_enabled;
        u32 wol_opts;
        u8  efuse_ver;
        u8  eeprom_type;
        u8  autoneg;
        u8  duplex;
        u32 speed;
        u64 advertising;
        enum rtl8125_fc_mode fcpause;
        u32 HwSuppMaxPhyLinkSpeed;
        u16 eeprom_len;
        u16 cur_page;
        u32 bios_setting;

        int (*set_speed)(struct net_device *, u8 autoneg, u32 speed, u8 duplex, u64 adv);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        void (*get_settings)(struct net_device *, struct ethtool_cmd *);
#else
        void (*get_settings)(struct net_device *, struct ethtool_link_ksettings *);
#endif
        void (*phy_reset_enable)(struct net_device *);
        unsigned int (*phy_reset_pending)(struct net_device *);
        unsigned int (*link_ok)(struct net_device *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
        struct work_struct reset_task;
        struct work_struct esd_task;
        struct work_struct linkchg_task;
        struct work_struct link_task;
        struct work_struct dash_task;
#else
        struct delayed_work reset_task;
        struct delayed_work esd_task;
        struct delayed_work linkchg_task;
        struct delayed_work link_task;
        struct delayed_work dash_task;
#endif
        DECLARE_BITMAP(task_flags, R8125_FLAG_MAX);
        unsigned features;

        u8 org_pci_offset_99;
        u8 org_pci_offset_180;
        u8 issue_offset_99_event;

        u8 org_pci_offset_80;
        u8 org_pci_offset_81;
        u8 use_timer_interrupt;

        u32 keep_intr_cnt;

        u8  HwIcVerUnknown;
        u8  NotWrRamCodeToMicroP;
        u8  NotWrMcuPatchCode;
        u8  HwHasWrRamCodeToMicroP;

        u16 sw_ram_code_ver;
        u16 hw_ram_code_ver;

        u8 rtk_enable_diag;

        u8 ShortPacketSwChecksum;

        u8 UseSwPaddingShortPkt;

        u8 RequireAdcBiasPatch;
        u16 AdcBiasPatchIoffset;

        u8 RequireAdjustUpsTxLinkPulseTiming;
        u16 SwrCnt1msIni;

        u8 HwSuppNowIsOobVer;

        u8 RequiredSecLanDonglePatch;

        u8 RequiredPfmPatch;

        u8 RequirePhyMdiSwapPatch;

        u8 RequireLSOPatch;

        u32 HwFiberModeVer;
        u32 HwFiberStat;
        u8 HwSwitchMdiToFiber;

        u16 BackupLedSel[4];

        u8 HwSuppMagicPktVer;

        u8 HwSuppLinkChgWakeUpVer;

        u8 HwSuppCheckPhyDisableModeVer;

        u8 random_mac;

        u16 phy_reg_aner;
        u16 phy_reg_anlpar;
        u16 phy_reg_gbsr;
        u16 phy_reg_status_2500;

        u32 HwPcieSNOffset;

        u8 HwSuppEsdVer;
        u8 TestPhyOcpReg;
        u16 BackupPhyFuseDout[R8125_MAX_PHY_FUSE_DOUT_NUM];

        u32 MaxTxDescPtrMask;
        u8 HwSuppTxNoCloseVer;
        u8 EnableTxNoClose;

        u8 HwSuppIsrVer;
        u8 HwCurrIsrVer;

        u8 HwSuppIntMitiVer;

        u8 HwSuppExtendTallyCounterVer;

        u8 check_keep_link_speed;
        u8 resume_not_chg_speed;

        u8 HwSuppD0SpeedUpVer;
        u8 D0SpeedUpSpeed;

        u8 ring_lib_enabled;

        const char *fw_name;
        struct rtl8125_fw *rtl_fw;
        u32 ocp_base;

        //Dash+++++++++++++++++
        u8 HwSuppDashVer;
        u8 DASH;
        u8 HwPkgDet;
        u8 HwSuppOcpChannelVer;
        u32 DashFirmwareVersion;
        u32 SizeOfSendToFwBuffer;
        u32 SizeOfRecvFromFwBuffer;
        u8 AllowAccessDashOcp;
        DECLARE_BITMAP(dash_req_flags, R8125_DASH_REQ_FLAG_MAX);

#ifdef ENABLE_DASH_SUPPORT
        u16 AfterRecvFromFwBufLen;
        u8 AfterRecvFromFwBuf[RECV_FROM_FW_BUF_SIZE];
        u32 RecvFromFwBufErrCnt;
        u16 AfterSendToFwBufLen;
        u8 AfterSendToFwBuf[SEND_TO_FW_BUF_SIZE];
        u16 SendToFwBufferLen;

        u8 OobReq;
        u8 OobAck;
        u32 OobReqComplete;
        u32 OobAckComplete;

        u8 SendingToFw;

        u32 RecvFromDashFwCnt;

        u8 DashReqRegValue;

        //Dash-----------------
#endif //ENABLE_DASH_SUPPORT

        //Realwow++++++++++++++
        u8 HwSuppKCPOffloadVer;

        u8 EnableDhcpTimeoutWake;
        u8 EnableTeredoOffload;
        u8 EnableKCPOffload;
#ifdef ENABLE_REALWOW_SUPPORT
        u32 DhcpTimeout;
        MP_KCP_INFO MpKCPInfo;
        //Realwow--------------
#endif //ENABLE_REALWOW_SUPPORT

        struct ethtool_keee eee;

#ifdef ENABLE_R8125_PROCFS
        //Procfs support
        struct proc_dir_entry *proc_dir;
        struct proc_dir_entry *proc_dir_debug;
        struct proc_dir_entry *proc_dir_test;
#endif
#ifdef ENABLE_R8125_SYSFS
        //sysfs support
        DECLARE_BITMAP(sysfs_flag, R8125_SYSFS_FLAG_MAX);
        u32 testmode;
#endif
        u8 HwSuppRxDescType;
        u8 InitRxDescType;
        u16 RxDescLength; //V1 16 Byte V2 32 Bytes

        spinlock_t phy_lock;

        u8 HwSuppPtpVer;
        u8 EnablePtp;
        u8 ptp_master_mode;
#ifdef ENABLE_PTP_SUPPORT
        u32 tx_hwtstamp_timeouts;
        u32 tx_hwtstamp_skipped;
        struct work_struct ptp_tx_work;
        struct sk_buff *ptp_tx_skb;
        struct hwtstamp_config hwtstamp_config;
        unsigned long ptp_tx_start;
        struct ptp_clock_info ptp_clock_info;
        struct ptp_clock *ptp_clock;
        u8 syncE_en;
        u8 pps_enable;
        struct hrtimer pps_timer;
#endif

        u8 HwSuppRssVer;
        u8 EnableRss;
        u16 HwSuppIndirTblEntries;
#ifdef ENABLE_RSS_SUPPORT
        u32 rss_flags;
        /* Receive Side Scaling settings */
        u8 rss_key[RTL8125_RSS_KEY_SIZE];
        u8 rss_indir_tbl[RTL8125_MAX_INDIRECTION_TABLE_ENTRIES];
        u32 rss_options;
#endif

        u8 HwSuppMacMcuVer;
        u16 MacMcuPageSize;
        u64 hw_mcu_patch_code_ver;
        u64 bin_mcu_patch_code_ver;

        u8 HwSuppTcamVer;

        u16 TcamNotValidReg;
        u16 TcamValidReg;
        u16 TcamMaAddrcOffset;
        u16 TcamVlanTagOffset;
};

#ifdef ENABLE_LIB_SUPPORT
static inline unsigned int
rtl8125_num_lib_tx_rings(struct rtl8125_private *tp)
{
        int count, i;

        for (count = 0, i = tp->num_tx_rings; i < tp->HwSuppNumTxQueues; i++)
                if(tp->lib_tx_ring[i].enabled)
                        count++;

        return count;
}

static inline unsigned int
rtl8125_num_lib_rx_rings(struct rtl8125_private *tp)
{
        int count, i;

        for (count = 0, i = 0; i < tp->HwSuppNumRxQueues; i++)
                if(tp->lib_rx_ring[i].enabled)
                        count++;

        return count;
}

#else
static inline unsigned int
rtl8125_num_lib_tx_rings(struct rtl8125_private *tp)
{
        return 0;
}

static inline unsigned int
rtl8125_num_lib_rx_rings(struct rtl8125_private *tp)
{
        return 0;
}
#endif

static inline unsigned int
rtl8125_tot_tx_rings(struct rtl8125_private *tp)
{
        return tp->num_tx_rings + rtl8125_num_lib_tx_rings(tp);
}

static inline unsigned int
rtl8125_tot_rx_rings(struct rtl8125_private *tp)
{
        unsigned int num_lib_rx_rings;

        num_lib_rx_rings = rtl8125_num_lib_rx_rings(tp);
        if (num_lib_rx_rings > 0)
                return num_lib_rx_rings;
        else
                return tp->num_rx_rings;
}

static inline struct netdev_queue *txring_txq(const struct rtl8125_tx_ring *ring)
{
        return netdev_get_tx_queue(ring->netdev, ring->index);
}

enum eetype {
        EEPROM_TYPE_NONE=0,
        EEPROM_TYPE_93C46,
        EEPROM_TYPE_93C56,
        EEPROM_TWSI
};

enum mcfg {
        CFG_METHOD_2=2,
        CFG_METHOD_3,
        CFG_METHOD_4,
        CFG_METHOD_5,
        CFG_METHOD_6,
        CFG_METHOD_7,
        CFG_METHOD_8,
        CFG_METHOD_9,
        CFG_METHOD_10,
        CFG_METHOD_11,
        CFG_METHOD_12,
        CFG_METHOD_13,
        CFG_METHOD_DEFAULT,
        CFG_METHOD_MAX
};

#define LSO_32K 32000
#define LSO_64K 64000

#define NIC_MIN_PHYS_BUF_COUNT          (2)
#define NIC_MAX_PHYS_BUF_COUNT_LSO_64K  (24)
#define NIC_MAX_PHYS_BUF_COUNT_LSO2     (16*4)

#define GTTCPHO_SHIFT                   18
#define GTTCPHO_MAX                     0x70U
#define GTPKTSIZE_MAX                   0x3ffffU
#define TCPHO_SHIFT                     18
#define TCPHO_MAX                       0x3ffU
#define LSOPKTSIZE_MAX                  0xffffU
#define MSS_MAX                         0x07ffu /* MSS value */

#define OOB_CMD_RESET       0x00
#define OOB_CMD_DRIVER_START    0x05
#define OOB_CMD_DRIVER_STOP 0x06
#define OOB_CMD_SET_IPMAC   0x41

#define WAKEUP_MAGIC_PACKET_NOT_SUPPORT (0)
#define WAKEUP_MAGIC_PACKET_V1 (1)
#define WAKEUP_MAGIC_PACKET_V2 (2)
#define WAKEUP_MAGIC_PACKET_V3 (3)

//Ram Code Version
#define NIC_RAMCODE_VERSION_CFG_METHOD_2 (0x0b11)
#define NIC_RAMCODE_VERSION_CFG_METHOD_3 (0x0b33)
#define NIC_RAMCODE_VERSION_CFG_METHOD_4 (0x0b17)
#define NIC_RAMCODE_VERSION_CFG_METHOD_5 (0x0b99)
#define NIC_RAMCODE_VERSION_CFG_METHOD_8 (0x0013)
#define NIC_RAMCODE_VERSION_CFG_METHOD_9 (0x0001)
#define NIC_RAMCODE_VERSION_CFG_METHOD_10 (0x0027)
#define NIC_RAMCODE_VERSION_CFG_METHOD_11 (0x0031)
#define NIC_RAMCODE_VERSION_CFG_METHOD_12 (0x0010)

//hwoptimize
#define HW_PATCH_SOC_LAN (BIT_0)
#define HW_PATCH_SAMSUNG_LAN_DONGLE (BIT_2)

static const u16 other_q_intr_mask = (RxOK1 | RxDU1);

#define HW_PHY_STATUS_INI       1
#define HW_PHY_STATUS_EXT_INI   2
#define HW_PHY_STATUS_LAN_ON    3

void rtl8125_mdio_write(struct rtl8125_private *tp, u16 RegAddr, u16 value);
void rtl8125_mdio_prot_write(struct rtl8125_private *tp, u32 RegAddr, u32 value);
void rtl8125_mdio_prot_direct_write_phy_ocp(struct rtl8125_private *tp, u32 RegAddr, u32 value);
u32 rtl8125_mdio_read(struct rtl8125_private *tp, u16 RegAddr);
u32 rtl8125_mdio_prot_read(struct rtl8125_private *tp, u32 RegAddr);
u32 rtl8125_mdio_prot_direct_read_phy_ocp(struct rtl8125_private *tp, u32 RegAddr);
void rtl8125_ephy_write(struct rtl8125_private *tp, int RegAddr, int value);
void rtl8125_mac_ocp_write(struct rtl8125_private *tp, u16 reg_addr, u16 value);
u16 rtl8125_mac_ocp_read(struct rtl8125_private *tp, u16 reg_addr);
void rtl8125_clear_eth_phy_bit(struct rtl8125_private *tp, u8 addr, u16 mask);
void rtl8125_set_eth_phy_bit(struct rtl8125_private *tp,  u8  addr, u16  mask);
void rtl8125_ocp_write(struct rtl8125_private *tp, u16 addr, u8 len, u32 data);
void rtl8125_init_ring_indexes(struct rtl8125_private *tp);
void rtl8125_oob_mutex_lock(struct rtl8125_private *tp);
u32 rtl8125_ocp_read(struct rtl8125_private *tp, u16 addr, u8 len);
u32 rtl8125_ocp_read_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, u32 base_address);
u32 rtl8125_ocp_write_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, u32 value, u32 base_address);
u32 rtl8125_eri_read(struct rtl8125_private *tp, int addr, int len, int type);
u32 rtl8125_eri_read_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, int type, u32 base_address);
int rtl8125_eri_write(struct rtl8125_private *tp, int addr, int len, u32 value, int type);
int rtl8125_eri_write_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, u32 value, int type, u32 base_address);
u16 rtl8125_ephy_read(struct rtl8125_private *tp, int RegAddr);
void rtl8125_wait_txrx_fifo_empty(struct net_device *dev);
void rtl8125_enable_now_is_oob(struct rtl8125_private *tp);
void rtl8125_disable_now_is_oob(struct rtl8125_private *tp);
void rtl8125_oob_mutex_unlock(struct rtl8125_private *tp);
void rtl8125_dash2_disable_tx(struct rtl8125_private *tp);
void rtl8125_dash2_enable_tx(struct rtl8125_private *tp);
void rtl8125_dash2_disable_rx(struct rtl8125_private *tp);
void rtl8125_dash2_enable_rx(struct rtl8125_private *tp);
void rtl8125_hw_disable_mac_mcu_bps(struct net_device *dev);
void rtl8125_mark_to_asic(struct rtl8125_private *tp, struct RxDesc *desc, u32 rx_buf_sz);
void rtl8125_mark_as_last_descriptor(struct rtl8125_private *tp, struct RxDesc *desc);

static inline void
rtl8125_make_unusable_by_asic(struct rtl8125_private *tp,
                              struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                ((struct RxDescV3 *)desc)->addr = RTL8125_MAGIC_NUMBER;
                ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts1 &= ~cpu_to_le32(DescOwn | RsvdMaskV3);
                break;
        case RX_DESC_RING_TYPE_4:
                ((struct RxDescV4 *)desc)->addr = RTL8125_MAGIC_NUMBER;
                ((struct RxDescV4 *)desc)->RxDescNormalDDWord2.opts1 &= ~cpu_to_le32(DescOwn | RsvdMaskV4);
                break;
        default:
                desc->addr = RTL8125_MAGIC_NUMBER;
                desc->opts1 &= ~cpu_to_le32(DescOwn | RsvdMask);
                break;
        }
}

static inline struct RxDesc*
rtl8125_get_rxdesc(struct rtl8125_private *tp, struct RxDesc *RxDescBase, u32 const cur_rx)
{
        return (struct RxDesc*)((u8*)RxDescBase + (cur_rx * tp->RxDescLength));
}

static inline void
rtl8125_disable_hw_interrupt_v2(struct rtl8125_private *tp,
                                u32 message_id)
{
        RTL_W32(tp, IMR_V2_CLEAR_REG_8125, BIT(message_id));
}

static inline void
rtl8125_enable_hw_interrupt_v2(struct rtl8125_private *tp, u32 message_id)
{
        RTL_W32(tp, IMR_V2_SET_REG_8125, BIT(message_id));
}

int rtl8125_open(struct net_device *dev);
int rtl8125_close(struct net_device *dev);
void rtl8125_hw_config(struct net_device *dev);
void rtl8125_hw_set_timer_int(struct rtl8125_private *tp, u32 message_id, u8 timer_intmiti_val);
void rtl8125_set_rx_q_num(struct rtl8125_private *tp, unsigned int num_rx_queues);
void rtl8125_set_tx_q_num(struct rtl8125_private *tp, unsigned int num_tx_queues);
void rtl8125_enable_mcu(struct rtl8125_private *tp, bool enable);
void rtl8125_hw_start(struct net_device *dev);
void rtl8125_hw_reset(struct net_device *dev);
void rtl8125_tx_clear(struct rtl8125_private *tp);
void rtl8125_rx_clear(struct rtl8125_private *tp);
int rtl8125_init_ring(struct net_device *dev);
void rtl8125_hw_set_rx_packet_filter(struct net_device *dev);
void rtl8125_enable_hw_linkchg_interrupt(struct rtl8125_private *tp);
int rtl8125_dump_tally_counter(struct rtl8125_private *tp, dma_addr_t paddr);
void rtl8125_enable_napi(struct rtl8125_private *tp);
void _rtl8125_wait_for_quiescence(struct net_device *dev);

void rtl8125_clear_mac_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 mask);
void rtl8125_set_mac_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 mask);

void rtl8125_mdio_direct_write_phy_ocp(struct rtl8125_private *tp, u16 RegAddr,u16 value);
u32 rtl8125_mdio_direct_read_phy_ocp(struct rtl8125_private *tp, u16 RegAddr);
void rtl8125_clear_and_set_eth_phy_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 clearmask, u16 setmask);
void rtl8125_clear_eth_phy_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 mask);
void rtl8125_set_eth_phy_ocp_bit(struct rtl8125_private *tp,  u16 addr, u16 mask);

#ifndef ENABLE_LIB_SUPPORT
static inline void rtl8125_lib_reset_prepare(struct rtl8125_private *tp) { }
static inline void rtl8125_lib_reset_complete(struct rtl8125_private *tp) { }
#endif

#define HW_SUPPORT_CHECK_PHY_DISABLE_MODE(_M)        ((_M)->HwSuppCheckPhyDisableModeVer > 0)
#define HW_HAS_WRITE_PHY_MCU_RAM_CODE(_M)        (((_M)->HwHasWrRamCodeToMicroP == TRUE) ? 1 : 0)
#define HW_SUPPORT_D0_SPEED_UP(_M)        ((_M)->HwSuppD0SpeedUpVer > 0)
#define HW_SUPPORT_MAC_MCU(_M)        ((_M)->HwSuppMacMcuVer > 0)
#define HW_SUPPORT_TCAM(_M)        ((_M)->HwSuppTcamVer > 0)

#define HW_SUPP_PHY_LINK_SPEED_GIGA(_M)        ((_M)->HwSuppMaxPhyLinkSpeed >= 1000)
#define HW_SUPP_PHY_LINK_SPEED_2500M(_M)        ((_M)->HwSuppMaxPhyLinkSpeed >= 2500)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define netdev_mc_count(dev) ((dev)->mc_count)
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#define netdev_for_each_mc_addr(mclist, dev) \
    for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

#endif /* __R8125_H */
