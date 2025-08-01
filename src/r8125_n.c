// SPDX-License-Identifier: GPL-2.0-only
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

/*
 * This driver is modified from r8169.c in Linux kernel 2.6.18
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/ip.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#endif
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/completion.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
#include <linux/pci-aspm.h>
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
#include <linux/prefetch.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define dev_printk(A,B,fmt,args...) printk(A fmt,##args)
#else
#include <linux/dma-mapping.h>
#include <linux/moduleparam.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#include <linux/mdio.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,10)
#include <net/gso.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,10) */

#include <asm/io.h>
#include <asm/irq.h>

#include "r8125.h"
#include "rtl_eeprom.h"
#include "rtltool.h"
#include "r8125_firmware.h"

#ifdef ENABLE_R8125_PROCFS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif

#define FIRMWARE_8125A_3	"rtl_nic/rtl8125a-3.fw"
#define FIRMWARE_8125B_2	"rtl_nic/rtl8125b-2.fw"
#define FIRMWARE_8125BP_1	"rtl_nic/rtl8125bp-1.fw"
#define FIRMWARE_8125BP_2	"rtl_nic/rtl8125bp-2.fw"
#define FIRMWARE_8125D_1	"rtl_nic/rtl8125d-1.fw"
#define FIRMWARE_8125D_2	"rtl_nic/rtl8125d-2.fw"
#define FIRMWARE_8125CP_1	"rtl_nic/rtl8125cp-1.fw"

static const struct {
        const char *name;
        const char *fw_name;
} rtl_chip_fw_infos[] = {
        /* PCI-E devices. */
        [CFG_METHOD_2] = {"RTL8125A"				},
        [CFG_METHOD_3] = {"RTL8125A",		FIRMWARE_8125A_3},
        [CFG_METHOD_4] = {"RTL8125B",                       },
        [CFG_METHOD_5] = {"RTL8125B",		FIRMWARE_8125B_2},
        [CFG_METHOD_6] = {"RTL8168KB",		FIRMWARE_8125A_3},
        [CFG_METHOD_7] = {"RTL8168KB",		FIRMWARE_8125B_2},
        [CFG_METHOD_8] = {"RTL8125BP",		FIRMWARE_8125BP_1},
        [CFG_METHOD_9] = {"RTL8125BP",		FIRMWARE_8125BP_2},
        [CFG_METHOD_10] = {"RTL8125D",		FIRMWARE_8125D_1},
        [CFG_METHOD_11] = {"RTL8125D",		FIRMWARE_8125D_2},
        [CFG_METHOD_12] = {"RTL8125CP",		FIRMWARE_8125CP_1},
        [CFG_METHOD_13] = {"RTL8168KD",		FIRMWARE_8125D_2},
        [CFG_METHOD_DEFAULT] = {"Unknown",                  },
};

#define _R(NAME,MAC,RCR,MASK,JumFrameSz) \
    { .name = NAME, .mcfg = MAC, .RCR_Cfg = RCR, .RxConfigMask = MASK, .jumbo_frame_sz = JumFrameSz }

static const struct {
        const char *name;
        u8 mcfg;
        u32 RCR_Cfg;
        u32 RxConfigMask;   /* Clears the bits supported by this chip */
        u32 jumbo_frame_sz;
} rtl_chip_info[] = {
        _R("RTL8125A",
        CFG_METHOD_2,
        Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125A",
        CFG_METHOD_3,
        Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125B",
        CFG_METHOD_4,
        Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125B",
        CFG_METHOD_5,
        Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8168KB",
        CFG_METHOD_6,
        Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8168KB",
        CFG_METHOD_7,
        Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125BP",
        CFG_METHOD_8,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125BP",
        CFG_METHOD_9,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125D",
        CFG_METHOD_10,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125D",
        CFG_METHOD_11,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125CP",
        CFG_METHOD_12,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8168KD",
        CFG_METHOD_13,
        Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("Unknown",
        CFG_METHOD_DEFAULT,
        (RX_DMA_BURST_512 << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_1k)
};
#undef _R


#ifndef PCI_VENDOR_ID_DLINK
#define PCI_VENDOR_ID_DLINK 0x1186
#endif

static struct pci_device_id rtl8125_pci_tbl[] = {
        { PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x8125), },
        { PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x8162), },
        { PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x3000), },
        {0,},
};

MODULE_DEVICE_TABLE(pci, rtl8125_pci_tbl);

static int use_dac = 1;
static int timer_count = 0x2600;
static int timer_count_v2 = (0x2600 / 0x100);

static struct {
        u32 msg_enable;
} debug = { -1 };

static unsigned int speed_mode = SPEED_2500;
static unsigned int duplex_mode = DUPLEX_FULL;
static unsigned int autoneg_mode = AUTONEG_ENABLE;
#ifdef CONFIG_ASPM
static int aspm = 1;
#else
static int aspm = 0;
#endif
#ifdef ENABLE_S5WOL
static int s5wol = 1;
#else
static int s5wol = 0;
#endif
#ifdef ENABLE_S5_KEEP_CURR_MAC
static int s5_keep_curr_mac = 1;
#else
static int s5_keep_curr_mac = 0;
#endif
#ifdef ENABLE_EEE
static int eee_enable = 1;
#else
static int eee_enable = 0;
#endif
#ifdef CONFIG_SOC_LAN
static ulong hwoptimize = HW_PATCH_SOC_LAN;
#else
static ulong hwoptimize = 0;
#endif
#ifdef ENABLE_S0_MAGIC_PACKET
static int s0_magic_packet = 1;
#else
static int s0_magic_packet = 0;
#endif
#ifdef ENABLE_TX_NO_CLOSE
static int tx_no_close_enable = 1;
#else
static int tx_no_close_enable = 0;
#endif
#ifdef ENABLE_PTP_MASTER_MODE
static int enable_ptp_master_mode = 1;
#else
static int enable_ptp_master_mode = 0;
#endif
#ifdef DISABLE_WOL_SUPPORT
static int disable_wol_support = 1;
#else
static int disable_wol_support = 0;
#endif
#ifdef ENABLE_DOUBLE_VLAN
static int enable_double_vlan = 1;
#else
static int enable_double_vlan = 0;
#endif
#ifdef ENABLE_GIGA_LITE
static int eee_giga_lite = 1;
#else
static int eee_giga_lite = 0;
#endif

MODULE_AUTHOR("Realtek and the Linux r8125 crew <netdev@vger.kernel.org>");
MODULE_DESCRIPTION("Realtek r8125 Ethernet controller driver");

module_param(speed_mode, uint, 0);
MODULE_PARM_DESC(speed_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(duplex_mode, uint, 0);
MODULE_PARM_DESC(duplex_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(autoneg_mode, uint, 0);
MODULE_PARM_DESC(autoneg_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(aspm, int, 0);
MODULE_PARM_DESC(aspm, "Enable ASPM.");

module_param(s5wol, int, 0);
MODULE_PARM_DESC(s5wol, "Enable Shutdown Wake On Lan.");

module_param(s5_keep_curr_mac, int, 0);
MODULE_PARM_DESC(s5_keep_curr_mac, "Enable Shutdown Keep Current MAC Address.");

module_param(use_dac, int, 0);
MODULE_PARM_DESC(use_dac, "Enable PCI DAC. Unsafe on 32 bit PCI slot.");

module_param(timer_count, int, 0);
MODULE_PARM_DESC(timer_count, "Timer Interrupt Interval.");

module_param(eee_enable, int, 0);
MODULE_PARM_DESC(eee_enable, "Enable Energy Efficient Ethernet.");

module_param(hwoptimize, ulong, 0);
MODULE_PARM_DESC(hwoptimize, "Enable HW optimization function.");

module_param(s0_magic_packet, int, 0);
MODULE_PARM_DESC(s0_magic_packet, "Enable S0 Magic Packet.");

module_param(tx_no_close_enable, int, 0);
MODULE_PARM_DESC(tx_no_close_enable, "Enable TX No Close.");

module_param(enable_ptp_master_mode, int, 0);
MODULE_PARM_DESC(enable_ptp_master_mode, "Enable PTP Master Mode.");

module_param(disable_wol_support, int, 0);
MODULE_PARM_DESC(disable_wol_support, "Disable PM support.");

module_param(enable_double_vlan, int, 0);
MODULE_PARM_DESC(enable_double_vlan, "Enable Double VLAN.");

module_param(eee_giga_lite, int, 0);
MODULE_PARM_DESC(eee_giga_lite, "Enable Giga Lite.");

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
module_param_named(debug, debug.msg_enable, int, 0);
MODULE_PARM_DESC(debug, "Debug verbosity level (0=none, ..., 16=all)");
#endif//LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

MODULE_LICENSE("GPL");
#ifdef ENABLE_USE_FIRMWARE_FILE
MODULE_FIRMWARE(FIRMWARE_8125A_3);
MODULE_FIRMWARE(FIRMWARE_8125B_2);
MODULE_FIRMWARE(FIRMWARE_8125BP_1);
MODULE_FIRMWARE(FIRMWARE_8125BP_2);
MODULE_FIRMWARE(FIRMWARE_8125D_1);
MODULE_FIRMWARE(FIRMWARE_8125D_2);
MODULE_FIRMWARE(FIRMWARE_8125CP_1);
#endif

MODULE_VERSION(RTL8125_VERSION);

/*
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void rtl8125_esd_timer(unsigned long __opaque);
#else
static void rtl8125_esd_timer(struct timer_list *t);
#endif
*/
/*
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void rtl8125_link_timer(unsigned long __opaque);
#else
static void rtl8125_link_timer(struct timer_list *t);
#endif
*/

static netdev_tx_t rtl8125_start_xmit(struct sk_buff *skb, struct net_device *dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance, struct pt_regs *regs);
#else
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance, struct pt_regs *regs);
#else
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance);
#endif
static void rtl8125_set_rx_mode(struct net_device *dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static void rtl8125_tx_timeout(struct net_device *dev, unsigned int txqueue);
#else
static void rtl8125_tx_timeout(struct net_device *dev);
#endif
static int rtl8125_rx_interrupt(struct net_device *, struct rtl8125_private *, struct rtl8125_rx_ring *, napi_budget);
static int rtl8125_tx_interrupt(struct rtl8125_tx_ring *ring, int budget);
static int rtl8125_tx_interrupt_with_vector(struct rtl8125_private *tp, const int message_id, int budget);
static void rtl8125_wait_for_quiescence(struct net_device *dev);
static int rtl8125_change_mtu(struct net_device *dev, int new_mtu);
static void rtl8125_down(struct net_device *dev);

static int rtl8125_set_mac_address(struct net_device *dev, void *p);
static void rtl8125_rar_set(struct rtl8125_private *tp, const u8 *addr);
static void rtl8125_desc_addr_fill(struct rtl8125_private *);
static void rtl8125_tx_desc_init(struct rtl8125_private *tp);
static void rtl8125_rx_desc_init(struct rtl8125_private *tp);

static u16 rtl8125_get_hw_phy_mcu_code_ver(struct rtl8125_private *tp);
static void rtl8125_phy_power_up(struct net_device *dev);
static void rtl8125_phy_power_down(struct net_device *dev);
static int rtl8125_set_speed(struct net_device *dev, u8 autoneg, u32 speed, u8 duplex, u64 adv);
static bool rtl8125_set_phy_mcu_patch_request(struct rtl8125_private *tp);
static bool rtl8125_clear_phy_mcu_patch_request(struct rtl8125_private *tp);

#ifdef CONFIG_R8125_NAPI
static int rtl8125_poll(napi_ptr napi, napi_budget budget);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_reset_task(void *_data);
static void rtl8125_esd_task(void *_data);
static void rtl8125_linkchg_task(void *_data);
static void rtl8125_link_task(void *_data);
static void rtl8125_dash_task(void *_data);
#else
static void rtl8125_reset_task(struct work_struct *work);
static void rtl8125_esd_task(struct work_struct *work);
static void rtl8125_linkchg_task(struct work_struct *work);
static void rtl8125_link_task(struct work_struct *work);
static void rtl8125_dash_task(struct work_struct *work);
#endif
static void rtl8125_schedule_reset_work(struct rtl8125_private *tp);
static void rtl8125_schedule_esd_work(struct rtl8125_private *tp);
static void rtl8125_schedule_linkchg_work(struct rtl8125_private *tp);
static void rtl8125_schedule_link_work(struct rtl8125_private *tp);
void rtl8125_schedule_dash_work(struct rtl8125_private *tp);
static void rtl8125_init_all_schedule_work(struct rtl8125_private *tp);
static void rtl8125_cancel_all_schedule_work(struct rtl8125_private *tp);

static inline struct device *tp_to_dev(struct rtl8125_private *tp)
{
        return &tp->pci_dev->dev;
}

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0) && \
     LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,00)))
void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst,
                u32 legacy_u32)
{
        bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
        dst[0] = legacy_u32;
}

bool ethtool_convert_link_mode_to_legacy_u32(u32 *legacy_u32,
                const unsigned long *src)
{
        bool retval = true;

        /* TODO: following test will soon always be true */
        if (__ETHTOOL_LINK_MODE_MASK_NBITS > 32) {
                __ETHTOOL_DECLARE_LINK_MODE_MASK(ext);

                bitmap_zero(ext, __ETHTOOL_LINK_MODE_MASK_NBITS);
                bitmap_fill(ext, 32);
                bitmap_complement(ext, ext, __ETHTOOL_LINK_MODE_MASK_NBITS);
                if (bitmap_intersects(ext, src,
                                      __ETHTOOL_LINK_MODE_MASK_NBITS)) {
                        /* src mask goes beyond bit 31 */
                        retval = false;
                }
        }
        *legacy_u32 = src[0];
        return retval;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)

#ifndef LPA_1000FULL
#define LPA_1000FULL            0x0800
#endif

#ifndef LPA_1000HALF
#define LPA_1000HALF            0x0400
#endif

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static inline void eth_hw_addr_random(struct net_device *dev)
{
        random_ether_addr(dev->dev_addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#undef ethtool_ops
#define ethtool_ops _kc_ethtool_ops

struct _kc_ethtool_ops {
        int  (*get_settings)(struct net_device *, struct ethtool_cmd *);
        int  (*set_settings)(struct net_device *, struct ethtool_cmd *);
        void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
        int  (*get_regs_len)(struct net_device *);
        void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
        void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
        int  (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
        u32  (*get_msglevel)(struct net_device *);
        void (*set_msglevel)(struct net_device *, u32);
        int  (*nway_reset)(struct net_device *);
        u32  (*get_link)(struct net_device *);
        int  (*get_eeprom_len)(struct net_device *);
        int  (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
        int  (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
        int  (*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
        int  (*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
        void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *);
        int  (*set_ringparam)(struct net_device *, struct ethtool_ringparam *);
        void (*get_pauseparam)(struct net_device *,
                               struct ethtool_pauseparam*);
        int  (*set_pauseparam)(struct net_device *,
                               struct ethtool_pauseparam*);
        u32  (*get_rx_csum)(struct net_device *);
        int  (*set_rx_csum)(struct net_device *, u32);
        u32  (*get_tx_csum)(struct net_device *);
        int  (*set_tx_csum)(struct net_device *, u32);
        u32  (*get_sg)(struct net_device *);
        int  (*set_sg)(struct net_device *, u32);
        u32  (*get_tso)(struct net_device *);
        int  (*set_tso)(struct net_device *, u32);
        int  (*self_test_count)(struct net_device *);
        void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
        void (*get_strings)(struct net_device *, u32 stringset, u8 *);
        int  (*phys_id)(struct net_device *, u32);
        int  (*get_stats_count)(struct net_device *);
        void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *,
                                  u64 *);
} *ethtool_ops = NULL;

#undef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) (ethtool_ops = (ops))

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
         ((netdev)->ethtool_ops = (ops))
#endif //SET_ETHTOOL_OPS
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)

//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)
#ifndef netif_msg_init
#define netif_msg_init _kc_netif_msg_init
/* copied from linux kernel 2.6.20 include/linux/netdevice.h */
static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
        /* use default */
        if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
                return default_msg_enable_bits;
        if (debug_value == 0)   /* no output */
                return 0;
        /* set low N bits */
        return (1 << debug_value) - 1;
}

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
static inline void eth_copy_and_sum (struct sk_buff *dest,
                                     const unsigned char *src,
                                     int len, int base)
{
        skb_copy_to_linear_data(dest, src, len);
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
/* copied from linux kernel 2.6.20 /include/linux/time.h */
/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L

/* copied from linux kernel 2.6.20 /include/linux/jiffies.h */
/*
 * Change timeval to jiffies, trying to avoid the
 * most obvious overflows..
 *
 * And some not so obvious.
 *
 * Note that we don't want to return MAX_LONG, because
 * for various timeout reasons we often end up having
 * to wait "jiffies+1" in order to guarantee that we wait
 * at _least_ "jiffies" - so "jiffies+1" had better still
 * be positive.
 */
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)

/*
 * Convert jiffies to milliseconds and back.
 *
 * Avoid unnecessary multiplications/divisions in the
 * two most common HZ cases:
 */
static inline unsigned int _kc_jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
        return (j * MSEC_PER_SEC) / HZ;
#endif
}

static inline unsigned long _kc_msecs_to_jiffies(const unsigned int m)
{
        if (m > _kc_jiffies_to_msecs(MAX_JIFFY_OFFSET))
                return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return m * (HZ / MSEC_PER_SEC);
#else
        return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)

/* copied from linux kernel 2.6.12.6 /include/linux/pm.h */
typedef int __bitwise pci_power_t;

/* copied from linux kernel 2.6.12.6 /include/linux/pci.h */
typedef u32 __bitwise pm_message_t;

#define PCI_D0  ((pci_power_t __force) 0)
#define PCI_D1  ((pci_power_t __force) 1)
#define PCI_D2  ((pci_power_t __force) 2)
#define PCI_D3hot   ((pci_power_t __force) 3)
#define PCI_D3cold  ((pci_power_t __force) 4)
#define PCI_POWER_ERROR ((pci_power_t __force) -1)

/* copied from linux kernel 2.6.12.6 /drivers/pci/pci.c */
/**
 * pci_choose_state - Choose the power state of a PCI device
 * @dev: PCI device to be suspended
 * @state: target sleep state for the whole system. This is the value
 *  that is passed to suspend() function.
 *
 * Returns PCI power state suitable for given device and given system
 * message.
 */

pci_power_t pci_choose_state(struct pci_dev *dev, pm_message_t state)
{
        if (!pci_find_capability(dev, PCI_CAP_ID_PM))
                return PCI_D0;

        switch (state) {
        case 0:
                return PCI_D0;
        case 3:
                return PCI_D3hot;
        default:
                printk("They asked me for state %d\n", state);
//      BUG();
        }
        return PCI_D0;
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
/**
 * msleep_interruptible - sleep waiting for waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
#define msleep_interruptible _kc_msleep_interruptible
unsigned long _kc_msleep_interruptible(unsigned int msecs)
{
        unsigned long timeout = _kc_msecs_to_jiffies(msecs);

        while (timeout && !signal_pending(current)) {
                set_current_state(TASK_INTERRUPTIBLE);
                timeout = schedule_timeout(timeout);
        }
        return _kc_jiffies_to_msecs(timeout);
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
/* copied from linux kernel 2.6.20 include/linux/sched.h */
#ifndef __sched
#define __sched     __attribute__((__section__(".sched.text")))
#endif

/* copied from linux kernel 2.6.20 kernel/timer.c */
signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
        __set_current_state(TASK_UNINTERRUPTIBLE);
        return schedule_timeout(timeout);
}

/* copied from linux kernel 2.6.20 include/linux/mii.h */
#undef if_mii
#define if_mii _kc_if_mii
static inline struct mii_ioctl_data *if_mii(struct ifreq *rq)
{
        return (struct mii_ioctl_data *) &rq->ifr_ifru;
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)

static u16 _rtl8125_read_thermal_sensor(struct rtl8125_private *tp)
{
        u16 ts_digout;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                ts_digout = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBD84);
                ts_digout &= 0x3ff;
                break;
        default:
                ts_digout = 0xffff;
                break;
        }

        return ts_digout;
}

static int rtl8125_read_thermal_sensor(struct rtl8125_private *tp)
{
        int tmp;

        tmp = _rtl8125_read_thermal_sensor(tp);
        if (tmp > 512)
                return (0 - ((512 - (tmp - 512)) / 2));
        else
                return (tmp / 2);
}

int rtl8125_dump_tally_counter(struct rtl8125_private *tp, dma_addr_t paddr)
{
        u32 cmd;
        u32 WaitCnt;
        int retval = -1;

        RTL_W32(tp, CounterAddrHigh, (u64)paddr >> 32);
        cmd = (u64)paddr & DMA_BIT_MASK(32);
        RTL_W32(tp, CounterAddrLow, cmd);
        RTL_W32(tp, CounterAddrLow, cmd | CounterDump);

        WaitCnt = 0;
        while (RTL_R32(tp, CounterAddrLow) & CounterDump) {
                udelay(10);

                WaitCnt++;
                if (WaitCnt > 20)
                        break;
        }

        if (WaitCnt <= 20)
                retval = 0;

        return retval;
}

static u32
rtl8125_get_hw_clo_ptr(struct rtl8125_tx_ring *ring)
{
        struct rtl8125_private *tp = ring->priv;

        if (!tp)
                return 0;

        switch (tp->HwSuppTxNoCloseVer) {
        case 3:
                return RTL_R16(tp, ring->hw_clo_ptr_reg);
        case 4:
        case 5:
        case 6:
                return RTL_R32(tp, ring->hw_clo_ptr_reg);
        default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                WARN_ON(1);
#endif
                return 0;
        }
}

static u32
rtl8125_get_sw_tail_ptr(struct rtl8125_tx_ring *ring)
{
        struct rtl8125_private *tp = ring->priv;

        if (!tp)
                return 0;

        switch (tp->HwSuppTxNoCloseVer) {
        case 3:
                return RTL_R16(tp, ring->sw_tail_ptr_reg);
        case 4:
        case 5:
        case 6:
                return RTL_R32(tp, ring->sw_tail_ptr_reg);
        default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                WARN_ON(1);
#endif
                return 0;
        }
}

static u32
rtl8125_get_phy_status(struct rtl8125_private *tp)
{
        return RTL_R32(tp, PHYstatus);
}

static bool
rtl8125_sysfs_testmode_on(struct rtl8125_private *tp)
{
#ifdef ENABLE_R8125_SYSFS
        return !!tp->testmode;
#else
        return 1;
#endif
}

static u32 rtl8125_convert_link_speed(u32 status)
{
        u32 speed = SPEED_UNKNOWN;

        if (status & LinkStatus) {
                if (status & _2500bpsF)
                        speed = SPEED_2500;
                else if (status & (_1000bpsF | _2500bpsL | _1000bpsL))
                        speed = SPEED_1000;
                else if (status & _100bps)
                        speed = SPEED_100;
                else if (status & _10bps)
                        speed = SPEED_10;
        }

        return speed;
}

static void rtl8125_mdi_swap(struct rtl8125_private *tp)
{
        int i;
        u16 reg, val, mdi_reverse;
        u16 tps_p0, tps_p1, tps_p2, tps_p3, tps_p3_p0;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                reg = 0x8284;
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                reg = 0x81aa;
                break;
        default:
                return;
        };

        tps_p3_p0 = rtl8125_mac_ocp_read(tp, 0xD440) & 0xF000;
        tps_p3 = !!(tps_p3_p0 & BIT_15);
        tps_p2 = !!(tps_p3_p0 & BIT_14);
        tps_p1 = !!(tps_p3_p0 & BIT_13);
        tps_p0 = !!(tps_p3_p0 & BIT_12);
        mdi_reverse = rtl8125_mac_ocp_read(tp, 0xD442);

        if ((mdi_reverse & BIT_5) && tps_p3_p0 == 0xA000)
                return;

        if (!(mdi_reverse & BIT_5))
                val = tps_p0 << 8 |
                      tps_p1 << 9 |
                      tps_p2 << 10 |
                      tps_p3 << 11;
        else
                val = tps_p3 << 8 |
                      tps_p2 << 9 |
                      tps_p1 << 10 |
                      tps_p0 << 11;

        for (i=8; i<12; i++) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, reg);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      BIT(i),
                                                      val & BIT(i));
        }
}

static int _rtl8125_vcd_test(struct rtl8125_private *tp)
{
        u16 val;
        u32 wait_cnt;
        int ret = -1;

        rtl8125_mdi_swap(tp);

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA422, BIT(0));
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA422, 0x00F0);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA422, BIT(0));

        wait_cnt = 0;
        do {
                mdelay(1);
                val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA422);
                wait_cnt++;
        } while (!(val & BIT_15) && (wait_cnt < 5000));

        if (wait_cnt == 5000)
                goto exit;

        ret = 0;

exit:
        return ret;
}

static int rtl8125_vcd_test(struct rtl8125_private *tp, bool poe_mode)
{
        int ret;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                /* update rtct threshold for poe mode */
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FE1);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, poe_mode ? 0x0A44 : 0x0000);

                /* enable rtct poe mode */
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FE3);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, poe_mode ? 0x0100 : 0x0000);

                ret = _rtl8125_vcd_test(tp);

                /* disable rtct poe mode */
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FE3);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);

                /* restore rtct threshold */
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FE1);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
                break;
        default:
                ret = _rtl8125_vcd_test(tp);
                break;
        }

        return ret;
}

static void rtl8125_get_cp_len(struct rtl8125_private *tp,
                               int cp_len[RTL8125_CP_NUM])
{
        int i;
        u32 status;
        int tmp_cp_len;

        status = rtl8125_get_phy_status(tp);
        if (status & LinkStatus) {
                if (status & _10bps) {
                        tmp_cp_len = -1;
                } else if (status & (_100bps | _1000bpsF)) {
                        rtl8125_mdio_write(tp, 0x1f, 0x0a88);
                        tmp_cp_len = rtl8125_mdio_read(tp, 0x10);
                } else if (status & _2500bpsF) {
                        switch (tp->mcfg) {
                        case CFG_METHOD_2:
                        case CFG_METHOD_3:
                        case CFG_METHOD_6:
                                rtl8125_mdio_write(tp, 0x1f, 0x0ac5);
                                tmp_cp_len = rtl8125_mdio_read(tp, 0x14);
                                tmp_cp_len >>= 4;
                                break;
                        default:
                                rtl8125_mdio_write(tp, 0x1f, 0x0acb);
                                tmp_cp_len = rtl8125_mdio_read(tp, 0x15);
                                tmp_cp_len >>= 2;
                                break;
                        }
                } else
                        tmp_cp_len = 0;
        } else
                tmp_cp_len = 0;

        if (tmp_cp_len > 0)
                tmp_cp_len &= 0xff;
        for (i=0; i<RTL8125_CP_NUM; i++)
                cp_len[i] = tmp_cp_len;

        rtl8125_mdio_write(tp, 0x1f, 0x0000);

        for (i=0; i<RTL8125_CP_NUM; i++)
                if (cp_len[i] > RTL8125_MAX_SUPPORT_CP_LEN)
                        cp_len[i] = RTL8125_MAX_SUPPORT_CP_LEN;

        return;
}

static int __rtl8125_get_cp_status(u16 val)
{
        switch (val) {
        case 0x0060:
                return rtl8125_cp_normal;
        case 0x0048:
                return rtl8125_cp_open;
        case 0x0050:
                return rtl8125_cp_short;
        case 0x0042:
        case 0x0044:
                return rtl8125_cp_mismatch;
        default:
                return rtl8125_cp_normal;
        }
}

static int _rtl8125_get_cp_status(struct rtl8125_private *tp, u8 pair_num)
{
        u16 val;
        int cp_status = rtl8125_cp_unknown;

        if (pair_num > 3)
                goto exit;

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8027 + 4 * pair_num);
        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA438);

        cp_status = __rtl8125_get_cp_status(val);

exit:
        return cp_status;
}

static const char * rtl8125_get_cp_status_string(int cp_status)
{
        switch(cp_status) {
        case rtl8125_cp_normal:
                return "normal  ";
        case rtl8125_cp_short:
                return "short   ";
        case rtl8125_cp_open:
                return "open    ";
        case rtl8125_cp_mismatch:
                return "mismatch";
        default:
                return "unknown ";
        }
}

static u16 rtl8125_get_cp_pp(struct rtl8125_private *tp, u8 pair_num)
{
        u16 pp = 0;

        if (pair_num > 3)
                goto exit;

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8029 + 4 * pair_num);
        pp = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA438);

        pp &= 0x3fff;
        pp /= 80;

exit:
        return pp;
}

static void rtl8125_get_cp_status(struct rtl8125_private *tp,
                                  int cp_status[RTL8125_CP_NUM],
                                  bool poe_mode)
{
        u32 status;
        int i;

        status = rtl8125_get_phy_status(tp);
        if (status & LinkStatus && !(status & (_10bps | _100bps))) {
                for (i=0; i<RTL8125_CP_NUM; i++)
                        cp_status[i] = rtl8125_cp_normal;
        } else {
                /* cannot do vcd when link is on */
                rtl8125_vcd_test(tp, poe_mode);

                for (i=0; i<RTL8125_CP_NUM; i++)
                        cp_status[i] = _rtl8125_get_cp_status(tp, i);
        }

        if (poe_mode) {
                for (i=0; i<RTL8125_CP_NUM; i++) {
                        if (cp_status[i] == rtl8125_cp_mismatch)
                                cp_status[i] = rtl8125_cp_normal;
                }
        }
}

static int rtl8125_cel_to_fah(int cel)
{
        return (cel * 9 / 5) + 32;
}

#ifdef ENABLE_R8125_PROCFS
/****************************************************************************
*   -----------------------------PROCFS STUFF-------------------------
*****************************************************************************
*/

static struct proc_dir_entry *rtl8125_proc;
static int proc_init_num = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int proc_get_driver_variable(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);

        seq_puts(m, "\nDump Driver Variable\n");

        rtnl_lock();

        seq_puts(m, "Variable\tValue\n----------\t-----\n");
        seq_printf(m, "MODULENAME\t%s\n", MODULENAME);
        seq_printf(m, "driver version\t%s\n", RTL8125_VERSION);
        seq_printf(m, "mcfg\t%d\n", tp->mcfg);
        seq_printf(m, "chipset\t%d\n", tp->chipset);
        seq_printf(m, "chipset_name\t%s\n", rtl_chip_info[tp->chipset].name);
        seq_printf(m, "mtu\t%d\n", dev->mtu);
        seq_printf(m, "NUM_RX_DESC\t0x%x\n", tp->rx_ring[0].num_rx_desc);
        seq_printf(m, "cur_rx0\t0x%x\n", tp->rx_ring[0].cur_rx);
        seq_printf(m, "dirty_rx0\t0x%x\n", tp->rx_ring[0].dirty_rx);
        seq_printf(m, "cur_rx1\t0x%x\n", tp->rx_ring[1].cur_rx);
        seq_printf(m, "dirty_rx1\t0x%x\n", tp->rx_ring[1].dirty_rx);
        seq_printf(m, "cur_rx2\t0x%x\n", tp->rx_ring[2].cur_rx);
        seq_printf(m, "dirty_rx2\t0x%x\n", tp->rx_ring[2].dirty_rx);
        seq_printf(m, "cur_rx3\t0x%x\n", tp->rx_ring[3].cur_rx);
        seq_printf(m, "dirty_rx3\t0x%x\n", tp->rx_ring[3].dirty_rx);
        seq_printf(m, "NUM_TX_DESC\t0x%x\n", tp->tx_ring[0].num_tx_desc);
        seq_printf(m, "cur_tx0\t0x%x\n", tp->tx_ring[0].cur_tx);
        seq_printf(m, "dirty_tx0\t0x%x\n", tp->tx_ring[0].dirty_tx);
        seq_printf(m, "cur_tx1\t0x%x\n", tp->tx_ring[1].cur_tx);
        seq_printf(m, "dirty_tx1\t0x%x\n", tp->tx_ring[1].dirty_tx);
        seq_printf(m, "rx_buf_sz\t0x%x\n", tp->rx_buf_sz);
#ifdef ENABLE_PAGE_REUSE
        seq_printf(m, "rx_buf_page_order\t0x%x\n", tp->rx_buf_page_order);
        seq_printf(m, "rx_buf_page_size\t0x%x\n", tp->rx_buf_page_size);
        seq_printf(m, "page_reuse_fail_cnt\t0x%x\n", tp->page_reuse_fail_cnt);
#endif //ENABLE_PAGE_REUSE
        seq_printf(m, "esd_flag\t0x%x\n", tp->esd_flag);
        seq_printf(m, "pci_cfg_is_read\t0x%x\n", tp->pci_cfg_is_read);
        seq_printf(m, "rtl8125_rx_config\t0x%x\n", tp->rtl8125_rx_config);
        seq_printf(m, "cp_cmd\t0x%x\n", tp->cp_cmd);
        seq_printf(m, "intr_mask\t0x%x\n", tp->intr_mask);
        seq_printf(m, "timer_intr_mask\t0x%x\n", tp->timer_intr_mask);
        seq_printf(m, "wol_enabled\t0x%x\n", tp->wol_enabled);
        seq_printf(m, "wol_opts\t0x%x\n", tp->wol_opts);
        seq_printf(m, "efuse_ver\t0x%x\n", tp->efuse_ver);
        seq_printf(m, "eeprom_type\t0x%x\n", tp->eeprom_type);
        seq_printf(m, "autoneg\t0x%x\n", tp->autoneg);
        seq_printf(m, "duplex\t0x%x\n", tp->duplex);
        seq_printf(m, "speed\t%d\n", tp->speed);
        seq_printf(m, "advertising\t0x%llx\n", tp->advertising);
        seq_printf(m, "eeprom_len\t0x%x\n", tp->eeprom_len);
        seq_printf(m, "cur_page\t0x%x\n", tp->cur_page);
        seq_printf(m, "features\t0x%x\n", tp->features);
        seq_printf(m, "org_pci_offset_99\t0x%x\n", tp->org_pci_offset_99);
        seq_printf(m, "org_pci_offset_180\t0x%x\n", tp->org_pci_offset_180);
        seq_printf(m, "issue_offset_99_event\t0x%x\n", tp->issue_offset_99_event);
        seq_printf(m, "org_pci_offset_80\t0x%x\n", tp->org_pci_offset_80);
        seq_printf(m, "org_pci_offset_81\t0x%x\n", tp->org_pci_offset_81);
        seq_printf(m, "use_timer_interrupt\t0x%x\n", tp->use_timer_interrupt);
        seq_printf(m, "HwIcVerUnknown\t0x%x\n", tp->HwIcVerUnknown);
        seq_printf(m, "NotWrRamCodeToMicroP\t0x%x\n", tp->NotWrRamCodeToMicroP);
        seq_printf(m, "NotWrMcuPatchCode\t0x%x\n", tp->NotWrMcuPatchCode);
        seq_printf(m, "HwHasWrRamCodeToMicroP\t0x%x\n", tp->HwHasWrRamCodeToMicroP);
        seq_printf(m, "sw_ram_code_ver\t0x%x\n", tp->sw_ram_code_ver);
        seq_printf(m, "hw_ram_code_ver\t0x%x\n", tp->hw_ram_code_ver);
        seq_printf(m, "rtk_enable_diag\t0x%x\n", tp->rtk_enable_diag);
        seq_printf(m, "ShortPacketSwChecksum\t0x%x\n", tp->ShortPacketSwChecksum);
        seq_printf(m, "UseSwPaddingShortPkt\t0x%x\n", tp->UseSwPaddingShortPkt);
        seq_printf(m, "RequireAdcBiasPatch\t0x%x\n", tp->RequireAdcBiasPatch);
        seq_printf(m, "AdcBiasPatchIoffset\t0x%x\n", tp->AdcBiasPatchIoffset);
        seq_printf(m, "RequireAdjustUpsTxLinkPulseTiming\t0x%x\n", tp->RequireAdjustUpsTxLinkPulseTiming);
        seq_printf(m, "SwrCnt1msIni\t0x%x\n", tp->SwrCnt1msIni);
        seq_printf(m, "HwSuppNowIsOobVer\t0x%x\n", tp->HwSuppNowIsOobVer);
        seq_printf(m, "HwFiberModeVer\t0x%x\n", tp->HwFiberModeVer);
        seq_printf(m, "HwFiberStat\t0x%x\n", tp->HwFiberStat);
        seq_printf(m, "HwSwitchMdiToFiber\t0x%x\n", tp->HwSwitchMdiToFiber);
        seq_printf(m, "Led0\t0x%x\n", tp->BackupLedSel[0]);
        seq_printf(m, "RequiredSecLanDonglePatch\t0x%x\n", tp->RequiredSecLanDonglePatch);
        seq_printf(m, "RequiredPfmPatch\t0x%x\n", tp->RequiredPfmPatch);
        seq_printf(m, "HwSuppDashVer\t0x%x\n", tp->HwSuppDashVer);
        seq_printf(m, "DASH\t0x%x\n", tp->DASH);
        seq_printf(m, "DashFirmwareVersion\t0x%x\n", tp->DashFirmwareVersion);
        seq_printf(m, "HwSuppKCPOffloadVer\t0x%x\n", tp->HwSuppKCPOffloadVer);
        seq_printf(m, "speed_mode\t0x%x\n", speed_mode);
        seq_printf(m, "duplex_mode\t0x%x\n", duplex_mode);
        seq_printf(m, "autoneg_mode\t0x%x\n", autoneg_mode);
        seq_printf(m, "aspm\t0x%x\n", aspm);
        seq_printf(m, "s5wol\t0x%x\n", s5wol);
        seq_printf(m, "s5_keep_curr_mac\t0x%x\n", s5_keep_curr_mac);
        seq_printf(m, "eee_enable\t0x%x\n", tp->eee.eee_enabled);
        seq_printf(m, "hwoptimize\t0x%lx\n", hwoptimize);
        seq_printf(m, "proc_init_num\t0x%x\n", proc_init_num);
        seq_printf(m, "s0_magic_packet\t0x%x\n", s0_magic_packet);
        seq_printf(m, "disable_wol_support\t0x%x\n", disable_wol_support);
        seq_printf(m, "enable_double_vlan\t0x%x\n", enable_double_vlan);
        seq_printf(m, "eee_giga_lite\t0x%x\n", eee_giga_lite);
        seq_printf(m, "HwSuppMagicPktVer\t0x%x\n", tp->HwSuppMagicPktVer);
        seq_printf(m, "HwSuppEsdVer\t0x%x\n", tp->HwSuppEsdVer);
        seq_printf(m, "HwSuppLinkChgWakeUpVer\t0x%x\n", tp->HwSuppLinkChgWakeUpVer);
        seq_printf(m, "HwSuppD0SpeedUpVer\t0x%x\n", tp->HwSuppD0SpeedUpVer);
        seq_printf(m, "D0SpeedUpSpeed\t0x%x\n", tp->D0SpeedUpSpeed);
        seq_printf(m, "HwSuppCheckPhyDisableModeVer\t0x%x\n", tp->HwSuppCheckPhyDisableModeVer);
        seq_printf(m, "HwPkgDet\t0x%x\n", tp->HwPkgDet);
        seq_printf(m, "HwSuppTxNoCloseVer\t0x%x\n", tp->HwSuppTxNoCloseVer);
        seq_printf(m, "EnableTxNoClose\t0x%x\n", tp->EnableTxNoClose);
        seq_printf(m, "NextHwDesCloPtr0\t0x%x\n", tp->tx_ring[0].NextHwDesCloPtr);
        seq_printf(m, "BeginHwDesCloPtr0\t0x%x\n", tp->tx_ring[0].BeginHwDesCloPtr);
        seq_printf(m, "hw_clo_ptr_reg0\t0x%x\n", rtl8125_get_hw_clo_ptr(&tp->tx_ring[0]));
        seq_printf(m, "sw_tail_ptr_reg0\t0x%x\n", rtl8125_get_sw_tail_ptr(&tp->tx_ring[0]));
        seq_printf(m, "NextHwDesCloPtr1\t0x%x\n", tp->tx_ring[1].NextHwDesCloPtr);
        seq_printf(m, "BeginHwDesCloPtr1\t0x%x\n", tp->tx_ring[1].BeginHwDesCloPtr);
        seq_printf(m, "hw_clo_ptr_reg1\t0x%x\n", rtl8125_get_hw_clo_ptr(&tp->tx_ring[1]));
        seq_printf(m, "sw_tail_ptr_reg1\t0x%x\n", rtl8125_get_sw_tail_ptr(&tp->tx_ring[1]));
        seq_printf(m, "InitRxDescType\t0x%x\n", tp->InitRxDescType);
        seq_printf(m, "RxDescLength\t0x%x\n", tp->RxDescLength);
        seq_printf(m, "num_rx_rings\t0x%x\n", tp->num_rx_rings);
        seq_printf(m, "num_tx_rings\t0x%x\n", tp->num_tx_rings);
        seq_printf(m, "tot_rx_rings\t0x%x\n", rtl8125_tot_rx_rings(tp));
        seq_printf(m, "tot_tx_rings\t0x%x\n", rtl8125_tot_tx_rings(tp));
        seq_printf(m, "HwSuppNumRxQueues\t0x%x\n", tp->HwSuppNumRxQueues);
        seq_printf(m, "HwSuppNumTxQueues\t0x%x\n", tp->HwSuppNumTxQueues);
        seq_printf(m, "EnableRss\t0x%x\n", tp->EnableRss);
        seq_printf(m, "EnablePtp\t0x%x\n", tp->EnablePtp);
        seq_printf(m, "ptp_master_mode\t0x%x\n", tp->ptp_master_mode);
        seq_printf(m, "min_irq_nvecs\t0x%x\n", tp->min_irq_nvecs);
        seq_printf(m, "irq_nvecs\t0x%x\n", tp->irq_nvecs);
        seq_printf(m, "hw_supp_irq_nvecs\t0x%x\n", tp->hw_supp_irq_nvecs);
        seq_printf(m, "ring_lib_enabled\t0x%x\n", tp->ring_lib_enabled);
        seq_printf(m, "HwSuppIsrVer\t0x%x\n", tp->HwSuppIsrVer);
        seq_printf(m, "HwCurrIsrVer\t0x%x\n", tp->HwCurrIsrVer);
        seq_printf(m, "HwSuppMacMcuVer\t0x%x\n", tp->HwSuppMacMcuVer);
        seq_printf(m, "MacMcuPageSize\t0x%x\n", tp->MacMcuPageSize);
        seq_printf(m, "hw_mcu_patch_code_ver\t0x%llx\n", tp->hw_mcu_patch_code_ver);
        seq_printf(m, "bin_mcu_patch_code_ver\t0x%llx\n", tp->bin_mcu_patch_code_ver);
#ifdef ENABLE_PTP_SUPPORT
        seq_printf(m, "tx_hwtstamp_timeouts\t0x%x\n", tp->tx_hwtstamp_timeouts);
        seq_printf(m, "tx_hwtstamp_skipped\t0x%x\n", tp->tx_hwtstamp_skipped);
#endif
        seq_printf(m, "random_mac\t0x%x\n", tp->random_mac);
        seq_printf(m, "org_mac_addr\t%pM\n", tp->org_mac_addr);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        seq_printf(m, "perm_addr\t%pM\n", dev->perm_addr);
#endif
        seq_printf(m, "dev_addr\t%pM\n", dev->dev_addr);

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_tally_counter(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;

        seq_puts(m, "\nDump Tally Counter\n");

        rtnl_lock();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters) {
                seq_puts(m, "\nDump Tally Counter Fail\n");
                goto out_unlock;
        }

        rtl8125_dump_tally_counter(tp, paddr);

        seq_puts(m, "Statistics\tValue\n----------\t-----\n");
        seq_printf(m, "tx_packets\t%lld\n", le64_to_cpu(counters->tx_packets));
        seq_printf(m, "rx_packets\t%lld\n", le64_to_cpu(counters->rx_packets));
        seq_printf(m, "tx_errors\t%lld\n", le64_to_cpu(counters->tx_errors));
        seq_printf(m, "rx_errors\t%d\n", le32_to_cpu(counters->rx_errors));
        seq_printf(m, "rx_missed\t%d\n", le16_to_cpu(counters->rx_missed));
        seq_printf(m, "align_errors\t%d\n", le16_to_cpu(counters->align_errors));
        seq_printf(m, "tx_one_collision\t%d\n", le32_to_cpu(counters->tx_one_collision));
        seq_printf(m, "tx_multi_collision\t%d\n", le32_to_cpu(counters->tx_multi_collision));
        seq_printf(m, "rx_unicast\t%lld\n", le64_to_cpu(counters->rx_unicast));
        seq_printf(m, "rx_broadcast\t%lld\n", le64_to_cpu(counters->rx_broadcast));
        seq_printf(m, "rx_multicast\t%d\n", le32_to_cpu(counters->rx_multicast));
        seq_printf(m, "tx_aborted\t%d\n", le16_to_cpu(counters->tx_aborted));
        seq_printf(m, "tx_underrun\t%d\n", le16_to_cpu(counters->tx_underrun));

        seq_printf(m, "tx_octets\t%lld\n", le64_to_cpu(counters->tx_octets));
        seq_printf(m, "rx_octets\t%lld\n", le64_to_cpu(counters->rx_octets));
        seq_printf(m, "rx_multicast64\t%lld\n", le64_to_cpu(counters->rx_multicast64));
        seq_printf(m, "tx_unicast64\t%lld\n", le64_to_cpu(counters->tx_unicast64));
        seq_printf(m, "tx_broadcast64\t%lld\n", le64_to_cpu(counters->tx_broadcast64));
        seq_printf(m, "tx_multicast64\t%lld\n", le64_to_cpu(counters->tx_multicast64));
        seq_printf(m, "tx_pause_on\t%d\n", le32_to_cpu(counters->tx_pause_on));
        seq_printf(m, "tx_pause_off\t%d\n", le32_to_cpu(counters->tx_pause_off));
        seq_printf(m, "tx_pause_all\t%d\n", le32_to_cpu(counters->tx_pause_all));
        seq_printf(m, "tx_deferred\t%d\n", le32_to_cpu(counters->tx_deferred));
        seq_printf(m, "tx_late_collision\t%d\n", le32_to_cpu(counters->tx_late_collision));
        seq_printf(m, "tx_all_collision\t%d\n", le32_to_cpu(counters->tx_all_collision));
        seq_printf(m, "tx_aborted32\t%d\n", le32_to_cpu(counters->tx_aborted32));
        seq_printf(m, "align_errors32\t%d\n", le32_to_cpu(counters->align_errors32));
        seq_printf(m, "rx_frame_too_long\t%d\n", le32_to_cpu(counters->rx_frame_too_long));
        seq_printf(m, "rx_runt\t%d\n", le32_to_cpu(counters->rx_runt));
        seq_printf(m, "rx_pause_on\t%d\n", le32_to_cpu(counters->rx_pause_on));
        seq_printf(m, "rx_pause_off\t%d\n", le32_to_cpu(counters->rx_pause_off));
        seq_printf(m, "rx_pause_all\t%d\n", le32_to_cpu(counters->rx_pause_all));
        seq_printf(m, "rx_unknown_opcode\t%d\n", le32_to_cpu(counters->rx_unknown_opcode));
        seq_printf(m, "rx_mac_error\t%d\n", le32_to_cpu(counters->rx_mac_error));
        seq_printf(m, "tx_underrun32\t%d\n", le32_to_cpu(counters->tx_underrun32));
        seq_printf(m, "rx_mac_missed\t%d\n", le32_to_cpu(counters->rx_mac_missed));
        seq_printf(m, "rx_tcam_dropped\t%d\n", le32_to_cpu(counters->rx_tcam_dropped));
        seq_printf(m, "tdu\t%d\n", le32_to_cpu(counters->tdu));
        seq_printf(m, "rdu\t%d\n", le32_to_cpu(counters->rdu));

        seq_putc(m, '\n');

out_unlock:
        rtnl_unlock();

        return 0;
}

static int proc_get_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_MAC_REGS_SIZE;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;

        seq_puts(m, "\nDump MAC Registers\n");
        seq_puts(m, "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%04x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }

        max = 0xB00;
        for (n = 0xA00; n < max;) {
                seq_printf(m, "\n0x%04x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }

        max = 0xD40;
        for (n = 0xD00; n < max;) {
                seq_printf(m, "\n0x%04x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }

        max = 0x2840;
        for (n = 0x2800; n < max;) {
                seq_printf(m, "\n0x%04x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_all_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        struct pci_dev *pdev = tp->pci_dev;

        seq_puts(m, "\nDump All MAC Registers\n");
        seq_puts(m, "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        max = pci_resource_len(pdev, 2);
        max = min(max, 0x8000);

        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%04x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }

        rtnl_unlock();

        seq_printf(m, "\nTotal length:0x%X", max);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_pcie_phy(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_EPHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);

        seq_puts(m, "\nDump PCIE PHY\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        rtnl_lock();

        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_ephy_read(tp, n);
                        seq_printf(m, "%04x ", word_rd);
                }
        }

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_eth_phy(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_PHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump Ethernet PHY\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        r8125_spin_lock(&tp->phy_lock, flags);

        seq_puts(m, "\n####################page 0##################\n ");
        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_mdio_read(tp, n);
                        seq_printf(m, "%04x ", word_rd);
                }
        }

        seq_puts(m, "\n####################extra reg##################\n ");
        n = 0xA400;
        seq_printf(m, "\n0x%02x:\t", n);
        for (i = 0; i < 8; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                seq_printf(m, "%04x ", word_rd);
        }

        n = 0xA410;
        seq_printf(m, "\n0x%02x:\t", n);
        for (i = 0; i < 3; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                seq_printf(m, "%04x ", word_rd);
        }

        n = 0xA434;
        seq_printf(m, "\n0x%02x:\t", n);
        word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
        seq_printf(m, "%04x ", word_rd);

        n = 0xA5D0;
        seq_printf(m, "\n0x%02x:\t", n);
        for (i = 0; i < 4; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                seq_printf(m, "%04x ", word_rd);
        }

        n = 0xA61A;
        seq_printf(m, "\n0x%02x:\t", n);
        word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
        seq_printf(m, "%04x ", word_rd);

        n = 0xA6D0;
        seq_printf(m, "\n0x%02x:\t", n);
        for (i = 0; i < 3; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                seq_printf(m, "%04x ", word_rd);
        }

        r8125_spin_unlock(&tp->phy_lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_extended_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_ERI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);

        seq_puts(m, "\nDump Extended Registers\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        rtnl_lock();

        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        dword_rd = rtl8125_eri_read(tp, n, 4, ERIAR_ExGMAC);
                        seq_printf(m, "%08x ", dword_rd);
                }
        }

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_pci_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_PCI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);

        seq_puts(m, "\nDump PCI Registers\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        rtnl_lock();

        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%03x:\t", n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
                        seq_printf(m, "%08x ", dword_rd);
                }
        }

        n = 0x110;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        seq_printf(m, "\n0x%03x:\t%08x ", n, dword_rd);
        n = 0x70c;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        seq_printf(m, "\n0x%03x:\t%08x ", n, dword_rd);

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_temperature(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int cel, fah;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                seq_puts(m, "\nChip Temperature\n");
                break;
        default:
                return -EOPNOTSUPP;
        }

        rtnl_lock();

        if (!rtl8125_sysfs_testmode_on(tp)) {
                seq_puts(m, "\nPlease turn on ""/sys/class/net/<iface>/rtk_adv/testmode"".\n\n");
                rtnl_unlock();
                return 0;
        }

        r8125_spin_lock(&tp->phy_lock, flags);

        netif_testing_on(dev);
        cel = rtl8125_read_thermal_sensor(tp);
        netif_testing_off(dev);

        r8125_spin_unlock(&tp->phy_lock, flags);

        rtnl_unlock();

        fah = rtl8125_cel_to_fah(cel);

        seq_printf(m, "Cel:%d\n", cel);
        seq_printf(m, "Fah:%d\n", fah);

        seq_putc(m, '\n');
        return 0;
}

static int _proc_get_cable_info(struct seq_file *m, void *v, bool poe_mode)
{
        int i;
        u32 status;
        int cp_status[RTL8125_CP_NUM];
        int cp_len[RTL8125_CP_NUM] = {0};
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        const char *pair_str[RTL8125_CP_NUM] = {"1-2", "3-6", "4-5", "7-8"};
        unsigned long flags;
        int ret;

        switch (tp->mcfg) {
        case CFG_METHOD_2 ... CFG_METHOD_7:
                /* support */
                break;
        default:
                ret = -EOPNOTSUPP;
                goto error_out;
        }

        rtnl_lock();

        if (!rtl8125_sysfs_testmode_on(tp)) {
                seq_puts(m, "\nPlease turn on ""/sys/class/net/<iface>/rtk_adv/testmode"".\n\n");
                ret = 0;
                goto error_unlock;
        }

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        if (rtl8125_mdio_read(tp, MII_BMCR) & BMCR_PDOWN) {
                r8125_spin_unlock(&tp->phy_lock, flags);
                ret = -EIO;
                goto error_unlock;
        }

        netif_testing_on(dev);

        status = rtl8125_get_phy_status(tp);
        if (status & LinkStatus)
                seq_printf(m, "\nlink speed:%d",
                           rtl8125_convert_link_speed(status));
        else
                seq_puts(m, "\nlink status:off");

        rtl8125_get_cp_len(tp, cp_len);

        rtl8125_get_cp_status(tp, cp_status, poe_mode);

        r8125_spin_unlock(&tp->phy_lock, flags);

        seq_puts(m, "\npair\tlength\tstatus   \tpp\n");

        for (i=0; i<RTL8125_CP_NUM; i++) {
                if (cp_len[i] < 0)
                        seq_printf(m, "%s\t%s\t%s\t",
                                   pair_str[i], "none",
                                   rtl8125_get_cp_status_string(cp_status[i]));
                else
                        seq_printf(m, "%s\t%d\t%s\t",
                                   pair_str[i], cp_len[i],
                                   rtl8125_get_cp_status_string(cp_status[i]));
                if (cp_status[i] == rtl8125_cp_normal)
                        seq_printf(m, "none\n");
                else
                        seq_printf(m, "%dm\n", rtl8125_get_cp_pp(tp, i));
        }

        netif_testing_off(dev);

        seq_putc(m, '\n');

        ret = 0;

error_unlock:
        rtnl_unlock();

error_out:
        return ret;
}

static int proc_get_cable_info(struct seq_file *m, void *v)
{
        return _proc_get_cable_info(m, v, 0);
}

static int proc_get_poe_cable_info(struct seq_file *m, void *v)
{
        return _proc_get_cable_info(m, v, 1);
}

static void _proc_dump_desc(struct seq_file *m, void *desc_base, u32 alloc_size)
{
        u32 *pdword;
        int i;

        if (desc_base == NULL ||
            alloc_size == 0)
                return;

        pdword = (u32*)desc_base;
        for (i=0; i<(alloc_size/4); i++) {
                if (!(i % 4))
                        seq_printf(m, "\n%04x ", i);
                seq_printf(m, "%08x ", pdword[i]);
        }

        seq_putc(m, '\n');
        return;
}

static int proc_dump_rx_desc(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtnl_lock();

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];

                if (!ring)
                        continue;

                seq_printf(m, "\ndump rx %d desc:%d\n", i, ring->num_rx_desc);

                _proc_dump_desc(m, (void*)ring->RxDescArray, ring->RxDescAllocSize);
        }

#ifdef ENABLE_LIB_SUPPORT
        if (rtl8125_num_lib_rx_rings(tp) > 0) {
                for (i = 0; i < tp->HwSuppNumRxQueues; i++) {
                        struct rtl8125_ring *lib_ring = &tp->lib_rx_ring[i];
                        if (lib_ring->enabled) {
                                seq_printf(m, "\ndump lib rx %d desc:%d\n", i,
                                           lib_ring->ring_size);
                                _proc_dump_desc(m, (void*)lib_ring->desc_addr,
                                                lib_ring->desc_size);
                        }
                }
        }
#endif //ENABLE_LIB_SUPPORT

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_dump_tx_desc(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtnl_lock();

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];

                if (!ring)
                        continue;

                seq_printf(m, "\ndump tx %d desc:%d\n", i, ring->num_tx_desc);

                _proc_dump_desc(m, (void*)ring->TxDescArray, ring->TxDescAllocSize);
        }

#ifdef ENABLE_LIB_SUPPORT
        if (rtl8125_num_lib_tx_rings(tp) > 0) {
                for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                        struct rtl8125_ring *lib_ring = &tp->lib_tx_ring[i];
                        if (lib_ring->enabled) {
                                seq_printf(m, "\ndump lib tx %d desc:%d\n", i,
                                           lib_ring->ring_size);
                                _proc_dump_desc(m, (void*)lib_ring->desc_addr,
                                                lib_ring->desc_size);
                        }
                }
        }
#endif //ENABLE_LIB_SUPPORT

        rtnl_unlock();

        seq_putc(m, '\n');
        return 0;
}

static int proc_dump_msix_tbl(struct seq_file *m, void *v)
{
        int i, j;
        void __iomem *ioaddr;
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);

        /* ioremap MMIO region */
        ioaddr = ioremap(pci_resource_start(tp->pci_dev, 4), pci_resource_len(tp->pci_dev, 4));
        if (!ioaddr)
                return -EFAULT;

        rtnl_lock();

        seq_printf(m, "\ndump MSI-X Table. Total Entry %d. \n", tp->hw_supp_irq_nvecs);

        for (i=0; i<tp->hw_supp_irq_nvecs; i++) {
                seq_printf(m, "\n%04x ", i);
                for (j=0; j<4; j++)
                        seq_printf(m, "%08x ",
                                   readl(ioaddr + i*0x10 + 4*j));
        }

        rtnl_unlock();

        iounmap(ioaddr);

        seq_putc(m, '\n');
        return 0;
}

#else //LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)

static int proc_get_driver_variable(char *page, char **start,
                                    off_t offset, int count,
                                    int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Driver Driver\n");

        rtnl_lock();

        len += snprintf(page + len, count - len,
                        "Variable\tValue\n----------\t-----\n");

        len += snprintf(page + len, count - len,
                        "MODULENAME\t%s\n"
                        "driver version\t%s\n"
                        "mcfg\t%d\n"
                        "chipset\t%d\n"
                        "chipset_name\t%s\n"
                        "mtu\t%d\n"
                        "NUM_RX_DESC\t0x%x\n"
                        "cur_rx0\t0x%x\n"
                        "dirty_rx0\t0x%x\n"
                        "cur_rx1\t0x%x\n"
                        "dirty_rx1\t0x%x\n"
                        "cur_rx2\t0x%x\n"
                        "dirty_rx2\t0x%x\n"
                        "cur_rx3\t0x%x\n"
                        "dirty_rx3\t0x%x\n"
                        "NUM_TX_DESC\t0x%x\n"
                        "cur_tx0\t0x%x\n"
                        "dirty_tx0\t0x%x\n"
                        "cur_tx1\t0x%x\n"
                        "dirty_tx1\t0x%x\n"
                        "rx_buf_sz\t0x%x\n"
#ifdef ENABLE_PAGE_REUSE
                        "rx_buf_page_order\t0x%x\n"
                        "rx_buf_page_size\t0x%x\n"
                        "page_reuse_fail_cnt\t0x%x\n"
#endif //ENABLE_PAGE_REUSE
                        "esd_flag\t0x%x\n"
                        "pci_cfg_is_read\t0x%x\n"
                        "rtl8125_rx_config\t0x%x\n"
                        "cp_cmd\t0x%x\n"
                        "intr_mask\t0x%x\n"
                        "timer_intr_mask\t0x%x\n"
                        "wol_enabled\t0x%x\n"
                        "wol_opts\t0x%x\n"
                        "efuse_ver\t0x%x\n"
                        "eeprom_type\t0x%x\n"
                        "autoneg\t0x%x\n"
                        "duplex\t0x%x\n"
                        "speed\t%d\n"
                        "advertising\t0x%llx\n"
                        "eeprom_len\t0x%x\n"
                        "cur_page\t0x%x\n"
                        "features\t0x%x\n"
                        "org_pci_offset_99\t0x%x\n"
                        "org_pci_offset_180\t0x%x\n"
                        "issue_offset_99_event\t0x%x\n"
                        "org_pci_offset_80\t0x%x\n"
                        "org_pci_offset_81\t0x%x\n"
                        "use_timer_interrupt\t0x%x\n"
                        "HwIcVerUnknown\t0x%x\n"
                        "NotWrRamCodeToMicroP\t0x%x\n"
                        "NotWrMcuPatchCode\t0x%x\n"
                        "HwHasWrRamCodeToMicroP\t0x%x\n"
                        "sw_ram_code_ver\t0x%x\n"
                        "hw_ram_code_ver\t0x%x\n"
                        "rtk_enable_diag\t0x%x\n"
                        "ShortPacketSwChecksum\t0x%x\n"
                        "UseSwPaddingShortPkt\t0x%x\n"
                        "RequireAdcBiasPatch\t0x%x\n"
                        "AdcBiasPatchIoffset\t0x%x\n"
                        "RequireAdjustUpsTxLinkPulseTiming\t0x%x\n"
                        "SwrCnt1msIni\t0x%x\n"
                        "HwSuppNowIsOobVer\t0x%x\n"
                        "HwFiberModeVer\t0x%x\n"
                        "HwFiberStat\t0x%x\n"
                        "HwSwitchMdiToFiber\t0x%x\n"
                        "Led0\t0x%x\n"
                        "RequiredSecLanDonglePatch\t0x%x\n"
                        "RequiredPfmPatch\t0x%x\n"
                        "HwSuppDashVer\t0x%x\n"
                        "DASH\t0x%x\n"
                        "DashFirmwareVersion\t0x%x\n"
                        "HwSuppKCPOffloadVer\t0x%x\n"
                        "speed_mode\t0x%x\n"
                        "duplex_mode\t0x%x\n"
                        "autoneg_mode\t0x%x\n"
                        "aspm\t0x%x\n"
                        "s5wol\t0x%x\n"
                        "s5_keep_curr_mac\t0x%x\n"
                        "eee_enable\t0x%x\n"
                        "hwoptimize\t0x%lx\n"
                        "proc_init_num\t0x%x\n"
                        "s0_magic_packet\t0x%x\n"
                        "disable_wol_support\t0x%x\n"
                        "enable_double_vlan\t0x%x\n"
                        "eee_giga_lite\t0x%x\n"
                        "HwSuppMagicPktVer\t0x%x\n"
                        "HwSuppEsdVer\t0x%x\n"
                        "HwSuppLinkChgWakeUpVer\t0x%x\n"
                        "HwSuppD0SpeedUpVer\t0x%x\n"
                        "D0SpeedUpSpeed\t0x%x\n"
                        "HwSuppCheckPhyDisableModeVer\t0x%x\n"
                        "HwPkgDet\t0x%x\n"
                        "HwSuppTxNoCloseVer\t0x%x\n"
                        "EnableTxNoClose\t0x%x\n"
                        "NextHwDesCloPtr0\t0x%x\n"
                        "BeginHwDesCloPtr0\t0x%x\n"
                        "hw_clo_ptr_reg0\t0x%x\n"
                        "sw_tail_ptr_reg0\t0x%x\n"
                        "NextHwDesCloPtr1\t0x%x\n"
                        "BeginHwDesCloPtr1\t0x%x\n"
                        "hw_clo_ptr_reg1\t0x%x\n"
                        "sw_tail_ptr_reg1\t0x%x\n"
                        "InitRxDescType\t0x%x\n"
                        "RxDescLength\t0x%x\n"
                        "num_rx_rings\t0x%x\n"
                        "num_tx_rings\t0x%x\n"
                        "tot_rx_rings\t0x%x\n"
                        "tot_tx_rings\t0x%x\n"
                        "HwSuppNumRxQueues\t0x%x\n"
                        "HwSuppNumTxQueues\t0x%x\n"
                        "EnableRss\t0x%x\n"
                        "EnablePtp\t0x%x\n"
                        "ptp_master_mode\t0x%x\n"
                        "min_irq_nvecs\t0x%x\n"
                        "irq_nvecs\t0x%x\n"
                        "hw_supp_irq_nvecs\t0x%x\n"
                        "ring_lib_enabled\t0x%x\n"
                        "HwSuppIsrVer\t0x%x\n"
                        "HwCurrIsrVer\t0x%x\n"
                        "HwSuppMacMcuVer\t0x%x\n"
                        "MacMcuPageSize\t0x%x\n"
                        "hw_mcu_patch_code_ver\t0x%llx\n"
                        "bin_mcu_patch_code_ver\t0x%llx\n"
#ifdef ENABLE_PTP_SUPPORT
                        "tx_hwtstamp_timeouts\t0x%x\n"
                        "tx_hwtstamp_skipped\t0x%x\n"
#endif
                        "random_mac\t0x%x\n"
                        "org_mac_addr\t%pM\n"
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
                        "perm_addr\t%pM\n"
#endif
                        "dev_addr\t%pM\n",
                        MODULENAME,
                        RTL8125_VERSION,
                        tp->mcfg,
                        tp->chipset,
                        rtl_chip_info[tp->chipset].name,
                        dev->mtu,
                        tp->rx_ring[0].num_rx_desc,
                        tp->rx_ring[0].cur_rx,
                        tp->rx_ring[0].dirty_rx,
                        tp->rx_ring[1].cur_rx,
                        tp->rx_ring[1].dirty_rx,
                        tp->rx_ring[2].cur_rx,
                        tp->rx_ring[2].dirty_rx,
                        tp->rx_ring[3].cur_rx,
                        tp->rx_ring[3].dirty_rx,
                        tp->tx_ring[0].num_tx_desc,
                        tp->tx_ring[0].cur_tx,
                        tp->tx_ring[0].dirty_tx,
                        tp->tx_ring[1].cur_tx,
                        tp->tx_ring[1].dirty_tx,
                        tp->rx_buf_sz,
#ifdef ENABLE_PAGE_REUSE
                        tp->rx_buf_page_order,
                        tp->rx_buf_page_size,
                        tp->page_reuse_fail_cnt,
#endif //ENABLE_PAGE_REUSE
                        tp->esd_flag,
                        tp->pci_cfg_is_read,
                        tp->rtl8125_rx_config,
                        tp->cp_cmd,
                        tp->intr_mask,
                        tp->timer_intr_mask,
                        tp->wol_enabled,
                        tp->wol_opts,
                        tp->efuse_ver,
                        tp->eeprom_type,
                        tp->autoneg,
                        tp->duplex,
                        tp->speed,
                        tp->advertising,
                        tp->eeprom_len,
                        tp->cur_page,
                        tp->features,
                        tp->org_pci_offset_99,
                        tp->org_pci_offset_180,
                        tp->issue_offset_99_event,
                        tp->org_pci_offset_80,
                        tp->org_pci_offset_81,
                        tp->use_timer_interrupt,
                        tp->HwIcVerUnknown,
                        tp->NotWrRamCodeToMicroP,
                        tp->NotWrMcuPatchCode,
                        tp->HwHasWrRamCodeToMicroP,
                        tp->sw_ram_code_ver,
                        tp->hw_ram_code_ver,
                        tp->rtk_enable_diag,
                        tp->ShortPacketSwChecksum,
                        tp->UseSwPaddingShortPkt,
                        tp->RequireAdcBiasPatch,
                        tp->AdcBiasPatchIoffset,
                        tp->RequireAdjustUpsTxLinkPulseTiming,
                        tp->SwrCnt1msIni,
                        tp->HwSuppNowIsOobVer,
                        tp->HwFiberModeVer,
                        tp->HwFiberStat,
                        tp->HwSwitchMdiToFiber,
                        tp->BackupLedSel[0],
                        tp->RequiredSecLanDonglePatch,
                        tp->RequiredPfmPatch,
                        tp->HwSuppDashVer,
                        tp->DASH,
                        tp->DashFirmwareVersion,
                        tp->HwSuppKCPOffloadVer,
                        speed_mode,
                        duplex_mode,
                        autoneg_mode,
                        aspm,
                        s5wol,
                        s5_keep_curr_mac,
                        tp->eee.eee_enabled,
                        hwoptimize,
                        proc_init_num,
                        s0_magic_packet,
                        disable_wol_support,
                        enable_double_vlan,
                        eee_giga_lite,
                        tp->HwSuppMagicPktVer,
                        tp->HwSuppEsdVer,
                        tp->HwSuppLinkChgWakeUpVer,
                        tp->HwSuppD0SpeedUpVer,
                        tp->D0SpeedUpSpeed,
                        tp->HwSuppCheckPhyDisableModeVer,
                        tp->HwPkgDet,
                        tp->HwSuppTxNoCloseVer,
                        tp->EnableTxNoClose,
                        tp->tx_ring[0].NextHwDesCloPtr,
                        tp->tx_ring[0].BeginHwDesCloPtr,
                        rtl8125_get_hw_clo_ptr(&tp->tx_ring[0]),
                        rtl8125_get_sw_tail_ptr(&tp->tx_ring[0]),
                        tp->tx_ring[1].NextHwDesCloPtr,
                        tp->tx_ring[1].BeginHwDesCloPtr,
                        rtl8125_get_hw_clo_ptr(&tp->tx_ring[1]),
                        rtl8125_get_sw_tail_ptr(&tp->tx_ring[1]),
                        tp->InitRxDescType,
                        tp->RxDescLength,
                        tp->num_rx_rings,
                        tp->num_tx_rings,
                        rtl8125_tot_rx_rings(tp),
                        rtl8125_tot_tx_rings(tp),
                        tp->HwSuppNumRxQueues,
                        tp->HwSuppNumTxQueues,
                        tp->EnableRss,
                        tp->EnablePtp,
                        tp->ptp_master_mode,
                        tp->min_irq_nvecs,
                        tp->irq_nvecs,
                        tp->hw_supp_irq_nvecs,
                        tp->ring_lib_enabled,
                        tp->HwSuppIsrVer,
                        tp->HwCurrIsrVer,
                        tp->HwSuppMacMcuVer,
                        tp->MacMcuPageSize,
                        tp->hw_mcu_patch_code_ver,
                        tp->bin_mcu_patch_code_ver,
#ifdef ENABLE_PTP_SUPPORT
                        tp->tx_hwtstamp_timeouts,
                        tp->tx_hwtstamp_skipped,
#endif
                        tp->random_mac,
                        tp->org_mac_addr,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
                        dev->perm_addr,
#endif
                        dev->dev_addr);

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_tally_counter(char *page, char **start,
                                  off_t offset, int count,
                                  int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Tally Counter\n");

        rtnl_lock();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters) {
                len += snprintf(page + len, count - len,
                                "\nDump Tally Counter Fail\n");
                goto out_unlock;
        }

        rtl8125_dump_tally_counter(tp, paddr);

        len += snprintf(page + len, count - len,
                        "Statistics\tValue\n----------\t-----\n");

        len += snprintf(page + len, count - len,
                        "tx_packets\t%lld\n"
                        "rx_packets\t%lld\n"
                        "tx_errors\t%lld\n"
                        "rx_errors\t%d\n"
                        "rx_missed\t%d\n"
                        "align_errors\t%d\n"
                        "tx_one_collision\t%d\n"
                        "tx_multi_collision\t%d\n"
                        "rx_unicast\t%lld\n"
                        "rx_broadcast\t%lld\n"
                        "rx_multicast\t%d\n"
                        "tx_aborted\t%d\n"
                        "tx_underrun\t%d\n"

                        "tx_octets\t%lld\n"
                        "rx_octets\t%lld\n"
                        "rx_multicast64\t%lld\n"
                        "tx_unicast64\t%lld\n"
                        "tx_broadcast64\t%lld\n"
                        "tx_multicast64\t%lld\n"
                        "tx_pause_on\t%d\n"
                        "tx_pause_off\t%d\n"
                        "tx_pause_all\t%d\n"
                        "tx_deferred\t%d\n"
                        "tx_late_collision\t%d\n"
                        "tx_all_collision\t%d\n"
                        "tx_aborted32\t%d\n"
                        "align_errors32\t%d\n"
                        "rx_frame_too_long\t%d\n"
                        "rx_runt\t%d\n"
                        "rx_pause_on\t%d\n"
                        "rx_pause_off\t%d\n"
                        "rx_pause_all\t%d\n"
                        "rx_unknown_opcode\t%d\n"
                        "rx_mac_error\t%d\n"
                        "tx_underrun32\t%d\n"
                        "rx_mac_missed\t%d\n"
                        "rx_tcam_dropped\t%d\n"
                        "tdu\t%d\n"
                        "rdu\t%d\n",
                        le64_to_cpu(counters->tx_packets),
                        le64_to_cpu(counters->rx_packets),
                        le64_to_cpu(counters->tx_errors),
                        le32_to_cpu(counters->rx_errors),
                        le16_to_cpu(counters->rx_missed),
                        le16_to_cpu(counters->align_errors),
                        le32_to_cpu(counters->tx_one_collision),
                        le32_to_cpu(counters->tx_multi_collision),
                        le64_to_cpu(counters->rx_unicast),
                        le64_to_cpu(counters->rx_broadcast),
                        le32_to_cpu(counters->rx_multicast),
                        le16_to_cpu(counters->tx_aborted),
                        le16_to_cpu(counters->tx_underrun),

                        le64_to_cpu(counters->tx_octets),
                        le64_to_cpu(counters->rx_octets),
                        le64_to_cpu(counters->rx_multicast64),
                        le64_to_cpu(counters->tx_unicast64),
                        le64_to_cpu(counters->tx_broadcast64),
                        le64_to_cpu(counters->tx_multicast64),
                        le32_to_cpu(counters->tx_pause_on),
                        le32_to_cpu(counters->tx_pause_off),
                        le32_to_cpu(counters->tx_pause_all),
                        le32_to_cpu(counters->tx_deferred),
                        le32_to_cpu(counters->tx_late_collision),
                        le32_to_cpu(counters->tx_all_collision),
                        le32_to_cpu(counters->tx_aborted32),
                        le32_to_cpu(counters->align_errors32),
                        le32_to_cpu(counters->rx_frame_too_long),
                        le32_to_cpu(counters->rx_runt),
                        le32_to_cpu(counters->rx_pause_on),
                        le32_to_cpu(counters->rx_pause_off),
                        le32_to_cpu(counters->rx_pause_all),
                        le32_to_cpu(counters->rx_unknown_opcode),
                        le32_to_cpu(counters->rx_mac_error),
                        le32_to_cpu(counters->tx_underrun32),
                        le32_to_cpu(counters->rx_mac_missed),
                        le32_to_cpu(counters->rx_tcam_dropped),
                        le32_to_cpu(counters->tdu),
                        le32_to_cpu(counters->rdu));

        len += snprintf(page + len, count - len, "\n");
out_unlock:
        rtnl_unlock();

        *eof = 1;
        return len;
}

static int proc_get_registers(char *page, char **start,
                              off_t offset, int count,
                              int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_MAC_REGS_SIZE;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump MAC Registers\n"
                        "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%04x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }

        max = 0xB00;
        for (n = 0xA00; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%04x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }

        max = 0xD40;
        for (n = 0xD00; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%04x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }

        max = 0x2840;
        for (n = 0x2800; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%04x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_all_registers(char *page, char **start,
                                  off_t offset, int count,
                                  int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        struct pci_dev *pdev = tp->pci_dev;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump All MAC Registers\n"
                        "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        max = pci_resource_len(pdev, 2);
        max = min(max, 0x8000);

        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%04x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\nTotal length:0x%X", max);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_pcie_phy(char *page, char **start,
                             off_t offset, int count,
                             int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_EPHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump PCIE PHY\n"
                        "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_ephy_read(tp, n);
                        len += snprintf(page + len, count - len,
                                        "%04x ",
                                        word_rd);
                }
        }

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_eth_phy(char *page, char **start,
                            off_t offset, int count,
                            int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_PHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Ethernet PHY\n"
                        "Offset\tValue\n------\t-----\n");

        r8125_spin_lock(&tp->phy_lock, flags);

        len += snprintf(page + len, count - len,
                        "\n####################page 0##################\n");
        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_mdio_read(tp, n);
                        len += snprintf(page + len, count - len,
                                        "%04x ",
                                        word_rd);
                }
        }

        len += snprintf(page + len, count - len,
                        "\n####################extra reg##################\n");
        n = 0xA400;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        for (i = 0; i < 8; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                len += snprintf(page + len, count - len,
                                "%04x ",
                                word_rd);
        }

        n = 0xA410;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        for (i = 0; i < 3; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                len += snprintf(page + len, count - len,
                                "%04x ",
                                word_rd);
        }

        n = 0xA434;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
        len += snprintf(page + len, count - len,
                        "%04x ",
                        word_rd);

        n = 0xA5D0;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        for (i = 0; i < 4; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                len += snprintf(page + len, count - len,
                                "%04x ",
                                word_rd);
        }

        n = 0xA61A;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
        len += snprintf(page + len, count - len,
                        "%04x ",
                        word_rd);

        n = 0xA6D0;
        len += snprintf(page + len, count - len,
                        "\n0x%02x:\t",
                        n);
        for (i = 0; i < 3; i++, n+=2) {
                word_rd = rtl8125_mdio_direct_read_phy_ocp(tp, n);
                len += snprintf(page + len, count - len,
                                "%04x ",
                                word_rd);
        }

        r8125_spin_unlock(&tp->phy_lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_extended_registers(char *page, char **start,
                                       off_t offset, int count,
                                       int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_ERI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Extended Registers\n"
                        "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        dword_rd = rtl8125_eri_read(tp, n, 4, ERIAR_ExGMAC);
                        len += snprintf(page + len, count - len,
                                        "%08x ",
                                        dword_rd);
                }
        }

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_pci_registers(char *page, char **start,
                                  off_t offset, int count,
                                  int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_PCI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump PCI Registers\n"
                        "Offset\tValue\n------\t-----\n");

        rtnl_lock();

        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%03x:\t",
                                n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
                        len += snprintf(page + len, count - len,
                                        "%08x ",
                                        dword_rd);
                }
        }

        n = 0x110;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        len += snprintf(page + len, count - len,
                        "\n0x%03x:\t%08x ",
                        n,
                        dword_rd);
        n = 0x70c;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        len += snprintf(page + len, count - len,
                        "\n0x%03x:\t%08x ",
                        n,
                        dword_rd);

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_temperature(char *page, char **start,
                                off_t offset, int count,
                                int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int cel, fah;
        int len = 0;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                len += snprintf(page + len, count - len,
                                "\nChip Temperature\n");
                break;
        default:
                return -EOPNOTSUPP;
        }

        rtnl_lock();

        if (!rtl8125_sysfs_testmode_on(tp)) {
                len += snprintf(page + len, count - len,
                                "\nPlease turn on ""/sys/class/net/<iface>/rtk_adv/testmode"".\n\n");
                goto out_unlock;
        }

        r8125_spin_lock(&tp->phy_lock, flags);
        cel = rtl8125_read_thermal_sensor(tp);
        r8125_spin_unlock(&tp->phy_lock, flags);

        fah = rtl8125_cel_to_fah(cel);

        len += snprintf(page + len, count - len,
                        "Cel:%d\n",
                        cel);
        len += snprintf(page + len, count - len,
                        "Fah:%d\n",
                        fah);

        len += snprintf(page + len, count - len, "\n");

out_unlock:
        rtnl_unlock();

        *eof = 1;
        return len;
}

static int _proc_get_cable_info(char *page, char **start,
                                off_t offset, int count,
                                int *eof, void *data,
                                bool poe_mode)
{
        int i;
        u32 status;
        int len = 0;
        struct net_device *dev = data;
        int cp_status[RTL8125_CP_NUM] = {0};
        int cp_len[RTL8125_CP_NUM] = {0};
        struct rtl8125_private *tp = netdev_priv(dev);
        const char *pair_str[RTL8125_CP_NUM] = {"1-2", "3-6", "4-5", "7-8"};
        unsigned long flags;

        switch (tp->mcfg) {
        case CFG_METHOD_2 ... CFG_METHOD_7:
                /* support */
                break;
        default:
                return -EOPNOTSUPP;
        }

        rtnl_lock();

        r8125_spin_lock(&tp->phy_lock, flags);

        if (!rtl8125_sysfs_testmode_on(tp)) {
                len += snprintf(page + len, count - len,
                                "\nPlease turn on ""/sys/class/net/<iface>/rtk_adv/testmode"".\n\n");
                goto out_unlock;
        }

        status = rtl8125_get_phy_status(tp);
        if (status & LinkStatus)
                len += snprintf(page + len, count - len,
                                "\nlink speed:%d",
                                rtl8125_convert_link_speed(status));
        else
                len += snprintf(page + len, count - len,
                                "\nlink status:off");

        rtl8125_get_cp_len(tp, cp_len);

        rtl8125_get_cp_status(tp, cp_status, poe_mode);

        len += snprintf(page + len, count - len,
                        "\npair\tlength\tstatus   \tpp\n");

        for (i=0; i<RTL8125_CP_NUM; i++) {
                if (cp_len[i] < 0)
                        len += snprintf(page + len, count - len,
                                        "%s\t%s\t%s\t",
                                        pair_str[i], "none",
                                        rtl8125_get_cp_status_string(cp_status[i]));
                else
                        len += snprintf(page + len, count - len,
                                        "%s\t%d\t%s\t",
                                        pair_str[i], cp_len[i],
                                        rtl8125_get_cp_status_string(cp_status[i]));
                if (cp_status[i] == rtl8125_cp_normal)
                        len += snprintf(page + len, count - len, "none\n");
                else
                        len += snprintf(page + len, count - len, "%dm\n",
                                        rtl8125_get_cp_pp(tp, i));
        }

        len += snprintf(page + len, count - len, "\n");

out_unlock:
        r8125_spin_unlock(&tp->phy_lock, flags);

        rtnl_unlock();

        *eof = 1;
        return len;
}

static int proc_get_cable_info(char *page, char **start,
                               off_t offset, int count,
                               int *eof, void *data)
{
        return _proc_get_cable_info(page, start, offset, count, eof, data, 0);
}

static int proc_get_poe_cable_info(char *page, char **start,
                                   off_t offset, int count,
                                   int *eof, void *data)
{
        return _proc_get_cable_info(page, start, offset, count, eof, data, 1);
}

static void _proc_dump_desc(char *page, int *page_len, int *count, void *desc_base,
                            u32 alloc_size)
{
        u32 *pdword;
        int i, len;

        if (desc_base == NULL ||
            alloc_size == 0)
                return;

        len = *page_len;
        pdword = (u32*)desc_base;
        for (i=0; i<(alloc_size/4); i++) {
                if (!(i % 4))
                        len += snprintf(page + len, *count - len,
                                        "\n%04x ",
                                        i);
                len += snprintf(page + len, *count - len,
                                "%08x ",
                                pdword[i]);
        }

        len += snprintf(page + len, *count - len, "\n");

        *page_len = len;
        return;
}

static int proc_dump_rx_desc(char *page, char **start,
                             off_t offset, int count,
                             int *eof, void *data)
{
        int i;
        int len = 0;
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);

        rtnl_lock();

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];

                if (!ring)
                        continue;

                len += snprintf(page + len, count - len,
                                "\ndump rx %d desc:%d",
                                i, ring->num_rx_desc);

                _proc_dump_desc(page, &len, &count,
                                ring->RxDescArray,
                                ring->RxDescAllocSize);
        }

#ifdef ENABLE_LIB_SUPPORT
        if (rtl8125_num_lib_rx_rings(tp) > 0) {
                for (i = 0; i < tp->HwSuppNumRxQueues; i++) {
                        struct rtl8125_ring *lib_ring = &tp->lib_rx_ring[i];
                        if (lib_ring->enabled) {
                                len += snprintf(page + len, count - len,
                                                "\ndump lib rx %d desc:%d",
                                                i,
                                                ring->ring_size);
                                _proc_dump_desc(page, &len, &count,
                                                (void*)lib_ring->desc_addr,
                                                lib_ring->desc_size);
                        }
                }
        }
#endif //ENABLE_LIB_SUPPORT

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;

        return len;
}

static int proc_dump_tx_desc(char *page, char **start,
                             off_t offset, int count,
                             int *eof, void *data)
{
        int len = 0;
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtnl_lock();

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];

                if (!ring)
                        continue;

                len += snprintf(page + len, count - len,
                                "\ndump tx desc:%d",
                                ring->num_tx_desc);

                _proc_dump_desc(page, &len, &count,
                                ring->TxDescArray,
                                ring->TxDescAllocSize);
        }

#ifdef ENABLE_LIB_SUPPORT
        if (rtl8125_num_lib_tx_rings(tp) > 0) {
                for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                        struct rtl8125_ring *lib_ring = &tp->lib_tx_ring[i];
                        if (lib_ring->enabled) {
                                len += snprintf(page + len, count - len,
                                                "\ndump lib tx %d desc:%d",
                                                i,
                                                ring->ring_size);
                                _proc_dump_desc(page, &len, &count,
                                                (void*)lib_ring->desc_addr,
                                                lib_ring->desc_size);
                        }
                }
        }
#endif //ENABLE_LIB_SUPPORT

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;

        return len;
}

static int proc_dump_msix_tbl(char *page, char **start,
                              off_t offset, int count,
                              int *eof, void *data)
{
        int i, j;
        int len = 0;
        void __iomem *ioaddr;
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);

        /* ioremap MMIO region */
        ioaddr = ioremap(pci_resource_start(tp->pci_dev, 4), pci_resource_len(tp->pci_dev, 4));
        if (!ioaddr)
                return -EFAULT;

        rtnl_lock();

        len += snprintf(page + len, count - len,
                        "\ndump MSI-X Table. Total Entry %d. \n",
                        tp->hw_supp_irq_nvecs);

        for (i=0; i<tp->hw_supp_irq_nvecs; i++) {
                len += snprintf(page + len, count - len,
                                "\n%04x ", i);
                for (j=0; j<4; j++)
                        len += snprintf(page + len, count - len, "%08x ",
                                        readl(ioaddr + i*0x10 + 4*j));
        }

        rtnl_unlock();

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return 0;
}

#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)

static void rtl8125_proc_module_init(void)
{
        //create /proc/net/r8125
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
        rtl8125_proc = proc_mkdir(MODULENAME, init_net.proc_net);
#else
        rtl8125_proc = proc_mkdir(MODULENAME, proc_net);
#endif
        if (!rtl8125_proc)
                dprintk("cannot create %s proc entry \n", MODULENAME);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
/*
 * seq_file wrappers for procfile show routines.
 */
static int rtl8125_proc_open(struct inode *inode, struct file *file)
{
        struct net_device *dev = proc_get_parent_data(inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
        int (*show)(struct seq_file *, void *) = pde_data(inode);
#else
        int (*show)(struct seq_file *, void *) = PDE_DATA(inode);
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)

        return single_open(file, show, dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops rtl8125_proc_fops = {
        .proc_open           = rtl8125_proc_open,
        .proc_read           = seq_read,
        .proc_lseek          = seq_lseek,
        .proc_release        = single_release,
};
#else
static const struct file_operations rtl8125_proc_fops = {
        .open           = rtl8125_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};
#endif

#endif

/*
 * Table of proc files we need to create.
 */
struct rtl8125_proc_file {
        char name[16];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        int (*show)(struct seq_file *, void *);
#else
        int (*show)(char *, char **, off_t, int, int *, void *);
#endif
};

static const struct rtl8125_proc_file rtl8125_debug_proc_files[] = {
        { "driver_var", &proc_get_driver_variable },
        { "tally", &proc_get_tally_counter },
        { "registers", &proc_get_registers },
        { "registers2", &proc_get_all_registers },
        { "pcie_phy", &proc_get_pcie_phy },
        { "eth_phy", &proc_get_eth_phy },
        { "ext_regs", &proc_get_extended_registers },
        { "pci_regs", &proc_get_pci_registers },
        { "tx_desc", &proc_dump_tx_desc },
        { "rx_desc", &proc_dump_rx_desc },
        { "msix_tbl", &proc_dump_msix_tbl },
        { "", NULL }
};

static const struct rtl8125_proc_file rtl8125_test_proc_files[] = {
        { "temp", &proc_get_temperature },
        { "cdt", &proc_get_cable_info },
        { "cdt_poe", &proc_get_poe_cable_info },
        { "", NULL }
};

#define R8125_PROC_DEBUG_DIR "debug"
#define R8125_PROC_TEST_DIR "test"

static void rtl8125_proc_init(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        const struct rtl8125_proc_file *f;
        struct proc_dir_entry *dir;

        if (!rtl8125_proc)
                return;

        if (tp->proc_dir_debug || tp->proc_dir_test)
                return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        dir = proc_mkdir_data(dev->name, 0, rtl8125_proc, dev);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s\n",
                       MODULENAME, dev->name);
                return;
        }
        tp->proc_dir = dir;
        proc_init_num++;

        /* create debug entry */
        dir = proc_mkdir_data(R8125_PROC_DEBUG_DIR, 0, tp->proc_dir, dev);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s/%s\n",
                       MODULENAME, dev->name, R8125_PROC_DEBUG_DIR);
                return;
        }

        tp->proc_dir_debug = dir;
        for (f = rtl8125_debug_proc_files; f->name[0]; f++) {
                if (!proc_create_data(f->name, S_IFREG | S_IRUGO, dir,
                                      &rtl8125_proc_fops, f->show)) {
                        printk("Unable to initialize "
                               "/proc/net/%s/%s/%s/%s\n",
                               MODULENAME, dev->name, R8125_PROC_DEBUG_DIR,
                               f->name);
                        return;
                }
        }

        /* create test entry */
        dir = proc_mkdir_data(R8125_PROC_TEST_DIR, 0, tp->proc_dir, dev);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s/%s\n",
                       MODULENAME, dev->name, R8125_PROC_TEST_DIR);
                return;
        }

        tp->proc_dir_test = dir;
        for (f = rtl8125_test_proc_files; f->name[0]; f++) {
                if (!proc_create_data(f->name, S_IFREG | S_IRUGO, dir,
                                      &rtl8125_proc_fops, f->show)) {
                        printk("Unable to initialize "
                               "/proc/net/%s/%s/%s/%s\n",
                               MODULENAME, dev->name, R8125_PROC_TEST_DIR,
                               f->name);
                        return;
                }
        }
#else
        dir = proc_mkdir(dev->name, rtl8125_proc);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s\n",
                       MODULENAME, dev->name);
                return;
        }

        tp->proc_dir = dir;
        proc_init_num++;

        /* create debug entry */
        dir = proc_mkdir(R8125_PROC_DEBUG_DIR, tp->proc_dir);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s/%s\n",
                       MODULENAME, dev->name, R8125_PROC_DEBUG_DIR);
                return;
        }

        tp->proc_dir_debug = dir;
        for (f = rtl8125_debug_proc_files; f->name[0]; f++) {
                if (!create_proc_read_entry(f->name, S_IFREG | S_IRUGO,
                                            dir, f->show, dev)) {
                        printk("Unable to initialize "
                               "/proc/net/%s/%s/%s/%s\n",
                               MODULENAME, dev->name, R8125_PROC_DEBUG_DIR,
                               f->name);
                        return;
                }
        }

        /* create test entry */
        dir = proc_mkdir(R8125_PROC_TEST_DIR, tp->proc_dir);
        if (!dir) {
                printk("Unable to initialize /proc/net/%s/%s/%s\n",
                       MODULENAME, dev->name, R8125_PROC_TEST_DIR);
                return;
        }

        tp->proc_dir_test = dir;
        for (f = rtl8125_test_proc_files; f->name[0]; f++) {
                if (!create_proc_read_entry(f->name, S_IFREG | S_IRUGO,
                                            dir, f->show, dev)) {
                        printk("Unable to initialize "
                               "/proc/net/%s/%s/%s/%s\n",
                               MODULENAME, dev->name, R8125_PROC_TEST_DIR,
                               f->name);
                        return;
                }
        }
#endif
}

static void rtl8125_proc_remove(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->proc_dir) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                remove_proc_subtree(dev->name, rtl8125_proc);
#else
                const struct rtl8125_proc_file *f;
                struct rtl8125_private *tp = netdev_priv(dev);

                if (tp->proc_dir_debug) {
                        for (f = rtl8125_debug_proc_files; f->name[0]; f++)
                                remove_proc_entry(f->name, tp->proc_dir_debug);
                        remove_proc_entry(R8125_PROC_DEBUG_DIR, tp->proc_dir);
                }

                if (tp->proc_dir_test) {
                        for (f = rtl8125_test_proc_files; f->name[0]; f++)
                                remove_proc_entry(f->name, tp->proc_dir_test);
                        remove_proc_entry(R8125_PROC_TEST_DIR, tp->proc_dir);
                }

                remove_proc_entry(dev->name, rtl8125_proc);
#endif
                proc_init_num--;

                tp->proc_dir_debug = NULL;
                tp->proc_dir_test = NULL;
                tp->proc_dir = NULL;
        }
}

#endif //ENABLE_R8125_PROCFS

#ifdef ENABLE_R8125_SYSFS
/****************************************************************************
*   -----------------------------SYSFS STUFF-------------------------
*****************************************************************************
*/
static ssize_t testmode_show(struct device *dev,
                             struct device_attribute *attr, char *buf)
{
        struct net_device *netdev = to_net_dev(dev);
        struct rtl8125_private *tp = netdev_priv(netdev);

        sprintf(buf, "%u\n", tp->testmode);

        return strlen(buf);
}

static ssize_t testmode_store(struct device *dev,
                              struct device_attribute *attr,
                              const char *buf, size_t count)
{
        struct net_device *netdev = to_net_dev(dev);
        struct rtl8125_private *tp = netdev_priv(netdev);
        u32 testmode;

        if (sscanf(buf, "%u\n", &testmode) != 1)
                return -EINVAL;

        if (tp->testmode != testmode) {
                rtnl_lock();
                tp->testmode = testmode;
                rtnl_unlock();
        }

        return count;
}

static DEVICE_ATTR_RW(testmode);

static struct attribute *rtk_adv_attrs[] = {
        &dev_attr_testmode.attr,
        NULL
};

static struct attribute_group rtk_adv_grp = {
        .name = "rtl_adv",
        .attrs = rtk_adv_attrs,
};

static void rtl8125_sysfs_init(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret;

        /* init rtl_adv */
#ifdef ENABLE_LIB_SUPPORT
        tp->testmode = 0;
#else
        tp->testmode = 1;
#endif //ENABLE_LIB_SUPPORT

        ret = sysfs_create_group(&dev->dev.kobj, &rtk_adv_grp);
        if (ret < 0)
                netif_warn(tp, probe, dev, "create rtk_adv_grp fail\n");
        else
                set_bit(R8125_SYSFS_RTL_ADV, tp->sysfs_flag);
}

static void rtl8125_sysfs_remove(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (test_and_clear_bit(R8125_SYSFS_RTL_ADV, tp->sysfs_flag))
                sysfs_remove_group(&dev->dev.kobj, &rtk_adv_grp);
}
#endif //ENABLE_R8125_SYSFS

static inline u16 map_phy_ocp_addr(u16 PageNum, u8 RegNum)
{
        u16 OcpPageNum = 0;
        u8 OcpRegNum = 0;
        u16 OcpPhyAddress = 0;

        if (PageNum == 0) {
                OcpPageNum = OCP_STD_PHY_BASE_PAGE + (RegNum / 8);
                OcpRegNum = 0x10 + (RegNum % 8);
        } else {
                OcpPageNum = PageNum;
                OcpRegNum = RegNum;
        }

        OcpPageNum <<= 4;

        if (OcpRegNum < 16) {
                OcpPhyAddress = 0;
        } else {
                OcpRegNum -= 16;
                OcpRegNum <<= 1;

                OcpPhyAddress = OcpPageNum + OcpRegNum;
        }


        return OcpPhyAddress;
}

static void mdio_real_direct_write_phy_ocp(struct rtl8125_private *tp,
                u16 RegAddr,
                u16 value)
{
        u32 data32;
        int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(RegAddr % 2);
#endif
        data32 = RegAddr/2;
        data32 <<= OCPR_Addr_Reg_shift;
        data32 |= OCPR_Write | value;

        RTL_W32(tp, PHYOCP, data32);
        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                if (!(RTL_R32(tp, PHYOCP) & OCPR_Flag))
                        break;
        }
}

void rtl8125_mdio_direct_write_phy_ocp(struct rtl8125_private *tp,
                                       u16 RegAddr,
                                       u16 value)
{
        if (tp->rtk_enable_diag)
                return;

        mdio_real_direct_write_phy_ocp(tp, RegAddr, value);
}

/*
void rtl8125_mdio_write_phy_ocp(struct rtl8125_private *tp,
                                       u16 PageNum,
                                       u32 RegAddr,
                                       u32 value)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        rtl8125_mdio_direct_write_phy_ocp(tp, ocp_addr, value);
}
*/

static void rtl8125_mdio_real_write_phy_ocp(struct rtl8125_private *tp,
                u16 PageNum,
                u32 RegAddr,
                u32 value)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        mdio_real_direct_write_phy_ocp(tp, ocp_addr, value);
}

static void mdio_real_write(struct rtl8125_private *tp,
                            u16 RegAddr,
                            u16 value)
{
        if (RegAddr == 0x1F) {
                tp->cur_page = value;
                return;
        }
        rtl8125_mdio_real_write_phy_ocp(tp, tp->cur_page, RegAddr, value);
}

void rtl8125_mdio_write(struct rtl8125_private *tp,
                        u16 RegAddr,
                        u16 value)
{
        if (tp->rtk_enable_diag)
                return;

        mdio_real_write(tp, RegAddr, value);
}

void rtl8125_mdio_prot_write(struct rtl8125_private *tp,
                             u32 RegAddr,
                             u32 value)
{
        mdio_real_write(tp, RegAddr, value);
}

void rtl8125_mdio_prot_direct_write_phy_ocp(struct rtl8125_private *tp,
                u32 RegAddr,
                u32 value)
{
        mdio_real_direct_write_phy_ocp(tp, RegAddr, value);
}

static u32 mdio_real_direct_read_phy_ocp(struct rtl8125_private *tp,
                u16 RegAddr)
{
        u32 data32;
        int i, value = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(RegAddr % 2);
#endif
        data32 = RegAddr/2;
        data32 <<= OCPR_Addr_Reg_shift;

        RTL_W32(tp, PHYOCP, data32);
        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                if (RTL_R32(tp, PHYOCP) & OCPR_Flag)
                        break;
        }
        value = RTL_R32(tp, PHYOCP) & OCPDR_Data_Mask;

        return value;
}

u32 rtl8125_mdio_direct_read_phy_ocp(struct rtl8125_private *tp,
                                     u16 RegAddr)
{
        if (tp->rtk_enable_diag)
                return 0xffffffff;

        return mdio_real_direct_read_phy_ocp(tp, RegAddr);
}

/*
static u32 rtl8125_mdio_read_phy_ocp(struct rtl8125_private *tp,
                                     u16 PageNum,
                                     u32 RegAddr)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        return rtl8125_mdio_direct_read_phy_ocp(tp, ocp_addr);
}
*/

static u32 rtl8125_mdio_real_read_phy_ocp(struct rtl8125_private *tp,
                u16 PageNum,
                u32 RegAddr)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        return mdio_real_direct_read_phy_ocp(tp, ocp_addr);
}

static u32 mdio_real_read(struct rtl8125_private *tp,
                          u16 RegAddr)
{
        return rtl8125_mdio_real_read_phy_ocp(tp, tp->cur_page, RegAddr);
}

u32 rtl8125_mdio_read(struct rtl8125_private *tp,
                      u16 RegAddr)
{
        if (tp->rtk_enable_diag)
                return 0xffffffff;

        return mdio_real_read(tp, RegAddr);
}

u32 rtl8125_mdio_prot_read(struct rtl8125_private *tp,
                           u32 RegAddr)
{
        return mdio_real_read(tp, RegAddr);
}

u32 rtl8125_mdio_prot_direct_read_phy_ocp(struct rtl8125_private *tp,
                u32 RegAddr)
{
        return mdio_real_direct_read_phy_ocp(tp, RegAddr);
}

static void rtl8125_clear_and_set_eth_phy_bit(struct rtl8125_private *tp, u8  addr, u16 clearmask, u16 setmask)
{
        u16 PhyRegValue;

        PhyRegValue = rtl8125_mdio_read(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        rtl8125_mdio_write(tp, addr, PhyRegValue);
}

void rtl8125_clear_eth_phy_bit(struct rtl8125_private *tp, u8 addr, u16 mask)
{
        rtl8125_clear_and_set_eth_phy_bit(tp,
                                          addr,
                                          mask,
                                          0);
}

void rtl8125_set_eth_phy_bit(struct rtl8125_private *tp,  u8  addr, u16  mask)
{
        rtl8125_clear_and_set_eth_phy_bit(tp,
                                          addr,
                                          0,
                                          mask);
}

void rtl8125_clear_and_set_eth_phy_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 clearmask, u16 setmask)
{
        u16 PhyRegValue;

        PhyRegValue = rtl8125_mdio_direct_read_phy_ocp(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        rtl8125_mdio_direct_write_phy_ocp(tp, addr, PhyRegValue);
}

void rtl8125_clear_eth_phy_ocp_bit(struct rtl8125_private *tp, u16 addr, u16 mask)
{
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              addr,
                                              mask,
                                              0);
}

void rtl8125_set_eth_phy_ocp_bit(struct rtl8125_private *tp,  u16 addr, u16 mask)
{
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              addr,
                                              0,
                                              mask);
}

void rtl8125_mac_ocp_write(struct rtl8125_private *tp, u16 reg_addr, u16 value)
{
        u32 data32;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(reg_addr % 2);
#endif

        data32 = reg_addr/2;
        data32 <<= OCPR_Addr_Reg_shift;
        data32 += value;
        data32 |= OCPR_Write;

        RTL_W32(tp, MACOCP, data32);
}

u16 rtl8125_mac_ocp_read(struct rtl8125_private *tp, u16 reg_addr)
{
        u32 data32;
        u16 data16 = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(reg_addr % 2);
#endif

        data32 = reg_addr/2;
        data32 <<= OCPR_Addr_Reg_shift;

        RTL_W32(tp, MACOCP, data32);
        data16 = (u16)RTL_R32(tp, MACOCP);

        return data16;
}

#ifdef ENABLE_USE_FIRMWARE_FILE
static void mac_mcu_write(struct rtl8125_private *tp, u16 reg, u16 value)
{
        if (reg == 0x1f) {
                tp->ocp_base = value << 4;
                return;
        }

        rtl8125_mac_ocp_write(tp, tp->ocp_base + reg, value);
}

static u32 mac_mcu_read(struct rtl8125_private *tp, u16 reg)
{
        return rtl8125_mac_ocp_read(tp, tp->ocp_base + reg);
}
#endif

static void
rtl8125_clear_set_mac_ocp_bit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   clearmask,
        u16   setmask
)
{
        u16 PhyRegValue;

        PhyRegValue = rtl8125_mac_ocp_read(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        rtl8125_mac_ocp_write(tp, addr, PhyRegValue);
}

void
rtl8125_clear_mac_ocp_bit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   mask
)
{
        rtl8125_clear_set_mac_ocp_bit(tp,
                                      addr,
                                      mask,
                                      0);
}

void
rtl8125_set_mac_ocp_bit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   mask
)
{
        rtl8125_clear_set_mac_ocp_bit(tp,
                                      addr,
                                      0,
                                      mask);
}

u32 rtl8125_ocp_read_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, const u32 base_address)
{
        return rtl8125_eri_read_with_oob_base_address(tp, addr, len, ERIAR_OOB, base_address);
}

u32 rtl8125_ocp_read(struct rtl8125_private *tp, u16 addr, u8 len)
{
        if (!tp->AllowAccessDashOcp || tp->HwSuppOcpChannelVer != 2)
                return 0xffffffff;

        return rtl8125_ocp_read_with_oob_base_address(tp, addr, len,
                        NO_BASE_ADDRESS);
}

u32 rtl8125_ocp_write_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, u32 value, const u32 base_address)
{
        return rtl8125_eri_write_with_oob_base_address(tp, addr, len, value,
                        ERIAR_OOB, base_address);
}

void rtl8125_ocp_write(struct rtl8125_private *tp, u16 addr, u8 len, u32 value)
{
        if (!tp->AllowAccessDashOcp || tp->HwSuppOcpChannelVer != 2)
                return;

        rtl8125_ocp_write_with_oob_base_address(tp, addr, len, value, NO_BASE_ADDRESS);
}

void rtl8125_oob_mutex_lock(struct rtl8125_private *tp)
{
        u8 reg_16, reg_a0;
        u32 wait_cnt_0, wait_Cnt_1;
        u16 ocp_reg_mutex_ib;
        u16 ocp_reg_mutex_oob;
        u16 ocp_reg_mutex_prio;

        if (!HW_DASH_SUPPORT_DASH(tp))
                return;

        if (!tp->DASH)
                return;

        ocp_reg_mutex_oob = 0x110;
        ocp_reg_mutex_ib = 0x114;
        ocp_reg_mutex_prio = 0x11C;

        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, BIT_0);
        reg_16 = rtl8125_ocp_read(tp, ocp_reg_mutex_oob, 1);
        wait_cnt_0 = 0;
        while(reg_16) {
                reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);
                if (reg_a0) {
                        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, 0x00);
                        reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);
                        wait_Cnt_1 = 0;
                        while(reg_a0) {
                                reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);

                                wait_Cnt_1++;

                                if (wait_Cnt_1 > 2000)
                                        break;
                        };
                        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, BIT_0);

                }
                reg_16 = rtl8125_ocp_read(tp, ocp_reg_mutex_oob, 1);

                wait_cnt_0++;

                if (wait_cnt_0 > 2000)
                        break;
        };
}

void rtl8125_oob_mutex_unlock(struct rtl8125_private *tp)
{
        u16 ocp_reg_mutex_ib;
        u16 ocp_reg_mutex_prio;

        if (!HW_DASH_SUPPORT_DASH(tp))
                return;

        if (!tp->DASH)
                return;

        ocp_reg_mutex_ib = 0x114;
        ocp_reg_mutex_prio = 0x11C;

        rtl8125_ocp_write(tp, ocp_reg_mutex_prio, 1, BIT_0);
        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, 0x00);
}

static bool rtl8125_is_allow_access_dash_ocp(struct rtl8125_private *tp)
{
        bool allow_access = false;
        u16 mac_ocp_data;

        if (!HW_DASH_SUPPORT_DASH(tp))
                goto exit;

        allow_access = true;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xd460);
                if (mac_ocp_data == 0xffff || !(mac_ocp_data & BIT_0))
                        allow_access = false;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xd4c0);
                if (mac_ocp_data == 0xffff || (mac_ocp_data & BIT_3))
                        allow_access = false;
                break;
        default:
                goto exit;
        }
exit:
        return allow_access;
}

static u32 rtl8125_get_dash_fw_ver(struct rtl8125_private *tp)
{
        u32 ver = 0xffffffff;

        if (FALSE == HW_DASH_SUPPORT_GET_FIRMWARE_VERSION(tp))
                goto exit;

        ver = rtl8125_ocp_read(tp, OCP_REG_FIRMWARE_MAJOR_VERSION, 4);

exit:
        return ver;
}

static int _rtl8125_check_dash(struct rtl8125_private *tp)
{
        if (!tp->AllowAccessDashOcp)
                return 0;

        if (!HW_DASH_SUPPORT_IPC2(tp))
                return 0;

        if (rtl8125_ocp_read(tp, 0x128, 1) & BIT_0)
                return 1;

        return 0;
}

static int rtl8125_check_dash(struct rtl8125_private *tp)
{
        if (HW_DASH_SUPPORT_DASH(tp) && _rtl8125_check_dash(tp)) {
                u32 ver = rtl8125_get_dash_fw_ver(tp);
                if (!(ver == 0 || ver == 0xffffffff))
                        return 1;
        }

        return 0;
}

static int rtl8125_wait_dash_fw_ready(struct rtl8125_private *tp)
{
        int rc = -1;
        int timeout;

        if (!tp->DASH)
                goto out;

        for (timeout = 0; timeout < 10; timeout++) {
                fsleep(10000);
                if (rtl8125_ocp_read(tp, 0x124, 1) & BIT_0) {
                        rc = 1;
                        goto out;
                }
        }

        rc = 0;

out:
        return rc;
}

static void
rtl8125_notify_dash_oob_cmac(struct rtl8125_private *tp, u32 cmd)
{
        u32 val;

        if (!HW_DASH_SUPPORT_CMAC(tp))
                return;

        rtl8125_ocp_write(tp, 0x180, 4, cmd);
        val = rtl8125_ocp_read(tp, 0x30, 4);
        val |= BIT_0;
        rtl8125_ocp_write(tp, 0x30, 4, val);
}

static void
rtl8125_notify_dash_oob_ipc2(struct rtl8125_private *tp, u32 cmd)
{
        if (!HW_DASH_SUPPORT_IPC2(tp))
                return;

        rtl8125_ocp_write(tp, IB2SOC_DATA, 4, cmd);
        rtl8125_ocp_write(tp, IB2SOC_CMD, 4, 0x00);
        rtl8125_ocp_write(tp, IB2SOC_SET, 4, 0x01);
}

static void
rtl8125_notify_dash_oob(struct rtl8125_private *tp, u32 cmd)
{
        if (HW_DASH_SUPPORT_CMAC(tp))
                return rtl8125_notify_dash_oob_cmac(tp, cmd);
        else if (HW_DASH_SUPPORT_IPC2(tp))
                return rtl8125_notify_dash_oob_ipc2(tp, cmd);
        else
                return;
}

static void rtl8125_driver_start(struct rtl8125_private *tp)
{
        if (!tp->AllowAccessDashOcp)
                return;

        rtl8125_notify_dash_oob(tp, OOB_CMD_DRIVER_START);

        rtl8125_wait_dash_fw_ready(tp);
}

static void rtl8125_driver_stop(struct rtl8125_private *tp)
{
        if (!tp->AllowAccessDashOcp)
                return;

        rtl8125_notify_dash_oob(tp, OOB_CMD_DRIVER_STOP);

        rtl8125_wait_dash_fw_ready(tp);
}

void rtl8125_ephy_write(struct rtl8125_private *tp, int RegAddr, int value)
{
        int i;

        RTL_W32(tp, EPHYAR,
                EPHYAR_Write |
                (RegAddr & EPHYAR_Reg_Mask_v2) << EPHYAR_Reg_shift |
                (value & EPHYAR_Data_Mask));

        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                /* Check if the RTL8125 has completed EPHY write */
                if (!(RTL_R32(tp, EPHYAR) & EPHYAR_Flag))
                        break;
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);
}

u16 rtl8125_ephy_read(struct rtl8125_private *tp, int RegAddr)
{
        int i;
        u16 value = 0xffff;

        RTL_W32(tp, EPHYAR,
                EPHYAR_Read | (RegAddr & EPHYAR_Reg_Mask_v2) << EPHYAR_Reg_shift);

        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                /* Check if the RTL8125 has completed EPHY read */
                if (RTL_R32(tp, EPHYAR) & EPHYAR_Flag) {
                        value = (u16) (RTL_R32(tp, EPHYAR) & EPHYAR_Data_Mask);
                        break;
                }
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);

        return value;
}

static void ClearAndSetPCIePhyBit(struct rtl8125_private *tp, u8 addr, u16 clearmask, u16 setmask)
{
        u16 EphyValue;

        EphyValue = rtl8125_ephy_read(tp, addr);
        EphyValue &= ~clearmask;
        EphyValue |= setmask;
        rtl8125_ephy_write(tp, addr, EphyValue);
}

static void ClearPCIePhyBit(struct rtl8125_private *tp, u8 addr, u16 mask)
{
        ClearAndSetPCIePhyBit(tp,
                              addr,
                              mask,
                              0);
}

static void SetPCIePhyBit(struct rtl8125_private *tp, u8 addr, u16 mask)
{
        ClearAndSetPCIePhyBit(tp,
                              addr,
                              0,
                              mask);
}

static u32
rtl8125_csi_other_fun_read(struct rtl8125_private *tp,
                           u8 multi_fun_sel_bit,
                           u32 addr)
{
        u32 cmd;
        int i;
        u32 value = 0xffffffff;

        cmd = CSIAR_Read | CSIAR_ByteEn << CSIAR_ByteEn_shift | (addr & CSIAR_Addr_Mask);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                multi_fun_sel_bit = 0;

        if (multi_fun_sel_bit > 7)
                goto exit;

        cmd |= multi_fun_sel_bit << 16;

        RTL_W32(tp, CSIAR, cmd);

        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                /* Check if the RTL8125 has completed CSI read */
                if (RTL_R32(tp, CSIAR) & CSIAR_Flag) {
                        value = (u32)RTL_R32(tp, CSIDR);
                        break;
                }
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);

exit:
        return value;
}

static void
rtl8125_csi_other_fun_write(struct rtl8125_private *tp,
                            u8 multi_fun_sel_bit,
                            u32 addr,
                            u32 value)
{
        u32 cmd;
        int i;

        RTL_W32(tp, CSIDR, value);
        cmd = CSIAR_Write | CSIAR_ByteEn << CSIAR_ByteEn_shift | (addr & CSIAR_Addr_Mask);
        if (tp->mcfg == CFG_METHOD_DEFAULT)
                multi_fun_sel_bit = 0;

        if (multi_fun_sel_bit > 7)
                return;

        cmd |= multi_fun_sel_bit << 16;

        RTL_W32(tp, CSIAR, cmd);

        for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                udelay(R8125_CHANNEL_WAIT_TIME);

                /* Check if the RTL8125 has completed CSI write */
                if (!(RTL_R32(tp, CSIAR) & CSIAR_Flag))
                        break;
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);
}

static u32
rtl8125_csi_read(struct rtl8125_private *tp,
                 u32 addr)
{
        u8 multi_fun_sel_bit;

        multi_fun_sel_bit = 0;

        return rtl8125_csi_other_fun_read(tp, multi_fun_sel_bit, addr);
}

static void
rtl8125_csi_write(struct rtl8125_private *tp,
                  u32 addr,
                  u32 value)
{
        u8 multi_fun_sel_bit;

        multi_fun_sel_bit = 0;

        rtl8125_csi_other_fun_write(tp, multi_fun_sel_bit, addr, value);
}

static u8
rtl8125_csi_fun0_read_byte(struct rtl8125_private *tp,
                           u32 addr)
{
        u8 RetVal = 0;

        if (tp->mcfg == CFG_METHOD_DEFAULT) {
                struct pci_dev *pdev = tp->pci_dev;

                pci_read_config_byte(pdev, addr, &RetVal);
        } else {
                u32 TmpUlong;
                u16 RegAlignAddr;
                u8 ShiftByte;

                RegAlignAddr = addr & ~(0x3);
                ShiftByte = addr & (0x3);
                TmpUlong = rtl8125_csi_other_fun_read(tp, 0, RegAlignAddr);
                TmpUlong >>= (8*ShiftByte);
                RetVal = (u8)TmpUlong;
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);

        return RetVal;
}

static void
rtl8125_csi_fun0_write_byte(struct rtl8125_private *tp,
                            u32 addr,
                            u8 value)
{
        if (tp->mcfg == CFG_METHOD_DEFAULT) {
                struct pci_dev *pdev = tp->pci_dev;

                pci_write_config_byte(pdev, addr, value);
        } else {
                u32 TmpUlong;
                u16 RegAlignAddr;
                u8 ShiftByte;

                RegAlignAddr = addr & ~(0x3);
                ShiftByte = addr & (0x3);
                TmpUlong = rtl8125_csi_other_fun_read(tp, 0, RegAlignAddr);
                TmpUlong &= ~(0xFF << (8*ShiftByte));
                TmpUlong |= (value << (8*ShiftByte));
                rtl8125_csi_other_fun_write(tp, 0, RegAlignAddr, TmpUlong);
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);
}

u32 rtl8125_eri_read_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, int type, const u32 base_address)
{
        int i, val_shift, shift = 0;
        u32 value1 = 0, value2 = 0, mask;
        u32 eri_cmd;
        const u32 transformed_base_address = ((base_address & 0x00FFF000) << 6) | (base_address & 0x000FFF);

        if (len > 4 || len <= 0)
                return -1;

        while (len > 0) {
                val_shift = addr % ERIAR_Addr_Align;
                addr = addr & ~0x3;

                eri_cmd = ERIAR_Read |
                          transformed_base_address |
                          type << ERIAR_Type_shift |
                          ERIAR_ByteEn << ERIAR_ByteEn_shift |
                          (addr & 0x0FFF);
                if (addr & 0xF000) {
                        u32 tmp;

                        tmp = addr & 0xF000;
                        tmp >>= 12;
                        eri_cmd |= (tmp << 20) & 0x00F00000;
                }

                RTL_W32(tp, ERIAR, eri_cmd);

                for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                        udelay(R8125_CHANNEL_WAIT_TIME);

                        /* Check if the RTL8125 has completed ERI read */
                        if (RTL_R32(tp, ERIAR) & ERIAR_Flag)
                                break;
                }

                if (len == 1)       mask = (0xFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 2)  mask = (0xFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 3)  mask = (0xFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else            mask = (0xFFFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;

                value1 = RTL_R32(tp, ERIDR) & mask;
                value2 |= (value1 >> val_shift * 8) << shift * 8;

                if (len <= 4 - val_shift) {
                        len = 0;
                } else {
                        len -= (4 - val_shift);
                        shift = 4 - val_shift;
                        addr += 4;
                }
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);

        return value2;
}

u32 rtl8125_eri_read(struct rtl8125_private *tp, int addr, int len, int type)
{
        return rtl8125_eri_read_with_oob_base_address(tp, addr, len, type, 0);
}

int rtl8125_eri_write_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, u32 value, int type, const u32 base_address)
{
        int i, val_shift, shift = 0;
        u32 value1 = 0, mask;
        u32 eri_cmd;
        const u32 transformed_base_address = ((base_address & 0x00FFF000) << 6) | (base_address & 0x000FFF);

        if (len > 4 || len <= 0)
                return -1;

        while (len > 0) {
                val_shift = addr % ERIAR_Addr_Align;
                addr = addr & ~0x3;

                if (len == 1)       mask = (0xFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 2)  mask = (0xFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 3)  mask = (0xFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else            mask = (0xFFFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;

                value1 = rtl8125_eri_read_with_oob_base_address(tp, addr, 4, type, base_address) & ~mask;
                value1 |= ((value << val_shift * 8) >> shift * 8);

                RTL_W32(tp, ERIDR, value1);

                eri_cmd = ERIAR_Write |
                          transformed_base_address |
                          type << ERIAR_Type_shift |
                          ERIAR_ByteEn << ERIAR_ByteEn_shift |
                          (addr & 0x0FFF);
                if (addr & 0xF000) {
                        u32 tmp;

                        tmp = addr & 0xF000;
                        tmp >>= 12;
                        eri_cmd |= (tmp << 20) & 0x00F00000;
                }

                RTL_W32(tp, ERIAR, eri_cmd);

                for (i = 0; i < R8125_CHANNEL_WAIT_COUNT; i++) {
                        udelay(R8125_CHANNEL_WAIT_TIME);

                        /* Check if the RTL8125 has completed ERI write */
                        if (!(RTL_R32(tp, ERIAR) & ERIAR_Flag))
                                break;
                }

                if (len <= 4 - val_shift) {
                        len = 0;
                } else {
                        len -= (4 - val_shift);
                        shift = 4 - val_shift;
                        addr += 4;
                }
        }

        udelay(R8125_CHANNEL_EXIT_DELAY_TIME);

        return 0;
}

int rtl8125_eri_write(struct rtl8125_private *tp, int addr, int len, u32 value, int type)
{
        return rtl8125_eri_write_with_oob_base_address(tp, addr, len, value, type, NO_BASE_ADDRESS);
}

static void
rtl8125_enable_rxdvgate(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) | BIT_3);
}

static void
rtl8125_disable_rxdvgate(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) & ~BIT_3);
}

static u8
rtl8125_is_gpio_low(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 gpio_low = FALSE;

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                if (!(rtl8125_mac_ocp_read(tp, 0xDC04) & BIT_13))
                        gpio_low = TRUE;
                break;
        }

        if (gpio_low)
                dprintk("gpio is low.\n");

        return gpio_low;
}

static u8
rtl8125_is_phy_disable_mode_enabled(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 phy_disable_mode_enabled = FALSE;

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                if (RTL_R8(tp, 0xF2) & BIT_5)
                        phy_disable_mode_enabled = TRUE;
                break;
        }

        if (phy_disable_mode_enabled)
                dprintk("phy disable mode enabled.\n");

        return phy_disable_mode_enabled;
}

static u8
rtl8125_is_in_phy_disable_mode(struct net_device *dev)
{
        u8 in_phy_disable_mode = FALSE;

        if (rtl8125_is_phy_disable_mode_enabled(dev) && rtl8125_is_gpio_low(dev))
                in_phy_disable_mode = TRUE;

        if (in_phy_disable_mode)
                dprintk("Hardware is in phy disable mode.\n");

        return in_phy_disable_mode;
}

static bool
rtl8125_stop_all_request(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        RTL_W8(tp, ChipCmd, RTL_R8(tp, ChipCmd) | StopReq);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                for (i = 0; i < 20; i++) {
                        udelay(10);
                        if (!(RTL_R8(tp, ChipCmd) & StopReq))
                                break;
                }

                if (i == 20)
                        return false;
                break;
        default:
                udelay(200);
                break;
        }

        return true;
}

static void
rtl8125_clear_stop_all_request(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W8(tp, ChipCmd, RTL_R8(tp, ChipCmd) & (CmdTxEnb | CmdRxEnb));
}

void
rtl8125_wait_txrx_fifo_empty(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        /* Txfifo_empty require StopReq been set */
        for (i = 0; i < 3000; i++) {
                udelay(50);
                if ((RTL_R8(tp, MCUCmd_reg) & (Txfifo_empty | Rxfifo_empty)) == (Txfifo_empty | Rxfifo_empty))
                        break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                for (i = 0; i < 3000; i++) {
                        udelay(50);
                        if ((RTL_R16(tp, IntrMitigate) & (BIT_0 | BIT_1 | BIT_8)) == (BIT_0 | BIT_1 | BIT_8))
                                break;
                }
                break;
        }
}

#ifdef ENABLE_DASH_SUPPORT

static inline void
rtl8125_enable_dash2_interrupt(struct rtl8125_private *tp)
{
        if (!HW_DASH_SUPPORT_IPC2(tp))
                return;

        if (!tp->DASH)
                return;

        rtl8125_set_ipc2_soc_imr_bit(tp, RISC_IPC2_INTR);
}

static inline void
rtl8125_disable_dash2_interrupt(struct rtl8125_private *tp)
{
        if (!HW_DASH_SUPPORT_IPC2(tp))
                return;

        rtl8125_clear_ipc2_soc_imr_bit(tp, RISC_IPC2_INTR);
}
#endif

void
rtl8125_enable_hw_linkchg_interrupt(struct rtl8125_private *tp)
{
        switch (tp->HwCurrIsrVer) {
        case 7:
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V7_LINKCHG);
                break;
        case 5:
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V5_LINKCHG);
                break;
        case 4:
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V4_LINKCHG);
                break;
        case 2:
        case 3:
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V2_LINKCHG);
                break;
        case 1:
                RTL_W32(tp, tp->imr_reg[0], LinkChg | RTL_R32(tp, tp->imr_reg[0]));
                break;
        }

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                rtl8125_enable_dash2_interrupt(tp);
#endif
}

static inline void
rtl8125_enable_hw_interrupt(struct rtl8125_private *tp)
{
        switch (tp->HwCurrIsrVer) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 7:
                RTL_W32(tp, IMR_V2_SET_REG_8125, tp->intr_mask);
                break;
        case 1:
                RTL_W32(tp, tp->imr_reg[0], tp->intr_mask);

                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->imr_reg[i], other_q_intr_mask);
                }
                break;
        }

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                rtl8125_enable_dash2_interrupt(tp);
#endif
}

static inline void rtl8125_clear_hw_isr_v2(struct rtl8125_private *tp,
                u32 message_id)
{
        RTL_W32(tp, ISR_V2_8125, BIT(message_id));
}

static inline void
rtl8125_disable_hw_interrupt(struct rtl8125_private *tp)
{
        if (tp->HwCurrIsrVer > 1) {
                RTL_W32(tp, IMR_V2_CLEAR_REG_8125, 0xFFFFFFFF);
                if (tp->HwCurrIsrVer > 3)
                        RTL_W32(tp, IMR_V4_L2_CLEAR_REG_8125, 0xFFFFFFFF);
        } else {
                RTL_W32(tp, tp->imr_reg[0], 0x0000);

                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->imr_reg[i], 0);
                }
        }

#ifdef ENABLE_DASH_SUPPORT
        rtl8125_disable_dash2_interrupt(tp);
#endif
}

static inline void
rtl8125_switch_to_hw_interrupt(struct rtl8125_private *tp)
{
        RTL_W32(tp, TIMER_INT0_8125, 0x0000);

        rtl8125_enable_hw_interrupt(tp);
}

static inline void
rtl8125_switch_to_timer_interrupt(struct rtl8125_private *tp)
{
        if (tp->use_timer_interrupt) {
                RTL_W32(tp, TIMER_INT0_8125, timer_count);
                RTL_W32(tp, TCTR0_8125, timer_count);
                RTL_W32(tp, tp->imr_reg[0], tp->timer_intr_mask);
        } else {
                rtl8125_switch_to_hw_interrupt(tp);
        }
}

static void
rtl8125_irq_mask_and_ack(struct rtl8125_private *tp)
{
        rtl8125_disable_hw_interrupt(tp);

        if (tp->HwCurrIsrVer > 1) {
                RTL_W32(tp, ISR_V2_8125, 0xFFFFFFFF);
                if (tp->HwCurrIsrVer > 3)
                        RTL_W32(tp, ISR_V4_L2_8125, 0xFFFFFFFF);
        } else {
                RTL_W32(tp, tp->isr_reg[0], RTL_R32(tp, tp->isr_reg[0]));

                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->isr_reg[i], RTL_R16(tp, tp->isr_reg[i]));
                }
        }

#ifdef ENABLE_DASH_SUPPORT
        rtl8125_clear_ipc2_isr(tp);
#endif
}

static void
rtl8125_disable_rx_packet_filter(struct rtl8125_private *tp)
{

        RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) &
                ~(AcceptErr | AcceptRunt |AcceptBroadcast | AcceptMulticast |
                  AcceptMyPhys |  AcceptAllPhys));
}

static void
rtl8125_nic_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtl8125_disable_rx_packet_filter(tp);

        rtl8125_enable_rxdvgate(dev);

        rtl8125_stop_all_request(dev);

        rtl8125_wait_txrx_fifo_empty(dev);

        rtl8125_clear_stop_all_request(dev);

        /* Soft reset the chip. */
        RTL_W8(tp, ChipCmd, CmdReset);

        /* Check that the chip has finished the reset. */
        for (i = 100; i > 0; i--) {
                udelay(100);
                if ((RTL_R8(tp, ChipCmd) & CmdReset) == 0)
                        break;
        }

        /* reset rcr */
        RTL_W32(tp, RxConfig, (RX_DMA_BURST_512 << RxCfgDMAShift));
}

static void
rtl8125_hw_set_interrupt_type(struct rtl8125_private *tp, u8 isr_ver)
{
        u8 tmp;

        if (tp->HwSuppIsrVer < 2)
                return;

        tmp = RTL_R8(tp, INT_CFG0_8125);

        switch (tp->HwSuppIsrVer) {
        case 7:
                tmp &= ~INT_CFG0_AVOID_MISS_INTR;
                fallthrough;
        case 4:
        case 5:
                if (tp->HwSuppIsrVer == 7)
                        tmp &= ~INT_CFG0_AUTO_CLEAR_IMR;
                else
                        tmp &= ~INT_CFG0_MSIX_ENTRY_NUM_MODE;
                fallthrough;
        case 2:
        case 3:
                tmp &= ~(INT_CFG0_ENABLE_8125);
                if (isr_ver > 1)
                        tmp |= INT_CFG0_ENABLE_8125;
                break;
        default:
                return;
        }

        RTL_W8(tp, INT_CFG0_8125, tmp);
}

static void
rtl8125_hw_clear_timer_int(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W32(tp, TIMER_INT0_8125, 0x0000);
        RTL_W32(tp, TIMER_INT1_8125, 0x0000);
        RTL_W32(tp, TIMER_INT2_8125, 0x0000);
        RTL_W32(tp, TIMER_INT3_8125, 0x0000);
}

static void
rtl8125_hw_clear_int_miti(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        switch (tp->HwSuppIntMitiVer) {
        case 3:
        case 6:
                //IntMITI_0-IntMITI_31
                for (i=0xA00; i<0xB00; i+=4)
                        RTL_W32(tp, i, 0x0000);
                break;
        case 4:
        case 5:
                //IntMITI_0-IntMITI_15
                for (i = 0xA00; i < 0xA80; i += 4)
                        RTL_W32(tp, i, 0x0000);

                if (tp->HwSuppIntMitiVer == 5)
                        RTL_W8(tp, INT_CFG0_8125, RTL_R8(tp, INT_CFG0_8125) &
                               ~(INT_CFG0_TIMEOUT0_BYPASS_8125 |
                                 INT_CFG0_MITIGATION_BYPASS_8125 |
                                 INT_CFG0_RDU_BYPASS_8126));
                else
                        RTL_W8(tp, INT_CFG0_8125, RTL_R8(tp, INT_CFG0_8125) &
                               ~(INT_CFG0_TIMEOUT0_BYPASS_8125 | INT_CFG0_MITIGATION_BYPASS_8125));

                RTL_W16(tp, INT_CFG1_8125, 0x0000);
                break;
        }
}

static bool
rtl8125_vec_2_tx_q_num(
        struct rtl8125_private *tp,
        u32 messageId,
        u32 *qnum
)
{
        u32 whichQ = 0xffffffff;
        bool rc = false;

        switch (tp->HwSuppIsrVer) {
        case 2:
                if (messageId == 0x10)
                        whichQ = 0;
                else if (messageId == 0x12 && tp->num_tx_rings > 1)
                        whichQ = 1;
                break;
        case 3:
        case 4:
                if (messageId == 0x00)
                        whichQ = 0;
                else if (messageId == 0x01 && tp->num_tx_rings > 1)
                        whichQ = 1;
                break;
        case 5:
                if (messageId == 0x10)
                        whichQ = 0;
                else if (messageId == 0x11 && tp->num_tx_rings > 1)
                        whichQ = 1;
                break;
        case 6:
                if (messageId == 0x08)
                        whichQ = 0;
                else if (messageId == 0x09 && tp->num_tx_rings > 1)
                        whichQ = 1;
                break;
        case 7:
                if (messageId == 0x1B)
                        whichQ = 0;
                else if (messageId == 0x1C && tp->num_tx_rings > 1)
                        whichQ = 1;
                break;
        }

        if (whichQ != 0xffffffff) {
                *qnum = whichQ;
                rc = true;
        }

        return rc;
}

static bool
rtl8125_vec_2_rx_q_num(
        struct rtl8125_private *tp,
        u32 messageId,
        u32 *qnum
)
{
        u32 whichQ = 0xffffffff;
        bool rc = false;

        switch (tp->HwSuppIsrVer) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
                if (messageId < tp->HwSuppNumRxQueues)
                        whichQ = messageId;
                break;
        }

        if (whichQ != 0xffffffff) {
                *qnum = whichQ;
                rc = true;
        }

        return rc;
}

void
rtl8125_hw_set_timer_int(struct rtl8125_private *tp,
                         u32 message_id,
                         u8 timer_intmiti_val)
{
        u32 qnum;

        switch (tp->HwSuppIntMitiVer) {
        case 4:
        case 5:
        case 6:
#ifdef ENABLE_LIB_SUPPORT
                if (message_id < R8125_MAX_RX_QUEUES_VEC_V3)
                        timer_intmiti_val = 0;
#else
                if ((tp->HwCurrIsrVer == 2) && (message_id < R8125_MAX_RX_QUEUES_VEC_V3))
                        timer_intmiti_val = 0;
#endif //ENABLE_LIB_SUPPORT
                //ROK
                if (rtl8125_vec_2_rx_q_num(tp, message_id, &qnum))
                        RTL_W8(tp,INT_MITI_V2_0_RX + 8 * qnum, timer_intmiti_val);
                //TOK
                if (rtl8125_vec_2_tx_q_num(tp, message_id, &qnum))
                        RTL_W8(tp,INT_MITI_V2_0_TX + 8 * qnum, timer_intmiti_val);
                break;
        }
}

void
rtl8125_hw_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_lib_reset_prepare(tp);

        /* Disable interrupts */
        rtl8125_irq_mask_and_ack(tp);

        rtl8125_hw_clear_timer_int(dev);

        rtl8125_nic_reset(dev);
}

static unsigned int
rtl8125_xmii_reset_pending(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        unsigned int retval;

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        retval = rtl8125_mdio_read(tp, MII_BMCR) & BMCR_RESET;

        r8125_spin_unlock(&tp->phy_lock, flags);

        return retval;
}

static unsigned int
_rtl8125_xmii_link_ok(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 status;

        status = rtl8125_get_phy_status(tp);
        if (status == UINT_MAX)
                return 0;

        return (status & LinkStatus) ? 1 : 0;
}

static unsigned int
rtl8125_xmii_link_ok(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int link_state;

        link_state = _rtl8125_xmii_link_ok(dev);
#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp) &&
            link_state == R8125_LINK_STATE_ON)
                return rtl8125_fiber_link_ok(dev);
#else
        (void)tp;
#endif /* ENABLE_FIBER_SUPPORT */

        return link_state;
}

static int
rtl8125_wait_phy_reset_complete(struct rtl8125_private *tp)
{
        int i, val;

        for (i = 0; i < 2500; i++) {
                val = rtl8125_mdio_read(tp, MII_BMCR) & BMCR_RESET;
                if (!val)
                        return 0;

                mdelay(1);
        }

        return -1;
}

static void
rtl8125_xmii_reset_enable(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int ret;

        if (rtl8125_is_in_phy_disable_mode(dev))
                return;

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        rtl8125_mdio_write(tp, MII_ADVERTISE, rtl8125_mdio_read(tp, MII_ADVERTISE) &
                           ~(ADVERTISE_10HALF | ADVERTISE_10FULL |
                             ADVERTISE_100HALF | ADVERTISE_100FULL));
        rtl8125_mdio_write(tp, MII_CTRL1000, rtl8125_mdio_read(tp, MII_CTRL1000) &
                           ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL));
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA5D4, rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D4) &
                                          ~RTK_ADVERTISE_2500FULL);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_RESET | BMCR_ANENABLE);

        ret = rtl8125_wait_phy_reset_complete(tp);

        r8125_spin_unlock(&tp->phy_lock, flags);

        if (ret != 0 && netif_msg_link(tp))
                printk(KERN_ERR "%s: PHY reset failed.\n", dev->name);
}

void
rtl8125_init_ring_indexes(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                ring->dirty_tx = ring->cur_tx = 0;
                ring->NextHwDesCloPtr = 0;
                ring->BeginHwDesCloPtr = 0;
                ring->index = i;
                ring->priv = tp;
                ring->netdev = tp->dev;

                /* reset BQL for queue */
                netdev_tx_reset_queue(txring_txq(ring));
        }

        for (i = 0; i < tp->HwSuppNumRxQueues; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                ring->dirty_rx = ring->cur_rx = 0;
                ring->index = i;
                ring->priv = tp;
                ring->netdev = tp->dev;
        }

#ifdef ENABLE_LIB_SUPPORT
        for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                struct rtl8125_ring *ring = &tp->lib_tx_ring[i];
                ring->direction = RTL8125_CH_DIR_TX;
                ring->queue_num = i;
                ring->private = tp;
        }

        for (i = 0; i < tp->HwSuppNumRxQueues; i++) {
                struct rtl8125_ring *ring = &tp->lib_rx_ring[i];
                ring->direction = RTL8125_CH_DIR_RX;
                ring->queue_num = i;
                ring->private = tp;
        }
#endif
}

static void
rtl8125_issue_offset_99_event(struct rtl8125_private *tp)
{
        rtl8125_mac_ocp_write(tp, 0xE09A,  rtl8125_mac_ocp_read(tp, 0xE09A) | BIT_0);
}

#ifdef ENABLE_DASH_SUPPORT
static void
rtl8125_check_and_enable_dash_interrupt(struct rtl8125_private *tp)
{
        if (!HW_DASH_SUPPORT_IPC2(tp))
                return;

        if (!tp->DASH)
                return;

        //
        // even disconnected, enable dash interrupt mask bits for in-band/out-band communication
        //
        rtl8125_enable_dash2_interrupt(tp);
        if (tp->HwCurrIsrVer > 1) {
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V4_LAYER2_INTR_STS);
                RTL_W32(tp, IMR_V4_L2_SET_REG_8125, ISRIMR_V4_L2_IPC2);
        } else {
                RTL_W16(tp, tp->imr_reg[0], ISRIMR_DASH_INTR_EN);
        }
}
#endif

static int rtl8125_enable_eee_plus(struct rtl8125_private *tp)
{
        rtl8125_mac_ocp_write(tp, 0xE080, rtl8125_mac_ocp_read(tp, 0xE080)|BIT_1);

        return 0;
}

static int rtl8125_disable_eee_plus(struct rtl8125_private *tp)
{
        rtl8125_mac_ocp_write(tp, 0xE080, rtl8125_mac_ocp_read(tp, 0xE080)&~BIT_1);

        return 0;
}

static void rtl8125_enable_double_vlan(struct rtl8125_private *tp)
{
        RTL_W16(tp, DOUBLE_VLAN_CONFIG, 0xf002);
}

static void rtl8125_disable_double_vlan(struct rtl8125_private *tp)
{
        RTL_W16(tp, DOUBLE_VLAN_CONFIG, 0);
}

static void
rtl8125_set_pfm_patch(struct rtl8125_private *tp, bool enable)
{
        if (!tp->RequiredPfmPatch)
                goto exit;

        if (enable) {
                rtl8125_set_mac_ocp_bit(tp, 0xD3F0, BIT_0);
                rtl8125_set_mac_ocp_bit(tp, 0xD3F2, BIT_0);
                rtl8125_set_mac_ocp_bit(tp, 0xE85A, BIT_6);
        } else {
                rtl8125_clear_mac_ocp_bit(tp, 0xD3F0, BIT_0);
                rtl8125_clear_mac_ocp_bit(tp, 0xD3F2, BIT_0);
                rtl8125_clear_mac_ocp_bit(tp, 0xE85A, BIT_6);
        }

exit:
        return;
}

static void
rtl8125_link_on_patch(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        u32 status;

        rtl8125_hw_config(dev);

        if ((tp->mcfg == CFG_METHOD_2) &&
            netif_running(dev)) {
                if (rtl8125_get_phy_status(tp)&FullDup)
                        RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | (BIT_24 | BIT_25)) & ~BIT_19);
                else
                        RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | BIT_25) & ~(BIT_19 | BIT_24));
        }

        status = rtl8125_get_phy_status(tp);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_12:
                if (status & _10bps)
                        rtl8125_enable_eee_plus(tp);
                break;
        default:
                break;
        }

        if (tp->RequiredPfmPatch)
                rtl8125_set_pfm_patch(tp, (status & _10bps) ? 1 : 0);

        rtl8125_hw_start(dev);

        netif_carrier_on(dev);

        netif_tx_wake_all_queues(dev);

        r8125_spin_lock(&tp->phy_lock, flags);

        tp->phy_reg_aner = rtl8125_mdio_read(tp, MII_EXPANSION);
        tp->phy_reg_anlpar = rtl8125_mdio_read(tp, MII_LPA);
        tp->phy_reg_gbsr = rtl8125_mdio_read(tp, MII_STAT1000);
        tp->phy_reg_status_2500 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D6);

        r8125_spin_unlock(&tp->phy_lock, flags);

#ifdef ENABLE_PTP_SUPPORT
        if (tp->HwSuppPtpVer == 3)
                rtl8125_set_phy_local_time(tp);
#endif // ENABLE_PTP_SUPPORT
}

static void
rtl8125_link_down_patch(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        r8125_spin_lock(&tp->phy_lock, flags);

        tp->phy_reg_aner = 0;
        tp->phy_reg_anlpar = 0;
        tp->phy_reg_gbsr = 0;
        tp->phy_reg_status_2500 = 0;

        r8125_spin_unlock(&tp->phy_lock, flags);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_12:
                rtl8125_disable_eee_plus(tp);
                break;
        default:
                break;
        }

        if (tp->RequiredPfmPatch)
                rtl8125_set_pfm_patch(tp, 1);

        netif_carrier_off(dev);

        netif_tx_disable(dev);

        rtl8125_hw_reset(dev);

        rtl8125_tx_clear(tp);

        rtl8125_rx_clear(tp);

        rtl8125_init_ring(dev);

        rtl8125_enable_hw_linkchg_interrupt(tp);

        //rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);

#ifdef ENABLE_DASH_SUPPORT
        rtl8125_check_and_enable_dash_interrupt(tp);
#endif
}

static void
_rtl8125_check_link_status(struct net_device *dev, unsigned int link_state)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (link_state != R8125_LINK_STATE_OFF &&
            link_state != R8125_LINK_STATE_ON)
                link_state = tp->link_ok(dev);

        if (link_state == R8125_LINK_STATE_ON) {
                rtl8125_link_on_patch(dev);

                if (netif_msg_ifup(tp))
                        printk(KERN_INFO PFX "%s: link up\n", dev->name);
        } else {
                if (netif_msg_ifdown(tp))
                        printk(KERN_INFO PFX "%s: link down\n", dev->name);

                rtl8125_link_down_patch(dev);
        }
}

static void
rtl8125_check_link_status(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int link_status_on;

        tp->resume_not_chg_speed = 0;

        link_status_on = tp->link_ok(dev);
        if (netif_carrier_ok(dev) == link_status_on)
                rtl8125_enable_hw_linkchg_interrupt(tp);
        else
                _rtl8125_check_link_status(dev, link_status_on);
}

static bool
rtl8125_is_autoneg_mode_valid(u32 autoneg)
{
        switch(autoneg) {
        case AUTONEG_ENABLE:
        case AUTONEG_DISABLE:
                return true;
        default:
                return false;
        }
}

static bool
rtl8125_is_speed_mode_valid(u32 speed)
{
        switch(speed) {
        case SPEED_2500:
        case SPEED_1000:
        case SPEED_100:
        case SPEED_10:
                return true;
        default:
                return false;
        }
}

static bool
rtl8125_is_duplex_mode_valid(u8 duplex)
{
        switch(duplex) {
        case DUPLEX_FULL:
        case DUPLEX_HALF:
                return true;
        default:
                return false;
        }
}

static void
rtl8125_set_link_option(struct rtl8125_private *tp,
                        u8 autoneg,
                        u32 speed,
                        u8 duplex,
                        enum rtl8125_fc_mode fc)
{
        u64 adv;

        if (!rtl8125_is_speed_mode_valid(speed))
                speed = SPEED_2500;

        if (!rtl8125_is_duplex_mode_valid(duplex))
                duplex = DUPLEX_FULL;

        if (!rtl8125_is_autoneg_mode_valid(autoneg))
                autoneg = AUTONEG_ENABLE;

        speed = min(speed, tp->HwSuppMaxPhyLinkSpeed);

        adv = 0;
        switch(speed) {
        case SPEED_2500:
                adv |= ADVERTISED_2500baseX_Full;
                fallthrough;
        default:
                adv |= (ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
                        ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
                        ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full);
                break;
        }

        tp->autoneg = autoneg;
        tp->speed = speed;
        tp->duplex = duplex;
        tp->advertising = adv;
        tp->fcpause = fc;
}

/*
static void
rtl8125_enable_ocp_phy_power_saving(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 val;

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6) {
                val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC416);
                if (val != 0x0050) {
                        rtl8125_set_phy_mcu_patch_request(tp);
                        rtl8125_mdio_direct_write_phy_ocp(tp, 0xC416, 0x0000);
                        rtl8125_mdio_direct_write_phy_ocp(tp, 0xC416, 0x0050);
                        rtl8125_clear_phy_mcu_patch_request(tp);
                }
        }
}
*/

static void
rtl8125_disable_ocp_phy_power_saving(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 val;

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6) {
                val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC416);
                if (val != 0x0500) {
                        rtl8125_set_phy_mcu_patch_request(tp);
                        rtl8125_mdio_direct_write_phy_ocp(tp, 0xC416, 0x0000);
                        rtl8125_mdio_direct_write_phy_ocp(tp, 0xC416, 0x0500);
                        rtl8125_clear_phy_mcu_patch_request(tp);
                }
        }
}

static void
rtl8125_wait_ll_share_fifo_ready(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        for (i = 0; i < 10; i++) {
                udelay(100);
                if (RTL_R16(tp, 0xD2) & BIT_9)
                        break;
        }
}

static void
rtl8125_disable_pci_offset_99(struct rtl8125_private *tp)
{
        rtl8125_mac_ocp_write(tp, 0xE032,  rtl8125_mac_ocp_read(tp, 0xE032) & ~(BIT_0 | BIT_1));

        rtl8125_csi_fun0_write_byte(tp, 0x99, 0x00);
}

static void
rtl8125_enable_pci_offset_99(struct rtl8125_private *tp)
{
        u32 csi_tmp;

        rtl8125_csi_fun0_write_byte(tp, 0x99, tp->org_pci_offset_99);

        csi_tmp = rtl8125_mac_ocp_read(tp, 0xE032);
        csi_tmp &= ~(BIT_0 | BIT_1);
        if (tp->org_pci_offset_99 & (BIT_5 | BIT_6))
                csi_tmp |= BIT_1;
        if (tp->org_pci_offset_99 & BIT_2)
                csi_tmp |= BIT_0;
        rtl8125_mac_ocp_write(tp, 0xE032, csi_tmp);
}

static void
rtl8125_init_pci_offset_99(struct rtl8125_private *tp)
{
        rtl8125_mac_ocp_write(tp, 0xCDD0, 0x9003);
        rtl8125_set_mac_ocp_bit(tp, 0xE034, (BIT_15 | BIT_14));
        rtl8125_mac_ocp_write(tp, 0xCDD2, 0x889C);
        rtl8125_mac_ocp_write(tp, 0xCDD8, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDD4, 0x8C30);
        rtl8125_mac_ocp_write(tp, 0xCDDA, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDD6, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDDC, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDE8, 0x883E);
        rtl8125_mac_ocp_write(tp, 0xCDEA, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDEC, 0x889C);
        rtl8125_mac_ocp_write(tp, 0xCDEE, 0x9003);
        rtl8125_mac_ocp_write(tp, 0xCDF0, 0x8C09);
        rtl8125_mac_ocp_write(tp, 0xCDF2, 0x9003);
        rtl8125_set_mac_ocp_bit(tp, 0xE032, BIT_14);
        rtl8125_set_mac_ocp_bit(tp, 0xE0A2, BIT_0);

        rtl8125_enable_pci_offset_99(tp);
}

static void
rtl8125_disable_pci_offset_180(struct rtl8125_private *tp)
{
        rtl8125_clear_mac_ocp_bit(tp, 0xE092, 0x00FF);
}

static void
rtl8125_enable_pci_offset_180(struct rtl8125_private *tp)
{
        rtl8125_clear_mac_ocp_bit(tp, 0xE094, 0xFF00);

        rtl8125_clear_set_mac_ocp_bit(tp, 0xE092, 0x00FF, BIT_2);
}

static void
rtl8125_init_pci_offset_180(struct rtl8125_private *tp)
{
        rtl8125_enable_pci_offset_180(tp);
}

static void
rtl8125_set_pci_99_exit_driver_para(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->org_pci_offset_99 & BIT_2)
                rtl8125_issue_offset_99_event(tp);
        rtl8125_disable_pci_offset_99(tp);
}

static void
rtl8125_enable_cfg9346_write(struct rtl8125_private *tp)
{
        RTL_W8(tp, Cfg9346, RTL_R8(tp, Cfg9346) | Cfg9346_Unlock);
}

static void
rtl8125_disable_cfg9346_write(struct rtl8125_private *tp)
{
        RTL_W8(tp, Cfg9346, RTL_R8(tp, Cfg9346) & ~Cfg9346_Unlock);
}

static void
rtl8125_enable_exit_l1_mask(struct rtl8125_private *tp)
{
        //(1)ERI(0xD4)(OCP 0xC0AC).bit[7:12]=6'b111111, L1 Mask
        rtl8125_set_mac_ocp_bit(tp, 0xC0AC, (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12));
}

static void
rtl8125_disable_exit_l1_mask(struct rtl8125_private *tp)
{
        //(1)ERI(0xD4)(OCP 0xC0AC).bit[7:12]=6'b000000, L1 Mask
        rtl8125_clear_mac_ocp_bit(tp, 0xC0AC, (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12));
}

static void
rtl8125_enable_extend_tally_couter(struct rtl8125_private *tp)
{
        switch (tp->HwSuppExtendTallyCounterVer) {
        case 1:
                rtl8125_set_mac_ocp_bit(tp, 0xEA84, (BIT_1 | BIT_0));
                break;
        }
}

static void
rtl8125_disable_extend_tally_couter(struct rtl8125_private *tp)
{
        switch (tp->HwSuppExtendTallyCounterVer) {
        case 1:
                rtl8125_clear_mac_ocp_bit(tp, 0xEA84, (BIT_1 | BIT_0));
                break;
        }
}

static void
rtl8125_enable_force_clkreq(struct rtl8125_private *tp, bool enable)
{
        if (enable)
                RTL_W8(tp, 0xF1, RTL_R8(tp, 0xF1) | BIT_7);
        else
                RTL_W8(tp, 0xF1, RTL_R8(tp, 0xF1) & ~BIT_7);
}

static void
rtl8125_enable_aspm_clkreq_lock(struct rtl8125_private *tp, bool enable)
{
        bool unlock_cfg_wr;

        if ((RTL_R8(tp, Cfg9346) & Cfg9346_EEM_MASK) == Cfg9346_Unlock)
                unlock_cfg_wr = false;
        else
                unlock_cfg_wr = true;

        if (unlock_cfg_wr)
                rtl8125_enable_cfg9346_write(tp);

        if (enable) {
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) | BIT_7);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) | BIT_0);
        } else {
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
        }

        if (unlock_cfg_wr)
                rtl8125_disable_cfg9346_write(tp);
}

static void
rtl8125_set_reg_oobs_en_sel(struct rtl8125_private *tp, bool enable)
{
        switch (tp->mcfg) {
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                if (enable)
                        rtl8125_set_mac_ocp_bit(tp, 0xD434, BIT_1);
                else
                        rtl8125_clear_mac_ocp_bit(tp, 0xD434, BIT_1);
                break;
        default:
                break;
        }
}

static void
rtl8125_hw_d3_para(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W16(tp, RxMaxSize, RX_BUF_SIZE);

        rtl8125_enable_force_clkreq(tp, 0);
        rtl8125_enable_aspm_clkreq_lock(tp, 0);

        rtl8125_disable_exit_l1_mask(tp);

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_set_realwow_d3_para(dev);
#endif

        rtl8125_set_pci_99_exit_driver_para(dev);

        /*disable ocp phy power saving*/
        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6)
                rtl8125_disable_ocp_phy_power_saving(dev);

        rtl8125_disable_rxdvgate(dev);

        rtl8125_disable_extend_tally_couter(tp);

        rtl8125_set_reg_oobs_en_sel(tp, false);
}

static void
rtl8125_enable_magic_packet(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                rtl8125_mac_ocp_write(tp, 0xC0B6, rtl8125_mac_ocp_read(tp, 0xC0B6) | BIT_0);
                break;
        }
}
static void
rtl8125_disable_magic_packet(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                rtl8125_mac_ocp_write(tp, 0xC0B6, rtl8125_mac_ocp_read(tp, 0xC0B6) & ~BIT_0);
                break;
        }
}

static void
rtl8125_enable_linkchg_wakeup(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                RTL_W8(tp, Config3, RTL_R8(tp, Config3) | LinkUp);
                rtl8125_clear_set_mac_ocp_bit(tp, 0xE0C6, (BIT_5 | BIT_3 | BIT_2), (BIT_4 | BIT_1 | BIT_0));
                break;
        }
}

static void
rtl8125_disable_linkchg_wakeup(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                RTL_W8(tp, Config3, RTL_R8(tp, Config3) & ~LinkUp);
                if (!(rtl8125_mac_ocp_read(tp, 0xE0C6) & BIT_0))
                        rtl8125_clear_set_mac_ocp_bit(tp, 0xE0C6, (BIT_5 | BIT_3 | BIT_2 | BIT_1), BIT_4);
                break;
        }
}

#define WAKE_ANY (WAKE_PHY | WAKE_MAGIC | WAKE_UCAST | WAKE_BCAST | WAKE_MCAST)

static u32
rtl8125_get_hw_wol(struct rtl8125_private *tp)
{
        u8 options;
        u32 csi_tmp;
        u32 wol_opts = 0;

        if (disable_wol_support)
                goto out;

        options = RTL_R8(tp, Config1);
        if (!(options & PMEnable))
                goto out;

        options = RTL_R8(tp, Config3);
        if (options & LinkUp)
                wol_opts |= WAKE_PHY;

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xC0B6);
                if (csi_tmp & BIT_0)
                        wol_opts |= WAKE_MAGIC;
                break;
        }

        options = RTL_R8(tp, Config5);
        if (options & UWF)
                wol_opts |= WAKE_UCAST;
        if (options & BWF)
                wol_opts |= WAKE_BCAST;
        if (options & MWF)
                wol_opts |= WAKE_MCAST;

out:
        return wol_opts;
}

static void
rtl8125_enable_d0_speedup(struct rtl8125_private *tp)
{
        u16 clearmask;
        u16 setmask;

        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp))
                return;

        if (tp->D0SpeedUpSpeed == D0_SPEED_UP_SPEED_DISABLE)
                return;

        if (tp->HwSuppD0SpeedUpVer == 1 || tp->HwSuppD0SpeedUpVer == 2) {
                //speed up speed
                clearmask = (BIT_10 | BIT_9 | BIT_8 | BIT_7);
                if (tp->D0SpeedUpSpeed == D0_SPEED_UP_SPEED_2500)
                        setmask = BIT_7;
                else
                        setmask = 0;
                rtl8125_clear_set_mac_ocp_bit(tp, 0xE10A, clearmask, setmask);

                //speed up flowcontrol
                clearmask = (BIT_15 | BIT_14);
                if (tp->HwSuppD0SpeedUpVer == 2)
                        clearmask |= BIT_13;

                if (tp->fcpause == rtl8125_fc_full) {
                        setmask = (BIT_15 | BIT_14);
                        if (tp->HwSuppD0SpeedUpVer == 2)
                                setmask |= BIT_13;
                } else
                        setmask = 0;
                rtl8125_clear_set_mac_ocp_bit(tp, 0xE860, clearmask, setmask);
        }

        RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) | BIT_3);
}

static void
rtl8125_disable_d0_speedup(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp))
                return;

        RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) & ~BIT_3);
}

static void
rtl8125_set_hw_wol(struct net_device *dev, u32 wolopts)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i,tmp;
        static struct {
                u32 opt;
                u16 reg;
                u8  mask;
        } cfg[] = {
                { WAKE_PHY,   Config3, LinkUp },
                { WAKE_UCAST, Config5, UWF },
                { WAKE_BCAST, Config5, BWF },
                { WAKE_MCAST, Config5, MWF },
                { WAKE_ANY,   Config5, LanWake },
                { WAKE_MAGIC, Config3, MagicPacket },
        };

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
        default:
                tmp = ARRAY_SIZE(cfg) - 1;

                if (wolopts & WAKE_MAGIC)
                        rtl8125_enable_magic_packet(dev);
                else
                        rtl8125_disable_magic_packet(dev);
                break;
        }

        rtl8125_enable_cfg9346_write(tp);

        for (i = 0; i < tmp; i++) {
                u8 options = RTL_R8(tp, cfg[i].reg) & ~cfg[i].mask;
                if (wolopts & cfg[i].opt)
                        options |= cfg[i].mask;
                RTL_W8(tp, cfg[i].reg, options);
        }

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                if (wolopts & WAKE_PHY)
                        rtl8125_enable_linkchg_wakeup(dev);
                else
                        rtl8125_disable_linkchg_wakeup(dev);
                break;
        }

        rtl8125_disable_cfg9346_write(tp);
}

static void
rtl8125_phy_restart_nway(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (rtl8125_is_in_phy_disable_mode(dev))
                return;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE | BMCR_ANRESTART);
}

static void
rtl8125_phy_setup_force_mode(struct net_device *dev, u32 speed, u8 duplex)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 bmcr_true_force = 0;

        if (rtl8125_is_in_phy_disable_mode(dev))
                return;

        if ((speed == SPEED_10) && (duplex == DUPLEX_HALF)) {
                bmcr_true_force = BMCR_SPEED10;
        } else if ((speed == SPEED_10) && (duplex == DUPLEX_FULL)) {
                bmcr_true_force = BMCR_SPEED10 | BMCR_FULLDPLX;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_HALF)) {
                bmcr_true_force = BMCR_SPEED100;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_FULL)) {
                bmcr_true_force = BMCR_SPEED100 | BMCR_FULLDPLX;
        } else {
                netif_err(tp, drv, dev, "Failed to set phy force mode!\n");
                return;
        }

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, bmcr_true_force);
}

static void
rtl8125_set_pci_pme(struct rtl8125_private *tp, int set)
{
        struct pci_dev *pdev = tp->pci_dev;
        u16 pmc;

        if (!pdev->pm_cap)
                return;

        pci_read_config_word(pdev, pdev->pm_cap + PCI_PM_CTRL, &pmc);
        pmc |= PCI_PM_CTRL_PME_STATUS;
        if (set)
                pmc |= PCI_PM_CTRL_PME_ENABLE;
        else
                pmc &= ~PCI_PM_CTRL_PME_ENABLE;
        pci_write_config_word(pdev, pdev->pm_cap + PCI_PM_CTRL, pmc);
}

static void
rtl8125_enable_giga_lite(struct rtl8125_private *tp, u64 adv)
{
        if (adv & ADVERTISED_1000baseT_Full)
                rtl8125_set_eth_phy_ocp_bit(tp, 0xA428, BIT_9);
        else
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_9);

        if (adv & ADVERTISED_2500baseX_Full)
                rtl8125_set_eth_phy_ocp_bit(tp, 0xA5EA, BIT_0);
        else
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5EA, BIT_0);
}

static void
rtl8125_disable_giga_lite(struct rtl8125_private *tp)
{
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_9);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5EA, BIT_0);
}

static int
rtl8125_set_wol_link_speed(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int auto_nego = 0;
        int giga_ctrl;
        int ctrl_2500;
        u64 adv;
        u16 anlpar;
        u16 gbsr;
        u16 status_2500;
        u16 aner;

        r8125_spin_lock(&tp->phy_lock, flags);

        if (tp->autoneg != AUTONEG_ENABLE)
                goto exit;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);

        auto_nego = rtl8125_mdio_read(tp, MII_ADVERTISE);
        auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL
                       | ADVERTISE_100HALF | ADVERTISE_100FULL);

        giga_ctrl = rtl8125_mdio_read(tp, MII_CTRL1000);
        giga_ctrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);

        ctrl_2500 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D4);
        ctrl_2500 &= ~RTK_ADVERTISE_2500FULL;

        aner = tp->phy_reg_aner;
        anlpar = tp->phy_reg_anlpar;
        gbsr = tp->phy_reg_gbsr;
        status_2500 = tp->phy_reg_status_2500;
        if (tp->link_ok(dev)) {
                aner = rtl8125_mdio_read(tp, MII_EXPANSION);
                anlpar = rtl8125_mdio_read(tp, MII_LPA);
                gbsr = rtl8125_mdio_read(tp, MII_STAT1000);
                status_2500 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D6);
        }

        adv = tp->advertising;
        if ((aner | anlpar | gbsr | status_2500) == 0) {
                int auto_nego_tmp = 0;
                if (adv & ADVERTISED_10baseT_Half)
                        auto_nego_tmp |= ADVERTISE_10HALF;
                if (adv & ADVERTISED_10baseT_Full)
                        auto_nego_tmp |= ADVERTISE_10FULL;
                if (adv & ADVERTISED_100baseT_Half)
                        auto_nego_tmp |= ADVERTISE_100HALF;
                if (adv & ADVERTISED_100baseT_Full)
                        auto_nego_tmp |= ADVERTISE_100FULL;

                if (auto_nego_tmp == 0)
                        goto exit;

                auto_nego |= auto_nego_tmp;
                goto skip_check_lpa;
        }
        if (!(aner & EXPANSION_NWAY))
                goto exit;

        if ((adv & ADVERTISED_10baseT_Half) && (anlpar & LPA_10HALF))
                auto_nego |= ADVERTISE_10HALF;
        else if ((adv & ADVERTISED_10baseT_Full) && (anlpar & LPA_10FULL))
                auto_nego |= ADVERTISE_10FULL;
        else if ((adv & ADVERTISED_100baseT_Half) && (anlpar & LPA_100HALF))
                auto_nego |= ADVERTISE_100HALF;
        else if ((adv & ADVERTISED_100baseT_Full) && (anlpar & LPA_100FULL))
                auto_nego |= ADVERTISE_100FULL;
        else if (adv & ADVERTISED_1000baseT_Half && (gbsr & LPA_1000HALF))
                giga_ctrl |= ADVERTISE_1000HALF;
        else if (adv & ADVERTISED_1000baseT_Full && (gbsr & LPA_1000FULL))
                giga_ctrl |= ADVERTISE_1000FULL;
        else if (adv & ADVERTISED_2500baseX_Full && (status_2500 & RTK_LPA_ADVERTISE_2500FULL))
                ctrl_2500 |= RTK_ADVERTISE_2500FULL;
        else
                goto exit;

skip_check_lpa:
        if (tp->DASH)
                auto_nego |= (ADVERTISE_100FULL | ADVERTISE_100HALF | ADVERTISE_10HALF | ADVERTISE_10FULL);

#ifdef CONFIG_DOWN_SPEED_100
        auto_nego |= (ADVERTISE_100FULL | ADVERTISE_100HALF | ADVERTISE_10HALF | ADVERTISE_10FULL);
#endif

        rtl8125_mdio_write(tp, MII_ADVERTISE, auto_nego);
        rtl8125_mdio_write(tp, MII_CTRL1000, giga_ctrl);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA5D4, ctrl_2500);

        rtl8125_disable_giga_lite(tp);

        rtl8125_phy_restart_nway(dev);

exit:
        r8125_spin_unlock(&tp->phy_lock, flags);

        return auto_nego;
}

static bool
rtl8125_keep_wol_link_speed(struct net_device *dev, u8 from_suspend)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (from_suspend && tp->link_ok(dev) && (tp->wol_opts & WAKE_PHY))
                return 1;

        if (!from_suspend && tp->resume_not_chg_speed)
                return 1;

        return 0;
}
static void
rtl8125_powerdown_pll(struct net_device *dev, u8 from_suspend)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        /* Reboot not set wol link speed */
        if (system_state == SYSTEM_RESTART)
                return;

        tp->check_keep_link_speed = 0;
        if (tp->wol_enabled == WOL_ENABLED || tp->DASH || tp->EnableKCPOffload) {
                int auto_nego;

                rtl8125_set_hw_wol(dev, tp->wol_opts);

                rtl8125_enable_cfg9346_write(tp);
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) | PMSTS_En);
                rtl8125_disable_cfg9346_write(tp);

                /* Enable the PME and clear the status */
                rtl8125_set_pci_pme(tp, 1);

#ifdef ENABLE_FIBER_SUPPORT
                if (HW_FIBER_MODE_ENABLED(tp))
                        return;
#endif /* ENABLE_FIBER_SUPPORT */

                if (rtl8125_keep_wol_link_speed(dev, from_suspend)) {
                        tp->check_keep_link_speed = 1;
                } else {
                        if (tp->D0SpeedUpSpeed != D0_SPEED_UP_SPEED_DISABLE) {
                                rtl8125_enable_d0_speedup(tp);
                                tp->check_keep_link_speed = 1;
                        }

                        auto_nego = rtl8125_set_wol_link_speed(dev);

                        if (tp->RequiredPfmPatch)
                                rtl8125_set_pfm_patch(tp,
                                                      (auto_nego & (ADVERTISE_10HALF | ADVERTISE_10FULL)) ?
                                                      1 : 0);
                }

                RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) | AcceptBroadcast | AcceptMulticast | AcceptMyPhys);

                return;
        }

#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp))
                return;
#endif /* ENABLE_FIBER_SUPPORT */

        if (tp->DASH)
                return;

        rtl8125_phy_power_down(dev);

        if (!tp->HwIcVerUnknown)
                RTL_W8(tp, PMCH, RTL_R8(tp, PMCH) & ~BIT_7);

        RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) & ~BIT_6);
}

static void rtl8125_powerup_pll(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W8(tp, PMCH, RTL_R8(tp, PMCH) | BIT_7 | BIT_6);

        if (tp->resume_not_chg_speed)
                return;

        rtl8125_phy_power_up(dev);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static void
rtl8125_get_wol(struct net_device *dev,
                struct ethtool_wolinfo *wol)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 options;

        wol->wolopts = 0;

        if (tp->mcfg == CFG_METHOD_DEFAULT || disable_wol_support) {
                wol->supported = 0;
                return;
        } else {
                wol->supported = WAKE_ANY;
        }

        options = RTL_R8(tp, Config1);
        if (!(options & PMEnable))
                return;

        wol->wolopts = tp->wol_opts;
}

static int
rtl8125_set_wol(struct net_device *dev,
                struct ethtool_wolinfo *wol)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_DEFAULT || disable_wol_support)
                return -EOPNOTSUPP;

        tp->wol_opts = wol->wolopts;

        tp->wol_enabled = (tp->wol_opts) ? WOL_ENABLED : WOL_DISABLED;

        device_set_wakeup_enable(tp_to_dev(tp), wol->wolopts);

        return 0;
}

static void
rtl8125_get_drvinfo(struct net_device *dev,
                    struct ethtool_drvinfo *info)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_fw *rtl_fw = tp->rtl_fw;

        strscpy(info->driver, MODULENAME, sizeof(info->driver));
        strscpy(info->version, RTL8125_VERSION, sizeof(info->version));
        strscpy(info->bus_info, pci_name(tp->pci_dev), sizeof(info->bus_info));
        info->regdump_len = R8125_REGS_DUMP_SIZE;
        info->eedump_len = tp->eeprom_len;
        BUILD_BUG_ON(sizeof(info->fw_version) < sizeof(rtl_fw->version));
        if (rtl_fw)
                strscpy(info->fw_version, rtl_fw->version,
                        sizeof(info->fw_version));
}

static int
rtl8125_get_regs_len(struct net_device *dev)
{
        return R8125_REGS_DUMP_SIZE;
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static void
rtl8125_set_d0_speedup_speed(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp))
                return;

        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_DISABLE;
        if (tp->autoneg == AUTONEG_ENABLE) {
                if (tp->speed == SPEED_2500)
                        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_2500;
                else if (tp->speed == SPEED_1000)
                        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_1000;
        }
}

static int
rtl8125_set_speed_xmii(struct net_device *dev,
                       u8 autoneg,
                       u32 speed,
                       u8 duplex,
                       u64 adv)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int auto_nego = 0;
        int giga_ctrl = 0;
        int ctrl_2500 = 0;
        int rc = -EINVAL;

        if (!rtl8125_is_speed_mode_valid(speed)) {
                speed = SPEED_2500;
                duplex = DUPLEX_FULL;
                adv |= tp->advertising;
        }

        if (eee_giga_lite && (autoneg == AUTONEG_ENABLE))
                rtl8125_enable_giga_lite(tp, adv);
        else
                rtl8125_disable_giga_lite(tp);

        giga_ctrl = rtl8125_mdio_read(tp, MII_CTRL1000);
        giga_ctrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);
        ctrl_2500 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D4);
        ctrl_2500 &= ~RTK_ADVERTISE_2500FULL;

        if (autoneg == AUTONEG_ENABLE) {
                /*n-way force*/
                auto_nego = rtl8125_mdio_read(tp, MII_ADVERTISE);
                auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL |
                               ADVERTISE_100HALF | ADVERTISE_100FULL |
                               ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);

                if (adv & ADVERTISED_10baseT_Half)
                        auto_nego |= ADVERTISE_10HALF;
                if (adv & ADVERTISED_10baseT_Full)
                        auto_nego |= ADVERTISE_10FULL;
                if (adv & ADVERTISED_100baseT_Half)
                        auto_nego |= ADVERTISE_100HALF;
                if (adv & ADVERTISED_100baseT_Full)
                        auto_nego |= ADVERTISE_100FULL;
                if (adv & ADVERTISED_1000baseT_Half)
                        giga_ctrl |= ADVERTISE_1000HALF;
                if (adv & ADVERTISED_1000baseT_Full)
                        giga_ctrl |= ADVERTISE_1000FULL;
                if (adv & ADVERTISED_2500baseX_Full)
                        ctrl_2500 |= RTK_ADVERTISE_2500FULL;

                //flow control
                if (tp->fcpause == rtl8125_fc_full)
                        auto_nego |= ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;

                tp->phy_auto_nego_reg = auto_nego;
                tp->phy_1000_ctrl_reg = giga_ctrl;

                tp->phy_2500_ctrl_reg = ctrl_2500;

                rtl8125_mdio_write(tp, 0x1f, 0x0000);
                rtl8125_mdio_write(tp, MII_ADVERTISE, auto_nego);
                rtl8125_mdio_write(tp, MII_CTRL1000, giga_ctrl);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA5D4, ctrl_2500);
                rtl8125_phy_restart_nway(dev);
        } else {
                /*true force*/
                if (speed == SPEED_10 || speed == SPEED_100)
                        rtl8125_phy_setup_force_mode(dev, speed, duplex);
                else
                        goto out;
        }

        tp->autoneg = autoneg;
        tp->speed = speed;
        tp->duplex = duplex;
        tp->advertising = adv;

        rtl8125_set_d0_speedup_speed(tp);

#ifdef ENABLE_FIBER_SUPPORT
        rtl8125_hw_fiber_phy_config(tp);
#endif /* ENABLE_FIBER_SUPPORT */

        rc = 0;
out:
        return rc;
}

static int
rtl8125_set_speed(struct net_device *dev,
                  u8 autoneg,
                  u32 speed,
                  u8 duplex,
                  u64 adv)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret;

        if (tp->resume_not_chg_speed)
                return 0;

        ret = tp->set_speed(dev, autoneg, speed, duplex, adv);

        return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int
rtl8125_set_settings(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                     struct ethtool_cmd *cmd
#else
                     const struct ethtool_link_ksettings *cmd
#endif
                    )
{
        int ret;
        u8 autoneg;
        u32 speed;
        u8 duplex;
        u64 supported = 0, advertising = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        autoneg = cmd->autoneg;
        speed = cmd->speed;
        duplex = cmd->duplex;
        supported = cmd->supported;
        advertising = cmd->advertising;
#else
        const struct ethtool_link_settings *base = &cmd->base;
        autoneg = base->autoneg;
        speed = base->speed;
        duplex = base->duplex;
        ethtool_convert_link_mode_to_legacy_u32((u32*)&supported,
                                                cmd->link_modes.supported);
        ethtool_convert_link_mode_to_legacy_u32((u32*)&advertising,
                                                cmd->link_modes.advertising);
        if (test_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
                     cmd->link_modes.supported))
                supported |= ADVERTISED_2500baseX_Full;
        if (test_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
                     cmd->link_modes.advertising))
                advertising |= ADVERTISED_2500baseX_Full;
#endif
        if (advertising & ~supported)
                return -EINVAL;

        ret = rtl8125_set_speed(dev, autoneg, speed, duplex, advertising);

        return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static u32
rtl8125_get_tx_csum(struct net_device *dev)
{
        u32 ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        ret = ((dev->features & NETIF_F_IP_CSUM) != 0);
#else
        ret = ((dev->features & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) != 0);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

        return ret;
}

static u32
rtl8125_get_rx_csum(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 ret;

        ret = tp->cp_cmd & RxChkSum;

        return ret;
}

static int
rtl8125_set_tx_csum(struct net_device *dev,
                    u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        if (data)
                dev->features |= NETIF_F_IP_CSUM;
        else
                dev->features &= ~NETIF_F_IP_CSUM;
#else
        if (data)
                dev->features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
        else
                dev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

        return 0;
}

static int
rtl8125_set_rx_csum(struct net_device *dev,
                    u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

        if (data)
                tp->cp_cmd |= RxChkSum;
        else
                tp->cp_cmd &= ~RxChkSum;

        RTL_W16(tp, CPlusCmd, tp->cp_cmd);

        return 0;
}
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static u32
rtl8125_rx_desc_opts1(struct rtl8125_private *tp,
                      struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                return READ_ONCE(((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts1);
        case RX_DESC_RING_TYPE_4:
                return READ_ONCE(((struct RxDescV4 *)desc)->RxDescNormalDDWord2.opts1);
        default:
                return READ_ONCE(desc->opts1);
        }
}

static u32
rtl8125_rx_desc_opts2(struct rtl8125_private *tp,
                      struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                return ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts2;
        case RX_DESC_RING_TYPE_4:
                return ((struct RxDescV4 *)desc)->RxDescNormalDDWord2.opts2;
        default:
                return desc->opts2;
        }
}

#ifdef CONFIG_R8125_VLAN

static void
rtl8125_clear_rx_desc_opts2(struct rtl8125_private *tp,
                            struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts2 = 0;
                break;
        case RX_DESC_RING_TYPE_4:
                ((struct RxDescV4 *)desc)->RxDescNormalDDWord2.opts2 = 0;
                break;
        default:
                desc->opts2 = 0;
                break;
        }
}

static inline u32
rtl8125_tx_vlan_tag(struct rtl8125_private *tp,
                    struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        return (tp->vlgrp && vlan_tx_tag_present(skb)) ?
               TxVlanTag | swab16(vlan_tx_tag_get(skb)) : 0x00;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        return (vlan_tx_tag_present(skb)) ?
               TxVlanTag | swab16(vlan_tx_tag_get(skb)) : 0x00;
#else
        return (skb_vlan_tag_present(skb)) ?
               TxVlanTag | swab16(skb_vlan_tag_get(skb)) : 0x00;
#endif

        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

static void
rtl8125_vlan_rx_register(struct net_device *dev,
                         struct vlan_group *grp)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->vlgrp = grp;

        if (tp->vlgrp) {
                tp->rtl8125_rx_config |= (EnableInnerVlan | EnableOuterVlan);
                RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) | (EnableInnerVlan | EnableOuterVlan))
        } else {
                tp->rtl8125_rx_config &= ~(EnableInnerVlan | EnableOuterVlan);
                RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) & ~(EnableInnerVlan | EnableOuterVlan))
        }
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
static void
rtl8125_vlan_rx_kill_vid(struct net_device *dev,
                         unsigned short vid)
{
        struct rtl8125_private *tp = netdev_priv(dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
        if (tp->vlgrp)
                tp->vlgrp->vlan_devices[vid] = NULL;
#else
        vlan_group_set_device(tp->vlgrp, vid, NULL);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
}
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

static int
rtl8125_rx_vlan_skb(struct rtl8125_private *tp,
                    struct RxDesc *desc,
                    struct sk_buff *skb)
{
        u32 opts2 = le32_to_cpu(rtl8125_rx_desc_opts2(tp, desc));
        int ret = -1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        if (tp->vlgrp && (opts2 & RxVlanTag)) {
                rtl8125_rx_hwaccel_skb(skb, tp->vlgrp,
                                       swab16(opts2 & 0xffff));
                ret = 0;
        }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        if (opts2 & RxVlanTag)
                __vlan_hwaccel_put_tag(skb, swab16(opts2 & 0xffff));
#else
        if (opts2 & RxVlanTag)
                __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), swab16(opts2 & 0xffff));
#endif

        rtl8125_clear_rx_desc_opts2(tp, desc);
        return ret;
}

#else /* !CONFIG_R8125_VLAN */

static inline u32
rtl8125_tx_vlan_tag(struct rtl8125_private *tp,
                    struct sk_buff *skb)
{
        return 0;
}

static int
rtl8125_rx_vlan_skb(struct rtl8125_private *tp,
                    struct RxDesc *desc,
                    struct sk_buff *skb)
{
        return -1;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)

static netdev_features_t rtl8125_fix_features(struct net_device *dev,
                netdev_features_t features)
{
        if (dev->mtu > MSS_MAX || dev->mtu > ETH_DATA_LEN)
                features &= ~NETIF_F_ALL_TSO;
#ifndef CONFIG_R8125_VLAN
        features &= ~NETIF_F_ALL_CSUM;
#endif

        return features;
}

static int rtl8125_hw_set_features(struct net_device *dev,
                                   netdev_features_t features)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 rx_config;

        rx_config = RTL_R32(tp, RxConfig);
        if (features & NETIF_F_RXALL) {
                tp->rtl8125_rx_config |= (AcceptErr | AcceptRunt);
                rx_config |= (AcceptErr | AcceptRunt);
        } else {
                tp->rtl8125_rx_config &= ~(AcceptErr | AcceptRunt);
                rx_config &= ~(AcceptErr | AcceptRunt);
        }

        if (features & NETIF_F_HW_VLAN_RX) {
                tp->rtl8125_rx_config |= (EnableInnerVlan | EnableOuterVlan);
                rx_config |= (EnableInnerVlan | EnableOuterVlan);
        } else {
                tp->rtl8125_rx_config &= ~(EnableInnerVlan | EnableOuterVlan);
                rx_config &= ~(EnableInnerVlan | EnableOuterVlan);
        }

        RTL_W32(tp, RxConfig, rx_config);

        if (features & NETIF_F_RXCSUM)
                tp->cp_cmd |= RxChkSum;
        else
                tp->cp_cmd &= ~RxChkSum;

        RTL_W16(tp, CPlusCmd, tp->cp_cmd);
        RTL_R16(tp, CPlusCmd);

        return 0;
}

static int rtl8125_set_features(struct net_device *dev,
                                netdev_features_t features)
{
        features &= NETIF_F_RXALL | NETIF_F_RXCSUM | NETIF_F_HW_VLAN_RX;

        rtl8125_hw_set_features(dev, features);

        return 0;
}

#endif

static u8 rtl8125_get_mdi_status(struct rtl8125_private *tp)
{
        if (!tp->link_ok(tp->dev))
                return ETH_TP_MDI_INVALID;

        if (rtl8125_mdio_direct_read_phy_ocp(tp, 0xA444) & BIT_1)
                return ETH_TP_MDI;
        else
                return ETH_TP_MDI_X;
}

static void rtl8125_gset_xmii(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                              struct ethtool_cmd *cmd
#else
                              struct ethtool_link_ksettings *cmd
#endif
                             )
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 aner = tp->phy_reg_aner;
        u16 anlpar = tp->phy_reg_anlpar;
        u16 gbsr = tp->phy_reg_gbsr;
        u16 status_2500 = tp->phy_reg_status_2500;
        u64 lpa_adv = 0;
        u32 status;
        u8 autoneg, duplex;
        u32 speed = 0;
        u16 bmcr;
        u64 supported, advertising;
        unsigned long flags;
        u8 report_lpa = 0;

        supported = SUPPORTED_10baseT_Half |
                    SUPPORTED_10baseT_Full |
                    SUPPORTED_100baseT_Half |
                    SUPPORTED_100baseT_Full |
                    SUPPORTED_1000baseT_Full |
                    SUPPORTED_2500baseX_Full |
                    SUPPORTED_Autoneg |
                    SUPPORTED_TP |
                    SUPPORTED_Pause |
                    SUPPORTED_Asym_Pause;

        if (!HW_SUPP_PHY_LINK_SPEED_2500M(tp))
                supported &= ~SUPPORTED_2500baseX_Full;

        advertising = tp->advertising;
        if (tp->phy_auto_nego_reg || tp->phy_1000_ctrl_reg ||
            tp->phy_2500_ctrl_reg) {
                advertising = 0;
                if (tp->phy_auto_nego_reg & ADVERTISE_10HALF)
                        advertising |= ADVERTISED_10baseT_Half;
                if (tp->phy_auto_nego_reg & ADVERTISE_10FULL)
                        advertising |= ADVERTISED_10baseT_Full;
                if (tp->phy_auto_nego_reg & ADVERTISE_100HALF)
                        advertising |= ADVERTISED_100baseT_Half;
                if (tp->phy_auto_nego_reg & ADVERTISE_100FULL)
                        advertising |= ADVERTISED_100baseT_Full;
                if (tp->phy_1000_ctrl_reg & ADVERTISE_1000FULL)
                        advertising |= ADVERTISED_1000baseT_Full;
                if (tp->phy_2500_ctrl_reg & RTK_ADVERTISE_2500FULL)
                        advertising |= ADVERTISED_2500baseX_Full;
        }

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        bmcr = rtl8125_mdio_read(tp, MII_BMCR);
        if (bmcr & BMCR_ANENABLE) {
                autoneg = AUTONEG_ENABLE;
                advertising |= ADVERTISED_Autoneg;
        } else {
                autoneg = AUTONEG_DISABLE;
        }

        advertising |= ADVERTISED_TP;

        status = rtl8125_get_phy_status(tp);
        if (netif_running(dev) && (status & LinkStatus))
                report_lpa = 1;
#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp) &&
            rtl8125_fiber_link_ok(dev) != R8125_LINK_STATE_ON)
                report_lpa = 0;
#endif /* ENABLE_FIBER_SUPPORT */

        if (report_lpa) {
                /*link on*/
                speed = rtl8125_convert_link_speed(status);

                if (status & TxFlowCtrl)
                        advertising |= ADVERTISED_Asym_Pause;

                if (status & RxFlowCtrl)
                        advertising |= ADVERTISED_Pause;

                duplex = ((status & (_1000bpsF | _2500bpsF)) ||
                          (status & FullDup)) ?
                         DUPLEX_FULL : DUPLEX_HALF;

                /*link partner*/
                if (aner & EXPANSION_NWAY)
                        lpa_adv |= ADVERTISED_Autoneg;
                if (anlpar & LPA_10HALF)
                        lpa_adv |= ADVERTISED_10baseT_Half;
                if (anlpar & LPA_10FULL)
                        lpa_adv |= ADVERTISED_10baseT_Full;
                if (anlpar & LPA_100HALF)
                        lpa_adv |= ADVERTISED_100baseT_Half;
                if (anlpar & LPA_100FULL)
                        lpa_adv |= ADVERTISED_100baseT_Full;
                if (anlpar & LPA_PAUSE_CAP)
                        lpa_adv |= ADVERTISED_Pause;
                if (anlpar & LPA_PAUSE_ASYM)
                        lpa_adv |= ADVERTISED_Asym_Pause;
                if (gbsr & LPA_1000HALF)
                        lpa_adv |= ADVERTISED_1000baseT_Half;
                if (gbsr & LPA_1000FULL)
                        lpa_adv |= ADVERTISED_1000baseT_Full;
                if (status_2500 & RTK_LPA_ADVERTISE_2500FULL)
                        lpa_adv |= ADVERTISED_2500baseX_Full;
        } else {
                /*link down*/
                speed = SPEED_UNKNOWN;
                duplex = DUPLEX_UNKNOWN;
                lpa_adv = 0;
        }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        cmd->supported = (u32)supported;
        cmd->advertising = (u32)advertising;
        cmd->autoneg = autoneg;
        cmd->speed = speed;
        cmd->duplex = duplex;
        cmd->port = PORT_TP;
        cmd->lp_advertising = (u32)lpa_adv;
        cmd->eth_tp_mdix = rtl8125_get_mdi_status(tp);
#else
        ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported,
                                                supported);
        ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising,
                                                advertising);
        ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.lp_advertising,
                                                lpa_adv);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
        if (supported & SUPPORTED_2500baseX_Full) {
                linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
                                 cmd->link_modes.supported, 0);
                linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
                                 cmd->link_modes.supported, 1);
        }
        if (advertising & ADVERTISED_2500baseX_Full) {
                linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
                                 cmd->link_modes.advertising, 0);
                linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
                                 cmd->link_modes.advertising, 1);
        }
        if (report_lpa) {
                if (lpa_adv & ADVERTISED_2500baseX_Full) {
                        linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
                                         cmd->link_modes.lp_advertising, 0);
                        linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
                                         cmd->link_modes.lp_advertising, 1);
                }
        }
#endif
        cmd->base.autoneg = autoneg;
        cmd->base.speed = speed;
        cmd->base.duplex = duplex;
        cmd->base.port = PORT_TP;
        cmd->base.eth_tp_mdix = rtl8125_get_mdi_status(tp);
#endif
        r8125_spin_unlock(&tp->phy_lock, flags);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int
rtl8125_get_settings(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                     struct ethtool_cmd *cmd
#else
                     struct ethtool_link_ksettings *cmd
#endif
                    )
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->get_settings(dev, cmd);

        return 0;
}

static void rtl8125_get_regs(struct net_device *dev, struct ethtool_regs *regs,
                             void *p)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        unsigned int i;
        u8 *data = p;

        if (regs->len < R8125_REGS_DUMP_SIZE)
                return /* -EINVAL */;

        memset(p, 0, regs->len);

        for (i = 0; i < R8125_MAC_REGS_SIZE; i++)
                *data++ = readb(ioaddr + i);
        data = (u8*)p + 256;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        for (i = 0; i < R8125_PHY_REGS_SIZE/2; i++) {
                *(u16*)data = rtl8125_mdio_read(tp, i);
                data += 2;
        }
        data = (u8*)p + 256 * 2;

        for (i = 0; i < R8125_EPHY_REGS_SIZE/2; i++) {
                *(u16*)data = rtl8125_ephy_read(tp, i);
                data += 2;
        }
        data = (u8*)p + 256 * 3;

        for (i = 0; i < R8125_ERI_REGS_SIZE; i+=4) {
                *(u32*)data = rtl8125_eri_read(tp, i , 4, ERIAR_ExGMAC);
                data += 4;
        }
}

static void rtl8125_get_pauseparam(struct net_device *dev,
                                   struct ethtool_pauseparam *pause)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        pause->autoneg = (tp->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE);
        if (tp->fcpause == rtl8125_fc_rx_pause)
                pause->rx_pause = 1;
        else if (tp->fcpause == rtl8125_fc_tx_pause)
                pause->tx_pause = 1;
        else if (tp->fcpause == rtl8125_fc_full) {
                pause->rx_pause = 1;
                pause->tx_pause = 1;
        }
}

static int rtl8125_set_pauseparam(struct net_device *dev,
                                  struct ethtool_pauseparam *pause)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        enum rtl8125_fc_mode newfc;

        if (pause->tx_pause || pause->rx_pause)
                newfc = rtl8125_fc_full;
        else
                newfc = rtl8125_fc_none;

        if (tp->fcpause != newfc) {
                tp->fcpause = newfc;

                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
        }

        return 0;
}

static u32
rtl8125_get_msglevel(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        return tp->msg_enable;
}

static void
rtl8125_set_msglevel(struct net_device *dev,
                     u32 value)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->msg_enable = value;
}

static const char rtl8125_gstrings[][ETH_GSTRING_LEN] = {
        /* legacy */
        "tx_packets",
        "rx_packets",
        "tx_errors",
        "rx_errors",
        "rx_missed",
        "align_errors",
        "tx_single_collisions",
        "tx_multi_collisions",
        "unicast",
        "broadcast",
        "multicast",
        "tx_aborted",
        "tx_underrun",

        /* extended */
        "tx_octets",
        "rx_octets",
        "rx_multicast64",
        "tx_unicast64",
        "tx_broadcast64",
        "tx_multicast64",
        "tx_pause_on",
        "tx_pause_off",
        "tx_pause_all",
        "tx_deferred",
        "tx_late_collision",
        "tx_all_collision",
        "tx_aborted32",
        "align_errors32",
        "rx_frame_too_long",
        "rx_runt",
        "rx_pause_on",
        "rx_pause_off",
        "rx_pause_all",
        "rx_unknown_opcode",
        "rx_mac_error",
        "tx_underrun32",
        "rx_mac_missed",
        "rx_tcam_dropped",
        "tdu",
        "rdu",
};
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int rtl8125_get_stats_count(struct net_device *dev)
{
        return ARRAY_SIZE(rtl8125_gstrings);
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
#else
static int rtl8125_get_sset_count(struct net_device *dev, int sset)
{
        switch (sset) {
        case ETH_SS_STATS:
                return ARRAY_SIZE(rtl8125_gstrings);
        default:
                return -EOPNOTSUPP;
        }
}
#endif

static void
rtl8125_set_ring_size(struct rtl8125_private *tp, u32 rx, u32 tx)
{
        int i;

        for (i = 0; i < R8125_MAX_RX_QUEUES; i++)
                tp->rx_ring[i].num_rx_desc = rx;

        for (i = 0; i < R8125_MAX_TX_QUEUES; i++)
                tp->tx_ring[i].num_tx_desc = tx;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
static void rtl8125_get_ringparam(struct net_device *dev,
                                  struct ethtool_ringparam *ring,
                                  struct kernel_ethtool_ringparam *kernel_ring,
                                  struct netlink_ext_ack *extack)
#else
static void rtl8125_get_ringparam(struct net_device *dev,
                                  struct ethtool_ringparam *ring)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        ring->rx_max_pending = MAX_NUM_TX_DESC;
        ring->tx_max_pending = MAX_NUM_RX_DESC;
        ring->rx_pending = tp->rx_ring[0].num_rx_desc;
        ring->tx_pending = tp->tx_ring[0].num_tx_desc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
static int rtl8125_set_ringparam(struct net_device *dev,
                                 struct ethtool_ringparam *ring,
                                 struct kernel_ethtool_ringparam *kernel_ring,
                                 struct netlink_ext_ack *extack)
#else
static int rtl8125_set_ringparam(struct net_device *dev,
                                 struct ethtool_ringparam *ring)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 new_rx_count, new_tx_count;
        int rc = 0;

        if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending))
                return -EINVAL;

        new_tx_count = clamp_t(u32, ring->tx_pending,
                               MIN_NUM_TX_DESC, MAX_NUM_TX_DESC);

        new_rx_count = clamp_t(u32, ring->rx_pending,
                               MIN_NUM_RX_DESC, MAX_NUM_RX_DESC);

        if ((new_rx_count == tp->rx_ring[0].num_rx_desc) &&
            (new_tx_count == tp->tx_ring[0].num_tx_desc)) {
                /* nothing to do */
                return 0;
        }

        if (netif_running(dev)) {
                rtl8125_wait_for_quiescence(dev);
                rtl8125_close(dev);
        }

        rtl8125_set_ring_size(tp, new_rx_count, new_tx_count);

        if (netif_running(dev))
                rc = rtl8125_open(dev);

        return rc;
}
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static void
rtl8125_get_ethtool_stats(struct net_device *dev,
                          struct ethtool_stats *stats,
                          u64 *data)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;

        ASSERT_RTNL();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters)
                return;

        rtl8125_dump_tally_counter(tp, paddr);

        data[0] = le64_to_cpu(counters->tx_packets);
        data[1] = le64_to_cpu(counters->rx_packets);
        data[2] = le64_to_cpu(counters->tx_errors);
        data[3] = le32_to_cpu(counters->rx_errors);
        data[4] = le16_to_cpu(counters->rx_missed);
        data[5] = le16_to_cpu(counters->align_errors);
        data[6] = le32_to_cpu(counters->tx_one_collision);
        data[7] = le32_to_cpu(counters->tx_multi_collision);
        data[8] = le64_to_cpu(counters->rx_unicast);
        data[9] = le64_to_cpu(counters->rx_broadcast);
        data[10] = le32_to_cpu(counters->rx_multicast);
        data[11] = le16_to_cpu(counters->tx_aborted);
        data[12] = le16_to_cpu(counters->tx_underrun);

        data[13] = le64_to_cpu(counters->tx_octets);
        data[14] = le64_to_cpu(counters->rx_octets);
        data[15] = le64_to_cpu(counters->rx_multicast64);
        data[16] = le64_to_cpu(counters->tx_unicast64);
        data[17] = le64_to_cpu(counters->tx_broadcast64);
        data[18] = le64_to_cpu(counters->tx_multicast64);
        data[19] = le32_to_cpu(counters->tx_pause_on);
        data[20] = le32_to_cpu(counters->tx_pause_off);
        data[21] = le32_to_cpu(counters->tx_pause_all);
        data[22] = le32_to_cpu(counters->tx_deferred);
        data[23] = le32_to_cpu(counters->tx_late_collision);
        data[24] = le32_to_cpu(counters->tx_all_collision);
        data[25] = le32_to_cpu(counters->tx_aborted32);
        data[26] = le32_to_cpu(counters->align_errors32);
        data[27] = le32_to_cpu(counters->rx_frame_too_long);
        data[28] = le32_to_cpu(counters->rx_runt);
        data[29] = le32_to_cpu(counters->rx_pause_on);
        data[30] = le32_to_cpu(counters->rx_pause_off);
        data[31] = le32_to_cpu(counters->rx_pause_all);
        data[32] = le32_to_cpu(counters->rx_unknown_opcode);
        data[33] = le32_to_cpu(counters->rx_mac_error);
        data[34] = le32_to_cpu(counters->tx_underrun32);
        data[35] = le32_to_cpu(counters->rx_mac_missed);
        data[36] = le32_to_cpu(counters->rx_tcam_dropped);
        data[37] = le32_to_cpu(counters->tdu);
        data[38] = le32_to_cpu(counters->rdu);
}

static void
rtl8125_get_strings(struct net_device *dev,
                    u32 stringset,
                    u8 *data)
{
        switch (stringset) {
        case ETH_SS_STATS:
                memcpy(data, rtl8125_gstrings, sizeof(rtl8125_gstrings));
                break;
        }
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static int rtl_get_eeprom_len(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        return tp->eeprom_len;
}

static int rtl_get_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom, u8 *buf)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i,j,ret;
        int start_w, end_w;
        int VPD_addr, VPD_data;
        u32 *eeprom_buff;
        u16 tmp;

        if (tp->eeprom_type == EEPROM_TYPE_NONE) {
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Detect none EEPROM\n");
                return -EOPNOTSUPP;
        } else if (eeprom->len == 0 || (eeprom->offset+eeprom->len) > tp->eeprom_len) {
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Invalid parameter\n");
                return -EINVAL;
        }

        VPD_addr = 0xD2;
        VPD_data = 0xD4;

        start_w = eeprom->offset >> 2;
        end_w = (eeprom->offset + eeprom->len - 1) >> 2;

        eeprom_buff = kmalloc(sizeof(u32)*(end_w - start_w + 1), GFP_KERNEL);
        if (!eeprom_buff)
                return -ENOMEM;

        rtl8125_enable_cfg9346_write(tp);
        ret = -EFAULT;
        for (i=start_w; i<=end_w; i++) {
                pci_write_config_word(tp->pci_dev, VPD_addr, (u16)i*4);
                ret = -EFAULT;
                for (j = 0; j < 10; j++) {
                        udelay(400);
                        pci_read_config_word(tp->pci_dev, VPD_addr, &tmp);
                        if (tmp&0x8000) {
                                ret = 0;
                                break;
                        }
                }

                if (ret)
                        break;

                pci_read_config_dword(tp->pci_dev, VPD_data, &eeprom_buff[i-start_w]);
        }
        rtl8125_disable_cfg9346_write(tp);

        if (!ret)
                memcpy(buf, (u8 *)eeprom_buff + (eeprom->offset & 3), eeprom->len);

        kfree(eeprom_buff);

        return ret;
}

#undef ethtool_op_get_link
#define ethtool_op_get_link _kc_ethtool_op_get_link
static u32 _kc_ethtool_op_get_link(struct net_device *dev)
{
        return netif_carrier_ok(dev) ? 1 : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#undef ethtool_op_get_sg
#define ethtool_op_get_sg _kc_ethtool_op_get_sg
static u32 _kc_ethtool_op_get_sg(struct net_device *dev)
{
#ifdef NETIF_F_SG
        return (dev->features & NETIF_F_SG) != 0;
#else
        return 0;
#endif
}

#undef ethtool_op_set_sg
#define ethtool_op_set_sg _kc_ethtool_op_set_sg
static int _kc_ethtool_op_set_sg(struct net_device *dev, u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

#ifdef NETIF_F_SG
        if (data)
                dev->features |= NETIF_F_SG;
        else
                dev->features &= ~NETIF_F_SG;
#endif

        return 0;
}
#endif

static void
rtl8125_set_eee_lpi_timer(struct rtl8125_private *tp)
{
        u16 dev_lpi_timer;

        dev_lpi_timer = tp->eee.tx_lpi_timer;

        RTL_W16(tp, EEE_TXIDLE_TIMER_8125, dev_lpi_timer);
}

static bool rtl8125_is_adv_eee_enabled(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        //case CFG_METHOD_10:
        //case CFG_METHOD_11:
        case CFG_METHOD_12:
                //case CFG_METHOD_13:
                if (rtl8125_mdio_direct_read_phy_ocp(tp, 0xA430) & BIT_15)
                        return true;
                break;
        default:
                break;
        }

        return false;
}

static void _rtl8125_disable_adv_eee(struct rtl8125_private *tp)
{
        bool lock;

        if (rtl8125_is_adv_eee_enabled(tp))
                lock = true;
        else
                lock = false;

        if (lock)
                rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_clear_mac_ocp_bit(tp, 0xE052, BIT_0);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA442, BIT_12 | BIT_13);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA430, BIT_15);

        if (lock)
                rtl8125_clear_phy_mcu_patch_request(tp);
}

static void rtl8125_disable_adv_eee(struct rtl8125_private *tp)
{
        rtl8125_oob_mutex_lock(tp);

        _rtl8125_disable_adv_eee(tp);

        rtl8125_oob_mutex_unlock(tp);
}

static int rtl8125_enable_eee(struct rtl8125_private *tp)
{
        struct ethtool_keee *eee = &tp->eee;
        u16 eee_adv_cap1_t = rtl8125_ethtool_adv_to_mmd_eee_adv_cap1_t(eee->advertised);
        u16 eee_adv_cap2_t = rtl8125_ethtool_adv_to_mmd_eee_adv_cap2_t(eee->advertised);
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_set_mac_ocp_bit(tp, 0xE040, (BIT_1|BIT_0));
                rtl8125_set_mac_ocp_bit(tp, 0xEB62, (BIT_2|BIT_1));

                rtl8125_set_eth_phy_ocp_bit(tp, 0xA432, BIT_4);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA5D0,
                                                      MDIO_EEE_100TX | MDIO_EEE_1000T,
                                                      eee_adv_cap1_t);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D4, MDIO_EEE_2_5GT);

                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D8, BIT_4);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_7);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA4A2, BIT_9);
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                rtl8125_set_mac_ocp_bit(tp, 0xE040, (BIT_1|BIT_0));

                rtl8125_set_eth_phy_ocp_bit(tp, 0xA432, BIT_4);

                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA5D0,
                                                      MDIO_EEE_100TX | MDIO_EEE_1000T,
                                                      eee_adv_cap1_t);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA6D4,
                                                      MDIO_EEE_2_5GT,
                                                      eee_adv_cap2_t);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D8, BIT_4);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_7);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA4A2, BIT_9);
                break;
        default:
                ret = -EOPNOTSUPP;
                break;
        }

        /*Advanced EEE*/
        rtl8125_disable_adv_eee(tp);

        return ret;
}

static int rtl8125_disable_eee(struct rtl8125_private *tp)
{
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_clear_mac_ocp_bit(tp, 0xE040, (BIT_1|BIT_0));
                rtl8125_clear_mac_ocp_bit(tp, 0xEB62, (BIT_2|BIT_1));

                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA432, BIT_4);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5D0, (MDIO_EEE_100TX | MDIO_EEE_1000T));
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D4, BIT_0);

                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D8, BIT_4);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_7);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA4A2, BIT_9);
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                rtl8125_clear_mac_ocp_bit(tp, 0xE040, (BIT_1|BIT_0));

                rtl8125_set_eth_phy_ocp_bit(tp, 0xA432, BIT_4);

                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5D0, (MDIO_EEE_100TX | MDIO_EEE_1000T));
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D4, MDIO_EEE_2_5GT);

                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA6D8, BIT_4);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA428, BIT_7);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA4A2, BIT_9);
                break;
        default:
                ret = -EOPNOTSUPP;
                break;
        }

        /*Advanced EEE*/
        rtl8125_disable_adv_eee(tp);

        return ret;
}

static int rtl_nway_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret, bmcr;

        if (unlikely(tp->rtk_enable_diag))
                return -EBUSY;

        /* if autoneg is off, it's an error */
        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        bmcr = rtl8125_mdio_read(tp, MII_BMCR);

        if (bmcr & BMCR_ANENABLE) {
                bmcr |= BMCR_ANRESTART;
                rtl8125_mdio_write(tp, MII_BMCR, bmcr);
                ret = 0;
        } else {
                ret = -EINVAL;
        }

        return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static u32
rtl8125_device_lpi_t_to_ethtool_lpi_t(struct rtl8125_private *tp , u32 lpi_timer)
{
        u32 to_us;
        u32 status;

        to_us = lpi_timer * 80;
        status = rtl8125_get_phy_status(tp);
        if (status & LinkStatus) {
                /*link on*/
                //2.5G : lpi_timer * 3.2ns
                //Giga: lpi_timer * 8ns
                //100M : lpi_timer * 80ns
                if (status & _2500bpsF)
                        to_us = (lpi_timer * 32) / 10;
                else if (status & _1000bpsF)
                        to_us = lpi_timer * 8;
        }

        //ns to us
        to_us /= 1000;

        return to_us;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
static void
rtl8125_adv_to_linkmode(unsigned long *mode, u64 adv)
{
        linkmode_zero(mode);

        if (adv & ADVERTISED_10baseT_Half)
                linkmode_set_bit(ETHTOOL_LINK_MODE_10baseT_Half_BIT, mode);
        if (adv & ADVERTISED_10baseT_Full)
                linkmode_set_bit(ETHTOOL_LINK_MODE_10baseT_Full_BIT, mode);
        if (adv & ADVERTISED_100baseT_Half)
                linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Half_BIT, mode);
        if (adv & ADVERTISED_100baseT_Full)
                linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, mode);
        if (adv & ADVERTISED_1000baseT_Half)
                linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Half_BIT, mode);
        if (adv & ADVERTISED_1000baseT_Full)
                linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, mode);
        if (adv & ADVERTISED_2500baseX_Full)
                linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT, mode);
}

static int
rtl_ethtool_get_eee(struct net_device *net, struct ethtool_keee *edata)
{
        __ETHTOOL_DECLARE_LINK_MODE_MASK(common);
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_keee *eee = &tp->eee;
        unsigned long flags;
        u32 tx_lpi_timer;
        u16 val;

        if (unlikely(tp->rtk_enable_diag))
                return -EBUSY;

        r8125_spin_lock(&tp->phy_lock, flags);

        /* Get LP advertisement EEE */
        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D2);
        mii_eee_cap1_mod_linkmode_t(edata->lp_advertised, val);
        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA6D0);
        mii_eee_cap2_mod_linkmode_sup_t(edata->lp_advertised, val);

        r8125_spin_unlock(&tp->phy_lock, flags);

        /* Get EEE Tx LPI timer*/
        tx_lpi_timer = rtl8125_device_lpi_t_to_ethtool_lpi_t(tp, eee->tx_lpi_timer);

        val = rtl8125_mac_ocp_read(tp, 0xE040);
        val &= BIT_1 | BIT_0;

        edata->eee_enabled = !!val;
        linkmode_copy(edata->supported, eee->supported);
        linkmode_copy(edata->advertised, eee->advertised);
        edata->tx_lpi_enabled = edata->eee_enabled;
        edata->tx_lpi_timer = tx_lpi_timer;
        linkmode_and(common, edata->advertised, edata->lp_advertised);
        edata->eee_active = !linkmode_empty(common);

        return 0;
}

static int
rtl_ethtool_set_eee(struct net_device *net, struct ethtool_keee *edata)
{
        __ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
        __ETHTOOL_DECLARE_LINK_MODE_MASK(tmp);
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_keee *eee = &tp->eee;
        unsigned long flags;
        int rc = 0;

        r8125_spin_lock(&tp->phy_lock, flags);

        if (!HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp) ||
            tp->DASH) {
                rc = -EOPNOTSUPP;
                goto out;
        }

        if (unlikely(tp->rtk_enable_diag)) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "Diag Enabled\n");
                rc = -EBUSY;
                goto out;
        }

        if (tp->autoneg != AUTONEG_ENABLE) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE requires autoneg\n");
                rc = -EINVAL;
                goto out;
        }

        /*
        if (edata->tx_lpi_enabled) {
        if (edata->tx_lpi_timer > tp->max_jumbo_frame_size ||
            edata->tx_lpi_timer < ETH_MIN_MTU) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "Valid LPI timer range is %d to %d. \n",
                           ETH_MIN_MTU, tp->max_jumbo_frame_size);
                rc = -EINVAL;
                goto out;
        }
        }
        */

        rtl8125_adv_to_linkmode(advertising, tp->advertising);
        if (linkmode_empty(edata->advertised)) {
                linkmode_and(edata->advertised, advertising, eee->supported);
        } else if (linkmode_andnot(tmp, edata->advertised, advertising)) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised must be a subset of autoneg advertised speeds\n");
                rc = -EINVAL;
                goto out;
        }

        if (linkmode_andnot(tmp, edata->advertised, eee->supported)) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised must be a subset of support \n");
                rc = -EINVAL;
                goto out;
        }

        //tp->eee.eee_enabled = edata->eee_enabled;
        //tp->eee_adv_t = rtl8125_ethtool_adv_to_mmd_eee_adv_cap1_t(edata->advertised);

        linkmode_copy(eee->advertised, edata->advertised);
        //eee->tx_lpi_enabled = edata->tx_lpi_enabled;
        //eee->tx_lpi_timer = edata->tx_lpi_timer;
        eee->eee_enabled = edata->eee_enabled;

        if (eee->eee_enabled)
                rtl8125_enable_eee(tp);
        else
                rtl8125_disable_eee(tp);

        rtl_nway_reset(net);

out:
        r8125_spin_unlock(&tp->phy_lock, flags);

        return rc;
}
#else
static int
rtl_ethtool_get_eee(struct net_device *net, struct ethtool_eee *edata)
{
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_eee *eee = &tp->eee;
        u32 lp, adv, tx_lpi_timer, supported = 0;
        unsigned long flags;
        u16 val;

        if (unlikely(tp->rtk_enable_diag))
                return -EBUSY;

        r8125_spin_lock(&tp->phy_lock, flags);

        /* Get Supported EEE */
        //val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5C4);
        //supported = mmd_eee_cap_to_ethtool_sup_t(val);
        supported = eee->supported;

        /* Get advertisement EEE */
        adv = eee->advertised;

        /* Get LP advertisement EEE */
        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA5D2);
        lp = mmd_eee_adv_to_ethtool_adv_t(val);
        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA6D0);
        if (val & RTK_LPA_EEE_ADVERTISE_2500FULL)
                lp |= ADVERTISED_2500baseX_Full;

        r8125_spin_unlock(&tp->phy_lock, flags);

        /* Get EEE Tx LPI timer*/
        tx_lpi_timer = rtl8125_device_lpi_t_to_ethtool_lpi_t(tp, eee->tx_lpi_timer);

        val = rtl8125_mac_ocp_read(tp, 0xE040);
        val &= BIT_1 | BIT_0;

        edata->eee_enabled = !!val;
        edata->eee_active = !!(supported & adv & lp);
        edata->supported = supported;
        edata->advertised = adv;
        edata->lp_advertised = lp;
        edata->tx_lpi_enabled = edata->eee_enabled;
        edata->tx_lpi_timer = tx_lpi_timer;

        return 0;
}

static int
rtl_ethtool_set_eee(struct net_device *net, struct ethtool_eee *edata)
{
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_eee *eee = &tp->eee;
        unsigned long flags;
        u64 advertising;
        int rc = 0;

        r8125_spin_lock(&tp->phy_lock, flags);

        if (!HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp) ||
            tp->DASH) {
                rc = -EOPNOTSUPP;
                goto out;
        }

        if (unlikely(tp->rtk_enable_diag)) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "Diag Enabled\n");
                rc = -EBUSY;
                goto out;
        }

        if (tp->autoneg != AUTONEG_ENABLE) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE requires autoneg\n");
                rc = -EINVAL;
                goto out;
        }

        /*
        if (edata->tx_lpi_enabled) {
        if (edata->tx_lpi_timer > tp->max_jumbo_frame_size ||
            edata->tx_lpi_timer < ETH_MIN_MTU) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "Valid LPI timer range is %d to %d. \n",
                           ETH_MIN_MTU, tp->max_jumbo_frame_size);
                rc = -EINVAL;
                goto out;
        }
        }
        */

        advertising = tp->advertising;
        if (!edata->advertised) {
                edata->advertised = advertising & eee->supported;
        } else if (edata->advertised & ~advertising) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised %x must be a subset of autoneg advertised speeds %llu\n",
                           edata->advertised, advertising);
                rc = -EINVAL;
                goto out;
        }

        if (edata->advertised & ~eee->supported) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised %x must be a subset of support %x\n",
                           edata->advertised, eee->supported);
                rc = -EINVAL;
                goto out;
        }

        //tp->eee.eee_enabled = edata->eee_enabled;
        //tp->eee_adv_t = rtl8125_ethtool_adv_to_mmd_eee_adv_cap1_t(edata->advertised);

        eee->advertised = edata->advertised;
        //eee->tx_lpi_enabled = edata->tx_lpi_enabled;
        //eee->tx_lpi_timer = edata->tx_lpi_timer;
        eee->eee_enabled = edata->eee_enabled;

        if (eee->eee_enabled)
                rtl8125_enable_eee(tp);
        else
                rtl8125_disable_eee(tp);

        rtl_nway_reset(net);

out:
        r8125_spin_unlock(&tp->phy_lock, flags);

        return rc;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0) */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
static void rtl8125_get_channels(struct net_device *dev,
                                 struct ethtool_channels *channel)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        channel->max_rx = tp->HwSuppNumRxQueues;
        channel->max_tx = tp->HwSuppNumTxQueues;
        channel->rx_count = tp->num_rx_rings;
        channel->tx_count = tp->num_tx_rings;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static const struct ethtool_ops rtl8125_ethtool_ops = {
        .get_drvinfo        = rtl8125_get_drvinfo,
        .get_regs_len       = rtl8125_get_regs_len,
        .get_link       = ethtool_op_get_link,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        .get_ringparam      = rtl8125_get_ringparam,
        .set_ringparam      = rtl8125_set_ringparam,
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        .get_settings       = rtl8125_get_settings,
        .set_settings       = rtl8125_set_settings,
#else
        .get_link_ksettings       = rtl8125_get_settings,
        .set_link_ksettings       = rtl8125_set_settings,
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        .get_pauseparam     = rtl8125_get_pauseparam,
        .set_pauseparam     = rtl8125_set_pauseparam,
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        .get_msglevel       = rtl8125_get_msglevel,
        .set_msglevel       = rtl8125_set_msglevel,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
        .get_rx_csum        = rtl8125_get_rx_csum,
        .set_rx_csum        = rtl8125_set_rx_csum,
        .get_tx_csum        = rtl8125_get_tx_csum,
        .set_tx_csum        = rtl8125_set_tx_csum,
        .get_sg         = ethtool_op_get_sg,
        .set_sg         = ethtool_op_set_sg,
#ifdef NETIF_F_TSO
        .get_tso        = ethtool_op_get_tso,
        .set_tso        = ethtool_op_set_tso,
#endif //NETIF_F_TSO
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
        .get_regs       = rtl8125_get_regs,
        .get_wol        = rtl8125_get_wol,
        .set_wol        = rtl8125_set_wol,
        .get_strings        = rtl8125_get_strings,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
        .get_stats_count    = rtl8125_get_stats_count,
#else
        .get_sset_count     = rtl8125_get_sset_count,
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
        .get_ethtool_stats  = rtl8125_get_ethtool_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#ifdef ETHTOOL_GPERMADDR
        .get_perm_addr      = ethtool_op_get_perm_addr,
#endif //ETHTOOL_GPERMADDR
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        .get_eeprom     = rtl_get_eeprom,
        .get_eeprom_len     = rtl_get_eeprom_len,
#ifdef ENABLE_RSS_SUPPORT
        .get_rxnfc		= rtl8125_get_rxnfc,
        .set_rxnfc		= rtl8125_set_rxnfc,
        .get_rxfh_indir_size	= rtl8125_rss_indir_size,
        .get_rxfh_key_size	= rtl8125_get_rxfh_key_size,
        .get_rxfh		= rtl8125_get_rxfh,
        .set_rxfh		= rtl8125_set_rxfh,
#endif //ENABLE_RSS_SUPPORT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#ifdef ENABLE_PTP_SUPPORT
        .get_ts_info        = rtl8125_get_ts_info,
#else
        .get_ts_info        = ethtool_op_get_ts_info,
#endif //ENABLE_PTP_SUPPORT
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        .get_eee = rtl_ethtool_get_eee,
        .set_eee = rtl_ethtool_set_eee,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
        .get_channels		= rtl8125_get_channels,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) */
        .nway_reset = rtl_nway_reset,

};
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static void rtl8125_get_mac_version(struct rtl8125_private *tp)
{
        u32 reg,val32;
        u32 ICVerID;
        struct pci_dev *pdev = tp->pci_dev;

        val32 = RTL_R32(tp, TxConfig);
        reg = val32 & 0x7c800000;
        ICVerID = val32 & 0x00700000;

        switch (reg) {
        case 0x60800000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_2;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_3;
                } else {
                        tp->mcfg = CFG_METHOD_3;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        case 0x64000000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_4;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_5;
                } else {
                        tp->mcfg = CFG_METHOD_5;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        case 0x68000000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_8;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_9;
                } else {
                        tp->mcfg = CFG_METHOD_9;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        case 0x68800000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_10;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_11;
                } else {
                        tp->mcfg = CFG_METHOD_11;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        case 0x70800000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_12;
                } else {
                        tp->mcfg = CFG_METHOD_12;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        default:
                printk("unknown chip version (%x)\n",reg);
                tp->mcfg = CFG_METHOD_DEFAULT;
                tp->HwIcVerUnknown = TRUE;
                tp->efuse_ver = EFUSE_NOT_SUPPORT;
                break;
        }

        if (pdev->device == 0x8162) {
                if (tp->mcfg == CFG_METHOD_3)
                        tp->mcfg = CFG_METHOD_6;
                else if (tp->mcfg == CFG_METHOD_5)
                        tp->mcfg = CFG_METHOD_7;
                else if (tp->mcfg == CFG_METHOD_11)
                        tp->mcfg = CFG_METHOD_13;
        }
}

static void
rtl8125_print_mac_version(struct rtl8125_private *tp)
{
        int i;
        for (i = ARRAY_SIZE(rtl_chip_info) - 1; i >= 0; i--) {
                if (tp->mcfg == rtl_chip_info[i].mcfg) {
                        dprintk("Realtek %s Ethernet controller mcfg = %04d\n",
                                MODULENAME, rtl_chip_info[i].mcfg);
                        return;
                }
        }

        dprintk("mac_version == Unknown\n");
}

static void
rtl8125_tally_counter_addr_fill(struct rtl8125_private *tp)
{
        if (!tp->tally_paddr)
                return;

        RTL_W32(tp, CounterAddrHigh, (u64)tp->tally_paddr >> 32);
        RTL_W32(tp, CounterAddrLow, (u64)tp->tally_paddr & (DMA_BIT_MASK(32)));
}

static void
rtl8125_tally_counter_clear(struct rtl8125_private *tp)
{
        if (!tp->tally_paddr)
                return;

        RTL_W32(tp, CounterAddrHigh, (u64)tp->tally_paddr >> 32);
        RTL_W32(tp, CounterAddrLow, ((u64)tp->tally_paddr & (DMA_BIT_MASK(32))) | CounterReset);
}

static void
rtl8125_clear_phy_ups_reg(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xA466, BIT_0);
                break;
        };
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA468, BIT_3 | BIT_1);
}

static int
rtl8125_is_ups_resume(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        return (rtl8125_mac_ocp_read(tp, 0xD42C) & BIT_8);
}

static void
rtl8125_clear_ups_resume_bit(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_clear_mac_ocp_bit(tp, 0xD42C, BIT_8);
}

static u8
rtl8125_get_phy_state(struct rtl8125_private *tp)
{
        return (rtl8125_mdio_direct_read_phy_ocp(tp, 0xA420) & 0x7);
}

static bool
rtl8125_wait_phy_state_ready(struct rtl8125_private *tp, u16 state,
                             u32 ms)
{
        u16 tmp_state;
        u32 wait_cnt;
        bool ready;
        u32 i;

        if (ms >= 1000)
                wait_cnt = ms / 1000;
        else
                wait_cnt = 100;

        i = 0;
        do {
                tmp_state = rtl8125_get_phy_state(tp);
                mdelay(1);
                i++;
        } while ((i < wait_cnt) && (tmp_state != state));

        ready = (i == wait_cnt && tmp_state != state) ? FALSE : TRUE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(i == wait_cnt);
#endif
        return ready;
}

static void
rtl8125_wait_phy_ups_resume(struct net_device *dev, u16 PhyState)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        for (i=0; i< 100; i++) {
                if (rtl8125_get_phy_state(tp) == PhyState)
                        break;
                else
                        mdelay(1);
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(i == 100);
#endif
}

static void
rtl8125_set_mcu_d3_stack(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                rtl8125_mac_ocp_write(tp, 0xD018, 0xD116);
                rtl8125_mac_ocp_write(tp, 0xD116, 0x45E0);
                break;
        case CFG_METHOD_9:
                rtl8125_mac_ocp_write(tp, 0xD018, 0xD116);
                rtl8125_mac_ocp_write(tp, 0xD116, 0x4782);
                break;
        case CFG_METHOD_10:
                rtl8125_mac_ocp_write(tp, 0xD018, 0xD116);
                rtl8125_mac_ocp_write(tp, 0xD116, 0x4836);
                break;
        case CFG_METHOD_11:
                rtl8125_mac_ocp_write(tp, 0xD018, 0xD116);
                rtl8125_mac_ocp_write(tp, 0xD116, 0x4848);
                break;
        case CFG_METHOD_12:
                rtl8125_mac_ocp_write(tp, 0xD018, 0xD116);
                rtl8125_mac_ocp_write(tp, 0xD116, 0x4C76);
                break;
        default:
                return;
        }
}

static void
_rtl8125_enable_now_is_oob(struct rtl8125_private *tp)
{
        if (tp->HwSuppNowIsOobVer == 1)
                RTL_W8(tp, MCUCmd_reg, RTL_R8(tp, MCUCmd_reg) | Now_is_oob);
}

void
rtl8125_enable_now_is_oob(struct rtl8125_private *tp)
{
        rtl8125_set_mcu_d3_stack(tp);
        _rtl8125_enable_now_is_oob(tp);
}

void
rtl8125_disable_now_is_oob(struct rtl8125_private *tp)
{
        if (tp->HwSuppNowIsOobVer == 1)
                RTL_W8(tp, MCUCmd_reg, RTL_R8(tp, MCUCmd_reg) & ~Now_is_oob);
}

static void
rtl8125_exit_oob(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 data16;

        rtl8125_disable_rx_packet_filter(tp);

        if (HW_DASH_SUPPORT_DASH(tp))
                rtl8125_driver_start(tp);

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_realwow_hw_init(dev);
#else
        //Disable realwow  function
        rtl8125_mac_ocp_write(tp, 0xC0BC, 0x00FF);
#endif //ENABLE_REALWOW_SUPPORT

        rtl8125_nic_reset(dev);

        rtl8125_disable_now_is_oob(tp);

        data16 = rtl8125_mac_ocp_read(tp, 0xE8DE) & ~BIT_14;
        rtl8125_mac_ocp_write(tp, 0xE8DE, data16);
        rtl8125_wait_ll_share_fifo_ready(dev);

        rtl8125_mac_ocp_write(tp, 0xC0AA, 0x07D0);
#ifdef ENABLE_LIB_SUPPORT
        rtl8125_mac_ocp_write(tp, 0xC0A6, 0x04E2);
#else
        rtl8125_mac_ocp_write(tp, 0xC0A6, 0x01B5);
#endif
        rtl8125_mac_ocp_write(tp, 0xC01E, 0x5555);

        rtl8125_wait_ll_share_fifo_ready(dev);

        //wait ups resume (phy state 2)
        if (rtl8125_is_ups_resume(dev)) {
                rtl8125_wait_phy_ups_resume(dev, 2);
                rtl8125_clear_ups_resume_bit(dev);
                rtl8125_clear_phy_ups_reg(dev);
        }
}

void
rtl8125_hw_disable_mac_mcu_bps(struct net_device *dev)
{
        u16 regAddr;

        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_enable_aspm_clkreq_lock(tp, 0);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x0000);

        for (regAddr = 0xFC28; regAddr < 0xFC48; regAddr += 2) {
                rtl8125_mac_ocp_write(tp, regAddr, 0x0000);
        }

        fsleep(3000);

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x0000);
}

#ifndef ENABLE_USE_FIRMWARE_FILE
static void
rtl8125_switch_mac_mcu_ram_code_page(struct rtl8125_private *tp, u16 page)
{
        u16 tmpUshort;

        page &= (BIT_1 | BIT_0);
        tmpUshort = rtl8125_mac_ocp_read(tp, 0xE446);
        tmpUshort &= ~(BIT_1 | BIT_0);
        tmpUshort |= page;
        rtl8125_mac_ocp_write(tp, 0xE446, tmpUshort);
}

static void
_rtl8125_set_hw_mcu_patch_code_ver(struct rtl8125_private *tp, u64 ver)
{
        int i;

        /* Switch to page 2 */
        rtl8125_switch_mac_mcu_ram_code_page(tp, 2);

        for (i = 0; i < 8; i += 2) {
                rtl8125_mac_ocp_write(tp, 0xF9F8 + 6 - i, (u16)ver);
                ver >>= 16;
        }

        /* Switch back to page 0 */
        rtl8125_switch_mac_mcu_ram_code_page(tp, 0);
}

static void
rtl8125_set_hw_mcu_patch_code_ver(struct rtl8125_private *tp, u64 ver)
{
        _rtl8125_set_hw_mcu_patch_code_ver(tp, ver);

        tp->hw_mcu_patch_code_ver = ver;
}

static u64
rtl8125_get_hw_mcu_patch_code_ver(struct rtl8125_private *tp)
{
        u64 ver;
        int i;

        /* Switch to page 2 */
        rtl8125_switch_mac_mcu_ram_code_page(tp, 2);

        ver = 0;
        for (i = 0; i < 8; i += 2) {
                ver <<= 16;
                ver |= rtl8125_mac_ocp_read(tp, 0xF9F8 + i);
        }

        /* Switch back to page 0 */
        rtl8125_switch_mac_mcu_ram_code_page(tp, 0);

        return ver;
}

static u64
rtl8125_get_bin_mcu_patch_code_ver(const u16 *entry, u16 entry_cnt)
{
        u64 ver;
        int i;

        if (entry == NULL || entry_cnt == 0 || entry_cnt < 4)
                return 0;

        ver = 0;
        for (i = 0; i < 4; i++) {
                ver <<= 16;
                ver |= entry[entry_cnt - 4 + i];
        }

        return ver;
}

static void
_rtl8125_write_mac_mcu_ram_code(struct rtl8125_private *tp, const u16 *entry, u16 entry_cnt)
{
        u16 i;

        for (i = 0; i < entry_cnt; i++)
                rtl8125_mac_ocp_write(tp, 0xF800 + i * 2, entry[i]);
}

static void
_rtl8125_write_mac_mcu_ram_code_with_page(struct rtl8125_private *tp, const u16 *entry, u16 entry_cnt, u16 page_size)
{
        u16 i;
        u16 offset;

        if (page_size == 0)
                return;

        for (i = 0; i < entry_cnt; i++) {
                offset = i % page_size;
                if (offset == 0) {
                        u16 page = (i / page_size);
                        rtl8125_switch_mac_mcu_ram_code_page(tp, page);
                }
                rtl8125_mac_ocp_write(tp, 0xF800 + offset * 2, entry[i]);
        }
}

static void
rtl8125_write_mac_mcu_ram_code(struct rtl8125_private *tp, const u16 *entry, u16 entry_cnt)
{
        if (FALSE == HW_SUPPORT_MAC_MCU(tp))
                return;

        if (entry == NULL || entry_cnt == 0)
                return;

        if (tp->MacMcuPageSize > 0)
                _rtl8125_write_mac_mcu_ram_code_with_page(tp, entry, entry_cnt, tp->MacMcuPageSize);
        else
                _rtl8125_write_mac_mcu_ram_code(tp, entry, entry_cnt);

        if (tp->bin_mcu_patch_code_ver > 0)
                rtl8125_set_hw_mcu_patch_code_ver(tp, tp->bin_mcu_patch_code_ver);
}

static void
rtl8125_set_mac_mcu_8125a_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE062, 0xE072, 0xE074, 0xE079, 0xE07B, 0xE0E4, 0xE0ED, 0xE0EF,
                0xE0FA, 0xE105, 0xE116, 0xE11C, 0xE121, 0xE126, 0xE12A, 0xB400, 0xB401,
                0xB402, 0xB403, 0xB404, 0xB405, 0xC03F, 0x7206, 0x49AE, 0xF1FE, 0xC13C,
                0x9904, 0xC13B, 0x9906, 0x7206, 0x49AE, 0xF1FE, 0x7200, 0x49A0, 0xF10D,
                0xC534, 0xC133, 0xC238, 0xC338, 0xE817, 0xC337, 0xE815, 0xC336, 0xE813,
                0xC335, 0xE811, 0xE01B, 0xC129, 0xC22D, 0xC528, 0xC32C, 0xE80B, 0xC526,
                0xC32A, 0xE808, 0xC524, 0xC328, 0xE805, 0xC522, 0xC326, 0xE802, 0xE00C,
                0x740E, 0x49CE, 0xF1FE, 0x9908, 0x9D0A, 0x9A0C, 0x9B0E, 0x740E, 0x49CE,
                0xF1FE, 0xFF80, 0xB005, 0xB004, 0xB003, 0xB002, 0xB001, 0xB000, 0xC604,
                0xC002, 0xB800, 0x3044, 0xE000, 0xE8E0, 0xF128, 0x0002, 0xFFFF, 0x10EC,
                0x816A, 0x816F, 0x8164, 0x816D, 0xF000, 0x8001, 0x8002, 0x8003, 0x8004,
                0xC60F, 0x73C4, 0x49B3, 0xF106, 0x73C2, 0xC608, 0xB406, 0xC609, 0xFF80,
                0xC605, 0xB406, 0xC605, 0xFF80, 0x0544, 0x0568, 0xE906, 0xCDE8, 0xC602,
                0xBE00, 0x0000, 0x48C1, 0x48C2, 0x9C46, 0xC402, 0xBC00, 0x0A12, 0xC602,
                0xBE00, 0x0EBA, 0x1501, 0xF02A, 0x1500, 0xF15D, 0xC661, 0x75C8, 0x49D5,
                0xF00A, 0x49D6, 0xF008, 0x49D7, 0xF006, 0x49D8, 0xF004, 0x75D2, 0x49D9,
                0xF150, 0xC553, 0x77A0, 0x75C8, 0x4855, 0x4856, 0x4857, 0x4858, 0x48DA,
                0x48DB, 0x49FE, 0xF002, 0x485A, 0x49FF, 0xF002, 0x485B, 0x9DC8, 0x75D2,
                0x4859, 0x9DD2, 0xC643, 0x75C0, 0x49D4, 0xF033, 0x49D1, 0xF137, 0xE030,
                0xC63A, 0x75C8, 0x49D5, 0xF00E, 0x49D6, 0xF00C, 0x49D7, 0xF00A, 0x49D8,
                0xF008, 0x75D2, 0x49D9, 0xF005, 0xC62E, 0x75C0, 0x49D7, 0xF125, 0xC528,
                0x77A0, 0xC627, 0x75C8, 0x4855, 0x4856, 0x4857, 0x4858, 0x48DA, 0x48DB,
                0x49FE, 0xF002, 0x485A, 0x49FF, 0xF002, 0x485B, 0x9DC8, 0x75D2, 0x4859,
                0x9DD2, 0xC616, 0x75C0, 0x4857, 0x9DC0, 0xC613, 0x75C0, 0x49DA, 0xF003,
                0x49D1, 0xF107, 0xC60B, 0xC50E, 0x48D9, 0x9DC0, 0x4859, 0x9DC0, 0xC608,
                0xC702, 0xBF00, 0x3AE0, 0xE860, 0xB400, 0xB5D4, 0xE908, 0xE86C, 0x1200,
                0xC409, 0x6780, 0x48F1, 0x8F80, 0xC404, 0xC602, 0xBE00, 0x10AA, 0xC010,
                0xEA7C, 0xC602, 0xBE00, 0x0000, 0x740A, 0x4846, 0x4847, 0x9C0A, 0xC607,
                0x74C0, 0x48C6, 0x9CC0, 0xC602, 0xBE00, 0x13FE, 0xE054, 0x72CA, 0x4826,
                0x4827, 0x9ACA, 0xC607, 0x72C0, 0x48A6, 0x9AC0, 0xC602, 0xBE00, 0x07DC,
                0xE054, 0xC60F, 0x74C4, 0x49CC, 0xF109, 0xC60C, 0x74CA, 0x48C7, 0x9CCA,
                0xC609, 0x74C0, 0x4846, 0x9CC0, 0xC602, 0xBE00, 0x2480, 0xE092, 0xE0C0,
                0xE054, 0x7420, 0x48C0, 0x9C20, 0x7444, 0xC602, 0xBE00, 0x12F8, 0x1BFF,
                0x46EB, 0x1BFF, 0xC102, 0xB900, 0x0D5A, 0x1BFF, 0x46EB, 0x1BFF, 0xC102,
                0xB900, 0x0E2A, 0xC104, 0xC202, 0xBA00, 0x21DE, 0xD116, 0xC602, 0xBE00,
                0x0000, 0x6486, 0x0119, 0x0606, 0x1327
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC2A, 0x0540);
        rtl8125_mac_ocp_write(tp, 0xFC2E, 0x0A06);
        rtl8125_mac_ocp_write(tp, 0xFC30, 0x0EB8);
        rtl8125_mac_ocp_write(tp, 0xFC32, 0x3A5C);
        rtl8125_mac_ocp_write(tp, 0xFC34, 0x10A8);
        rtl8125_mac_ocp_write(tp, 0xFC40, 0x0D54);
        rtl8125_mac_ocp_write(tp, 0xFC42, 0x0E24);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x307A);
}

static void
rtl8125_set_mac_mcu_8125b_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE01B, 0xE026, 0xE037, 0xE03D, 0xE057, 0xE05B, 0xE060, 0xE0B6,
                0xE103, 0xE14C, 0xE150, 0xE153, 0xE156, 0xE158, 0xE15A, 0x740A, 0x4846,
                0x4847, 0x9C0A, 0xC607, 0x74C0, 0x48C6, 0x9CC0, 0xC602, 0xBE00, 0x13F0,
                0xE054, 0x72CA, 0x4826, 0x4827, 0x9ACA, 0xC607, 0x72C0, 0x48A6, 0x9AC0,
                0xC602, 0xBE00, 0x081C, 0xE054, 0xC60F, 0x74C4, 0x49CC, 0xF109, 0xC60C,
                0x74CA, 0x48C7, 0x9CCA, 0xC609, 0x74C0, 0x4846, 0x9CC0, 0xC602, 0xBE00,
                0x2494, 0xE092, 0xE0C0, 0xE054, 0x7420, 0x48C0, 0x9C20, 0x7444, 0xC602,
                0xBE00, 0x12DC, 0x733A, 0x21B5, 0x25BC, 0x1304, 0xF111, 0x1B12, 0x1D2A,
                0x3168, 0x3ADA, 0x31AB, 0x1A00, 0x9AC0, 0x1300, 0xF1FB, 0x7620, 0x236E,
                0x276F, 0x1A3C, 0x22A1, 0x41B5, 0x9EE2, 0x76E4, 0x486F, 0x9EE4, 0xC602,
                0xBE00, 0x4A26, 0x733A, 0x49BB, 0xC602, 0xBE00, 0x47A2, 0x48C1, 0x48C2,
                0x9C46, 0xC402, 0xBC00, 0x0A52, 0xC74B, 0x76E2, 0xC54A, 0x402E, 0xF034,
                0x76E0, 0x402E, 0xF006, 0xC703, 0xC403, 0xBC00, 0xC0BC, 0x0980, 0x76F0,
                0x1601, 0xF023, 0xC741, 0x1E04, 0x9EE0, 0x1E40, 0x9EE4, 0xC63D, 0x9EE8,
                0xC73D, 0x76E0, 0x4863, 0x9EE0, 0xC73A, 0x76E0, 0x48EA, 0x48EB, 0x9EE0,
                0xC736, 0x1E01, 0x9EE2, 0xC72D, 0x76E0, 0x486F, 0x9EE0, 0xC72D, 0x76E0,
                0x48E3, 0x9EE0, 0xC728, 0x1E0E, 0x9EE0, 0xC71D, 0x1E01, 0x9EE4, 0xE00D,
                0x1E00, 0x9EF0, 0x1E05, 0xC715, 0x9EE0, 0xE00A, 0x1E00, 0x9EE2, 0xC614,
                0x75CC, 0x48D2, 0x9DCC, 0x1E04, 0xC70B, 0x9EE0, 0xB000, 0xB001, 0xB002,
                0xB003, 0xB004, 0xB005, 0xB006, 0xB007, 0xFFC0, 0xE428, 0xD3C0, 0xBEEF,
                0x473E, 0xDC46, 0xE0CC, 0xE84E, 0xC0A2, 0x0100, 0xC010, 0xE85A, 0xE812,
                0xC0B4, 0xC5F4, 0x74A0, 0xC6F3, 0x4026, 0xF107, 0x74A2, 0xC6EF, 0x4026,
                0xF107, 0xC6ED, 0xBE00, 0x753A, 0xC602, 0xBE00, 0x462E, 0x7520, 0x49DE,
                0xF102, 0xE7F9, 0xC6A1, 0x67C6, 0x7520, 0x22D2, 0x26DD, 0x1500, 0xF002,
                0xE7F1, 0x7532, 0x26D5, 0x0530, 0x0D6C, 0xC42D, 0x308D, 0x7540, 0x4025,
                0xF11E, 0x7542, 0x4025, 0xF11B, 0x7544, 0x4025, 0xF118, 0xC423, 0x7546,
                0x4025, 0xF114, 0x7548, 0x4025, 0xF111, 0x754A, 0x4025, 0xF10E, 0xC5C0,
                0xC4C0, 0x9CA2, 0xC6C0, 0x75CC, 0x4852, 0x9DCC, 0xC6B8, 0x1D7D, 0x9DC2,
                0x1D01, 0x9DC0, 0xE7C9, 0xC40B, 0x7546, 0x4025, 0xF1FC, 0x7548, 0x4025,
                0xF1F9, 0x754A, 0x4025, 0xF1F6, 0xE7C0, 0xFFFF, 0xEEEE, 0xC2A6, 0x7340,
                0xC2A5, 0x4013, 0xF013, 0xC2AC, 0x7340, 0x4835, 0x9B40, 0xC240, 0x7358,
                0x48B7, 0x48B2, 0x9B58, 0x7346, 0x48B7, 0x48B2, 0x9B46, 0x7340, 0x48B7,
                0x48B2, 0x9B40, 0xE012, 0xC29A, 0x7340, 0x48B5, 0x9B40, 0xC22E, 0x7358,
                0x4837, 0x4832, 0x9B58, 0x7346, 0x4837, 0x4832, 0x9B46, 0x7340, 0x4837,
                0x4832, 0x9B40, 0xC283, 0x7340, 0x49BF, 0xF010, 0xC21B, 0x7344, 0x1300,
                0xF104, 0x1B00, 0xC217, 0x9B40, 0x1B01, 0xC213, 0x9B44, 0xC213, 0x734C,
                0x48B7, 0x9B4C, 0xE008, 0xC20C, 0x1B00, 0x9B44, 0xC20B, 0x734C, 0x4837,
                0x9B4C, 0xC204, 0xC302, 0xBB00, 0x2230, 0xE092, 0xD3C0, 0xE428, 0xDC46,
                0xC104, 0xC202, 0xBA00, 0x21F8, 0xD116, 0x49D1, 0xC602, 0xBE00, 0x3E7A,
                0x49D1, 0xC602, 0xBE00, 0x3EDA, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00,
                0x0000, 0xC602, 0xBE00, 0x0000, 0x6637, 0x0119, 0x0604, 0x1203
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x13E6);
        rtl8125_mac_ocp_write(tp, 0xFC2A, 0x0812);
        rtl8125_mac_ocp_write(tp, 0xFC2C, 0x248C);
        rtl8125_mac_ocp_write(tp, 0xFC2E, 0x12DA);
        rtl8125_mac_ocp_write(tp, 0xFC30, 0x4A20);
        rtl8125_mac_ocp_write(tp, 0xFC32, 0x47A0);
        //rtl8125_mac_ocp_write(tp, 0xFC34, 0x0A46);
        //rtl8125_mac_ocp_write(tp, 0xFC36, 0x097E);
        //rtl8125_mac_ocp_write(tp, 0xFC38, 0x462C);
        //rtl8125_mac_ocp_write(tp, 0xFC3A, 0x222E);
        rtl8125_mac_ocp_write(tp, 0xFC3C, 0x21F6);
        rtl8125_mac_ocp_write(tp, 0xFC3E, 0x3E78);
        rtl8125_mac_ocp_write(tp, 0xFC40, 0x3ED8);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x1C7B);
}

static void
rtl8125_set_mac_mcu_8125bp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE014, 0xE027, 0xE04A, 0xE04D, 0xE050, 0xE052, 0xE054, 0xE056,
                0xE058, 0xE05A, 0xE05C, 0xE05E, 0xE060, 0xE062, 0xE064, 0x1BC8, 0x46EB,
                0xC302, 0xBB00, 0x0F14, 0xC211, 0x400A, 0xF00A, 0xC20F, 0x400A, 0xF007,
                0x73A4, 0xC20C, 0x400A, 0xF102, 0x48B0, 0x9B20, 0x1B00, 0x9BA0, 0xC602,
                0xBE00, 0x4364, 0xE6E0, 0xE6E2, 0xC01C, 0xB406, 0x1000, 0xF016, 0xC61F,
                0x400E, 0xF012, 0x218E, 0x25BE, 0x1300, 0xF007, 0x7340, 0xC618, 0x400E,
                0xF102, 0x48B0, 0x8320, 0xB400, 0x2402, 0x1000, 0xF003, 0x7342, 0x8322,
                0xB000, 0xE007, 0x7322, 0x9B42, 0x7320, 0x9B40, 0x0300, 0x0300, 0xB006,
                0xC302, 0xBB00, 0x413E, 0xE6E0, 0xC01C, 0x49D1, 0xC602, 0xBE00, 0x3F94,
                0x49D1, 0xC602, 0xBE00, 0x4030, 0xC602, 0xBE00, 0x3FDA, 0xC102, 0xB900,
                0x401A, 0xC102, 0xB900, 0x0000, 0xC002, 0xB800, 0x0000, 0xC602, 0xBE00,
                0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00,
                0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00,
                0x0000, 0x6936, 0x0A18, 0x0C02, 0x0D21
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x0f10);
        rtl8125_mac_ocp_write(tp, 0xFC2A, 0x435c);
        rtl8125_mac_ocp_write(tp, 0xFC2C, 0x4112);
        rtl8125_mac_ocp_write(tp, 0xFC2E, 0x3F92);
        rtl8125_mac_ocp_write(tp, 0xFC30, 0x402E);
        rtl8125_mac_ocp_write(tp, 0xFC32, 0x3FD6);
        rtl8125_mac_ocp_write(tp, 0xFC34, 0x4018);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x007F);
}

static void
rtl8125_set_mac_mcu_8125bp_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE033, 0xE046, 0xE04A, 0xE04D, 0xE050, 0xE054, 0xE056, 0xE058,
                0xE05A, 0xE05C, 0xE05E, 0xE060, 0xE062, 0xE064, 0xE066, 0xB406, 0x1000,
                0xF016, 0xC61F, 0x400E, 0xF012, 0x218E, 0x25BE, 0x1300, 0xF007, 0x7340,
                0xC618, 0x400E, 0xF102, 0x48B0, 0x8320, 0xB400, 0x2402, 0x1000, 0xF003,
                0x7342, 0x8322, 0xB000, 0xE007, 0x7322, 0x9B42, 0x7320, 0x9B40, 0x0300,
                0x0300, 0xB006, 0xC302, 0xBB00, 0x4168, 0xE6E0, 0xC01C, 0xC211, 0x400A,
                0xF00A, 0xC20F, 0x400A, 0xF007, 0x73A4, 0xC20C, 0x400A, 0xF102, 0x48B0,
                0x9B20, 0x1B00, 0x9BA0, 0xC602, 0xBE00, 0x4392, 0xE6E0, 0xE6E2, 0xC01C,
                0x4166, 0x9CF6, 0xC002, 0xB800, 0x143C, 0x49D1, 0xC602, 0xBE00, 0x3FC4,
                0x49D1, 0xC602, 0xBE00, 0x405A, 0xC104, 0xC202, 0xBA00, 0x22E6, 0xD116,
                0xC602, 0xBE00, 0x0000, 0xC102, 0xB900, 0x0000, 0xC002, 0xB800, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0x6936, 0x0119, 0x030E, 0x0B18
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x413C);
        rtl8125_mac_ocp_write(tp, 0xFC2A, 0x438A);
        rtl8125_mac_ocp_write(tp, 0xFC2C, 0x143A);
        rtl8125_mac_ocp_write(tp, 0xFC2E, 0x3FC2);
        rtl8125_mac_ocp_write(tp, 0xFC30, 0x4058);
        rtl8125_mac_ocp_write(tp, 0xFC32, 0x22E4);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x003F);
}

static void
rtl8125_set_mac_mcu_8125d_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE014, 0xE018, 0xE01A, 0xE01C, 0xE01E, 0xE020, 0xE022, 0xE024,
                0xE026, 0xE028, 0xE02A, 0xE02C, 0xE02E, 0xE030, 0xE032, 0x4166, 0x9CF6,
                0xC002, 0xB800, 0x14A4, 0xC104, 0xC202, 0xBA00, 0x2378, 0xD116, 0xC602,
                0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602,
                0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602,
                0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602,
                0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602,
                0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x6938,
                0x0A19, 0x030E, 0x0B2B
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x14A2);
        rtl8125_mac_ocp_write(tp, 0xFC2A, 0x2376);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x0003);
}

static void
rtl8125_set_mac_mcu_8125d_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE014, 0xE016, 0xE018, 0xE01A, 0xE01C, 0xE01E, 0xE020, 0xE022,
                0xE024, 0xE026, 0xE028, 0xE02A, 0xE02C, 0xE02E, 0xE030, 0xC104, 0xC202,
                0xBA00, 0x2384, 0xD116, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x6938,
                0x0A19, 0x030E, 0x0B2F
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x2382);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x0001);
}


static void
rtl8125_set_mac_mcu_8125cp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        static const u16 mcu_patch_code[] = {
                0xE010, 0xE014, 0xE016, 0xE018, 0xE01A, 0xE01C, 0xE01E, 0xE020, 0xE022,
                0xE024, 0xE026, 0xE028, 0xE02A, 0xE02C, 0xE02E, 0xE030, 0xC104, 0xC202,
                0xBA00, 0x2438, 0xD116, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000, 0xC602, 0xBE00, 0x0000,
                0xC602, 0xBE00, 0x0000, 0x7023, 0x0019, 0x031A, 0x0E20
        };

        /* Get BIN mac mcu patch code version */
        tp->bin_mcu_patch_code_ver = rtl8125_get_bin_mcu_patch_code_ver(mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        if (tp->hw_mcu_patch_code_ver != tp->bin_mcu_patch_code_ver)
                rtl8125_write_mac_mcu_ram_code(tp, mcu_patch_code, ARRAY_SIZE(mcu_patch_code));

        rtl8125_mac_ocp_write(tp, 0xFC26, 0x8000);

        rtl8125_mac_ocp_write(tp, 0xFC28, 0x2436);

        rtl8125_mac_ocp_write(tp, 0xFC48, 0x0001);
}

static void
rtl8125_hw_mac_mcu_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->NotWrMcuPatchCode == TRUE)
                return;

        rtl8125_hw_disable_mac_mcu_bps(dev);

        /* Get H/W mac mcu patch code version */
        tp->hw_mcu_patch_code_ver = rtl8125_get_hw_mcu_patch_code_ver(tp);

        switch (tp->mcfg) {
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_set_mac_mcu_8125a_2(dev);
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                rtl8125_set_mac_mcu_8125b_2(dev);
                break;
        case CFG_METHOD_8:
                rtl8125_set_mac_mcu_8125bp_1(dev);
                break;
        case CFG_METHOD_9:
                rtl8125_set_mac_mcu_8125bp_2(dev);
                break;
        case CFG_METHOD_10:
                rtl8125_set_mac_mcu_8125d_1(dev);
                break;
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                rtl8125_set_mac_mcu_8125d_2(dev);
                break;
        case CFG_METHOD_12:
                rtl8125_set_mac_mcu_8125cp_1(dev);
                break;
        case CFG_METHOD_2:
        case CFG_METHOD_4:
                /* no mac mcu patch code */
                break;
        default:
                break;
        }
}
#endif

#ifdef ENABLE_USE_FIRMWARE_FILE
static void rtl8125_release_firmware(struct rtl8125_private *tp)
{
        if (tp->rtl_fw) {
                rtl8125_fw_release_firmware(tp->rtl_fw);
                kfree(tp->rtl_fw);
                tp->rtl_fw = NULL;
        }
}

static void rtl8125_apply_firmware(struct rtl8125_private *tp)
{
        unsigned long flags;

        /* TODO: release firmware if rtl_fw_write_firmware signals failure. */
        if (tp->rtl_fw) {
                r8125_spin_lock(&tp->phy_lock, flags);

                rtl8125_fw_write_firmware(tp, tp->rtl_fw);
                /* At least one firmware doesn't reset tp->ocp_base. */
                tp->ocp_base = OCP_STD_PHY_BASE;

                /* PHY soft reset may still be in progress */
                //phy_read_poll_timeout(tp->phydev, MII_BMCR, val,
                //		      !(val & BMCR_RESET),
                //		      50000, 600000, true);
                rtl8125_wait_phy_reset_complete(tp);

                tp->hw_ram_code_ver = rtl8125_get_hw_phy_mcu_code_ver(tp);
                tp->sw_ram_code_ver = tp->hw_ram_code_ver;
                tp->HwHasWrRamCodeToMicroP = TRUE;

                r8125_spin_unlock(&tp->phy_lock, flags);
        }
}
#endif

static void
rtl8125_hw_init(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 csi_tmp;

        rtl8125_enable_aspm_clkreq_lock(tp, 0);
        rtl8125_enable_force_clkreq(tp, 0);

        rtl8125_set_reg_oobs_en_sel(tp, true);

        //Disable UPS
        rtl8125_mac_ocp_write(tp, 0xD40A, rtl8125_mac_ocp_read(tp, 0xD40A) & ~(BIT_4));

#ifndef ENABLE_USE_FIRMWARE_FILE
        if (!tp->rtl_fw)
                rtl8125_hw_mac_mcu_config(dev);
#endif

        /*disable ocp phy power saving*/
        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6)
                rtl8125_disable_ocp_phy_power_saving(dev);

        //Set PCIE uncorrectable error status mask pcie 0x108
        csi_tmp = rtl8125_csi_read(tp, 0x108);
        csi_tmp |= BIT_20;
        rtl8125_csi_write(tp, 0x108, csi_tmp);

        rtl8125_enable_cfg9346_write(tp);
        rtl8125_disable_linkchg_wakeup(dev);
        rtl8125_disable_cfg9346_write(tp);
        rtl8125_disable_magic_packet(dev);
        rtl8125_disable_d0_speedup(tp);
        rtl8125_set_pci_pme(tp, 0);
        if (s0_magic_packet == 1)
                rtl8125_enable_magic_packet(dev);

#ifdef ENABLE_USE_FIRMWARE_FILE
        if (tp->rtl_fw && !tp->resume_not_chg_speed)
                rtl8125_apply_firmware(tp);
#endif
}

static void
rtl8125_hw_ephy_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_ephy_write(tp, 0x01, 0xA812);
                rtl8125_ephy_write(tp, 0x09, 0x520C);
                rtl8125_ephy_write(tp, 0x04, 0xD000);
                rtl8125_ephy_write(tp, 0x0D, 0xF702);
                rtl8125_ephy_write(tp, 0x0A, 0x8653);
                rtl8125_ephy_write(tp, 0x06, 0x001E);
                rtl8125_ephy_write(tp, 0x08, 0x3595);
                rtl8125_ephy_write(tp, 0x20, 0x9455);
                rtl8125_ephy_write(tp, 0x21, 0x99FF);
                rtl8125_ephy_write(tp, 0x02, 0x6046);
                rtl8125_ephy_write(tp, 0x29, 0xFE00);
                rtl8125_ephy_write(tp, 0x23, 0xAB62);

                rtl8125_ephy_write(tp, 0x41, 0xA80C);
                rtl8125_ephy_write(tp, 0x49, 0x520C);
                rtl8125_ephy_write(tp, 0x44, 0xD000);
                rtl8125_ephy_write(tp, 0x4D, 0xF702);
                rtl8125_ephy_write(tp, 0x4A, 0x8653);
                rtl8125_ephy_write(tp, 0x46, 0x001E);
                rtl8125_ephy_write(tp, 0x48, 0x3595);
                rtl8125_ephy_write(tp, 0x60, 0x9455);
                rtl8125_ephy_write(tp, 0x61, 0x99FF);
                rtl8125_ephy_write(tp, 0x42, 0x6046);
                rtl8125_ephy_write(tp, 0x69, 0xFE00);
                rtl8125_ephy_write(tp, 0x63, 0xAB62);
                break;
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_ephy_write(tp, 0x04, 0xD000);
                rtl8125_ephy_write(tp, 0x0A, 0x8653);
                rtl8125_ephy_write(tp, 0x23, 0xAB66);
                rtl8125_ephy_write(tp, 0x20, 0x9455);
                rtl8125_ephy_write(tp, 0x21, 0x99FF);
                rtl8125_ephy_write(tp, 0x29, 0xFE04);

                rtl8125_ephy_write(tp, 0x44, 0xD000);
                rtl8125_ephy_write(tp, 0x4A, 0x8653);
                rtl8125_ephy_write(tp, 0x63, 0xAB66);
                rtl8125_ephy_write(tp, 0x60, 0x9455);
                rtl8125_ephy_write(tp, 0x61, 0x99FF);
                rtl8125_ephy_write(tp, 0x69, 0xFE04);

                ClearAndSetPCIePhyBit(tp,
                                      0x2A,
                                      (BIT_14 | BIT_13 | BIT_12),
                                      (BIT_13 | BIT_12));
                ClearPCIePhyBit(tp, 0x19, BIT_6);
                SetPCIePhyBit(tp, 0x1B, (BIT_11 | BIT_10 | BIT_9));
                ClearPCIePhyBit(tp, 0x1B, (BIT_14 | BIT_13 | BIT_12));
                rtl8125_ephy_write(tp, 0x02, 0x6042);
                rtl8125_ephy_write(tp, 0x06, 0x0014);

                ClearAndSetPCIePhyBit(tp,
                                      0x6A,
                                      (BIT_14 | BIT_13 | BIT_12),
                                      (BIT_13 | BIT_12));
                ClearPCIePhyBit(tp, 0x59, BIT_6);
                SetPCIePhyBit(tp, 0x5B, (BIT_11 | BIT_10 | BIT_9));
                ClearPCIePhyBit(tp, 0x5B, (BIT_14 | BIT_13 | BIT_12));
                rtl8125_ephy_write(tp, 0x42, 0x6042);
                rtl8125_ephy_write(tp, 0x46, 0x0014);
                break;
        case CFG_METHOD_4:
                rtl8125_ephy_write(tp, 0x06, 0x001F);
                rtl8125_ephy_write(tp, 0x0A, 0xB66B);
                rtl8125_ephy_write(tp, 0x01, 0xA852);
                rtl8125_ephy_write(tp, 0x24, 0x0008);
                rtl8125_ephy_write(tp, 0x2F, 0x6052);
                rtl8125_ephy_write(tp, 0x0D, 0xF716);
                rtl8125_ephy_write(tp, 0x20, 0xD477);
                rtl8125_ephy_write(tp, 0x21, 0x4477);
                rtl8125_ephy_write(tp, 0x22, 0x0013);
                rtl8125_ephy_write(tp, 0x23, 0xBB66);
                rtl8125_ephy_write(tp, 0x0B, 0xA909);
                rtl8125_ephy_write(tp, 0x29, 0xFF04);
                rtl8125_ephy_write(tp, 0x1B, 0x1EA0);

                rtl8125_ephy_write(tp, 0x46, 0x001F);
                rtl8125_ephy_write(tp, 0x4A, 0xB66B);
                rtl8125_ephy_write(tp, 0x41, 0xA84A);
                rtl8125_ephy_write(tp, 0x64, 0x000C);
                rtl8125_ephy_write(tp, 0x6F, 0x604A);
                rtl8125_ephy_write(tp, 0x4D, 0xF716);
                rtl8125_ephy_write(tp, 0x60, 0xD477);
                rtl8125_ephy_write(tp, 0x61, 0x4477);
                rtl8125_ephy_write(tp, 0x62, 0x0013);
                rtl8125_ephy_write(tp, 0x63, 0xBB66);
                rtl8125_ephy_write(tp, 0x4B, 0xA909);
                rtl8125_ephy_write(tp, 0x69, 0xFF04);
                rtl8125_ephy_write(tp, 0x5B, 0x1EA0);
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                rtl8125_ephy_write(tp, 0x0B, 0xA908);
                rtl8125_ephy_write(tp, 0x1E, 0x20EB);
                rtl8125_ephy_write(tp, 0x22, 0x0023);
                rtl8125_ephy_write(tp, 0x02, 0x60C2);
                rtl8125_ephy_write(tp, 0x29, 0xFF00);

                rtl8125_ephy_write(tp, 0x4B, 0xA908);
                rtl8125_ephy_write(tp, 0x5E, 0x28EB);
                rtl8125_ephy_write(tp, 0x62, 0x0023);
                rtl8125_ephy_write(tp, 0x42, 0x60C2);
                rtl8125_ephy_write(tp, 0x69, 0xFF00);
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                /* nothing to do */
                break;
        }
}

static u16
rtl8125_get_hw_phy_mcu_code_ver(struct rtl8125_private *tp)
{
        u16 hw_ram_code_ver;

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x801E);
        hw_ram_code_ver = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA438);

        return hw_ram_code_ver;
}

static int
rtl8125_check_hw_phy_mcu_code_ver(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->hw_ram_code_ver = rtl8125_get_hw_phy_mcu_code_ver(tp);

        if (tp->hw_ram_code_ver == tp->sw_ram_code_ver) {
                tp->HwHasWrRamCodeToMicroP = TRUE;
                return 1;
        } else {
                tp->HwHasWrRamCodeToMicroP = FALSE;
                return 0;
        }
}

bool
rtl8125_set_phy_mcu_patch_request(struct rtl8125_private *tp)
{
        u16 gphy_val;
        u16 WaitCount;
        bool bSuccess = TRUE;

        rtl8125_set_eth_phy_ocp_bit(tp, 0xB820, BIT_4);

        WaitCount = 0;
        do {
                gphy_val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xB800);
                udelay(100);
                WaitCount++;
        } while (!(gphy_val & BIT_6) && (WaitCount < 1000));

        if (!(gphy_val & BIT_6) && (WaitCount == 1000))
                bSuccess = FALSE;

        if (!bSuccess)
                dprintk("rtl8125_set_phy_mcu_patch_request fail.\n");

        return bSuccess;
}

bool
rtl8125_clear_phy_mcu_patch_request(struct rtl8125_private *tp)
{
        u16 gphy_val;
        u16 WaitCount;
        bool bSuccess = TRUE;

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB820, BIT_4);

        WaitCount = 0;
        do {
                gphy_val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xB800);
                udelay(100);
                WaitCount++;
        } while ((gphy_val & BIT_6) && (WaitCount < 1000));

        if ((gphy_val & BIT_6) && (WaitCount == 1000))
                bSuccess = FALSE;

        if (!bSuccess)
                dprintk("rtl8125_clear_phy_mcu_patch_request fail.\n");

        return bSuccess;
}

#ifndef ENABLE_USE_FIRMWARE_FILE
static void
rtl8125_write_hw_phy_mcu_code_ver(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x801E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, tp->sw_ram_code_ver);
        tp->hw_ram_code_ver = tp->sw_ram_code_ver;
}

static void
rtl8125_acquire_phy_mcu_patch_key_lock(struct rtl8125_private *tp)
{
        u16 PatchKey;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                PatchKey = 0x8600;
                break;
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                PatchKey = 0x8601;
                break;
        case CFG_METHOD_4:
                PatchKey = 0x3700;
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                PatchKey = 0x3701;
                break;
        default:
                return;
        }
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, PatchKey);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xB82E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0001);
}

static void
rtl8125_release_phy_mcu_patch_key_lock(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x0000);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xB82E, BIT_0);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8024);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
                break;
        default:
                break;
        }
}

static void
rtl8125_set_phy_mcu_ram_code(struct net_device *dev, const u16 *ramcode, u16 codesize)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 i;
        u16 addr;
        u16 val;

        if (ramcode == NULL || codesize % 2) {
                goto out;
        }

        for (i = 0; i < codesize; i += 2) {
                addr = ramcode[i];
                val = ramcode[i + 1];
                if (addr == 0xFFFF && val == 0xFFFF) {
                        break;
                }
                rtl8125_mdio_direct_write_phy_ocp(tp, addr, val);
        }

out:
        return;
}

static void
rtl8125_enable_phy_disable_mode(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) | BIT_5);
                break;
        }

        dprintk("enable phy disable mode.\n");
}

static void
rtl8125_disable_phy_disable_mode(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) & ~BIT_5);
                break;
        }

        mdelay(1);

        dprintk("disable phy disable mode.\n");
}

static void
rtl8125_set_hw_phy_before_init_phy_mcu(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 PhyRegValue;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xBF86, 0x9000);

                rtl8125_set_eth_phy_ocp_bit(tp, 0xC402, BIT_10);
                rtl8125_clear_eth_phy_ocp_bit(tp, 0xC402, BIT_10);

                PhyRegValue = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBF86);
                PhyRegValue &= (BIT_1 | BIT_0);
                if (PhyRegValue != 0)
                        dprintk("PHY watch dog not clear, value = 0x%x \n", PhyRegValue);

                rtl8125_mdio_direct_write_phy_ocp(tp, 0xBD86, 0x1010);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xBD88, 0x1010);

                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBD4E,
                                                      BIT_11 | BIT_10,
                                                      BIT_11);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBF46,
                                                      BIT_11 | BIT_10 | BIT_9 | BIT_8,
                                                      BIT_10 | BIT_9 | BIT_8);
                break;
        }
}

static void
rtl8125_real_set_phy_mcu_8125a_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_acquire_phy_mcu_patch_key_lock(tp);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xB820, BIT_7);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8013);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8021);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x802f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x803d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8042);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8051);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8051);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa088);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a50);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8008);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1a3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x401a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd707);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40c2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60a6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f8b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a6c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8080);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd019);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1a2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x401a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd707);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40c4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60a6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f8b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a84);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8970);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c07);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0901);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcf09);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd705);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xceff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf0a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1213);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8401);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8580);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1253);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd064);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd181);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4018);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc50f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd706);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2c59);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x804d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc60f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc605);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x10fd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA026);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA022);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x10f4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA020);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1252);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA006);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1206);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA004);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a78);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a60);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a4f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA008);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3f00);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8066);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x807c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8089);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x808e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80b2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80c2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x62db);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x655c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd73e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x614a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0505);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0509);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x653c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd73e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x614a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0502);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0506);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x050a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd73e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x614a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0505);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0506);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x050c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd73e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x614a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0509);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x050a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x050c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0508);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0304);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd73e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x614a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0321);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0502);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0321);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0321);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0508);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0321);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0346);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8208);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x609d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa50f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x001a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x001a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x607d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00ab);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60fd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa50f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaa0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x017b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a05);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x017b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60fd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa50f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaa0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x01e0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a05);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x01e0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60fd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa50f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaa0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0231);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0503);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a05);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0231);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0221);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x01ce);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA088);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0169);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA086);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00a6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA084);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x000d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA082);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0308);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA080);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x029f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA090);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x007f);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0020);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8017);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8029);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8054);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x805a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8064);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80a7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9430);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9480);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb408);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd120);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd057);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x064b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb80);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9906);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0567);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb94);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x82a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x800a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8406);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8dff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0773);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb91);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4063);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd139);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd140);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07dc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa110);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa2a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4045);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa180);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x405d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa720);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0742);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07ec);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f74);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0742);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7fb6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x82a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07dc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x064b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07c0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5fa7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0481);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x94bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x870c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa00a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa280);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8220);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x078e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb92);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4063);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd140);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd150);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd703);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6121);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x61a2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6223);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf02f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d10);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf00f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d20);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf00a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d30);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf005);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d40);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa008);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4046);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x405d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa720);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0742);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07f7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f74);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0742);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7fb5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x800a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3ad4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0537);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x064b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8301);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x800a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x82a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa70c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9402);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x890c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x064b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0642);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0686);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0788);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA108);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x047b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA106);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x065c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA104);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0769);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA102);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0565);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x06f9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA110);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00ff);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb87c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8530);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb87e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf85);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3caf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8593);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf85);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9caf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x85a5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5afb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe083);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfb0c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x020d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x021b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x10bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86d7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbe0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x83fc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1b10);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xda02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xdd02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5afb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe083);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfd0c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x020d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x021b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x10bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86dd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86e0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbe0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x83fe);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1b10);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf2f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbd02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2cac);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0286);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x65af);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x212b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x022c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86b6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf21);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cd1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x03bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8710);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x870d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8719);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8716);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x871f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x871c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8728);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8725);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8707);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbad);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x281c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1302);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2202);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2b02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae1a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd101);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1302);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2202);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2b02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd101);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3402);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3102);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3d02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3a02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4302);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4c02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4902);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2e02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4602);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf87);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4f02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ab7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf35);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7ff8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfaef);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x69bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86e3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86fb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86e6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86fe);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86e9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86ec);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfbbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x025a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7bf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86ef);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0262);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7cbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86f2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0262);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7cbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86f5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0262);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7cbf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x86f8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0262);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7cef);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x96fe);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfc04);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf8fa);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xef69);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xef02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6273);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf202);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6273);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf502);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6273);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbf86);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf802);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6273);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xef96);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfefc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0420);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb540);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x53b5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4086);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb540);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb9b5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40c8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb03a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc8b0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbac8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb13a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc8b1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xba77);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbd26);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffbd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2677);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbd28);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffbd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbd26);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc8bd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2640);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbd28);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc8bd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x28bb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa430);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x98b0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1eba);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb01e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xdcb0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e98);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb09e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbab0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9edc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb09e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x98b1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1eba);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb11e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xdcb1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e98);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb19e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbab1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9edc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb19e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x11b0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e22);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb01e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x33b0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e11);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb09e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x22b0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9e33);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb09e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x11b1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e22);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb11e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x33b1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1e11);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb19e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x22b1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9e33);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb19e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb85e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2f71);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb860);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x20d9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb862);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2109);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb864);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x34e7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb878);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x000f);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB820, BIT_7);


        rtl8125_release_phy_mcu_patch_key_lock(tp);
}

static void
rtl8125_set_phy_mcu_8125a_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125a_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_real_set_phy_mcu_8125a_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_acquire_phy_mcu_patch_key_lock(tp);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xB820, BIT_7);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x808b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x808f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8093);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8097);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x809d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80a1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80aa);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x607b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf00e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x42da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf01e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x615b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1456);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14a4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f2e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf01c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1456);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14a4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f2e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1456);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14a4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f2e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf02c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1456);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14a4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x14bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f2e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf034);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd719);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4118);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac11);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa410);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4779);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1444);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf034);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd719);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4118);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac22);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa420);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4559);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1444);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf023);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd719);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4118);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac44);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa440);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4339);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1444);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd719);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4118);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac88);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa480);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xce00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4119);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xac0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1444);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf001);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1456);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd718);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5fac);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc48f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x141b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd504);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x121a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd0b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1bb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0898);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd0b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1bb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a0e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd064);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd18a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0b7e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x401c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd501);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa804);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8804);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x053b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa301);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0648);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc520);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa201);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x252d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1646);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd708);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4006);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1646);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0308);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA026);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0307);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1645);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA022);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0647);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA020);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x053a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA006);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0b7c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA004);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0a0c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0896);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x11a1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA008);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xff00);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8015);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x801a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xad02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x02d7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00ed);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0509);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xc100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x008f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA08A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA088);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA086);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA084);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA082);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x008d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA080);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00eb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA090);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0103);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA016);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0020);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8014);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8018);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8051);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8055);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8072);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x80dc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfffd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfffd);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8301);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x800a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x82a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa70c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x9402);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x890c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8840);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa380);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x066e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb91);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4063);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd139);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd140);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa110);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa2a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4085);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa180);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8280);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x405d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa720);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0743);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07f0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5f74);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0743);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7fb6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x82a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0c0f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x066e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd158);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd04d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x03d4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x94bc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x870c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8380);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd10d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07c4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5fb4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa190);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa00a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa280);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa404);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa220);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd130);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07c4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5fb4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xbb80);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1c4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd074);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa301);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x604b);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa90c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0556);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xcb92);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4063);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd116);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd119);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd040);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd703);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x60a0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6241);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x63e2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6583);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf054);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x611e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d10);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf02f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d50);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf02a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x611e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d20);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf021);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d60);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf01c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x611e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d30);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf013);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d70);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf00e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x611e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x40da);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d40);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf005);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d80);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x405d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa720);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5ff4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa008);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd704);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4046);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0743);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07fb);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd703);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7f6f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7f4e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7f2d);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7f0c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x800a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0cf0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0d00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07e8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8010);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa740);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0743);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7fb5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd701);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3ad4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0556);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8610);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x066e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd1f5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xd049);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x1800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x01ec);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x01ea);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x06a9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA10A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x078a);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA108);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x03d2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA106);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x067f);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA104);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0665);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA102);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xA110);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00fc);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb87c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8530);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb87e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf85);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x3caf);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8545);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf85);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x45af);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8545);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xee82);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf900);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0103);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xaf03);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb7f8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe0a6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00e1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa601);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xef01);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x58f0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa080);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x37a1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8402);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae16);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa185);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x02ae);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x11a1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8702);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae0c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xa188);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x02ae);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x07a1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8902);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae02);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xae1c);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe0b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x62e1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb463);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6901);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe4b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x62e5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb463);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe0b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x62e1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb463);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6901);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xe4b4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x62e5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xb463);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xfc04);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb85e);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x03b3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb860);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb862);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb864);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xffff);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0xb878);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0001);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB820, BIT_7);


        rtl8125_release_phy_mcu_patch_key_lock(tp);
}

static void
rtl8125_set_phy_mcu_8125a_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125a_2(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static const u16 phy_mcu_ram_code_8125b_1[] = {
        0xa436, 0x8024, 0xa438, 0x3700, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x8025, 0xa438, 0x1800, 0xa438, 0x803a,
        0xa438, 0x1800, 0xa438, 0x8044, 0xa438, 0x1800, 0xa438, 0x8083,
        0xa438, 0x1800, 0xa438, 0x808d, 0xa438, 0x1800, 0xa438, 0x808d,
        0xa438, 0x1800, 0xa438, 0x808d, 0xa438, 0xd712, 0xa438, 0x4077,
        0xa438, 0xd71e, 0xa438, 0x4159, 0xa438, 0xd71e, 0xa438, 0x6099,
        0xa438, 0x7f44, 0xa438, 0x1800, 0xa438, 0x1a14, 0xa438, 0x9040,
        0xa438, 0x9201, 0xa438, 0x1800, 0xa438, 0x1b1a, 0xa438, 0xd71e,
        0xa438, 0x2425, 0xa438, 0x1a14, 0xa438, 0xd71f, 0xa438, 0x3ce5,
        0xa438, 0x1afb, 0xa438, 0x1800, 0xa438, 0x1b00, 0xa438, 0xd712,
        0xa438, 0x4077, 0xa438, 0xd71e, 0xa438, 0x4159, 0xa438, 0xd71e,
        0xa438, 0x60b9, 0xa438, 0x2421, 0xa438, 0x1c17, 0xa438, 0x1800,
        0xa438, 0x1a14, 0xa438, 0x9040, 0xa438, 0x1800, 0xa438, 0x1c2c,
        0xa438, 0xd71e, 0xa438, 0x2425, 0xa438, 0x1a14, 0xa438, 0xd71f,
        0xa438, 0x3ce5, 0xa438, 0x1c0f, 0xa438, 0x1800, 0xa438, 0x1c13,
        0xa438, 0xd702, 0xa438, 0xd501, 0xa438, 0x6072, 0xa438, 0x8401,
        0xa438, 0xf002, 0xa438, 0xa401, 0xa438, 0x1000, 0xa438, 0x146e,
        0xa438, 0x1800, 0xa438, 0x0b77, 0xa438, 0xd703, 0xa438, 0x665d,
        0xa438, 0x653e, 0xa438, 0x641f, 0xa438, 0xd700, 0xa438, 0x62c4,
        0xa438, 0x6185, 0xa438, 0x6066, 0xa438, 0x1800, 0xa438, 0x165a,
        0xa438, 0xc101, 0xa438, 0xcb00, 0xa438, 0x1000, 0xa438, 0x1945,
        0xa438, 0xd700, 0xa438, 0x7fa6, 0xa438, 0x1800, 0xa438, 0x807d,
        0xa438, 0xc102, 0xa438, 0xcb00, 0xa438, 0x1000, 0xa438, 0x1945,
        0xa438, 0xd700, 0xa438, 0x2569, 0xa438, 0x8058, 0xa438, 0x1800,
        0xa438, 0x807d, 0xa438, 0xc104, 0xa438, 0xcb00, 0xa438, 0x1000,
        0xa438, 0x1945, 0xa438, 0xd700, 0xa438, 0x7fa4, 0xa438, 0x1800,
        0xa438, 0x807d, 0xa438, 0xc120, 0xa438, 0xcb00, 0xa438, 0x1000,
        0xa438, 0x1945, 0xa438, 0xd703, 0xa438, 0x7fbf, 0xa438, 0x1800,
        0xa438, 0x807d, 0xa438, 0xc140, 0xa438, 0xcb00, 0xa438, 0x1000,
        0xa438, 0x1945, 0xa438, 0xd703, 0xa438, 0x7fbe, 0xa438, 0x1800,
        0xa438, 0x807d, 0xa438, 0xc180, 0xa438, 0xcb00, 0xa438, 0x1000,
        0xa438, 0x1945, 0xa438, 0xd703, 0xa438, 0x7fbd, 0xa438, 0xc100,
        0xa438, 0xcb00, 0xa438, 0xd708, 0xa438, 0x6018, 0xa438, 0x1800,
        0xa438, 0x165a, 0xa438, 0x1000, 0xa438, 0x14f6, 0xa438, 0xd014,
        0xa438, 0xd1e3, 0xa438, 0x1000, 0xa438, 0x1356, 0xa438, 0xd705,
        0xa438, 0x5fbe, 0xa438, 0x1800, 0xa438, 0x1559, 0xa436, 0xA026,
        0xa438, 0xffff, 0xa436, 0xA024, 0xa438, 0xffff, 0xa436, 0xA022,
        0xa438, 0xffff, 0xa436, 0xA020, 0xa438, 0x1557, 0xa436, 0xA006,
        0xa438, 0x1677, 0xa436, 0xA004, 0xa438, 0x0b75, 0xa436, 0xA002,
        0xa438, 0x1c17, 0xa436, 0xA000, 0xa438, 0x1b04, 0xa436, 0xA008,
        0xa438, 0x1f00, 0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x817f, 0xa438, 0x1800, 0xa438, 0x82ab,
        0xa438, 0x1800, 0xa438, 0x83f8, 0xa438, 0x1800, 0xa438, 0x8444,
        0xa438, 0x1800, 0xa438, 0x8454, 0xa438, 0x1800, 0xa438, 0x8459,
        0xa438, 0x1800, 0xa438, 0x8465, 0xa438, 0xcb11, 0xa438, 0xa50c,
        0xa438, 0x8310, 0xa438, 0xd701, 0xa438, 0x4076, 0xa438, 0x0c03,
        0xa438, 0x0903, 0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f,
        0xa438, 0x0d00, 0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d00,
        0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0x1000, 0xa438, 0x0a4d,
        0xa438, 0xcb12, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5f84, 0xa438, 0xd102, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xd701,
        0xa438, 0x60f3, 0xa438, 0xd413, 0xa438, 0x1000, 0xa438, 0x0a37,
        0xa438, 0xd410, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xcb13,
        0xa438, 0xa108, 0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8108,
        0xa438, 0xa00a, 0xa438, 0xa910, 0xa438, 0xa780, 0xa438, 0xd14a,
        0xa438, 0xd048, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd701,
        0xa438, 0x6255, 0xa438, 0xd700, 0xa438, 0x5f74, 0xa438, 0x6326,
        0xa438, 0xd702, 0xa438, 0x5f07, 0xa438, 0x800a, 0xa438, 0xa004,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8004, 0xa438, 0xa001,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001, 0xa438, 0x0c03,
        0xa438, 0x0902, 0xa438, 0xffe2, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x5fab, 0xa438, 0xba08, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f8b, 0xa438, 0x9a08,
        0xa438, 0x800a, 0xa438, 0xd702, 0xa438, 0x6535, 0xa438, 0xd40d,
        0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xcb14, 0xa438, 0xa004,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8004, 0xa438, 0xa001,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001, 0xa438, 0xa00a,
        0xa438, 0xa780, 0xa438, 0xd14a, 0xa438, 0xd048, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0x6206,
        0xa438, 0xd702, 0xa438, 0x5f47, 0xa438, 0x800a, 0xa438, 0xa004,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8004, 0xa438, 0xa001,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001, 0xa438, 0x0c03,
        0xa438, 0x0902, 0xa438, 0x1800, 0xa438, 0x8064, 0xa438, 0x800a,
        0xa438, 0xd40e, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xb920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac,
        0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x7f8c, 0xa438, 0xd701, 0xa438, 0x6073, 0xa438, 0xd701,
        0xa438, 0x4216, 0xa438, 0xa004, 0xa438, 0x1000, 0xa438, 0x0a42,
        0xa438, 0x8004, 0xa438, 0xa001, 0xa438, 0x1000, 0xa438, 0x0a42,
        0xa438, 0x8001, 0xa438, 0xd120, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0x8504,
        0xa438, 0xcb21, 0xa438, 0xa301, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5f9f, 0xa438, 0x8301, 0xa438, 0xd704,
        0xa438, 0x40e0, 0xa438, 0xd196, 0xa438, 0xd04d, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xcb22,
        0xa438, 0x1000, 0xa438, 0x0a6d, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xa640, 0xa438, 0x9503, 0xa438, 0x8910, 0xa438, 0x8720,
        0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f, 0xa438, 0x0d01,
        0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d01, 0xa438, 0x1000,
        0xa438, 0x0a7d, 0xa438, 0x0c1f, 0xa438, 0x0f14, 0xa438, 0xcb23,
        0xa438, 0x8fc0, 0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0xaf40,
        0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0x0cc0, 0xa438, 0x0f80,
        0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0xafc0, 0xa438, 0x1000,
        0xa438, 0x0a25, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd701,
        0xa438, 0x5dee, 0xa438, 0xcb24, 0xa438, 0x8f1f, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd701, 0xa438, 0x7f6e, 0xa438, 0xa111,
        0xa438, 0xa215, 0xa438, 0xa401, 0xa438, 0x8404, 0xa438, 0xa720,
        0xa438, 0xcb25, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8640,
        0xa438, 0x9503, 0xa438, 0x1000, 0xa438, 0x0b43, 0xa438, 0x1000,
        0xa438, 0x0b86, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xb920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac,
        0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x7f8c, 0xa438, 0xcb26, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x5f82, 0xa438, 0x8111, 0xa438, 0x8205,
        0xa438, 0x8404, 0xa438, 0xcb27, 0xa438, 0xd404, 0xa438, 0x1000,
        0xa438, 0x0a37, 0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f,
        0xa438, 0x0d02, 0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d02,
        0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0xa710, 0xa438, 0xa104,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8104, 0xa438, 0xa001,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001, 0xa438, 0xa120,
        0xa438, 0xaa0f, 0xa438, 0x8110, 0xa438, 0xa284, 0xa438, 0xa404,
        0xa438, 0xa00a, 0xa438, 0xd193, 0xa438, 0xd046, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xcb28,
        0xa438, 0xa110, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fa8, 0xa438, 0x8110, 0xa438, 0x8284, 0xa438, 0xa404,
        0xa438, 0x800a, 0xa438, 0x8710, 0xa438, 0xb804, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f82, 0xa438, 0x9804,
        0xa438, 0xcb29, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5f85, 0xa438, 0xa710, 0xa438, 0xb820, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f65, 0xa438, 0x9820,
        0xa438, 0xcb2a, 0xa438, 0xa190, 0xa438, 0xa284, 0xa438, 0xa404,
        0xa438, 0xa00a, 0xa438, 0xd13d, 0xa438, 0xd04a, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x3444, 0xa438, 0x8149,
        0xa438, 0xa220, 0xa438, 0xd1a0, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x3444, 0xa438, 0x8151,
        0xa438, 0xd702, 0xa438, 0x5f51, 0xa438, 0xcb2f, 0xa438, 0xa302,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd708, 0xa438, 0x5f63,
        0xa438, 0xd411, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0x8302,
        0xa438, 0xd409, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xb920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac,
        0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x7f8c, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5fa3, 0xa438, 0x8190, 0xa438, 0x82a4, 0xa438, 0x8404,
        0xa438, 0x800a, 0xa438, 0xb808, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x7fa3, 0xa438, 0x9808, 0xa438, 0x1800,
        0xa438, 0x0433, 0xa438, 0xcb15, 0xa438, 0xa508, 0xa438, 0xd700,
        0xa438, 0x6083, 0xa438, 0x0c1f, 0xa438, 0x0d01, 0xa438, 0xf003,
        0xa438, 0x0c1f, 0xa438, 0x0d01, 0xa438, 0x1000, 0xa438, 0x0a7d,
        0xa438, 0x1000, 0xa438, 0x0a4d, 0xa438, 0xa301, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5f9f, 0xa438, 0x8301,
        0xa438, 0xd704, 0xa438, 0x40e0, 0xa438, 0xd115, 0xa438, 0xd04f,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4,
        0xa438, 0xd413, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xcb16,
        0xa438, 0x1000, 0xa438, 0x0a6d, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xa640, 0xa438, 0x9503, 0xa438, 0x8720, 0xa438, 0xd17a,
        0xa438, 0xd04c, 0xa438, 0x0c1f, 0xa438, 0x0f14, 0xa438, 0xcb17,
        0xa438, 0x8fc0, 0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0xaf40,
        0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0x0cc0, 0xa438, 0x0f80,
        0xa438, 0x1000, 0xa438, 0x0a25, 0xa438, 0xafc0, 0xa438, 0x1000,
        0xa438, 0x0a25, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd701,
        0xa438, 0x61ce, 0xa438, 0xd700, 0xa438, 0x5db4, 0xa438, 0xcb18,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8640, 0xa438, 0x9503,
        0xa438, 0xa720, 0xa438, 0x1000, 0xa438, 0x0b43, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xffd6, 0xa438, 0x8f1f, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd701, 0xa438, 0x7f8e, 0xa438, 0xa131,
        0xa438, 0xaa0f, 0xa438, 0xa2d5, 0xa438, 0xa407, 0xa438, 0xa720,
        0xa438, 0x8310, 0xa438, 0xa308, 0xa438, 0x8308, 0xa438, 0xcb19,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8640, 0xa438, 0x9503,
        0xa438, 0x1000, 0xa438, 0x0b43, 0xa438, 0x1000, 0xa438, 0x0b86,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xb920, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac, 0xa438, 0x9920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f8c,
        0xa438, 0xcb1a, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5f82, 0xa438, 0x8111, 0xa438, 0x82c5, 0xa438, 0xa404,
        0xa438, 0x8402, 0xa438, 0xb804, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x7f82, 0xa438, 0x9804, 0xa438, 0xcb1b,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5f85,
        0xa438, 0xa710, 0xa438, 0xb820, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x7f65, 0xa438, 0x9820, 0xa438, 0xcb1c,
        0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f, 0xa438, 0x0d02,
        0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d02, 0xa438, 0x1000,
        0xa438, 0x0a7d, 0xa438, 0xa110, 0xa438, 0xa284, 0xa438, 0xa404,
        0xa438, 0x8402, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fa8, 0xa438, 0xcb1d, 0xa438, 0xa180, 0xa438, 0xa402,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fa8,
        0xa438, 0xa220, 0xa438, 0xd1f5, 0xa438, 0xd049, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x3444, 0xa438, 0x8221,
        0xa438, 0xd702, 0xa438, 0x5f51, 0xa438, 0xb920, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac, 0xa438, 0x9920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f8c,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fa3,
        0xa438, 0xa504, 0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f,
        0xa438, 0x0d00, 0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d00,
        0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0xa00a, 0xa438, 0x8190,
        0xa438, 0x82a4, 0xa438, 0x8402, 0xa438, 0xa404, 0xa438, 0xb808,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7fa3,
        0xa438, 0x9808, 0xa438, 0xcb2b, 0xa438, 0xcb2c, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5f84, 0xa438, 0xd14a,
        0xa438, 0xd048, 0xa438, 0xa780, 0xa438, 0xcb2d, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5f94, 0xa438, 0x6208,
        0xa438, 0xd702, 0xa438, 0x5f27, 0xa438, 0x800a, 0xa438, 0xa004,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8004, 0xa438, 0xa001,
        0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001, 0xa438, 0x0c03,
        0xa438, 0x0902, 0xa438, 0xa00a, 0xa438, 0xffe9, 0xa438, 0xcb2e,
        0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f, 0xa438, 0x0d02,
        0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d02, 0xa438, 0x1000,
        0xa438, 0x0a7d, 0xa438, 0xa190, 0xa438, 0xa284, 0xa438, 0xa406,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fa8,
        0xa438, 0xa220, 0xa438, 0xd1a0, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x3444, 0xa438, 0x827d,
        0xa438, 0xd702, 0xa438, 0x5f51, 0xa438, 0xcb2f, 0xa438, 0xa302,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd708, 0xa438, 0x5f63,
        0xa438, 0xd411, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0x8302,
        0xa438, 0xd409, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0xb920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac,
        0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x7f8c, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5fa3, 0xa438, 0x8190, 0xa438, 0x82a4, 0xa438, 0x8406,
        0xa438, 0x800a, 0xa438, 0xb808, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x7fa3, 0xa438, 0x9808, 0xa438, 0x1800,
        0xa438, 0x0433, 0xa438, 0xcb30, 0xa438, 0x8380, 0xa438, 0xcb31,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5f86,
        0xa438, 0x9308, 0xa438, 0xb204, 0xa438, 0xb301, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd701, 0xa438, 0x5fa2, 0xa438, 0xb302,
        0xa438, 0x9204, 0xa438, 0xcb32, 0xa438, 0xd408, 0xa438, 0x1000,
        0xa438, 0x0a37, 0xa438, 0xd141, 0xa438, 0xd043, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xd704,
        0xa438, 0x4ccc, 0xa438, 0xd700, 0xa438, 0x4c81, 0xa438, 0xd702,
        0xa438, 0x609e, 0xa438, 0xd1e5, 0xa438, 0xd04d, 0xa438, 0xf003,
        0xa438, 0xd1e5, 0xa438, 0xd04d, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xd700, 0xa438, 0x6083,
        0xa438, 0x0c1f, 0xa438, 0x0d01, 0xa438, 0xf003, 0xa438, 0x0c1f,
        0xa438, 0x0d01, 0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0x8710,
        0xa438, 0xa108, 0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8108,
        0xa438, 0xa203, 0xa438, 0x8120, 0xa438, 0x8a0f, 0xa438, 0xa111,
        0xa438, 0x8204, 0xa438, 0xa140, 0xa438, 0x1000, 0xa438, 0x0a42,
        0xa438, 0x8140, 0xa438, 0xd17a, 0xa438, 0xd04b, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xa204,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fa7,
        0xa438, 0xb920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x5fac, 0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x7f8c, 0xa438, 0xd404, 0xa438, 0x1000,
        0xa438, 0x0a37, 0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f,
        0xa438, 0x0d02, 0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d02,
        0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0xa710, 0xa438, 0x8101,
        0xa438, 0x8201, 0xa438, 0xa104, 0xa438, 0x1000, 0xa438, 0x0a42,
        0xa438, 0x8104, 0xa438, 0xa120, 0xa438, 0xaa0f, 0xa438, 0x8110,
        0xa438, 0xa284, 0xa438, 0xa404, 0xa438, 0xa00a, 0xa438, 0xd193,
        0xa438, 0xd047, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0xa110, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5fa8, 0xa438, 0xa180, 0xa438, 0xd13d,
        0xa438, 0xd04a, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0xf024, 0xa438, 0xa710, 0xa438, 0xa00a,
        0xa438, 0x8190, 0xa438, 0x8204, 0xa438, 0xa280, 0xa438, 0xa404,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fa7,
        0xa438, 0x8710, 0xa438, 0xb920, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x5fac, 0xa438, 0x9920, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f8c, 0xa438, 0x800a,
        0xa438, 0x8190, 0xa438, 0x8284, 0xa438, 0x8406, 0xa438, 0xd700,
        0xa438, 0x4121, 0xa438, 0xd701, 0xa438, 0x60f3, 0xa438, 0xd1e5,
        0xa438, 0xd04d, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0x8710, 0xa438, 0xa00a, 0xa438, 0x8190,
        0xa438, 0x8204, 0xa438, 0xa280, 0xa438, 0xa404, 0xa438, 0xb920,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x5fac,
        0xa438, 0x9920, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f,
        0xa438, 0x7f8c, 0xa438, 0xcb33, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd71f, 0xa438, 0x5f85, 0xa438, 0xa710, 0xa438, 0xb820,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd71f, 0xa438, 0x7f65,
        0xa438, 0x9820, 0xa438, 0xcb34, 0xa438, 0xa00a, 0xa438, 0xa190,
        0xa438, 0xa284, 0xa438, 0xa404, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5fa9, 0xa438, 0xd701, 0xa438, 0x6853,
        0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f, 0xa438, 0x0d00,
        0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d00, 0xa438, 0x1000,
        0xa438, 0x0a7d, 0xa438, 0x8190, 0xa438, 0x8284, 0xa438, 0xcb35,
        0xa438, 0xd407, 0xa438, 0x1000, 0xa438, 0x0a37, 0xa438, 0x8110,
        0xa438, 0x8204, 0xa438, 0xa280, 0xa438, 0xa00a, 0xa438, 0xd704,
        0xa438, 0x4215, 0xa438, 0xa304, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5fb8, 0xa438, 0xd1c3, 0xa438, 0xd043,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4,
        0xa438, 0x8304, 0xa438, 0xd700, 0xa438, 0x4109, 0xa438, 0xf01e,
        0xa438, 0xcb36, 0xa438, 0xd412, 0xa438, 0x1000, 0xa438, 0x0a37,
        0xa438, 0xd700, 0xa438, 0x6309, 0xa438, 0xd702, 0xa438, 0x42c7,
        0xa438, 0x800a, 0xa438, 0x8180, 0xa438, 0x8280, 0xa438, 0x8404,
        0xa438, 0xa004, 0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8004,
        0xa438, 0xa001, 0xa438, 0x1000, 0xa438, 0x0a42, 0xa438, 0x8001,
        0xa438, 0x0c03, 0xa438, 0x0902, 0xa438, 0xa00a, 0xa438, 0xd14a,
        0xa438, 0xd048, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0xd700, 0xa438, 0x6083, 0xa438, 0x0c1f,
        0xa438, 0x0d02, 0xa438, 0xf003, 0xa438, 0x0c1f, 0xa438, 0x0d02,
        0xa438, 0x1000, 0xa438, 0x0a7d, 0xa438, 0xcc55, 0xa438, 0xcb37,
        0xa438, 0xa00a, 0xa438, 0xa190, 0xa438, 0xa2a4, 0xa438, 0xa404,
        0xa438, 0xd700, 0xa438, 0x6041, 0xa438, 0xa402, 0xa438, 0xd13d,
        0xa438, 0xd04a, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700,
        0xa438, 0x5fa9, 0xa438, 0xd702, 0xa438, 0x5f71, 0xa438, 0xcb38,
        0xa438, 0x8224, 0xa438, 0xa288, 0xa438, 0x8180, 0xa438, 0xa110,
        0xa438, 0xa404, 0xa438, 0x800a, 0xa438, 0xd700, 0xa438, 0x6041,
        0xa438, 0x8402, 0xa438, 0xd415, 0xa438, 0x1000, 0xa438, 0x0a37,
        0xa438, 0xd13d, 0xa438, 0xd04a, 0xa438, 0x1000, 0xa438, 0x0a5e,
        0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xcb39, 0xa438, 0xa00a,
        0xa438, 0xa190, 0xa438, 0xa2a0, 0xa438, 0xa404, 0xa438, 0xd700,
        0xa438, 0x6041, 0xa438, 0xa402, 0xa438, 0xd17a, 0xa438, 0xd047,
        0xa438, 0x1000, 0xa438, 0x0a5e, 0xa438, 0xd700, 0xa438, 0x5fb4,
        0xa438, 0x1800, 0xa438, 0x0560, 0xa438, 0xa111, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0xd3f5,
        0xa438, 0xd219, 0xa438, 0x1000, 0xa438, 0x0c31, 0xa438, 0xd708,
        0xa438, 0x5fa5, 0xa438, 0xa215, 0xa438, 0xd30e, 0xa438, 0xd21a,
        0xa438, 0x1000, 0xa438, 0x0c31, 0xa438, 0xd708, 0xa438, 0x63e9,
        0xa438, 0xd708, 0xa438, 0x5f65, 0xa438, 0xd708, 0xa438, 0x7f36,
        0xa438, 0xa004, 0xa438, 0x1000, 0xa438, 0x0c35, 0xa438, 0x8004,
        0xa438, 0xa001, 0xa438, 0x1000, 0xa438, 0x0c35, 0xa438, 0x8001,
        0xa438, 0xd708, 0xa438, 0x4098, 0xa438, 0xd102, 0xa438, 0x9401,
        0xa438, 0xf003, 0xa438, 0xd103, 0xa438, 0xb401, 0xa438, 0x1000,
        0xa438, 0x0c27, 0xa438, 0xa108, 0xa438, 0x1000, 0xa438, 0x0c35,
        0xa438, 0x8108, 0xa438, 0x8110, 0xa438, 0x8294, 0xa438, 0xa202,
        0xa438, 0x1800, 0xa438, 0x0bdb, 0xa438, 0xd39c, 0xa438, 0xd210,
        0xa438, 0x1000, 0xa438, 0x0c31, 0xa438, 0xd708, 0xa438, 0x5fa5,
        0xa438, 0xd39c, 0xa438, 0xd210, 0xa438, 0x1000, 0xa438, 0x0c31,
        0xa438, 0xd708, 0xa438, 0x5fa5, 0xa438, 0x1000, 0xa438, 0x0c31,
        0xa438, 0xd708, 0xa438, 0x29b5, 0xa438, 0x840e, 0xa438, 0xd708,
        0xa438, 0x5f4a, 0xa438, 0x0c1f, 0xa438, 0x1014, 0xa438, 0x1000,
        0xa438, 0x0c31, 0xa438, 0xd709, 0xa438, 0x7fa4, 0xa438, 0x901f,
        0xa438, 0x1800, 0xa438, 0x0c23, 0xa438, 0xcb43, 0xa438, 0xa508,
        0xa438, 0xd701, 0xa438, 0x3699, 0xa438, 0x844a, 0xa438, 0xa504,
        0xa438, 0xa190, 0xa438, 0xa2a0, 0xa438, 0xa404, 0xa438, 0xa00a,
        0xa438, 0xd700, 0xa438, 0x2109, 0xa438, 0x05ea, 0xa438, 0xa402,
        0xa438, 0x1800, 0xa438, 0x05ea, 0xa438, 0xcb90, 0xa438, 0x0cf0,
        0xa438, 0x0ca0, 0xa438, 0x1800, 0xa438, 0x06db, 0xa438, 0xd1ff,
        0xa438, 0xd052, 0xa438, 0xa508, 0xa438, 0x8718, 0xa438, 0xa00a,
        0xa438, 0xa190, 0xa438, 0xa2a0, 0xa438, 0xa404, 0xa438, 0x0cf0,
        0xa438, 0x0c50, 0xa438, 0x1800, 0xa438, 0x09ef, 0xa438, 0x1000,
        0xa438, 0x0a5e, 0xa438, 0xd704, 0xa438, 0x2e70, 0xa438, 0x06da,
        0xa438, 0xd700, 0xa438, 0x5f55, 0xa438, 0xa90c, 0xa438, 0x1800,
        0xa438, 0x0645, 0xa436, 0xA10E, 0xa438, 0x0644, 0xa436, 0xA10C,
        0xa438, 0x09e9, 0xa436, 0xA10A, 0xa438, 0x06da, 0xa436, 0xA108,
        0xa438, 0x05e1, 0xa436, 0xA106, 0xa438, 0x0be4, 0xa436, 0xA104,
        0xa438, 0x0435, 0xa436, 0xA102, 0xa438, 0x0141, 0xa436, 0xA100,
        0xa438, 0x026d, 0xa436, 0xA110, 0xa438, 0x00ff, 0xa436, 0xb87c,
        0xa438, 0x85fe, 0xa436, 0xb87e, 0xa438, 0xaf86, 0xa438, 0x16af,
        0xa438, 0x8699, 0xa438, 0xaf86, 0xa438, 0xe5af, 0xa438, 0x86f9,
        0xa438, 0xaf87, 0xa438, 0x7aaf, 0xa438, 0x883a, 0xa438, 0xaf88,
        0xa438, 0x58af, 0xa438, 0x8b6c, 0xa438, 0xd48b, 0xa438, 0x7c02,
        0xa438, 0x8644, 0xa438, 0x2c00, 0xa438, 0x503c, 0xa438, 0xffd6,
        0xa438, 0xac27, 0xa438, 0x18e1, 0xa438, 0x82fe, 0xa438, 0xad28,
        0xa438, 0x0cd4, 0xa438, 0x8b84, 0xa438, 0x0286, 0xa438, 0x442c,
        0xa438, 0x003c, 0xa438, 0xac27, 0xa438, 0x06ee, 0xa438, 0x8299,
        0xa438, 0x01ae, 0xa438, 0x04ee, 0xa438, 0x8299, 0xa438, 0x00af,
        0xa438, 0x23dc, 0xa438, 0xf9fa, 0xa438, 0xcefa, 0xa438, 0xfbef,
        0xa438, 0x79fb, 0xa438, 0xc4bf, 0xa438, 0x8b76, 0xa438, 0x026c,
        0xa438, 0x6dac, 0xa438, 0x2804, 0xa438, 0xd203, 0xa438, 0xae02,
        0xa438, 0xd201, 0xa438, 0xbdd8, 0xa438, 0x19d9, 0xa438, 0xef94,
        0xa438, 0x026c, 0xa438, 0x6d78, 0xa438, 0x03ef, 0xa438, 0x648a,
        0xa438, 0x0002, 0xa438, 0xbdd8, 0xa438, 0x19d9, 0xa438, 0xef94,
        0xa438, 0x026c, 0xa438, 0x6d78, 0xa438, 0x03ef, 0xa438, 0x7402,
        0xa438, 0x72cd, 0xa438, 0xac50, 0xa438, 0x02ef, 0xa438, 0x643a,
        0xa438, 0x019f, 0xa438, 0xe4ef, 0xa438, 0x4678, 0xa438, 0x03ac,
        0xa438, 0x2002, 0xa438, 0xae02, 0xa438, 0xd0ff, 0xa438, 0xffef,
        0xa438, 0x97ff, 0xa438, 0xfec6, 0xa438, 0xfefd, 0xa438, 0x041f,
        0xa438, 0x771f, 0xa438, 0x221c, 0xa438, 0x450d, 0xa438, 0x481f,
        0xa438, 0x00ac, 0xa438, 0x7f04, 0xa438, 0x1a94, 0xa438, 0xae08,
        0xa438, 0x1a94, 0xa438, 0xac7f, 0xa438, 0x03d7, 0xa438, 0x0100,
        0xa438, 0xef46, 0xa438, 0x0d48, 0xa438, 0x1f00, 0xa438, 0x1c45,
        0xa438, 0xef69, 0xa438, 0xef57, 0xa438, 0xef74, 0xa438, 0x0272,
        0xa438, 0xe8a7, 0xa438, 0xffff, 0xa438, 0x0d1a, 0xa438, 0x941b,
        0xa438, 0x979e, 0xa438, 0x072d, 0xa438, 0x0100, 0xa438, 0x1a64,
        0xa438, 0xef76, 0xa438, 0xef97, 0xa438, 0x0d98, 0xa438, 0xd400,
        0xa438, 0xff1d, 0xa438, 0x941a, 0xa438, 0x89cf, 0xa438, 0x1a75,
        0xa438, 0xaf74, 0xa438, 0xf9bf, 0xa438, 0x8b79, 0xa438, 0x026c,
        0xa438, 0x6da1, 0xa438, 0x0005, 0xa438, 0xe180, 0xa438, 0xa0ae,
        0xa438, 0x03e1, 0xa438, 0x80a1, 0xa438, 0xaf26, 0xa438, 0x9aac,
        0xa438, 0x284d, 0xa438, 0xe08f, 0xa438, 0xffef, 0xa438, 0x10c0,
        0xa438, 0xe08f, 0xa438, 0xfe10, 0xa438, 0x1b08, 0xa438, 0xa000,
        0xa438, 0x04c8, 0xa438, 0xaf40, 0xa438, 0x67c8, 0xa438, 0xbf8b,
        0xa438, 0x8c02, 0xa438, 0x6c4e, 0xa438, 0xc4bf, 0xa438, 0x8b8f,
        0xa438, 0x026c, 0xa438, 0x6def, 0xa438, 0x74e0, 0xa438, 0x830c,
        0xa438, 0xad20, 0xa438, 0x0302, 0xa438, 0x74ac, 0xa438, 0xccef,
        0xa438, 0x971b, 0xa438, 0x76ad, 0xa438, 0x5f02, 0xa438, 0xae13,
        0xa438, 0xef69, 0xa438, 0xef30, 0xa438, 0x1b32, 0xa438, 0xc4ef,
        0xa438, 0x46e4, 0xa438, 0x8ffb, 0xa438, 0xe58f, 0xa438, 0xfce7,
        0xa438, 0x8ffd, 0xa438, 0xcc10, 0xa438, 0x11ae, 0xa438, 0xb8d1,
        0xa438, 0x00a1, 0xa438, 0x1f03, 0xa438, 0xaf40, 0xa438, 0x4fbf,
        0xa438, 0x8b8c, 0xa438, 0x026c, 0xa438, 0x4ec4, 0xa438, 0xbf8b,
        0xa438, 0x8f02, 0xa438, 0x6c6d, 0xa438, 0xef74, 0xa438, 0xe083,
        0xa438, 0x0cad, 0xa438, 0x2003, 0xa438, 0x0274, 0xa438, 0xaccc,
        0xa438, 0xef97, 0xa438, 0x1b76, 0xa438, 0xad5f, 0xa438, 0x02ae,
        0xa438, 0x04ef, 0xa438, 0x69ef, 0xa438, 0x3111, 0xa438, 0xaed1,
        0xa438, 0x0287, 0xa438, 0x80af, 0xa438, 0x2293, 0xa438, 0xf8f9,
        0xa438, 0xfafb, 0xa438, 0xef59, 0xa438, 0xe080, 0xa438, 0x13ad,
        0xa438, 0x252f, 0xa438, 0xbf88, 0xa438, 0x2802, 0xa438, 0x6c6d,
        0xa438, 0xef64, 0xa438, 0x1f44, 0xa438, 0xe18f, 0xa438, 0xb91b,
        0xa438, 0x64ad, 0xa438, 0x4f1d, 0xa438, 0xd688, 0xa438, 0x2bd7,
        0xa438, 0x882e, 0xa438, 0x0274, 0xa438, 0x73ad, 0xa438, 0x5008,
        0xa438, 0xbf88, 0xa438, 0x3102, 0xa438, 0x737c, 0xa438, 0xae03,
        0xa438, 0x0287, 0xa438, 0xd0bf, 0xa438, 0x882b, 0xa438, 0x0273,
        0xa438, 0x73e0, 0xa438, 0x824c, 0xa438, 0xf621, 0xa438, 0xe482,
        0xa438, 0x4cbf, 0xa438, 0x8834, 0xa438, 0x0273, 0xa438, 0x7cef,
        0xa438, 0x95ff, 0xa438, 0xfefd, 0xa438, 0xfc04, 0xa438, 0xf8f9,
        0xa438, 0xfafb, 0xa438, 0xef79, 0xa438, 0xbf88, 0xa438, 0x1f02,
        0xa438, 0x737c, 0xa438, 0x1f22, 0xa438, 0xac32, 0xa438, 0x31ef,
        0xa438, 0x12bf, 0xa438, 0x8822, 0xa438, 0x026c, 0xa438, 0x4ed6,
        0xa438, 0x8fba, 0xa438, 0x1f33, 0xa438, 0xac3c, 0xa438, 0x1eef,
        0xa438, 0x13bf, 0xa438, 0x8837, 0xa438, 0x026c, 0xa438, 0x4eef,
        0xa438, 0x96d8, 0xa438, 0x19d9, 0xa438, 0xbf88, 0xa438, 0x2502,
        0xa438, 0x6c4e, 0xa438, 0xbf88, 0xa438, 0x2502, 0xa438, 0x6c4e,
        0xa438, 0x1616, 0xa438, 0x13ae, 0xa438, 0xdf12, 0xa438, 0xaecc,
        0xa438, 0xbf88, 0xa438, 0x1f02, 0xa438, 0x7373, 0xa438, 0xef97,
        0xa438, 0xfffe, 0xa438, 0xfdfc, 0xa438, 0x0466, 0xa438, 0xac88,
        0xa438, 0x54ac, 0xa438, 0x88f0, 0xa438, 0xac8a, 0xa438, 0x92ac,
        0xa438, 0xbadd, 0xa438, 0xac6c, 0xa438, 0xeeac, 0xa438, 0x6cff,
        0xa438, 0xad02, 0xa438, 0x99ac, 0xa438, 0x0030, 0xa438, 0xac88,
        0xa438, 0xd4c3, 0xa438, 0x5000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x00b4, 0xa438, 0xecee,
        0xa438, 0x8298, 0xa438, 0x00af, 0xa438, 0x1412, 0xa438, 0xf8bf,
        0xa438, 0x8b5d, 0xa438, 0x026c, 0xa438, 0x6d58, 0xa438, 0x03e1,
        0xa438, 0x8fb8, 0xa438, 0x2901, 0xa438, 0xe58f, 0xa438, 0xb8a0,
        0xa438, 0x0049, 0xa438, 0xef47, 0xa438, 0xe483, 0xa438, 0x02e5,
        0xa438, 0x8303, 0xa438, 0xbfc2, 0xa438, 0x5f1a, 0xa438, 0x95f7,
        0xa438, 0x05ee, 0xa438, 0xffd2, 0xa438, 0x00d8, 0xa438, 0xf605,
        0xa438, 0x1f11, 0xa438, 0xef60, 0xa438, 0xbf8b, 0xa438, 0x3002,
        0xa438, 0x6c4e, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c6d,
        0xa438, 0xf728, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c4e,
        0xa438, 0xf628, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c4e,
        0xa438, 0x0c64, 0xa438, 0xef46, 0xa438, 0xbf8b, 0xa438, 0x6002,
        0xa438, 0x6c4e, 0xa438, 0x0289, 0xa438, 0x9902, 0xa438, 0x3920,
        0xa438, 0xaf89, 0xa438, 0x96a0, 0xa438, 0x0149, 0xa438, 0xef47,
        0xa438, 0xe483, 0xa438, 0x04e5, 0xa438, 0x8305, 0xa438, 0xbfc2,
        0xa438, 0x5f1a, 0xa438, 0x95f7, 0xa438, 0x05ee, 0xa438, 0xffd2,
        0xa438, 0x00d8, 0xa438, 0xf605, 0xa438, 0x1f11, 0xa438, 0xef60,
        0xa438, 0xbf8b, 0xa438, 0x3002, 0xa438, 0x6c4e, 0xa438, 0xbf8b,
        0xa438, 0x3302, 0xa438, 0x6c6d, 0xa438, 0xf729, 0xa438, 0xbf8b,
        0xa438, 0x3302, 0xa438, 0x6c4e, 0xa438, 0xf629, 0xa438, 0xbf8b,
        0xa438, 0x3302, 0xa438, 0x6c4e, 0xa438, 0x0c64, 0xa438, 0xef46,
        0xa438, 0xbf8b, 0xa438, 0x6302, 0xa438, 0x6c4e, 0xa438, 0x0289,
        0xa438, 0x9902, 0xa438, 0x3920, 0xa438, 0xaf89, 0xa438, 0x96a0,
        0xa438, 0x0249, 0xa438, 0xef47, 0xa438, 0xe483, 0xa438, 0x06e5,
        0xa438, 0x8307, 0xa438, 0xbfc2, 0xa438, 0x5f1a, 0xa438, 0x95f7,
        0xa438, 0x05ee, 0xa438, 0xffd2, 0xa438, 0x00d8, 0xa438, 0xf605,
        0xa438, 0x1f11, 0xa438, 0xef60, 0xa438, 0xbf8b, 0xa438, 0x3002,
        0xa438, 0x6c4e, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c6d,
        0xa438, 0xf72a, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c4e,
        0xa438, 0xf62a, 0xa438, 0xbf8b, 0xa438, 0x3302, 0xa438, 0x6c4e,
        0xa438, 0x0c64, 0xa438, 0xef46, 0xa438, 0xbf8b, 0xa438, 0x6602,
        0xa438, 0x6c4e, 0xa438, 0x0289, 0xa438, 0x9902, 0xa438, 0x3920,
        0xa438, 0xaf89, 0xa438, 0x96ef, 0xa438, 0x47e4, 0xa438, 0x8308,
        0xa438, 0xe583, 0xa438, 0x09bf, 0xa438, 0xc25f, 0xa438, 0x1a95,
        0xa438, 0xf705, 0xa438, 0xeeff, 0xa438, 0xd200, 0xa438, 0xd8f6,
        0xa438, 0x051f, 0xa438, 0x11ef, 0xa438, 0x60bf, 0xa438, 0x8b30,
        0xa438, 0x026c, 0xa438, 0x4ebf, 0xa438, 0x8b33, 0xa438, 0x026c,
        0xa438, 0x6df7, 0xa438, 0x2bbf, 0xa438, 0x8b33, 0xa438, 0x026c,
        0xa438, 0x4ef6, 0xa438, 0x2bbf, 0xa438, 0x8b33, 0xa438, 0x026c,
        0xa438, 0x4e0c, 0xa438, 0x64ef, 0xa438, 0x46bf, 0xa438, 0x8b69,
        0xa438, 0x026c, 0xa438, 0x4e02, 0xa438, 0x8999, 0xa438, 0x0239,
        0xa438, 0x20af, 0xa438, 0x8996, 0xa438, 0xaf39, 0xa438, 0x1ef8,
        0xa438, 0xf9fa, 0xa438, 0xe08f, 0xa438, 0xb838, 0xa438, 0x02ad,
        0xa438, 0x2702, 0xa438, 0xae03, 0xa438, 0xaf8b, 0xa438, 0x201f,
        0xa438, 0x66ef, 0xa438, 0x65bf, 0xa438, 0xc21f, 0xa438, 0x1a96,
        0xa438, 0xf705, 0xa438, 0xeeff, 0xa438, 0xd200, 0xa438, 0xdaf6,
        0xa438, 0x05bf, 0xa438, 0xc22f, 0xa438, 0x1a96, 0xa438, 0xf705,
        0xa438, 0xeeff, 0xa438, 0xd200, 0xa438, 0xdbf6, 0xa438, 0x05ef,
        0xa438, 0x021f, 0xa438, 0x110d, 0xa438, 0x42bf, 0xa438, 0x8b3c,
        0xa438, 0x026c, 0xa438, 0x4eef, 0xa438, 0x021b, 0xa438, 0x031f,
        0xa438, 0x110d, 0xa438, 0x42bf, 0xa438, 0x8b36, 0xa438, 0x026c,
        0xa438, 0x4eef, 0xa438, 0x021a, 0xa438, 0x031f, 0xa438, 0x110d,
        0xa438, 0x42bf, 0xa438, 0x8b39, 0xa438, 0x026c, 0xa438, 0x4ebf,
        0xa438, 0xc23f, 0xa438, 0x1a96, 0xa438, 0xf705, 0xa438, 0xeeff,
        0xa438, 0xd200, 0xa438, 0xdaf6, 0xa438, 0x05bf, 0xa438, 0xc24f,
        0xa438, 0x1a96, 0xa438, 0xf705, 0xa438, 0xeeff, 0xa438, 0xd200,
        0xa438, 0xdbf6, 0xa438, 0x05ef, 0xa438, 0x021f, 0xa438, 0x110d,
        0xa438, 0x42bf, 0xa438, 0x8b45, 0xa438, 0x026c, 0xa438, 0x4eef,
        0xa438, 0x021b, 0xa438, 0x031f, 0xa438, 0x110d, 0xa438, 0x42bf,
        0xa438, 0x8b3f, 0xa438, 0x026c, 0xa438, 0x4eef, 0xa438, 0x021a,
        0xa438, 0x031f, 0xa438, 0x110d, 0xa438, 0x42bf, 0xa438, 0x8b42,
        0xa438, 0x026c, 0xa438, 0x4eef, 0xa438, 0x56d0, 0xa438, 0x201f,
        0xa438, 0x11bf, 0xa438, 0x8b4e, 0xa438, 0x026c, 0xa438, 0x4ebf,
        0xa438, 0x8b48, 0xa438, 0x026c, 0xa438, 0x4ebf, 0xa438, 0x8b4b,
        0xa438, 0x026c, 0xa438, 0x4ee1, 0xa438, 0x8578, 0xa438, 0xef03,
        0xa438, 0x480a, 0xa438, 0x2805, 0xa438, 0xef20, 0xa438, 0x1b01,
        0xa438, 0xad27, 0xa438, 0x3f1f, 0xa438, 0x44e0, 0xa438, 0x8560,
        0xa438, 0xe185, 0xa438, 0x61bf, 0xa438, 0x8b51, 0xa438, 0x026c,
        0xa438, 0x4ee0, 0xa438, 0x8566, 0xa438, 0xe185, 0xa438, 0x67bf,
        0xa438, 0x8b54, 0xa438, 0x026c, 0xa438, 0x4ee0, 0xa438, 0x856c,
        0xa438, 0xe185, 0xa438, 0x6dbf, 0xa438, 0x8b57, 0xa438, 0x026c,
        0xa438, 0x4ee0, 0xa438, 0x8572, 0xa438, 0xe185, 0xa438, 0x73bf,
        0xa438, 0x8b5a, 0xa438, 0x026c, 0xa438, 0x4ee1, 0xa438, 0x8fb8,
        0xa438, 0x5900, 0xa438, 0xf728, 0xa438, 0xe58f, 0xa438, 0xb8af,
        0xa438, 0x8b2c, 0xa438, 0xe185, 0xa438, 0x791b, 0xa438, 0x21ad,
        0xa438, 0x373e, 0xa438, 0x1f44, 0xa438, 0xe085, 0xa438, 0x62e1,
        0xa438, 0x8563, 0xa438, 0xbf8b, 0xa438, 0x5102, 0xa438, 0x6c4e,
        0xa438, 0xe085, 0xa438, 0x68e1, 0xa438, 0x8569, 0xa438, 0xbf8b,
        0xa438, 0x5402, 0xa438, 0x6c4e, 0xa438, 0xe085, 0xa438, 0x6ee1,
        0xa438, 0x856f, 0xa438, 0xbf8b, 0xa438, 0x5702, 0xa438, 0x6c4e,
        0xa438, 0xe085, 0xa438, 0x74e1, 0xa438, 0x8575, 0xa438, 0xbf8b,
        0xa438, 0x5a02, 0xa438, 0x6c4e, 0xa438, 0xe18f, 0xa438, 0xb859,
        0xa438, 0x00f7, 0xa438, 0x28e5, 0xa438, 0x8fb8, 0xa438, 0xae4a,
        0xa438, 0x1f44, 0xa438, 0xe085, 0xa438, 0x64e1, 0xa438, 0x8565,
        0xa438, 0xbf8b, 0xa438, 0x5102, 0xa438, 0x6c4e, 0xa438, 0xe085,
        0xa438, 0x6ae1, 0xa438, 0x856b, 0xa438, 0xbf8b, 0xa438, 0x5402,
        0xa438, 0x6c4e, 0xa438, 0xe085, 0xa438, 0x70e1, 0xa438, 0x8571,
        0xa438, 0xbf8b, 0xa438, 0x5702, 0xa438, 0x6c4e, 0xa438, 0xe085,
        0xa438, 0x76e1, 0xa438, 0x8577, 0xa438, 0xbf8b, 0xa438, 0x5a02,
        0xa438, 0x6c4e, 0xa438, 0xe18f, 0xa438, 0xb859, 0xa438, 0x00f7,
        0xa438, 0x28e5, 0xa438, 0x8fb8, 0xa438, 0xae0c, 0xa438, 0xe18f,
        0xa438, 0xb839, 0xa438, 0x04ac, 0xa438, 0x2f04, 0xa438, 0xee8f,
        0xa438, 0xb800, 0xa438, 0xfefd, 0xa438, 0xfc04, 0xa438, 0xf0ac,
        0xa438, 0x8efc, 0xa438, 0xac8c, 0xa438, 0xf0ac, 0xa438, 0xfaf0,
        0xa438, 0xacf8, 0xa438, 0xf0ac, 0xa438, 0xf6f0, 0xa438, 0xad00,
        0xa438, 0xf0ac, 0xa438, 0xfef0, 0xa438, 0xacfc, 0xa438, 0xf0ac,
        0xa438, 0xf4f0, 0xa438, 0xacf2, 0xa438, 0xf0ac, 0xa438, 0xf0f0,
        0xa438, 0xacb0, 0xa438, 0xf0ac, 0xa438, 0xaef0, 0xa438, 0xacac,
        0xa438, 0xf0ac, 0xa438, 0xaaf0, 0xa438, 0xacee, 0xa438, 0xf0b0,
        0xa438, 0x24f0, 0xa438, 0xb0a4, 0xa438, 0xf0b1, 0xa438, 0x24f0,
        0xa438, 0xb1a4, 0xa438, 0xee8f, 0xa438, 0xb800, 0xa438, 0xd400,
        0xa438, 0x00af, 0xa438, 0x3976, 0xa438, 0x66ac, 0xa438, 0xeabb,
        0xa438, 0xa430, 0xa438, 0x6e50, 0xa438, 0x6e53, 0xa438, 0x6e56,
        0xa438, 0x6e59, 0xa438, 0x6e5c, 0xa438, 0x6e5f, 0xa438, 0x6e62,
        0xa438, 0x6e65, 0xa438, 0xd9ac, 0xa438, 0x70f0, 0xa438, 0xac6a,
        0xa436, 0xb85e, 0xa438, 0x23b7, 0xa436, 0xb860, 0xa438, 0x74db,
        0xa436, 0xb862, 0xa438, 0x268c, 0xa436, 0xb864, 0xa438, 0x3FE5,
        0xa436, 0xb886, 0xa438, 0x2250, 0xa436, 0xb888, 0xa438, 0x140e,
        0xa436, 0xb88a, 0xa438, 0x3696, 0xa436, 0xb88c, 0xa438, 0x3973,
        0xa436, 0xb838, 0xa438, 0x00ff, 0xb820, 0x0010, 0xa436, 0x8464,
        0xa438, 0xaf84, 0xa438, 0x7caf, 0xa438, 0x8485, 0xa438, 0xaf85,
        0xa438, 0x13af, 0xa438, 0x851e, 0xa438, 0xaf85, 0xa438, 0xb9af,
        0xa438, 0x8684, 0xa438, 0xaf87, 0xa438, 0x01af, 0xa438, 0x8701,
        0xa438, 0xac38, 0xa438, 0x03af, 0xa438, 0x38bb, 0xa438, 0xaf38,
        0xa438, 0xc302, 0xa438, 0x4618, 0xa438, 0xbf85, 0xa438, 0x0a02,
        0xa438, 0x54b7, 0xa438, 0xbf85, 0xa438, 0x1002, 0xa438, 0x54c0,
        0xa438, 0xd400, 0xa438, 0x0fbf, 0xa438, 0x8507, 0xa438, 0x024f,
        0xa438, 0x48bf, 0xa438, 0x8504, 0xa438, 0x024f, 0xa438, 0x6759,
        0xa438, 0xf0a1, 0xa438, 0x3008, 0xa438, 0xbf85, 0xa438, 0x0d02,
        0xa438, 0x54c0, 0xa438, 0xae06, 0xa438, 0xbf85, 0xa438, 0x0d02,
        0xa438, 0x54b7, 0xa438, 0xbf85, 0xa438, 0x0402, 0xa438, 0x4f67,
        0xa438, 0xa183, 0xa438, 0x02ae, 0xa438, 0x15a1, 0xa438, 0x8502,
        0xa438, 0xae10, 0xa438, 0x59f0, 0xa438, 0xa180, 0xa438, 0x16bf,
        0xa438, 0x8501, 0xa438, 0x024f, 0xa438, 0x67a1, 0xa438, 0x381b,
        0xa438, 0xae0b, 0xa438, 0xe18f, 0xa438, 0xffbf, 0xa438, 0x84fe,
        0xa438, 0x024f, 0xa438, 0x48ae, 0xa438, 0x17bf, 0xa438, 0x84fe,
        0xa438, 0x0254, 0xa438, 0xb7bf, 0xa438, 0x84fb, 0xa438, 0x0254,
        0xa438, 0xb7ae, 0xa438, 0x09a1, 0xa438, 0x5006, 0xa438, 0xbf84,
        0xa438, 0xfb02, 0xa438, 0x54c0, 0xa438, 0xaf04, 0xa438, 0x4700,
        0xa438, 0xad34, 0xa438, 0xfdad, 0xa438, 0x0670, 0xa438, 0xae14,
        0xa438, 0xf0a6, 0xa438, 0x00b8, 0xa438, 0xbd32, 0xa438, 0x30bd,
        0xa438, 0x30aa, 0xa438, 0xbd2c, 0xa438, 0xccbd, 0xa438, 0x2ca1,
        0xa438, 0x0705, 0xa438, 0xec80, 0xa438, 0xaf40, 0xa438, 0xf7af,
        0xa438, 0x40f5, 0xa438, 0xd101, 0xa438, 0xbf85, 0xa438, 0xa402,
        0xa438, 0x4f48, 0xa438, 0xbf85, 0xa438, 0xa702, 0xa438, 0x54c0,
        0xa438, 0xd10f, 0xa438, 0xbf85, 0xa438, 0xaa02, 0xa438, 0x4f48,
        0xa438, 0x024d, 0xa438, 0x6abf, 0xa438, 0x85ad, 0xa438, 0x024f,
        0xa438, 0x67bf, 0xa438, 0x8ff7, 0xa438, 0xddbf, 0xa438, 0x85b0,
        0xa438, 0x024f, 0xa438, 0x67bf, 0xa438, 0x8ff8, 0xa438, 0xddbf,
        0xa438, 0x85b3, 0xa438, 0x024f, 0xa438, 0x67bf, 0xa438, 0x8ff9,
        0xa438, 0xddbf, 0xa438, 0x85b6, 0xa438, 0x024f, 0xa438, 0x67bf,
        0xa438, 0x8ffa, 0xa438, 0xddd1, 0xa438, 0x00bf, 0xa438, 0x85aa,
        0xa438, 0x024f, 0xa438, 0x4802, 0xa438, 0x4d6a, 0xa438, 0xbf85,
        0xa438, 0xad02, 0xa438, 0x4f67, 0xa438, 0xbf8f, 0xa438, 0xfbdd,
        0xa438, 0xbf85, 0xa438, 0xb002, 0xa438, 0x4f67, 0xa438, 0xbf8f,
        0xa438, 0xfcdd, 0xa438, 0xbf85, 0xa438, 0xb302, 0xa438, 0x4f67,
        0xa438, 0xbf8f, 0xa438, 0xfddd, 0xa438, 0xbf85, 0xa438, 0xb602,
        0xa438, 0x4f67, 0xa438, 0xbf8f, 0xa438, 0xfedd, 0xa438, 0xbf85,
        0xa438, 0xa702, 0xa438, 0x54b7, 0xa438, 0xbf85, 0xa438, 0xa102,
        0xa438, 0x54b7, 0xa438, 0xaf3c, 0xa438, 0x2066, 0xa438, 0xb800,
        0xa438, 0xb8bd, 0xa438, 0x30ee, 0xa438, 0xbd2c, 0xa438, 0xb8bd,
        0xa438, 0x7040, 0xa438, 0xbd86, 0xa438, 0xc8bd, 0xa438, 0x8640,
        0xa438, 0xbd88, 0xa438, 0xc8bd, 0xa438, 0x8802, 0xa438, 0x1929,
        0xa438, 0xa202, 0xa438, 0x02ae, 0xa438, 0x03a2, 0xa438, 0x032e,
        0xa438, 0xd10f, 0xa438, 0xbf85, 0xa438, 0xaa02, 0xa438, 0x4f48,
        0xa438, 0xe18f, 0xa438, 0xf7bf, 0xa438, 0x85ad, 0xa438, 0x024f,
        0xa438, 0x48e1, 0xa438, 0x8ff8, 0xa438, 0xbf85, 0xa438, 0xb002,
        0xa438, 0x4f48, 0xa438, 0xe18f, 0xa438, 0xf9bf, 0xa438, 0x85b3,
        0xa438, 0x024f, 0xa438, 0x48e1, 0xa438, 0x8ffa, 0xa438, 0xbf85,
        0xa438, 0xb602, 0xa438, 0x4f48, 0xa438, 0xae2c, 0xa438, 0xd100,
        0xa438, 0xbf85, 0xa438, 0xaa02, 0xa438, 0x4f48, 0xa438, 0xe18f,
        0xa438, 0xfbbf, 0xa438, 0x85ad, 0xa438, 0x024f, 0xa438, 0x48e1,
        0xa438, 0x8ffc, 0xa438, 0xbf85, 0xa438, 0xb002, 0xa438, 0x4f48,
        0xa438, 0xe18f, 0xa438, 0xfdbf, 0xa438, 0x85b3, 0xa438, 0x024f,
        0xa438, 0x48e1, 0xa438, 0x8ffe, 0xa438, 0xbf85, 0xa438, 0xb602,
        0xa438, 0x4f48, 0xa438, 0xbf86, 0xa438, 0x7e02, 0xa438, 0x4f67,
        0xa438, 0xa100, 0xa438, 0x02ae, 0xa438, 0x25a1, 0xa438, 0x041d,
        0xa438, 0xe18f, 0xa438, 0xf1bf, 0xa438, 0x8675, 0xa438, 0x024f,
        0xa438, 0x48e1, 0xa438, 0x8ff2, 0xa438, 0xbf86, 0xa438, 0x7802,
        0xa438, 0x4f48, 0xa438, 0xe18f, 0xa438, 0xf3bf, 0xa438, 0x867b,
        0xa438, 0x024f, 0xa438, 0x48ae, 0xa438, 0x29a1, 0xa438, 0x070b,
        0xa438, 0xae24, 0xa438, 0xbf86, 0xa438, 0x8102, 0xa438, 0x4f67,
        0xa438, 0xad28, 0xa438, 0x1be1, 0xa438, 0x8ff4, 0xa438, 0xbf86,
        0xa438, 0x7502, 0xa438, 0x4f48, 0xa438, 0xe18f, 0xa438, 0xf5bf,
        0xa438, 0x8678, 0xa438, 0x024f, 0xa438, 0x48e1, 0xa438, 0x8ff6,
        0xa438, 0xbf86, 0xa438, 0x7b02, 0xa438, 0x4f48, 0xa438, 0xaf09,
        0xa438, 0x8420, 0xa438, 0xbc32, 0xa438, 0x20bc, 0xa438, 0x3e76,
        0xa438, 0xbc08, 0xa438, 0xfda6, 0xa438, 0x1a00, 0xa438, 0xb64e,
        0xa438, 0xd101, 0xa438, 0xbf85, 0xa438, 0xa402, 0xa438, 0x4f48,
        0xa438, 0xbf85, 0xa438, 0xa702, 0xa438, 0x54c0, 0xa438, 0xd10f,
        0xa438, 0xbf85, 0xa438, 0xaa02, 0xa438, 0x4f48, 0xa438, 0x024d,
        0xa438, 0x6abf, 0xa438, 0x85ad, 0xa438, 0x024f, 0xa438, 0x67bf,
        0xa438, 0x8ff7, 0xa438, 0xddbf, 0xa438, 0x85b0, 0xa438, 0x024f,
        0xa438, 0x67bf, 0xa438, 0x8ff8, 0xa438, 0xddbf, 0xa438, 0x85b3,
        0xa438, 0x024f, 0xa438, 0x67bf, 0xa438, 0x8ff9, 0xa438, 0xddbf,
        0xa438, 0x85b6, 0xa438, 0x024f, 0xa438, 0x67bf, 0xa438, 0x8ffa,
        0xa438, 0xddd1, 0xa438, 0x00bf, 0xa438, 0x85aa, 0xa438, 0x024f,
        0xa438, 0x4802, 0xa438, 0x4d6a, 0xa438, 0xbf85, 0xa438, 0xad02,
        0xa438, 0x4f67, 0xa438, 0xbf8f, 0xa438, 0xfbdd, 0xa438, 0xbf85,
        0xa438, 0xb002, 0xa438, 0x4f67, 0xa438, 0xbf8f, 0xa438, 0xfcdd,
        0xa438, 0xbf85, 0xa438, 0xb302, 0xa438, 0x4f67, 0xa438, 0xbf8f,
        0xa438, 0xfddd, 0xa438, 0xbf85, 0xa438, 0xb602, 0xa438, 0x4f67,
        0xa438, 0xbf8f, 0xa438, 0xfedd, 0xa438, 0xbf85, 0xa438, 0xa702,
        0xa438, 0x54b7, 0xa438, 0xaf00, 0xa438, 0x8800, 0xa436, 0xb818,
        0xa438, 0x38b8, 0xa436, 0xb81a, 0xa438, 0x0444, 0xa436, 0xb81c,
        0xa438, 0x40ee, 0xa436, 0xb81e, 0xa438, 0x3C1A, 0xa436, 0xb850,
        0xa438, 0x0981, 0xa436, 0xb852, 0xa438, 0x0085, 0xa436, 0xb878,
        0xa438, 0xffff, 0xa436, 0xb884, 0xa438, 0xffff, 0xa436, 0xb832,
        0xa438, 0x003f, 0xa436, 0x0000, 0xa438, 0x0000, 0xa436, 0xB82E,
        0xa438, 0x0000, 0xa436, 0x8024, 0xa438, 0x0000, 0xb820, 0x0000,
        0xa436, 0x801E, 0xa438, 0x0021, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125b_2[] = {
        0xa436, 0x8024, 0xa438, 0x3701, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x801a, 0xa438, 0x1800, 0xa438, 0x803f,
        0xa438, 0x1800, 0xa438, 0x8045, 0xa438, 0x1800, 0xa438, 0x8067,
        0xa438, 0x1800, 0xa438, 0x806d, 0xa438, 0x1800, 0xa438, 0x8071,
        0xa438, 0x1800, 0xa438, 0x80b1, 0xa438, 0xd093, 0xa438, 0xd1c4,
        0xa438, 0x1000, 0xa438, 0x135c, 0xa438, 0xd704, 0xa438, 0x5fbc,
        0xa438, 0xd504, 0xa438, 0xc9f1, 0xa438, 0x1800, 0xa438, 0x0fc9,
        0xa438, 0xbb50, 0xa438, 0xd505, 0xa438, 0xa202, 0xa438, 0xd504,
        0xa438, 0x8c0f, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1519,
        0xa438, 0x1000, 0xa438, 0x135c, 0xa438, 0xd75e, 0xa438, 0x5fae,
        0xa438, 0x9b50, 0xa438, 0x1000, 0xa438, 0x135c, 0xa438, 0xd75e,
        0xa438, 0x7fae, 0xa438, 0x1000, 0xa438, 0x135c, 0xa438, 0xd707,
        0xa438, 0x40a7, 0xa438, 0xd719, 0xa438, 0x4071, 0xa438, 0x1800,
        0xa438, 0x1557, 0xa438, 0xd719, 0xa438, 0x2f70, 0xa438, 0x803b,
        0xa438, 0x2f73, 0xa438, 0x156a, 0xa438, 0x5e70, 0xa438, 0x1800,
        0xa438, 0x155d, 0xa438, 0xd505, 0xa438, 0xa202, 0xa438, 0xd500,
        0xa438, 0xffed, 0xa438, 0xd709, 0xa438, 0x4054, 0xa438, 0xa788,
        0xa438, 0xd70b, 0xa438, 0x1800, 0xa438, 0x172a, 0xa438, 0xc0c1,
        0xa438, 0xc0c0, 0xa438, 0xd05a, 0xa438, 0xd1ba, 0xa438, 0xd701,
        0xa438, 0x2529, 0xa438, 0x022a, 0xa438, 0xd0a7, 0xa438, 0xd1b9,
        0xa438, 0xa208, 0xa438, 0x1000, 0xa438, 0x080e, 0xa438, 0xd701,
        0xa438, 0x408b, 0xa438, 0x1000, 0xa438, 0x0a65, 0xa438, 0xf003,
        0xa438, 0x1000, 0xa438, 0x0a6b, 0xa438, 0xd701, 0xa438, 0x1000,
        0xa438, 0x0920, 0xa438, 0x1000, 0xa438, 0x0915, 0xa438, 0x1000,
        0xa438, 0x0909, 0xa438, 0x228f, 0xa438, 0x804e, 0xa438, 0x9801,
        0xa438, 0xd71e, 0xa438, 0x5d61, 0xa438, 0xd701, 0xa438, 0x1800,
        0xa438, 0x022a, 0xa438, 0x2005, 0xa438, 0x091a, 0xa438, 0x3bd9,
        0xa438, 0x0919, 0xa438, 0x1800, 0xa438, 0x0916, 0xa438, 0xd090,
        0xa438, 0xd1c9, 0xa438, 0x1800, 0xa438, 0x1064, 0xa438, 0xd096,
        0xa438, 0xd1a9, 0xa438, 0xd503, 0xa438, 0xa104, 0xa438, 0x0c07,
        0xa438, 0x0902, 0xa438, 0xd500, 0xa438, 0xbc10, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0xa201, 0xa438, 0x8201, 0xa438, 0xce00,
        0xa438, 0xd500, 0xa438, 0xc484, 0xa438, 0xd503, 0xa438, 0xcc02,
        0xa438, 0xcd0d, 0xa438, 0xaf01, 0xa438, 0xd500, 0xa438, 0xd703,
        0xa438, 0x4371, 0xa438, 0xbd08, 0xa438, 0x1000, 0xa438, 0x135c,
        0xa438, 0xd75e, 0xa438, 0x5fb3, 0xa438, 0xd503, 0xa438, 0xd0f5,
        0xa438, 0xd1c6, 0xa438, 0x0cf0, 0xa438, 0x0e50, 0xa438, 0xd704,
        0xa438, 0x401c, 0xa438, 0xd0f5, 0xa438, 0xd1c6, 0xa438, 0x0cf0,
        0xa438, 0x0ea0, 0xa438, 0x401c, 0xa438, 0xd07b, 0xa438, 0xd1c5,
        0xa438, 0x8ef0, 0xa438, 0x401c, 0xa438, 0x9d08, 0xa438, 0x1000,
        0xa438, 0x135c, 0xa438, 0xd75e, 0xa438, 0x7fb3, 0xa438, 0x1000,
        0xa438, 0x135c, 0xa438, 0xd75e, 0xa438, 0x5fad, 0xa438, 0x1000,
        0xa438, 0x14c5, 0xa438, 0xd703, 0xa438, 0x3181, 0xa438, 0x80af,
        0xa438, 0x60ad, 0xa438, 0x1000, 0xa438, 0x135c, 0xa438, 0xd703,
        0xa438, 0x5fba, 0xa438, 0x1800, 0xa438, 0x0cc7, 0xa438, 0xa802,
        0xa438, 0xa301, 0xa438, 0xa801, 0xa438, 0xc004, 0xa438, 0xd710,
        0xa438, 0x4000, 0xa438, 0x1800, 0xa438, 0x1e79, 0xa436, 0xA026,
        0xa438, 0x1e78, 0xa436, 0xA024, 0xa438, 0x0c93, 0xa436, 0xA022,
        0xa438, 0x1062, 0xa436, 0xA020, 0xa438, 0x0915, 0xa436, 0xA006,
        0xa438, 0x020a, 0xa436, 0xA004, 0xa438, 0x1726, 0xa436, 0xA002,
        0xa438, 0x1542, 0xa436, 0xA000, 0xa438, 0x0fc7, 0xa436, 0xA008,
        0xa438, 0xff00, 0xa436, 0xA016, 0xa438, 0x0010, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x801d, 0xa438, 0x1800, 0xa438, 0x802c,
        0xa438, 0x1800, 0xa438, 0x802c, 0xa438, 0x1800, 0xa438, 0x802c,
        0xa438, 0x1800, 0xa438, 0x802c, 0xa438, 0x1800, 0xa438, 0x802c,
        0xa438, 0x1800, 0xa438, 0x802c, 0xa438, 0xd700, 0xa438, 0x6090,
        0xa438, 0x60d1, 0xa438, 0xc95c, 0xa438, 0xf007, 0xa438, 0x60b1,
        0xa438, 0xc95a, 0xa438, 0xf004, 0xa438, 0xc956, 0xa438, 0xf002,
        0xa438, 0xc94e, 0xa438, 0x1800, 0xa438, 0x00cd, 0xa438, 0xd700,
        0xa438, 0x6090, 0xa438, 0x60d1, 0xa438, 0xc95c, 0xa438, 0xf007,
        0xa438, 0x60b1, 0xa438, 0xc95a, 0xa438, 0xf004, 0xa438, 0xc956,
        0xa438, 0xf002, 0xa438, 0xc94e, 0xa438, 0x1000, 0xa438, 0x022a,
        0xa438, 0x1800, 0xa438, 0x0132, 0xa436, 0xA08E, 0xa438, 0xffff,
        0xa436, 0xA08C, 0xa438, 0xffff, 0xa436, 0xA08A, 0xa438, 0xffff,
        0xa436, 0xA088, 0xa438, 0xffff, 0xa436, 0xA086, 0xa438, 0xffff,
        0xa436, 0xA084, 0xa438, 0xffff, 0xa436, 0xA082, 0xa438, 0x012f,
        0xa436, 0xA080, 0xa438, 0x00cc, 0xa436, 0xA090, 0xa438, 0x0103,
        0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x0000,
        0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800,
        0xa438, 0x8020, 0xa438, 0x1800, 0xa438, 0x802a, 0xa438, 0x1800,
        0xa438, 0x8035, 0xa438, 0x1800, 0xa438, 0x803c, 0xa438, 0x1800,
        0xa438, 0x803c, 0xa438, 0x1800, 0xa438, 0x803c, 0xa438, 0x1800,
        0xa438, 0x803c, 0xa438, 0xd107, 0xa438, 0xd042, 0xa438, 0xa404,
        0xa438, 0x1000, 0xa438, 0x09df, 0xa438, 0xd700, 0xa438, 0x5fb4,
        0xa438, 0x8280, 0xa438, 0xd700, 0xa438, 0x6065, 0xa438, 0xd125,
        0xa438, 0xf002, 0xa438, 0xd12b, 0xa438, 0xd040, 0xa438, 0x1800,
        0xa438, 0x077f, 0xa438, 0x0cf0, 0xa438, 0x0c50, 0xa438, 0xd104,
        0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x0aa8, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0x1800, 0xa438, 0x0a2e, 0xa438, 0xcb9b,
        0xa438, 0xd110, 0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x0b7b,
        0xa438, 0x1000, 0xa438, 0x09df, 0xa438, 0xd700, 0xa438, 0x5fb4,
        0xa438, 0x1800, 0xa438, 0x081b, 0xa438, 0x1000, 0xa438, 0x09df,
        0xa438, 0xd704, 0xa438, 0x7fb8, 0xa438, 0xa718, 0xa438, 0x1800,
        0xa438, 0x074e, 0xa436, 0xA10E, 0xa438, 0xffff, 0xa436, 0xA10C,
        0xa438, 0xffff, 0xa436, 0xA10A, 0xa438, 0xffff, 0xa436, 0xA108,
        0xa438, 0xffff, 0xa436, 0xA106, 0xa438, 0x074d, 0xa436, 0xA104,
        0xa438, 0x0818, 0xa436, 0xA102, 0xa438, 0x0a2c, 0xa436, 0xA100,
        0xa438, 0x077e, 0xa436, 0xA110, 0xa438, 0x000f, 0xa436, 0xb87c,
        0xa438, 0x8625, 0xa436, 0xb87e, 0xa438, 0xaf86, 0xa438, 0x3daf,
        0xa438, 0x8689, 0xa438, 0xaf88, 0xa438, 0x69af, 0xa438, 0x8887,
        0xa438, 0xaf88, 0xa438, 0x9caf, 0xa438, 0x88be, 0xa438, 0xaf88,
        0xa438, 0xbeaf, 0xa438, 0x88be, 0xa438, 0xbf86, 0xa438, 0x49d7,
        0xa438, 0x0040, 0xa438, 0x0277, 0xa438, 0x7daf, 0xa438, 0x2727,
        0xa438, 0x0000, 0xa438, 0x7205, 0xa438, 0x0000, 0xa438, 0x7208,
        0xa438, 0x0000, 0xa438, 0x71f3, 0xa438, 0x0000, 0xa438, 0x71f6,
        0xa438, 0x0000, 0xa438, 0x7229, 0xa438, 0x0000, 0xa438, 0x722c,
        0xa438, 0x0000, 0xa438, 0x7217, 0xa438, 0x0000, 0xa438, 0x721a,
        0xa438, 0x0000, 0xa438, 0x721d, 0xa438, 0x0000, 0xa438, 0x7211,
        0xa438, 0x0000, 0xa438, 0x7220, 0xa438, 0x0000, 0xa438, 0x7214,
        0xa438, 0x0000, 0xa438, 0x722f, 0xa438, 0x0000, 0xa438, 0x7223,
        0xa438, 0x0000, 0xa438, 0x7232, 0xa438, 0x0000, 0xa438, 0x7226,
        0xa438, 0xf8f9, 0xa438, 0xfae0, 0xa438, 0x85b3, 0xa438, 0x3802,
        0xa438, 0xad27, 0xa438, 0x02ae, 0xa438, 0x03af, 0xa438, 0x8830,
        0xa438, 0x1f66, 0xa438, 0xef65, 0xa438, 0xbfc2, 0xa438, 0x1f1a,
        0xa438, 0x96f7, 0xa438, 0x05ee, 0xa438, 0xffd2, 0xa438, 0x00da,
        0xa438, 0xf605, 0xa438, 0xbfc2, 0xa438, 0x2f1a, 0xa438, 0x96f7,
        0xa438, 0x05ee, 0xa438, 0xffd2, 0xa438, 0x00db, 0xa438, 0xf605,
        0xa438, 0xef02, 0xa438, 0x1f11, 0xa438, 0x0d42, 0xa438, 0xbf88,
        0xa438, 0x4202, 0xa438, 0x6e7d, 0xa438, 0xef02, 0xa438, 0x1b03,
        0xa438, 0x1f11, 0xa438, 0x0d42, 0xa438, 0xbf88, 0xa438, 0x4502,
        0xa438, 0x6e7d, 0xa438, 0xef02, 0xa438, 0x1a03, 0xa438, 0x1f11,
        0xa438, 0x0d42, 0xa438, 0xbf88, 0xa438, 0x4802, 0xa438, 0x6e7d,
        0xa438, 0xbfc2, 0xa438, 0x3f1a, 0xa438, 0x96f7, 0xa438, 0x05ee,
        0xa438, 0xffd2, 0xa438, 0x00da, 0xa438, 0xf605, 0xa438, 0xbfc2,
        0xa438, 0x4f1a, 0xa438, 0x96f7, 0xa438, 0x05ee, 0xa438, 0xffd2,
        0xa438, 0x00db, 0xa438, 0xf605, 0xa438, 0xef02, 0xa438, 0x1f11,
        0xa438, 0x0d42, 0xa438, 0xbf88, 0xa438, 0x4b02, 0xa438, 0x6e7d,
        0xa438, 0xef02, 0xa438, 0x1b03, 0xa438, 0x1f11, 0xa438, 0x0d42,
        0xa438, 0xbf88, 0xa438, 0x4e02, 0xa438, 0x6e7d, 0xa438, 0xef02,
        0xa438, 0x1a03, 0xa438, 0x1f11, 0xa438, 0x0d42, 0xa438, 0xbf88,
        0xa438, 0x5102, 0xa438, 0x6e7d, 0xa438, 0xef56, 0xa438, 0xd020,
        0xa438, 0x1f11, 0xa438, 0xbf88, 0xa438, 0x5402, 0xa438, 0x6e7d,
        0xa438, 0xbf88, 0xa438, 0x5702, 0xa438, 0x6e7d, 0xa438, 0xbf88,
        0xa438, 0x5a02, 0xa438, 0x6e7d, 0xa438, 0xe185, 0xa438, 0xa0ef,
        0xa438, 0x0348, 0xa438, 0x0a28, 0xa438, 0x05ef, 0xa438, 0x201b,
        0xa438, 0x01ad, 0xa438, 0x2735, 0xa438, 0x1f44, 0xa438, 0xe085,
        0xa438, 0x88e1, 0xa438, 0x8589, 0xa438, 0xbf88, 0xa438, 0x5d02,
        0xa438, 0x6e7d, 0xa438, 0xe085, 0xa438, 0x8ee1, 0xa438, 0x858f,
        0xa438, 0xbf88, 0xa438, 0x6002, 0xa438, 0x6e7d, 0xa438, 0xe085,
        0xa438, 0x94e1, 0xa438, 0x8595, 0xa438, 0xbf88, 0xa438, 0x6302,
        0xa438, 0x6e7d, 0xa438, 0xe085, 0xa438, 0x9ae1, 0xa438, 0x859b,
        0xa438, 0xbf88, 0xa438, 0x6602, 0xa438, 0x6e7d, 0xa438, 0xaf88,
        0xa438, 0x3cbf, 0xa438, 0x883f, 0xa438, 0x026e, 0xa438, 0x9cad,
        0xa438, 0x2835, 0xa438, 0x1f44, 0xa438, 0xe08f, 0xa438, 0xf8e1,
        0xa438, 0x8ff9, 0xa438, 0xbf88, 0xa438, 0x5d02, 0xa438, 0x6e7d,
        0xa438, 0xe08f, 0xa438, 0xfae1, 0xa438, 0x8ffb, 0xa438, 0xbf88,
        0xa438, 0x6002, 0xa438, 0x6e7d, 0xa438, 0xe08f, 0xa438, 0xfce1,
        0xa438, 0x8ffd, 0xa438, 0xbf88, 0xa438, 0x6302, 0xa438, 0x6e7d,
        0xa438, 0xe08f, 0xa438, 0xfee1, 0xa438, 0x8fff, 0xa438, 0xbf88,
        0xa438, 0x6602, 0xa438, 0x6e7d, 0xa438, 0xaf88, 0xa438, 0x3ce1,
        0xa438, 0x85a1, 0xa438, 0x1b21, 0xa438, 0xad37, 0xa438, 0x341f,
        0xa438, 0x44e0, 0xa438, 0x858a, 0xa438, 0xe185, 0xa438, 0x8bbf,
        0xa438, 0x885d, 0xa438, 0x026e, 0xa438, 0x7de0, 0xa438, 0x8590,
        0xa438, 0xe185, 0xa438, 0x91bf, 0xa438, 0x8860, 0xa438, 0x026e,
        0xa438, 0x7de0, 0xa438, 0x8596, 0xa438, 0xe185, 0xa438, 0x97bf,
        0xa438, 0x8863, 0xa438, 0x026e, 0xa438, 0x7de0, 0xa438, 0x859c,
        0xa438, 0xe185, 0xa438, 0x9dbf, 0xa438, 0x8866, 0xa438, 0x026e,
        0xa438, 0x7dae, 0xa438, 0x401f, 0xa438, 0x44e0, 0xa438, 0x858c,
        0xa438, 0xe185, 0xa438, 0x8dbf, 0xa438, 0x885d, 0xa438, 0x026e,
        0xa438, 0x7de0, 0xa438, 0x8592, 0xa438, 0xe185, 0xa438, 0x93bf,
        0xa438, 0x8860, 0xa438, 0x026e, 0xa438, 0x7de0, 0xa438, 0x8598,
        0xa438, 0xe185, 0xa438, 0x99bf, 0xa438, 0x8863, 0xa438, 0x026e,
        0xa438, 0x7de0, 0xa438, 0x859e, 0xa438, 0xe185, 0xa438, 0x9fbf,
        0xa438, 0x8866, 0xa438, 0x026e, 0xa438, 0x7dae, 0xa438, 0x0ce1,
        0xa438, 0x85b3, 0xa438, 0x3904, 0xa438, 0xac2f, 0xa438, 0x04ee,
        0xa438, 0x85b3, 0xa438, 0x00af, 0xa438, 0x39d9, 0xa438, 0x22ac,
        0xa438, 0xeaf0, 0xa438, 0xacf6, 0xa438, 0xf0ac, 0xa438, 0xfaf0,
        0xa438, 0xacf8, 0xa438, 0xf0ac, 0xa438, 0xfcf0, 0xa438, 0xad00,
        0xa438, 0xf0ac, 0xa438, 0xfef0, 0xa438, 0xacf0, 0xa438, 0xf0ac,
        0xa438, 0xf4f0, 0xa438, 0xacf2, 0xa438, 0xf0ac, 0xa438, 0xb0f0,
        0xa438, 0xacae, 0xa438, 0xf0ac, 0xa438, 0xacf0, 0xa438, 0xacaa,
        0xa438, 0xa100, 0xa438, 0x0ce1, 0xa438, 0x8ff7, 0xa438, 0xbf88,
        0xa438, 0x8402, 0xa438, 0x6e7d, 0xa438, 0xaf26, 0xa438, 0xe9e1,
        0xa438, 0x8ff6, 0xa438, 0xbf88, 0xa438, 0x8402, 0xa438, 0x6e7d,
        0xa438, 0xaf26, 0xa438, 0xf520, 0xa438, 0xac86, 0xa438, 0xbf88,
        0xa438, 0x3f02, 0xa438, 0x6e9c, 0xa438, 0xad28, 0xa438, 0x03af,
        0xa438, 0x3324, 0xa438, 0xad38, 0xa438, 0x03af, 0xa438, 0x32e6,
        0xa438, 0xaf32, 0xa438, 0xfbee, 0xa438, 0x826a, 0xa438, 0x0002,
        0xa438, 0x88a6, 0xa438, 0xaf04, 0xa438, 0x78f8, 0xa438, 0xfaef,
        0xa438, 0x69e0, 0xa438, 0x8015, 0xa438, 0xad20, 0xa438, 0x06bf,
        0xa438, 0x88bb, 0xa438, 0x0275, 0xa438, 0xb1ef, 0xa438, 0x96fe,
        0xa438, 0xfc04, 0xa438, 0x00b8, 0xa438, 0x7a00, 0xa436, 0xb87c,
        0xa438, 0x8ff6, 0xa436, 0xb87e, 0xa438, 0x0705, 0xa436, 0xb87c,
        0xa438, 0x8ff8, 0xa436, 0xb87e, 0xa438, 0x19cc, 0xa436, 0xb87c,
        0xa438, 0x8ffa, 0xa436, 0xb87e, 0xa438, 0x28e3, 0xa436, 0xb87c,
        0xa438, 0x8ffc, 0xa436, 0xb87e, 0xa438, 0x1047, 0xa436, 0xb87c,
        0xa438, 0x8ffe, 0xa436, 0xb87e, 0xa438, 0x0a45, 0xa436, 0xb85e,
        0xa438, 0x271E, 0xa436, 0xb860, 0xa438, 0x3846, 0xa436, 0xb862,
        0xa438, 0x26E6, 0xa436, 0xb864, 0xa438, 0x32E3, 0xa436, 0xb886,
        0xa438, 0x0474, 0xa436, 0xb888, 0xa438, 0xffff, 0xa436, 0xb88a,
        0xa438, 0xffff, 0xa436, 0xb88c, 0xa438, 0xffff, 0xa436, 0xb838,
        0xa438, 0x001f, 0xb820, 0x0010, 0xa436, 0x846e, 0xa438, 0xaf84,
        0xa438, 0x86af, 0xa438, 0x8690, 0xa438, 0xaf86, 0xa438, 0xa4af,
        0xa438, 0x8934, 0xa438, 0xaf89, 0xa438, 0x60af, 0xa438, 0x897e,
        0xa438, 0xaf89, 0xa438, 0xa9af, 0xa438, 0x89a9, 0xa438, 0xee82,
        0xa438, 0x5f00, 0xa438, 0x0284, 0xa438, 0x90af, 0xa438, 0x0441,
        0xa438, 0xf8e0, 0xa438, 0x8ff3, 0xa438, 0xa000, 0xa438, 0x0502,
        0xa438, 0x84a4, 0xa438, 0xae06, 0xa438, 0xa001, 0xa438, 0x0302,
        0xa438, 0x84c8, 0xa438, 0xfc04, 0xa438, 0xf8f9, 0xa438, 0xef59,
        0xa438, 0xe080, 0xa438, 0x15ad, 0xa438, 0x2702, 0xa438, 0xae03,
        0xa438, 0xaf84, 0xa438, 0xc3bf, 0xa438, 0x53ca, 0xa438, 0x0252,
        0xa438, 0xc8ad, 0xa438, 0x2807, 0xa438, 0x0285, 0xa438, 0x2cee,
        0xa438, 0x8ff3, 0xa438, 0x01ef, 0xa438, 0x95fd, 0xa438, 0xfc04,
        0xa438, 0xf8f9, 0xa438, 0xfaef, 0xa438, 0x69bf, 0xa438, 0x53ca,
        0xa438, 0x0252, 0xa438, 0xc8ac, 0xa438, 0x2822, 0xa438, 0xd480,
        0xa438, 0x00bf, 0xa438, 0x8684, 0xa438, 0x0252, 0xa438, 0xa9bf,
        0xa438, 0x8687, 0xa438, 0x0252, 0xa438, 0xa9bf, 0xa438, 0x868a,
        0xa438, 0x0252, 0xa438, 0xa9bf, 0xa438, 0x868d, 0xa438, 0x0252,
        0xa438, 0xa9ee, 0xa438, 0x8ff3, 0xa438, 0x00af, 0xa438, 0x8526,
        0xa438, 0xe08f, 0xa438, 0xf4e1, 0xa438, 0x8ff5, 0xa438, 0xe28f,
        0xa438, 0xf6e3, 0xa438, 0x8ff7, 0xa438, 0x1b45, 0xa438, 0xac27,
        0xa438, 0x0eee, 0xa438, 0x8ff4, 0xa438, 0x00ee, 0xa438, 0x8ff5,
        0xa438, 0x0002, 0xa438, 0x852c, 0xa438, 0xaf85, 0xa438, 0x26e0,
        0xa438, 0x8ff4, 0xa438, 0xe18f, 0xa438, 0xf52c, 0xa438, 0x0001,
        0xa438, 0xe48f, 0xa438, 0xf4e5, 0xa438, 0x8ff5, 0xa438, 0xef96,
        0xa438, 0xfefd, 0xa438, 0xfc04, 0xa438, 0xf8f9, 0xa438, 0xef59,
        0xa438, 0xbf53, 0xa438, 0x2202, 0xa438, 0x52c8, 0xa438, 0xa18b,
        0xa438, 0x02ae, 0xa438, 0x03af, 0xa438, 0x85da, 0xa438, 0xbf57,
        0xa438, 0x7202, 0xa438, 0x52c8, 0xa438, 0xe48f, 0xa438, 0xf8e5,
        0xa438, 0x8ff9, 0xa438, 0xbf57, 0xa438, 0x7502, 0xa438, 0x52c8,
        0xa438, 0xe48f, 0xa438, 0xfae5, 0xa438, 0x8ffb, 0xa438, 0xbf57,
        0xa438, 0x7802, 0xa438, 0x52c8, 0xa438, 0xe48f, 0xa438, 0xfce5,
        0xa438, 0x8ffd, 0xa438, 0xbf57, 0xa438, 0x7b02, 0xa438, 0x52c8,
        0xa438, 0xe48f, 0xa438, 0xfee5, 0xa438, 0x8fff, 0xa438, 0xbf57,
        0xa438, 0x6c02, 0xa438, 0x52c8, 0xa438, 0xa102, 0xa438, 0x13ee,
        0xa438, 0x8ffc, 0xa438, 0x80ee, 0xa438, 0x8ffd, 0xa438, 0x00ee,
        0xa438, 0x8ffe, 0xa438, 0x80ee, 0xa438, 0x8fff, 0xa438, 0x00af,
        0xa438, 0x8599, 0xa438, 0xa101, 0xa438, 0x0cbf, 0xa438, 0x534c,
        0xa438, 0x0252, 0xa438, 0xc8a1, 0xa438, 0x0303, 0xa438, 0xaf85,
        0xa438, 0x77bf, 0xa438, 0x5322, 0xa438, 0x0252, 0xa438, 0xc8a1,
        0xa438, 0x8b02, 0xa438, 0xae03, 0xa438, 0xaf86, 0xa438, 0x64e0,
        0xa438, 0x8ff8, 0xa438, 0xe18f, 0xa438, 0xf9bf, 0xa438, 0x8684,
        0xa438, 0x0252, 0xa438, 0xa9e0, 0xa438, 0x8ffa, 0xa438, 0xe18f,
        0xa438, 0xfbbf, 0xa438, 0x8687, 0xa438, 0x0252, 0xa438, 0xa9e0,
        0xa438, 0x8ffc, 0xa438, 0xe18f, 0xa438, 0xfdbf, 0xa438, 0x868a,
        0xa438, 0x0252, 0xa438, 0xa9e0, 0xa438, 0x8ffe, 0xa438, 0xe18f,
        0xa438, 0xffbf, 0xa438, 0x868d, 0xa438, 0x0252, 0xa438, 0xa9af,
        0xa438, 0x867f, 0xa438, 0xbf53, 0xa438, 0x2202, 0xa438, 0x52c8,
        0xa438, 0xa144, 0xa438, 0x3cbf, 0xa438, 0x547b, 0xa438, 0x0252,
        0xa438, 0xc8e4, 0xa438, 0x8ff8, 0xa438, 0xe58f, 0xa438, 0xf9bf,
        0xa438, 0x547e, 0xa438, 0x0252, 0xa438, 0xc8e4, 0xa438, 0x8ffa,
        0xa438, 0xe58f, 0xa438, 0xfbbf, 0xa438, 0x5481, 0xa438, 0x0252,
        0xa438, 0xc8e4, 0xa438, 0x8ffc, 0xa438, 0xe58f, 0xa438, 0xfdbf,
        0xa438, 0x5484, 0xa438, 0x0252, 0xa438, 0xc8e4, 0xa438, 0x8ffe,
        0xa438, 0xe58f, 0xa438, 0xffbf, 0xa438, 0x5322, 0xa438, 0x0252,
        0xa438, 0xc8a1, 0xa438, 0x4448, 0xa438, 0xaf85, 0xa438, 0xa7bf,
        0xa438, 0x5322, 0xa438, 0x0252, 0xa438, 0xc8a1, 0xa438, 0x313c,
        0xa438, 0xbf54, 0xa438, 0x7b02, 0xa438, 0x52c8, 0xa438, 0xe48f,
        0xa438, 0xf8e5, 0xa438, 0x8ff9, 0xa438, 0xbf54, 0xa438, 0x7e02,
        0xa438, 0x52c8, 0xa438, 0xe48f, 0xa438, 0xfae5, 0xa438, 0x8ffb,
        0xa438, 0xbf54, 0xa438, 0x8102, 0xa438, 0x52c8, 0xa438, 0xe48f,
        0xa438, 0xfce5, 0xa438, 0x8ffd, 0xa438, 0xbf54, 0xa438, 0x8402,
        0xa438, 0x52c8, 0xa438, 0xe48f, 0xa438, 0xfee5, 0xa438, 0x8fff,
        0xa438, 0xbf53, 0xa438, 0x2202, 0xa438, 0x52c8, 0xa438, 0xa131,
        0xa438, 0x03af, 0xa438, 0x85a7, 0xa438, 0xd480, 0xa438, 0x00bf,
        0xa438, 0x8684, 0xa438, 0x0252, 0xa438, 0xa9bf, 0xa438, 0x8687,
        0xa438, 0x0252, 0xa438, 0xa9bf, 0xa438, 0x868a, 0xa438, 0x0252,
        0xa438, 0xa9bf, 0xa438, 0x868d, 0xa438, 0x0252, 0xa438, 0xa9ef,
        0xa438, 0x95fd, 0xa438, 0xfc04, 0xa438, 0xf0d1, 0xa438, 0x2af0,
        0xa438, 0xd12c, 0xa438, 0xf0d1, 0xa438, 0x44f0, 0xa438, 0xd146,
        0xa438, 0xbf86, 0xa438, 0xa102, 0xa438, 0x52c8, 0xa438, 0xbf86,
        0xa438, 0xa102, 0xa438, 0x52c8, 0xa438, 0xd101, 0xa438, 0xaf06,
        0xa438, 0xa570, 0xa438, 0xce42, 0xa438, 0xee83, 0xa438, 0xc800,
        0xa438, 0x0286, 0xa438, 0xba02, 0xa438, 0x8728, 0xa438, 0x0287,
        0xa438, 0xbe02, 0xa438, 0x87f9, 0xa438, 0x0288, 0xa438, 0xc3af,
        0xa438, 0x4771, 0xa438, 0xf8f9, 0xa438, 0xfafb, 0xa438, 0xef69,
        0xa438, 0xfae0, 0xa438, 0x8015, 0xa438, 0xad25, 0xa438, 0x45d2,
        0xa438, 0x0002, 0xa438, 0x8714, 0xa438, 0xac4f, 0xa438, 0x02ae,
        0xa438, 0x0bef, 0xa438, 0x46f6, 0xa438, 0x273c, 0xa438, 0x0400,
        0xa438, 0xab26, 0xa438, 0xae30, 0xa438, 0xe08f, 0xa438, 0xe9e1,
        0xa438, 0x8fea, 0xa438, 0x1b46, 0xa438, 0xab26, 0xa438, 0xef32,
        0xa438, 0x0c31, 0xa438, 0xbf8f, 0xa438, 0xe91a, 0xa438, 0x93d8,
        0xa438, 0x19d9, 0xa438, 0x1b46, 0xa438, 0xab0a, 0xa438, 0x19d8,
        0xa438, 0x19d9, 0xa438, 0x1b46, 0xa438, 0xaa02, 0xa438, 0xae0c,
        0xa438, 0xbf57, 0xa438, 0x1202, 0xa438, 0x58b1, 0xa438, 0xbf57,
        0xa438, 0x1202, 0xa438, 0x58a8, 0xa438, 0xfeef, 0xa438, 0x96ff,
        0xa438, 0xfefd, 0xa438, 0xfc04, 0xa438, 0xf8fb, 0xa438, 0xef79,
        0xa438, 0xa200, 0xa438, 0x08bf, 0xa438, 0x892e, 0xa438, 0x0252,
        0xa438, 0xc8ef, 0xa438, 0x64ef, 0xa438, 0x97ff, 0xa438, 0xfc04,
        0xa438, 0xf8f9, 0xa438, 0xfafb, 0xa438, 0xef69, 0xa438, 0xfae0,
        0xa438, 0x8015, 0xa438, 0xad25, 0xa438, 0x50d2, 0xa438, 0x0002,
        0xa438, 0x878d, 0xa438, 0xac4f, 0xa438, 0x02ae, 0xa438, 0x0bef,
        0xa438, 0x46f6, 0xa438, 0x273c, 0xa438, 0x1000, 0xa438, 0xab31,
        0xa438, 0xae29, 0xa438, 0xe08f, 0xa438, 0xede1, 0xa438, 0x8fee,
        0xa438, 0x1b46, 0xa438, 0xab1f, 0xa438, 0xa200, 0xa438, 0x04ef,
        0xa438, 0x32ae, 0xa438, 0x02d3, 0xa438, 0x010c, 0xa438, 0x31bf,
        0xa438, 0x8fed, 0xa438, 0x1a93, 0xa438, 0xd819, 0xa438, 0xd91b,
        0xa438, 0x46ab, 0xa438, 0x0e19, 0xa438, 0xd819, 0xa438, 0xd91b,
        0xa438, 0x46aa, 0xa438, 0x0612, 0xa438, 0xa205, 0xa438, 0xc0ae,
        0xa438, 0x0cbf, 0xa438, 0x5712, 0xa438, 0x0258, 0xa438, 0xb1bf,
        0xa438, 0x5712, 0xa438, 0x0258, 0xa438, 0xa8fe, 0xa438, 0xef96,
        0xa438, 0xfffe, 0xa438, 0xfdfc, 0xa438, 0x04f8, 0xa438, 0xfbef,
        0xa438, 0x79a2, 0xa438, 0x0005, 0xa438, 0xbf89, 0xa438, 0x1fae,
        0xa438, 0x1ba2, 0xa438, 0x0105, 0xa438, 0xbf89, 0xa438, 0x22ae,
        0xa438, 0x13a2, 0xa438, 0x0205, 0xa438, 0xbf89, 0xa438, 0x25ae,
        0xa438, 0x0ba2, 0xa438, 0x0305, 0xa438, 0xbf89, 0xa438, 0x28ae,
        0xa438, 0x03bf, 0xa438, 0x892b, 0xa438, 0x0252, 0xa438, 0xc8ef,
        0xa438, 0x64ef, 0xa438, 0x97ff, 0xa438, 0xfc04, 0xa438, 0xf8f9,
        0xa438, 0xfaef, 0xa438, 0x69fa, 0xa438, 0xe080, 0xa438, 0x15ad,
        0xa438, 0x2628, 0xa438, 0xe081, 0xa438, 0xabe1, 0xa438, 0x81ac,
        0xa438, 0xef64, 0xa438, 0xbf57, 0xa438, 0x1802, 0xa438, 0x52c8,
        0xa438, 0x1b46, 0xa438, 0xaa0a, 0xa438, 0xbf57, 0xa438, 0x1b02,
        0xa438, 0x52c8, 0xa438, 0x1b46, 0xa438, 0xab0c, 0xa438, 0xbf57,
        0xa438, 0x1502, 0xa438, 0x58b1, 0xa438, 0xbf57, 0xa438, 0x1502,
        0xa438, 0x58a8, 0xa438, 0xfeef, 0xa438, 0x96fe, 0xa438, 0xfdfc,
        0xa438, 0x04f8, 0xa438, 0xf9ef, 0xa438, 0x59f9, 0xa438, 0xe080,
        0xa438, 0x15ad, 0xa438, 0x2622, 0xa438, 0xbf53, 0xa438, 0x2202,
        0xa438, 0x52c8, 0xa438, 0x3972, 0xa438, 0x9e10, 0xa438, 0xe083,
        0xa438, 0xc9ac, 0xa438, 0x2605, 0xa438, 0x0288, 0xa438, 0x2cae,
        0xa438, 0x0d02, 0xa438, 0x8870, 0xa438, 0xae08, 0xa438, 0xe283,
        0xa438, 0xc9f6, 0xa438, 0x36e6, 0xa438, 0x83c9, 0xa438, 0xfdef,
        0xa438, 0x95fd, 0xa438, 0xfc04, 0xa438, 0xf8f9, 0xa438, 0xfafb,
        0xa438, 0xef79, 0xa438, 0xfbbf, 0xa438, 0x5718, 0xa438, 0x0252,
        0xa438, 0xc8ef, 0xa438, 0x64e2, 0xa438, 0x8fe5, 0xa438, 0xe38f,
        0xa438, 0xe61b, 0xa438, 0x659e, 0xa438, 0x10e4, 0xa438, 0x8fe5,
        0xa438, 0xe58f, 0xa438, 0xe6e2, 0xa438, 0x83c9, 0xa438, 0xf636,
        0xa438, 0xe683, 0xa438, 0xc9ae, 0xa438, 0x13e2, 0xa438, 0x83c9,
        0xa438, 0xf736, 0xa438, 0xe683, 0xa438, 0xc902, 0xa438, 0x5820,
        0xa438, 0xef57, 0xa438, 0xe68f, 0xa438, 0xe7e7, 0xa438, 0x8fe8,
        0xa438, 0xffef, 0xa438, 0x97ff, 0xa438, 0xfefd, 0xa438, 0xfc04,
        0xa438, 0xf8f9, 0xa438, 0xfafb, 0xa438, 0xef79, 0xa438, 0xfbe2,
        0xa438, 0x8fe7, 0xa438, 0xe38f, 0xa438, 0xe8ef, 0xa438, 0x65e2,
        0xa438, 0x81b8, 0xa438, 0xe381, 0xa438, 0xb9ef, 0xa438, 0x7502,
        0xa438, 0x583b, 0xa438, 0xac50, 0xa438, 0x1abf, 0xa438, 0x5718,
        0xa438, 0x0252, 0xa438, 0xc8ef, 0xa438, 0x64e2, 0xa438, 0x8fe5,
        0xa438, 0xe38f, 0xa438, 0xe61b, 0xa438, 0x659e, 0xa438, 0x1ce4,
        0xa438, 0x8fe5, 0xa438, 0xe58f, 0xa438, 0xe6ae, 0xa438, 0x0cbf,
        0xa438, 0x5715, 0xa438, 0x0258, 0xa438, 0xb1bf, 0xa438, 0x5715,
        0xa438, 0x0258, 0xa438, 0xa8e2, 0xa438, 0x83c9, 0xa438, 0xf636,
        0xa438, 0xe683, 0xa438, 0xc9ff, 0xa438, 0xef97, 0xa438, 0xfffe,
        0xa438, 0xfdfc, 0xa438, 0x04f8, 0xa438, 0xf9fa, 0xa438, 0xef69,
        0xa438, 0xe080, 0xa438, 0x15ad, 0xa438, 0x264b, 0xa438, 0xbf53,
        0xa438, 0xca02, 0xa438, 0x52c8, 0xa438, 0xad28, 0xa438, 0x42bf,
        0xa438, 0x8931, 0xa438, 0x0252, 0xa438, 0xc8ef, 0xa438, 0x54bf,
        0xa438, 0x576c, 0xa438, 0x0252, 0xa438, 0xc8a1, 0xa438, 0x001b,
        0xa438, 0xbf53, 0xa438, 0x4c02, 0xa438, 0x52c8, 0xa438, 0xac29,
        0xa438, 0x0dac, 0xa438, 0x2805, 0xa438, 0xa302, 0xa438, 0x16ae,
        0xa438, 0x20a3, 0xa438, 0x0311, 0xa438, 0xae1b, 0xa438, 0xa304,
        0xa438, 0x0cae, 0xa438, 0x16a3, 0xa438, 0x0802, 0xa438, 0xae11,
        0xa438, 0xa309, 0xa438, 0x02ae, 0xa438, 0x0cbf, 0xa438, 0x5715,
        0xa438, 0x0258, 0xa438, 0xb1bf, 0xa438, 0x5715, 0xa438, 0x0258,
        0xa438, 0xa8ef, 0xa438, 0x96fe, 0xa438, 0xfdfc, 0xa438, 0x04f0,
        0xa438, 0xa300, 0xa438, 0xf0a3, 0xa438, 0x02f0, 0xa438, 0xa304,
        0xa438, 0xf0a3, 0xa438, 0x06f0, 0xa438, 0xa308, 0xa438, 0xf0a2,
        0xa438, 0x8074, 0xa438, 0xa600, 0xa438, 0xac4f, 0xa438, 0x02ae,
        0xa438, 0x0bef, 0xa438, 0x46f6, 0xa438, 0x273c, 0xa438, 0x1000,
        0xa438, 0xab1b, 0xa438, 0xae16, 0xa438, 0xe081, 0xa438, 0xabe1,
        0xa438, 0x81ac, 0xa438, 0x1b46, 0xa438, 0xab0c, 0xa438, 0xac32,
        0xa438, 0x04ef, 0xa438, 0x32ae, 0xa438, 0x02d3, 0xa438, 0x04af,
        0xa438, 0x486c, 0xa438, 0xaf48, 0xa438, 0x82af, 0xa438, 0x4888,
        0xa438, 0xe081, 0xa438, 0x9be1, 0xa438, 0x819c, 0xa438, 0xe28f,
        0xa438, 0xe3ad, 0xa438, 0x3009, 0xa438, 0x1f55, 0xa438, 0xe38f,
        0xa438, 0xe20c, 0xa438, 0x581a, 0xa438, 0x45e4, 0xa438, 0x83a6,
        0xa438, 0xe583, 0xa438, 0xa7af, 0xa438, 0x2a75, 0xa438, 0xe08f,
        0xa438, 0xe3ad, 0xa438, 0x201c, 0xa438, 0x1f44, 0xa438, 0xe18f,
        0xa438, 0xe10c, 0xa438, 0x44ef, 0xa438, 0x64e0, 0xa438, 0x8232,
        0xa438, 0xe182, 0xa438, 0x331b, 0xa438, 0x649f, 0xa438, 0x091f,
        0xa438, 0x44e1, 0xa438, 0x8fe2, 0xa438, 0x0c48, 0xa438, 0x1b54,
        0xa438, 0xe683, 0xa438, 0xa6e7, 0xa438, 0x83a7, 0xa438, 0xaf2b,
        0xa438, 0xd900, 0xa436, 0xb818, 0xa438, 0x043d, 0xa436, 0xb81a,
        0xa438, 0x06a3, 0xa436, 0xb81c, 0xa438, 0x476d, 0xa436, 0xb81e,
        0xa438, 0x4852, 0xa436, 0xb850, 0xa438, 0x2A69, 0xa436, 0xb852,
        0xa438, 0x2BD3, 0xa436, 0xb878, 0xa438, 0xffff, 0xa436, 0xb884,
        0xa438, 0xffff, 0xa436, 0xb832, 0xa438, 0x003f, 0xb844, 0xffff,
        0xa436, 0x8fe9, 0xa438, 0x0000, 0xa436, 0x8feb, 0xa438, 0x02fe,
        0xa436, 0x8fed, 0xa438, 0x0019, 0xa436, 0x8fef, 0xa438, 0x0bdb,
        0xa436, 0x8ff1, 0xa438, 0x0ca4, 0xa436, 0x0000, 0xa438, 0x0000,
        0xa436, 0xB82E, 0xa438, 0x0000, 0xa436, 0x8024, 0xa438, 0x0000,
        0xa436, 0x801E, 0xa438, 0x0024, 0xb820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16  phy_mcu_ram_code_8125d_1_1[] = {
        0xa436, 0x8023, 0xa438, 0x3800, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x8018, 0xa438, 0x1800, 0xa438, 0x8021,
        0xa438, 0x1800, 0xa438, 0x8029, 0xa438, 0x1800, 0xa438, 0x8031,
        0xa438, 0x1800, 0xa438, 0x8035, 0xa438, 0x1800, 0xa438, 0x819c,
        0xa438, 0x1800, 0xa438, 0x81e9, 0xa438, 0xd711, 0xa438, 0x6081,
        0xa438, 0x8904, 0xa438, 0x1800, 0xa438, 0x2021, 0xa438, 0xa904,
        0xa438, 0x1800, 0xa438, 0x2021, 0xa438, 0xd75f, 0xa438, 0x4083,
        0xa438, 0xd503, 0xa438, 0xa908, 0xa438, 0x87f0, 0xa438, 0x1000,
        0xa438, 0x17e0, 0xa438, 0x1800, 0xa438, 0x13c3, 0xa438, 0xd707,
        0xa438, 0x2005, 0xa438, 0x8027, 0xa438, 0xd75e, 0xa438, 0x1800,
        0xa438, 0x1434, 0xa438, 0x1800, 0xa438, 0x14a5, 0xa438, 0xc504,
        0xa438, 0xce20, 0xa438, 0xcf01, 0xa438, 0xd70a, 0xa438, 0x4005,
        0xa438, 0xcf02, 0xa438, 0x1800, 0xa438, 0x1c50, 0xa438, 0xa980,
        0xa438, 0xd500, 0xa438, 0x1800, 0xa438, 0x14f3, 0xa438, 0xd75e,
        0xa438, 0x67b1, 0xa438, 0xd504, 0xa438, 0xd71e, 0xa438, 0x65bb,
        0xa438, 0x63da, 0xa438, 0x61f9, 0xa438, 0x0cf0, 0xa438, 0x0c10,
        0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0808, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0x0cf0, 0xa438, 0x0470, 0xa438, 0x0cf0,
        0xa438, 0x0430, 0xa438, 0x0cf0, 0xa438, 0x0410, 0xa438, 0xf02a,
        0xa438, 0x0cf0, 0xa438, 0x0c20, 0xa438, 0xd505, 0xa438, 0x0c0f,
        0xa438, 0x0804, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0x0cf0,
        0xa438, 0x0470, 0xa438, 0x0cf0, 0xa438, 0x0430, 0xa438, 0x0cf0,
        0xa438, 0x0420, 0xa438, 0xf01c, 0xa438, 0x0cf0, 0xa438, 0x0c40,
        0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0802, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0x0cf0, 0xa438, 0x0470, 0xa438, 0x0cf0,
        0xa438, 0x0450, 0xa438, 0x0cf0, 0xa438, 0x0440, 0xa438, 0xf00e,
        0xa438, 0x0cf0, 0xa438, 0x0c80, 0xa438, 0xd505, 0xa438, 0x0c0f,
        0xa438, 0x0801, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0x0cf0,
        0xa438, 0x04b0, 0xa438, 0x0cf0, 0xa438, 0x0490, 0xa438, 0x0cf0,
        0xa438, 0x0480, 0xa438, 0xd501, 0xa438, 0xce00, 0xa438, 0xd500,
        0xa438, 0xc48e, 0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd718,
        0xa438, 0x5faf, 0xa438, 0xd504, 0xa438, 0x8e01, 0xa438, 0x8c0f,
        0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x17e0, 0xa438, 0xd504,
        0xa438, 0xd718, 0xa438, 0x4074, 0xa438, 0x6195, 0xa438, 0xf005,
        0xa438, 0x60f5, 0xa438, 0x0c03, 0xa438, 0x0d00, 0xa438, 0xf009,
        0xa438, 0x0c03, 0xa438, 0x0d01, 0xa438, 0xf006, 0xa438, 0x0c03,
        0xa438, 0x0d02, 0xa438, 0xf003, 0xa438, 0x0c03, 0xa438, 0x0d03,
        0xa438, 0xd500, 0xa438, 0xd706, 0xa438, 0x2529, 0xa438, 0x809c,
        0xa438, 0xd718, 0xa438, 0x607b, 0xa438, 0x40da, 0xa438, 0xf00f,
        0xa438, 0x431a, 0xa438, 0xf021, 0xa438, 0xd718, 0xa438, 0x617b,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0x1000, 0xa438, 0x1ad1,
        0xa438, 0xd718, 0xa438, 0x608e, 0xa438, 0xd73e, 0xa438, 0x5f34,
        0xa438, 0xf020, 0xa438, 0xf053, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0x1000, 0xa438, 0x1ad1, 0xa438, 0xd718, 0xa438, 0x608e,
        0xa438, 0xd73e, 0xa438, 0x5f34, 0xa438, 0xf023, 0xa438, 0xf067,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0x1000, 0xa438, 0x1ad1,
        0xa438, 0xd718, 0xa438, 0x608e, 0xa438, 0xd73e, 0xa438, 0x5f34,
        0xa438, 0xf026, 0xa438, 0xf07b, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0x1000, 0xa438, 0x1ad1, 0xa438, 0xd718, 0xa438, 0x608e,
        0xa438, 0xd73e, 0xa438, 0x5f34, 0xa438, 0xf029, 0xa438, 0xf08f,
        0xa438, 0x1000, 0xa438, 0x8173, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0xd73e, 0xa438, 0x7fb4, 0xa438, 0x1000, 0xa438, 0x8188,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd718, 0xa438, 0x5fae,
        0xa438, 0xf028, 0xa438, 0x1000, 0xa438, 0x8173, 0xa438, 0x1000,
        0xa438, 0x1a41, 0xa438, 0xd73e, 0xa438, 0x7fb4, 0xa438, 0x1000,
        0xa438, 0x8188, 0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd718,
        0xa438, 0x5fae, 0xa438, 0xf039, 0xa438, 0x1000, 0xa438, 0x8173,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd73e, 0xa438, 0x7fb4,
        0xa438, 0x1000, 0xa438, 0x8188, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0xd718, 0xa438, 0x5fae, 0xa438, 0xf04a, 0xa438, 0x1000,
        0xa438, 0x8173, 0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd73e,
        0xa438, 0x7fb4, 0xa438, 0x1000, 0xa438, 0x8188, 0xa438, 0x1000,
        0xa438, 0x1a41, 0xa438, 0xd718, 0xa438, 0x5fae, 0xa438, 0xf05b,
        0xa438, 0xd719, 0xa438, 0x4119, 0xa438, 0xd504, 0xa438, 0xac01,
        0xa438, 0xae01, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a2f,
        0xa438, 0xf00a, 0xa438, 0xd719, 0xa438, 0x4118, 0xa438, 0xd504,
        0xa438, 0xac11, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xa410,
        0xa438, 0xce00, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0xd718, 0xa438, 0x5fb0, 0xa438, 0xd505, 0xa438, 0xd719,
        0xa438, 0x4079, 0xa438, 0xa80f, 0xa438, 0xf05d, 0xa438, 0x4b98,
        0xa438, 0xa808, 0xa438, 0xf05a, 0xa438, 0xd719, 0xa438, 0x4119,
        0xa438, 0xd504, 0xa438, 0xac02, 0xa438, 0xae01, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a2f, 0xa438, 0xf00a, 0xa438, 0xd719,
        0xa438, 0x4118, 0xa438, 0xd504, 0xa438, 0xac22, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0xa420, 0xa438, 0xce00, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd718, 0xa438, 0x5fb0,
        0xa438, 0xd505, 0xa438, 0xd719, 0xa438, 0x4079, 0xa438, 0xa80f,
        0xa438, 0xf03f, 0xa438, 0x47d8, 0xa438, 0xa804, 0xa438, 0xf03c,
        0xa438, 0xd719, 0xa438, 0x4119, 0xa438, 0xd504, 0xa438, 0xac04,
        0xa438, 0xae01, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a2f,
        0xa438, 0xf00a, 0xa438, 0xd719, 0xa438, 0x4118, 0xa438, 0xd504,
        0xa438, 0xac44, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xa440,
        0xa438, 0xce00, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a41,
        0xa438, 0xd718, 0xa438, 0x5fb0, 0xa438, 0xd505, 0xa438, 0xd719,
        0xa438, 0x4079, 0xa438, 0xa80f, 0xa438, 0xf021, 0xa438, 0x4418,
        0xa438, 0xa802, 0xa438, 0xf01e, 0xa438, 0xd719, 0xa438, 0x4119,
        0xa438, 0xd504, 0xa438, 0xac08, 0xa438, 0xae01, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a2f, 0xa438, 0xf00a, 0xa438, 0xd719,
        0xa438, 0x4118, 0xa438, 0xd504, 0xa438, 0xac88, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0xa480, 0xa438, 0xce00, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a41, 0xa438, 0xd718, 0xa438, 0x5fb0,
        0xa438, 0xd505, 0xa438, 0xd719, 0xa438, 0x4079, 0xa438, 0xa80f,
        0xa438, 0xf003, 0xa438, 0x4058, 0xa438, 0xa801, 0xa438, 0x1800,
        0xa438, 0x16ed, 0xa438, 0xd73e, 0xa438, 0xd505, 0xa438, 0x3088,
        0xa438, 0x817a, 0xa438, 0x6193, 0xa438, 0x6132, 0xa438, 0x60d1,
        0xa438, 0x3298, 0xa438, 0x8185, 0xa438, 0xf00a, 0xa438, 0xa808,
        0xa438, 0xf008, 0xa438, 0xa804, 0xa438, 0xf006, 0xa438, 0xa802,
        0xa438, 0xf004, 0xa438, 0xa801, 0xa438, 0xf002, 0xa438, 0xa80f,
        0xa438, 0xd500, 0xa438, 0x0800, 0xa438, 0xd505, 0xa438, 0xd75e,
        0xa438, 0x6211, 0xa438, 0xd71e, 0xa438, 0x619b, 0xa438, 0x611a,
        0xa438, 0x6099, 0xa438, 0x0c0f, 0xa438, 0x0808, 0xa438, 0xf009,
        0xa438, 0x0c0f, 0xa438, 0x0804, 0xa438, 0xf006, 0xa438, 0x0c0f,
        0xa438, 0x0802, 0xa438, 0xf003, 0xa438, 0x0c0f, 0xa438, 0x0801,
        0xa438, 0xd500, 0xa438, 0x0800, 0xa438, 0xd500, 0xa438, 0xc48d,
        0xa438, 0xd504, 0xa438, 0x8d03, 0xa438, 0xd701, 0xa438, 0x4045,
        0xa438, 0xad02, 0xa438, 0xd504, 0xa438, 0xd706, 0xa438, 0x2529,
        0xa438, 0x81ad, 0xa438, 0xd718, 0xa438, 0x607b, 0xa438, 0x40da,
        0xa438, 0xf013, 0xa438, 0x441a, 0xa438, 0xf02d, 0xa438, 0xd718,
        0xa438, 0x61fb, 0xa438, 0xbb01, 0xa438, 0xd75e, 0xa438, 0x6171,
        0xa438, 0x0cf0, 0xa438, 0x0c10, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0x0cf0, 0xa438, 0x0410, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0808, 0xa438, 0xf02a, 0xa438, 0xbb02,
        0xa438, 0xd75e, 0xa438, 0x6171, 0xa438, 0x0cf0, 0xa438, 0x0c20,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0x0cf0, 0xa438, 0x0420,
        0xa438, 0xce00, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0804,
        0xa438, 0xf01c, 0xa438, 0xbb04, 0xa438, 0xd75e, 0xa438, 0x6171,
        0xa438, 0x0cf0, 0xa438, 0x0c40, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0x0cf0, 0xa438, 0x0440, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0802, 0xa438, 0xf00e, 0xa438, 0xbb08,
        0xa438, 0xd75e, 0xa438, 0x6171, 0xa438, 0x0cf0, 0xa438, 0x0c80,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0x0cf0, 0xa438, 0x0480,
        0xa438, 0xce00, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0801,
        0xa438, 0xd500, 0xa438, 0x1800, 0xa438, 0x1616, 0xa436, 0xA026,
        0xa438, 0xffff, 0xa436, 0xA024, 0xa438, 0x15d8, 0xa436, 0xA022,
        0xa438, 0x161f, 0xa436, 0xA020, 0xa438, 0x14f2, 0xa436, 0xA006,
        0xa438, 0x1c4f, 0xa436, 0xA004, 0xa438, 0x1433, 0xa436, 0xA002,
        0xa438, 0x13c1, 0xa436, 0xA000, 0xa438, 0x2020, 0xa436, 0xA008,
        0xa438, 0x7f00, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x07f8, 0xa436, 0xA014, 0xa438, 0xd04d, 0xa438, 0x8904,
        0xa438, 0x813C, 0xa438, 0xA13D, 0xa438, 0xcc01, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa436, 0xA152, 0xa438, 0x1384,
        0xa436, 0xA154, 0xa438, 0x1fa8, 0xa436, 0xA156, 0xa438, 0x218B,
        0xa436, 0xA158, 0xa438, 0x21B8, 0xa436, 0xA15A, 0xa438, 0x021c,
        0xa436, 0xA15C, 0xa438, 0x3fff, 0xa436, 0xA15E, 0xa438, 0x3fff,
        0xa436, 0xA160, 0xa438, 0x3fff, 0xa436, 0xA150, 0xa438, 0x001f,
        0xa436, 0xA016, 0xa438, 0x0010, 0xa436, 0xA012, 0xa438, 0x0000,
        0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800,
        0xa438, 0x8013, 0xa438, 0x1800, 0xa438, 0x803a, 0xa438, 0x1800,
        0xa438, 0x8045, 0xa438, 0x1800, 0xa438, 0x8049, 0xa438, 0x1800,
        0xa438, 0x804d, 0xa438, 0x1800, 0xa438, 0x8059, 0xa438, 0x1800,
        0xa438, 0x805d, 0xa438, 0xc2ff, 0xa438, 0x1800, 0xa438, 0x0042,
        0xa438, 0x1000, 0xa438, 0x02e5, 0xa438, 0x1000, 0xa438, 0x02b4,
        0xa438, 0xd701, 0xa438, 0x40e3, 0xa438, 0xd700, 0xa438, 0x5f6c,
        0xa438, 0x1000, 0xa438, 0x8021, 0xa438, 0x1800, 0xa438, 0x0073,
        0xa438, 0x1800, 0xa438, 0x0084, 0xa438, 0xd701, 0xa438, 0x4061,
        0xa438, 0xba0f, 0xa438, 0xf004, 0xa438, 0x4060, 0xa438, 0x1000,
        0xa438, 0x802a, 0xa438, 0xba10, 0xa438, 0x0800, 0xa438, 0xd700,
        0xa438, 0x60bb, 0xa438, 0x611c, 0xa438, 0x0c0f, 0xa438, 0x1a01,
        0xa438, 0xf00a, 0xa438, 0x60fc, 0xa438, 0x0c0f, 0xa438, 0x1a02,
        0xa438, 0xf006, 0xa438, 0x0c0f, 0xa438, 0x1a04, 0xa438, 0xf003,
        0xa438, 0x0c0f, 0xa438, 0x1a08, 0xa438, 0x0800, 0xa438, 0x0c0f,
        0xa438, 0x0504, 0xa438, 0xad02, 0xa438, 0x1000, 0xa438, 0x02c0,
        0xa438, 0xd700, 0xa438, 0x5fac, 0xa438, 0x1000, 0xa438, 0x8021,
        0xa438, 0x1800, 0xa438, 0x0139, 0xa438, 0x9a1f, 0xa438, 0x8bf0,
        0xa438, 0x1800, 0xa438, 0x02df, 0xa438, 0x9a1f, 0xa438, 0x9910,
        0xa438, 0x1800, 0xa438, 0x02d7, 0xa438, 0xad02, 0xa438, 0x8d01,
        0xa438, 0x9a1f, 0xa438, 0x9910, 0xa438, 0x9860, 0xa438, 0xcb00,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0x85f0, 0xa438, 0xd500,
        0xa438, 0x1800, 0xa438, 0x015c, 0xa438, 0x8580, 0xa438, 0x8d02,
        0xa438, 0x1800, 0xa438, 0x018f, 0xa438, 0x0c0f, 0xa438, 0x0503,
        0xa438, 0xad02, 0xa438, 0x1800, 0xa438, 0x00dd, 0xa436, 0xA08E,
        0xa438, 0x00db, 0xa436, 0xA08C, 0xa438, 0x018e, 0xa436, 0xA08A,
        0xa438, 0x015a, 0xa436, 0xA088, 0xa438, 0x02d6, 0xa436, 0xA086,
        0xa438, 0x02de, 0xa436, 0xA084, 0xa438, 0x0137, 0xa436, 0xA082,
        0xa438, 0x0071, 0xa436, 0xA080, 0xa438, 0x0041, 0xa436, 0xA090,
        0xa438, 0x00ff, 0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012,
        0xa438, 0x1ff8, 0xa436, 0xA014, 0xa438, 0x001c, 0xa438, 0xce15,
        0xa438, 0xd105, 0xa438, 0xa410, 0xa438, 0x8320, 0xa438, 0xFFD7,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa436, 0xA164, 0xa438, 0x0260,
        0xa436, 0xA166, 0xa438, 0x0add, 0xa436, 0xA168, 0xa438, 0x05CC,
        0xa436, 0xA16A, 0xa438, 0x05C5, 0xa436, 0xA16C, 0xa438, 0x0429,
        0xa436, 0xA16E, 0xa438, 0x07B6, 0xa436, 0xA170, 0xa438, 0x0259,
        0xa436, 0xA172, 0xa438, 0x3fff, 0xa436, 0xA162, 0xa438, 0x003f,
        0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x0000,
        0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800,
        0xa438, 0x8023, 0xa438, 0x1800, 0xa438, 0x814c, 0xa438, 0x1800,
        0xa438, 0x8156, 0xa438, 0x1800, 0xa438, 0x815e, 0xa438, 0x1800,
        0xa438, 0x8210, 0xa438, 0x1800, 0xa438, 0x8221, 0xa438, 0x1800,
        0xa438, 0x822f, 0xa438, 0xa801, 0xa438, 0x9308, 0xa438, 0xb201,
        0xa438, 0xb301, 0xa438, 0xd701, 0xa438, 0x4000, 0xa438, 0xd2ff,
        0xa438, 0xb302, 0xa438, 0xd200, 0xa438, 0xb201, 0xa438, 0xb309,
        0xa438, 0xd701, 0xa438, 0x4000, 0xa438, 0xd2ff, 0xa438, 0xb302,
        0xa438, 0xd200, 0xa438, 0xa800, 0xa438, 0x1800, 0xa438, 0x0031,
        0xa438, 0xd700, 0xa438, 0x4543, 0xa438, 0xd71f, 0xa438, 0x40fe,
        0xa438, 0xd1b7, 0xa438, 0xd049, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd700, 0xa438, 0x5fbb, 0xa438, 0xa220, 0xa438, 0x8501,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x0c70, 0xa438, 0x0b00,
        0xa438, 0x0c07, 0xa438, 0x0604, 0xa438, 0x9503, 0xa438, 0xa510,
        0xa438, 0xce49, 0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x8520,
        0xa438, 0xa520, 0xa438, 0xa501, 0xa438, 0xd105, 0xa438, 0xd047,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd707, 0xa438, 0x6087,
        0xa438, 0xd700, 0xa438, 0x5f7b, 0xa438, 0xffe9, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0x8501, 0xa438, 0xd707, 0xa438, 0x5e08,
        0xa438, 0x8530, 0xa438, 0xba20, 0xa438, 0xf00c, 0xa438, 0xd700,
        0xa438, 0x4098, 0xa438, 0xd1ef, 0xa438, 0xd047, 0xa438, 0xf003,
        0xa438, 0xd1db, 0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd700, 0xa438, 0x5fbb, 0xa438, 0x8980, 0xa438, 0xd702,
        0xa438, 0x6126, 0xa438, 0xd704, 0xa438, 0x4063, 0xa438, 0xd702,
        0xa438, 0x6060, 0xa438, 0xd702, 0xa438, 0x6077, 0xa438, 0x8410,
        0xa438, 0xf002, 0xa438, 0xa410, 0xa438, 0xce02, 0xa438, 0x1000,
        0xa438, 0x10be, 0xa438, 0xcd81, 0xa438, 0xd412, 0xa438, 0x1000,
        0xa438, 0x1069, 0xa438, 0xcd82, 0xa438, 0xd40e, 0xa438, 0x1000,
        0xa438, 0x1069, 0xa438, 0xcd83, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd71f, 0xa438, 0x5fb4, 0xa438, 0xd702, 0xa438, 0x6c26,
        0xa438, 0xd704, 0xa438, 0x4063, 0xa438, 0xd702, 0xa438, 0x6060,
        0xa438, 0xd702, 0xa438, 0x6b77, 0xa438, 0xa340, 0xa438, 0x0c06,
        0xa438, 0x0102, 0xa438, 0xce01, 0xa438, 0x1000, 0xa438, 0x10be,
        0xa438, 0xa240, 0xa438, 0xa902, 0xa438, 0xa204, 0xa438, 0xa280,
        0xa438, 0xa364, 0xa438, 0xab02, 0xa438, 0x8380, 0xa438, 0xa00a,
        0xa438, 0xcd8d, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706,
        0xa438, 0x5fb5, 0xa438, 0xb920, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd71f, 0xa438, 0x7fb4, 0xa438, 0x9920, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0xd71f, 0xa438, 0x6065, 0xa438, 0x7c74,
        0xa438, 0xfffb, 0xa438, 0xb820, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd71f, 0xa438, 0x7fa5, 0xa438, 0x9820, 0xa438, 0xa410,
        0xa438, 0x8902, 0xa438, 0xa120, 0xa438, 0xa380, 0xa438, 0xce02,
        0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x8280, 0xa438, 0xa324,
        0xa438, 0xab02, 0xa438, 0xa00a, 0xa438, 0x8118, 0xa438, 0x863f,
        0xa438, 0x87fb, 0xa438, 0xcd8e, 0xa438, 0xd193, 0xa438, 0xd047,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x10a3,
        0xa438, 0xd700, 0xa438, 0x5f7b, 0xa438, 0xa280, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x10a3, 0xa438, 0xd706,
        0xa438, 0x5f78, 0xa438, 0xa210, 0xa438, 0xd700, 0xa438, 0x6083,
        0xa438, 0xd101, 0xa438, 0xd047, 0xa438, 0xf003, 0xa438, 0xd160,
        0xa438, 0xd04b, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000,
        0xa438, 0x10a3, 0xa438, 0xd700, 0xa438, 0x5f7b, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x10a3, 0xa438, 0xd706,
        0xa438, 0x5f79, 0xa438, 0x8120, 0xa438, 0xbb20, 0xa438, 0xf04c,
        0xa438, 0xa00a, 0xa438, 0xa340, 0xa438, 0x0c06, 0xa438, 0x0102,
        0xa438, 0xa240, 0xa438, 0xa290, 0xa438, 0xa324, 0xa438, 0xab02,
        0xa438, 0xd13e, 0xa438, 0xd05a, 0xa438, 0xd13e, 0xa438, 0xd06b,
        0xa438, 0xcd84, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706,
        0xa438, 0x6079, 0xa438, 0xd700, 0xa438, 0x5f5c, 0xa438, 0xcd8a,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706, 0xa438, 0x6079,
        0xa438, 0xd700, 0xa438, 0x5f5d, 0xa438, 0xcd8b, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0xcd8c, 0xa438, 0xd700, 0xa438, 0x6050,
        0xa438, 0xab04, 0xa438, 0xd700, 0xa438, 0x4083, 0xa438, 0xd160,
        0xa438, 0xd04b, 0xa438, 0xf003, 0xa438, 0xd193, 0xa438, 0xd047,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700, 0xa438, 0x5fbb,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x8410, 0xa438, 0xd71f,
        0xa438, 0x5f94, 0xa438, 0xb920, 0xa438, 0x1000, 0xa438, 0x109e,
        0xa438, 0xd71f, 0xa438, 0x7fb4, 0xa438, 0x9920, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0xd71f, 0xa438, 0x6105, 0xa438, 0x6054,
        0xa438, 0xfffb, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706,
        0xa438, 0x5fb9, 0xa438, 0xfff0, 0xa438, 0xa410, 0xa438, 0xb820,
        0xa438, 0xcd85, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd71f,
        0xa438, 0x7fa5, 0xa438, 0x9820, 0xa438, 0xbb20, 0xa438, 0xd105,
        0xa438, 0xd042, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706,
        0xa438, 0x5fbb, 0xa438, 0x5f85, 0xa438, 0xd700, 0xa438, 0x5f5b,
        0xa438, 0xd700, 0xa438, 0x6090, 0xa438, 0xd700, 0xa438, 0x4043,
        0xa438, 0xaa20, 0xa438, 0xcd86, 0xa438, 0xd700, 0xa438, 0x6083,
        0xa438, 0xd1c7, 0xa438, 0xd045, 0xa438, 0xf003, 0xa438, 0xd17a,
        0xa438, 0xd04b, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700,
        0xa438, 0x5fbb, 0xa438, 0x0c18, 0xa438, 0x0108, 0xa438, 0x0c3f,
        0xa438, 0x0609, 0xa438, 0x0cfb, 0xa438, 0x0729, 0xa438, 0xa308,
        0xa438, 0x8320, 0xa438, 0xd105, 0xa438, 0xd042, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0xd700, 0xa438, 0x5fbb, 0xa438, 0x1800,
        0xa438, 0x08f7, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000,
        0xa438, 0x10a3, 0xa438, 0xd700, 0xa438, 0x607b, 0xa438, 0xd700,
        0xa438, 0x5f2b, 0xa438, 0x1800, 0xa438, 0x0a81, 0xa438, 0xd700,
        0xa438, 0x40bd, 0xa438, 0xd707, 0xa438, 0x4065, 0xa438, 0x1800,
        0xa438, 0x1121, 0xa438, 0x1800, 0xa438, 0x1124, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8f80, 0xa438, 0x9503, 0xa438, 0xd705,
        0xa438, 0x641d, 0xa438, 0xd704, 0xa438, 0x62b2, 0xa438, 0xd702,
        0xa438, 0x4116, 0xa438, 0xce15, 0xa438, 0x1000, 0xa438, 0x10be,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8f40, 0xa438, 0x9503,
        0xa438, 0xa00a, 0xa438, 0xd704, 0xa438, 0x4247, 0xa438, 0xd700,
        0xa438, 0x3691, 0xa438, 0x8183, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xa570, 0xa438, 0x9503, 0xa438, 0xf00a, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xaf40, 0xa438, 0x9503, 0xa438, 0x800a,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x1108,
        0xa438, 0xcd64, 0xa438, 0xd704, 0xa438, 0x3398, 0xa438, 0x8203,
        0xa438, 0xd71f, 0xa438, 0x620e, 0xa438, 0xd704, 0xa438, 0x6096,
        0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf004, 0xa438, 0xd705,
        0xa438, 0x605d, 0xa438, 0xf008, 0xa438, 0xd706, 0xa438, 0x609d,
        0xa438, 0xd705, 0xa438, 0x405f, 0xa438, 0xf003, 0xa438, 0xd700,
        0xa438, 0x58fb, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xc7aa,
        0xa438, 0x9503, 0xa438, 0xd71f, 0xa438, 0x6d2e, 0xa438, 0xd704,
        0xa438, 0x6096, 0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf005,
        0xa438, 0xd705, 0xa438, 0x607d, 0xa438, 0x1800, 0xa438, 0x0cc7,
        0xa438, 0xd706, 0xa438, 0x60bd, 0xa438, 0xd705, 0xa438, 0x407f,
        0xa438, 0x1800, 0xa438, 0x0e42, 0xa438, 0xd702, 0xa438, 0x40a4,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8e20, 0xa438, 0x9503,
        0xa438, 0xd702, 0xa438, 0x40a5, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8e40, 0xa438, 0x9503, 0xa438, 0xd705, 0xa438, 0x659d,
        0xa438, 0xd704, 0xa438, 0x62b2, 0xa438, 0xd702, 0xa438, 0x4116,
        0xa438, 0xce15, 0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8f40, 0xa438, 0x9503, 0xa438, 0xa00a,
        0xa438, 0xd704, 0xa438, 0x4247, 0xa438, 0xd700, 0xa438, 0x3691,
        0xa438, 0x81de, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa570,
        0xa438, 0x9503, 0xa438, 0xf00a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xaf40, 0xa438, 0x9503, 0xa438, 0x800a, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503, 0xa438, 0xd706,
        0xa438, 0x60e4, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x0cf0,
        0xa438, 0x07a0, 0xa438, 0x9503, 0xa438, 0xf005, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x87f0, 0xa438, 0x9503, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x1108, 0xa438, 0xcd61,
        0xa438, 0xd704, 0xa438, 0x3398, 0xa438, 0x8203, 0xa438, 0xd704,
        0xa438, 0x6096, 0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf005,
        0xa438, 0xd705, 0xa438, 0x607d, 0xa438, 0x1800, 0xa438, 0x0cc7,
        0xa438, 0xd71f, 0xa438, 0x61ce, 0xa438, 0xd706, 0xa438, 0x767d,
        0xa438, 0xd705, 0xa438, 0x563f, 0xa438, 0x1800, 0xa438, 0x0e42,
        0xa438, 0x800a, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xae40,
        0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0c47, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xaf80, 0xa438, 0x9503, 0xa438, 0x1800,
        0xa438, 0x0b5f, 0xa438, 0x607c, 0xa438, 0x1800, 0xa438, 0x027a,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xae01, 0xa438, 0x9503,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd702, 0xa438, 0x5fa3,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8e01, 0xa438, 0x9503,
        0xa438, 0x1800, 0xa438, 0x027d, 0xa438, 0x1000, 0xa438, 0x10be,
        0xa438, 0xd702, 0xa438, 0x40a5, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8e40, 0xa438, 0x9503, 0xa438, 0xd73e, 0xa438, 0x6065,
        0xa438, 0x1800, 0xa438, 0x0cea, 0xa438, 0x1800, 0xa438, 0x0cf4,
        0xa438, 0xd701, 0xa438, 0x6fd1, 0xa438, 0xd71f, 0xa438, 0x6eee,
        0xa438, 0xd707, 0xa438, 0x4d0f, 0xa438, 0xd73e, 0xa438, 0x4cc5,
        0xa438, 0xd705, 0xa438, 0x4c99, 0xa438, 0xd704, 0xa438, 0x6c57,
        0xa438, 0xd702, 0xa438, 0x6c11, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8c20, 0xa438, 0xa608, 0xa438, 0x9503, 0xa438, 0xa201,
        0xa438, 0xa804, 0xa438, 0xd704, 0xa438, 0x40a7, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xa620, 0xa438, 0x9503, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xac40, 0xa438, 0x9503, 0xa438, 0x800a,
        0xa438, 0x8290, 0xa438, 0x8306, 0xa438, 0x8b02, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503, 0xa438, 0xce00,
        0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0xcd99, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x10cc, 0xa438, 0xd701,
        0xa438, 0x69f1, 0xa438, 0xd71f, 0xa438, 0x690e, 0xa438, 0xd73e,
        0xa438, 0x5ee6, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x87f0,
        0xa438, 0x9503, 0xa438, 0xce46, 0xa438, 0x1000, 0xa438, 0x10be,
        0xa438, 0xa00a, 0xa438, 0xd704, 0xa438, 0x40a7, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xa570, 0xa438, 0x9503, 0xa438, 0xcd9a,
        0xa438, 0xd700, 0xa438, 0x6078, 0xa438, 0xd700, 0xa438, 0x609a,
        0xa438, 0xd109, 0xa438, 0xd074, 0xa438, 0xf003, 0xa438, 0xd109,
        0xa438, 0xd075, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000,
        0xa438, 0x10cc, 0xa438, 0xd701, 0xa438, 0x65b1, 0xa438, 0xd71f,
        0xa438, 0x64ce, 0xa438, 0xd700, 0xa438, 0x5efe, 0xa438, 0xce00,
        0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8608, 0xa438, 0x8c40, 0xa438, 0x9503, 0xa438, 0x8201,
        0xa438, 0x800a, 0xa438, 0x8290, 0xa438, 0x8306, 0xa438, 0x8b02,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xc7aa, 0xa438, 0x8570,
        0xa438, 0x8d08, 0xa438, 0x9503, 0xa438, 0xcd9b, 0xa438, 0x1800,
        0xa438, 0x0c8b, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd705,
        0xa438, 0x61d9, 0xa438, 0xd704, 0xa438, 0x4193, 0xa438, 0x800a,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xae40, 0xa438, 0x9503,
        0xa438, 0x1800, 0xa438, 0x0c47, 0xa438, 0x1800, 0xa438, 0x0df8,
        0xa438, 0x1800, 0xa438, 0x8339, 0xa438, 0x0800, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8d08, 0xa438, 0x8f02, 0xa438, 0x8c40,
        0xa438, 0x9503, 0xa438, 0x8201, 0xa438, 0xa804, 0xa438, 0xd704,
        0xa438, 0x40a7, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa620,
        0xa438, 0x9503, 0xa438, 0x800a, 0xa438, 0x8290, 0xa438, 0x8306,
        0xa438, 0x8b02, 0xa438, 0x8010, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8570, 0xa438, 0x9503, 0xa438, 0xaa03, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0xac20, 0xa438, 0xa608, 0xa438, 0x9503,
        0xa438, 0xce00, 0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0xcd95,
        0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd701, 0xa438, 0x7b91,
        0xa438, 0xd71f, 0xa438, 0x7aae, 0xa438, 0xd701, 0xa438, 0x7ab0,
        0xa438, 0xd704, 0xa438, 0x7ef3, 0xa438, 0xd701, 0xa438, 0x5eb3,
        0xa438, 0x84b0, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa608,
        0xa438, 0xc700, 0xa438, 0x9503, 0xa438, 0xce54, 0xa438, 0x1000,
        0xa438, 0x10be, 0xa438, 0xa290, 0xa438, 0xa304, 0xa438, 0xab02,
        0xa438, 0xd700, 0xa438, 0x6050, 0xa438, 0xab04, 0xa438, 0x0c38,
        0xa438, 0x0608, 0xa438, 0xaa0b, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8d01, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xae40,
        0xa438, 0x9503, 0xa438, 0xd702, 0xa438, 0x40a4, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8e20, 0xa438, 0x9503, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8c20, 0xa438, 0x9503, 0xa438, 0xd700,
        0xa438, 0x6078, 0xa438, 0xd700, 0xa438, 0x609a, 0xa438, 0xd109,
        0xa438, 0xd074, 0xa438, 0xf003, 0xa438, 0xd109, 0xa438, 0xd075,
        0xa438, 0xd704, 0xa438, 0x62b2, 0xa438, 0xd702, 0xa438, 0x4116,
        0xa438, 0xce54, 0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8f40, 0xa438, 0x9503, 0xa438, 0xa00a,
        0xa438, 0xd704, 0xa438, 0x4247, 0xa438, 0xd700, 0xa438, 0x3691,
        0xa438, 0x8326, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa570,
        0xa438, 0x9503, 0xa438, 0xf00a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xaf40, 0xa438, 0x9503, 0xa438, 0x800a, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503, 0xa438, 0x1000,
        0xa438, 0x109e, 0xa438, 0xd704, 0xa438, 0x60f3, 0xa438, 0xd71f,
        0xa438, 0x618e, 0xa438, 0xd700, 0xa438, 0x5b5e, 0xa438, 0x1800,
        0xa438, 0x0deb, 0xa438, 0x800a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xae40, 0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0c47,
        0xa438, 0x1800, 0xa438, 0x0df8, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8608, 0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0e2b,
        0xa436, 0xA10E, 0xa438, 0x0d14, 0xa436, 0xA10C, 0xa438, 0x0ce8,
        0xa436, 0xA10A, 0xa438, 0x0279, 0xa436, 0xA108, 0xa438, 0x0b19,
        0xa436, 0xA106, 0xa438, 0x111f, 0xa436, 0xA104, 0xa438, 0x0a7b,
        0xa436, 0xA102, 0xa438, 0x0ba3, 0xa436, 0xA100, 0xa438, 0x0022,
        0xa436, 0xA110, 0xa438, 0x00ff, 0xa436, 0xb87c, 0xa438, 0x859b,
        0xa436, 0xb87e, 0xa438, 0xaf85, 0xa438, 0xb3af, 0xa438, 0x863b,
        0xa438, 0xaf86, 0xa438, 0x4caf, 0xa438, 0x8688, 0xa438, 0xaf86,
        0xa438, 0xceaf, 0xa438, 0x8744, 0xa438, 0xaf87, 0xa438, 0x68af,
        0xa438, 0x8781, 0xa438, 0xbf5e, 0xa438, 0x7202, 0xa438, 0x5f7e,
        0xa438, 0xac28, 0xa438, 0x68e1, 0xa438, 0x84e6, 0xa438, 0xad28,
        0xa438, 0x09bf, 0xa438, 0x5e75, 0xa438, 0x025f, 0xa438, 0x7eac,
        0xa438, 0x2d59, 0xa438, 0xe18f, 0xa438, 0xebad, 0xa438, 0x2809,
        0xa438, 0xbf5e, 0xa438, 0x7502, 0xa438, 0x5f7e, 0xa438, 0xac2e,
        0xa438, 0x50e1, 0xa438, 0x84e6, 0xa438, 0xac28, 0xa438, 0x08bf,
        0xa438, 0x873e, 0xa438, 0x025f, 0xa438, 0x3cae, 0xa438, 0x06bf,
        0xa438, 0x873e, 0xa438, 0x025f, 0xa438, 0x33bf, 0xa438, 0x8741,
        0xa438, 0x025f, 0xa438, 0x33ee, 0xa438, 0x8fea, 0xa438, 0x02e1,
        0xa438, 0x84e4, 0xa438, 0xad28, 0xa438, 0x14e1, 0xa438, 0x8fe8,
        0xa438, 0xad28, 0xa438, 0x17e1, 0xa438, 0x84e5, 0xa438, 0x11e5,
        0xa438, 0x84e5, 0xa438, 0xa10c, 0xa438, 0x04ee, 0xa438, 0x84e5,
        0xa438, 0x0002, 0xa438, 0x4977, 0xa438, 0xee84, 0xa438, 0xdc03,
        0xa438, 0xae1d, 0xa438, 0xe18f, 0xa438, 0xe811, 0xa438, 0xe58f,
        0xa438, 0xe8ae, 0xa438, 0x14bf, 0xa438, 0x873e, 0xa438, 0x025f,
        0xa438, 0x3cbf, 0xa438, 0x8741, 0xa438, 0x025f, 0xa438, 0x3cee,
        0xa438, 0x8fea, 0xa438, 0x01ee, 0xa438, 0x84e4, 0xa438, 0x00af,
        0xa438, 0x50c1, 0xa438, 0x1f00, 0xa438, 0xbf5a, 0xa438, 0x6102,
        0xa438, 0x5f5f, 0xa438, 0xbf5a, 0xa438, 0x5e02, 0xa438, 0x5f3c,
        0xa438, 0xaf45, 0xa438, 0x7be0, 0xa438, 0x8012, 0xa438, 0xad23,
        0xa438, 0x141f, 0xa438, 0x001f, 0xa438, 0x22d1, 0xa438, 0x00bf,
        0xa438, 0x3fcf, 0xa438, 0x0261, 0xa438, 0x3412, 0xa438, 0xa204,
        0xa438, 0xf6ee, 0xa438, 0x8317, 0xa438, 0x00e0, 0xa438, 0x8012,
        0xa438, 0xad24, 0xa438, 0x141f, 0xa438, 0x001f, 0xa438, 0x22d1,
        0xa438, 0x00bf, 0xa438, 0x3fd7, 0xa438, 0x0261, 0xa438, 0x3412,
        0xa438, 0xa204, 0xa438, 0xf6ee, 0xa438, 0x8317, 0xa438, 0x00ef,
        0xa438, 0x96fe, 0xa438, 0xfdfc, 0xa438, 0xaf42, 0xa438, 0x9802,
        0xa438, 0x56ec, 0xa438, 0xf70b, 0xa438, 0xac13, 0xa438, 0x0fbf,
        0xa438, 0x5e75, 0xa438, 0x025f, 0xa438, 0x7eac, 0xa438, 0x280c,
        0xa438, 0xe2ff, 0xa438, 0xcfad, 0xa438, 0x32ee, 0xa438, 0x0257,
        0xa438, 0x05af, 0xa438, 0x00a4, 0xa438, 0x0286, 0xa438, 0xaaae,
        0xa438, 0xeff8, 0xa438, 0xf9ef, 0xa438, 0x5902, 0xa438, 0x1fe1,
        0xa438, 0xbf59, 0xa438, 0x4d02, 0xa438, 0x5f3c, 0xa438, 0xac13,
        0xa438, 0x09bf, 0xa438, 0x5e75, 0xa438, 0x025f, 0xa438, 0x7ea1,
        0xa438, 0x00f4, 0xa438, 0xbf59, 0xa438, 0x4d02, 0xa438, 0x5f33,
        0xa438, 0xef95, 0xa438, 0xfdfc, 0xa438, 0x04bf, 0xa438, 0x5e72,
        0xa438, 0x025f, 0xa438, 0x7eac, 0xa438, 0x284a, 0xa438, 0xe184,
        0xa438, 0xe6ad, 0xa438, 0x2809, 0xa438, 0xbf5e, 0xa438, 0x7502,
        0xa438, 0x5f7e, 0xa438, 0xac2d, 0xa438, 0x3be1, 0xa438, 0x8feb,
        0xa438, 0xad28, 0xa438, 0x09bf, 0xa438, 0x5e75, 0xa438, 0x025f,
        0xa438, 0x7eac, 0xa438, 0x2e32, 0xa438, 0xe184, 0xa438, 0xe6ac,
        0xa438, 0x2808, 0xa438, 0xbf87, 0xa438, 0x3e02, 0xa438, 0x5f3c,
        0xa438, 0xae06, 0xa438, 0xbf87, 0xa438, 0x3e02, 0xa438, 0x5f33,
        0xa438, 0xbf87, 0xa438, 0x4102, 0xa438, 0x5f33, 0xa438, 0xee8f,
        0xa438, 0xea04, 0xa438, 0xbf5e, 0xa438, 0x4e02, 0xa438, 0x5f7e,
        0xa438, 0xad28, 0xa438, 0x1f02, 0xa438, 0x4b12, 0xa438, 0xae1a,
        0xa438, 0xbf87, 0xa438, 0x3e02, 0xa438, 0x5f3c, 0xa438, 0xbf87,
        0xa438, 0x4102, 0xa438, 0x5f3c, 0xa438, 0xee8f, 0xa438, 0xea03,
        0xa438, 0xbf5e, 0xa438, 0x2a02, 0xa438, 0x5f33, 0xa438, 0xee84,
        0xa438, 0xe701, 0xa438, 0xaf4a, 0xa438, 0x7444, 0xa438, 0xac0e,
        0xa438, 0x55ac, 0xa438, 0x0ebf, 0xa438, 0x5e75, 0xa438, 0x025f,
        0xa438, 0x7ead, 0xa438, 0x2d0b, 0xa438, 0xbf5e, 0xa438, 0x36e1,
        0xa438, 0x8fe9, 0xa438, 0x025f, 0xa438, 0x5fae, 0xa438, 0x09bf,
        0xa438, 0x5e36, 0xa438, 0xe184, 0xa438, 0xe102, 0xa438, 0x5f5f,
        0xa438, 0xee8f, 0xa438, 0xe800, 0xa438, 0xaf49, 0xa438, 0xcdbf,
        0xa438, 0x595c, 0xa438, 0x025f, 0xa438, 0x7ea1, 0xa438, 0x0203,
        0xa438, 0xaf87, 0xa438, 0x79d1, 0xa438, 0x00af, 0xa438, 0x877c,
        0xa438, 0xe181, 0xa438, 0x941f, 0xa438, 0x00af, 0xa438, 0x3ff7,
        0xa438, 0xac4e, 0xa438, 0x06ac, 0xa438, 0x4003, 0xa438, 0xaf24,
        0xa438, 0x97af, 0xa438, 0x2467, 0xa436, 0xb85e, 0xa438, 0x5082,
        0xa436, 0xb860, 0xa438, 0x4575, 0xa436, 0xb862, 0xa438, 0x425F,
        0xa436, 0xb864, 0xa438, 0x0096, 0xa436, 0xb886, 0xa438, 0x4A44,
        0xa436, 0xb888, 0xa438, 0x49c4, 0xa436, 0xb88a, 0xa438, 0x3FF2,
        0xa436, 0xb88c, 0xa438, 0x245C, 0xa436, 0xb838, 0xa438, 0x00ff,
        0xb820, 0x0010, 0xa436, 0x843d, 0xa438, 0xaf84, 0xa438, 0xa6af,
        0xa438, 0x8540, 0xa438, 0xaf85, 0xa438, 0xaeaf, 0xa438, 0x85b5,
        0xa438, 0xaf87, 0xa438, 0x7daf, 0xa438, 0x8784, 0xa438, 0xaf87,
        0xa438, 0x87af, 0xa438, 0x87e5, 0xa438, 0x0066, 0xa438, 0x0a03,
        0xa438, 0x6607, 0xa438, 0x2666, 0xa438, 0x1c00, 0xa438, 0x660d,
        0xa438, 0x0166, 0xa438, 0x1004, 0xa438, 0x6616, 0xa438, 0x0566,
        0xa438, 0x1f06, 0xa438, 0x6a5d, 0xa438, 0x2766, 0xa438, 0x1900,
        0xa438, 0x6625, 0xa438, 0x2466, 0xa438, 0x2820, 0xa438, 0x662b,
        0xa438, 0x2466, 0xa438, 0x4600, 0xa438, 0x664c, 0xa438, 0x0166,
        0xa438, 0x4902, 0xa438, 0x8861, 0xa438, 0x0388, 0xa438, 0x5e05,
        0xa438, 0x886d, 0xa438, 0x0588, 0xa438, 0x7005, 0xa438, 0x8873,
        0xa438, 0x0588, 0xa438, 0x7605, 0xa438, 0x8879, 0xa438, 0x0588,
        0xa438, 0x7c05, 0xa438, 0x887f, 0xa438, 0x0588, 0xa438, 0x8205,
        0xa438, 0x8885, 0xa438, 0x0588, 0xa438, 0x881e, 0xa438, 0x13ad,
        0xa438, 0x2841, 0xa438, 0xbf64, 0xa438, 0xf102, 0xa438, 0x6b9d,
        0xa438, 0xad28, 0xa438, 0x03af, 0xa438, 0x15fc, 0xa438, 0xbf65,
        0xa438, 0xcb02, 0xa438, 0x6b9d, 0xa438, 0x0d11, 0xa438, 0xf62f,
        0xa438, 0xef31, 0xa438, 0xd202, 0xa438, 0xbf88, 0xa438, 0x6402,
        0xa438, 0x6b52, 0xa438, 0xe082, 0xa438, 0x020d, 0xa438, 0x01f6,
        0xa438, 0x271b, 0xa438, 0x03aa, 0xa438, 0x0182, 0xa438, 0xe082,
        0xa438, 0x010d, 0xa438, 0x01f6, 0xa438, 0x271b, 0xa438, 0x03aa,
        0xa438, 0x0782, 0xa438, 0xbf88, 0xa438, 0x6402, 0xa438, 0x6b5b,
        0xa438, 0xaf15, 0xa438, 0xf9bf, 0xa438, 0x65cb, 0xa438, 0x026b,
        0xa438, 0x9d0d, 0xa438, 0x11f6, 0xa438, 0x2fef, 0xa438, 0x31e0,
        0xa438, 0x8ff7, 0xa438, 0x0d01, 0xa438, 0xf627, 0xa438, 0x1b03,
        0xa438, 0xaa20, 0xa438, 0xe18f, 0xa438, 0xf4d0, 0xa438, 0x00bf,
        0xa438, 0x6587, 0xa438, 0x026b, 0xa438, 0x7ee1, 0xa438, 0x8ff5,
        0xa438, 0xbf65, 0xa438, 0x8a02, 0xa438, 0x6b7e, 0xa438, 0xe18f,
        0xa438, 0xf6bf, 0xa438, 0x6584, 0xa438, 0x026b, 0xa438, 0x7eaf,
        0xa438, 0x15fc, 0xa438, 0xe18f, 0xa438, 0xf1d0, 0xa438, 0x00bf,
        0xa438, 0x6587, 0xa438, 0x026b, 0xa438, 0x7ee1, 0xa438, 0x8ff2,
        0xa438, 0xbf65, 0xa438, 0x8a02, 0xa438, 0x6b7e, 0xa438, 0xe18f,
        0xa438, 0xf3bf, 0xa438, 0x6584, 0xa438, 0xaf15, 0xa438, 0xfcd1,
        0xa438, 0x07bf, 0xa438, 0x65ce, 0xa438, 0x026b, 0xa438, 0x7ed1,
        0xa438, 0x0cbf, 0xa438, 0x65d1, 0xa438, 0x026b, 0xa438, 0x7ed1,
        0xa438, 0x03bf, 0xa438, 0x885e, 0xa438, 0x026b, 0xa438, 0x7ed1,
        0xa438, 0x05bf, 0xa438, 0x8867, 0xa438, 0x026b, 0xa438, 0x7ed1,
        0xa438, 0x07bf, 0xa438, 0x886a, 0xa438, 0x026b, 0xa438, 0x7ebf,
        0xa438, 0x6a6c, 0xa438, 0x026b, 0xa438, 0x5b02, 0xa438, 0x62b5,
        0xa438, 0xbf6a, 0xa438, 0x0002, 0xa438, 0x6b5b, 0xa438, 0xbf64,
        0xa438, 0x4e02, 0xa438, 0x6b9d, 0xa438, 0xac28, 0xa438, 0x0bbf,
        0xa438, 0x6412, 0xa438, 0x026b, 0xa438, 0x9da1, 0xa438, 0x0502,
        0xa438, 0xaeec, 0xa438, 0xd104, 0xa438, 0xbf65, 0xa438, 0xce02,
        0xa438, 0x6b7e, 0xa438, 0xd104, 0xa438, 0xbf65, 0xa438, 0xd102,
        0xa438, 0x6b7e, 0xa438, 0xd102, 0xa438, 0xbf88, 0xa438, 0x6702,
        0xa438, 0x6b7e, 0xa438, 0xd104, 0xa438, 0xbf88, 0xa438, 0x6a02,
        0xa438, 0x6b7e, 0xa438, 0xaf62, 0xa438, 0x72f6, 0xa438, 0x0af6,
        0xa438, 0x09af, 0xa438, 0x34e3, 0xa438, 0x0285, 0xa438, 0xbe02,
        0xa438, 0x106c, 0xa438, 0xaf10, 0xa438, 0x6bf8, 0xa438, 0xfaef,
        0xa438, 0x69e0, 0xa438, 0x804c, 0xa438, 0xac25, 0xa438, 0x17e0,
        0xa438, 0x8040, 0xa438, 0xad25, 0xa438, 0x1a02, 0xa438, 0x85ed,
        0xa438, 0xe080, 0xa438, 0x40ac, 0xa438, 0x2511, 0xa438, 0xbf87,
        0xa438, 0x6502, 0xa438, 0x6b5b, 0xa438, 0xae09, 0xa438, 0x0287,
        0xa438, 0x2402, 0xa438, 0x875a, 0xa438, 0x0287, 0xa438, 0x4fef,
        0xa438, 0x96fe, 0xa438, 0xfc04, 0xa438, 0xf8e0, 0xa438, 0x8019,
        0xa438, 0xad20, 0xa438, 0x11e0, 0xa438, 0x8fe3, 0xa438, 0xac20,
        0xa438, 0x0502, 0xa438, 0x860a, 0xa438, 0xae03, 0xa438, 0x0286,
        0xa438, 0x7802, 0xa438, 0x86c1, 0xa438, 0x0287, 0xa438, 0x4ffc,
        0xa438, 0x04f8, 0xa438, 0xf9ef, 0xa438, 0x79fb, 0xa438, 0xbf87,
        0xa438, 0x6802, 0xa438, 0x6b9d, 0xa438, 0x5c20, 0xa438, 0x000d,
        0xa438, 0x4da1, 0xa438, 0x0151, 0xa438, 0xbf87, 0xa438, 0x6802,
        0xa438, 0x6b9d, 0xa438, 0x5c07, 0xa438, 0xffe3, 0xa438, 0x8fe4,
        0xa438, 0x1b31, 0xa438, 0x9f41, 0xa438, 0x0d48, 0xa438, 0xe38f,
        0xa438, 0xe51b, 0xa438, 0x319f, 0xa438, 0x38bf, 0xa438, 0x876b,
        0xa438, 0x026b, 0xa438, 0x9d5c, 0xa438, 0x07ff, 0xa438, 0xe38f,
        0xa438, 0xe61b, 0xa438, 0x319f, 0xa438, 0x280d, 0xa438, 0x48e3,
        0xa438, 0x8fe7, 0xa438, 0x1b31, 0xa438, 0x9f1f, 0xa438, 0xbf87,
        0xa438, 0x6e02, 0xa438, 0x6b9d, 0xa438, 0x5c07, 0xa438, 0xffe3,
        0xa438, 0x8fe8, 0xa438, 0x1b31, 0xa438, 0x9f0f, 0xa438, 0x0d48,
        0xa438, 0xe38f, 0xa438, 0xe91b, 0xa438, 0x319f, 0xa438, 0x06ee,
        0xa438, 0x8fe3, 0xa438, 0x01ae, 0xa438, 0x04ee, 0xa438, 0x8fe3,
        0xa438, 0x00ff, 0xa438, 0xef97, 0xa438, 0xfdfc, 0xa438, 0x04f8,
        0xa438, 0xf9ef, 0xa438, 0x79fb, 0xa438, 0xbf87, 0xa438, 0x6802,
        0xa438, 0x6b9d, 0xa438, 0x5c20, 0xa438, 0x000d, 0xa438, 0x4da1,
        0xa438, 0x0020, 0xa438, 0xbf87, 0xa438, 0x6802, 0xa438, 0x6b9d,
        0xa438, 0x5c06, 0xa438, 0x000d, 0xa438, 0x49e3, 0xa438, 0x8fea,
        0xa438, 0x1b31, 0xa438, 0x9f0e, 0xa438, 0xbf87, 0xa438, 0x7102,
        0xa438, 0x6b5b, 0xa438, 0xbf87, 0xa438, 0x7702, 0xa438, 0x6b5b,
        0xa438, 0xae0c, 0xa438, 0xbf87, 0xa438, 0x7102, 0xa438, 0x6b52,
        0xa438, 0xbf87, 0xa438, 0x7702, 0xa438, 0x6b52, 0xa438, 0xee8f,
        0xa438, 0xe300, 0xa438, 0xffef, 0xa438, 0x97fd, 0xa438, 0xfc04,
        0xa438, 0xf8f9, 0xa438, 0xef79, 0xa438, 0xfbbf, 0xa438, 0x8768,
        0xa438, 0x026b, 0xa438, 0x9d5c, 0xa438, 0x2000, 0xa438, 0x0d4d,
        0xa438, 0xa101, 0xa438, 0x4abf, 0xa438, 0x8768, 0xa438, 0x026b,
        0xa438, 0x9d5c, 0xa438, 0x07ff, 0xa438, 0xe38f, 0xa438, 0xeb1b,
        0xa438, 0x319f, 0xa438, 0x3a0d, 0xa438, 0x48e3, 0xa438, 0x8fec,
        0xa438, 0x1b31, 0xa438, 0x9f31, 0xa438, 0xbf87, 0xa438, 0x6b02,
        0xa438, 0x6b9d, 0xa438, 0xe38f, 0xa438, 0xed1b, 0xa438, 0x319f,
        0xa438, 0x240d, 0xa438, 0x48e3, 0xa438, 0x8fee, 0xa438, 0x1b31,
        0xa438, 0x9f1b, 0xa438, 0xbf87, 0xa438, 0x6e02, 0xa438, 0x6b9d,
        0xa438, 0xe38f, 0xa438, 0xef1b, 0xa438, 0x319f, 0xa438, 0x0ebf,
        0xa438, 0x8774, 0xa438, 0x026b, 0xa438, 0x5bbf, 0xa438, 0x877a,
        0xa438, 0x026b, 0xa438, 0x5bae, 0xa438, 0x00ff, 0xa438, 0xef97,
        0xa438, 0xfdfc, 0xa438, 0x04f8, 0xa438, 0xef79, 0xa438, 0xfbe0,
        0xa438, 0x8019, 0xa438, 0xad20, 0xa438, 0x1cee, 0xa438, 0x8fe3,
        0xa438, 0x00bf, 0xa438, 0x8771, 0xa438, 0x026b, 0xa438, 0x52bf,
        0xa438, 0x8777, 0xa438, 0x026b, 0xa438, 0x52bf, 0xa438, 0x8774,
        0xa438, 0x026b, 0xa438, 0x52bf, 0xa438, 0x877a, 0xa438, 0x026b,
        0xa438, 0x52ff, 0xa438, 0xef97, 0xa438, 0xfc04, 0xa438, 0xf8e0,
        0xa438, 0x8040, 0xa438, 0xf625, 0xa438, 0xe480, 0xa438, 0x40fc,
        0xa438, 0x04f8, 0xa438, 0xe080, 0xa438, 0x4cf6, 0xa438, 0x25e4,
        0xa438, 0x804c, 0xa438, 0xfc04, 0xa438, 0x55a4, 0xa438, 0xbaf0,
        0xa438, 0xa64a, 0xa438, 0xf0a6, 0xa438, 0x4cf0, 0xa438, 0xa64e,
        0xa438, 0x66a4, 0xa438, 0xb655, 0xa438, 0xa4b6, 0xa438, 0x00ac,
        0xa438, 0x0e66, 0xa438, 0xac0e, 0xa438, 0xee80, 0xa438, 0x4c3a,
        0xa438, 0xaf07, 0xa438, 0xd0af, 0xa438, 0x26d0, 0xa438, 0xa201,
        0xa438, 0x0ebf, 0xa438, 0x663d, 0xa438, 0x026b, 0xa438, 0x52bf,
        0xa438, 0x6643, 0xa438, 0x026b, 0xa438, 0x52ae, 0xa438, 0x11bf,
        0xa438, 0x6643, 0xa438, 0x026b, 0xa438, 0x5bd4, 0xa438, 0x0054,
        0xa438, 0xb4fe, 0xa438, 0xbf66, 0xa438, 0x3d02, 0xa438, 0x6b5b,
        0xa438, 0xd300, 0xa438, 0x020d, 0xa438, 0xf6a2, 0xa438, 0x0405,
        0xa438, 0xe081, 0xa438, 0x47ae, 0xa438, 0x03e0, 0xa438, 0x8148,
        0xa438, 0xac23, 0xa438, 0x02ae, 0xa438, 0x0268, 0xa438, 0xf01a,
        0xa438, 0x10ad, 0xa438, 0x2f04, 0xa438, 0xd100, 0xa438, 0xae05,
        0xa438, 0xad2c, 0xa438, 0x02d1, 0xa438, 0x0f1f, 0xa438, 0x00a2,
        0xa438, 0x0407, 0xa438, 0x3908, 0xa438, 0xad2f, 0xa438, 0x02d1,
        0xa438, 0x0002, 0xa438, 0x0e1c, 0xa438, 0x2b01, 0xa438, 0xad3a,
        0xa438, 0xc9af, 0xa438, 0x0dee, 0xa438, 0xa000, 0xa438, 0x2702,
        0xa438, 0x1beb, 0xa438, 0xe18f, 0xa438, 0xe1ac, 0xa438, 0x2819,
        0xa438, 0xee8f, 0xa438, 0xe101, 0xa438, 0x1f44, 0xa438, 0xbf65,
        0xa438, 0x9302, 0xa438, 0x6b9d, 0xa438, 0xe58f, 0xa438, 0xe21f,
        0xa438, 0x44d1, 0xa438, 0x02bf, 0xa438, 0x6593, 0xa438, 0x026b,
        0xa438, 0x7ee0, 0xa438, 0x82b1, 0xa438, 0xae49, 0xa438, 0xa001,
        0xa438, 0x0502, 0xa438, 0x1c4d, 0xa438, 0xae41, 0xa438, 0xa002,
        0xa438, 0x0502, 0xa438, 0x1c90, 0xa438, 0xae39, 0xa438, 0xa003,
        0xa438, 0x0502, 0xa438, 0x1c9d, 0xa438, 0xae31, 0xa438, 0xa004,
        0xa438, 0x0502, 0xa438, 0x1cbc, 0xa438, 0xae29, 0xa438, 0xa005,
        0xa438, 0x1e02, 0xa438, 0x1cc9, 0xa438, 0xe080, 0xa438, 0xdfac,
        0xa438, 0x2013, 0xa438, 0xac21, 0xa438, 0x10ac, 0xa438, 0x220d,
        0xa438, 0xe18f, 0xa438, 0xe2bf, 0xa438, 0x6593, 0xa438, 0x026b,
        0xa438, 0x7eee, 0xa438, 0x8fe1, 0xa438, 0x00ae, 0xa438, 0x08a0,
        0xa438, 0x0605, 0xa438, 0x021d, 0xa438, 0x07ae, 0xa438, 0x00e0,
        0xa438, 0x82b1, 0xa438, 0xaf1b, 0xa438, 0xe910, 0xa438, 0xbf4a,
        0xa438, 0x99bf, 0xa438, 0x4a00, 0xa438, 0xa86a, 0xa438, 0xfdad,
        0xa438, 0x5eca, 0xa438, 0xad5e, 0xa438, 0x88bd, 0xa438, 0x2c99,
        0xa438, 0xbd2c, 0xa438, 0x33bd, 0xa438, 0x3222, 0xa438, 0xbd32,
        0xa438, 0x11bd, 0xa438, 0x3200, 0xa438, 0xbd32, 0xa438, 0x77bd,
        0xa438, 0x3266, 0xa438, 0xbd32, 0xa438, 0x55bd, 0xa438, 0x3244,
        0xa438, 0xbd32, 0xa436, 0xb818, 0xa438, 0x15c5, 0xa436, 0xb81a,
        0xa438, 0x6255, 0xa436, 0xb81c, 0xa438, 0x34e1, 0xa436, 0xb81e,
        0xa438, 0x1068, 0xa436, 0xb850, 0xa438, 0x07cc, 0xa436, 0xb852,
        0xa438, 0x26ca, 0xa436, 0xb878, 0xa438, 0x0dbf, 0xa436, 0xb884,
        0xa438, 0x1BB1, 0xa436, 0xb832, 0xa438, 0x00ff, 0xa436, 0x0000,
        0xa438, 0x0000, 0xB82E, 0x0000, 0xa436, 0x8023, 0xa438, 0x0000,
        0xa436, 0x801E, 0xa438, 0x0031, 0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16  phy_mcu_ram_code_8125d_1_2[] = {
        0xb892, 0x0000, 0xB88E, 0xC28F, 0xB890, 0x252D, 0xB88E, 0xC290,
        0xB890, 0xC924, 0xB88E, 0xC291, 0xB890, 0xC92E, 0xB88E, 0xC292,
        0xB890, 0xF626, 0xB88E, 0xC293, 0xB890, 0xF630, 0xB88E, 0xC294,
        0xB890, 0xA328, 0xB88E, 0xC295, 0xB890, 0xA332, 0xB88E, 0xC296,
        0xB890, 0xD72B, 0xB88E, 0xC297, 0xB890, 0xD735, 0xB88E, 0xC298,
        0xB890, 0x8A2E, 0xB88E, 0xC299, 0xB890, 0x8A38, 0xB88E, 0xC29A,
        0xB890, 0xBE32, 0xB88E, 0xC29B, 0xB890, 0xBE3C, 0xB88E, 0xC29C,
        0xB890, 0x7436, 0xB88E, 0xC29D, 0xB890, 0x7440, 0xB88E, 0xC29E,
        0xB890, 0xAD3B, 0xB88E, 0xC29F, 0xB890, 0xAD45, 0xB88E, 0xC2A0,
        0xB890, 0x6640, 0xB88E, 0xC2A1, 0xB890, 0x664A, 0xB88E, 0xC2A2,
        0xB890, 0xA646, 0xB88E, 0xC2A3, 0xB890, 0xA650, 0xB88E, 0xC2A4,
        0xB890, 0x624C, 0xB88E, 0xC2A5, 0xB890, 0x6256, 0xB88E, 0xC2A6,
        0xB890, 0xA453, 0xB88E, 0xC2A7, 0xB890, 0xA45D, 0xB88E, 0xC2A8,
        0xB890, 0x665A, 0xB88E, 0xC2A9, 0xB890, 0x6664, 0xB88E, 0xC2AA,
        0xB890, 0xAC62, 0xB88E, 0xC2AB, 0xB890, 0xAC6C, 0xB88E, 0xC2AC,
        0xB890, 0x746A, 0xB88E, 0xC2AD, 0xB890, 0x7474, 0xB88E, 0xC2AE,
        0xB890, 0xBCFA, 0xB88E, 0xC2AF, 0xB890, 0xBCFD, 0xB88E, 0xC2B0,
        0xB890, 0x79FF, 0xB88E, 0xC2B1, 0xB890, 0x7901, 0xB88E, 0xC2B2,
        0xB890, 0xF703, 0xB88E, 0xC2B3, 0xB890, 0xF706, 0xB88E, 0xC2B4,
        0xB890, 0x7408, 0xB88E, 0xC2B5, 0xB890, 0x740A, 0xB88E, 0xC2B6,
        0xB890, 0xF10C, 0xB88E, 0xC2B7, 0xB890, 0xF10F, 0xB88E, 0xC2B8,
        0xB890, 0x6F10, 0xB88E, 0xC2B9, 0xB890, 0x6F13, 0xB88E, 0xC2BA,
        0xB890, 0xEC15, 0xB88E, 0xC2BB, 0xB890, 0xEC18, 0xB88E, 0xC2BC,
        0xB890, 0x6A1A, 0xB88E, 0xC2BD, 0xB890, 0x6A1C, 0xB88E, 0xC2BE,
        0xB890, 0xE71E, 0xB88E, 0xC2BF, 0xB890, 0xE721, 0xB88E, 0xC2C0,
        0xB890, 0x6424, 0xB88E, 0xC2C1, 0xB890, 0x6425, 0xB88E, 0xC2C2,
        0xB890, 0xE228, 0xB88E, 0xC2C3, 0xB890, 0xE22A, 0xB88E, 0xC2C4,
        0xB890, 0x5F2B, 0xB88E, 0xC2C5, 0xB890, 0x5F2E, 0xB88E, 0xC2C6,
        0xB890, 0xDC31, 0xB88E, 0xC2C7, 0xB890, 0xDC33, 0xB88E, 0xC2C8,
        0xB890, 0x2035, 0xB88E, 0xC2C9, 0xB890, 0x2036, 0xB88E, 0xC2CA,
        0xB890, 0x9F3A, 0xB88E, 0xC2CB, 0xB890, 0x9F3A, 0xB88E, 0xC2CC,
        0xB890, 0x4430, 0xFFFF, 0xFFFF
};

static const u16  phy_mcu_ram_code_8125d_1_3[] = {
        0xa436, 0xacca, 0xa438, 0x0104, 0xa436, 0xaccc, 0xa438, 0x8000,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xfd47, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xe56f, 0xa436, 0xacd0, 0xa438, 0x01c0,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xed97, 0xa436, 0xacd0, 0xa438, 0x01c8,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xf5bf, 0xa436, 0xacd0, 0xa438, 0x01d0,
        0xa436, 0xacce, 0xa438, 0xfb07, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb0f, 0xa436, 0xacd0, 0xa438, 0x01d8,
        0xa436, 0xacce, 0xa438, 0xa087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0xa00f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0xa807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0xa88f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0xb027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0xb02f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0xb847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0xb84f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0xfb17, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb1f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xa017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0xa01f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0xa837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0xa83f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0xb097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0xb05f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0xb857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0xb89f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0xfb27, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb2f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x8087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x800f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x8807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x888f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x9027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x902f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x9847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x984f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0xa0a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0xa8af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0xa067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0xa86f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb37, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb3f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x8017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x801f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x8837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x883f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x9097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x905f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x9857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x989f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0xb0b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0xb8bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0xb077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0xb87f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb47, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb4f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x600f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x6807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x688f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x7027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x702f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x7847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x784f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0x80a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x88af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x8067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x886f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb57, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb5f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x601f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x6837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x683f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x7097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x705f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x7857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x789f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0x90b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x98bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x9077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x987f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb67, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb6f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x4087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x400f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x4807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x488f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x5027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x502f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x5847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x584f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0x60a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x68af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x6067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x686f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb77, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb7f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x4017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x401f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x4837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x483f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x5097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x505f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x5857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x589f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0x70b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x78bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x7077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x787f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb87, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb8f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x40a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x48af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x4067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x486f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb97, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb9f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x50b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x58bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x5077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x587f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfba7, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfbaf, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x2067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x286f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfbb7, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfbbf, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x3077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x387f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfff9, 0xa436, 0xacd0, 0xa438, 0x17ff,
        0xa436, 0xacce, 0xa438, 0xfff9, 0xa436, 0xacd0, 0xa438, 0x17ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xfff8, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb47, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb4f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x600f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x6807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x688f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x7027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x702f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x7847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x784f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0x80a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x88af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x8067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x886f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb57, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb5f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x601f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x6837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x683f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x7097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x705f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x7857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x789f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0x90b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x98bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x9077, 0xa436, 0xacd0, 0xa438, 0x1171,
        0xa436, 0xacce, 0xa438, 0x987f, 0xa436, 0xacd0, 0xa438, 0x1179,
        0xa436, 0xacca, 0xa438, 0x0004, 0xa436, 0xacc6, 0xa438, 0x0008,
        0xa436, 0xacc8, 0xa438, 0xc000, 0xa436, 0xacc6, 0xa438, 0x0015,
        0xa436, 0xacc8, 0xa438, 0xc043, 0xa436, 0xacc8, 0xa438, 0x0000,
        0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125d_1_efuse[] = {
        0xB87C, 0x8014, 0xB87E, 0x90C0, 0xa436, 0x8023, 0xa438, 0x3800,
        0xa436, 0xB82E, 0xa438, 0x0001, 0xb820, 0x0010, 0xa436, 0x843d,
        0xa438, 0xaf84, 0xa438, 0x55af, 0xa438, 0x8458, 0xa438, 0xaf84,
        0xa438, 0x58af, 0xa438, 0x8458, 0xa438, 0xaf84, 0xa438, 0x58af,
        0xa438, 0x8458, 0xa438, 0xaf84, 0xa438, 0x58af, 0xa438, 0x8458,
        0xa438, 0xaf26, 0xa438, 0xd000, 0xa436, 0xb818, 0xa438, 0x26ca,
        0xa436, 0xb81a, 0xa438, 0xffff, 0xa436, 0xb81c, 0xa438, 0xffff,
        0xa436, 0xb81e, 0xa438, 0xffff, 0xa436, 0xb850, 0xa438, 0xffff,
        0xa436, 0xb852, 0xa438, 0xffff, 0xa436, 0xb878, 0xa438, 0xffff,
        0xa436, 0xb884, 0xa438, 0xffff, 0xa436, 0xb832, 0xa438, 0x0001,
        0xa436, 0x0000, 0xa438, 0x0000, 0xB82E, 0x0000, 0xa436, 0x8023,
        0xa438, 0x0000, 0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16  phy_mcu_ram_code_8125d_2_1[] = {
        0xa436, 0x8023, 0xa438, 0x3801, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x808e, 0xa438, 0x1800, 0xa438, 0x80d6,
        0xa438, 0x1800, 0xa438, 0x81e2, 0xa438, 0x1800, 0xa438, 0x81e2,
        0xa438, 0x1800, 0xa438, 0x81e2, 0xa438, 0x1800, 0xa438, 0x81e2,
        0xa438, 0x1800, 0xa438, 0x81e2, 0xa438, 0xd500, 0xa438, 0xc48d,
        0xa438, 0xd504, 0xa438, 0x8d03, 0xa438, 0xd701, 0xa438, 0x4045,
        0xa438, 0xad02, 0xa438, 0xd504, 0xa438, 0xd706, 0xa438, 0x2529,
        0xa438, 0x8021, 0xa438, 0xd718, 0xa438, 0x607b, 0xa438, 0x40da,
        0xa438, 0xf019, 0xa438, 0x459a, 0xa438, 0xf03f, 0xa438, 0xd718,
        0xa438, 0x62bb, 0xa438, 0xbb01, 0xa438, 0xd75e, 0xa438, 0x6231,
        0xa438, 0x0cf0, 0xa438, 0x0c10, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0xd70c, 0xa438, 0x6147, 0xa438, 0x8480, 0xa438, 0x8440,
        0xa438, 0x8420, 0xa438, 0xa410, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0808, 0xa438, 0xf002, 0xa438, 0xa4f0,
        0xa438, 0xf03c, 0xa438, 0xbb02, 0xa438, 0xd75e, 0xa438, 0x6231,
        0xa438, 0x0cf0, 0xa438, 0x0c20, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0xd70c, 0xa438, 0x6147, 0xa438, 0x8480, 0xa438, 0x8440,
        0xa438, 0xa420, 0xa438, 0x8410, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0804, 0xa438, 0xf002, 0xa438, 0xa4f0,
        0xa438, 0xf028, 0xa438, 0xbb04, 0xa438, 0xd75e, 0xa438, 0x6231,
        0xa438, 0x0cf0, 0xa438, 0x0c40, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0xd70c, 0xa438, 0x6147, 0xa438, 0x8480, 0xa438, 0xa440,
        0xa438, 0x8420, 0xa438, 0x8410, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0802, 0xa438, 0xf002, 0xa438, 0xa4f0,
        0xa438, 0xf014, 0xa438, 0xbb08, 0xa438, 0xd75e, 0xa438, 0x6231,
        0xa438, 0x0cf0, 0xa438, 0x0c80, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0xd70c, 0xa438, 0x6147, 0xa438, 0xa480, 0xa438, 0x8440,
        0xa438, 0x8420, 0xa438, 0x8410, 0xa438, 0xce00, 0xa438, 0xd505,
        0xa438, 0x0c0f, 0xa438, 0x0801, 0xa438, 0xf002, 0xa438, 0xa4f0,
        0xa438, 0xce00, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0x1000, 0xa438, 0x1829, 0xa438, 0xd73e, 0xa438, 0x6074,
        0xa438, 0xd718, 0xa438, 0x5f2d, 0xa438, 0x1000, 0xa438, 0x81b7,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0x1000, 0xa438, 0x1829,
        0xa438, 0xd73e, 0xa438, 0x7f74, 0xa438, 0x1000, 0xa438, 0x81ce,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0x1000, 0xa438, 0x1829,
        0xa438, 0xd718, 0xa438, 0x5f6d, 0xa438, 0x1800, 0xa438, 0x1660,
        0xa438, 0xd75e, 0xa438, 0x68b1, 0xa438, 0xd504, 0xa438, 0xd71e,
        0xa438, 0x667b, 0xa438, 0x645a, 0xa438, 0x6239, 0xa438, 0x0cf0,
        0xa438, 0x0c10, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0808,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xd70c, 0xa438, 0x60c7,
        0xa438, 0x8480, 0xa438, 0x8440, 0xa438, 0x8420, 0xa438, 0xa410,
        0xa438, 0xf032, 0xa438, 0xa4f0, 0xa438, 0xf030, 0xa438, 0x0cf0,
        0xa438, 0x0c20, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0804,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xd70c, 0xa438, 0x60c7,
        0xa438, 0x8480, 0xa438, 0x8440, 0xa438, 0xa420, 0xa438, 0x8410,
        0xa438, 0xf022, 0xa438, 0xa4f0, 0xa438, 0xf020, 0xa438, 0x0cf0,
        0xa438, 0x0c40, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0802,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xd70c, 0xa438, 0x60c7,
        0xa438, 0x8480, 0xa438, 0xa440, 0xa438, 0x8420, 0xa438, 0x8410,
        0xa438, 0xf012, 0xa438, 0xa4f0, 0xa438, 0xf010, 0xa438, 0x0cf0,
        0xa438, 0x0c80, 0xa438, 0xd505, 0xa438, 0x0c0f, 0xa438, 0x0801,
        0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xd70c, 0xa438, 0x60c7,
        0xa438, 0xa480, 0xa438, 0x8440, 0xa438, 0x8420, 0xa438, 0x8410,
        0xa438, 0xf002, 0xa438, 0xa4f0, 0xa438, 0x1800, 0xa438, 0x168c,
        0xa438, 0xd500, 0xa438, 0xd706, 0xa438, 0x2529, 0xa438, 0x80e0,
        0xa438, 0xd718, 0xa438, 0x607b, 0xa438, 0x40da, 0xa438, 0xf00f,
        0xa438, 0x431a, 0xa438, 0xf021, 0xa438, 0xd718, 0xa438, 0x617b,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0x1000, 0xa438, 0x1b1a,
        0xa438, 0xd718, 0xa438, 0x608e, 0xa438, 0xd73e, 0xa438, 0x5f34,
        0xa438, 0xf020, 0xa438, 0xf053, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0x1000, 0xa438, 0x1b1a, 0xa438, 0xd718, 0xa438, 0x608e,
        0xa438, 0xd73e, 0xa438, 0x5f34, 0xa438, 0xf023, 0xa438, 0xf067,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0x1000, 0xa438, 0x1b1a,
        0xa438, 0xd718, 0xa438, 0x608e, 0xa438, 0xd73e, 0xa438, 0x5f34,
        0xa438, 0xf026, 0xa438, 0xf07b, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0x1000, 0xa438, 0x1b1a, 0xa438, 0xd718, 0xa438, 0x608e,
        0xa438, 0xd73e, 0xa438, 0x5f34, 0xa438, 0xf029, 0xa438, 0xf08f,
        0xa438, 0x1000, 0xa438, 0x81b7, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0xd73e, 0xa438, 0x7fb4, 0xa438, 0x1000, 0xa438, 0x81ce,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd718, 0xa438, 0x5fae,
        0xa438, 0xf028, 0xa438, 0x1000, 0xa438, 0x81b7, 0xa438, 0x1000,
        0xa438, 0x1a8a, 0xa438, 0xd73e, 0xa438, 0x7fb4, 0xa438, 0x1000,
        0xa438, 0x81ce, 0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd718,
        0xa438, 0x5fae, 0xa438, 0xf039, 0xa438, 0x1000, 0xa438, 0x81b7,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd73e, 0xa438, 0x7fb4,
        0xa438, 0x1000, 0xa438, 0x81ce, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0xd718, 0xa438, 0x5fae, 0xa438, 0xf04a, 0xa438, 0x1000,
        0xa438, 0x81b7, 0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd73e,
        0xa438, 0x7fb4, 0xa438, 0x1000, 0xa438, 0x81ce, 0xa438, 0x1000,
        0xa438, 0x1a8a, 0xa438, 0xd718, 0xa438, 0x5fae, 0xa438, 0xf05b,
        0xa438, 0xd719, 0xa438, 0x4119, 0xa438, 0xd504, 0xa438, 0xac01,
        0xa438, 0xae01, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a78,
        0xa438, 0xf00a, 0xa438, 0xd719, 0xa438, 0x4118, 0xa438, 0xd504,
        0xa438, 0xac11, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xa410,
        0xa438, 0xce00, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0xd718, 0xa438, 0x5fb0, 0xa438, 0xd505, 0xa438, 0xd719,
        0xa438, 0x4079, 0xa438, 0xa80f, 0xa438, 0xf05d, 0xa438, 0x4b98,
        0xa438, 0xa808, 0xa438, 0xf05a, 0xa438, 0xd719, 0xa438, 0x4119,
        0xa438, 0xd504, 0xa438, 0xac02, 0xa438, 0xae01, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a78, 0xa438, 0xf00a, 0xa438, 0xd719,
        0xa438, 0x4118, 0xa438, 0xd504, 0xa438, 0xac22, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0xa420, 0xa438, 0xce00, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd718, 0xa438, 0x5fb0,
        0xa438, 0xd505, 0xa438, 0xd719, 0xa438, 0x4079, 0xa438, 0xa80f,
        0xa438, 0xf03f, 0xa438, 0x47d8, 0xa438, 0xa804, 0xa438, 0xf03c,
        0xa438, 0xd719, 0xa438, 0x4119, 0xa438, 0xd504, 0xa438, 0xac04,
        0xa438, 0xae01, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a78,
        0xa438, 0xf00a, 0xa438, 0xd719, 0xa438, 0x4118, 0xa438, 0xd504,
        0xa438, 0xac44, 0xa438, 0xd501, 0xa438, 0xce01, 0xa438, 0xa440,
        0xa438, 0xce00, 0xa438, 0xd500, 0xa438, 0x1000, 0xa438, 0x1a8a,
        0xa438, 0xd718, 0xa438, 0x5fb0, 0xa438, 0xd505, 0xa438, 0xd719,
        0xa438, 0x4079, 0xa438, 0xa80f, 0xa438, 0xf021, 0xa438, 0x4418,
        0xa438, 0xa802, 0xa438, 0xf01e, 0xa438, 0xd719, 0xa438, 0x4119,
        0xa438, 0xd504, 0xa438, 0xac08, 0xa438, 0xae01, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a78, 0xa438, 0xf00a, 0xa438, 0xd719,
        0xa438, 0x4118, 0xa438, 0xd504, 0xa438, 0xac88, 0xa438, 0xd501,
        0xa438, 0xce01, 0xa438, 0xa480, 0xa438, 0xce00, 0xa438, 0xd500,
        0xa438, 0x1000, 0xa438, 0x1a8a, 0xa438, 0xd718, 0xa438, 0x5fb0,
        0xa438, 0xd505, 0xa438, 0xd719, 0xa438, 0x4079, 0xa438, 0xa80f,
        0xa438, 0xf003, 0xa438, 0x4058, 0xa438, 0xa801, 0xa438, 0x1800,
        0xa438, 0x1736, 0xa438, 0xd73e, 0xa438, 0xd505, 0xa438, 0x3088,
        0xa438, 0x81c0, 0xa438, 0x61d3, 0xa438, 0x6172, 0xa438, 0x6111,
        0xa438, 0x60b0, 0xa438, 0xf00d, 0xa438, 0x3298, 0xa438, 0x81cb,
        0xa438, 0xf00a, 0xa438, 0xa808, 0xa438, 0xf008, 0xa438, 0xa804,
        0xa438, 0xf006, 0xa438, 0xa802, 0xa438, 0xf004, 0xa438, 0xa801,
        0xa438, 0xf002, 0xa438, 0xa80f, 0xa438, 0xd500, 0xa438, 0x0800,
        0xa438, 0xd505, 0xa438, 0xd75e, 0xa438, 0x6211, 0xa438, 0xd71e,
        0xa438, 0x619b, 0xa438, 0x611a, 0xa438, 0x6099, 0xa438, 0x0c0f,
        0xa438, 0x0808, 0xa438, 0xf009, 0xa438, 0x0c0f, 0xa438, 0x0804,
        0xa438, 0xf006, 0xa438, 0x0c0f, 0xa438, 0x0802, 0xa438, 0xf003,
        0xa438, 0x0c0f, 0xa438, 0x0801, 0xa438, 0xd500, 0xa438, 0x0800,
        0xa436, 0xA026, 0xa438, 0xffff, 0xa436, 0xA024, 0xa438, 0xffff,
        0xa436, 0xA022, 0xa438, 0xffff, 0xa436, 0xA020, 0xa438, 0xffff,
        0xa436, 0xA006, 0xa438, 0xffff, 0xa436, 0xA004, 0xa438, 0x16ab,
        0xa436, 0xA002, 0xa438, 0x1663, 0xa436, 0xA000, 0xa438, 0x1608,
        0xa436, 0xA008, 0xa438, 0x0700, 0xa436, 0xA016, 0xa438, 0x0000,
        0xa436, 0xA012, 0xa438, 0x07f8, 0xa436, 0xA014, 0xa438, 0xcc01,
        0xa438, 0x20f6, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000, 0xa436, 0xA152,
        0xa438, 0x021c, 0xa436, 0xA154, 0xa438, 0x2100, 0xa436, 0xA156,
        0xa438, 0x3fff, 0xa436, 0xA158, 0xa438, 0x3fff, 0xa436, 0xA15A,
        0xa438, 0x3fff, 0xa436, 0xA15C, 0xa438, 0x3fff, 0xa436, 0xA15E,
        0xa438, 0x3fff, 0xa436, 0xA160, 0xa438, 0x3fff, 0xa436, 0xA150,
        0xa438, 0x0003, 0xa436, 0xA016, 0xa438, 0x0010, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x8014, 0xa438, 0x1800, 0xa438, 0x803d,
        0xa438, 0x1800, 0xa438, 0x804a, 0xa438, 0x1800, 0xa438, 0x804e,
        0xa438, 0x1800, 0xa438, 0x8052, 0xa438, 0x1800, 0xa438, 0x8092,
        0xa438, 0x1800, 0xa438, 0x80a0, 0xa438, 0xc2ff, 0xa438, 0x9a40,
        0xa438, 0x1800, 0xa438, 0x0042, 0xa438, 0x1000, 0xa438, 0x02e5,
        0xa438, 0xba20, 0xa438, 0x1000, 0xa438, 0x02b4, 0xa438, 0xd701,
        0xa438, 0x4103, 0xa438, 0xd700, 0xa438, 0x5f6c, 0xa438, 0x1000,
        0xa438, 0x8024, 0xa438, 0x9a20, 0xa438, 0x1800, 0xa438, 0x0073,
        0xa438, 0x1800, 0xa438, 0x0084, 0xa438, 0xd701, 0xa438, 0x4061,
        0xa438, 0xba0f, 0xa438, 0xf004, 0xa438, 0x4060, 0xa438, 0x1000,
        0xa438, 0x802d, 0xa438, 0xba10, 0xa438, 0x0800, 0xa438, 0xd700,
        0xa438, 0x60bb, 0xa438, 0x611c, 0xa438, 0x0c0f, 0xa438, 0x1a01,
        0xa438, 0xf00a, 0xa438, 0x60fc, 0xa438, 0x0c0f, 0xa438, 0x1a02,
        0xa438, 0xf006, 0xa438, 0x0c0f, 0xa438, 0x1a04, 0xa438, 0xf003,
        0xa438, 0x0c0f, 0xa438, 0x1a08, 0xa438, 0x0800, 0xa438, 0x0c0f,
        0xa438, 0x0504, 0xa438, 0xad02, 0xa438, 0xd73e, 0xa438, 0x40f6,
        0xa438, 0x1000, 0xa438, 0x02c0, 0xa438, 0xd700, 0xa438, 0x5fac,
        0xa438, 0x1000, 0xa438, 0x8024, 0xa438, 0x1800, 0xa438, 0x0139,
        0xa438, 0x9a3f, 0xa438, 0x8bf0, 0xa438, 0x1800, 0xa438, 0x02df,
        0xa438, 0x9a3f, 0xa438, 0x9910, 0xa438, 0x1800, 0xa438, 0x02d7,
        0xa438, 0xad02, 0xa438, 0x8d01, 0xa438, 0x9a7f, 0xa438, 0x9910,
        0xa438, 0x9860, 0xa438, 0xcb00, 0xa438, 0xd501, 0xa438, 0xce01,
        0xa438, 0x85f0, 0xa438, 0xd500, 0xa438, 0x0c0f, 0xa438, 0x0505,
        0xa438, 0xb820, 0xa438, 0xc000, 0xa438, 0xc100, 0xa438, 0xc628,
        0xa438, 0xc700, 0xa438, 0xc801, 0xa438, 0xc91e, 0xa438, 0xc001,
        0xa438, 0x4019, 0xa438, 0xc6f8, 0xa438, 0xc702, 0xa438, 0xc809,
        0xa438, 0xc940, 0xa438, 0xc002, 0xa438, 0x4019, 0xa438, 0x1000,
        0xa438, 0x02cc, 0xa438, 0xd700, 0xa438, 0x5fa7, 0xa438, 0xc010,
        0xa438, 0x1000, 0xa438, 0x02cc, 0xa438, 0xd700, 0xa438, 0x5fa0,
        0xa438, 0xc020, 0xa438, 0x1000, 0xa438, 0x02cc, 0xa438, 0xd700,
        0xa438, 0x5fa1, 0xa438, 0x0c0f, 0xa438, 0x0506, 0xa438, 0xb840,
        0xa438, 0xc6ca, 0xa438, 0xc701, 0xa438, 0xc809, 0xa438, 0xc900,
        0xa438, 0xc001, 0xa438, 0x4019, 0xa438, 0xc6b8, 0xa438, 0xc700,
        0xa438, 0xc800, 0xa438, 0xc900, 0xa438, 0xc008, 0xa438, 0x4019,
        0xa438, 0x1000, 0xa438, 0x02cc, 0xa438, 0xd700, 0xa438, 0x5fa5,
        0xa438, 0x8580, 0xa438, 0x8d02, 0xa438, 0x1800, 0xa438, 0x018f,
        0xa438, 0x1000, 0xa438, 0x02cc, 0xa438, 0xd700, 0xa438, 0x6124,
        0xa438, 0xd73e, 0xa438, 0x5f75, 0xa438, 0xd700, 0xa438, 0x5f2c,
        0xa438, 0x1000, 0xa438, 0x8024, 0xa438, 0x9a20, 0xa438, 0xfff5,
        0xa438, 0x1800, 0xa438, 0x00b8, 0xa438, 0x0c0f, 0xa438, 0x0503,
        0xa438, 0xad02, 0xa438, 0x68c8, 0xa438, 0x1000, 0xa438, 0x02c0,
        0xa438, 0xd700, 0xa438, 0x6848, 0xa438, 0x604d, 0xa438, 0xfffb,
        0xa438, 0xd73e, 0xa438, 0x6082, 0xa438, 0x1000, 0xa438, 0x02a1,
        0xa438, 0x8a0f, 0xa438, 0x1000, 0xa438, 0x02c0, 0xa438, 0xd700,
        0xa438, 0x5fae, 0xa438, 0x1000, 0xa438, 0x02de, 0xa438, 0x1000,
        0xa438, 0x02c0, 0xa438, 0xd700, 0xa438, 0x5faf, 0xa438, 0x8d01,
        0xa438, 0x8b0f, 0xa438, 0x1000, 0xa438, 0x02c0, 0xa438, 0xd700,
        0xa438, 0x2a58, 0xa438, 0x80c5, 0xa438, 0x2a5b, 0xa438, 0x80cd,
        0xa438, 0x2b53, 0xa438, 0x80d9, 0xa438, 0xfff7, 0xa438, 0x1000,
        0xa438, 0x022a, 0xa438, 0x1000, 0xa438, 0x02e5, 0xa438, 0xba40,
        0xa438, 0x1000, 0xa438, 0x02fd, 0xa438, 0xf018, 0xa438, 0x1000,
        0xa438, 0x022a, 0xa438, 0x1000, 0xa438, 0x02e5, 0xa438, 0xba40,
        0xa438, 0x1000, 0xa438, 0x02c0, 0xa438, 0xd700, 0xa438, 0x5faa,
        0xa438, 0x1000, 0xa438, 0x02fd, 0xa438, 0xf00c, 0xa438, 0x1000,
        0xa438, 0x022a, 0xa438, 0x1000, 0xa438, 0x02fd, 0xa438, 0x1000,
        0xa438, 0x02c0, 0xa438, 0xd700, 0xa438, 0x5fab, 0xa438, 0x1000,
        0xa438, 0x02e5, 0xa438, 0xba40, 0xa438, 0x1000, 0xa438, 0x02c0,
        0xa438, 0xd700, 0xa438, 0x6088, 0xa438, 0xfffc, 0xa438, 0x1800,
        0xa438, 0x0120, 0xa438, 0x1800, 0xa438, 0x0122, 0xa436, 0xA08E,
        0xa438, 0x00db, 0xa436, 0xA08C, 0xa438, 0x00b4, 0xa436, 0xA08A,
        0xa438, 0x015a, 0xa436, 0xA088, 0xa438, 0x02d6, 0xa436, 0xA086,
        0xa438, 0x02de, 0xa436, 0xA084, 0xa438, 0x0137, 0xa436, 0xA082,
        0xa438, 0x0071, 0xa436, 0xA080, 0xa438, 0x0041, 0xa436, 0xA090,
        0xa438, 0x00ff, 0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x801d, 0xa438, 0x1800, 0xa438, 0x808a,
        0xa438, 0x1800, 0xa438, 0x80a5, 0xa438, 0x1800, 0xa438, 0x80b8,
        0xa438, 0x1800, 0xa438, 0x8108, 0xa438, 0x1800, 0xa438, 0x810f,
        0xa438, 0x1800, 0xa438, 0x811b, 0xa438, 0x8980, 0xa438, 0xd702,
        0xa438, 0x6126, 0xa438, 0xd704, 0xa438, 0x4063, 0xa438, 0xd702,
        0xa438, 0x6060, 0xa438, 0xd702, 0xa438, 0x6077, 0xa438, 0x1800,
        0xa438, 0x0c29, 0xa438, 0x1800, 0xa438, 0x0c2b, 0xa438, 0x1000,
        0xa438, 0x115a, 0xa438, 0xd71f, 0xa438, 0x5fb4, 0xa438, 0xd702,
        0xa438, 0x6c46, 0xa438, 0xd704, 0xa438, 0x4063, 0xa438, 0xd702,
        0xa438, 0x6060, 0xa438, 0xd702, 0xa438, 0x6b97, 0xa438, 0xa340,
        0xa438, 0x0c06, 0xa438, 0x0102, 0xa438, 0xce01, 0xa438, 0x1000,
        0xa438, 0x117a, 0xa438, 0xa240, 0xa438, 0xa902, 0xa438, 0xa204,
        0xa438, 0xa280, 0xa438, 0xa364, 0xa438, 0xab02, 0xa438, 0x8380,
        0xa438, 0xa00a, 0xa438, 0xcd8d, 0xa438, 0x1000, 0xa438, 0x115a,
        0xa438, 0xd706, 0xa438, 0x5fb5, 0xa438, 0xb920, 0xa438, 0x1000,
        0xa438, 0x115a, 0xa438, 0xd71f, 0xa438, 0x7fb4, 0xa438, 0x9920,
        0xa438, 0x1000, 0xa438, 0x115a, 0xa438, 0xd71f, 0xa438, 0x6065,
        0xa438, 0x7c74, 0xa438, 0xfffb, 0xa438, 0xb820, 0xa438, 0x1000,
        0xa438, 0x115a, 0xa438, 0xd71f, 0xa438, 0x7fa5, 0xa438, 0x9820,
        0xa438, 0xa410, 0xa438, 0x8902, 0xa438, 0xa120, 0xa438, 0xa380,
        0xa438, 0xce02, 0xa438, 0x1000, 0xa438, 0x117a, 0xa438, 0x8280,
        0xa438, 0xa324, 0xa438, 0xab02, 0xa438, 0xa00a, 0xa438, 0x8118,
        0xa438, 0x863f, 0xa438, 0x87fb, 0xa438, 0xcd8e, 0xa438, 0xd193,
        0xa438, 0xd047, 0xa438, 0x1000, 0xa438, 0x115a, 0xa438, 0x1000,
        0xa438, 0x115f, 0xa438, 0xd700, 0xa438, 0x5f7b, 0xa438, 0xa280,
        0xa438, 0x1000, 0xa438, 0x115a, 0xa438, 0x1000, 0xa438, 0x115f,
        0xa438, 0xd706, 0xa438, 0x5f78, 0xa438, 0xa210, 0xa438, 0xd700,
        0xa438, 0x6083, 0xa438, 0xd101, 0xa438, 0xd047, 0xa438, 0xf003,
        0xa438, 0xd160, 0xa438, 0xd04b, 0xa438, 0x1000, 0xa438, 0x115a,
        0xa438, 0x1000, 0xa438, 0x115f, 0xa438, 0xd700, 0xa438, 0x5f7b,
        0xa438, 0x1000, 0xa438, 0x115a, 0xa438, 0x1000, 0xa438, 0x115f,
        0xa438, 0xd706, 0xa438, 0x5f79, 0xa438, 0x8120, 0xa438, 0xbb20,
        0xa438, 0x1800, 0xa438, 0x0c8b, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8f80, 0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0c3c,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa608, 0xa438, 0x9503,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8f80, 0xa438, 0x9503,
        0xa438, 0xd704, 0xa438, 0x6192, 0xa438, 0xd702, 0xa438, 0x4116,
        0xa438, 0xce04, 0xa438, 0x1000, 0xa438, 0x117a, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8f40, 0xa438, 0x9503, 0xa438, 0x1800,
        0xa438, 0x0b3d, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xaf40,
        0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0b48, 0xa438, 0xd704,
        0xa438, 0x6192, 0xa438, 0xd702, 0xa438, 0x4116, 0xa438, 0xce04,
        0xa438, 0x1000, 0xa438, 0x117a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8f40, 0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x1269,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xaf40, 0xa438, 0x9503,
        0xa438, 0x1800, 0xa438, 0x1274, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xa608, 0xa438, 0xc700, 0xa438, 0x9503, 0xa438, 0xce54,
        0xa438, 0x1000, 0xa438, 0x117a, 0xa438, 0xa290, 0xa438, 0xa304,
        0xa438, 0xab02, 0xa438, 0xd700, 0xa438, 0x6050, 0xa438, 0xab04,
        0xa438, 0x0c38, 0xa438, 0x0608, 0xa438, 0xaa0b, 0xa438, 0xd702,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8d01, 0xa438, 0xae40,
        0xa438, 0x4044, 0xa438, 0x8e20, 0xa438, 0x9503, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8c20, 0xa438, 0x9503, 0xa438, 0xd700,
        0xa438, 0x6078, 0xa438, 0xd700, 0xa438, 0x609a, 0xa438, 0xd109,
        0xa438, 0xd074, 0xa438, 0xf003, 0xa438, 0xd109, 0xa438, 0xd075,
        0xa438, 0x1000, 0xa438, 0x115a, 0xa438, 0xd704, 0xa438, 0x6252,
        0xa438, 0xd702, 0xa438, 0x4116, 0xa438, 0xce54, 0xa438, 0x1000,
        0xa438, 0x117a, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8f40,
        0xa438, 0x9503, 0xa438, 0xa00a, 0xa438, 0xd704, 0xa438, 0x41e7,
        0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xa570, 0xa438, 0x9503,
        0xa438, 0xf00a, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xaf40,
        0xa438, 0x9503, 0xa438, 0x800a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0x8570, 0xa438, 0x9503, 0xa438, 0xd704, 0xa438, 0x60f3,
        0xa438, 0xd71f, 0xa438, 0x60ee, 0xa438, 0xd700, 0xa438, 0x5bbe,
        0xa438, 0x1800, 0xa438, 0x0e71, 0xa438, 0x1800, 0xa438, 0x0e7c,
        0xa438, 0x1800, 0xa438, 0x0e7e, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xaf80, 0xa438, 0x9503, 0xa438, 0xcd62, 0xa438, 0x1800,
        0xa438, 0x0bd2, 0xa438, 0x800a, 0xa438, 0x8530, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8d10, 0xa438, 0x9503, 0xa438, 0xd700,
        0xa438, 0x6050, 0xa438, 0xaa20, 0xa438, 0x8306, 0xa438, 0x1800,
        0xa438, 0x0cb6, 0xa438, 0xd105, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0d8f, 0xa438, 0xd700, 0xa438, 0x5fbb, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8608, 0xa438, 0x9503, 0xa438, 0x1000,
        0xa438, 0x0d8f, 0xa438, 0xd704, 0xa438, 0x7fb6, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x87f0, 0xa438, 0x9503, 0xa438, 0xce88,
        0xa438, 0x1000, 0xa438, 0x117a, 0xa438, 0x0c03, 0xa438, 0x1502,
        0xa438, 0xa608, 0xa438, 0x9503, 0xa438, 0xd73e, 0xa438, 0x60a5,
        0xa438, 0xd705, 0xa438, 0x4071, 0xa438, 0x1800, 0xa438, 0x0d65,
        0xa438, 0x1800, 0xa438, 0x0d6f, 0xa436, 0xA10E, 0xa438, 0x0d58,
        0xa436, 0xA10C, 0xa438, 0x0cb5, 0xa436, 0xA10A, 0xa438, 0x0bd1,
        0xa436, 0xA108, 0xa438, 0x0e37, 0xa436, 0xA106, 0xa438, 0x1267,
        0xa436, 0xA104, 0xa438, 0x0b3b, 0xa436, 0xA102, 0xa438, 0x0c38,
        0xa436, 0xA100, 0xa438, 0x0c24, 0xa436, 0xA110, 0xa438, 0x00ff,
        0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x1ff8,
        0xa436, 0xA014, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa436, 0xA164, 0xa438, 0x0ceb, 0xa436, 0xA166,
        0xa438, 0x0e73, 0xa436, 0xA168, 0xa438, 0x0deb, 0xa436, 0xA16A,
        0xa438, 0x3fff, 0xa436, 0xA16C, 0xa438, 0x3fff, 0xa436, 0xA16E,
        0xa438, 0x3fff, 0xa436, 0xA170, 0xa438, 0x3fff, 0xa436, 0xA172,
        0xa438, 0x3fff, 0xa436, 0xA162, 0xa438, 0x0007, 0xa436, 0xb87c,
        0xa438, 0x85bf, 0xa436, 0xb87e, 0xa438, 0xaf85, 0xa438, 0xd7af,
        0xa438, 0x85fb, 0xa438, 0xaf86, 0xa438, 0x10af, 0xa438, 0x8638,
        0xa438, 0xaf86, 0xa438, 0x47af, 0xa438, 0x8647, 0xa438, 0xaf86,
        0xa438, 0x47af, 0xa438, 0x8647, 0xa438, 0xbf85, 0xa438, 0xf802,
        0xa438, 0x627f, 0xa438, 0xbf61, 0xa438, 0xc702, 0xa438, 0x627f,
        0xa438, 0xae0c, 0xa438, 0xbf85, 0xa438, 0xf802, 0xa438, 0x6276,
        0xa438, 0xbf61, 0xa438, 0xc702, 0xa438, 0x6276, 0xa438, 0xee85,
        0xa438, 0x4200, 0xa438, 0xaf1b, 0xa438, 0x2333, 0xa438, 0xa484,
        0xa438, 0xbf86, 0xa438, 0x0a02, 0xa438, 0x627f, 0xa438, 0xbf86,
        0xa438, 0x0d02, 0xa438, 0x627f, 0xa438, 0xaf1b, 0xa438, 0x8422,
        0xa438, 0xa484, 0xa438, 0x66ac, 0xa438, 0x0ef8, 0xa438, 0xfbef,
        0xa438, 0x79fb, 0xa438, 0xe080, 0xa438, 0x16ad, 0xa438, 0x230f,
        0xa438, 0xee85, 0xa438, 0x4200, 0xa438, 0x1f44, 0xa438, 0xbf86,
        0xa438, 0x30d7, 0xa438, 0x0008, 0xa438, 0x0264, 0xa438, 0xa3ff,
        0xa438, 0xef97, 0xa438, 0xfffc, 0xa438, 0x0485, 0xa438, 0xf861,
        0xa438, 0xc786, 0xa438, 0x0a86, 0xa438, 0x0de1, 0xa438, 0x8feb,
        0xa438, 0xe583, 0xa438, 0x20e1, 0xa438, 0x8fea, 0xa438, 0xe583,
        0xa438, 0x21af, 0xa438, 0x41a7, 0xa436, 0xb85e, 0xa438, 0x1b05,
        0xa436, 0xb860, 0xa438, 0x1b78, 0xa436, 0xb862, 0xa438, 0x1a08,
        0xa436, 0xb864, 0xa438, 0x419F, 0xa436, 0xb886, 0xa438, 0xffff,
        0xa436, 0xb888, 0xa438, 0xffff, 0xa436, 0xb88a, 0xa438, 0xffff,
        0xa436, 0xb88c, 0xa438, 0xffff, 0xa436, 0xb838, 0xa438, 0x000f,
        0xb820, 0x0010, 0xa436, 0x0000, 0xa438, 0x0000, 0xB82E, 0x0000,
        0xa436, 0x8023, 0xa438, 0x0000, 0xa436, 0x801E, 0xa438, 0x0013,
        0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16  phy_mcu_ram_code_8125d_2_2[] = {
        0xa436, 0xacca, 0xa438, 0x0104, 0xa436, 0xaccc, 0xa438, 0x8000,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xfd47, 0xa436, 0xacd0, 0xa438, 0x0fff,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xe56f, 0xa436, 0xacd0, 0xa438, 0x01c0,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xed97, 0xa436, 0xacd0, 0xa438, 0x01c8,
        0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xf5bf, 0xa436, 0xacd0, 0xa438, 0x01d0,
        0xa436, 0xacce, 0xa438, 0xfb07, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb0f, 0xa436, 0xacd0, 0xa438, 0x01d8,
        0xa436, 0xacce, 0xa438, 0xa087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0xa00f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0xa807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0xa88f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0xb027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0xb02f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0xb847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0xb84f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0xfb17, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb1f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xa017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0xa01f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0xa837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0xa83f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0xb097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0xb05f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0xb857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0xb89f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0xfb27, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb2f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x8087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x800f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x8807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x888f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x9027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x902f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x9847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x984f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0xa0a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0xa8af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0xa067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0xa86f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb37, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb3f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x8017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x801f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x8837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x883f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x9097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x905f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x9857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x989f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0xb0b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0xb8bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0xb077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0xb87f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb47, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb4f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x600f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x6807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x688f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x7027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x702f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x7847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x784f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0x80a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x88af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x8067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x886f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb57, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb5f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x6017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x601f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x6837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x683f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x7097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x705f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x7857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x789f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0x90b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x98bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x9077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x987f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb67, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb6f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x4087, 0xa436, 0xacd0, 0xa438, 0x0180,
        0xa436, 0xacce, 0xa438, 0x400f, 0xa436, 0xacd0, 0xa438, 0x0108,
        0xa436, 0xacce, 0xa438, 0x4807, 0xa436, 0xacd0, 0xa438, 0x0100,
        0xa436, 0xacce, 0xa438, 0x488f, 0xa436, 0xacd0, 0xa438, 0x0188,
        0xa436, 0xacce, 0xa438, 0x5027, 0xa436, 0xacd0, 0xa438, 0x0120,
        0xa436, 0xacce, 0xa438, 0x502f, 0xa436, 0xacd0, 0xa438, 0x0128,
        0xa436, 0xacce, 0xa438, 0x5847, 0xa436, 0xacd0, 0xa438, 0x0140,
        0xa436, 0xacce, 0xa438, 0x584f, 0xa436, 0xacd0, 0xa438, 0x0148,
        0xa436, 0xacce, 0xa438, 0x60a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x68af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x6067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x686f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb77, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb7f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x4017, 0xa436, 0xacd0, 0xa438, 0x0110,
        0xa436, 0xacce, 0xa438, 0x401f, 0xa436, 0xacd0, 0xa438, 0x0118,
        0xa436, 0xacce, 0xa438, 0x4837, 0xa436, 0xacd0, 0xa438, 0x0130,
        0xa436, 0xacce, 0xa438, 0x483f, 0xa436, 0xacd0, 0xa438, 0x0138,
        0xa436, 0xacce, 0xa438, 0x5097, 0xa436, 0xacd0, 0xa438, 0x0190,
        0xa436, 0xacce, 0xa438, 0x505f, 0xa436, 0xacd0, 0xa438, 0x0158,
        0xa436, 0xacce, 0xa438, 0x5857, 0xa436, 0xacd0, 0xa438, 0x0150,
        0xa436, 0xacce, 0xa438, 0x589f, 0xa436, 0xacd0, 0xa438, 0x0198,
        0xa436, 0xacce, 0xa438, 0x70b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x78bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x7077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x787f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfb87, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb8f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x40a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
        0xa436, 0xacce, 0xa438, 0x48af, 0xa436, 0xacd0, 0xa438, 0x01a8,
        0xa436, 0xacce, 0xa438, 0x4067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x486f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfb97, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfb9f, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x50b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
        0xa436, 0xacce, 0xa438, 0x58bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
        0xa436, 0xacce, 0xa438, 0x5077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x587f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfba7, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfbaf, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x2067, 0xa436, 0xacd0, 0xa438, 0x0161,
        0xa436, 0xacce, 0xa438, 0x286f, 0xa436, 0xacd0, 0xa438, 0x0169,
        0xa436, 0xacce, 0xa438, 0xfbb7, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0xfbbf, 0xa436, 0xacd0, 0xa438, 0x07ff,
        0xa436, 0xacce, 0xa438, 0x3077, 0xa436, 0xacd0, 0xa438, 0x0171,
        0xa436, 0xacce, 0xa438, 0x387f, 0xa436, 0xacd0, 0xa438, 0x0179,
        0xa436, 0xacce, 0xa438, 0xfff9, 0xa436, 0xacd0, 0xa438, 0x17ff,
        0xa436, 0xacce, 0xa438, 0xfff9, 0xa436, 0xacd0, 0xa438, 0x17ff,
        0xa436, 0xacca, 0xa438, 0x0004, 0xa436, 0xacc6, 0xa438, 0x0008,
        0xa436, 0xacc8, 0xa438, 0xc000, 0xa436, 0xacc8, 0xa438, 0x0000,
        0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125bp_1_1[] = {
        0xa436, 0x8024, 0xa438, 0x3600, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
        0xa438, 0x1800, 0xa438, 0x8014, 0xa438, 0x1800, 0xa438, 0x8018,
        0xa438, 0x1800, 0xa438, 0x801c, 0xa438, 0x1800, 0xa438, 0x8020,
        0xa438, 0x1800, 0xa438, 0x8024, 0xa438, 0x1800, 0xa438, 0x8028,
        0xa438, 0x1800, 0xa438, 0x8028, 0xa438, 0xdb20, 0xa438, 0xd501,
        0xa438, 0x1800, 0xa438, 0x034c, 0xa438, 0xdb10, 0xa438, 0xd501,
        0xa438, 0x1800, 0xa438, 0x032c, 0xa438, 0x8620, 0xa438, 0xa480,
        0xa438, 0x1800, 0xa438, 0x1cfe, 0xa438, 0xbf40, 0xa438, 0xd703,
        0xa438, 0x1800, 0xa438, 0x0ce9, 0xa438, 0x9c10, 0xa438, 0x9f40,
        0xa438, 0x1800, 0xa438, 0x137a, 0xa438, 0x9f20, 0xa438, 0x9f40,
        0xa438, 0x1800, 0xa438, 0x16c4, 0xa436, 0xA026, 0xa438, 0xffff,
        0xa436, 0xA024, 0xa438, 0xffff, 0xa436, 0xA022, 0xa438, 0x16c3,
        0xa436, 0xA020, 0xa438, 0x1379, 0xa436, 0xA006, 0xa438, 0x0ce8,
        0xa436, 0xA004, 0xa438, 0x1cfd, 0xa436, 0xA002, 0xa438, 0x032b,
        0xa436, 0xA000, 0xa438, 0x034b, 0xa436, 0xA008, 0xa438, 0x3f00,
        0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x0000,
        0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800,
        0xa438, 0x8018, 0xa438, 0x1800, 0xa438, 0x8021, 0xa438, 0x1800,
        0xa438, 0x802b, 0xa438, 0x1800, 0xa438, 0x8055, 0xa438, 0x1800,
        0xa438, 0x805a, 0xa438, 0x1800, 0xa438, 0x805e, 0xa438, 0x1800,
        0xa438, 0x8062, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0xcb11,
        0xa438, 0xd1b9, 0xa438, 0xd05b, 0xa438, 0x0000, 0xa438, 0x1800,
        0xa438, 0x0284, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0xd700,
        0xa438, 0x5fb4, 0xa438, 0x5f95, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x1800, 0xa438, 0x02b7, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0xcb21, 0xa438, 0x1000, 0xa438, 0x0b34, 0xa438, 0xd71f,
        0xa438, 0x5f5e, 0xa438, 0x0000, 0xa438, 0x1800, 0xa438, 0x0322,
        0xa438, 0xd700, 0xa438, 0xd113, 0xa438, 0xd040, 0xa438, 0x1000,
        0xa438, 0x0a57, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xd700,
        0xa438, 0x6065, 0xa438, 0xd122, 0xa438, 0xf002, 0xa438, 0xd122,
        0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x0b53, 0xa438, 0xa008,
        0xa438, 0xd704, 0xa438, 0x4052, 0xa438, 0xa002, 0xa438, 0xd704,
        0xa438, 0x4054, 0xa438, 0xa740, 0xa438, 0x1000, 0xa438, 0x0a57,
        0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0xcb9b, 0xa438, 0xd110,
        0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x0c01, 0xa438, 0x1000,
        0xa438, 0x0a57, 0xa438, 0xd700, 0xa438, 0x5fb4, 0xa438, 0x801a,
        0xa438, 0x1000, 0xa438, 0x0a57, 0xa438, 0xd704, 0xa438, 0x7fb9,
        0xa438, 0x1800, 0xa438, 0x088d, 0xa438, 0xcb62, 0xa438, 0xd700,
        0xa438, 0x8880, 0xa438, 0x1800, 0xa438, 0x06cb, 0xa438, 0xbe02,
        0xa438, 0x0000, 0xa438, 0x1800, 0xa438, 0x002c, 0xa438, 0xbe04,
        0xa438, 0x0000, 0xa438, 0x1800, 0xa438, 0x002c, 0xa438, 0xbe08,
        0xa438, 0x0000, 0xa438, 0x1800, 0xa438, 0x002c, 0xa436, 0xA10E,
        0xa438, 0x802a, 0xa436, 0xA10C, 0xa438, 0x8026, 0xa436, 0xA10A,
        0xa438, 0x8022, 0xa436, 0xA108, 0xa438, 0x06ca, 0xa436, 0xA106,
        0xa438, 0x086f, 0xa436, 0xA104, 0xa438, 0x0321, 0xa436, 0xA102,
        0xa438, 0x02b5, 0xa436, 0xA100, 0xa438, 0x0283, 0xa436, 0xA110,
        0xa438, 0x001f, 0xb820, 0x0010, 0xb82e, 0x0000, 0xa436, 0x8024,
        0xa438, 0x0000, 0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125bp_1_2[] = {
        0xb892, 0x0000, 0xb88e, 0xC201, 0xb890, 0x2C01, 0xb890, 0xCD02,
        0xb890, 0x0602, 0xb890, 0x5502, 0xb890, 0xB903, 0xb890, 0x3303,
        0xb890, 0xC204, 0xb890, 0x6605, 0xb890, 0x1F05, 0xb890, 0xEE06,
        0xb890, 0xD207, 0xb890, 0xCC08, 0xb890, 0xDA09, 0xb890, 0xFF0B,
        0xb890, 0x380C, 0xb890, 0x87F3, 0xb88e, 0xC27F, 0xb890, 0x2B66,
        0xb890, 0x6666, 0xb890, 0x6666, 0xb890, 0x6666, 0xb890, 0x6666,
        0xb890, 0x6666, 0xb890, 0x6666, 0xb890, 0x6666, 0xb890, 0x66C2,
        0xb88e, 0xC26F, 0xb890, 0x751D, 0xb890, 0x1D1F, 0xb890, 0x2022,
        0xb890, 0x2325, 0xb890, 0x2627, 0xb890, 0x2829, 0xb890, 0x2929,
        0xb890, 0x2A2A, 0xb890, 0x2B66, 0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125cp_1_1[] = {
        0xa436, 0x8023, 0xa438, 0x2300, 0xa436, 0xB82E, 0xa438, 0x0001,
        0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
        0xa438, 0x07f8, 0xa436, 0xA014, 0xa438, 0xcc01, 0xa438, 0x2166,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000, 0xa438, 0x0000,
        0xa438, 0x0000, 0xa438, 0x0000, 0xa436, 0xA152, 0xa438, 0x021c,
        0xa436, 0xA154, 0xa438, 0x2170, 0xa436, 0xA156, 0xa438, 0x3fff,
        0xa436, 0xA158, 0xa438, 0x3fff, 0xa436, 0xA15A, 0xa438, 0x3fff,
        0xa436, 0xA15C, 0xa438, 0x3fff, 0xa436, 0xA15E, 0xa438, 0x3fff,
        0xa436, 0xA160, 0xa438, 0x3fff, 0xa436, 0xA150, 0xa438, 0x0003,
        0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x0000,
        0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800,
        0xa438, 0x801b, 0xa438, 0x1800, 0xa438, 0x802b, 0xa438, 0x1800,
        0xa438, 0x8031, 0xa438, 0x1800, 0xa438, 0x8037, 0xa438, 0x1800,
        0xa438, 0x8037, 0xa438, 0x1800, 0xa438, 0x8037, 0xa438, 0x1800,
        0xa438, 0x8037, 0xa438, 0x800a, 0xa438, 0x8530, 0xa438, 0x0c03,
        0xa438, 0x1502, 0xa438, 0x8d10, 0xa438, 0x9503, 0xa438, 0xd700,
        0xa438, 0x6050, 0xa438, 0xaa20, 0xa438, 0x1800, 0xa438, 0x0d53,
        0xa438, 0xd707, 0xa438, 0x40f6, 0xa438, 0x8901, 0xa438, 0xd704,
        0xa438, 0x6091, 0xa438, 0x8306, 0xa438, 0x8b02, 0xa438, 0x8290,
        0xa438, 0x1000, 0xa438, 0x0e4d, 0xa438, 0x1000, 0xa438, 0x1277,
        0xa438, 0xd704, 0xa438, 0x7e77, 0xa438, 0x1800, 0xa438, 0x0dc5,
        0xa438, 0xd700, 0xa438, 0x4063, 0xa438, 0x1800, 0xa438, 0x0d15,
        0xa438, 0x1800, 0xa438, 0x0d18, 0xa438, 0xd700, 0xa438, 0x6063,
        0xa438, 0x1800, 0xa438, 0x0ca6, 0xa438, 0x1800, 0xa438, 0x0ca7,
        0xa436, 0xA10E, 0xa438, 0xffff, 0xa436, 0xA10C, 0xa438, 0xffff,
        0xa436, 0xA10A, 0xa438, 0xffff, 0xa436, 0xA108, 0xa438, 0xffff,
        0xa436, 0xA106, 0xa438, 0x0ca2, 0xa436, 0xA104, 0xa438, 0x0d13,
        0xa436, 0xA102, 0xa438, 0x0dbf, 0xa436, 0xA100, 0xa438, 0x0d52,
        0xa436, 0xA110, 0xa438, 0x000f, 0xa436, 0xb87c, 0xa438, 0x85bd,
        0xa436, 0xb87e, 0xa438, 0xaf85, 0xa438, 0xd5af, 0xa438, 0x85fb,
        0xa438, 0xaf85, 0xa438, 0xfbaf, 0xa438, 0x85fb, 0xa438, 0xaf85,
        0xa438, 0xfbaf, 0xa438, 0x85fb, 0xa438, 0xaf85, 0xa438, 0xfbaf,
        0xa438, 0x85fb, 0xa438, 0xac28, 0xa438, 0x0bd4, 0xa438, 0x0294,
        0xa438, 0xbf85, 0xa438, 0xf802, 0xa438, 0x61c2, 0xa438, 0xae09,
        0xa438, 0xd414, 0xa438, 0x50bf, 0xa438, 0x85f8, 0xa438, 0x0261,
        0xa438, 0xc2bf, 0xa438, 0x60de, 0xa438, 0x0261, 0xa438, 0xe1bf,
        0xa438, 0x80cf, 0xa438, 0xaf24, 0xa438, 0xe8f0, 0xa438, 0xac52,
        0xa436, 0xb85e, 0xa438, 0x24e5, 0xa436, 0xb860, 0xa438, 0xffff,
        0xa436, 0xb862, 0xa438, 0xffff, 0xa436, 0xb864, 0xa438, 0xffff,
        0xa436, 0xb886, 0xa438, 0xffff, 0xa436, 0xb888, 0xa438, 0xffff,
        0xa436, 0xb88a, 0xa438, 0xffff, 0xa436, 0xb88c, 0xa438, 0xffff,
        0xa436, 0xb838, 0xa438, 0x0001, 0xb820, 0x0010, 0xB82E, 0x0000,
        0xa436, 0x8023, 0xa438, 0x0000, 0xB820, 0x0000, 0xFFFF, 0xFFFF
};

static void
rtl8125_real_set_phy_mcu_8125b_1(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125b_1,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125b_1));
}

static void
rtl8125_set_phy_mcu_8125b_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125b_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_real_set_phy_mcu_8125b_2(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125b_2,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125b_2));
}

static void
rtl8125_set_phy_mcu_8125b_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125b_2(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_real_set_phy_mcu_8125d_1_1(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_1_1,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_1_1));
}

static void
rtl8125_real_set_phy_mcu_8125d_1_2(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_1_2,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_1_2));
}

static void
rtl8125_real_set_phy_mcu_8125d_1_3(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_1_3,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_1_3));
}

static void
rtl8125_set_phy_mcu_8125d_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125d_1_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125d_1_2(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125d_1_3(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_set_phy_mcu_8125d_1_efuse(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_1_efuse,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_1_efuse));
}

static void
rtl8125_real_set_phy_mcu_8125d_2_1(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_2_1,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_2_1));
}

static void
rtl8125_real_set_phy_mcu_8125d_2_2(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125d_2_2,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125d_2_2));
}

static void
rtl8125_set_phy_mcu_8125d_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125d_2_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125d_2_2(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_real_set_phy_mcu_8125bp_1_1(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125bp_1_1,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125bp_1_1));
}

static void
rtl8125_real_set_phy_mcu_8125bp_1_2(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125bp_1_2,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125bp_1_2));
}

static void
rtl8125_set_phy_mcu_8125bp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125bp_1_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125bp_1_2(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_real_set_phy_mcu_8125cp_1_1(struct net_device *dev)
{
        rtl8125_set_phy_mcu_ram_code(dev,
                                     phy_mcu_ram_code_8125cp_1_1,
                                     ARRAY_SIZE(phy_mcu_ram_code_8125cp_1_1));
}

static void
rtl8125_set_phy_mcu_8125cp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_real_set_phy_mcu_8125cp_1_1(dev);

        rtl8125_clear_phy_mcu_patch_request(tp);
}

static void
rtl8125_init_hw_phy_mcu(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 require_disable_phy_disable_mode = FALSE;

        if (tp->NotWrRamCodeToMicroP == TRUE)
                return;

        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                return;

        if (HW_SUPPORT_CHECK_PHY_DISABLE_MODE(tp) && rtl8125_is_in_phy_disable_mode(dev))
                require_disable_phy_disable_mode = TRUE;

        if (require_disable_phy_disable_mode)
                rtl8125_disable_phy_disable_mode(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_set_phy_mcu_8125a_1(dev);
                break;
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_set_phy_mcu_8125a_2(dev);
                break;
        case CFG_METHOD_4:
                rtl8125_set_phy_mcu_8125b_1(dev);
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                rtl8125_set_phy_mcu_8125b_2(dev);
                break;
        case CFG_METHOD_8:
                rtl8125_set_phy_mcu_8125bp_1(dev);
                break;
        case CFG_METHOD_9:
                /* nothing to do */
                break;
        case CFG_METHOD_10:
                rtl8125_set_phy_mcu_8125d_1(dev);
                break;
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                rtl8125_set_phy_mcu_8125d_2(dev);
                break;
        case CFG_METHOD_12:
                rtl8125_set_phy_mcu_8125cp_1(dev);
                break;
        }

        if (require_disable_phy_disable_mode)
                rtl8125_enable_phy_disable_mode(dev);

        rtl8125_write_hw_phy_mcu_code_ver(dev);

        rtl8125_mdio_write(tp,0x1F, 0x0000);

        tp->HwHasWrRamCodeToMicroP = TRUE;
}
#else
static void
rtl8125_set_phy_mcu_8125d_1_efuse(struct net_device *dev)
{
        (void)dev;
}
#endif

static void
rtl8125_enable_phy_aldps(struct rtl8125_private *tp)
{
        //enable aldps
        //GPHY OCP 0xA430 bit[2] = 0x1 (en_aldps)
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA430, BIT_2);
}

static void
rtl8125_tgphy_irq_mask_and_ack(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA4D2, 0x0000);
                (void)rtl8125_mdio_direct_read_phy_ocp(tp, 0xA4D4);
                break;
        default:
                break;
        }
}

static void
rtl8125_hw_phy_config_8125a_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD40,
                                              0x03FF,
                                              0x84);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xAD4E, BIT_4);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD16,
                                              0x03FF,
                                              0x0006);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD32,
                                              0x003F,
                                              0x0006);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC08, BIT_12);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC08, BIT_8);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC8A,
                                              BIT_15|BIT_14|BIT_13|BIT_12,
                                              BIT_14|BIT_13|BIT_12);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xAD18, BIT_10);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xAD1A, 0x3FF);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xAD1C, 0x3FF);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EA);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xC400);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EB);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0x0700,
                                              0x0300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80F8);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x1C00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80F1);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x3000);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80FE);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xA500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8102);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x5000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8105);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x3300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8100);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x7000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8104);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xF000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8106);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x6500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DC);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xED00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DF);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80E1);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_8);

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBF06,
                                              0x003F,
                                              0x38);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x819F);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xD0B6);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBC34, 0x5555);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBF0A,
                                              BIT_11|BIT_10|BIT_9,
                                              BIT_11|BIT_9);

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5C0, BIT_10);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);

        //enable aldps
        //GPHY OCP 0xA430 bit[2] = 0x1 (en_aldps)
        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125a_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xAD4E, BIT_4);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD16,
                                              0x03FF,
                                              0x03FF);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD32,
                                              0x003F,
                                              0x0006);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC08, BIT_12);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC08, BIT_8);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xACC0,
                                              BIT_1|BIT_0,
                                              BIT_1);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD40,
                                              BIT_7|BIT_6|BIT_5,
                                              BIT_6);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD40,
                                              BIT_2|BIT_1|BIT_0,
                                              BIT_2);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC14, BIT_7);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAC80, BIT_9|BIT_8);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC5E,
                                              BIT_2|BIT_1|BIT_0,
                                              BIT_1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAD4C, 0x00A8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC5C, 0x01FF);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC8A,
                                              BIT_7|BIT_6|BIT_5|BIT_4,
                                              BIT_5|BIT_4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8157);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8159);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0700);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80A2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0153);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x809C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0153);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81B3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0043);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00A7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00D6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00EC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00F6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FB);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FD);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FF);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00BB);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0058);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0029);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0013);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0009);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0004);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8257);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x020F);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EA);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7843);


        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB896, BIT_0);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB892, 0xFF00);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC091);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E12);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC092);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1214);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC094);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1516);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC096);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x171B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC098);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1B1C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1F1F);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x2021);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x2224);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC018);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0AF2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0D4A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0F26);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x118D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC020);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x14F3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC022);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x175A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC024);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x19C0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC026);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1C26);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC089);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x6050);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x5F6E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E6E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E6E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC090);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E12);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xB896, BIT_0);

        rtl8125_clear_phy_mcu_patch_request(tp);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xD068, BIT_13);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81A2);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_8);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB54C,
                                              0xFF00,
                                              0xDB00);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA454, BIT_0);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA5D4, BIT_5);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAD4E, BIT_4);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA86A, BIT_0);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        if (tp->RequirePhyMdiSwapPatch) {
                u16 adccal_offset_p0;
                u16 adccal_offset_p1;
                u16 adccal_offset_p2;
                u16 adccal_offset_p3;
                u16 rg_lpf_cap_xg_p0;
                u16 rg_lpf_cap_xg_p1;
                u16 rg_lpf_cap_xg_p2;
                u16 rg_lpf_cap_xg_p3;
                u16 rg_lpf_cap_p0;
                u16 rg_lpf_cap_p1;
                u16 rg_lpf_cap_p2;
                u16 rg_lpf_cap_p3;

                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0007,
                                                      0x0001);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0000);
                adccal_offset_p0 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p0 &= 0x07FF;
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0008);
                adccal_offset_p1 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p1 &= 0x07FF;
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0010);
                adccal_offset_p2 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p2 &= 0x07FF;
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0018);
                adccal_offset_p3 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p3 &= 0x07FF;


                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0000);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD06A,
                                                      0x07FF,
                                                      adccal_offset_p3);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0008);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD06A,
                                                      0x07FF,
                                                      adccal_offset_p2);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0010);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD06A,
                                                      0x07FF,
                                                      adccal_offset_p1);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD068,
                                                      0x0018,
                                                      0x0018);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xD06A,
                                                      0x07FF,
                                                      adccal_offset_p0);


                rg_lpf_cap_xg_p0 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBD5A);
                rg_lpf_cap_xg_p0 &= 0x001F;
                rg_lpf_cap_xg_p1 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBD5A);
                rg_lpf_cap_xg_p1 &= 0x1F00;
                rg_lpf_cap_xg_p2 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBD5C);
                rg_lpf_cap_xg_p2 &= 0x001F;
                rg_lpf_cap_xg_p3 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBD5C);
                rg_lpf_cap_xg_p3 &= 0x1F00;
                rg_lpf_cap_p0 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBC18);
                rg_lpf_cap_p0 &= 0x001F;
                rg_lpf_cap_p1 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBC18);
                rg_lpf_cap_p1 &= 0x1F00;
                rg_lpf_cap_p2 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBC1A);
                rg_lpf_cap_p2 &= 0x001F;
                rg_lpf_cap_p3 = rtl8125_mdio_direct_read_phy_ocp(tp, 0xBC1A);
                rg_lpf_cap_p3 &= 0x1F00;


                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBD5A,
                                                      0x001F,
                                                      rg_lpf_cap_xg_p3 >> 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBD5A,
                                                      0x1F00,
                                                      rg_lpf_cap_xg_p2 << 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBD5C,
                                                      0x001F,
                                                      rg_lpf_cap_xg_p1 >> 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBD5C,
                                                      0x1F00,
                                                      rg_lpf_cap_xg_p0 << 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBC18,
                                                      0x001F,
                                                      rg_lpf_cap_p3 >> 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBC18,
                                                      0x1F00,
                                                      rg_lpf_cap_p2 << 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBC1A,
                                                      0x001F,
                                                      rg_lpf_cap_p1 >> 8);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xBC1A,
                                                      0x1F00,
                                                      rg_lpf_cap_p0 << 8);
        }


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA424, BIT_3);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125b_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC08, (BIT_3 | BIT_2));


        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FFF);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x0400);
        }
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8560);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8562);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8564);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8566);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8568);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x856A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FFE);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0907);
        }
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xACDA,
                                              0xFF00,
                                              0xFF00);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xACDE,
                                              0xF000,
                                              0xF000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80D6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x6077);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB506, 0x01E7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC8C, 0x0FFC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC46, 0xB7B4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC50, 0x0FBC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC3C, 0x9240);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC4E, 0x0DB4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xACC6, 0x0707);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xACC8, 0xA0D3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAD08, 0x0007);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8013);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0700);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FB9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBA);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBC);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x1900);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBE);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xE100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0800);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xE500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0F00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0400);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCa);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCc);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFD00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCe);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFF00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFB00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD2);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF400);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFF00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF600);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x813D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x390E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x814F);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x790E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80B0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0F31);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBF4C, BIT_1);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBCCA, (BIT_9 | BIT_8));
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8141);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x320E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8153);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x720E);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA432, BIT_6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8529);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x050E);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x816C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xC4A0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8170);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xC4A0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8174);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x04A0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8178);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x04A0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x817C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0719);
        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF4);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0400);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF1);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0404);
        }
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBF4A, 0x001B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8033);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8037);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x803B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFC32);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x803F);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8043);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8047);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8145);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x370E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8157);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x770E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8169);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0D0A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x817B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x1D0A);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8217);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x5000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x821A);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x5000);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DA);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0403);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DC);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0384);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2007);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BA);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x6C00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xF009);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BD);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x9F00);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80C7);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xf083);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DD);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x03f0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DF);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x1000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CB);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x2007);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CE);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x6C00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80C9);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8009);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80D1);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x8000);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x200A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xF0AD);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x809F);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x6073);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x000B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A9);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xC000);

        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB896, BIT_0);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xB892, 0xFF00);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC23E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC240);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0103);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC242);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0507);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC244);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x090B);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC246);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x0C0E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC248);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1012);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC24A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB890, 0x1416);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xB896, BIT_0);

        rtl8125_clear_phy_mcu_patch_request(tp);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA86A, BIT_0);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA6F0, BIT_0);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA0, 0xD70D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA2, 0x4100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA4, 0xE868);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA6, 0xDC59);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB54C, 0x3C18);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBFA4, BIT_5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x817D);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_12);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125b_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC46,
                                              0x00F0,
                                              0x0090);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD30,
                                              0x0003,
                                              0x0001);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x760E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8107);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87E, 0x360E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8551);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              BIT_15 | BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10 | BIT_9 | BIT_8,
                                              BIT_11);

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xbf00,
                                              0xE000,
                                              0xA000);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xbf46,
                                              0x0F00,
                                              0x0300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8044);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x804A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8050);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8056);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x805C);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8062);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8068);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x806E);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x8074);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa436, 0x807A);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA4CA, BIT_6);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBF84,
                                              BIT_15 | BIT_14 | BIT_13,
                                              BIT_15 | BIT_13);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8170);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              BIT_13 | BIT_10 | BIT_9 | BIT_8,
                                              BIT_15 | BIT_14 | BIT_12 | BIT_11);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8015);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xB87E, BIT_8);
        rtl8125_mdio_direct_read_phy_ocp(tp, 0xB906);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA424, BIT_3);

        /*
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA0, 0xD70D);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA2, 0x4100);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA4, 0xE868);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA6, 0xDC59);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB54C, 0x3C18);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBFA4, BIT_5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x817D);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_12);
        */


#ifdef ENABLE_LIB_SUPPORT
        /* disable phy speed down */
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA442, BIT_3 | BIT_2);
#endif /* ENABLE_LIB_SUPPORT */


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125bp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA80C,
                                              BIT_14,
                                              BIT_15 | BIT_11 | BIT_10);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8010);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_11);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8088);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x9000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x808F);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x9000);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8174);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              BIT_13,
                                              BIT_12 | BIT_11);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125bp_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8010);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_11);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8088);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x9000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x808F);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x9000);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8174);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              BIT_13,
                                              BIT_12 | BIT_11);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125cp_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_tgphy_irq_mask_and_ack(tp);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xad0e,
                                              0x007F,
                                              0x000B);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xad78, BIT_4);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81B8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00B4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81BA);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00E4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81C5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0104);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81D0);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x054D);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125d_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xBF96, BIT_15);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBF94,
                                              0x0007,
                                              0x0005);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBF8E,
                                              0x3C00,
                                              0x2800);

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x4000);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x4000);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC80,
                                              0x001F,
                                              0x0004);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_15 | BIT_14 | BIT_13);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_12 | BIT_11 | BIT_10);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC80,
                                              0x001F,
                                              0x0005);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC82,
                                              0x00E0,
                                              0x0040);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_4 | BIT_3 | BIT_2);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x8000);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);

        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBD70, BIT_8);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA466, BIT_1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x836a);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, 0xFF00);

        rtl8125_clear_phy_mcu_patch_request(tp);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x832C);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0500);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB106,
                                              0x0700,
                                              0x0100);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB206,
                                              0x0700,
                                              0x0200);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB306,
                                              0x0700,
                                              0x0300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80CB);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0300);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBCF4, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBCF6, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBC12, 0x0000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x844d);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0200);
        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8feb);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xB87E,
                                                      0xFF00,
                                                      0x0100);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8fe9);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xB87E,
                                                      0xFF00,
                                                      0x0600);
        }

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC7E,
                                              0x01FC,
                                              0x00B4);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8105);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x7A00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8117);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x3A00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8103);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x7400);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8115);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x3400);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xAD40, BIT_5 | BIT_4);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD66,
                                              0x000F,
                                              0x0007);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD68,
                                              0xF000,
                                              0x8000);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD68,
                                              0x0F00,
                                              0x0500);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD68,
                                              0x000F,
                                              0x0002);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAD6A,
                                              0xF000,
                                              0x7000);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xAC50, 0x01E8);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x81FA);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x5400);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA864,
                                              0x00F0,
                                              0x00C0);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA42C,
                                              0x00FF,
                                              0x0002);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80E1);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x0F00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DE);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xF000,
                                              0x0700);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA846, BIT_7);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BA);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8A04);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BD);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xCA00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B7);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xB300);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CE);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8A04);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80D1);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xCA00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CB);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0xBB00);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A6);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x4909);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x05B8);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8200);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x5800);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF1);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7078);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF3);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x5D78);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF5);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x7862);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF7);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x1400);


        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x814C);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x8455);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x814E);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x84A6);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8163);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x0600);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x816A);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x0500);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8171);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x1f00);
        }


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC3A,
                                              0x000F,
                                              0x0006);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8064);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8067);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x806A);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x806D);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8070);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8073);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8076);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8079);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x807C);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x807F);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA438, BIT_10 | BIT_9 | BIT_8);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBFA0,
                                              0xFF70,
                                              0x5500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xBFA2, 0x9D00);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8165);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0x0700,
                                              0x0200);


        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8019);
                rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_8);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FE3);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0005);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x00ED);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0502);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0x0B00);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, 0xD401);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x2900);
        }


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x8018);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xA438,
                                              0xFF00,
                                              0x1700);


        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x815B);
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA438,
                                                      0xFF00,
                                                      0x1700);
        }


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA4E0, BIT_15);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5D4, BIT_5);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA654, BIT_11);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA430, BIT_12 | BIT_0);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_7);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config_8125d_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_11);


        rtl8125_set_phy_mcu_patch_request(tp);

        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x4000);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x4000);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC80,
                                              0x001F,
                                              0x0004);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_15 | BIT_14 | BIT_13);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_12 | BIT_11 | BIT_10);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC80,
                                              0x001F,
                                              0x0005);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBC82,
                                              0x00E0,
                                              0x0040);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC82, BIT_4 | BIT_3 | BIT_2);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xBCD8,
                                              0xC000,
                                              0x8000);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBCD8, BIT_15 | BIT_14);

        rtl8125_clear_phy_mcu_patch_request(tp);


        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xAC7E,
                                              0x01FC,
                                              0x00B4);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8105);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x7A00);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8117);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x3A00);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8103);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x7400);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8115);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x3400);

        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FEB);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0500);
        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FEA);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0x0700);


        rtl8125_mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80D6);
        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                              0xB87E,
                                              0xFF00,
                                              0xEF00);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5D4, BIT_5);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA654, BIT_11);


        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA448, BIT_10);
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA586, BIT_10);


        rtl8125_set_eth_phy_ocp_bit(tp, 0xA430, BIT_12 | BIT_0);
        rtl8125_set_eth_phy_ocp_bit(tp, 0xA442, BIT_7);


        if (aspm && HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                rtl8125_enable_phy_aldps(tp);
}

static void
rtl8125_hw_phy_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (tp->resume_not_chg_speed)
                return;

        tp->phy_reset_enable(dev);

        r8125_spin_lock(&tp->phy_lock, flags);

#ifndef ENABLE_USE_FIRMWARE_FILE
        if (!tp->rtl_fw) {
                rtl8125_set_hw_phy_before_init_phy_mcu(dev);

                rtl8125_init_hw_phy_mcu(dev);
        }
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_hw_phy_config_8125a_1(dev);
                break;
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                rtl8125_hw_phy_config_8125a_2(dev);
                break;
        case CFG_METHOD_4:
                rtl8125_hw_phy_config_8125b_1(dev);
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                rtl8125_hw_phy_config_8125b_2(dev);
                break;
        case CFG_METHOD_8:
                rtl8125_hw_phy_config_8125bp_1(dev);
                break;
        case CFG_METHOD_9:
                rtl8125_hw_phy_config_8125bp_2(dev);
                break;
        case CFG_METHOD_10:
                rtl8125_hw_phy_config_8125d_1(dev);
                break;
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                rtl8125_hw_phy_config_8125d_2(dev);
                break;
        case CFG_METHOD_12:
                rtl8125_hw_phy_config_8125cp_1(dev);
                break;
        }

        //legacy force mode(Chap 22)
        rtl8125_clear_eth_phy_ocp_bit(tp, 0xA5B4, BIT_15);

#ifdef ENABLE_FIBER_SUPPORT
        rtl8125_hw_fiber_phy_config(tp);
#endif /* ENABLE_FIBER_SUPPORT */

        /*ocp phy power saving*/
        /*
        if (aspm) {
        if (tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6)
                rtl8125_enable_ocp_phy_power_saving(dev);
        }
        */

        rtl8125_mdio_write(tp, 0x1F, 0x0000);

        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                if (tp->eee.eee_enabled)
                        rtl8125_enable_eee(tp);
                else
                        rtl8125_disable_eee(tp);
        }

        r8125_spin_unlock(&tp->phy_lock, flags);
}

static void
rtl8125_up(struct net_device *dev)
{
        rtl8125_hw_init(dev);
        rtl8125_hw_reset(dev);
        rtl8125_powerup_pll(dev);
        rtl8125_hw_ephy_config(dev);
        rtl8125_hw_phy_config(dev);
        rtl8125_hw_config(dev);
}

/*
static inline void rtl8125_delete_esd_timer(struct net_device *dev, struct timer_list *timer)
{
        del_timer_sync(timer);
}

static inline void rtl8125_request_esd_timer(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->esd_timer;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        setup_timer(timer, rtl8125_esd_timer, (unsigned long)dev);
#else
        timer_setup(timer, rtl8125_esd_timer, 0);
#endif
        mod_timer(timer, jiffies + RTL8125_ESD_TIMEOUT);
}
*/

/*
static inline void rtl8125_delete_link_timer(struct net_device *dev, struct timer_list *timer)
{
        del_timer_sync(timer);
}

static inline void rtl8125_request_link_timer(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->link_timer;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        setup_timer(timer, rtl8125_link_timer, (unsigned long)dev);
#else
        timer_setup(timer, rtl8125_link_timer, 0);
#endif
        mod_timer(timer, jiffies + RTL8125_LINK_TIMEOUT);
}
*/

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void
rtl8125_netpoll(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;
        for (i = 0; i < tp->irq_nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                struct r8125_napi *r8125napi = &tp->r8125napi[i];

                disable_irq(irq->vector);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
                irq->handler(irq->vector, r8125napi);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
                irq->handler(irq->vector, r8125napi, NULL);
#else
                irq->handler(irq->vector, r8125napi);
#endif

                enable_irq(irq->vector);
        }
}
#endif //CONFIG_NET_POLL_CONTROLLER

static void
rtl8125_setup_interrupt_mask(struct rtl8125_private *tp)
{
        int i;

        if (tp->HwCurrIsrVer == 7) {
                tp->intr_mask = ISRIMR_V7_LINKCHG | ISRIMR_V7_TOK_Q0;
                if (tp->num_tx_rings > 1)
                        tp->intr_mask |= ISRIMR_V7_TOK_Q1;
                for (i = 0; i < tp->num_rx_rings; i++)
                        tp->intr_mask |= ISRIMR_V7_ROK_Q0 << i;
        } else if (tp->HwCurrIsrVer == 5) {
                tp->intr_mask = ISRIMR_V5_LINKCHG | ISRIMR_V5_TOK_Q0;
                if (tp->num_tx_rings > 1)
                        tp->intr_mask |= ISRIMR_V5_TOK_Q1;
                for (i = 0; i < tp->num_rx_rings; i++)
                        tp->intr_mask |= ISRIMR_V5_ROK_Q0 << i;
        } else if (tp->HwCurrIsrVer == 4) {
                tp->intr_mask = ISRIMR_V4_LINKCHG;
                for (i = 0; i < max(tp->num_tx_rings, tp->num_rx_rings); i++)
                        tp->intr_mask |= ISRIMR_V4_ROK_Q0 << i;

                if (tp->DASH)
                        tp->intr_l2_mask |= ISRIMR_V4_L2_IPC2;

                if (tp->intr_l2_mask > 0)
                        tp->intr_mask |= ISRIMR_V4_LAYER2_INTR_STS;
        } else if (tp->HwCurrIsrVer == 3) {
                tp->intr_mask = ISRIMR_V2_LINKCHG;
                for (i = 0; i < max(tp->num_tx_rings, tp->num_rx_rings); i++)
                        tp->intr_mask |= ISRIMR_V2_ROK_Q0 << i;
        } else if (tp->HwCurrIsrVer == 2) {
                tp->intr_mask = ISRIMR_V2_LINKCHG | ISRIMR_TOK_Q0;
                if (tp->num_tx_rings > 1)
                        tp->intr_mask |= ISRIMR_TOK_Q1;

                for (i = 0; i < tp->num_rx_rings; i++)
                        tp->intr_mask |= ISRIMR_V2_ROK_Q0 << i;
        } else {
                tp->intr_mask = LinkChg | RxDescUnavail | TxOK | RxOK | SWInt;
                tp->timer_intr_mask = LinkChg | PCSTimeout;

#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH) {
                        if (HW_DASH_SUPPORT_IPC2(tp)) {
                                tp->timer_intr_mask |= ISRIMR_DASH_INTR_EN;
                                tp->intr_mask |= ISRIMR_DASH_INTR_EN;
                        }
                }
#endif
        }
}

static void
rtl8125_setup_mqs_reg(struct rtl8125_private *tp)
{
        u16 hw_clo_ptr0_reg, sw_tail_ptr0_reg;
        u16 reg_len;
        int i;

        //tx
        tp->tx_ring[0].tdsar_reg = TxDescStartAddrLow;
        for (i = 1; i < tp->HwSuppNumTxQueues; i++) {
                tp->tx_ring[i].tdsar_reg = (u16)(TNPDS_Q1_LOW_8125 + (i - 1) * 8);
        }

        switch (tp->HwSuppTxNoCloseVer) {
        case 4:
        case 5:
                hw_clo_ptr0_reg = HW_CLO_PTR0_8126;
                sw_tail_ptr0_reg = SW_TAIL_PTR0_8126;
                reg_len = 4;
                break;
        case 6:
                hw_clo_ptr0_reg = HW_CLO_PTR0_8125BP;
                sw_tail_ptr0_reg = SW_TAIL_PTR0_8125BP;
                reg_len = 8;
                break;
        default:
                hw_clo_ptr0_reg = HW_CLO_PTR0_8125;
                sw_tail_ptr0_reg = SW_TAIL_PTR0_8125;
                reg_len = 4;
                break;
        }

        for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                tp->tx_ring[i].hw_clo_ptr_reg = (u16)(hw_clo_ptr0_reg + i * reg_len);
                tp->tx_ring[i].sw_tail_ptr_reg = (u16)(sw_tail_ptr0_reg + i * reg_len);
        }

        //rx
        tp->rx_ring[0].rdsar_reg = RxDescAddrLow;
        for (i = 1; i < tp->HwSuppNumRxQueues; i++)
                tp->rx_ring[i].rdsar_reg = (u16)(RDSAR_Q1_LOW_8125 + (i - 1) * 8);

        tp->isr_reg[0] = ISR0_8125;
        for (i = 1; i < tp->hw_supp_irq_nvecs; i++)
                tp->isr_reg[i] = (u16)(ISR1_8125 + (i - 1) * 4);

        tp->imr_reg[0] = IMR0_8125;
        for (i = 1; i < tp->hw_supp_irq_nvecs; i++)
                tp->imr_reg[i] = (u16)(IMR1_8125 + (i - 1) * 4);
}

static void
rtl8125_backup_led_select(struct rtl8125_private *tp)
{
        tp->BackupLedSel[1] = RTL_R16(tp, LEDSEL_1_8125);
        tp->BackupLedSel[2] = RTL_R16(tp, LEDSEL_2_8125);
        tp->BackupLedSel[3] = RTL_R16(tp, LEDSEL_3_8125);
        tp->BackupLedSel[0] = RTL_R16(tp, CustomLED);
}

static void
rtl8125_restore_led_select(struct rtl8125_private *tp)
{
        RTL_W16(tp, LEDSEL_1_8125, tp->BackupLedSel[1]);
        RTL_W16(tp, LEDSEL_2_8125, tp->BackupLedSel[2]);
        RTL_W16(tp, LEDSEL_3_8125, tp->BackupLedSel[3]);
        RTL_W16(tp, CustomLED, tp->BackupLedSel[0]);
}

static bool
_rtl8125_backup_phy_fuse_dout_v4(struct rtl8125_private *tp)
{
        u16 i;

        for (i = 0; i < R8125_PHY_FUSE_DOUT_NUM; i++) {
                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA460,
                                                      0x001F,
                                                      i);
                tp->BackupPhyFuseDout[i] = rtl8125_mdio_direct_read_phy_ocp(tp, 0xA462);
        }

        if (tp->HwSuppEsdVer == 4) {
                tp->BackupPhyFuseDout[3] |= 0xF000;
                tp->BackupPhyFuseDout[7] |= 0x03FF;
                tp->BackupPhyFuseDout[4] = USHRT_MAX;
                tp->BackupPhyFuseDout[5] = USHRT_MAX;
                tp->BackupPhyFuseDout[6] = USHRT_MAX;
        } else if (tp->HwSuppEsdVer == 5) {
                tp->BackupPhyFuseDout[30] = USHRT_MAX;
                tp->BackupPhyFuseDout[31] = USHRT_MAX;
        }

        return TRUE;
}

static bool
rtl8125_backup_phy_fuse_dout(struct rtl8125_private *tp)
{
        if (tp->HwSuppEsdVer == 4 || tp->HwSuppEsdVer == 5)
                return _rtl8125_backup_phy_fuse_dout_v4(tp);
        else
                return FALSE;
}

static void
_rtl8125_restore_phy_fuse_dout_v4(struct rtl8125_private *tp)
{
        u16 i;

        for (i = 0; i < R8125_PHY_FUSE_DOUT_NUM; i++) {
                if (tp->BackupPhyFuseDout[i] == USHRT_MAX)
                        continue;

                rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                      0xA460,
                                                      0x001F,
                                                      i);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA462, tp->BackupPhyFuseDout[i]);
        }
}

static void
rtl8125_restore_phy_fuse_dout(struct rtl8125_private *tp)
{
        if (tp->HwSuppEsdVer == 4 || tp->HwSuppEsdVer == 5)
                _rtl8125_restore_phy_fuse_dout_v4(tp);
        else
                return;
}

static void
rtl8125_init_software_variable(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct pci_dev *pdev = tp->pci_dev;

#ifdef ENABLE_LIB_SUPPORT
        tp->ring_lib_enabled = 1;
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3: {
                u8 tmp = (u8)rtl8125_mac_ocp_read(tp, 0xD006);
                if (tmp == 0x02 || tmp == 0x04)
                        tp->HwSuppDashVer = 2;
        }
        break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
                tp->HwSuppDashVer = 4;
                break;
        default:
                tp->HwSuppDashVer = 0;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                if (HW_DASH_SUPPORT_DASH(tp))
                        tp->HwSuppOcpChannelVer = 2;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_12:
                tp->HwSuppOcpChannelVer = 2;
                break;
        }
        tp->AllowAccessDashOcp = rtl8125_is_allow_access_dash_ocp(tp);

        tp->HwPkgDet = rtl8125_mac_ocp_read(tp, 0xDC00);
        tp->HwPkgDet = (tp->HwPkgDet >> 3) & 0x07;

        tp->HwSuppNowIsOobVer = 1;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
                tp->HwPcieSNOffset = 0x16C;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwPcieSNOffset = 0x168;
                break;
        }

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_get_realwow_hw_version(dev);
#endif //ENABLE_REALWOW_SUPPORT

        tp->DASH = rtl8125_check_dash(tp);

        if (tp->DASH) {
                eee_enable = 0;

                tp->SizeOfSendToFwBuffer = SEND_TO_FW_BUF_SIZE;
                tp->SizeOfRecvFromFwBuffer = RECV_FROM_FW_BUF_SIZE;

                tp->DashFirmwareVersion = rtl8125_get_dash_fw_ver(tp);
        }

        if (aspm) {
                tp->org_pci_offset_99 = rtl8125_csi_fun0_read_byte(tp, 0x99);
                tp->org_pci_offset_99 &= ~(BIT_5|BIT_6);

                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                case CFG_METHOD_6:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x264);
                        break;
                case CFG_METHOD_4:
                case CFG_METHOD_5:
                case CFG_METHOD_7:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x214);
                        break;
                case CFG_METHOD_8:
                case CFG_METHOD_9:
                case CFG_METHOD_10:
                case CFG_METHOD_11:
                case CFG_METHOD_13:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x210);
                        break;
                case CFG_METHOD_12:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x184);
                        break;
                }
        }

        pci_read_config_byte(pdev, 0x80, &tp->org_pci_offset_80);
        pci_read_config_byte(pdev, 0x81, &tp->org_pci_offset_81);

        tp->use_timer_interrupt = TRUE;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
                tp->HwSuppMaxPhyLinkSpeed = 2500;
                break;
        default:
                tp->HwSuppMaxPhyLinkSpeed = 1000;
                break;
        }

        if (timer_count == 0 || tp->mcfg == CFG_METHOD_DEFAULT)
                tp->use_timer_interrupt = FALSE;

        tp->ShortPacketSwChecksum = TRUE;
        tp->UseSwPaddingShortPkt = TRUE;

#ifdef ENABLE_FIBER_SUPPORT
        rtl8125_check_fiber_mode_support(tp);
#endif /* ENABLE_FIBER_SUPPORT */

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_V3;
                break;
        default:
                tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_NOT_SUPPORT;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                tp->HwSuppEsdVer = 4;
                break;
        case CFG_METHOD_10:
                tp->HwSuppEsdVer = 5;
                break;
        default:
                tp->HwSuppEsdVer = 1;
                break;
        }

        if (rtl8125_backup_phy_fuse_dout(tp))
                tp->TestPhyOcpReg = TRUE;

#ifdef ENABLE_USE_FIRMWARE_FILE
        tp->TestPhyOcpReg = FALSE;
#endif

        tp->HwSuppLinkChgWakeUpVer = 3;

        switch (tp->mcfg) {
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
                tp->HwSuppD0SpeedUpVer = 1;
                break;
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppD0SpeedUpVer = 2;
                break;
        }

        tp->HwSuppCheckPhyDisableModeVer = 3;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
                tp->HwSuppTxNoCloseVer = 3;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppTxNoCloseVer = 6;
                break;
        }

        switch (tp->HwSuppTxNoCloseVer) {
        case 5:
        case 6:
                tp->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4;
                break;
        case 4:
                tp->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V3;
                break;
        case 3:
                tp->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V2;
                break;
        default:
                tx_no_close_enable = 0;
                break;
        }

        if (tp->HwSuppTxNoCloseVer > 0 && tx_no_close_enable == 1)
                tp->EnableTxNoClose = TRUE;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                tp->RequireLSOPatch = TRUE;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_2;
                break;
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_3;
                break;
        case CFG_METHOD_4:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_4;
                break;
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_5;
                break;
        case CFG_METHOD_8:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_8;
                break;
        case CFG_METHOD_9:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_9;
                break;
        case CFG_METHOD_10:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_10;
                break;
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_11;
                break;
        case CFG_METHOD_12:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_12;
                break;
        }

        if (tp->HwIcVerUnknown) {
                tp->NotWrRamCodeToMicroP = TRUE;
                tp->NotWrMcuPatchCode = TRUE;
        }

        rtl8125_check_hw_phy_mcu_code_ver(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                if ((rtl8125_mac_ocp_read(tp, 0xD442) & BIT_5) &&
                    (rtl8125_mdio_direct_read_phy_ocp(tp, 0xD068) & BIT_1))
                        tp->RequirePhyMdiSwapPatch = TRUE;
                break;
        }

        tp->HwSuppMacMcuVer = 2;

        tp->MacMcuPageSize = RTL8125_MAC_MCU_PAGE_SIZE;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppNumTxQueues = 2;
                tp->HwSuppNumRxQueues = 4;
                break;
        default:
                tp->HwSuppNumTxQueues = 1;
                tp->HwSuppNumRxQueues = 1;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                /* mac ptp */
                tp->HwSuppPtpVer = 1;
                break;
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                /* phy ptp */
                tp->HwSuppPtpVer = 3;
                break;
        }
#ifdef ENABLE_PTP_SUPPORT
        if (tp->HwSuppPtpVer > 0)
                tp->EnablePtp = 1;
#endif

        //init interrupt
        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                tp->HwSuppIsrVer = 2;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
                tp->HwSuppIsrVer = 4;
                break;
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                tp->HwSuppIsrVer = 5;
                break;
        case CFG_METHOD_12:
                tp->HwSuppIsrVer = 7;
                break;
        default:
                tp->HwSuppIsrVer = 1;
                break;
        }

        tp->HwCurrIsrVer = tp->HwSuppIsrVer;
        if (tp->HwCurrIsrVer > 1) {
                if (!(tp->features & RTL_FEATURE_MSIX) ||
                    tp->irq_nvecs < tp->min_irq_nvecs)
                        tp->HwCurrIsrVer = 1;
        }

        tp->num_tx_rings = 1;
#ifdef ENABLE_MULTIPLE_TX_QUEUE
#ifndef ENABLE_LIB_SUPPORT
        tp->num_tx_rings = tp->HwSuppNumTxQueues;
#endif
#endif
        if (tp->HwCurrIsrVer < 2 ||
            (tp->HwCurrIsrVer == 2 && tp->irq_nvecs < 19))
                tp->num_tx_rings = 1;

        //RSS
        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppRssVer = 5;
                tp->HwSuppIndirTblEntries = 128;
                break;
        }

        tp->num_rx_rings = 1;
#ifdef ENABLE_RSS_SUPPORT
#ifdef ENABLE_LIB_SUPPORT
        if (tp->HwSuppRssVer > 0)
                tp->EnableRss = 1;
#else
        if (tp->HwSuppRssVer > 0 && tp->HwCurrIsrVer > 1) {
                u8 rss_queue_num = netif_get_num_default_rss_queues();
                tp->num_rx_rings = (tp->HwSuppNumRxQueues > rss_queue_num)?
                                   rss_queue_num : tp->HwSuppNumRxQueues;

                if (!(tp->num_rx_rings >= 2 && tp->irq_nvecs >= tp->num_rx_rings))
                        tp->num_rx_rings = 1;

                if (tp->num_rx_rings >= 2)
                        tp->EnableRss = 1;
        }
#endif
#endif

        //interrupt mask
        rtl8125_setup_interrupt_mask(tp);

        rtl8125_setup_mqs_reg(tp);

        rtl8125_set_ring_size(tp, NUM_RX_DESC, NUM_TX_DESC);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
                tp->HwSuppIntMitiVer = 3;
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                tp->HwSuppIntMitiVer = 4;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppIntMitiVer = 6;
                break;
        }

        tp->HwSuppTcamVer = 1;
        tp->TcamNotValidReg = TCAM_NOTVALID_ADDR;
        tp->TcamValidReg = TCAM_VALID_ADDR;
        tp->TcamMaAddrcOffset = TCAM_MAC_ADDR;
        tp->TcamVlanTagOffset = TCAM_VLAN_TAG;

        tp->HwSuppExtendTallyCounterVer = 1;

        timer_count_v2 = (timer_count / 0x100);
        /* timer unit is double */
        switch (tp->mcfg) {
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                timer_count_v2 /= 2;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                tp->RequiredPfmPatch = TRUE;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
                tp->HwSuppRxDescType = RX_DESC_RING_TYPE_3;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                tp->HwSuppRxDescType = RX_DESC_RING_TYPE_4;
                break;
        default:
                tp->HwSuppRxDescType = RX_DESC_RING_TYPE_1;
                break;
        }

        tp->InitRxDescType = RX_DESC_RING_TYPE_1;
        tp->RxDescLength = RX_DESC_LEN_TYPE_1;
        switch (tp->HwSuppRxDescType) {
        case RX_DESC_RING_TYPE_3:
                if (tp->EnableRss || tp->EnablePtp) {
                        tp->InitRxDescType = RX_DESC_RING_TYPE_3;
                        tp->RxDescLength = RX_DESC_LEN_TYPE_3;
                }
                break;
        case RX_DESC_RING_TYPE_4:
                if (tp->EnableRss) {
                        tp->InitRxDescType = RX_DESC_RING_TYPE_4;
                        tp->RxDescLength = RX_DESC_LEN_TYPE_4;
                }
                break;
        }

        tp->rtl8125_rx_config = rtl_chip_info[tp->chipset].RCR_Cfg;
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                tp->rtl8125_rx_config |= EnableRxDescV3;
        else if (tp->InitRxDescType == RX_DESC_RING_TYPE_4)
                tp->rtl8125_rx_config &= ~EnableRxDescV4_1;

        rtl8125_backup_led_select(tp);

        tp->wol_opts = rtl8125_get_hw_wol(tp);
        tp->wol_enabled = (tp->wol_opts) ? WOL_ENABLED : WOL_DISABLED;

        rtl8125_set_link_option(tp, autoneg_mode, speed_mode, duplex_mode,
                                rtl8125_fc_full);

        tp->max_jumbo_frame_size = rtl_chip_info[tp->chipset].jumbo_frame_sz;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
        /* MTU range: 60 - hw-specific max */
        dev->min_mtu = ETH_MIN_MTU;
        dev->max_mtu = tp->max_jumbo_frame_size;
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)

        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                struct ethtool_keee *eee = &tp->eee;

                eee->eee_enabled = eee_enable;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
                eee->supported  = SUPPORTED_100baseT_Full |
                                  SUPPORTED_1000baseT_Full;
                eee->advertised = mmd_eee_adv_to_ethtool_adv_t(MDIO_EEE_1000T | MDIO_EEE_100TX);
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                        /* nothing to do */
                        break;
                default:
                        if (HW_SUPP_PHY_LINK_SPEED_2500M(tp)) {
                                eee->supported |= SUPPORTED_2500baseX_Full;
                                eee->advertised |= SUPPORTED_2500baseX_Full;
                        }
                        break;
                }
#else
                linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, eee->supported);
                linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, eee->supported);
                linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, eee->advertised);
                linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, eee->advertised);
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                        /* nothing to do */
                        break;
                default:
                        if (HW_SUPP_PHY_LINK_SPEED_2500M(tp)) {
                                linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT, eee->supported);
                                linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT, eee->advertised);
                        }
                        break;
                }
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0) */
                eee->tx_lpi_enabled = eee_enable;
                eee->tx_lpi_timer = dev->mtu + ETH_HLEN + 0x20;
        }

        tp->ptp_master_mode = enable_ptp_master_mode;

#ifdef ENABLE_RSS_SUPPORT
        if (tp->EnableRss)
                rtl8125_init_rss(tp);
#endif
}

static void
rtl8125_release_board(struct pci_dev *pdev,
                      struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;

        rtl8125_rar_set(tp, tp->org_mac_addr);
        tp->wol_enabled = WOL_DISABLED;

        if (!tp->DASH)
                rtl8125_phy_power_down(dev);

        iounmap(ioaddr);
        pci_release_regions(pdev);
        pci_clear_mwi(pdev);
        pci_disable_device(pdev);
        free_netdev(dev);
}

static void
rtl8125_hw_address_set(struct net_device *dev, u8 mac_addr[MAC_ADDR_LEN])
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
        eth_hw_addr_set(dev, mac_addr);
#else
        memcpy(dev->dev_addr, mac_addr, MAC_ADDR_LEN);
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
}

static int
rtl8125_get_mac_address(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;
        u8 mac_addr[MAC_ADDR_LEN];

        for (i = 0; i < MAC_ADDR_LEN; i++)
                mac_addr[i] = RTL_R8(tp, MAC0 + i);

        *(u32*)&mac_addr[0] = RTL_R32(tp, BACKUP_ADDR0_8125);
        *(u16*)&mac_addr[4] = RTL_R16(tp, BACKUP_ADDR1_8125);

        if (!is_valid_ether_addr(mac_addr)) {
                netif_err(tp, probe, dev, "Invalid ether addr %pM\n",
                          mac_addr);
                eth_random_addr(mac_addr);
                dev->addr_assign_type = NET_ADDR_RANDOM;
                netif_info(tp, probe, dev, "Random ether addr %pM\n",
                           mac_addr);
                tp->random_mac = 1;
        }

        rtl8125_hw_address_set(dev, mac_addr);
        rtl8125_rar_set(tp, mac_addr);

        /* keep the original MAC address */
        memcpy(tp->org_mac_addr, dev->dev_addr, MAC_ADDR_LEN);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        memcpy(dev->perm_addr, dev->dev_addr, MAC_ADDR_LEN);
#endif
        return 0;
}

/**
 * rtl8125_set_mac_address - Change the Ethernet Address of the NIC
 * @dev: network interface device structure
 * @p:   pointer to an address structure
 *
 * Return 0 on success, negative on failure
 **/
static int
rtl8125_set_mac_address(struct net_device *dev,
                        void *p)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct sockaddr *addr = p;

        if (!is_valid_ether_addr(addr->sa_data))
                return -EADDRNOTAVAIL;

        rtl8125_hw_address_set(dev, addr->sa_data);

        rtl8125_rar_set(tp, dev->dev_addr);

        return 0;
}

/******************************************************************************
 * rtl8125_rar_set - Puts an ethernet address into a receive address register.
 *
 * tp - The private data structure for driver
 * addr - Address to put into receive address register
 *****************************************************************************/
void
rtl8125_rar_set(struct rtl8125_private *tp,
                const u8 *addr)
{
        uint32_t rar_low = 0;
        uint32_t rar_high = 0;

        rar_low = ((uint32_t) addr[0] |
                   ((uint32_t) addr[1] << 8) |
                   ((uint32_t) addr[2] << 16) |
                   ((uint32_t) addr[3] << 24));

        rar_high = ((uint32_t) addr[4] |
                    ((uint32_t) addr[5] << 8));

        rtl8125_enable_cfg9346_write(tp);
        RTL_W32(tp, MAC0, rar_low);
        RTL_W32(tp, MAC4, rar_high);

        rtl8125_disable_cfg9346_write(tp);
}

#ifdef ETHTOOL_OPS_COMPAT
static int ethtool_get_settings(struct net_device *dev, void *useraddr)
{
        struct ethtool_cmd cmd = { ETHTOOL_GSET };
        int err;

        if (!ethtool_ops->get_settings)
                return -EOPNOTSUPP;

        err = ethtool_ops->get_settings(dev, &cmd);
        if (err < 0)
                return err;

        if (copy_to_user(useraddr, &cmd, sizeof(cmd)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_settings(struct net_device *dev, void *useraddr)
{
        struct ethtool_cmd cmd;

        if (!ethtool_ops->set_settings)
                return -EOPNOTSUPP;

        if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
                return -EFAULT;

        return ethtool_ops->set_settings(dev, &cmd);
}

static int ethtool_get_drvinfo(struct net_device *dev, void *useraddr)
{
        struct ethtool_drvinfo info;
        struct ethtool_ops *ops = ethtool_ops;

        if (!ops->get_drvinfo)
                return -EOPNOTSUPP;

        memset(&info, 0, sizeof(info));
        info.cmd = ETHTOOL_GDRVINFO;
        ops->get_drvinfo(dev, &info);

        if (ops->self_test_count)
                info.testinfo_len = ops->self_test_count(dev);
        if (ops->get_stats_count)
                info.n_stats = ops->get_stats_count(dev);
        if (ops->get_regs_len)
                info.regdump_len = ops->get_regs_len(dev);
        if (ops->get_eeprom_len)
                info.eedump_len = ops->get_eeprom_len(dev);

        if (copy_to_user(useraddr, &info, sizeof(info)))
                return -EFAULT;
        return 0;
}

static int ethtool_get_regs(struct net_device *dev, char *useraddr)
{
        struct ethtool_regs regs;
        struct ethtool_ops *ops = ethtool_ops;
        void *regbuf;
        int reglen, ret;

        if (!ops->get_regs || !ops->get_regs_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&regs, useraddr, sizeof(regs)))
                return -EFAULT;

        reglen = ops->get_regs_len(dev);
        if (regs.len > reglen)
                regs.len = reglen;

        regbuf = kmalloc(reglen, GFP_USER);
        if (!regbuf)
                return -ENOMEM;

        ops->get_regs(dev, &regs, regbuf);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &regs, sizeof(regs)))
                goto out;
        useraddr += offsetof(struct ethtool_regs, data);
        if (copy_to_user(useraddr, regbuf, reglen))
                goto out;
        ret = 0;

out:
        kfree(regbuf);
        return ret;
}

static int ethtool_get_wol(struct net_device *dev, char *useraddr)
{
        struct ethtool_wolinfo wol = { ETHTOOL_GWOL };

        if (!ethtool_ops->get_wol)
                return -EOPNOTSUPP;

        ethtool_ops->get_wol(dev, &wol);

        if (copy_to_user(useraddr, &wol, sizeof(wol)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_wol(struct net_device *dev, char *useraddr)
{
        struct ethtool_wolinfo wol;

        if (!ethtool_ops->set_wol)
                return -EOPNOTSUPP;

        if (copy_from_user(&wol, useraddr, sizeof(wol)))
                return -EFAULT;

        return ethtool_ops->set_wol(dev, &wol);
}

static int ethtool_get_msglevel(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GMSGLVL };

        if (!ethtool_ops->get_msglevel)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_msglevel(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_msglevel(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_msglevel)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        ethtool_ops->set_msglevel(dev, edata.data);
        return 0;
}

static int ethtool_nway_reset(struct net_device *dev)
{
        if (!ethtool_ops->nway_reset)
                return -EOPNOTSUPP;

        return ethtool_ops->nway_reset(dev);
}

static int ethtool_get_link(struct net_device *dev, void *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GLINK };

        if (!ethtool_ops->get_link)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_link(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_get_eeprom(struct net_device *dev, void *useraddr)
{
        struct ethtool_eeprom eeprom;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->get_eeprom || !ops->get_eeprom_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&eeprom, useraddr, sizeof(eeprom)))
                return -EFAULT;

        /* Check for wrap and zero */
        if (eeprom.offset + eeprom.len <= eeprom.offset)
                return -EINVAL;

        /* Check for exceeding total eeprom len */
        if (eeprom.offset + eeprom.len > ops->get_eeprom_len(dev))
                return -EINVAL;

        data = kmalloc(eeprom.len, GFP_USER);
        if (!data)
                return -ENOMEM;

        ret = -EFAULT;
        if (copy_from_user(data, useraddr + sizeof(eeprom), eeprom.len))
                goto out;

        ret = ops->get_eeprom(dev, &eeprom, data);
        if (ret)
                goto out;

        ret = -EFAULT;
        if (copy_to_user(useraddr, &eeprom, sizeof(eeprom)))
                goto out;
        if (copy_to_user(useraddr + sizeof(eeprom), data, eeprom.len))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_set_eeprom(struct net_device *dev, void *useraddr)
{
        struct ethtool_eeprom eeprom;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->set_eeprom || !ops->get_eeprom_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&eeprom, useraddr, sizeof(eeprom)))
                return -EFAULT;

        /* Check for wrap and zero */
        if (eeprom.offset + eeprom.len <= eeprom.offset)
                return -EINVAL;

        /* Check for exceeding total eeprom len */
        if (eeprom.offset + eeprom.len > ops->get_eeprom_len(dev))
                return -EINVAL;

        data = kmalloc(eeprom.len, GFP_USER);
        if (!data)
                return -ENOMEM;

        ret = -EFAULT;
        if (copy_from_user(data, useraddr + sizeof(eeprom), eeprom.len))
                goto out;

        ret = ops->set_eeprom(dev, &eeprom, data);
        if (ret)
                goto out;

        if (copy_to_user(useraddr + sizeof(eeprom), data, eeprom.len))
                ret = -EFAULT;

out:
        kfree(data);
        return ret;
}

static int ethtool_get_coalesce(struct net_device *dev, void *useraddr)
{
        struct ethtool_coalesce coalesce = { ETHTOOL_GCOALESCE };

        if (!ethtool_ops->get_coalesce)
                return -EOPNOTSUPP;

        ethtool_ops->get_coalesce(dev, &coalesce);

        if (copy_to_user(useraddr, &coalesce, sizeof(coalesce)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_coalesce(struct net_device *dev, void *useraddr)
{
        struct ethtool_coalesce coalesce;

        if (!ethtool_ops->get_coalesce)
                return -EOPNOTSUPP;

        if (copy_from_user(&coalesce, useraddr, sizeof(coalesce)))
                return -EFAULT;

        return ethtool_ops->set_coalesce(dev, &coalesce);
}

static int ethtool_get_ringparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_ringparam ringparam = { ETHTOOL_GRINGPARAM };

        if (!ethtool_ops->get_ringparam)
                return -EOPNOTSUPP;

        ethtool_ops->get_ringparam(dev, &ringparam);

        if (copy_to_user(useraddr, &ringparam, sizeof(ringparam)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_ringparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_ringparam ringparam;

        if (!ethtool_ops->get_ringparam)
                return -EOPNOTSUPP;

        if (copy_from_user(&ringparam, useraddr, sizeof(ringparam)))
                return -EFAULT;

        return ethtool_ops->set_ringparam(dev, &ringparam);
}

static int ethtool_get_pauseparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_pauseparam pauseparam = { ETHTOOL_GPAUSEPARAM };

        if (!ethtool_ops->get_pauseparam)
                return -EOPNOTSUPP;

        ethtool_ops->get_pauseparam(dev, &pauseparam);

        if (copy_to_user(useraddr, &pauseparam, sizeof(pauseparam)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_pauseparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_pauseparam pauseparam;

        if (!ethtool_ops->get_pauseparam)
                return -EOPNOTSUPP;

        if (copy_from_user(&pauseparam, useraddr, sizeof(pauseparam)))
                return -EFAULT;

        return ethtool_ops->set_pauseparam(dev, &pauseparam);
}

static int ethtool_get_rx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GRXCSUM };

        if (!ethtool_ops->get_rx_csum)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_rx_csum(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_rx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_rx_csum)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        ethtool_ops->set_rx_csum(dev, edata.data);
        return 0;
}

static int ethtool_get_tx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GTXCSUM };

        if (!ethtool_ops->get_tx_csum)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_tx_csum(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_tx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_tx_csum)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_tx_csum(dev, edata.data);
}

static int ethtool_get_sg(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GSG };

        if (!ethtool_ops->get_sg)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_sg(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_sg(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_sg)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_sg(dev, edata.data);
}

static int ethtool_get_tso(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GTSO };

        if (!ethtool_ops->get_tso)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_tso(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_tso(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_tso)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_tso(dev, edata.data);
}

static int ethtool_self_test(struct net_device *dev, char *useraddr)
{
        struct ethtool_test test;
        struct ethtool_ops *ops = ethtool_ops;
        u64 *data;
        int ret;

        if (!ops->self_test || !ops->self_test_count)
                return -EOPNOTSUPP;

        if (copy_from_user(&test, useraddr, sizeof(test)))
                return -EFAULT;

        test.len = ops->self_test_count(dev);
        data = kmalloc(test.len * sizeof(u64), GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->self_test(dev, &test, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &test, sizeof(test)))
                goto out;
        useraddr += sizeof(test);
        if (copy_to_user(useraddr, data, test.len * sizeof(u64)))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_get_strings(struct net_device *dev, void *useraddr)
{
        struct ethtool_gstrings gstrings;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->get_strings)
                return -EOPNOTSUPP;

        if (copy_from_user(&gstrings, useraddr, sizeof(gstrings)))
                return -EFAULT;

        switch (gstrings.string_set) {
        case ETH_SS_TEST:
                if (!ops->self_test_count)
                        return -EOPNOTSUPP;
                gstrings.len = ops->self_test_count(dev);
                break;
        case ETH_SS_STATS:
                if (!ops->get_stats_count)
                        return -EOPNOTSUPP;
                gstrings.len = ops->get_stats_count(dev);
                break;
        default:
                return -EINVAL;
        }

        data = kmalloc(gstrings.len * ETH_GSTRING_LEN, GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->get_strings(dev, gstrings.string_set, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &gstrings, sizeof(gstrings)))
                goto out;
        useraddr += sizeof(gstrings);
        if (copy_to_user(useraddr, data, gstrings.len * ETH_GSTRING_LEN))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_phys_id(struct net_device *dev, void *useraddr)
{
        struct ethtool_value id;

        if (!ethtool_ops->phys_id)
                return -EOPNOTSUPP;

        if (copy_from_user(&id, useraddr, sizeof(id)))
                return -EFAULT;

        return ethtool_ops->phys_id(dev, id.data);
}

static int ethtool_get_stats(struct net_device *dev, void *useraddr)
{
        struct ethtool_stats stats;
        struct ethtool_ops *ops = ethtool_ops;
        u64 *data;
        int ret;

        if (!ops->get_ethtool_stats || !ops->get_stats_count)
                return -EOPNOTSUPP;

        if (copy_from_user(&stats, useraddr, sizeof(stats)))
                return -EFAULT;

        stats.n_stats = ops->get_stats_count(dev);
        data = kmalloc(stats.n_stats * sizeof(u64), GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->get_ethtool_stats(dev, &stats, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &stats, sizeof(stats)))
                goto out;
        useraddr += sizeof(stats);
        if (copy_to_user(useraddr, data, stats.n_stats * sizeof(u64)))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_ioctl(struct ifreq *ifr)
{
        struct net_device *dev = __dev_get_by_name(ifr->ifr_name);
        void *useraddr = (void *) ifr->ifr_data;
        u32 ethcmd;

        /*
         * XXX: This can be pushed down into the ethtool_* handlers that
         * need it.  Keep existing behaviour for the moment.
         */
        if (!capable(CAP_NET_ADMIN))
                return -EPERM;

        if (!dev || !netif_device_present(dev))
                return -ENODEV;

        if (copy_from_user(&ethcmd, useraddr, sizeof (ethcmd)))
                return -EFAULT;

        switch (ethcmd) {
        case ETHTOOL_GSET:
                return ethtool_get_settings(dev, useraddr);
        case ETHTOOL_SSET:
                return ethtool_set_settings(dev, useraddr);
        case ETHTOOL_GDRVINFO:
                return ethtool_get_drvinfo(dev, useraddr);
        case ETHTOOL_GREGS:
                return ethtool_get_regs(dev, useraddr);
        case ETHTOOL_GWOL:
                return ethtool_get_wol(dev, useraddr);
        case ETHTOOL_SWOL:
                return ethtool_set_wol(dev, useraddr);
        case ETHTOOL_GMSGLVL:
                return ethtool_get_msglevel(dev, useraddr);
        case ETHTOOL_SMSGLVL:
                return ethtool_set_msglevel(dev, useraddr);
        case ETHTOOL_NWAY_RST:
                return ethtool_nway_reset(dev);
        case ETHTOOL_GLINK:
                return ethtool_get_link(dev, useraddr);
        case ETHTOOL_GEEPROM:
                return ethtool_get_eeprom(dev, useraddr);
        case ETHTOOL_SEEPROM:
                return ethtool_set_eeprom(dev, useraddr);
        case ETHTOOL_GCOALESCE:
                return ethtool_get_coalesce(dev, useraddr);
        case ETHTOOL_SCOALESCE:
                return ethtool_set_coalesce(dev, useraddr);
        case ETHTOOL_GRINGPARAM:
                return ethtool_get_ringparam(dev, useraddr);
        case ETHTOOL_SRINGPARAM:
                return ethtool_set_ringparam(dev, useraddr);
        case ETHTOOL_GPAUSEPARAM:
                return ethtool_get_pauseparam(dev, useraddr);
        case ETHTOOL_SPAUSEPARAM:
                return ethtool_set_pauseparam(dev, useraddr);
        case ETHTOOL_GRXCSUM:
                return ethtool_get_rx_csum(dev, useraddr);
        case ETHTOOL_SRXCSUM:
                return ethtool_set_rx_csum(dev, useraddr);
        case ETHTOOL_GTXCSUM:
                return ethtool_get_tx_csum(dev, useraddr);
        case ETHTOOL_STXCSUM:
                return ethtool_set_tx_csum(dev, useraddr);
        case ETHTOOL_GSG:
                return ethtool_get_sg(dev, useraddr);
        case ETHTOOL_SSG:
                return ethtool_set_sg(dev, useraddr);
        case ETHTOOL_GTSO:
                return ethtool_get_tso(dev, useraddr);
        case ETHTOOL_STSO:
                return ethtool_set_tso(dev, useraddr);
        case ETHTOOL_TEST:
                return ethtool_self_test(dev, useraddr);
        case ETHTOOL_GSTRINGS:
                return ethtool_get_strings(dev, useraddr);
        case ETHTOOL_PHYS_ID:
                return ethtool_phys_id(dev, useraddr);
        case ETHTOOL_GSTATS:
                return ethtool_get_stats(dev, useraddr);
        default:
                return -EOPNOTSUPP;
        }

        return -EOPNOTSUPP;
}
#endif //ETHTOOL_OPS_COMPAT

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
static int rtl8125_siocdevprivate(struct net_device *dev, struct ifreq *ifr,
                                  void __user *data, int cmd)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret = 0;

        switch (cmd) {
#ifdef ENABLE_DASH_SUPPORT
        case SIOCDEVPRIVATE_RTLDASH:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }
                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_dash_ioctl(dev, ifr);
                break;
#endif

#ifdef ENABLE_REALWOW_SUPPORT
        case SIOCDEVPRIVATE_RTLREALWOW:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }

                ret = rtl8125_realwow_ioctl(dev, ifr);
                break;
#endif

        case SIOCRTLTOOL:
                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_tool_ioctl(tp, ifr);
                break;

        default:
                ret = -EOPNOTSUPP;
        }

        return ret;
}
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)

static int
rtl8125_do_ioctl(struct net_device *dev,
                 struct ifreq *ifr,
                 int cmd)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct mii_ioctl_data *data = if_mii(ifr);
        int ret = 0;

        switch (cmd) {
        case SIOCGMIIPHY:
                data->phy_id = 32; /* Internal PHY */
                break;

        case SIOCGMIIREG:
                rtl8125_mdio_write(tp, 0x1F, 0x0000);
                data->val_out = rtl8125_mdio_read(tp, data->reg_num);
                break;

        case SIOCSMIIREG:
                if (!capable(CAP_NET_ADMIN))
                        return -EPERM;
                rtl8125_mdio_write(tp, 0x1F, 0x0000);
                rtl8125_mdio_write(tp, data->reg_num, data->val_in);
                break;

#ifdef ETHTOOL_OPS_COMPAT
        case SIOCETHTOOL:
                ret = ethtool_ioctl(ifr);
                break;
#endif

#ifdef ENABLE_PTP_SUPPORT
        case SIOCSHWTSTAMP:
        case SIOCGHWTSTAMP:
                if (tp->EnablePtp)
                        ret = rtl8125_ptp_ioctl(dev, ifr, cmd);
                else
                        ret = -EOPNOTSUPP;
                break;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
#ifdef ENABLE_DASH_SUPPORT
        case SIOCDEVPRIVATE_RTLDASH:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }
                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_dash_ioctl(dev, ifr);
                break;
#endif

#ifdef ENABLE_REALWOW_SUPPORT
        case SIOCDEVPRIVATE_RTLREALWOW:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }

                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_realwow_ioctl(dev, ifr);
                break;
#endif

        case SIOCRTLTOOL:
                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_tool_ioctl(tp, ifr);
                break;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)

        default:
                ret = -EOPNOTSUPP;
                break;
        }

        return ret;
}

static void
rtl8125_phy_power_up(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (rtl8125_is_in_phy_disable_mode(dev))
                return;

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE);

        //wait ups resume (phy state 3)
        rtl8125_wait_phy_ups_resume(dev, 3);

        r8125_spin_unlock(&tp->phy_lock, flags);
}

static void
rtl8125_phy_power_down(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp))
                return;
#endif /* ENABLE_FIBER_SUPPORT */

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE | BMCR_PDOWN);

        r8125_spin_unlock(&tp->phy_lock, flags);
}

static int __devinit
rtl8125_init_board(struct pci_dev *pdev,
                   struct net_device **dev_out,
                   void __iomem **ioaddr_out)
{
        void __iomem *ioaddr;
        struct net_device *dev;
        struct rtl8125_private *tp;
        int rc = -ENOMEM, i, pm_cap;

        assert(ioaddr_out != NULL);

        /* dev zeroed in alloc_etherdev */
        dev = alloc_etherdev_mq(sizeof (*tp), R8125_MAX_QUEUES);
        if (dev == NULL) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_drv(&debug))
                        dev_err(&pdev->dev, "unable to alloc new ethernet\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out;
        }

        SET_MODULE_OWNER(dev);
        SET_NETDEV_DEV(dev, &pdev->dev);
        tp = netdev_priv(dev);
        tp->dev = dev;
        tp->pci_dev = pdev;
        tp->msg_enable = netif_msg_init(debug.msg_enable, R8125_MSG_DEFAULT);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
        if (!aspm)
                pci_disable_link_state(pdev, PCIE_LINK_STATE_L0S | PCIE_LINK_STATE_L1 |
                                       PCIE_LINK_STATE_CLKPM);
#endif

        /* enable device (incl. PCI PM wakeup and hotplug setup) */
        rc = pci_enable_device(pdev);
        if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "enable failure\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out_free_dev;
        }

        if (pci_set_mwi(pdev) < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_drv(&debug))
                        dev_info(&pdev->dev, "Mem-Wr-Inval unavailable.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        }

        /* save power state before pci_enable_device overwrites it */
        pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
        if (pm_cap) {
                u16 pwr_command;

                pci_read_config_word(pdev, pm_cap + PCI_PM_CTRL, &pwr_command);
        } else {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp)) {
                        dev_err(&pdev->dev, "PowerManagement capability not found.\n");
                }
#else
                printk("PowerManagement capability not found.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        }

        /* make sure PCI base addr 1 is MMIO */
        if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "region #1 not an MMIO resource, aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -ENODEV;
                goto err_out_mwi;
        }
        /* check for weird/broken PCI region reporting */
        if (pci_resource_len(pdev, 2) < R8125_REGS_SIZE) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "Invalid PCI region size(s), aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -ENODEV;
                goto err_out_mwi;
        }

        rc = pci_request_regions(pdev, MODULENAME);
        if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "could not request regions.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out_mwi;
        }

        if ((sizeof(dma_addr_t) > 4) &&
            use_dac &&
            !dma_set_mask(&pdev->dev, DMA_BIT_MASK(64)) &&
            !dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64))) {
                dev->features |= NETIF_F_HIGHDMA;
        } else {
                rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
                if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        if (netif_msg_probe(tp))
                                dev_err(&pdev->dev, "DMA configuration failed.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        goto err_out_free_res;
                }
        }

        /* ioremap MMIO region */
        ioaddr = ioremap(pci_resource_start(pdev, 2), pci_resource_len(pdev, 2));
        if (ioaddr == NULL) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "cannot remap MMIO, aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -EIO;
                goto err_out_free_res;
        }

        tp->mmio_addr = ioaddr;

        /* Identify chip attached to board */
        rtl8125_get_mac_version(tp);

        rtl8125_print_mac_version(tp);

        for (i = ARRAY_SIZE(rtl_chip_info) - 1; i >= 0; i--) {
                if (tp->mcfg == rtl_chip_info[i].mcfg)
                        break;
        }

        if (i < 0) {
                /* Unknown chip: assume array element #0, original RTL-8125 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_printk(KERN_DEBUG, &pdev->dev, "unknown chip version, assuming %s\n", rtl_chip_info[0].name);
#else
                printk("Realtek unknown chip version, assuming %s\n", rtl_chip_info[0].name);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
                i++;
        }

        tp->chipset = i;

        *ioaddr_out = ioaddr;
        *dev_out = dev;
out:
        return rc;

err_out_free_res:
        pci_release_regions(pdev);
err_out_mwi:
        pci_clear_mwi(pdev);
        pci_disable_device(pdev);
err_out_free_dev:
        free_netdev(dev);
err_out:
        *ioaddr_out = NULL;
        *dev_out = NULL;
        goto out;
}

static bool
rtl8125_test_phy_ocp_v4(struct rtl8125_private *tp)
{
        bool restore = FALSE;
        bool uc2_response;
        u8 phy_fatal_err;
        u16 val;

        if (FALSE == HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                goto exit;

        uc2_response = !!(rtl8125_mdio_direct_read_phy_ocp(tp, 0xB87A) & BIT_0);
        phy_fatal_err = rtl8125_mdio_direct_read_phy_ocp(tp, 0xB98E);

        if (!uc2_response && (phy_fatal_err == 0))
                goto exit;

        rtl8125_set_eth_phy_ocp_bit(tp, 0xC418, BIT_0);
        mdelay(24);

        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC404);
        if ((val & 0x03) != 0x00) {
                u32 wait_cnt = 0;

                while ((val & 0x03) != 0x00 && wait_cnt < 5) {
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC02, 0x000C);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC04, 0x03FC);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC4C, 0x1F00);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC06, 0x7F00);

                        rtl8125_set_eth_phy_ocp_bit(tp, 0xC402, BIT_10);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xC402, BIT_10);

                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC06, 0x7F00);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC4C, 0x1F00);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC04, 0x03FC);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC02, 0x000C);

                        mdelay(100);
                        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC404);
                        wait_cnt++;
                }
        }

        rtl8125_restore_phy_fuse_dout(tp);

        rtl8125_wait_phy_state_ready(tp, HW_PHY_STATUS_INI, 5000000);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA468, BIT_0);

        rtl8125_wait_phy_state_ready(tp, HW_PHY_STATUS_LAN_ON, 500000);

        if (phy_fatal_err) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x801C);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, phy_fatal_err);
        }
        if (uc2_response) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x801B);
                rtl8125_set_eth_phy_ocp_bit(tp, 0xA438, BIT_8);
        }

        rtl8125_restore_led_select(tp);

        tp->HwHasWrRamCodeToMicroP = FALSE;

        restore = TRUE;

exit:
        rtl8125_set_eth_phy_ocp_bit(tp, 0xB87A, BIT_0);
        rtl8125_mdio_write(tp, 0x1F, 0x0000);

        return restore;
}

static bool
rtl8125_test_phy_ocp_v5(struct rtl8125_private *tp)
{
        bool restore = FALSE;
        u8 phy_fatal_err;
        u16 val;

        if (FALSE == HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp))
                goto exit;

        phy_fatal_err = rtl8125_mdio_direct_read_phy_ocp(tp, 0xB98C);

        if (phy_fatal_err == 0)
                goto exit;

        rtl8125_set_eth_phy_ocp_bit(tp, 0xC418, BIT_0);
        mdelay(24);

        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC404);
        if (val & 0x0F) {
                u32 wait_cnt = 0;

                while (val & 0x0F && wait_cnt < 5) {
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC02, 0x000C);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC04, 0x03FC);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC4C, 0x1F00);
                        rtl8125_set_eth_phy_ocp_bit(tp, 0xBC06, 0x4F00);
                        rtl8125_clear_and_set_eth_phy_ocp_bit(tp,
                                                              0xBC06,
                                                              0x7F00,
                                                              0x4F00);

                        rtl8125_set_eth_phy_ocp_bit(tp, 0xC402, BIT_10);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xC402, BIT_10);

                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC06, 0x7F00);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC4C, 0x1F00);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC04, 0x03FC);
                        rtl8125_clear_eth_phy_ocp_bit(tp, 0xBC02, 0x000C);

                        mdelay(100);
                        val = rtl8125_mdio_direct_read_phy_ocp(tp, 0xC404);
                        wait_cnt++;
                }
        }

        rtl8125_restore_phy_fuse_dout(tp);

        rtl8125_wait_phy_state_ready(tp, HW_PHY_STATUS_INI, 5000000);

        if (tp->mcfg == CFG_METHOD_10)
                rtl8125_set_phy_mcu_8125d_1_efuse(tp->dev);

        rtl8125_set_eth_phy_ocp_bit(tp, 0xA468, BIT_0);

        rtl8125_clear_phy_ups_reg(tp->dev);

        rtl8125_wait_phy_state_ready(tp, HW_PHY_STATUS_LAN_ON, 500000);

        if (phy_fatal_err) {
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA436, 0x801C);
                rtl8125_mdio_direct_write_phy_ocp(tp, 0xA438, phy_fatal_err);
        }

        rtl8125_restore_led_select(tp);

        tp->HwHasWrRamCodeToMicroP = FALSE;

        restore = TRUE;

exit:
        rtl8125_mdio_write(tp, 0x1F, 0x0000);

        return restore;
}

static bool
rtl8125_test_phy_ocp(struct rtl8125_private *tp)
{
        unsigned long flags;
        bool reset = false;

        r8125_spin_lock(&tp->phy_lock, flags);

        if (tp->TestPhyOcpReg == FALSE)
                goto unlock;

        switch (tp->HwSuppEsdVer) {
        case 4:
                reset = rtl8125_test_phy_ocp_v4(tp);
                break;
        case 5:
                reset = rtl8125_test_phy_ocp_v5(tp);
                break;
        default:
                goto unlock;
        }

unlock:
        r8125_spin_unlock(&tp->phy_lock, flags);

        return reset;
}

static void
rtl8125_esd_checker(struct rtl8125_private *tp)
{
        struct net_device *dev = tp->dev;
        struct pci_dev *pdev = tp->pci_dev;
        u8 cmd;
        u16 io_base_l;
        u16 mem_base_l;
        u16 mem_base_h;
        u8 ilr;
        u16 resv_0x1c_h;
        u16 resv_0x1c_l;
        u16 resv_0x20_l;
        u16 resv_0x20_h;
        u16 resv_0x24_l;
        u16 resv_0x24_h;
        u16 resv_0x2c_h;
        u16 resv_0x2c_l;
        u32 pci_sn_l;
        u32 pci_sn_h;

        if (unlikely(tp->rtk_enable_diag))
                goto exit;

        tp->esd_flag = 0;

        pci_read_config_byte(pdev, PCI_COMMAND, &cmd);
        if (cmd != tp->pci_cfg_space.cmd) {
                printk(KERN_ERR "%s: cmd = 0x%02x, should be 0x%02x \n.", dev->name, cmd, tp->pci_cfg_space.cmd);
                pci_write_config_byte(pdev, PCI_COMMAND, tp->pci_cfg_space.cmd);
                tp->esd_flag |= BIT_0;

                pci_read_config_byte(pdev, PCI_COMMAND, &cmd);
                if (cmd == 0xff) {
                        printk(KERN_ERR "%s: pci link is down \n.", dev->name);
                        goto exit;
                }
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_0, &io_base_l);
        if (io_base_l != tp->pci_cfg_space.io_base_l) {
                printk(KERN_ERR "%s: io_base_l = 0x%04x, should be 0x%04x \n.", dev->name, io_base_l, tp->pci_cfg_space.io_base_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_0, tp->pci_cfg_space.io_base_l);
                tp->esd_flag |= BIT_1;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_2, &mem_base_l);
        if (mem_base_l != tp->pci_cfg_space.mem_base_l) {
                printk(KERN_ERR "%s: mem_base_l = 0x%04x, should be 0x%04x \n.", dev->name, mem_base_l, tp->pci_cfg_space.mem_base_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_2, tp->pci_cfg_space.mem_base_l);
                tp->esd_flag |= BIT_2;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, &mem_base_h);
        if (mem_base_h!= tp->pci_cfg_space.mem_base_h) {
                printk(KERN_ERR "%s: mem_base_h = 0x%04x, should be 0x%04x \n.", dev->name, mem_base_h, tp->pci_cfg_space.mem_base_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, tp->pci_cfg_space.mem_base_h);
                tp->esd_flag |= BIT_3;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_3, &resv_0x1c_l);
        if (resv_0x1c_l != tp->pci_cfg_space.resv_0x1c_l) {
                printk(KERN_ERR "%s: resv_0x1c_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x1c_l, tp->pci_cfg_space.resv_0x1c_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_3, tp->pci_cfg_space.resv_0x1c_l);
                tp->esd_flag |= BIT_4;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, &resv_0x1c_h);
        if (resv_0x1c_h != tp->pci_cfg_space.resv_0x1c_h) {
                printk(KERN_ERR "%s: resv_0x1c_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x1c_h, tp->pci_cfg_space.resv_0x1c_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, tp->pci_cfg_space.resv_0x1c_h);
                tp->esd_flag |= BIT_5;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_4, &resv_0x20_l);
        if (resv_0x20_l != tp->pci_cfg_space.resv_0x20_l) {
                printk(KERN_ERR "%s: resv_0x20_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x20_l, tp->pci_cfg_space.resv_0x20_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_4, tp->pci_cfg_space.resv_0x20_l);
                tp->esd_flag |= BIT_6;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, &resv_0x20_h);
        if (resv_0x20_h != tp->pci_cfg_space.resv_0x20_h) {
                printk(KERN_ERR "%s: resv_0x20_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x20_h, tp->pci_cfg_space.resv_0x20_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, tp->pci_cfg_space.resv_0x20_h);
                tp->esd_flag |= BIT_7;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_5, &resv_0x24_l);
        if (resv_0x24_l != tp->pci_cfg_space.resv_0x24_l) {
                printk(KERN_ERR "%s: resv_0x24_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x24_l, tp->pci_cfg_space.resv_0x24_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_5, tp->pci_cfg_space.resv_0x24_l);
                tp->esd_flag |= BIT_8;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, &resv_0x24_h);
        if (resv_0x24_h != tp->pci_cfg_space.resv_0x24_h) {
                printk(KERN_ERR "%s: resv_0x24_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x24_h, tp->pci_cfg_space.resv_0x24_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, tp->pci_cfg_space.resv_0x24_h);
                tp->esd_flag |= BIT_9;
        }

        pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &ilr);
        if (ilr != tp->pci_cfg_space.ilr) {
                printk(KERN_ERR "%s: ilr = 0x%02x, should be 0x%02x \n.", dev->name, ilr, tp->pci_cfg_space.ilr);
                pci_write_config_byte(pdev, PCI_INTERRUPT_LINE, tp->pci_cfg_space.ilr);
                tp->esd_flag |= BIT_10;
        }

        pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &resv_0x2c_l);
        if (resv_0x2c_l != tp->pci_cfg_space.resv_0x2c_l) {
                printk(KERN_ERR "%s: resv_0x2c_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x2c_l, tp->pci_cfg_space.resv_0x2c_l);
                pci_write_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, tp->pci_cfg_space.resv_0x2c_l);
                tp->esd_flag |= BIT_11;
        }

        pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, &resv_0x2c_h);
        if (resv_0x2c_h != tp->pci_cfg_space.resv_0x2c_h) {
                printk(KERN_ERR "%s: resv_0x2c_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x2c_h, tp->pci_cfg_space.resv_0x2c_h);
                pci_write_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, tp->pci_cfg_space.resv_0x2c_h);
                tp->esd_flag |= BIT_12;
        }

        if (tp->HwPcieSNOffset > 0) {
                pci_sn_l = rtl8125_csi_read(tp, tp->HwPcieSNOffset);
                if (pci_sn_l != tp->pci_cfg_space.pci_sn_l) {
                        printk(KERN_ERR "%s: pci_sn_l = 0x%08x, should be 0x%08x \n.", dev->name, pci_sn_l, tp->pci_cfg_space.pci_sn_l);
                        rtl8125_csi_write(tp, tp->HwPcieSNOffset, tp->pci_cfg_space.pci_sn_l);
                        tp->esd_flag |= BIT_13;
                }

                pci_sn_h = rtl8125_csi_read(tp, tp->HwPcieSNOffset + 4);
                if (pci_sn_h != tp->pci_cfg_space.pci_sn_h) {
                        printk(KERN_ERR "%s: pci_sn_h = 0x%08x, should be 0x%08x \n.", dev->name, pci_sn_h, tp->pci_cfg_space.pci_sn_h);
                        rtl8125_csi_write(tp, tp->HwPcieSNOffset + 4, tp->pci_cfg_space.pci_sn_h);
                        tp->esd_flag |= BIT_14;
                }
        }

        if (tp->TestPhyOcpReg && rtl8125_test_phy_ocp(tp))
                tp->esd_flag |= BIT_15;

        if (tp->esd_flag != 0) {
                printk(KERN_ERR "%s: esd_flag = 0x%04x\n.\n", dev->name, tp->esd_flag);
                netif_carrier_off(dev);
                netif_tx_disable(dev);
                rtl8125_hw_reset(dev);
                rtl8125_tx_clear(tp);
                rtl8125_rx_clear(tp);
                rtl8125_init_ring(dev);
                rtl8125_up(dev);
                rtl8125_enable_hw_linkchg_interrupt(tp);
                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
                tp->esd_flag = 0;
        }
exit:
        return;
}
/*
static void
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
rtl8125_esd_timer(unsigned long __opaque)
#else
rtl8125_esd_timer(struct timer_list *t)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        struct net_device *dev = (struct net_device *)__opaque;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->esd_timer;
#else
        struct rtl8125_private *tp = from_timer(tp, t, esd_timer);
        //struct net_device *dev = tp->dev;
        struct timer_list *timer = t;
#endif
        rtl8125_esd_checker(tp);

        mod_timer(timer, jiffies + timeout);
}
*/

/*
static void
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
rtl8125_link_timer(unsigned long __opaque)
#else
rtl8125_link_timer(struct timer_list *t)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        struct net_device *dev = (struct net_device *)__opaque;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->link_timer;
#else
        struct rtl8125_private *tp = from_timer(tp, t, link_timer);
        struct net_device *dev = tp->dev;
        struct timer_list *timer = t;
#endif
        rtl8125_check_link_status(dev);

        mod_timer(timer, jiffies + RTL8125_LINK_TIMEOUT);
}
*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static int pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
                                 int minvec, int maxvec)
{
        int nvec = maxvec;
        int rc;

        if (maxvec < minvec)
                return -ERANGE;

        do {
                rc = pci_enable_msix(dev, entries, nvec);
                if (rc < 0) {
                        return rc;
                } else if (rc > 0) {
                        if (rc < minvec)
                                return -ENOSPC;
                        nvec = rc;
                }
        } while (rc);

        return nvec;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0) */

static int rtl8125_enable_msix(struct rtl8125_private *tp)
{
        int i, nvecs = 0;
        struct msix_entry msix_ent[R8125_MAX_MSIX_VEC];
        //struct net_device *dev = tp->dev;
        //const int len = sizeof(tp->irq_tbl[0].name);

        for (i = 0; i < R8125_MAX_MSIX_VEC; i++) {
                msix_ent[i].entry = i;
                msix_ent[i].vector = 0;
        }

        nvecs = pci_enable_msix_range(tp->pci_dev, msix_ent,
                                      tp->min_irq_nvecs, tp->max_irq_nvecs);
        if (nvecs < 0)
                goto out;

        for (i = 0; i < nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                irq->vector = msix_ent[i].vector;
                //snprintf(irq->name, len, "%s-%d", dev->name, i);
                //irq->handler = rtl8125_interrupt_msix;
        }

out:
        return nvecs;
}

/* Cfg9346_Unlock assumed. */
static int rtl8125_try_msi(struct rtl8125_private *tp)
{
        struct pci_dev *pdev = tp->pci_dev;
        unsigned int hw_supp_irq_nvecs;
        unsigned msi = 0;
        int nvecs = 1;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                hw_supp_irq_nvecs = R8125_MAX_MSIX_VEC_8125A;
                break;
        case CFG_METHOD_4 ... CFG_METHOD_7:
                hw_supp_irq_nvecs = R8125_MAX_MSIX_VEC_8125B;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                hw_supp_irq_nvecs = R8125_MAX_MSIX_VEC_8125D;
                break;
        default:
                hw_supp_irq_nvecs = 1;
                break;
        }
        tp->hw_supp_irq_nvecs = clamp_val(hw_supp_irq_nvecs, 1,
                                          R8125_MAX_MSIX_VEC);

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
                tp->max_irq_nvecs = tp->hw_supp_irq_nvecs;
                tp->min_irq_nvecs = R8125_MIN_MSIX_VEC_8125B;
                break;
        case CFG_METHOD_8:
        case CFG_METHOD_9:
                tp->max_irq_nvecs = tp->hw_supp_irq_nvecs;
                tp->min_irq_nvecs = R8125_MIN_MSIX_VEC_8125BP;
                break;
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_13:
                tp->max_irq_nvecs = tp->hw_supp_irq_nvecs;
                tp->min_irq_nvecs = R8125_MIN_MSIX_VEC_8125D;
                break;
        case CFG_METHOD_12:
                tp->max_irq_nvecs = tp->hw_supp_irq_nvecs;
                tp->min_irq_nvecs = R8125_MIN_MSIX_VEC_8125CP;
                break;
        default:
                tp->max_irq_nvecs = 1;
                tp->min_irq_nvecs = 1;
                break;
        }
#ifdef DISABLE_MULTI_MSIX_VECTOR
        tp->max_irq_nvecs = 1;
#endif

#if defined(RTL_USE_NEW_INTR_API)
        if ((nvecs = pci_alloc_irq_vectors(pdev, tp->min_irq_nvecs, tp->max_irq_nvecs, PCI_IRQ_MSIX)) > 0)
                msi |= RTL_FEATURE_MSIX;
        else if ((nvecs = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES)) > 0 &&
                 pci_dev_msi_enabled(pdev))
                msi |= RTL_FEATURE_MSI;
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        if ((nvecs = rtl8125_enable_msix(tp)) > 0)
                msi |= RTL_FEATURE_MSIX;
        else if (!pci_enable_msi(pdev))
                msi |= RTL_FEATURE_MSI;
#endif
        if (!(msi & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX)))
                dev_info(&pdev->dev, "no MSI/MSI-X. Back to INTx.\n");

        if (!(msi & RTL_FEATURE_MSIX) || nvecs < 1)
                nvecs = 1;

        tp->irq_nvecs = nvecs;

        tp->features |= msi;

        return nvecs;
}

static void rtl8125_disable_msi(struct pci_dev *pdev, struct rtl8125_private *tp)
{
#if defined(RTL_USE_NEW_INTR_API)
        if (tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX))
                pci_free_irq_vectors(pdev);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        if (tp->features & (RTL_FEATURE_MSIX))
                pci_disable_msix(pdev);
        else if (tp->features & (RTL_FEATURE_MSI))
                pci_disable_msi(pdev);
#endif
        tp->features &= ~(RTL_FEATURE_MSI | RTL_FEATURE_MSIX);
}

static int rtl8125_get_irq(struct pci_dev *pdev)
{
#if defined(RTL_USE_NEW_INTR_API)
        return pci_irq_vector(pdev, 0);
#else
        return pdev->irq;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void
rtl8125_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters = tp->tally_vaddr;
        dma_addr_t paddr = tp->tally_paddr;

        if (!counters)
                return;

        netdev_stats_to_stats64(stats, &dev->stats);
        dev_fetch_sw_netstats(stats, dev->tstats);

        /*
         * Fetch additional counter values missing in stats collected by driver
         * from tally counters.
         */
        rtl8125_dump_tally_counter(tp, paddr);

        stats->tx_errors = le64_to_cpu(counters->tx_errors);
        stats->collisions = le32_to_cpu(counters->tx_multi_collision);
        stats->tx_aborted_errors = le16_to_cpu(counters->tx_aborted);
        stats->rx_missed_errors = le16_to_cpu(counters->rx_missed);
}
#else
/**
 *  rtl8125_get_stats - Get rtl8125 read/write statistics
 *  @dev: The Ethernet Device to get statistics for
 *
 *  Get TX/RX statistics for rtl8125
 */
static struct
net_device_stats *rtl8125_get_stats(struct net_device *dev)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
        struct rtl8125_private *tp = netdev_priv(dev);
#endif
        return &RTLDEV->stats;
}
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static const struct net_device_ops rtl8125_netdev_ops = {
        .ndo_open       = rtl8125_open,
        .ndo_stop       = rtl8125_close,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
        .ndo_get_stats64    = rtl8125_get_stats64,
#else
        .ndo_get_stats      = rtl8125_get_stats,
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
        .ndo_start_xmit     = rtl8125_start_xmit,
        .ndo_tx_timeout     = rtl8125_tx_timeout,
        .ndo_change_mtu     = rtl8125_change_mtu,
        .ndo_set_mac_address    = rtl8125_set_mac_address,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
        .ndo_do_ioctl       = rtl8125_do_ioctl,
#else
        .ndo_siocdevprivate = rtl8125_siocdevprivate,
        .ndo_eth_ioctl      = rtl8125_do_ioctl,
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
        .ndo_set_multicast_list = rtl8125_set_rx_mode,
#else
        .ndo_set_rx_mode    = rtl8125_set_rx_mode,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#ifdef CONFIG_R8125_VLAN
        .ndo_vlan_rx_register   = rtl8125_vlan_rx_register,
#endif
#else
        .ndo_fix_features   = rtl8125_fix_features,
        .ndo_set_features   = rtl8125_set_features,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
        .ndo_poll_controller    = rtl8125_netpoll,
#endif
};
#endif


#ifdef  CONFIG_R8125_NAPI

static int rtl8125_poll(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        int i;

        for (i = 0; i < tp->num_tx_rings; i++)
                rtl8125_tx_interrupt(&tp->tx_ring[i], budget);

        for (i = 0; i < tp->num_rx_rings; i++)
                work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[i], budget);

        work_done = min(work_done, work_to_do);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#ifdef ENABLE_DASH_SUPPORT
                if (rtl8125_check_dash_interrupt(tp))
                        rtl8125_schedule_dash_work(tp);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE)
                        return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_switch_to_timer_interrupt(tp);
        }

        return RTL_NAPI_RETURN_VALUE;
}

static int rtl8125_poll_msix_ring(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        const int message_id = r8125napi->index;

        if (message_id < tp->num_tx_rings)
                rtl8125_tx_interrupt_with_vector(tp, message_id, budget);

        if (message_id < tp->num_rx_rings)
                work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#ifdef ENABLE_DASH_SUPPORT
                if (message_id == 31)
                        if (rtl8125_check_dash_interrupt(tp))
                                rtl8125_schedule_dash_work(tp);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE)
                        return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}

static int rtl8125_poll_msix_tx(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        const int message_id = r8125napi->index;

        //suppress unused variable
        (void)(dev);

        rtl8125_tx_interrupt_with_vector(tp, message_id, budget);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE)
                        return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}

static int rtl8125_poll_msix_other(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        const int message_id = r8125napi->index;

        //suppress unused variable
        (void)(dev);
        (void)(work_to_do);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
        RTL_NETIF_RX_COMPLETE(dev, napi, work_to_do);
#else
        RTL_NETIF_RX_COMPLETE(dev, napi, work_to_do);
#endif

        rtl8125_enable_hw_interrupt_v2(tp, message_id);

        return 1;
}

static int rtl8125_poll_msix_rx(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        const int message_id = r8125napi->index;

        if (message_id < tp->num_rx_rings)
                work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE)
                        return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}

void rtl8125_enable_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_ENABLE(tp->dev, &tp->r8125napi[i].napi);
#endif
}

static void rtl8125_disable_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_DISABLE(tp->dev, &tp->r8125napi[i].napi);
#endif
}

static void rtl8125_del_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_DEL((&tp->r8125napi[i]));
#endif
}
#endif //CONFIG_R8125_NAPI

static void rtl8125_init_napi(struct rtl8125_private *tp)
{
        int i;

        for (i=0; i<tp->irq_nvecs; i++) {
                struct r8125_napi *r8125napi = &tp->r8125napi[i];
#ifdef CONFIG_R8125_NAPI
                int (*poll)(struct napi_struct *, int);

                poll = rtl8125_poll;
                if (tp->features & RTL_FEATURE_MSIX) {
                        switch (tp->HwCurrIsrVer) {
                        case 7:
                                if (i < R8125_MAX_RX_QUEUES_VEC_V3)
                                        poll = rtl8125_poll_msix_rx;
                                else if (i == 27 || i == 28)
                                        poll = rtl8125_poll_msix_tx;
                                else
                                        poll = rtl8125_poll_msix_other;
                                break;
                        case 5:
                                if (i < R8125_MAX_RX_QUEUES_VEC_V3)
                                        poll = rtl8125_poll_msix_rx;
                                else if (i == 16 || i == 17)
                                        poll = rtl8125_poll_msix_tx;
                                else
                                        poll = rtl8125_poll_msix_other;
                                break;
                        case 2:
                                if (i < R8125_MAX_RX_QUEUES_VEC_V3)
                                        poll = rtl8125_poll_msix_rx;
                                else if (i == 16 || i == 18)
                                        poll = rtl8125_poll_msix_tx;
                                else
                                        poll = rtl8125_poll_msix_other;
                                break;
                        case 3:
                        case 4:
                                if (i < R8125_MAX_RX_QUEUES_VEC_V3)
                                        poll = rtl8125_poll_msix_ring;
                                else
                                        poll = rtl8125_poll_msix_other;
                                break;
                        }
                }

                RTL_NAPI_CONFIG(tp->dev, r8125napi, poll, R8125_NAPI_WEIGHT);
#endif

                r8125napi->priv = tp;
                r8125napi->index = i;
        }
}

static int
rtl8125_set_real_num_queue(struct rtl8125_private *tp)
{
        int retval = 0;

        retval = netif_set_real_num_tx_queues(tp->dev, tp->num_tx_rings);
        if (retval < 0)
                goto exit;

        retval = netif_set_real_num_rx_queues(tp->dev, tp->num_rx_rings);
        if (retval < 0)
                goto exit;

exit:
        return retval;
}

static int __devinit
rtl8125_init_one(struct pci_dev *pdev,
                 const struct pci_device_id *ent)
{
        struct net_device *dev = NULL;
        struct rtl8125_private *tp;
        void __iomem *ioaddr = NULL;
        static int board_idx = -1;

        int rc;

        assert(pdev != NULL);
        assert(ent != NULL);

        board_idx++;

        if (netif_msg_drv(&debug))
                printk(KERN_INFO "%s Ethernet controller driver %s loaded\n",
                       MODULENAME, RTL8125_VERSION);

        rc = rtl8125_init_board(pdev, &dev, &ioaddr);
        if (rc)
                goto out;

        tp = netdev_priv(dev);
        assert(ioaddr != NULL);

        spin_lock_init(&tp->phy_lock);

        tp->set_speed = rtl8125_set_speed_xmii;
        tp->get_settings = rtl8125_gset_xmii;
        tp->phy_reset_enable = rtl8125_xmii_reset_enable;
        tp->phy_reset_pending = rtl8125_xmii_reset_pending;
        tp->link_ok = rtl8125_xmii_link_ok;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
        dev->tstats = devm_netdev_alloc_pcpu_stats(&pdev->dev,
                        struct pcpu_sw_netstats);
        if (!dev->tstats)
                goto err_out_1;
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)

        rc = rtl8125_try_msi(tp);
        if (rc < 0) {
                dev_err(&pdev->dev, "Can't allocate interrupt\n");
                goto err_out_1;
        }

        rtl8125_init_software_variable(dev);

        RTL_NET_DEVICE_OPS(rtl8125_netdev_ops);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
        SET_ETHTOOL_OPS(dev, &rtl8125_ethtool_ops);
#endif

        dev->watchdog_timeo = RTL8125_TX_TIMEOUT;
        dev->irq = rtl8125_get_irq(pdev);
        dev->base_addr = (unsigned long) ioaddr;

        rtl8125_init_napi(tp);

#ifdef CONFIG_R8125_VLAN
        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                dev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
                dev->vlan_rx_kill_vid = rtl8125_vlan_rx_kill_vid;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
        }
#endif

        /* There has been a number of reports that using SG/TSO results in
         * tx timeouts. However for a lot of people SG/TSO works fine.
         * Therefore disable both features by default, but allow users to
         * enable them. Use at own risk!
         */
        tp->cp_cmd |= RTL_R16(tp, CPlusCmd);
        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                dev->features |= NETIF_F_IP_CSUM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
                tp->cp_cmd |= RxChkSum;
#else
                dev->features |= NETIF_F_RXCSUM;
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                case CFG_METHOD_6:
                        /* nothing to do */
                        break;
                default:
                        dev->features |= NETIF_F_SG | NETIF_F_TSO;
                        break;
                };
                dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO |
                                   NETIF_F_RXCSUM | NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
                dev->vlan_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO |
                                     NETIF_F_HIGHDMA;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
                dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
                dev->hw_features |= NETIF_F_RXALL;
                dev->hw_features |= NETIF_F_RXFCS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
                dev->hw_features |= NETIF_F_IPV6_CSUM | NETIF_F_TSO6;
                dev->features |= NETIF_F_IPV6_CSUM;
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                case CFG_METHOD_6:
                        /* nothing to do */
                        break;
                default:
                        dev->features |= NETIF_F_TSO6;
                        break;
                };
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
                netif_set_tso_max_size(dev, LSO_64K);
                netif_set_tso_max_segs(dev, NIC_MAX_PHYS_BUF_COUNT_LSO2);
#else //LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
                netif_set_gso_max_size(dev, LSO_64K);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
                dev->gso_max_segs = NIC_MAX_PHYS_BUF_COUNT_LSO2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
                dev->gso_min_segs = NIC_MIN_PHYS_BUF_COUNT;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)

#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

#ifdef ENABLE_RSS_SUPPORT
                if (tp->EnableRss) {
                        dev->hw_features |= NETIF_F_RXHASH;
                        dev->features |= NETIF_F_RXHASH;
                }
#endif
        }

        netdev_sw_irq_coalesce_default_on(dev);

#ifdef ENABLE_LIB_SUPPORT
        BLOCKING_INIT_NOTIFIER_HEAD(&tp->lib_nh);
#endif
        rtl8125_init_all_schedule_work(tp);

        rc = rtl8125_set_real_num_queue(tp);
        if (rc < 0)
                goto err_out;

        rtl8125_exit_oob(dev);

        rtl8125_powerup_pll(dev);

        rtl8125_hw_init(dev);

        rtl8125_hw_reset(dev);

        /* Get production from EEPROM */
        rtl8125_eeprom_type(tp);

        if (tp->eeprom_type == EEPROM_TYPE_93C46 || tp->eeprom_type == EEPROM_TYPE_93C56)
                rtl8125_set_eeprom_sel_low(tp);

        rtl8125_get_mac_address(dev);

        tp->fw_name = rtl_chip_fw_infos[tp->mcfg].fw_name;

        tp->tally_vaddr = dma_alloc_coherent(&pdev->dev, sizeof(*tp->tally_vaddr),
                                             &tp->tally_paddr, GFP_KERNEL);
        if (!tp->tally_vaddr) {
                rc = -ENOMEM;
                goto err_out;
        }

        rtl8125_tally_counter_clear(tp);

        pci_set_drvdata(pdev, dev);

        rc = register_netdev(dev);
        if (rc)
                goto err_out;

        printk(KERN_INFO "%s: This product is covered by one or more of the following patents: US6,570,884, US6,115,776, and US6,327,625.\n", MODULENAME);

        rtl8125_disable_rxdvgate(dev);

        device_set_wakeup_enable(&pdev->dev, tp->wol_enabled);

        netif_carrier_off(dev);

#ifdef ENABLE_R8125_SYSFS
        rtl8125_sysfs_init(dev);
#endif /* ENABLE_R8125_SYSFS */

        printk("%s", GPL_CLAIM);

out:
        return rc;

err_out:
        if (tp->tally_vaddr != NULL) {
                dma_free_coherent(&pdev->dev, sizeof(*tp->tally_vaddr), tp->tally_vaddr,
                                  tp->tally_paddr);

                tp->tally_vaddr = NULL;
        }
#ifdef  CONFIG_R8125_NAPI
        rtl8125_del_napi(tp);
#endif
        rtl8125_disable_msi(pdev, tp);

err_out_1:
        rtl8125_release_board(pdev, dev);

        goto out;
}

static void __devexit
rtl8125_remove_one(struct pci_dev *pdev)
{
        struct net_device *dev = pci_get_drvdata(pdev);
        struct rtl8125_private *tp = netdev_priv(dev);

        assert(dev != NULL);
        assert(tp != NULL);

        set_bit(R8125_FLAG_DOWN, tp->task_flags);

        rtl8125_cancel_all_schedule_work(tp);

        if (HW_DASH_SUPPORT_DASH(tp))
                rtl8125_driver_stop(tp);

        rtl8125_disable_pci_offset_180(tp);

#ifdef ENABLE_R8125_SYSFS
        rtl8125_sysfs_remove(dev);
#endif //ENABLE_R8125_SYSFS

        unregister_netdev(dev);
#ifdef  CONFIG_R8125_NAPI
        rtl8125_del_napi(tp);
#endif
        rtl8125_disable_msi(pdev, tp);
#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_remove(dev);
#endif
        if (tp->tally_vaddr != NULL) {
                dma_free_coherent(&pdev->dev, sizeof(*tp->tally_vaddr), tp->tally_vaddr, tp->tally_paddr);
                tp->tally_vaddr = NULL;
        }

        rtl8125_release_board(pdev, dev);

#ifdef ENABLE_USE_FIRMWARE_FILE
        rtl8125_release_firmware(tp);
#endif

        pci_set_drvdata(pdev, NULL);
}

#ifdef ENABLE_PAGE_REUSE
static inline unsigned int rtl8125_rx_page_order(unsigned rx_buf_sz, unsigned page_size)
{
        unsigned truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
                            SKB_DATA_ALIGN(rx_buf_sz + R8125_RX_ALIGN);

        return get_order(truesize * 2);
}
#endif //ENABLE_PAGE_REUSE

static void
rtl8125_set_rxbufsize(struct rtl8125_private *tp,
                      struct net_device *dev)
{
        unsigned int mtu = dev->mtu;

        tp->rms = (mtu > ETH_DATA_LEN) ?
                  mtu + ETH_HLEN + RT_VALN_HLEN + ETH_FCS_LEN:
                  RX_BUF_SIZE;
        tp->rx_buf_sz = tp->rms;
#ifdef ENABLE_RX_PACKET_FRAGMENT
        tp->rx_buf_sz =  SKB_DATA_ALIGN(RX_BUF_SIZE);
#endif //ENABLE_RX_PACKET_FRAGMENT
#ifdef ENABLE_PAGE_REUSE
        tp->rx_buf_page_order = rtl8125_rx_page_order(tp->rx_buf_sz, PAGE_SIZE);
        tp->rx_buf_page_size = rtl8125_rx_page_size(tp->rx_buf_page_order);
#endif //ENABLE_PAGE_REUSE
}

static void
rtl8125_set_rms(struct rtl8125_private *tp, u16 rms)
{
        switch (tp->mcfg) {
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                rms |= AcceppVlanPhys;
                break;
        default:
                rms &= ~AcceppVlanPhys;
                break;
        }
        RTL_W16(tp, RxMaxSize, rms);
}

static void rtl8125_free_irq(struct rtl8125_private *tp)
{
        int i;

        for (i=0; i<tp->irq_nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                struct r8125_napi *r8125napi = &tp->r8125napi[i];

                if (irq->requested) {
                        irq->requested = 0;
#if defined(RTL_USE_NEW_INTR_API)
                        pci_free_irq(tp->pci_dev, i, r8125napi);
#else
                        free_irq(irq->vector, r8125napi);
#endif
                }
        }
}

static int rtl8125_alloc_irq(struct rtl8125_private *tp)
{
        struct net_device *dev = tp->dev;
        int rc = 0;
        struct r8125_irq *irq;
        struct r8125_napi *r8125napi;
        int i = 0;
        const int len = sizeof(tp->irq_tbl[0].name);

#if defined(RTL_USE_NEW_INTR_API)
        for (i=0; i<tp->irq_nvecs; i++) {
                irq = &tp->irq_tbl[i];
                if (tp->features & RTL_FEATURE_MSIX &&
                    tp->HwCurrIsrVer > 1)
                        irq->handler = rtl8125_interrupt_msix;
                else
                        irq->handler = rtl8125_interrupt;

                r8125napi = &tp->r8125napi[i];
                snprintf(irq->name, len, "%s-%d", dev->name, i);
                rc = pci_request_irq(tp->pci_dev, i, irq->handler, NULL, r8125napi,
                                     irq->name);
                if (rc)
                        break;

                irq->vector = pci_irq_vector(tp->pci_dev, i);
                irq->requested = 1;
        }
#else
        unsigned long irq_flags = 0;
#ifdef ENABLE_LIB_SUPPORT
        irq_flags |= IRQF_NO_SUSPEND;
#endif
        if (tp->features & RTL_FEATURE_MSIX &&
            tp->HwCurrIsrVer > 1) {
                for (i=0; i<tp->irq_nvecs; i++) {
                        irq = &tp->irq_tbl[i];
                        irq->handler = rtl8125_interrupt_msix;
                        r8125napi = &tp->r8125napi[i];
                        snprintf(irq->name, len, "%s-%d", dev->name, i);
                        rc = request_irq(irq->vector, irq->handler, irq_flags, irq->name, r8125napi);

                        if (rc)
                                break;

                        irq->requested = 1;
                }
        } else {
                irq = &tp->irq_tbl[0];
                irq->handler = rtl8125_interrupt;
                r8125napi = &tp->r8125napi[0];
                snprintf(irq->name, len, "%s-0", dev->name);
                if (!(tp->features & RTL_FEATURE_MSIX))
                        irq->vector = dev->irq;
                irq_flags |= (tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX)) ? 0 : SA_SHIRQ;
                rc = request_irq(irq->vector, irq->handler, irq_flags, irq->name, r8125napi);

                if (rc == 0)
                        irq->requested = 1;
        }
#endif
        if (rc)
                rtl8125_free_irq(tp);

        return rc;
}

static int rtl8125_alloc_tx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_tx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                ring = &tp->tx_ring[i];
                ring->TxDescAllocSize = (ring->num_tx_desc + 1) * sizeof(struct TxDesc);
                ring->TxDescArray = dma_alloc_coherent(&pdev->dev,
                                                       ring->TxDescAllocSize,
                                                       &ring->TxPhyAddr,
                                                       GFP_KERNEL);

                if (!ring->TxDescArray)
                        return -1;
        }

        return 0;
}

static int rtl8125_alloc_rx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_rx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                ring = &tp->rx_ring[i];
                ring->RxDescAllocSize = (ring->num_rx_desc + 1) * tp->RxDescLength;
                ring->RxDescArray = dma_alloc_coherent(&pdev->dev,
                                                       ring->RxDescAllocSize,
                                                       &ring->RxPhyAddr,
                                                       GFP_KERNEL);

                if (!ring->RxDescArray)
                        return -1;
        }

        return 0;
}

static void rtl8125_free_tx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_tx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                ring = &tp->tx_ring[i];
                if (ring->TxDescArray) {
                        dma_free_coherent(&pdev->dev,
                                          ring->TxDescAllocSize,
                                          ring->TxDescArray,
                                          ring->TxPhyAddr);
                        ring->TxDescArray = NULL;
                }
        }
}

static void rtl8125_free_rx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_rx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                ring = &tp->rx_ring[i];
                if (ring->RxDescArray) {
                        dma_free_coherent(&pdev->dev,
                                          ring->RxDescAllocSize,
                                          ring->RxDescArray,
                                          ring->RxPhyAddr);
                        ring->RxDescArray = NULL;
                }
        }
}

static void rtl8125_free_alloc_resources(struct rtl8125_private *tp)
{
        rtl8125_free_rx_desc(tp);

        rtl8125_free_tx_desc(tp);
}

#ifdef ENABLE_USE_FIRMWARE_FILE
static void rtl8125_request_firmware(struct rtl8125_private *tp)
{
        struct rtl8125_fw *rtl_fw;

        /* firmware loaded already or no firmware available */
        if (tp->rtl_fw || !tp->fw_name)
                return;

        rtl_fw = kzalloc(sizeof(*rtl_fw), GFP_KERNEL);
        if (!rtl_fw)
                return;

        rtl_fw->phy_write = rtl8125_mdio_write;
        rtl_fw->phy_read = rtl8125_mdio_read;
        rtl_fw->mac_mcu_write = mac_mcu_write;
        rtl_fw->mac_mcu_read = mac_mcu_read;
        rtl_fw->fw_name = tp->fw_name;
        rtl_fw->dev = tp_to_dev(tp);

        if (rtl8125_fw_request_firmware(rtl_fw))
                kfree(rtl_fw);
        else
                tp->rtl_fw = rtl_fw;
}
#endif

int rtl8125_open(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int retval;

        retval = -ENOMEM;

#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_init(dev);
#endif
        rtl8125_set_rxbufsize(tp, dev);
        /*
         * Rx and Tx descriptors needs 256 bytes alignment.
         * pci_alloc_consistent provides more.
         */
        if (rtl8125_alloc_tx_desc(tp) < 0 || rtl8125_alloc_rx_desc(tp) < 0)
                goto err_free_all_allocated_mem;

        retval = rtl8125_init_ring(dev);
        if (retval < 0)
                goto err_free_all_allocated_mem;

        retval = rtl8125_alloc_irq(tp);
        if (retval < 0)
                goto err_free_all_allocated_mem;

        if (netif_msg_probe(tp)) {
                printk(KERN_INFO "%s: 0x%lx, "
                       "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x, "
                       "IRQ %d\n",
                       dev->name,
                       dev->base_addr,
                       dev->dev_addr[0], dev->dev_addr[1],
                       dev->dev_addr[2], dev->dev_addr[3],
                       dev->dev_addr[4], dev->dev_addr[5], dev->irq);
        }

#ifdef ENABLE_USE_FIRMWARE_FILE
        rtl8125_request_firmware(tp);
#endif
        pci_set_master(tp->pci_dev);

#ifdef  CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif

        rtl8125_exit_oob(dev);

        rtl8125_up(dev);

#ifdef ENABLE_PTP_SUPPORT
        if (tp->EnablePtp)
                rtl8125_ptp_init(tp);
#endif
        clear_bit(R8125_FLAG_DOWN, tp->task_flags);

        if (tp->resume_not_chg_speed)
                _rtl8125_check_link_status(dev, R8125_LINK_STATE_UNKNOWN);
        else
                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);

        if (tp->esd_flag == 0) {
                //rtl8125_request_esd_timer(dev);

                rtl8125_schedule_esd_work(tp);
        }

        //rtl8125_request_link_timer(dev);
#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp))
                rtl8125_schedule_link_work(tp);
#endif /* ENABLE_FIBER_SUPPORT */

        rtl8125_enable_hw_linkchg_interrupt(tp);
out:

        return retval;

err_free_all_allocated_mem:
        rtl8125_free_alloc_resources(tp);

        goto out;
}

static void
_rtl8125_set_l1_l0s_entry_latency(struct rtl8125_private *tp, u8 setting)
{
        u32 csi_tmp;
        u32 temp;

        temp = setting & 0x3f;
        temp <<= 24;
        /*set PCI configuration space offset 0x70F to setting*/
        /*When the register offset of PCI configuration space larger than 0xff, use CSI to access it.*/

        csi_tmp = rtl8125_csi_read(tp, 0x70c) & 0xc0ffffff;
        rtl8125_csi_write(tp, 0x70c, csi_tmp | temp);
}

static void
rtl8125_set_l1_l0s_entry_latency(struct rtl8125_private *tp)
{
        _rtl8125_set_l1_l0s_entry_latency(tp, 0x27);
}

static void
_rtl8125_set_mrrs(struct rtl8125_private *tp, u8 setting)
{
        struct pci_dev *pdev = tp->pci_dev;
        u8 device_control;

        pci_read_config_byte(pdev, 0x79, &device_control);
        device_control &= ~0x70;
        device_control |= setting;
        pci_write_config_byte(pdev, 0x79, device_control);
}

static void
rtl8125_set_mrrs(struct rtl8125_private *tp)
{
        if (hwoptimize & HW_PATCH_SOC_LAN)
                return;

        _rtl8125_set_mrrs(tp, 0x40);
}

void
rtl8125_hw_set_rx_packet_filter(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 mc_filter[2];   /* Multicast hash filter */
        int rx_mode;
        u32 tmp = 0;

        if (dev->flags & IFF_PROMISC) {
                /* Unconditionally log net taps. */
                if (netif_msg_link(tp))
                        printk(KERN_NOTICE "%s: Promiscuous mode enabled.\n",
                               dev->name);

                rx_mode =
                        AcceptBroadcast | AcceptMulticast | AcceptMyPhys |
                        AcceptAllPhys;
                mc_filter[1] = mc_filter[0] = 0xffffffff;
        } else if (dev->flags & IFF_ALLMULTI) {
                /* accept all multicasts. */
                rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0xffffffff;
        } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
                struct dev_mc_list *mclist;
                unsigned int i;

                rx_mode = AcceptBroadcast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0;
                for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
                     i++, mclist = mclist->next) {
                        int bit_nr = ether_crc(ETH_ALEN, mclist->dmi_addr) >> 26;
                        mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
                        rx_mode |= AcceptMulticast;
                }
#else
                struct netdev_hw_addr *ha;

                rx_mode = AcceptBroadcast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0;
                netdev_for_each_mc_addr(ha, dev) {
                        int bit_nr = ether_crc(ETH_ALEN, ha->addr) >> 26;
                        mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
                        rx_mode |= AcceptMulticast;
                }
#endif
        }

        if (dev->features & NETIF_F_RXALL)
                rx_mode |= (AcceptErr | AcceptRunt);

        tmp = mc_filter[0];
        mc_filter[0] = swab32(mc_filter[1]);
        mc_filter[1] = swab32(tmp);

        tmp = tp->rtl8125_rx_config | rx_mode | (RTL_R32(tp, RxConfig) & rtl_chip_info[tp->chipset].RxConfigMask);

        RTL_W32(tp, RxConfig, tmp);
        RTL_W32(tp, MAR0 + 0, mc_filter[0]);
        RTL_W32(tp, MAR0 + 4, mc_filter[1]);
}

static void
rtl8125_set_rx_mode(struct net_device *dev)
{
        rtl8125_hw_set_rx_packet_filter(dev);
}

void
rtl8125_set_rx_q_num(struct rtl8125_private *tp,
                     unsigned int num_rx_queues)
{
        u16 q_ctrl;
        u16 rx_q_num;

        rx_q_num = (u16)ilog2(num_rx_queues);
        rx_q_num &= (BIT_0 | BIT_1 | BIT_2);
        rx_q_num <<= 2;
        q_ctrl = RTL_R16(tp, Q_NUM_CTRL_8125);
        q_ctrl &= ~(BIT_2 | BIT_3 | BIT_4);
        q_ctrl |= rx_q_num;
        RTL_W16(tp, Q_NUM_CTRL_8125, q_ctrl);
}

void
rtl8125_set_tx_q_num(struct rtl8125_private *tp,
                     unsigned int num_tx_queues)
{
        u16 mac_ocp_data;

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE63E);
        mac_ocp_data &= ~(BIT_11 | BIT_10);
        mac_ocp_data |= ((ilog2(num_tx_queues) & 0x03) << 10);
        rtl8125_mac_ocp_write(tp, 0xE63E, mac_ocp_data);
}

void
rtl8125_enable_mcu(struct rtl8125_private *tp, bool enable)
{
        if (FALSE == HW_SUPPORT_MAC_MCU(tp))
                return;

        if (enable)
                rtl8125_set_mac_ocp_bit(tp, 0xC0B4, BIT_0);
        else
                rtl8125_clear_mac_ocp_bit(tp, 0xC0B4, BIT_0);
}

static void
rtl8125_clear_tcam_entries(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_TCAM(tp))
                return;

        rtl8125_set_mac_ocp_bit(tp, 0xEB54, BIT_0);
        udelay(1);
        rtl8125_clear_mac_ocp_bit(tp, 0xEB54, BIT_0);
}

static void
rtl8125_enable_tcam(struct rtl8125_private *tp)
{
        if (tp->HwSuppTcamVer != 1)
                return;

        RTL_W16(tp, 0x382, 0x221B);
}

static u8
rtl8125_get_l1off_cap_bits(struct rtl8125_private *tp)
{
        u8 l1offCapBits = 0;

        l1offCapBits = (BIT_0 | BIT_1);
        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
                l1offCapBits |= (BIT_2 | BIT_3);
                break;
        default:
                break;
        }

        return l1offCapBits;
}

void
rtl8125_hw_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct pci_dev *pdev = tp->pci_dev;
        u16 mac_ocp_data;

        rtl8125_disable_rx_packet_filter(tp);

        rtl8125_hw_reset(dev);

        rtl8125_enable_cfg9346_write(tp);

        rtl8125_enable_force_clkreq(tp, 0);
        rtl8125_enable_aspm_clkreq_lock(tp, 0);

        rtl8125_set_eee_lpi_timer(tp);

        //keep magic packet only
        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xC0B6);
        mac_ocp_data &= BIT_0;
        rtl8125_mac_ocp_write(tp, 0xC0B6, mac_ocp_data);

        rtl8125_tally_counter_addr_fill(tp);

        rtl8125_enable_extend_tally_couter(tp);

        rtl8125_desc_addr_fill(tp);

        /* Set DMA burst size and Interframe Gap Time */
        RTL_W32(tp, TxConfig, (TX_DMA_BURST_unlimited << TxDMAShift) |
                (InterFrameGap << TxInterFrameGapShift));

        if (tp->EnableTxNoClose)
                RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | BIT_6));

        if (enable_double_vlan)
                rtl8125_enable_double_vlan(tp);
        else
                rtl8125_disable_double_vlan(tp);

        switch (tp->mcfg) {
        case CFG_METHOD_2 ... CFG_METHOD_7:
                rtl8125_enable_tcam(tp);
                break;
        }

        rtl8125_set_l1_l0s_entry_latency(tp);

        rtl8125_set_mrrs(tp);

#ifdef ENABLE_RSS_SUPPORT
        rtl8125_config_rss(tp);
#else
        RTL_W32(tp, RSS_CTRL_8125, 0x00);
#endif
        rtl8125_set_rx_q_num(tp, rtl8125_tot_rx_rings(tp));

        RTL_W8(tp, Config1, RTL_R8(tp, Config1) & ~0x10);

        rtl8125_mac_ocp_write(tp, 0xC140, 0xFFFF);
        rtl8125_mac_ocp_write(tp, 0xC142, 0xFFFF);

        //new tx desc format
        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB58);
        mac_ocp_data |= (BIT_0);
        rtl8125_mac_ocp_write(tp, 0xEB58, mac_ocp_data);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE614);
        mac_ocp_data &= ~(BIT_10 | BIT_9 | BIT_8);
        if (tp->mcfg == CFG_METHOD_4 || tp->mcfg == CFG_METHOD_5 ||
            tp->mcfg == CFG_METHOD_7)
                mac_ocp_data |= ((2 & 0x07) << 8);
        else
                mac_ocp_data |= ((3 & 0x07) << 8);
        rtl8125_mac_ocp_write(tp, 0xE614, mac_ocp_data);

        rtl8125_set_tx_q_num(tp, rtl8125_tot_tx_rings(tp));

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE63E);
        mac_ocp_data &= ~(BIT_5 | BIT_4);
        mac_ocp_data |= (0x02 << 4);
        rtl8125_mac_ocp_write(tp, 0xE63E, mac_ocp_data);

        rtl8125_enable_mcu(tp, 0);
        rtl8125_enable_mcu(tp, 1);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xC0B4);
        mac_ocp_data |= (BIT_3 | BIT_2);
        rtl8125_mac_ocp_write(tp, 0xC0B4, mac_ocp_data);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB6A);
        mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
        mac_ocp_data |= (BIT_5 | BIT_4 | BIT_1 | BIT_0);
        rtl8125_mac_ocp_write(tp, 0xEB6A, mac_ocp_data);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB50);
        mac_ocp_data &= ~(BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5);
        mac_ocp_data |= (BIT_6);
        rtl8125_mac_ocp_write(tp, 0xEB50, mac_ocp_data);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE056);
        mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
        //mac_ocp_data |= (BIT_4 | BIT_5);
        rtl8125_mac_ocp_write(tp, 0xE056, mac_ocp_data);

        RTL_W8(tp, TDFNR, 0x10);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE040);
        mac_ocp_data &= ~(BIT_12);
        rtl8125_mac_ocp_write(tp, 0xE040, mac_ocp_data);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEA1C);
        mac_ocp_data &= ~(BIT_1 | BIT_0);
        mac_ocp_data |= (BIT_0);
        rtl8125_mac_ocp_write(tp, 0xEA1C, mac_ocp_data);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_12:
                rtl8125_oob_mutex_lock(tp);
                break;
        }

        if (tp->mcfg == CFG_METHOD_10 || tp->mcfg == CFG_METHOD_11 ||
            tp->mcfg == CFG_METHOD_13)
                rtl8125_mac_ocp_write(tp, 0xE0C0, 0x4403);
        else
                rtl8125_mac_ocp_write(tp, 0xE0C0, 0x4000);

        rtl8125_set_mac_ocp_bit(tp, 0xE052, (BIT_6 | BIT_5));
        rtl8125_clear_mac_ocp_bit(tp, 0xE052, BIT_3 | BIT_7);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_6:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_12:
                rtl8125_oob_mutex_unlock(tp);
                break;
        }

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xD430);
        mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
        mac_ocp_data |= 0x45F;
        rtl8125_mac_ocp_write(tp, 0xD430, mac_ocp_data);

        //rtl8125_mac_ocp_write(tp, 0xE0C0, 0x4F87);
        if (!tp->DASH)
                RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) | BIT_6 | BIT_7);
        else
                RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) & ~(BIT_6 | BIT_7));

        if (tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_6)
                RTL_W8(tp, MCUCmd_reg, RTL_R8(tp, MCUCmd_reg) | BIT_0);

        if (tp->mcfg != CFG_METHOD_10 && tp->mcfg != CFG_METHOD_11 &&
            tp->mcfg != CFG_METHOD_13)
                rtl8125_disable_eee_plus(tp);

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEA1C);
        mac_ocp_data &= ~(BIT_2);
        rtl8125_mac_ocp_write(tp, 0xEA1C, mac_ocp_data);

        rtl8125_clear_tcam_entries(tp);

        RTL_W16(tp, 0x1880, RTL_R16(tp, 0x1880) & ~(BIT_4 | BIT_5));

        if (tp->HwSuppRxDescType == RX_DESC_RING_TYPE_4) {
                if (tp->InitRxDescType == RX_DESC_RING_TYPE_4)
                        RTL_W8(tp, 0xd8, RTL_R8(tp, 0xd8) |
                               EnableRxDescV4_0);
                else
                        RTL_W8(tp, 0xd8, RTL_R8(tp, 0xd8) &
                               ~EnableRxDescV4_0);
        }

        if (tp->mcfg == CFG_METHOD_12) {
                rtl8125_clear_mac_ocp_bit(tp, 0xE00C, BIT_12);

                rtl8125_clear_mac_ocp_bit(tp, 0xC0C2, BIT_6);
        }

        /* csum offload command for RTL8125 */
        tp->tx_tcp_csum_cmd = TxTCPCS_C;
        tp->tx_udp_csum_cmd = TxUDPCS_C;
        tp->tx_ip_csum_cmd = TxIPCS_C;
        tp->tx_ipv6_csum_cmd = TxIPV6F_C;

        /* config interrupt type for RTL8125B */
        if (tp->HwSuppIsrVer > 1)
                rtl8125_hw_set_interrupt_type(tp, tp->HwCurrIsrVer);

        //other hw parameters
        rtl8125_hw_clear_timer_int(dev);

        rtl8125_hw_clear_int_miti(dev);

        if (tp->use_timer_interrupt &&
            (tp->HwCurrIsrVer > 1) &&
            (tp->HwSuppIntMitiVer > 3) &&
            (tp->features & RTL_FEATURE_MSIX)) {
                int i;
                for (i = 0; i < tp->irq_nvecs; i++)
                        rtl8125_hw_set_timer_int(tp, i, timer_count_v2);
        }

        rtl8125_enable_exit_l1_mask(tp);

        rtl8125_mac_ocp_write(tp, 0xE098, 0xC302);

        if (aspm && (tp->org_pci_offset_99 & (BIT_2 | BIT_5 | BIT_6)))
                rtl8125_init_pci_offset_99(tp);
        else
                rtl8125_disable_pci_offset_99(tp);

        if (aspm && (tp->org_pci_offset_180 & rtl8125_get_l1off_cap_bits(tp)))
                rtl8125_init_pci_offset_180(tp);
        else
                rtl8125_disable_pci_offset_180(tp);

        if (tp->RequiredPfmPatch)
                rtl8125_set_pfm_patch(tp, 0);

        tp->cp_cmd &= ~(EnableBist | Macdbgo_oe | Force_halfdup |
                        Force_rxflow_en | Force_txflow_en | Cxpl_dbg_sel |
                        ASF | Macdbgo_sel);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        RTL_W16(tp, CPlusCmd, tp->cp_cmd);
#else
        rtl8125_hw_set_features(dev, dev->features);
#endif
        rtl8125_set_rms(tp, tp->rms);

        rtl8125_disable_rxdvgate(dev);

        if (!tp->pci_cfg_is_read) {
                pci_read_config_byte(pdev, PCI_COMMAND, &tp->pci_cfg_space.cmd);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_0, &tp->pci_cfg_space.io_base_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_0 + 2, &tp->pci_cfg_space.io_base_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_2, &tp->pci_cfg_space.mem_base_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, &tp->pci_cfg_space.mem_base_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_3, &tp->pci_cfg_space.resv_0x1c_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, &tp->pci_cfg_space.resv_0x1c_h);
                pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &tp->pci_cfg_space.ilr);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_4, &tp->pci_cfg_space.resv_0x20_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, &tp->pci_cfg_space.resv_0x20_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_5, &tp->pci_cfg_space.resv_0x24_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, &tp->pci_cfg_space.resv_0x24_h);
                pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &tp->pci_cfg_space.resv_0x2c_l);
                pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, &tp->pci_cfg_space.resv_0x2c_h);
                if (tp->HwPcieSNOffset > 0) {
                        tp->pci_cfg_space.pci_sn_l = rtl8125_csi_read(tp, tp->HwPcieSNOffset);
                        tp->pci_cfg_space.pci_sn_h = rtl8125_csi_read(tp, tp->HwPcieSNOffset + 4);
                }

                tp->pci_cfg_is_read = 1;
        }

        /* Set Rx packet filter */
        rtl8125_hw_set_rx_packet_filter(dev);

#ifdef ENABLE_DASH_SUPPORT
        rtl8125_check_and_enable_dash_interrupt(tp);
#endif

        rtl8125_enable_aspm_clkreq_lock(tp, aspm ? 1 : 0);

        rtl8125_disable_cfg9346_write(tp);

        udelay(10);
}

void
rtl8125_hw_start(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

#ifdef ENABLE_LIB_SUPPORT
        rtl8125_init_lib_ring(tp);
#endif

        RTL_W8(tp, ChipCmd, CmdTxEnb | CmdRxEnb);

        rtl8125_enable_hw_interrupt(tp);

        rtl8125_lib_reset_complete(tp);
}

static int
rtl8125_change_mtu(struct net_device *dev,
                   int new_mtu)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
        if (new_mtu < ETH_MIN_MTU)
                return -EINVAL;
        else if (new_mtu > tp->max_jumbo_frame_size)
                new_mtu = tp->max_jumbo_frame_size;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)

        dev->mtu = new_mtu;

        tp->eee.tx_lpi_timer = dev->mtu + ETH_HLEN + 0x20;

        if (!netif_running(dev))
                goto out;

        rtl8125_down(dev);

        rtl8125_set_rxbufsize(tp, dev);

        ret = rtl8125_init_ring(dev);

        if (ret < 0)
                goto err_out;

#ifdef CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif//CONFIG_R8125_NAPI

        if (tp->link_ok(dev))
                rtl8125_link_on_patch(dev);
        else
                rtl8125_link_down_patch(dev);

        //mod_timer(&tp->esd_timer, jiffies + RTL8125_ESD_TIMEOUT);
        //mod_timer(&tp->link_timer, jiffies + RTL8125_LINK_TIMEOUT);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
        netdev_update_features(dev);
#endif

err_out:
        return ret;
}

static inline void
rtl8125_set_desc_dma_addr(struct rtl8125_private *tp,
                          struct RxDesc *desc,
                          dma_addr_t mapping)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                ((struct RxDescV3 *)desc)->addr = cpu_to_le64(mapping);
                break;
        case RX_DESC_RING_TYPE_4:
                ((struct RxDescV4 *)desc)->addr = cpu_to_le64(mapping);
                break;
        default:
                desc->addr = cpu_to_le64(mapping);
                break;
        }
}

static inline void
rtl8125_mark_to_asic_v1(struct RxDesc *desc,
                        u32 rx_buf_sz)
{
        u32 eor = le32_to_cpu(desc->opts1) & RingEnd;

        WRITE_ONCE(desc->opts1, cpu_to_le32(DescOwn | eor | rx_buf_sz));
}

static inline void
rtl8125_mark_to_asic_v3(struct RxDescV3 *descv3,
                        u32 rx_buf_sz)
{
        u32 eor = le32_to_cpu(descv3->RxDescNormalDDWord4.opts1) & RingEnd;

        WRITE_ONCE(descv3->RxDescNormalDDWord4.opts1, cpu_to_le32(DescOwn | eor | rx_buf_sz));
}

static inline void
rtl8125_mark_to_asic_v4(struct RxDescV4 *descv4,
                        u32 rx_buf_sz)
{
        u32 eor = le32_to_cpu(descv4->RxDescNormalDDWord2.opts1) & RingEnd;

        WRITE_ONCE(descv4->RxDescNormalDDWord2.opts1, cpu_to_le32(DescOwn | eor | rx_buf_sz));
}

void
rtl8125_mark_to_asic(struct rtl8125_private *tp,
                     struct RxDesc *desc,
                     u32 rx_buf_sz)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                rtl8125_mark_to_asic_v3((struct RxDescV3 *)desc, rx_buf_sz);
                break;
        case RX_DESC_RING_TYPE_4:
                rtl8125_mark_to_asic_v4((struct RxDescV4 *)desc, rx_buf_sz);
                break;
        default:
                rtl8125_mark_to_asic_v1(desc, rx_buf_sz);
                break;
        }
}

static inline void
rtl8125_map_to_asic(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct RxDesc *desc,
                    dma_addr_t mapping,
                    u32 rx_buf_sz,
                    const u32 cur_rx)
{
        ring->RxDescPhyAddr[cur_rx] = mapping;
        rtl8125_set_desc_dma_addr(tp, desc, mapping);
        wmb();
        rtl8125_mark_to_asic(tp, desc, rx_buf_sz);
}

#ifdef ENABLE_PAGE_REUSE

static int
rtl8125_alloc_rx_page(struct rtl8125_private *tp, struct rtl8125_rx_ring *ring,
                      struct rtl8125_rx_buffer *rxb)
{
        struct page *page;
        dma_addr_t dma;
        unsigned int order = tp->rx_buf_page_order;

        //get free page
        page = dev_alloc_pages(order);

        if (unlikely(!page))
                return -ENOMEM;

        dma = dma_map_page_attrs(&tp->pci_dev->dev, page, 0,
                                 tp->rx_buf_page_size,
                                 DMA_FROM_DEVICE,
                                 (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING));

        if (unlikely(dma_mapping_error(&tp->pci_dev->dev, dma))) {
                __free_pages(page, order);
                return -ENOMEM;
        }

        rxb->page = page;
        rxb->data = page_address(page);
        rxb->page_offset = ring->rx_offset;
        rxb->dma = dma;

        //after page alloc, page refcount already = 1

        return 0;
}

static void
rtl8125_free_rx_page(struct rtl8125_private *tp, struct rtl8125_rx_buffer *rxb)
{
        if (!rxb->page)
                return;

        dma_unmap_page_attrs(&tp->pci_dev->dev, rxb->dma,
                             tp->rx_buf_page_size,
                             DMA_FROM_DEVICE,
                             (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING));
        __free_pages(rxb->page, tp->rx_buf_page_order);
        rxb->page = NULL;
}

static void
_rtl8125_rx_clear(struct rtl8125_private *tp, struct rtl8125_rx_ring *ring)
{
        int i;
        struct rtl8125_rx_buffer *rxb;

        for (i = 0; i < ring->num_rx_desc; i++) {
                rxb = &ring->rx_buffer[i];
                if (rxb->skb) {
                        dev_kfree_skb(rxb->skb);
                        rxb->skb = NULL;
                }
                rtl8125_free_rx_page(tp, rxb);
        }
}

static u32
rtl8125_rx_fill(struct rtl8125_private *tp,
                struct rtl8125_rx_ring *ring,
                struct net_device *dev,
                u32 start,
                u32 end,
                u8 in_intr)
{
        u32 cur;
        struct rtl8125_rx_buffer *rxb;

        for (cur = start; end - cur > 0; cur++) {
                int ret, i = cur % ring->num_rx_desc;

                rxb = &ring->rx_buffer[i];
                if (rxb->page)
                        continue;

                ret = rtl8125_alloc_rx_page(tp, ring, rxb);
                if (ret)
                        break;

                dma_sync_single_range_for_device(tp_to_dev(tp),
                                                 rxb->dma,
                                                 rxb->page_offset,
                                                 tp->rx_buf_sz,
                                                 DMA_FROM_DEVICE);

                rtl8125_map_to_asic(tp, ring,
                                    rtl8125_get_rxdesc(tp, ring->RxDescArray, i),
                                    rxb->dma + rxb->page_offset,
                                    tp->rx_buf_sz, i);
        }
        return cur - start;
}

#else //ENABLE_PAGE_REUSE

static void
rtl8125_free_rx_skb(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct sk_buff **sk_buff,
                    struct RxDesc *desc,
                    const u32 cur_rx)
{
        struct pci_dev *pdev = tp->pci_dev;

        dma_unmap_single(&pdev->dev, ring->RxDescPhyAddr[cur_rx], tp->rx_buf_sz,
                         DMA_FROM_DEVICE);
        dev_kfree_skb(*sk_buff);
        *sk_buff = NULL;
        rtl8125_make_unusable_by_asic(tp, desc);
}

static int
rtl8125_alloc_rx_skb(struct rtl8125_private *tp,
                     struct rtl8125_rx_ring *ring,
                     struct sk_buff **sk_buff,
                     struct RxDesc *desc,
                     int rx_buf_sz,
                     const u32 cur_rx,
                     u8 in_intr)
{
        struct sk_buff *skb;
        dma_addr_t mapping;
        int ret = 0;

        if (in_intr)
                skb = RTL_ALLOC_SKB_INTR(&tp->r8125napi[ring->index].napi, rx_buf_sz + R8125_RX_ALIGN);
        else
                skb = dev_alloc_skb(rx_buf_sz + R8125_RX_ALIGN);

        if (unlikely(!skb))
                goto err_out;

        if (!in_intr || !R8125_USE_NAPI_ALLOC_SKB)
                skb_reserve(skb, R8125_RX_ALIGN);

        mapping = dma_map_single(tp_to_dev(tp), skb->data, rx_buf_sz,
                                 DMA_FROM_DEVICE);
        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                if (unlikely(net_ratelimit()))
                        netif_err(tp, drv, tp->dev, "Failed to map RX DMA!\n");
                goto err_out;
        }

        *sk_buff = skb;
        rtl8125_map_to_asic(tp, ring, desc, mapping, rx_buf_sz, cur_rx);
out:
        return ret;

err_out:
        if (skb)
                dev_kfree_skb(skb);
        ret = -ENOMEM;
        rtl8125_make_unusable_by_asic(tp, desc);
        goto out;
}

static void
_rtl8125_rx_clear(struct rtl8125_private *tp, struct rtl8125_rx_ring *ring)
{
        int i;

        for (i = 0; i < ring->num_rx_desc; i++) {
                if (ring->Rx_skbuff[i]) {
                        rtl8125_free_rx_skb(tp,
                                            ring,
                                            ring->Rx_skbuff + i,
                                            rtl8125_get_rxdesc(tp, ring->RxDescArray, i),
                                            i);
                        ring->Rx_skbuff[i] = NULL;
                }
        }
}

static u32
rtl8125_rx_fill(struct rtl8125_private *tp,
                struct rtl8125_rx_ring *ring,
                struct net_device *dev,
                u32 start,
                u32 end,
                u8 in_intr)
{
        u32 cur;

        for (cur = start; end - cur > 0; cur++) {
                int ret, i = cur % ring->num_rx_desc;

                if (ring->Rx_skbuff[i])
                        continue;

                ret = rtl8125_alloc_rx_skb(tp,
                                           ring,
                                           ring->Rx_skbuff + i,
                                           rtl8125_get_rxdesc(tp, ring->RxDescArray, i),
                                           tp->rx_buf_sz,
                                           i,
                                           in_intr);
                if (ret < 0)
                        break;
        }
        return cur - start;
}

#endif //ENABLE_PAGE_REUSE

void
rtl8125_rx_clear(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];

                _rtl8125_rx_clear(tp, ring);
        }
}

static void
rtl8125_mark_as_last_descriptor_v1(struct RxDesc *desc)
{
        desc->opts1 |= cpu_to_le32(RingEnd);
}

static void
rtl8125_mark_as_last_descriptor_v3(struct RxDescV3 *descv3)
{
        descv3->RxDescNormalDDWord4.opts1 |= cpu_to_le32(RingEnd);
}

static void
rtl8125_mark_as_last_descriptor_v4(struct RxDescV4 *descv4)
{
        descv4->RxDescNormalDDWord2.opts1 |= cpu_to_le32(RingEnd);
}

void
rtl8125_mark_as_last_descriptor(struct rtl8125_private *tp,
                                struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                rtl8125_mark_as_last_descriptor_v3((struct RxDescV3 *)desc);
                break;
        case RX_DESC_RING_TYPE_4:
                rtl8125_mark_as_last_descriptor_v4((struct RxDescV4 *)desc);
                break;
        default:
                rtl8125_mark_as_last_descriptor_v1(desc);
                break;
        }
}

static void
rtl8125_desc_addr_fill(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                RTL_W32(tp, ring->tdsar_reg, ((u64)ring->TxPhyAddr & DMA_BIT_MASK(32)));
                RTL_W32(tp, ring->tdsar_reg + 4, ((u64)ring->TxPhyAddr >> 32));
        }

        if (rtl8125_num_lib_rx_rings(tp) == 0) {
                for (i = 0; i < tp->num_rx_rings; i++) {
                        struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                        RTL_W32(tp, ring->rdsar_reg, ((u64)ring->RxPhyAddr & DMA_BIT_MASK(32)));
                        RTL_W32(tp, ring->rdsar_reg + 4, ((u64)ring->RxPhyAddr >> 32));
                }
        }
}

static void
rtl8125_tx_desc_init(struct rtl8125_private *tp)
{
        int i = 0;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                memset(ring->TxDescArray, 0x0, ring->TxDescAllocSize);

                ring->TxDescArray[ring->num_tx_desc - 1].opts1 = cpu_to_le32(RingEnd);
        }
}

static void
rtl8125_rx_desc_init(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                memset(ring->RxDescArray, 0x0, ring->RxDescAllocSize);
        }
}

int
rtl8125_init_ring(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtl8125_init_ring_indexes(tp);

        rtl8125_tx_desc_init(tp);
        rtl8125_rx_desc_init(tp);

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                memset(ring->tx_skb, 0x0, sizeof(ring->tx_skb));
        }

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
#ifdef ENABLE_PAGE_REUSE
                ring->rx_offset = R8125_RX_ALIGN;
#else
                memset(ring->Rx_skbuff, 0x0, sizeof(ring->Rx_skbuff));
#endif //ENABLE_PAGE_REUSE
                if (rtl8125_rx_fill(tp, ring, dev, 0, ring->num_rx_desc, 0) != ring->num_rx_desc)
                        goto err_out;

                rtl8125_mark_as_last_descriptor(tp, rtl8125_get_rxdesc(tp, ring->RxDescArray, ring->num_rx_desc - 1));
        }

        return 0;

err_out:
        rtl8125_rx_clear(tp);
        return -ENOMEM;
}

static void
rtl8125_unmap_tx_skb(struct pci_dev *pdev,
                     struct ring_info *tx_skb,
                     struct TxDesc *desc)
{
        unsigned int len = tx_skb->len;

        dma_unmap_single(&pdev->dev, le64_to_cpu(desc->addr), len, DMA_TO_DEVICE);

        desc->opts1 = cpu_to_le32(RTK_MAGIC_DEBUG_VALUE);
        desc->opts2 = 0x00;
        desc->addr = RTL8125_MAGIC_NUMBER;
        tx_skb->len = 0;
}

static void
rtl8125_tx_clear_range(struct rtl8125_private *tp,
                       struct rtl8125_tx_ring *ring,
                       u32 start,
                       unsigned int n)
{
        unsigned int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
        struct net_device *dev = tp->dev;
#endif

        for (i = 0; i < n; i++) {
                unsigned int entry = (start + i) % ring->num_tx_desc;
                struct ring_info *tx_skb = ring->tx_skb + entry;
                unsigned int len = tx_skb->len;

                if (len) {
                        struct sk_buff *skb = tx_skb->skb;

                        rtl8125_unmap_tx_skb(tp->pci_dev, tx_skb,
                                             ring->TxDescArray + entry);
                        if (skb) {
                                RTLDEV->stats.tx_dropped++;
                                dev_kfree_skb_any(skb);
                                tx_skb->skb = NULL;
                        }
                }
        }
}

void
rtl8125_tx_clear(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                rtl8125_tx_clear_range(tp, ring, ring->dirty_tx, ring->num_tx_desc);
                ring->cur_tx = ring->dirty_tx = 0;
        }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_schedule_reset_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        set_bit(R8125_FLAG_TASK_RESET_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->reset_task, 4);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

static void rtl8125_schedule_esd_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        set_bit(R8125_FLAG_TASK_ESD_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->esd_task, RTL8125_ESD_TIMEOUT);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

static void rtl8125_schedule_linkchg_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        set_bit(R8125_FLAG_TASK_LINKCHG_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->linkchg_task, 4);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

static void rtl8125_schedule_link_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        set_bit(R8125_FLAG_TASK_LINK_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->link_task, RTL8125_LINK_TIMEOUT);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

static void rtl8125_schedule_dash_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        set_bit(R8125_FLAG_TASK_DASH_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->dash_task, RTL8125_DASH_TIMEOUT);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

#define rtl8125_cancel_schedule_reset_work(a)
#define rtl8125_cancel_schedule_esd_work(a)
#define rtl8125_cancel_schedule_linkchg_work(a)
#define rtl8125_cancel_schedule_link_work(a)
#define rtl8125_cancel_schedule_dash_work(a)

#else
static void rtl8125_schedule_reset_work(struct rtl8125_private *tp)
{
        set_bit(R8125_FLAG_TASK_RESET_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->reset_task, 4);
}

static void rtl8125_cancel_schedule_reset_work(struct rtl8125_private *tp)
{
        struct work_struct *work = &tp->reset_task.work;

        if (!work->func)
                return;

        cancel_delayed_work_sync(&tp->reset_task);
}

static void rtl8125_schedule_esd_work(struct rtl8125_private *tp)
{
        set_bit(R8125_FLAG_TASK_ESD_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->esd_task, RTL8125_ESD_TIMEOUT);
}

static void rtl8125_cancel_schedule_esd_work(struct rtl8125_private *tp)
{
        struct work_struct *work = &tp->esd_task.work;

        if (!work->func)
                return;

        cancel_delayed_work_sync(&tp->esd_task);
}

static void rtl8125_schedule_linkchg_work(struct rtl8125_private *tp)
{
        set_bit(R8125_FLAG_TASK_LINKCHG_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->linkchg_task, 4);
}

static void rtl8125_cancel_schedule_linkchg_work(struct rtl8125_private *tp)
{
        struct work_struct *work = &tp->linkchg_task.work;

        if (!work->func)
                return;

        cancel_delayed_work_sync(&tp->linkchg_task);
}

static void rtl8125_schedule_link_work(struct rtl8125_private *tp)
{
        set_bit(R8125_FLAG_TASK_LINK_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->link_task, RTL8125_LINK_TIMEOUT);
}

static void rtl8125_cancel_schedule_link_work(struct rtl8125_private *tp)
{
        struct work_struct *work = &tp->link_task.work;

        if (!work->func)
                return;

        cancel_delayed_work_sync(&tp->link_task);
}

void rtl8125_schedule_dash_work(struct rtl8125_private *tp)
{
        set_bit(R8125_FLAG_TASK_DASH_CHECK_PENDING, tp->task_flags);
        schedule_delayed_work(&tp->dash_task, RTL8125_DASH_TIMEOUT);
}

static void rtl8125_cancel_schedule_dash_work(struct rtl8125_private *tp)
{
        struct work_struct *work = &tp->dash_task.work;

        if (!work->func)
                return;

        cancel_delayed_work_sync(&tp->dash_task);
}
#endif

static void rtl8125_init_all_schedule_work(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
        INIT_WORK(&tp->reset_task, rtl8125_reset_task, dev);
        INIT_WORK(&tp->esd_task, rtl8125_esd_task, dev);
        INIT_WORK(&tp->linkchg_task, rtl8125_linkchg_task, dev);
        INIT_WORK(&tp->link_task, rtl8125_link_task, dev);
        INIT_WORK(&tp->dash_task, rtl8125_dash_task, dev);
#else
        INIT_DELAYED_WORK(&tp->reset_task, rtl8125_reset_task);
        INIT_DELAYED_WORK(&tp->esd_task, rtl8125_esd_task);
        INIT_DELAYED_WORK(&tp->linkchg_task, rtl8125_linkchg_task);
        INIT_DELAYED_WORK(&tp->link_task, rtl8125_link_task);
        INIT_DELAYED_WORK(&tp->dash_task, rtl8125_dash_task);
#endif
}

static void rtl8125_cancel_all_schedule_work(struct rtl8125_private *tp)
{
        rtl8125_cancel_schedule_reset_work(tp);
        rtl8125_cancel_schedule_esd_work(tp);
        rtl8125_cancel_schedule_linkchg_work(tp);
        rtl8125_cancel_schedule_link_work(tp);
        rtl8125_cancel_schedule_dash_work(tp);
}

static void
rtl8125_wait_for_irq_complete(struct rtl8125_private *tp)
{
        if (tp->features & RTL_FEATURE_MSIX) {
                int i;
                for (i = 0; i < tp->irq_nvecs; i++)
                        synchronize_irq(tp->irq_tbl[i].vector);
        } else {
                synchronize_irq(tp->dev->irq);
        }
}

void
_rtl8125_wait_for_quiescence(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        /* Wait for any pending NAPI task to complete */
#ifdef CONFIG_R8125_NAPI
        rtl8125_disable_napi(tp);
#endif//CONFIG_R8125_NAPI

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,67)
        /* Give a racing hard_start_xmit a few cycles to complete. */
        synchronize_net();
#endif

        rtl8125_irq_mask_and_ack(tp);

        rtl8125_wait_for_irq_complete(tp);
}

static void
rtl8125_wait_for_quiescence(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        //suppress unused variable
        (void)(tp);

        _rtl8125_wait_for_quiescence(dev);

#ifdef CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif//CONFIG_R8125_NAPI
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_reset_task(void *_data)
{
        struct net_device *dev = _data;
        struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_reset_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, reset_task.work);
        struct net_device *dev = tp->dev;
#endif
        int i;

        rtnl_lock();

        if (!netif_running(dev) ||
            test_bit(R8125_FLAG_DOWN, tp->task_flags) ||
            !test_and_clear_bit(R8125_FLAG_TASK_RESET_PENDING, tp->task_flags))
                goto out_unlock;

        netdev_err(dev, "Device reseting!\n");

        netif_carrier_off(dev);
        netif_tx_disable(dev);
        _rtl8125_wait_for_quiescence(dev);
        rtl8125_hw_reset(dev);

        rtl8125_tx_clear(tp);

        rtl8125_init_ring_indexes(tp);

        rtl8125_tx_desc_init(tp);
        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring;
                u32 entry;

                ring = &tp->rx_ring[i];
                for (entry = 0; entry < ring->num_rx_desc; entry++) {
                        struct RxDesc *desc;

                        desc = rtl8125_get_rxdesc(tp, ring->RxDescArray, entry);
                        rtl8125_mark_to_asic(tp, desc, tp->rx_buf_sz);
                }
        }

#ifdef ENABLE_PTP_SUPPORT
        rtl8125_ptp_reset(tp);
#endif

#ifdef CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif //CONFIG_R8125_NAPI

        if (tp->resume_not_chg_speed) {
                _rtl8125_check_link_status(dev, R8125_LINK_STATE_UNKNOWN);

                tp->resume_not_chg_speed = 0;
        } else {
                rtl8125_enable_hw_linkchg_interrupt(tp);

                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
        }

out_unlock:
        rtnl_unlock();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_esd_task(void *_data)
{
        struct net_device *dev = _data;
        struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_esd_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, esd_task.work);
        struct net_device *dev = tp->dev;
#endif
        rtnl_lock();

        if (!netif_running(dev) ||
            test_bit(R8125_FLAG_DOWN, tp->task_flags) ||
            !test_and_clear_bit(R8125_FLAG_TASK_ESD_CHECK_PENDING, tp->task_flags))
                goto out_unlock;

        rtl8125_esd_checker(tp);

        rtl8125_schedule_esd_work(tp);

out_unlock:
        rtnl_unlock();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_linkchg_task(void *_data)
{
        struct net_device *dev = _data;
        //struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_linkchg_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, linkchg_task.work);
        struct net_device *dev = tp->dev;
#endif
        rtnl_lock();

        if (!netif_running(dev) ||
            test_bit(R8125_FLAG_DOWN, tp->task_flags) ||
            !test_and_clear_bit(R8125_FLAG_TASK_LINKCHG_CHECK_PENDING, tp->task_flags))
                goto out_unlock;

        rtl8125_check_link_status(dev);

out_unlock:
        rtnl_unlock();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_link_task(void *_data)
{
        struct net_device *dev = _data;
        //struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_link_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, link_task.work);
        struct net_device *dev = tp->dev;
#endif
        rtnl_lock();

        if (!netif_running(dev) ||
            test_bit(R8125_FLAG_DOWN, tp->task_flags) ||
            !test_and_clear_bit(R8125_FLAG_TASK_LINK_CHECK_PENDING,
                                tp->task_flags))
                goto out_unlock;

        if (netif_carrier_ok(dev) != tp->link_ok(dev))
                rtl8125_schedule_linkchg_work(tp);

        rtl8125_schedule_link_work(tp);

out_unlock:
        rtnl_unlock();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_dash_task(void *_data)
{
        struct net_device *dev = _data;
        //struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_dash_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, dash_task.work);
        struct net_device *dev = tp->dev;
#endif
        rtnl_lock();

        if (!netif_running(dev) ||
            test_bit(R8125_FLAG_DOWN, tp->task_flags) ||
            !test_and_clear_bit(R8125_FLAG_TASK_DASH_CHECK_PENDING, tp->task_flags))
                goto out_unlock;

#ifdef ENABLE_DASH_SUPPORT
        rtl8125_handle_dash_interrupt(dev);
#endif

out_unlock:
        rtnl_unlock();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static void
rtl8125_tx_timeout(struct net_device *dev, unsigned int txqueue)
#else
static void
rtl8125_tx_timeout(struct net_device *dev)
#endif
{
        struct rtl8125_private *tp = netdev_priv(dev);

        netdev_err(dev, "Transmit timeout reset Device!\n");

        /* Let's wait a bit while any (async) irq lands on */
        rtl8125_schedule_reset_work(tp);
}

static u32
rtl8125_get_txd_opts1(struct rtl8125_tx_ring *ring,
                      u32 opts1,
                      u32 len,
                      unsigned int entry)
{
        u32 status = opts1 | len;

        if (entry == ring->num_tx_desc - 1)
                status |= RingEnd;

        return status;
}

static int
rtl8125_xmit_frags(struct rtl8125_private *tp,
                   struct rtl8125_tx_ring *ring,
                   struct sk_buff *skb,
                   const u32 *opts)
{
        struct skb_shared_info *info = skb_shinfo(skb);
        unsigned int cur_frag, entry;
        struct TxDesc *txd = NULL;
        const unsigned char nr_frags = info->nr_frags;
        unsigned long PktLenCnt = 0;
        bool LsoPatchEnabled = FALSE;

        entry = ring->cur_tx;
        for (cur_frag = 0; cur_frag < nr_frags; cur_frag++) {
                skb_frag_t *frag = info->frags + cur_frag;
                dma_addr_t mapping;
                u32 status, len;
                void *addr;

                entry = (entry + 1) % ring->num_tx_desc;

                txd = ring->TxDescArray + entry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
                len = frag->size;
                addr = ((void *) page_address(frag->page)) + frag->page_offset;
#else
                len = skb_frag_size(frag);
                addr = skb_frag_address(frag);
#endif
                if (tp->RequireLSOPatch  &&
                    (cur_frag == nr_frags - 1) &&
                    (opts[0] & (GiantSendv4|GiantSendv6)) &&
                    PktLenCnt < ETH_FRAME_LEN &&
                    len > 1) {
                        len -= 1;
                        mapping = dma_map_single(tp_to_dev(tp), addr, len, DMA_TO_DEVICE);

                        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                                if (unlikely(net_ratelimit()))
                                        netif_err(tp, drv, tp->dev,
                                                  "Failed to map TX fragments DMA!\n");
                                goto err_out;
                        }

                        /* anti gcc 2.95.3 bugware (sic) */
                        status = rtl8125_get_txd_opts1(ring, opts[0], len, entry);

                        txd->addr = cpu_to_le64(mapping);

                        ring->tx_skb[entry].len = len;

                        txd->opts2 = cpu_to_le32(opts[1]);
                        wmb();
                        txd->opts1 = cpu_to_le32(status);

                        //second txd
                        addr += len;
                        len = 1;
                        entry = (entry + 1) % ring->num_tx_desc;
                        txd = ring->TxDescArray + entry;
                        cur_frag += 1;

                        LsoPatchEnabled = TRUE;
                }

                mapping = dma_map_single(tp_to_dev(tp), addr, len, DMA_TO_DEVICE);

                if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                        if (unlikely(net_ratelimit()))
                                netif_err(tp, drv, tp->dev,
                                          "Failed to map TX fragments DMA!\n");
                        goto err_out;
                }

                /* anti gcc 2.95.3 bugware (sic) */
                status = rtl8125_get_txd_opts1(ring, opts[0], len, entry);
                if (cur_frag == (nr_frags - 1) || LsoPatchEnabled == TRUE)
                        status |= LastFrag;

                txd->addr = cpu_to_le64(mapping);

                ring->tx_skb[entry].len = len;

                txd->opts2 = cpu_to_le32(opts[1]);
                wmb();
                txd->opts1 = cpu_to_le32(status);

                PktLenCnt += len;
        }

        return cur_frag;

err_out:
        rtl8125_tx_clear_range(tp, ring, ring->cur_tx + 1, cur_frag);
        return -EIO;
}

static inline
__be16 get_protocol(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
        return vlan_get_protocol(skb);
#else
        __be16 protocol;

        if (skb->protocol == htons(ETH_P_8021Q))
                protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
        else
                protocol = skb->protocol;

        return protocol;
#endif
}

static inline
u8 rtl8125_get_l4_protocol(struct sk_buff *skb)
{
        int no = skb_network_offset(skb);
        struct ipv6hdr *i6h, _i6h;
        struct iphdr *ih, _ih;
        u8 ip_protocol = IPPROTO_RAW;

        switch (get_protocol(skb)) {
        case  __constant_htons(ETH_P_IP):
                ih = skb_header_pointer(skb, no, sizeof(_ih), &_ih);
                if (ih)
                        ip_protocol = ih->protocol;
                break;
        case  __constant_htons(ETH_P_IPV6):
                i6h = skb_header_pointer(skb, no, sizeof(_i6h), &_i6h);
                if (i6h)
                        ip_protocol = i6h->nexthdr;
                break;
        }

        return ip_protocol;
}

static bool rtl8125_skb_pad_with_len(struct sk_buff *skb, unsigned int len)
{
        if (skb_padto(skb, len))
                return false;
        skb_put(skb, len - skb->len);
        return true;
}

static bool rtl8125_skb_pad(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        return rtl8125_skb_pad_with_len(skb, ETH_ZLEN);
#else
        return !eth_skb_pad(skb);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
/* msdn_giant_send_check()
 * According to the document of microsoft, the TCP Pseudo Header excludes the
 * packet length for IPv6 TCP large packets.
 */
static int msdn_giant_send_check(struct sk_buff *skb)
{
        const struct ipv6hdr *ipv6h;
        struct tcphdr *th;
        int ret;

        ret = skb_cow_head(skb, 0);
        if (ret)
                return ret;

        ipv6h = ipv6_hdr(skb);
        th = tcp_hdr(skb);

        th->check = 0;
        th->check = ~tcp_v6_check(0, &ipv6h->saddr, &ipv6h->daddr, 0);

        return ret;
}
#endif

static bool rtl8125_require_pad_ptp_pkt(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2 ... CFG_METHOD_7:
                return true;
        default:
                return false;
        }
}

#define MIN_PATCH_LEN (47)
static u32
rtl8125_get_patch_pad_len(struct rtl8125_private *tp,
                          struct sk_buff *skb)
{
        u32 pad_len = 0;
        int trans_data_len;
        u32 hdr_len;
        u32 pkt_len = skb->len;
        u8 ip_protocol;
        bool has_trans = skb_transport_header_was_set(skb);

        if (!rtl8125_require_pad_ptp_pkt(tp))
                goto no_padding;

        if (!(has_trans && (pkt_len < 175))) //128 + MIN_PATCH_LEN
                goto no_padding;

        ip_protocol = rtl8125_get_l4_protocol(skb);
        if (!(ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP))
                goto no_padding;

        trans_data_len = pkt_len -
                         (skb->transport_header -
                          skb_headroom(skb));
        if (ip_protocol == IPPROTO_UDP) {
                if (trans_data_len > 3 && trans_data_len < MIN_PATCH_LEN) {
                        u16 dest_port = 0;

                        skb_copy_bits(skb, skb->transport_header - skb_headroom(skb) + 2, &dest_port, 2);
                        dest_port = ntohs(dest_port);

                        if (dest_port == 0x13f ||
                            dest_port == 0x140) {
                                pad_len = MIN_PATCH_LEN - trans_data_len;
                                goto out;
                        }
                }
        }

        hdr_len = 0;
        if (ip_protocol == IPPROTO_TCP)
                hdr_len = 20;
        else if (ip_protocol == IPPROTO_UDP)
                hdr_len = 8;
        if (trans_data_len < hdr_len)
                pad_len = hdr_len - trans_data_len;

out:
        if ((pkt_len + pad_len) < ETH_ZLEN)
                pad_len = ETH_ZLEN - pkt_len;

        return pad_len;

no_padding:

        return 0;
}

static bool
rtl8125_tso_csum(struct sk_buff *skb,
                 struct net_device *dev,
                 u32 *opts,
                 unsigned int *bytecount,
                 unsigned short *gso_segs)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long large_send = 0;
        u32 csum_cmd = 0;
        u8 sw_calc_csum = false;
        u8 check_patch_required = true;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        if (dev->features & (NETIF_F_TSO | NETIF_F_TSO6)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
                u32 mss = skb_shinfo(skb)->tso_size;
#else
                u32 mss = skb_shinfo(skb)->gso_size;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)

                /* TCP Segmentation Offload (or TCP Large Send) */
                if (mss) {
                        union {
                                struct iphdr *v4;
                                struct ipv6hdr *v6;
                                unsigned char *hdr;
                        } ip;
                        union {
                                struct tcphdr *tcp;
                                struct udphdr *udp;
                                unsigned char *hdr;
                        } l4;
                        u32 l4_offset, hdr_len;

                        ip.hdr = skb_network_header(skb);
                        l4.hdr = skb_checksum_start(skb);

                        l4_offset = skb_transport_offset(skb);
                        assert((l4_offset%2) == 0);
                        switch (get_protocol(skb)) {
                        case __constant_htons(ETH_P_IP):
                                if (l4_offset <= GTTCPHO_MAX) {
                                        opts[0] |= GiantSendv4;
                                        opts[0] |= l4_offset << GTTCPHO_SHIFT;
                                        opts[1] |= min(mss, MSS_MAX) << 18;
                                        large_send = 1;
                                }
                                break;
                        case __constant_htons(ETH_P_IPV6):
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
                                if (msdn_giant_send_check(skb))
                                        return false;
#endif
                                if (l4_offset <= GTTCPHO_MAX) {
                                        opts[0] |= GiantSendv6;
                                        opts[0] |= l4_offset << GTTCPHO_SHIFT;
                                        opts[1] |= min(mss, MSS_MAX) << 18;
                                        large_send = 1;
                                }
                                break;
                        default:
                                if (unlikely(net_ratelimit()))
                                        dprintk("tso proto=%x!\n", skb->protocol);
                                break;
                        }

                        if (large_send == 0)
                                return false;


                        /* compute length of segmentation header */
                        hdr_len = (l4.tcp->doff * 4) + l4_offset;
                        /* update gso size and bytecount with header size */
                        *gso_segs = skb_shinfo(skb)->gso_segs;
                        *bytecount += (*gso_segs - 1) * hdr_len;

                        return true;
                }
        }
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        if (skb->ip_summed == CHECKSUM_PARTIAL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
                const struct iphdr *ip = skb->nh.iph;

                if (dev->features & NETIF_F_IP_CSUM) {
                        if (ip->protocol == IPPROTO_TCP)
                                csum_cmd = tp->tx_ip_csum_cmd | tp->tx_tcp_csum_cmd;
                        else if (ip->protocol == IPPROTO_UDP)
                                csum_cmd = tp->tx_ip_csum_cmd | tp->tx_udp_csum_cmd;
                        else if (ip->protocol == IPPROTO_IP)
                                csum_cmd = tp->tx_ip_csum_cmd;
                }
#else
                u8 ip_protocol = IPPROTO_RAW;

                switch (get_protocol(skb)) {
                case  __constant_htons(ETH_P_IP):
                        if (dev->features & NETIF_F_IP_CSUM) {
                                ip_protocol = ip_hdr(skb)->protocol;
                                csum_cmd = tp->tx_ip_csum_cmd;
                        }
                        break;
                case  __constant_htons(ETH_P_IPV6):
                        if (dev->features & NETIF_F_IPV6_CSUM) {
                                if (skb_transport_offset(skb) > 0 && skb_transport_offset(skb) <= TCPHO_MAX) {
                                        ip_protocol = ipv6_hdr(skb)->nexthdr;
                                        csum_cmd = tp->tx_ipv6_csum_cmd;
                                        csum_cmd |= skb_transport_offset(skb) << TCPHO_SHIFT;
                                }
                        }
                        break;
                default:
                        if (unlikely(net_ratelimit()))
                                dprintk("checksum_partial proto=%x!\n", skb->protocol);
                        break;
                }

                if (ip_protocol == IPPROTO_TCP)
                        csum_cmd |= tp->tx_tcp_csum_cmd;
                else if (ip_protocol == IPPROTO_UDP)
                        csum_cmd |= tp->tx_udp_csum_cmd;
#endif
                if (csum_cmd == 0) {
                        sw_calc_csum = true;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        WARN_ON(1); /* we need a WARN() */
#endif
                }

                if (ip_protocol == IPPROTO_TCP)
                        check_patch_required = false;
        }

        if (check_patch_required) {
                u32 pad_len = rtl8125_get_patch_pad_len(tp, skb);

                if (pad_len > 0) {
                        if (!rtl8125_skb_pad_with_len(skb, skb->len + pad_len))
                                return false;

                        if (csum_cmd != 0)
                                sw_calc_csum = true;
                }
        }

        if (skb->len < ETH_ZLEN) {
                if (tp->UseSwPaddingShortPkt ||
                    (tp->ShortPacketSwChecksum && csum_cmd != 0)) {
                        if (!rtl8125_skb_pad(skb))
                                return false;

                        if (csum_cmd != 0)
                                sw_calc_csum = true;
                }
        }

        if (sw_calc_csum) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
                skb_checksum_help(&skb, 0);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
                skb_checksum_help(skb, 0);
#else
                skb_checksum_help(skb);
#endif
        } else
                opts[1] |= csum_cmd;

        return true;
}

static bool rtl8125_tx_slots_avail(struct rtl8125_private *tp,
                                   struct rtl8125_tx_ring *ring)
{
        unsigned int slots_avail = READ_ONCE(ring->dirty_tx) + ring->num_tx_desc
                                   - READ_ONCE(ring->cur_tx);

        /* A skbuff with nr_frags needs nr_frags+1 entries in the tx queue */
        return slots_avail > MAX_SKB_FRAGS;
}

static inline u32
rtl8125_fast_mod_mask(const u32 input, const u32 mask)
{
        return input > mask ? input & mask : input;
}

static void rtl8125_doorbell(struct rtl8125_private *tp,
                             struct rtl8125_tx_ring *ring)
{
        if (tp->EnableTxNoClose) {
                if (tp->HwSuppTxNoCloseVer > 3)
                        RTL_W32(tp, ring->sw_tail_ptr_reg, ring->cur_tx);
                else
                        RTL_W16(tp, ring->sw_tail_ptr_reg, ring->cur_tx);
        } else
                RTL_W16(tp, TPPOLL_8125, BIT(ring->index));    /* set polling bit */
}

static netdev_tx_t
rtl8125_start_xmit(struct sk_buff *skb,
                   struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int   bytecount;
        unsigned short gso_segs;
        struct ring_info *last;
        unsigned int last_entry;
        unsigned int entry;
        struct TxDesc *txd;
        dma_addr_t mapping;
        u32 len;
        u32 opts[2];
        netdev_tx_t ret = NETDEV_TX_OK;
        int frags;
        u8 EnableTxNoClose = tp->EnableTxNoClose;
        const u16 queue_mapping = skb_get_queue_mapping(skb);
        struct rtl8125_tx_ring *ring;
        bool stop_queue;

        assert(queue_mapping < tp->num_tx_rings);

        ring = &tp->tx_ring[queue_mapping];

        if (unlikely(!rtl8125_tx_slots_avail(tp, ring))) {
                if (netif_msg_drv(tp)) {
                        printk(KERN_ERR
                               "%s: BUG! Tx Ring[%d] full when queue awake!\n",
                               dev->name,
                               queue_mapping);
                }
                goto err_stop;
        }

        entry = ring->cur_tx % ring->num_tx_desc;
        txd = ring->TxDescArray + entry;

        if (!EnableTxNoClose) {
                if (unlikely(le32_to_cpu(txd->opts1) & DescOwn)) {
                        if (netif_msg_drv(tp)) {
                                printk(KERN_ERR
                                       "%s: BUG! Tx Desc is own by hardware!\n",
                                       dev->name);
                        }
                        goto err_stop;
                }
        }

        bytecount = skb->len;
        gso_segs = 1;

        opts[0] = DescOwn;
        opts[1] = rtl8125_tx_vlan_tag(tp, skb);

        if (unlikely(!rtl8125_tso_csum(skb, dev, opts, &bytecount, &gso_segs)))
                goto err_dma_0;

        frags = rtl8125_xmit_frags(tp, ring, skb, opts);
        if (unlikely(frags < 0))
                goto err_dma_0;
        if (frags) {
                len = skb_headlen(skb);
                opts[0] |= FirstFrag;
        } else {
                len = skb->len;
                opts[0] |= FirstFrag | LastFrag;
        }

        opts[0] = rtl8125_get_txd_opts1(ring, opts[0], len, entry);
        mapping = dma_map_single(tp_to_dev(tp), skb->data, len, DMA_TO_DEVICE);
        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                if (unlikely(net_ratelimit()))
                        netif_err(tp, drv, dev, "Failed to map TX DMA!\n");
                goto err_dma_1;
        }

#ifdef ENABLE_PTP_SUPPORT
        if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
                if (!test_and_set_bit_lock(__RTL8125_PTP_TX_IN_PROGRESS, &tp->state)) {
                        if (tp->hwtstamp_config.tx_type == HWTSTAMP_TX_ON &&
                            !tp->ptp_tx_skb) {
                                skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

                                tp->ptp_tx_skb = skb_get(skb);
                                tp->ptp_tx_start = jiffies;
                                schedule_work(&tp->ptp_tx_work);
                        } else
                                tp->tx_hwtstamp_skipped++;
                }
        }
#endif
        /* set first fragment's length */
        ring->tx_skb[entry].len = len;

        /* set skb to last fragment */
        last_entry = (entry + frags) % ring->num_tx_desc;
        last = &ring->tx_skb[last_entry];
        last->skb = skb;
        last->gso_segs = gso_segs;
        last->bytecount = bytecount;

        txd->addr = cpu_to_le64(mapping);
        txd->opts2 = cpu_to_le32(opts[1]);
        wmb();
        txd->opts1 = cpu_to_le32(opts[0]);

        netdev_tx_sent_queue(txring_txq(ring), bytecount);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
        dev->trans_start = jiffies;
#else
        skb_tx_timestamp(skb);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)

        /* rtl_tx needs to see descriptor changes before updated tp->cur_tx */
        smp_wmb();

        WRITE_ONCE(ring->cur_tx, ring->cur_tx + frags + 1);

        stop_queue = !rtl8125_tx_slots_avail(tp, ring);
        if (unlikely(stop_queue)) {
                /* Avoid wrongly optimistic queue wake-up: rtl_tx thread must
                 * not miss a ring update when it notices a stopped queue.
                 */
                smp_wmb();
                netif_stop_subqueue(dev, queue_mapping);
        }

        if (netif_xmit_stopped(txring_txq(ring)) || !netdev_xmit_more())
                rtl8125_doorbell(tp, ring);

        if (unlikely(stop_queue)) {
                /* Sync with rtl_tx:
                 * - publish queue status and cur_tx ring index (write barrier)
                 * - refresh dirty_tx ring index (read barrier).
                 * May the current thread have a pessimistic view of the ring
                 * status and forget to wake up queue, a racing rtl_tx thread
                 * can't.
                 */
                smp_mb();
                if (rtl8125_tx_slots_avail(tp, ring))
                        netif_start_subqueue(dev, queue_mapping);
        }
out:
        return ret;
err_dma_1:
        rtl8125_tx_clear_range(tp, ring, ring->cur_tx + 1, frags);
err_dma_0:
        RTLDEV->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        ret = NETDEV_TX_OK;
        goto out;
err_stop:
        netif_stop_subqueue(dev, queue_mapping);
        ret = NETDEV_TX_BUSY;
        RTLDEV->stats.tx_dropped++;
        goto out;
}

/* recycle tx no close desc*/
static int
rtl8125_tx_interrupt_noclose(struct rtl8125_tx_ring *ring, int budget)
{
        unsigned int total_bytes = 0, total_packets = 0;
        struct rtl8125_private *tp = ring->priv;
        struct net_device *dev = tp->dev;
        unsigned int dirty_tx, tx_left;
        unsigned int tx_desc_closed;
        unsigned int count = 0;

        dirty_tx = ring->dirty_tx;
        ring->NextHwDesCloPtr = rtl8125_get_hw_clo_ptr(ring);
        tx_desc_closed = rtl8125_fast_mod_mask(ring->NextHwDesCloPtr -
                                               ring->BeginHwDesCloPtr,
                                               tp->MaxTxDescPtrMask);
        tx_left = min((READ_ONCE(ring->cur_tx) - dirty_tx), tx_desc_closed);
        ring->BeginHwDesCloPtr += tx_left;

        while (tx_left > 0) {
                unsigned int entry = dirty_tx % ring->num_tx_desc;
                struct ring_info *tx_skb = ring->tx_skb + entry;

                rtl8125_unmap_tx_skb(tp->pci_dev,
                                     tx_skb,
                                     ring->TxDescArray + entry);

                if (tx_skb->skb != NULL) {
                        /* update the statistics for this packet */
                        total_bytes += tx_skb->bytecount;
                        total_packets += tx_skb->gso_segs;

                        RTL_NAPI_CONSUME_SKB_ANY(tx_skb->skb, budget);
                        tx_skb->skb = NULL;
                }
                dirty_tx++;
                tx_left--;
        }

        if (total_packets) {
                netdev_tx_completed_queue(txring_txq(ring),
                                          total_packets, total_bytes);

                RTLDEV->stats.tx_bytes += total_bytes;
                RTLDEV->stats.tx_packets+= total_packets;
        }

        if (ring->dirty_tx != dirty_tx) {
                count = dirty_tx - ring->dirty_tx;
                WRITE_ONCE(ring->dirty_tx, dirty_tx);
                smp_wmb();
                if (__netif_subqueue_stopped(dev, ring->index) &&
                    rtl8125_tx_slots_avail(tp, ring) && netif_carrier_ok(dev)) {
                        netif_start_subqueue(dev, ring->index);
                }
        }

        return count;
}

/* recycle tx close desc*/
static int
rtl8125_tx_interrupt_close(struct rtl8125_tx_ring *ring, int budget)
{
        unsigned int total_bytes = 0, total_packets = 0;
        struct rtl8125_private *tp = ring->priv;
        struct net_device *dev = tp->dev;
        unsigned int dirty_tx, tx_left;
        unsigned int count = 0;

        dirty_tx = ring->dirty_tx;
        tx_left = READ_ONCE(ring->cur_tx) - dirty_tx;

        while (tx_left > 0) {
                unsigned int entry = dirty_tx % ring->num_tx_desc;
                struct ring_info *tx_skb = ring->tx_skb + entry;

                if (le32_to_cpu(READ_ONCE(ring->TxDescArray[entry].opts1)) & DescOwn)
                        break;

                rtl8125_unmap_tx_skb(tp->pci_dev,
                                     tx_skb,
                                     ring->TxDescArray + entry);

                if (tx_skb->skb != NULL) {
                        /* update the statistics for this packet */
                        total_bytes += tx_skb->bytecount;
                        total_packets += tx_skb->gso_segs;

                        RTL_NAPI_CONSUME_SKB_ANY(tx_skb->skb, budget);
                        tx_skb->skb = NULL;
                }
                dirty_tx++;
                tx_left--;
        }

        if (total_packets) {
                netdev_tx_completed_queue(txring_txq(ring),
                                          total_packets, total_bytes);

                RTLDEV->stats.tx_bytes += total_bytes;
                RTLDEV->stats.tx_packets+= total_packets;
        }

        if (ring->dirty_tx != dirty_tx) {
                count = dirty_tx - ring->dirty_tx;
                WRITE_ONCE(ring->dirty_tx, dirty_tx);
                smp_wmb();
                if (__netif_subqueue_stopped(dev, ring->index) &&
                    rtl8125_tx_slots_avail(tp, ring) && netif_carrier_ok(dev)) {
                        netif_start_subqueue(dev, ring->index);
                }

                if (READ_ONCE(ring->cur_tx) != dirty_tx)
                        rtl8125_doorbell(tp, ring);
        }

        return count;
}

static int
rtl8125_tx_interrupt(struct rtl8125_tx_ring *ring, int budget)
{
        struct rtl8125_private *tp = ring->priv;

        if (tp->EnableTxNoClose)
                return rtl8125_tx_interrupt_noclose(ring, budget);
        else
                return rtl8125_tx_interrupt_close(ring, budget);
}

static int
rtl8125_tx_interrupt_with_vector(struct rtl8125_private *tp,
                                 const int message_id,
                                 int budget)
{
        int count = 0;

        switch (tp->HwCurrIsrVer) {
        case 3:
        case 4:
                if (message_id < tp->num_tx_rings)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[message_id], budget);
                break;
        case 5:
                if (message_id == 16)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[0], budget);
#ifdef ENABLE_MULTIPLE_TX_QUEUE
                else if (message_id == 17 && tp->num_tx_rings > 1)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[1], budget);
#endif
                break;
        case 7:
                if (message_id == 27)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[0], budget);
#ifdef ENABLE_MULTIPLE_TX_QUEUE
                else if (message_id == 28 && tp->num_tx_rings > 1)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[1], budget);
#endif
                break;
        default:
                if (message_id == 16)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[0], budget);
#ifdef ENABLE_MULTIPLE_TX_QUEUE
                else if (message_id == 18 && tp->num_tx_rings > 1)
                        count += rtl8125_tx_interrupt(&tp->tx_ring[1], budget);
#endif
                break;
        }

        return count;
}

static inline int
rtl8125_fragmented_frame(struct rtl8125_private *tp, u32 status)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                return (status & (FirstFrag_V3 | LastFrag_V3)) != (FirstFrag_V3 | LastFrag_V3);
        case RX_DESC_RING_TYPE_4:
                return (status & (FirstFrag_V4 | LastFrag_V4)) != (FirstFrag_V4 | LastFrag_V4);
        default:
                return (status & (FirstFrag | LastFrag)) != (FirstFrag | LastFrag);
        }
}

static inline int
rtl8125_is_non_eop(struct rtl8125_private *tp, u32 status)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                return !(status & LastFrag_V3);
        case RX_DESC_RING_TYPE_4:
                return !(status & LastFrag_V4);
        default:
                return !(status & LastFrag);
        }
}

static inline int
rtl8125_rx_desc_type(u32 status)
{
        return ((status >> 26) & 0x0F);
}

static inline void
rtl8125_rx_v1_csum(struct rtl8125_private *tp,
                   struct sk_buff *skb,
                   struct RxDesc *desc)
{
        u32 opts1 = le32_to_cpu(desc->opts1);

        if (((opts1 & RxTCPT) && !(opts1 & RxTCPF)) ||
            ((opts1 & RxUDPT) && !(opts1 & RxUDPF)))
                skb->ip_summed = CHECKSUM_UNNECESSARY;
        else
                skb_checksum_none_assert(skb);
}

static inline void
rtl8125_rx_v3_csum(struct rtl8125_private *tp,
                   struct sk_buff *skb,
                   struct RxDescV3 *descv3)
{
        u32 opts2 = le32_to_cpu(descv3->RxDescNormalDDWord4.opts2);

        /* rx csum offload for RTL8125 */
        if (((opts2 & RxTCPT_v3) && !(opts2 & RxTCPF_v3)) ||
            ((opts2 & RxUDPT_v3) && !(opts2 & RxUDPF_v3)))
                skb->ip_summed = CHECKSUM_UNNECESSARY;
        else
                skb_checksum_none_assert(skb);
}

static inline void
rtl8125_rx_v4_csum(struct rtl8125_private *tp,
                   struct sk_buff *skb,
                   struct RxDescV4 *descv4)
{
        u32 opts1 = le32_to_cpu(descv4->RxDescNormalDDWord2.opts1);

        /* rx csum offload for RTL8125 */
        if (((opts1 & RxTCPT_v4) && !(opts1 & RxTCPF_v4)) ||
            ((opts1 & RxUDPT_v4) && !(opts1 & RxUDPF_v4)))
                skb->ip_summed = CHECKSUM_UNNECESSARY;
        else
                skb_checksum_none_assert(skb);
}

static inline void
rtl8125_rx_csum(struct rtl8125_private *tp,
                struct sk_buff *skb,
                struct RxDesc *desc)
{
        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                rtl8125_rx_v3_csum(tp, skb, (struct RxDescV3 *)desc);
                break;
        case RX_DESC_RING_TYPE_4:
                rtl8125_rx_v4_csum(tp, skb, (struct RxDescV4 *)desc);
                break;
        default:
                rtl8125_rx_v1_csum(tp, skb, desc);
                break;
        }
}

/*
static inline int
rtl8125_try_rx_copy(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct sk_buff **sk_buff,
                    int pkt_size,
                    struct RxDesc *desc,
                    int rx_buf_sz)
{
        int ret = -1;

        struct sk_buff *skb;

        skb = RTL_ALLOC_SKB_INTR(&tp->r8125napi[ring->index].napi, pkt_size + R8125_RX_ALIGN);
        if (skb) {
                u8 *data;

                data = sk_buff[0]->data;
                if (!R8125_USE_NAPI_ALLOC_SKB)
                    skb_reserve(skb, R8125_RX_ALIGN);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
                prefetch(data - R8125_RX_ALIGN);
#endif
                eth_copy_and_sum(skb, data, pkt_size, 0);
                *sk_buff = skb;
                rtl8125_mark_to_asic(tp, desc, rx_buf_sz);
                ret = 0;
        }

        return ret;
}
*/

static inline void
rtl8125_rx_skb(struct rtl8125_private *tp,
               struct sk_buff *skb,
               u32 ring_index)
{
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        netif_receive_skb(skb);
#else
        napi_gro_receive(&tp->r8125napi[ring_index].napi, skb);
#endif
#else
        netif_rx(skb);
#endif
}

static int
rtl8125_check_rx_desc_error(struct net_device *dev,
                            struct rtl8125_private *tp,
                            u32 status)
{
        int ret = 0;

        switch (tp->InitRxDescType) {
        case RX_DESC_RING_TYPE_3:
                if (unlikely(status & RxRES_V3)) {
                        if (status & (RxRWT_V3 | RxRUNT_V3))
                                RTLDEV->stats.rx_length_errors++;
                        if (status & RxCRC_V3)
                                RTLDEV->stats.rx_crc_errors++;

                        ret = -1;
                }
                break;
        case RX_DESC_RING_TYPE_4:
                if (unlikely(status & RxRES_V4)) {
                        if (status & RxRUNT_V4)
                                RTLDEV->stats.rx_length_errors++;
                        if (status & RxCRC_V4)
                                RTLDEV->stats.rx_crc_errors++;

                        ret = -1;
                }
                break;
        default:
                if (unlikely(status & RxRES)) {
                        if (status & (RxRWT | RxRUNT))
                                RTLDEV->stats.rx_length_errors++;
                        if (status & RxCRC)
                                RTLDEV->stats.rx_crc_errors++;

                        ret = -1;
                }
                break;
        }

        return ret;
}

#ifdef ENABLE_PAGE_REUSE

static inline bool
rtl8125_reuse_rx_ok(struct page *page)
{
        /* avoid re-using remote pages */
        if (!dev_page_is_reusable(page)) {
                //printk(KERN_INFO "r8125 page pfmemalloc, can't reuse!\n");
                return false;
        }
        /* if we are only owner of page we can reuse it */
        if (unlikely(page_ref_count(page) != 1)) {
                //printk(KERN_INFO "r8125 page refcnt %d, can't reuse!\n", page_ref_count(page));
                return false;
        }

        return true;
}

static void
rtl8125_reuse_rx_buffer(struct rtl8125_private *tp, struct rtl8125_rx_ring *ring, u32 cur_rx, struct rtl8125_rx_buffer *rxb)
{
        struct page *page = rxb->page;

        u32 dirty_rx = ring->dirty_rx;
        u32 entry = dirty_rx % ring->num_rx_desc;
        struct rtl8125_rx_buffer *nrxb = &ring->rx_buffer[entry];

        u32 noffset;

        //the page gonna be shared by us and kernel, keep page ref = 2
        page_ref_inc(page);

        //flip the buffer in page to use next
        noffset = rxb->page_offset ^ (tp->rx_buf_page_size / 2); //one page, two buffer, ping-pong

        nrxb->dma = rxb->dma;
        nrxb->page_offset = noffset;
        nrxb->data = rxb->data;

        if (cur_rx != dirty_rx) {
                //move the buffer to other slot
                nrxb->page = page;
                rxb->page = NULL;
        }
}

static void rtl8125_put_rx_buffer(struct rtl8125_private *tp,
                                  struct rtl8125_rx_ring *ring,
                                  u32 cur_rx,
                                  struct rtl8125_rx_buffer *rxb)
{
        struct rtl8125_rx_buffer *nrxb;
        struct page *page = rxb->page;
        u32 entry;

        entry = ring->dirty_rx % ring->num_rx_desc;
        nrxb = &ring->rx_buffer[entry];
        if (likely(rtl8125_reuse_rx_ok(page))) {
                /* hand second half of page back to the ring */
                rtl8125_reuse_rx_buffer(tp, ring, cur_rx, rxb);
        } else {
                tp->page_reuse_fail_cnt++;

                dma_unmap_page_attrs(&tp->pci_dev->dev, rxb->dma,
                                     tp->rx_buf_page_size,
                                     DMA_FROM_DEVICE,
                                     (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING));
                //the page ref is kept 1, uniquely owned by kernel now
                rxb->page = NULL;

                return;
        }

        dma_sync_single_range_for_device(tp_to_dev(tp),
                                         nrxb->dma,
                                         nrxb->page_offset,
                                         tp->rx_buf_sz,
                                         DMA_FROM_DEVICE);

        rtl8125_map_to_asic(tp, ring,
                            rtl8125_get_rxdesc(tp, ring->RxDescArray, entry),
                            nrxb->dma + nrxb->page_offset,
                            tp->rx_buf_sz, entry);

        ring->dirty_rx++;
}

#endif //ENABLE_PAGE_REUSE

static int
rtl8125_rx_interrupt(struct net_device *dev,
                     struct rtl8125_private *tp,
                     struct rtl8125_rx_ring *ring,
                     napi_budget budget)
{
        unsigned int cur_rx, rx_left;
        unsigned int delta, count = 0;
        unsigned int entry;
        struct RxDesc *desc;
        struct sk_buff *skb;
        u32 status;
        u32 rx_quota;
        u32 ring_index = ring->index;
#ifdef ENABLE_PAGE_REUSE
        struct rtl8125_rx_buffer *rxb;
#else //ENABLE_PAGE_REUSE
        u64 rx_buf_phy_addr;
#endif //ENABLE_PAGE_REUSE
        unsigned int total_rx_multicast_packets = 0;
        unsigned int total_rx_bytes = 0, total_rx_packets = 0;

        assert(dev != NULL);
        assert(tp != NULL);

        if (ring->RxDescArray == NULL)
                goto rx_out;

        rx_quota = RTL_RX_QUOTA(budget);
        cur_rx = ring->cur_rx;
        rx_left = ring->num_rx_desc + ring->dirty_rx - cur_rx;
        rx_left = rtl8125_rx_quota(rx_left, (u32)rx_quota);

        for (; rx_left > 0; rx_left--, cur_rx++) {
#ifdef ENABLE_PTP_SUPPORT
                u8 desc_type = RXDESC_TYPE_NORMAL;
                struct RxDescV3 ptp_desc;
#endif //ENABLE_PTP_SUPPORT
#ifndef ENABLE_PAGE_REUSE
                const void *rx_buf;
#endif //!ENABLE_PAGE_REUSE
                u32 pkt_size;

                entry = cur_rx % ring->num_rx_desc;
                desc = rtl8125_get_rxdesc(tp, ring->RxDescArray, entry);
                status = le32_to_cpu(rtl8125_rx_desc_opts1(tp, desc));
                if (status & DescOwn) {
                        RTL_R8(tp, tp->imr_reg[0]);
                        status = le32_to_cpu(rtl8125_rx_desc_opts1(tp, desc));
                        if (status & DescOwn)
                                break;
                }

                rmb();

                if (unlikely(rtl8125_check_rx_desc_error(dev, tp, status) < 0)) {
                        if (netif_msg_rx_err(tp)) {
                                printk(KERN_INFO
                                       "%s: Rx ERROR. status = %08x\n",
                                       dev->name, status);
                        }

                        RTLDEV->stats.rx_errors++;

                        if (!(dev->features & NETIF_F_RXALL))
                                goto release_descriptor;
                }
                pkt_size = status & 0x00003fff;
                if (likely(!(dev->features & NETIF_F_RXFCS))) {
#ifdef ENABLE_RX_PACKET_FRAGMENT
                        if (rtl8125_is_non_eop(tp, status) &&
                            pkt_size == tp->rx_buf_sz) {
                                struct RxDesc *desc_next;
                                unsigned int entry_next;
                                int pkt_size_next;
                                u32 status_next;

                                entry_next = (cur_rx + 1) % ring->num_rx_desc;
                                desc_next = rtl8125_get_rxdesc(tp, ring->RxDescArray, entry_next);
                                status_next = le32_to_cpu(rtl8125_rx_desc_opts1(tp, desc_next));
                                if (!(status_next & DescOwn)) {
                                        pkt_size_next = status_next & 0x00003fff;
                                        if (pkt_size_next < ETH_FCS_LEN)
                                                pkt_size -= (ETH_FCS_LEN - pkt_size_next);
                                }
                        }
#endif //ENABLE_RX_PACKET_FRAGMENT
                        if (!rtl8125_is_non_eop(tp, status)) {
                                if (pkt_size < ETH_FCS_LEN) {
#ifdef ENABLE_RX_PACKET_FRAGMENT
                                        pkt_size = 0;
#else
                                        goto drop_packet;
#endif //ENABLE_RX_PACKET_FRAGMENT
                                } else
                                        pkt_size -= ETH_FCS_LEN;
                        }
                }

                if (unlikely(pkt_size > tp->rx_buf_sz))
                        goto drop_packet;

#if !defined(ENABLE_RX_PACKET_FRAGMENT) || !defined(ENABLE_PAGE_REUSE)
                /*
                 * The driver does not support incoming fragmented
                 * frames. They are seen as a symptom of over-mtu
                 * sized frames.
                 */
                if (unlikely(rtl8125_fragmented_frame(tp, status)))
                        goto drop_packet;
#endif //!ENABLE_RX_PACKET_FRAGMENT || !ENABLE_PAGE_REUSE

#ifdef ENABLE_PTP_SUPPORT
                if (tp->HwSuppPtpVer == 1) {
                        desc_type = rtl8125_rx_desc_type(status);
                        if (desc_type == RXDESC_TYPE_NEXT && rx_left > 0) {
                                u32 status_next;
                                struct RxDescV3 *desc_next;
                                unsigned int entry_next;

                                cur_rx++;
                                rx_left--;
                                entry_next = cur_rx % ring->num_rx_desc;
                                desc_next = (struct RxDescV3 *)rtl8125_get_rxdesc(tp, ring->RxDescArray, entry_next);
                                status_next = le32_to_cpu(desc_next->RxDescNormalDDWord4.opts1);
                                if (unlikely(status_next & DescOwn)) {
                                        udelay(1);
                                        status_next = le32_to_cpu(desc_next->RxDescNormalDDWord4.opts1);
                                        if (unlikely(status_next & DescOwn)) {
                                                if (netif_msg_rx_err(tp)) {
                                                        printk(KERN_ERR
                                                               "%s: Rx Next Desc ERROR. status = %08x\n",
                                                               dev->name, status_next);
                                                }
                                                rtl8125_set_desc_dma_addr(tp, (struct RxDesc *)desc_next,
                                                                          ring->RxDescPhyAddr[entry_next]);
                                                wmb();
                                                rtl8125_mark_to_asic(tp, (struct RxDesc *)desc_next, tp->rx_buf_sz);
                                                goto drop_packet;
                                        }
                                }

                                rmb();

                                desc_type = rtl8125_rx_desc_type(status_next);
                                if (desc_type == RXDESC_TYPE_PTP) {
                                        ptp_desc = *desc_next;
                                        rmb();
                                        rtl8125_set_desc_dma_addr(tp, (struct RxDesc *)desc_next,
                                                                  ring->RxDescPhyAddr[entry_next]);
                                        wmb();
                                        rtl8125_mark_to_asic(tp, (struct RxDesc *)desc_next, tp->rx_buf_sz);
                                } else {
                                        WARN_ON(1);
                                        rtl8125_set_desc_dma_addr(tp, (struct RxDesc *)desc_next,
                                                                  ring->RxDescPhyAddr[entry_next]);
                                        wmb();
                                        rtl8125_mark_to_asic(tp, (struct RxDesc *)desc_next, tp->rx_buf_sz);
                                        goto drop_packet;
                                }
                        } else
                                WARN_ON(desc_type != RXDESC_TYPE_NORMAL);
                }
#endif
#ifdef ENABLE_PAGE_REUSE
                rxb = &ring->rx_buffer[entry];
                skb = rxb->skb;
                rxb->skb = NULL;
                if (!skb) {
                        skb = RTL_BUILD_SKB_INTR(rxb->data + rxb->page_offset - ring->rx_offset, tp->rx_buf_page_size / 2);
                        if (!skb) {
                                //netdev_err(tp->dev, "Failed to allocate RX skb!\n");
                                goto drop_packet;
                        }

                        skb->dev = dev;
                        if (!R8125_USE_NAPI_ALLOC_SKB)
                                skb_reserve(skb, R8125_RX_ALIGN);
                        skb_put(skb, pkt_size);
#ifdef ENABLE_RSS_SUPPORT
                        rtl8125_rx_hash(tp, desc, skb);
#endif
                        rtl8125_rx_csum(tp, skb, desc);
                } else
                        skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rxb->page,
                                        rxb->page_offset, pkt_size, tp->rx_buf_page_size / 2);

                //recycle desc
                rtl8125_put_rx_buffer(tp, ring, cur_rx, rxb);

                dma_sync_single_range_for_cpu(tp_to_dev(tp),
                                              rxb->dma,
                                              rxb->page_offset,
                                              tp->rx_buf_sz,
                                              DMA_FROM_DEVICE);
#else //ENABLE_PAGE_REUSE
                skb = RTL_ALLOC_SKB_INTR(&tp->r8125napi[ring->index].napi, pkt_size + R8125_RX_ALIGN);
                if (!skb) {
                        //netdev_err(tp->dev, "Failed to allocate RX skb!\n");
                        goto drop_packet;
                }

                skb->dev = dev;
                if (!R8125_USE_NAPI_ALLOC_SKB)
                        skb_reserve(skb, R8125_RX_ALIGN);
                skb_put(skb, pkt_size);

                rx_buf_phy_addr = ring->RxDescPhyAddr[entry];
                dma_sync_single_for_cpu(tp_to_dev(tp),
                                        rx_buf_phy_addr, tp->rx_buf_sz,
                                        DMA_FROM_DEVICE);
                rx_buf = ring->Rx_skbuff[entry]->data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
                prefetch(rx_buf - R8125_RX_ALIGN);
#endif
                eth_copy_and_sum(skb, rx_buf, pkt_size, 0);

                dma_sync_single_for_device(tp_to_dev(tp), rx_buf_phy_addr,
                                           tp->rx_buf_sz, DMA_FROM_DEVICE);
#endif //ENABLE_PAGE_REUSE

#ifdef ENABLE_PTP_SUPPORT
                if (tp->HwSuppPtpVer == 1 && desc_type == RXDESC_TYPE_PTP)
                        rtl8125_rx_mac_ptp_pktstamp(tp, skb, &ptp_desc);
                else if (tp->HwSuppPtpVer == 3 && (tp->flags & RTL_FLAG_RX_HWTSTAMP_ENABLED))
                        rtl8125_rx_phy_ptp_timestamp(tp, skb);
#endif // ENABLE_PTP_SUPPORT

#ifdef ENABLE_RX_PACKET_FRAGMENT
                if (rtl8125_is_non_eop(tp, status)) {
                        unsigned int entry_next;
                        entry_next = (entry + 1) % ring->num_rx_desc;
                        rxb = &ring->rx_buffer[entry_next];
                        rxb->skb = skb;
                        continue;
                }
#endif //ENABLE_RX_PACKET_FRAGMENT

#ifndef ENABLE_PAGE_REUSE
#ifdef ENABLE_RSS_SUPPORT
                rtl8125_rx_hash(tp, desc, skb);
#endif
                rtl8125_rx_csum(tp, skb, desc);
#endif /* !ENABLE_PAGE_REUSE */

                skb->protocol = eth_type_trans(skb, dev);

                total_rx_bytes += skb->len;

                if (skb->pkt_type == PACKET_MULTICAST)
                        total_rx_multicast_packets++;

                if (rtl8125_rx_vlan_skb(tp, desc, skb) < 0)
                        rtl8125_rx_skb(tp, skb, ring_index);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
                dev->last_rx = jiffies;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
                total_rx_packets++;

#ifdef ENABLE_PAGE_REUSE
                rxb->skb = NULL;
                continue;
#endif

release_descriptor:
                switch (tp->InitRxDescType) {
                case RX_DESC_RING_TYPE_3:
                case RX_DESC_RING_TYPE_4:
                        rtl8125_set_desc_dma_addr(tp, desc,
                                                  ring->RxDescPhyAddr[entry]);
                        wmb();
                        break;
                }
                rtl8125_mark_to_asic(tp, desc, tp->rx_buf_sz);
                continue;
drop_packet:
                RTLDEV->stats.rx_dropped++;
                RTLDEV->stats.rx_length_errors++;
                goto release_descriptor;
        }

        count = cur_rx - ring->cur_rx;
        ring->cur_rx = cur_rx;

        delta = rtl8125_rx_fill(tp, ring, dev, ring->dirty_rx, ring->cur_rx, 1);
        if (!delta && count && netif_msg_intr(tp))
                printk(KERN_INFO "%s: no Rx buffer allocated\n", dev->name);
        ring->dirty_rx += delta;

        RTLDEV->stats.rx_bytes += total_rx_bytes;
        RTLDEV->stats.rx_packets += total_rx_packets;
        RTLDEV->stats.multicast += total_rx_multicast_packets;

        /*
         * FIXME: until there is periodic timer to try and refill the ring,
         * a temporary shortage may definitely kill the Rx process.
         * - disable the asic to try and avoid an overflow and kick it again
         *   after refill ?
         * - how do others driver handle this condition (Uh oh...).
         */
        if ((ring->dirty_rx + ring->num_rx_desc == ring->cur_rx) && netif_msg_intr(tp))
                printk(KERN_EMERG "%s: Rx buffers exhausted\n", dev->name);

rx_out:
        return total_rx_packets;
}

static bool
rtl8125_linkchg_interrupt(struct rtl8125_private *tp, u32 status)
{
        switch (tp->HwCurrIsrVer) {
        case 2:
        case 3:
                return status & ISRIMR_V2_LINKCHG;
        case 4:
                return status & ISRIMR_V4_LINKCHG;
        case 5:
                return status & ISRIMR_V5_LINKCHG;
        case 7:
                return status & ISRIMR_V7_LINKCHG;
        default:
                return status & LinkChg;
        }
}

static u32
rtl8125_get_linkchg_message_id(struct rtl8125_private *tp)
{
        switch (tp->HwCurrIsrVer) {
        case 4:
        case 7:
                return 29;
        case 5:
                return 18;
        default:
                return 21;
        }
}

/*
 *The interrupt handler does all of the Rx thread work and cleans up after
 *the Tx thread.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
#else
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance)
#endif
{
        struct r8125_napi *r8125napi = dev_instance;
        struct rtl8125_private *tp = r8125napi->priv;
        struct net_device *dev = tp->dev;
        u32 status;
        int handled = 0;

        do {
                status = RTL_R32(tp, tp->isr_reg[0]);

                if (!(tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX))) {
                        /* hotplug/major error/no more work/shared irq */
                        if (!status)
                                break;

                        if (status == 0xFFFFFFFF)
                                break;

                        if (!(status & (tp->intr_mask | tp->timer_intr_mask)))
                                break;
                }

                handled = 1;

#if defined(RTL_USE_NEW_INTR_API)
                if (!tp->irq_tbl[0].requested)
                        break;
#endif
                rtl8125_disable_hw_interrupt(tp);

                RTL_W32(tp, tp->isr_reg[0], status&~RxFIFOOver);

                if (rtl8125_linkchg_interrupt(tp, status))
                        rtl8125_schedule_linkchg_work(tp);

#ifdef ENABLE_DASH_SUPPORT
                if ((status & ISRIMR_V4_LAYER2_INTR_STS) &&
                    rtl8125_check_dash_interrupt(tp))
                        rtl8125_schedule_dash_work(tp);
#endif

#ifdef CONFIG_R8125_NAPI
                if (status & tp->intr_mask || tp->keep_intr_cnt-- > 0) {
                        if (status & tp->intr_mask)
                                tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;

                        if (likely(RTL_NETIF_RX_SCHEDULE_PREP(dev, &tp->r8125napi[0].napi)))
                                __RTL_NETIF_RX_SCHEDULE(dev, &tp->r8125napi[0].napi);
                        else if (netif_msg_intr(tp))
                                printk(KERN_INFO "%s: interrupt %04x in poll\n",
                                       dev->name, status);
                } else {
                        tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;
                        rtl8125_switch_to_hw_interrupt(tp);
                }
#else
                if (status & tp->intr_mask || tp->keep_intr_cnt-- > 0) {
                        u32 budget = ~(u32)0;
                        int i;

                        if (status & tp->intr_mask)
                                tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;

                        for (i = 0; i < tp->num_tx_rings; i++)
                                rtl8125_tx_interrupt(&tp->tx_ring[i], ~(u32)0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[0], &budget);
#else
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[0], budget);
#endif	//LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

#ifdef ENABLE_DASH_SUPPORT
                        if ((status & ISRIMR_V4_LAYER2_INTR_STS) &&
                            rtl8125_check_dash_interrupt(tp))
                                rtl8125_schedule_dash_work(tp);
#endif

                        rtl8125_switch_to_timer_interrupt(tp);
                } else {
                        tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;
                        rtl8125_switch_to_hw_interrupt(tp);
                }
#endif
        } while (false);

        return IRQ_RETVAL(handled);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance, struct pt_regs *regs)
#else
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance)
#endif
{
        struct r8125_napi *r8125napi = dev_instance;
        struct rtl8125_private *tp = r8125napi->priv;
        struct net_device *dev = tp->dev;
        int message_id = r8125napi->index;
#ifndef CONFIG_R8125_NAPI
        u32 budget = ~(u32)0;
#endif

        do {
#if defined(RTL_USE_NEW_INTR_API)
                if (!tp->irq_tbl[message_id].requested)
                        break;
#endif
                //link change
                if (message_id == rtl8125_get_linkchg_message_id(tp)) {
                        rtl8125_disable_hw_interrupt_v2(tp, message_id);
                        rtl8125_clear_hw_isr_v2(tp, message_id);
                        rtl8125_schedule_linkchg_work(tp);
                        break;
                }

#ifdef ENABLE_DASH_SUPPORT
                if (message_id == 31) {
                        if (rtl8125_check_dash_interrupt(tp))
                                rtl8125_disable_hw_interrupt_v2(tp, message_id);
                        rtl8125_clear_hw_isr_v2(tp, message_id);
                        rtl8125_schedule_dash_work(tp);
                        rtl8125_enable_hw_interrupt_v2(tp, message_id);
                        break;
                }
#endif

#ifdef CONFIG_R8125_NAPI
                if (likely(RTL_NETIF_RX_SCHEDULE_PREP(dev, &r8125napi->napi))) {
                        rtl8125_disable_hw_interrupt_v2(tp, message_id);
                        __RTL_NETIF_RX_SCHEDULE(dev, &r8125napi->napi);
                } else if (netif_msg_intr(tp))
                        printk(KERN_INFO "%s: interrupt message id %d in poll_msix\n",
                               dev->name, message_id);
                rtl8125_clear_hw_isr_v2(tp, message_id);
#else
                rtl8125_disable_hw_interrupt_v2(tp, message_id);

                rtl8125_clear_hw_isr_v2(tp, message_id);

                rtl8125_tx_interrupt_with_vector(tp, message_id, ~(u32)0);

                if (message_id < tp->num_rx_rings) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], &budget);
#else
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);
#endif	//LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                }

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
#endif

        } while (false);

        return IRQ_HANDLED;
}

static void rtl8125_down(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        //rtl8125_delete_esd_timer(dev, &tp->esd_timer);

        //rtl8125_delete_link_timer(dev, &tp->link_timer);

        netif_carrier_off(dev);

        netif_tx_disable(dev);

        _rtl8125_wait_for_quiescence(dev);

        rtl8125_hw_reset(dev);

        rtl8125_tx_clear(tp);

        rtl8125_rx_clear(tp);
}

static int rtl8125_resource_freed(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++)
                if (tp->tx_ring[i].TxDescArray)
                        return 0;

        for (i = 0; i < tp->num_rx_rings; i++)
                if (tp->rx_ring[i].RxDescArray)
                        return 0;

        return 1;
}

int rtl8125_close(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (!rtl8125_resource_freed(tp)) {
                set_bit(R8125_FLAG_DOWN, tp->task_flags);

                rtl8125_down(dev);

                pci_clear_master(tp->pci_dev);

#ifdef ENABLE_PTP_SUPPORT
                rtl8125_ptp_stop(tp);
#endif
                rtl8125_hw_d3_para(dev);

                rtl8125_powerdown_pll(dev, 0);

                rtl8125_free_irq(tp);

                rtl8125_free_alloc_resources(tp);
        } else {
                rtl8125_hw_d3_para(dev);

                rtl8125_powerdown_pll(dev, 0);
        }

        return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11)
static void rtl8125_shutdown(struct pci_dev *pdev)
{
        struct net_device *dev = pci_get_drvdata(pdev);
        struct rtl8125_private *tp = netdev_priv(dev);

        rtnl_lock();

        if (HW_DASH_SUPPORT_DASH(tp))
                rtl8125_driver_stop(tp);

        rtl8125_disable_pci_offset_180(tp);

        if (s5_keep_curr_mac == 0 && tp->random_mac == 0)
                rtl8125_rar_set(tp, tp->org_mac_addr);

        if (s5wol == 0)
                tp->wol_enabled = WOL_DISABLED;

        rtl8125_close(dev);
        rtl8125_disable_msi(pdev, tp);

        rtnl_unlock();

        if (system_state == SYSTEM_POWER_OFF) {
                pci_clear_master(tp->pci_dev);
                pci_wake_from_d3(pdev, tp->wol_enabled);
                pci_set_power_state(pdev, PCI_D3hot);
        }
}
#endif

#ifdef CONFIG_PM

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
static int
rtl8125_suspend(struct pci_dev *pdev, u32 state)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static int
rtl8125_suspend(struct device *device)
#else
static int
rtl8125_suspend(struct pci_dev *pdev, pm_message_t state)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        struct pci_dev *pdev = to_pci_dev(device);
        struct net_device *dev = pci_get_drvdata(pdev);
#else
        struct net_device *dev = pci_get_drvdata(pdev);
#endif
        struct rtl8125_private *tp = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        u32 pci_pm_state = pci_choose_state(pdev, state);
#endif
        rtnl_lock();

        if (!netif_running(dev))
                goto out;

        set_bit(R8125_FLAG_DOWN, tp->task_flags);

        netif_carrier_off(dev);

        netif_tx_disable(dev);

        netif_device_detach(dev);

#ifdef ENABLE_PTP_SUPPORT
        rtl8125_ptp_suspend(tp);
#endif
        rtl8125_hw_reset(dev);

        pci_clear_master(pdev);

        rtl8125_hw_d3_para(dev);

        rtl8125_powerdown_pll(dev, 1);

out:
        if (HW_DASH_SUPPORT_DASH(tp))
                rtl8125_driver_stop(tp);

        rtnl_unlock();

        pci_disable_device(pdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        pci_save_state(pdev, &pci_pm_state);
#else
        pci_save_state(pdev);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        pci_enable_wake(pdev, pci_choose_state(pdev, state), tp->wol_enabled);
#endif

        pci_prepare_to_sleep(pdev);

        return 0;
}

static int
rtl8125_hw_d3_not_power_off(struct net_device *dev)
{
        return rtl8125_check_hw_phy_mcu_code_ver(dev);
}

static int rtl8125_wait_phy_nway_complete_sleep(struct rtl8125_private *tp)
{
        int i, val;

        for (i = 0; i < 30; i++) {
                val = rtl8125_mdio_read(tp, MII_BMSR) & BMSR_ANEGCOMPLETE;
                if (val)
                        return 0;

                mdelay(100);
        }

        return -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
static int
rtl8125_resume(struct pci_dev *pdev)
#else
static int
rtl8125_resume(struct device *device)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        struct pci_dev *pdev = to_pci_dev(device);
        struct net_device *dev = pci_get_drvdata(pdev);
#else
        struct net_device *dev = pci_get_drvdata(pdev);
#endif
        struct rtl8125_private *tp = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        u32 pci_pm_state = PCI_D0;
#endif
        unsigned long flags;
        u32 err;

        rtnl_lock();

        err = pci_enable_device(pdev);
        if (err) {
                dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
                goto out_unlock;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        pci_restore_state(pdev, &pci_pm_state);
#else
        pci_restore_state(pdev);
#endif
        pci_enable_wake(pdev, PCI_D0, 0);

        /* restore last modified mac address */
        rtl8125_rar_set(tp, dev->dev_addr);

        r8125_spin_lock(&tp->phy_lock, flags);

        rtl8125_check_hw_phy_mcu_code_ver(dev);

        tp->resume_not_chg_speed = 0;
        if (tp->check_keep_link_speed &&
            //tp->link_ok(dev) &&
            rtl8125_hw_d3_not_power_off(dev) &&
            rtl8125_wait_phy_nway_complete_sleep(tp) == 0)
                tp->resume_not_chg_speed = 1;

        r8125_spin_unlock(&tp->phy_lock, flags);

        if (!netif_running(dev))
                goto out_unlock;

        pci_set_master(pdev);

        rtl8125_exit_oob(dev);

        rtl8125_up(dev);

        clear_bit(R8125_FLAG_DOWN, tp->task_flags);

        rtl8125_schedule_reset_work(tp);

        rtl8125_schedule_esd_work(tp);

#ifdef ENABLE_FIBER_SUPPORT
        if (HW_FIBER_MODE_ENABLED(tp))
                rtl8125_schedule_link_work(tp);
#endif /* ENABLE_FIBER_SUPPORT */

        //mod_timer(&tp->esd_timer, jiffies + RTL8125_ESD_TIMEOUT);
        //mod_timer(&tp->link_timer, jiffies + RTL8125_LINK_TIMEOUT);
out_unlock:
        netif_device_attach(dev);

        rtnl_unlock();

        return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)

static struct dev_pm_ops rtl8125_pm_ops = {
        .suspend = rtl8125_suspend,
        .resume = rtl8125_resume,
        .freeze = rtl8125_suspend,
        .thaw = rtl8125_resume,
        .poweroff = rtl8125_suspend,
        .restore = rtl8125_resume,
};

#define RTL8125_PM_OPS	(&rtl8125_pm_ops)

#endif

#else /* !CONFIG_PM */

#define RTL8125_PM_OPS	NULL

#endif /* CONFIG_PM */

static struct pci_driver rtl8125_pci_driver = {
        .name       = MODULENAME,
        .id_table   = rtl8125_pci_tbl,
        .probe      = rtl8125_init_one,
        .remove     = __devexit_p(rtl8125_remove_one),
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11)
        .shutdown   = rtl8125_shutdown,
#endif
#ifdef CONFIG_PM
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        .suspend    = rtl8125_suspend,
        .resume     = rtl8125_resume,
#else
        .driver.pm	= RTL8125_PM_OPS,
#endif
#endif
};

static int __init
rtl8125_init_module(void)
{
        int ret = 0;
#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_module_init();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        ret = pci_register_driver(&rtl8125_pci_driver);
#else
        ret = pci_module_init(&rtl8125_pci_driver);
#endif

        return ret;
}

static void __exit
rtl8125_cleanup_module(void)
{
        pci_unregister_driver(&rtl8125_pci_driver);

#ifdef ENABLE_R8125_PROCFS
        if (rtl8125_proc) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                remove_proc_subtree(MODULENAME, init_net.proc_net);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
                remove_proc_entry(MODULENAME, init_net.proc_net);
#else
                remove_proc_entry(MODULENAME, proc_net);
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                rtl8125_proc = NULL;
        }
#endif
}

module_init(rtl8125_init_module);
module_exit(rtl8125_cleanup_module);
