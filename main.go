package main

import (
	"dannytools/ehand"
	"dannytools/logging"
	"dannytools/netip"
	"flag"
	"fmt"
	"os"
)

var (
	gLogger *logging.MyLog = &logging.MyLog{}
	gConf   *ConfCmd       = &ConfCmd{}
)

func main() {
	gLogger.CreateNewRawLogger()
	gConf.ParseCmdArgs()

	PrintIpAndRouterInfo(gConf.ShowInfoByOur, "before add/delete ip")
	if gConf.IfaddIp {
		gConf.AddIp()
	} else if gConf.IfDelIp {
		gConf.DeleteIp()
	} else {
		gLogger.WriteToLogByFieldsNormalOnlyMsg("unsupported action, only add/delete ip is allowed", logging.ERROR)
	}
	PrintIpAndRouterInfo(gConf.ShowInfoByOur, "after add/delete ip")
	os.Exit(0)
}

type ConfCmd struct {
	IfaddIp        bool
	IfDelIp        bool
	Iface          string // netiface
	Subnet         int    // subnet
	PeerIp         string // for add ip
	TargetIp       string // the ip to add/delete
	ShowInfoByOur  bool   // show ip info by the way the progam, otherwise by /sbin/ip a
	OnlyShowIpinfo bool   // show all ip info and exits
}

func (this *ConfCmd) ParseCmdArgs() {
	flag.BoolVar(&this.IfaddIp, "a", false, "add ip")
	flag.BoolVar(&this.IfDelIp, "d", false, "delete ip")
	flag.StringVar(&this.Iface, "i", "", "netiface to add/delete ip")
	flag.IntVar(&this.Subnet, "s", 24, "subnet/netmask bits")
	flag.StringVar(&this.PeerIp, "p", "", "use this peer ip on the same netiface to get netiface, subnet and gateway info. it is prefered to -i and -s")
	flag.StringVar(&this.TargetIp, "t", "", "ip to add/delete")
	flag.BoolVar(&this.ShowInfoByOur, "m", false, "show ip info in nice readable format, otherwise directly print output of /sbin/ip a")
	flag.BoolVar(&this.OnlyShowIpinfo, "o", false, "show all but loopback ip info in nice readable format, then exits, not add/delete ip")
	flag.Parse()

	if this.OnlyShowIpinfo {
		msg, err := netip.GetAllIpInfoMsg()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error to get ip info: %s\n", err)
			os.Exit(1)
		} else {
			fmt.Fprintln(os.Stdout, msg)
			os.Exit(0)
		}
	}

	if this.IfaddIp && this.IfDelIp {
		gLogger.WriteToLogByFieldsExitMsgNoErr("-a and -d are mutually exclusive.", logging.ERROR, ehand.ERR_INVALID_OPTION)
	}
	if !this.IfaddIp && !this.IfDelIp {
		gLogger.WriteToLogByFieldsExitMsgNoErr("-a or -d should be specify.", logging.ERROR, ehand.ERR_INVALID_OPTION)
	}
	if this.IfaddIp {
		if this.PeerIp == "" {
			if this.Iface == "" || this.Subnet == 0 {
				gLogger.WriteToLogByFieldsExitMsgNoErr("-p or (-i -s) must be specified to add ip", logging.ERROR, ehand.ERR_INVALID_OPTION)
			}
		}
	}
	if this.Subnet < 0 || this.Subnet > 32 {
		gLogger.WriteToLogByFieldsExitMsgNoErr("-s should be in range (0,32]", logging.ERROR, ehand.ERR_INVALID_OPTION)
	}

	if this.PeerIp != "" && !netip.CheckValidIpv4(this.PeerIp) {
		gLogger.WriteToLogByFieldsExitMsgNoErr(fmt.Sprintf("-p %s is invalid v4 ip addr", this.PeerIp), logging.ERROR, ehand.ERR_INVALID_OPTION)
	}

	if this.TargetIp == "" {
		gLogger.WriteToLogByFieldsExitMsgNoErr("target ip -t must be set", logging.ERROR, ehand.ERR_INVALID_OPTION)
	} else if !netip.CheckValidIpv4(this.TargetIp) {
		gLogger.WriteToLogByFieldsExitMsgNoErr(fmt.Sprintf("-t %s is invalid v4 ip addr", this.TargetIp), logging.ERROR, ehand.ERR_INVALID_OPTION)
	}

}

func (this *ConfCmd) AddIp() {
	var (
		err    error
		ipInfo netip.IpInfo
	)

	ipInfo, err = netip.GetTargetIpInfo("", true, this.TargetIp, true)
	if err == nil {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("target ip %s is already bonded on the server, skip adding ip\n%s",
			this.TargetIp, ipInfo.String(true)), logging.ERROR)
		return
	}

	if this.PeerIp == "" {
		err = netip.AddIp(this.TargetIp, this.Subnet, this.Iface)
		if err != nil {
			gLogger.WriteToLogByFieldsErrorExtramsgExit(err, fmt.Sprintf("error to add ip %s/%d to %s",
				this.TargetIp, this.Subnet, this.Iface), logging.ERROR, ehand.ERR_ERROR)
			return
		} else {
			gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("successfully add ip %s/%d to %s", this.TargetIp,
				this.Subnet, this.Iface), logging.INFO)
		}
		ipInfo, err = netip.GetTargetIpInfo(this.Iface, true, this.TargetIp, true)
		if err != nil {
			gLogger.WriteToLogByFieldsErrorExtramsgExitCode(err, fmt.Sprintf("after adding ip %s/%d to %s, error to get info of ip %s, not going to arping, but still mark adding ip success",
				this.TargetIp, this.Subnet, this.Iface, this.TargetIp), logging.ERROR, ehand.ERR_ERROR)
			//still mark as success
			return
		} else {
			gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("after adding ip, successfully get ip info: \n%s", ipInfo.String(true)), logging.INFO)
		}
	} else {
		ipInfo, err = netip.GetTargetIpInfo("", true, this.PeerIp, true)
		if err != nil {
			gLogger.WriteToLogByFieldsErrorExtramsgExit(err, fmt.Sprintf("before adding ip, error to get info of peer ip %s, cannot add ip %s",
				this.PeerIp, this.TargetIp), logging.ERROR, ehand.ERR_ERROR)
			return
		} else {
			gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("before adding ip, successfully get peer ip info: \n%s", ipInfo.String(true)), logging.INFO)
		}
		err = netip.AddIp(this.TargetIp, ipInfo.MaskBits, ipInfo.IfaceName)
		if err != nil {
			gLogger.WriteToLogByFieldsErrorExtramsgExit(err, fmt.Sprintf("error to add ip %s/%d to %s",
				this.TargetIp, ipInfo.MaskBits, ipInfo.IfaceName), logging.ERROR, ehand.ERR_ERROR)
			return
		} else {
			gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("successfully add ip %s/%d to %s", this.TargetIp,
				ipInfo.MaskBits, ipInfo.IfaceName), logging.INFO)
		}
	}

	// arping
	outMsg, err := netip.Arping(this.TargetIp, ipInfo.IfaceName, ipInfo.GateWays[0])
	if err != nil {
		gLogger.WriteToLogByFieldsErrorExtramsgExitCode(err, fmt.Sprintf("error to arping ip=%s iface=%s gateway=%s, but still mark adding ip success\n%s",
			this.TargetIp, ipInfo.IfaceName, ipInfo.GateWays[0], outMsg), logging.ERROR, ehand.ERR_ERROR)
	} else {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("successfully arping ip=%s iface=%s gateway=%s\n%s",
			this.TargetIp, ipInfo.IfaceName, ipInfo.GateWays[0], outMsg), logging.INFO)
	}
}

func (this *ConfCmd) DeleteIp() {
	var (
		err    error
		ipInfo netip.IpInfo
	)

	ipInfo, err = netip.GetTargetIpInfo("", true, this.TargetIp, false)
	if err != nil {
		gLogger.WriteToLogByFieldsErrorExtramsgExit(err, fmt.Sprintf("before deleting ip, error to get info of target ip %s, cannot delete it",
			this.TargetIp), logging.ERROR, ehand.ERR_ERROR)
		return
	} else if ipInfo.Addr == "" {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("target ip %s not found, skip delete it", this.TargetIp), logging.ERROR)
		return
	} else {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("before deleting ip, successfully get ip info: \n%s", ipInfo.String(true)), logging.INFO)
	}
	err = netip.DelIp(this.TargetIp, ipInfo.MaskBits, ipInfo.IfaceName)
	if err != nil {
		gLogger.WriteToLogByFieldsErrorExtramsgExit(err, fmt.Sprintf("error to delete ip %s/%d from %s",
			this.TargetIp, ipInfo.MaskBits, ipInfo.IfaceName), logging.ERROR, ehand.ERR_ERROR)
		return
	} else {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("successfully delete ip %s/%d from %s", this.TargetIp,
			ipInfo.MaskBits, ipInfo.IfaceName), logging.INFO)
	}

}

func PrintIpAndRouterInfo(ifNice bool, extMsg string) {
	var (
		msg string
		err error
	)
	if ifNice {
		msg, err = netip.GetAllIpInfoMsg()
	} else {
		msg, err = netip.GetIpAndRouterInfoString()
	}
	if err != nil {
		gLogger.WriteToLogByFieldsErrorExtramsgExitCode(err, fmt.Sprintf("%s, error to get ip and route info\n%s", extMsg, msg), logging.ERROR, ehand.ERR_ERROR)
	} else {
		gLogger.WriteToLogByFieldsNormalOnlyMsg(fmt.Sprintf("%s, successfully get ip and route info\n%s", extMsg, msg), logging.INFO)
	}
}
