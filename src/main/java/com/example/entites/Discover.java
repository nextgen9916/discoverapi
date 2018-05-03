package com.example.entites;

public class Discover {

	private String ip;
	private String snmp;
	private String netconf;
	
	public String getIp() {
		return ip;
	}
	public void setIp(String ip) {
		this.ip = ip;
	}
	public String getSnmp() {
		return snmp;
	}
	public void setSnmp(String snmp) {
		this.snmp = snmp;
	}
	public String getNetconf() {
		return netconf;
	}
	public void setNetconf(String netconf) {
		this.netconf = netconf;
	}
	
	@Override
	public String toString() {
		return "Discover [ip=" + ip + ", snmp=" + snmp + ", netconf=" + netconf + "]";
	}
	
	
	
}
