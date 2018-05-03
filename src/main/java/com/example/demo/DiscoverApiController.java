package com.example.demo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.nmap4j.Nmap4j;
import org.nmap4j.core.nmap.ExecutionResults;
import org.nmap4j.data.NMapRun;
import org.nmap4j.data.nmaprun.Host;
import org.nmap4j.parser.OnePassParser;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.entites.Discover;
import com.example.entites.Resolution;

@RestController
public class DiscoverApiController {

	@RequestMapping(value="/insert/{ipaddress:.+}",method=RequestMethod.GET)
	public void getNmaPDetails(HttpServletResponse response,@PathVariable("ipaddress") String paramName) throws IOException {
		
		String originalvalue = paramName.replaceAll("_","/");
		
		 Nmap4j nmap4j = new Nmap4j("/usr") ;
	   	 nmap4j.includeHosts(originalvalue) ;   	 
	   	 nmap4j.addFlags("--privileged --min-parallelism 1 -sT -sU -p 161,2022");
	   	 System.out.println("Completed NMAP");
	   	  try{
	   	  nmap4j.execute() ; 
	   	 }catch(Exception e){
	   		 e.printStackTrace();
	   	  System.out.println("error execute");

	   	 }
	   	 if( !nmap4j.hasError() ) { 

		   		ExecutionResults res = nmap4j.getExecutionResults();
		   		String nmapRun = nmap4j.getOutput() ;
		   	   	
		   	   	OnePassParser opp = new OnePassParser() ;
		   	   	NMapRun nmapRun1 = opp.parse( nmapRun, OnePassParser.STRING_INPUT ) ;
		   	   	ArrayList<Host> hosts=nmapRun1.getHosts(); 
		   	   	System.out.println("File Creation Starts");
		   	 	FileWriter fw = new FileWriter("/home/discoverinfo.txt");
		   	   	   	
		   	   	for(Host ipAddr:hosts) {   	   		
		   	  
		   	    if(fw != null) {
		   	    	fw.write(ipAddr.getAddresses().get(0).getAddr());
		   	    	fw.append("Snmp");
		   	    	fw.write(ipAddr.getPorts().getPorts().get(2).getState().getState());
		   	    	fw.append("Netconf");
		   	    	fw.write(ipAddr.getPorts().getPorts().get(1).getState().getState()+"\n");
		   	    }
		   	
		  	}
		   	 fw.close();
		   	  System.out.println(""+res.getOutput()+"\n");
		   	 }
	   	  else {
	   	   System.out.println( nmap4j.getExecutionResults().getErrors() ) ; 
	   	   }	   		
	}
	
	@RequestMapping(value="/{ipaddress:.+}",method=RequestMethod.GET)
	public void fetchingData(HttpServletResponse response,@PathVariable("ipaddress") String ipadd) throws IOException{
		
		System.out.println("entering fetchingData");
		PrintWriter out = response.getWriter();
		String ips="";
		String snmp="";
		String netconf="";
		String none="";
		String ipaddress="";
		List<Discover> discoverlist = new ArrayList<Discover>();
		String filterip="";
		String beforeSnmp="";
		String aftersnmp="";
		
		List<String> list = Files.readAllLines(new File("/home/discoverinfo.txt").toPath(), Charset.defaultCharset() );
		for(String li : list) {
			Discover dis = new Discover();
			
			filterip = before(li, "Snmp");
			beforeSnmp = after(li, "Snmp");
			snmp = before(beforeSnmp, "Netconf");
			
			aftersnmp = after(li, "Netconf");
			
			if(ipadd.contains(filterip) ) {
			dis.setIp(filterip);
			dis.setNetconf(aftersnmp);
			dis.setSnmp(snmp);
			discoverlist.add(dis);
			}
		}

		for(Discover ls:discoverlist ){
			
			if(ls.getSnmp() != null){
				if(ls.getSnmp().contains("open")){
					snmp ="Snmp";
					ips = ls.getIp()+" = "+ snmp;
				}else if(ls.getSnmp().contains("closed")){
					none = "None";
					ips = ls.getIp()+" = "+  none;
				}
					
				
			}else if(ls.getNetconf() != null){
				if(ls.getNetconf().contains("open")){
					netconf ="Netconf";
					ips = ls.getIp()+" = "+  netconf;
				}else if(ls.getNetconf().contains("closed")){
					none = "None";
					ips = ls.getIp()+" = "+  none;
				}
			}else if(ls.getSnmp().contains("closed") || ls.getNetconf().contains("closed")){
				
				none += "None";
				ips = ls.getIp()+" = "+  none;
			}
			
			ipaddress = ls.getIp();
		}
		out.println(ips);
		
	}
	
	
	@RequestMapping(value="/fetch",method=RequestMethod.GET)
	public void fetchingData(HttpServletResponse response) throws IOException {

		System.out.println("entering fetchingData");

		PrintWriter out = response.getWriter();
		String ips="";
		String none="";
		String ipaddress="";
		List<Discover> discoverlist = new ArrayList<Discover>();
		String filterip="";
		String beforeSnmp="";
		String aftersnmp="";
		
		List<String> list = Files.readAllLines(new File("/home/discoverinfo.txt").toPath(), Charset.defaultCharset() );
		for(String li : list) {
			Discover dis = new Discover();
			filterip = before(li, "Snmp");
			beforeSnmp = before(li, "Netconf");
			aftersnmp = after(li, "Netconf");
			dis.setIp(filterip);
			dis.setNetconf(beforeSnmp);
			dis.setSnmp(aftersnmp);
			discoverlist.add(dis);
		}

			String snmp = "Snmp";
			String netconf = "Netconf";
			String snmpnetconf = "";

			for (Discover rs : discoverlist) {
				if (rs.getSnmp().equalsIgnoreCase(("open"))) {
					snmpnetconf = rs.getIp();
					out.println(snmpnetconf);
					System.out.println("Snmp" + snmpnetconf);
				} else if (rs.getSnmp().equalsIgnoreCase("open|filtered")) {
					snmpnetconf = rs.getIp();
					out.println(snmpnetconf);
					System.out.println("Snmp" + snmpnetconf);
				} else if (rs.getNetconf().contains("open")) {
					snmpnetconf = rs.getIp();
					out.println(snmpnetconf);
					System.out.println("Netconf" + snmpnetconf);
				} else if (rs.getNetconf().contains("open|filtered")) {
					snmpnetconf = rs.getIp();
					out.println(snmpnetconf);
					System.out.println("Netconf" + snmpnetconf);
				}

			}


		out.close();
	}		

	
	 static String before(String value, String a) {
	        // Return substring containing all characters before a string.
	        int posA = value.indexOf(a);
	        if (posA == -1) {
	            return "";
	        }
	        return value.substring(0, posA);
	    }
	 
	 static String after(String value, String a) {
	        // Returns a substring containing all characters after a string.
	        int posA = value.lastIndexOf(a);
	        if (posA == -1) {
	            return "";
	        }
	        int adjustedPosA = posA + a.length();
	        if (adjustedPosA >= value.length()) {
	            return "";
	        }
	        return value.substring(adjustedPosA);
	    }
	 
}
