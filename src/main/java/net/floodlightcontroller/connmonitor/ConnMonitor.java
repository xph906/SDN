package net.floodlightcontroller.connmonitor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFSetConfig;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFSwitchConfig.OFConfigFlags;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;

import net.floodlightcontroller.connmonitor.ForwardFlowItem.ForwardFLowItemState;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;

public class ConnMonitor extends ForwardingBase implements IFloodlightModule,IOFMessageListener, IOFSwitchListener, IConnMonitorService {
	//FIXME: move these to configure file
	static short HARD_TIMEOUT = 0;
	static short IDLE_TIMEOUT = 300;
	static short HIH_HARD_TIMEOUT = 300;
	static short HIH_IDLE_TIMEOUT = 60;
	static short DELTA = 50;
	static long CONN_TIMEOUT = 300000;
	static short HIGH_PRIORITY = 20;
	static short DEFAULT_PRIORITY = 5;
	static short DROP_PRIORITY = 0;
	static short HIGH_DROP_PRIORITY = 100;
	static short HIGH_DROP_TIMEOUT = 300;
	static long LASSEN_SW = 203050741063572L;
	static long MISSOURI_SW = 161340422318L;
	static int CONN_MAX_SIZE = 100000;
	static String hih_manager_url = "http://localhost:55551/inform";
	static String honeypotConfigFileName = "honeypots.config";
	static String PortsConfigFileName = "ports.config";
	
	static byte[] lassen_mac_address = {(byte)0xb8,(byte) 0xac,(byte)0x6f,(byte)0x4a,(byte) 0xdf,(byte) 0x94};
	static short lassen_default_out_port = 9; //port number for eth0
	static byte[] missouri_mac_address = {(byte)0x00, (byte)0x25, (byte)0x90, (byte)0xA3, (byte)0x78, (byte)0xAE};
	static short missouri_default_out_port = 1;
	static byte[] nc_mac_address = {(byte)0x00, (byte)0x30, (byte)0x48, (byte)0x30, (byte)0x03, (byte)0xAF};
	
	static byte[] honeypot_net = {(byte)192,(byte)168,(byte)1, (byte)0};
	static int honeypot_net_mask = 8;
	static byte[] public_honeypot_net = {(byte)130, (byte)107, (byte)0, (byte)0};
	static int public_honeypot_net_mask = 16;
	
	//FIXME: move these to configure file 
	//static byte[] nw_ip_address = {(byte)129,(byte)105,(byte)44, (byte)107};
	static byte[] test_ip_address_in = {(byte)130,(byte)107,(byte)240, (byte)188};
	static byte[] test_ip_address_out = {(byte)112,(byte)221,(byte)111, (byte)111};
	/*
	 * only for test... 
	 */
	//static byte[] heather_download_address = {(byte)130, (byte)107, (byte)128, (byte)143}; //FIXME
	static byte[] migration_ip_address = {(byte)10,(byte)1,(byte)1, (byte)10};
	static byte[] migration_mac_address = {(byte)0x62, (byte)0x04, (byte)0xc6, (byte)0x49, (byte)0xb0, (byte)0x2e};
	static short migration_out_port = 6;
	static byte migration_type = HoneyPot.HIGH_INTERACTION;
	
	static byte[] garuda_src_ip = {(byte)129,(byte)105,(byte)44,(byte)99 };
	static byte[] dod_src_ip = {(byte)129,(byte)105,(byte)44,(byte)60 };
	static byte[] a_src_ip = {(byte)24,(byte)13,(byte)81,(byte)140 };
	
	static byte[] neighbor_ip_address = {(byte)10,(byte)1,(byte)1, (byte)2};
	static byte[] neighbor_mac_address = {(byte)0x08, (byte)0x00, (byte)0x27, (byte)0xeb, (byte)0x66, (byte)0xbb};
	static short neighbor_out_port = 5;
	
	static byte[] snooper_ip_address = {(byte)10,(byte)1,(byte)1, (byte)21};
	static short snooper_out_port = 19;
	
	String migrationEngineIP = "130.107.10.50";
	short migrationEngineListenPort = 22222;
	
	/*
	 * These five tables' sizes are fixed.
	 * no worry about memory leak...
	 */
	protected Hashtable<String,HoneyPot> honeypots;
	private Hashtable<String,Long> switches;
	protected Hashtable<Short, Vector<HoneyPot>> ports;
	protected Hashtable<Short, Vector<HoneyPot>> portsForHIH;
	protected Hashtable<String,Boolean> HIHAvailabilityMap; 
	protected Hashtable<Long, String > HIHNameMap;
	protected Hashtable<String, Integer> HIHFlowCount;

	/*
	 * These tables's sizes will get increased 
	 * Make sure they will NOT increase infinitely...
	 */
	protected Hashtable<Long,Connection> connMap;
	protected Hashtable<String, Connection> connToPot;
	protected Hashtable<String, HashSet<Integer> > HIHClientMap;
	protected ForwardFlowTable forwardFlowTable;

	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	
	private ExecutorService executor;
	
	protected MyLogger logger;
	static Date currentTime = new Date();
	
	private long lastClearConnMapTime;
	private long lastClearConnToPotTime;
	private long lastTime;
	
	private long packetCounter;
	private long droppedCounter;
	private long droppedHIHCounter;
	
	BlockingQueue<ForwardFlowItem> flowRemovedTasks;
	BlockingQueue<ForwardFlowItem> flowRemovedDoneTasks;
	
	@Override
	public String getName() {
		return  ConnMonitor.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	/*
	 * DownloadIP:	130.107.1XXXXXXX.1XXXXXX1
	 * OpenIP:		130.107.1XXXXXXX.1XXXXXX0 => 13 valid bits
	 * srcIP/13 => one OpenIP
	 */
	static public int getOpenAddress(int srcIP){
		/* get first 13 bits 0x00 00 1F FF */
		int net = (srcIP>>19)&(0x00001FFF);
		int first7 = (net>>6)&(0x0000007F);
		int last6 = (net)&(0x0000003F);
		int c = first7 | 128;      //1 first7
		int d = (last6<<1) | 128;  //1 last6 0
		int dstIP = ((130<<24) | (107<<16) | (c<<8) | d);
		return dstIP;
	}
	
	private String buildMessageForHIHManager(String name, String type, String time){
		String url = hih_manager_url+"?name="+name+"&type="+type;
		if(time != null)
			url += "&time="+time;
		return url;
	}
	
	private net.floodlightcontroller.core.IListener.Command PacketInMsgHandler(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		packetCounter++;
		
		if(sw.getId() == MISSOURI_SW){
			Ethernet eth =
	                IFloodlightProviderService.bcStore.get(cntx,
	                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			Connection conn = new Connection(eth);
			/*OFPacketIn packet_in_msg = (OFPacketIn)msg;
			boolean no_buffer_id = false;
			if (packet_in_msg.getBufferId() == 0xffffffff){
				no_buffer_id = true;
			}*/
			
			/* For statistics */
			if((conn.getType()==Connection.INTERNAL_TO_EXTERNAL) && 
				(conn.getProtocol()==0x06)){
				long now = System.currentTimeMillis();
				long five_min = 60000*10;
				if(now - lastTime > five_min){		
					Date date = new Date(now);
					float rs = (float)(packetCounter-droppedCounter)/(float)(packetCounter);
					logger.LogDebug("In five mins: pkt counter: "+packetCounter+" dropped counter:"+droppedCounter+" rs:"+rs+" time:"+date.toString());
					OFMatch match = new OFMatch();
					match.setWildcards(OFMatch.OFPFW_ALL); 
					int mb = 1024*1024;
					Runtime runtime = Runtime.getRuntime();
					long free_memory = runtime.freeMemory()/mb;
					long total_memory = runtime.totalMemory()/mb;
								
					logger.LogDebug("free memory: "+free_memory+" Total memory:"+total_memory);
					logger.LogDebug("connection size: "+connMap.size()+" connToPot size:"+connToPot.size());
					if (free_memory < 100){
						forceClearMaps();
						logger.LogDebug("Force clear maps!!!");
					}
					logger.LogDebug("");
					packetCounter = 1;
					droppedCounter = 1;
					lastTime = now;
				}
			}
			if(conn.srcIP==0 || conn.type==Connection.INVALID){
				droppedCounter++;
				return Command.CONTINUE;
			}
			int x = 2;
			int y = 1;
			y += 1;
			if(processedByOtherHoneynets(conn, ((OFPacketIn)msg).getInPort(), sw,msg, eth) ){
				return Command.CONTINUE;
			}
			else if(x==y){
				return Command.CONTINUE;
			}
			
			HoneyPot pot = getHoneypotFromConnection(conn);
			if(pot == null){
				droppedCounter++;
				return Command.CONTINUE;
			}
			conn.setHoneyPot(pot);
			Long key = conn.getConnectionSimplifiedKey();
	
			Connection e2IFlow = null;
			byte[] srcIP = null;
			
			if(connMap.containsKey(key)){	
				e2IFlow = connMap.get(key);
				if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
					String connKey = 
							Connection.createConnKeyString(conn.getDstIP(), conn.getDstPort(), e2IFlow.dstIP, conn.getSrcPort());
					if(connToPot.containsKey(connKey) && (connToPot.get(connKey).pot.getName().equals(conn.pot.getName())) ){
						connToPot.get(connKey).updateTime();
					}
					else if((e2IFlow.dstIP != conn.dstIP)){
						if(e2IFlow.isConnExpire(CONN_TIMEOUT)){
							connMap.put(key, conn);
						}
						else{
							int openIP = getOpenAddress(conn.srcIP);
							if(openIP == conn.dstIP){
								logger.LogDebug("hit open IP: "+ IPv4.fromIPv4Address(conn.srcIP)+" "+IPv4.fromIPv4Address(conn.dstIP));
							}
							else{
								return Command.CONTINUE;
							}
						}
					}
					else
					{
						e2IFlow.updateTime();
					}
				}
				else if(conn.type==Connection.INTERNAL_TO_EXTERNAL){
					srcIP = IPv4.toIPv4AddressBytes(e2IFlow.dstIP);
					if(e2IFlow.getHoneyPot()==null){
						e2IFlow.setHoneyPot(getHoneypotFromConnection(e2IFlow));
					}	
					String connKey = 
							Connection.createConnKeyString(conn.getDstIP(), conn.getDstPort(), e2IFlow.dstIP, conn.getSrcPort());
					
					if(connToPot.containsKey(connKey)){
						if(connToPot.get(connKey).getHoneyPot().getName().equals( conn.getHoneyPot().getName())){
							connToPot.get(connKey).updateTime();
						}
						else{
							connToPot.put(connKey, conn);
						}
					}
					else{
						connToPot.put(connKey, conn);
					}
					if(conn.getHoneyPot().getType()==HoneyPot.HIGH_INTERACTION){
						if(!( HIHClientMap.containsKey( conn.getHoneyPot().getName() )) ){
							HIHClientMap.put(conn.getHoneyPot().getName(), new HashSet<Integer>() );
						}
						HIHClientMap.get(conn.getHoneyPot().getName()).add(conn.getDstIP());	
					}
					clearMaps();
					
				}
				else{
					logger.LogError("shouldn't come here "+conn);
					return Command.CONTINUE;
				}
			}
			else{ //no such connection
				if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
					connMap.put(key, conn);
					if(conn.pot.getType()==HoneyPot.HIGH_INTERACTION){
						logger.LogDebug("allocate HIGH_INTERACTION honeypot for connection "+conn);
						//inform hih manager
						String url = buildMessageForHIHManager(conn.pot.getName(),"newvm",null);
						try {
							executor.submit(new Request(new URL(url)));
						} catch (MalformedURLException e) {
							logger.LogError("error sending request");
							e.printStackTrace();
						}
						if(HIHAvailabilityMap.get(conn.pot.getName())==false){
							logger.LogError("error inconsistency "+conn.pot.getName()+" ");
							droppedHIHCounter++;
							return Command.CONTINUE;
						}
						if(conn.getHoneyPot().getType()==HoneyPot.HIGH_INTERACTION){
							if(!( HIHClientMap.containsKey( conn.getHoneyPot().getName() )) ){
								HIHClientMap.put(conn.getHoneyPot().getName(), new HashSet<Integer>() );
							}
							HIHClientMap.get(conn.getHoneyPot().getName()).add(conn.getSrcIP());	
						}
						HIHAvailabilityMap.put(conn.pot.getName(), false);
					}
					clearMaps();
					//logger.info("2 new e2i connection, assigned to "+key+" "+conn);
				}
				else if(conn.type==Connection.INTERNAL_TO_EXTERNAL){
					conn.setSrcIP(conn.getHoneyPot().getDownloadAddrInt());
					e2IFlow = new Connection(conn);
					e2IFlow.setHoneyPot(conn.getHoneyPot());				
					
					srcIP = pot.getDownloadAddress();
					String connKey = 
							Connection.createConnKeyString(conn.getDstIP(), conn.getDstPort(), 
											conn.getHoneyPot().getDownloadAddrInt(), conn.getSrcPort());
					if(connToPot.containsKey(connKey)){
						if(connToPot.get(connKey).getHoneyPot().getName().equals( conn.getHoneyPot().getName())){
							connToPot.get(connKey).updateTime();
						}
						else{
							connToPot.put(connKey, conn);
						}
					}
					else{
						connToPot.put(connKey, conn);
					}
					if(conn.getHoneyPot().getType()==HoneyPot.HIGH_INTERACTION){
						if(!( HIHClientMap.containsKey( conn.getHoneyPot().getName() )) ){
							HIHClientMap.put(conn.getHoneyPot().getName(), new HashSet<Integer>() );
						}
						HIHClientMap.get(conn.getHoneyPot().getName()).add(conn.getDstIP());	
					}
				}
				else{
					logger.LogError("shouldn't come here 2 "+conn);
					return Command.CONTINUE;
				}
			}
			
			OFPacketIn pktInMsg = (OFPacketIn)msg;
			OFMatch match = null;
			byte[] newDstMAC = null;
			byte[] newDstIP = null;
 			short outPort = 0;
 			boolean result1 = true;
 			
 			if( conn.pot.getType() == HoneyPot.HIGH_INTERACTION  ){
 				/* High Interaction Honeypot (HIH)'s flow is different:
 				 *   1. we guarantee e2i flow expire before i2e flow
 				 *   2. we handle flow removal message only for e2i flow
 				 *   3. e2i flow will be set idle timeout, i2e will not
 				 */
 				//i2e
 				match = new OFMatch();
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.srcIP);
				match.setNetworkSource(conn.getHoneyPot().getIpAddrInt());
				match.setInputPort(conn.pot.getOutPort());
				match.setTransportSource(conn.dstPort);
				match.setTransportDestination(conn.srcPort);
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	
					OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
					OFMatch.OFPFW_NW_TOS |   
					OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );	
				newDstMAC = nc_mac_address;	
				outPort = missouri_default_out_port;
				byte[] newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);
				result1 = 
					installPathForFlow(sw.getId(),conn.pot.getOutPort(),match,(short)0,conn.pot.getId(), 
							newDstMAC,newDstIP,newSrcIP,
							(short)0, (short)0,
							outPort,(short)0,(short)(HIH_HARD_TIMEOUT+DELTA),HIGH_PRIORITY);
				
				//e2i
				match = new OFMatch();	
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.dstIP);
				match.setNetworkSource(conn.srcIP);
				match.setTransportSource(conn.srcPort);
				match.setTransportDestination(conn.dstPort);
				match.setInputPort(pktInMsg.getInPort());
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	
						OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
						 OFMatch.OFPFW_NW_TOS |   
						OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
				newDstMAC = conn.pot.getMacAddress();
				newDstIP = conn.getHoneyPot().getIpAddress();
				outPort = conn.pot.getOutPort();
				boolean result2 = 
						installPathForFlow(sw.getId(),pktInMsg.getInPort(),match,OFFlowMod.OFPFF_SEND_FLOW_REM,conn.pot.getId(), 
										newDstMAC,newDstIP,srcIP,(short)0, (short)0,outPort,HIH_IDLE_TIMEOUT,HIH_HARD_TIMEOUT,HIGH_PRIORITY);
					
				result1 &= result2;
				int count = HIHFlowCount.get(conn.getHoneyPot().getName());
				count++;
				HIHFlowCount.put(conn.getHoneyPot().getName(), count);
 			}
 			else if(conn.type == Connection.EXTERNAL_TO_INTERNAL){
	
				match = new OFMatch();
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.srcIP);
				match.setNetworkSource(conn.getHoneyPot().getIpAddrInt());
				match.setInputPort(pktInMsg.getInPort());
				match.setTransportSource(conn.dstPort);
				match.setTransportDestination(conn.srcPort);
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	
					OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
					OFMatch.OFPFW_NW_TOS |   
					OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );
				newDstMAC = nc_mac_address;
				outPort = pktInMsg.getInPort();
				byte[] newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);	
				result1 = installPathForFlow(sw.getId(),pktInMsg.getInPort(),match,(short)0,(long)0, 
									newDstMAC,newDstIP,newSrcIP,(short)0, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
					
				match = new OFMatch();	
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.dstIP);
				match.setNetworkSource(conn.srcIP);
				match.setTransportSource(conn.srcPort);
				match.setTransportDestination(conn.dstPort);
				match.setInputPort(pktInMsg.getInPort());
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	
						OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
						 OFMatch.OFPFW_NW_TOS |   
						OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
				newDstMAC = lassen_mac_address;
				newDstIP = conn.getHoneyPot().getIpAddress();
				outPort = pktInMsg.getInPort();
				boolean result2 = installPathForFlow(sw.getId(),pktInMsg.getInPort(),match,(short)0,(long)0,
									newDstMAC,newDstIP,srcIP,(short)0, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);			
				result1 &= result2;
			}
			else if(conn.type == Connection.INTERNAL_TO_EXTERNAL){
				match = new OFMatch();
				//FIXME: no need to set strict match here
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.dstIP);
				match.setNetworkSource(e2IFlow.getHoneyPot().getIpAddrInt());
				match.setInputPort(pktInMsg.getInPort());
				match.setTransportSource(conn.srcPort);
				match.setTransportDestination(conn.dstPort);
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	
						OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
						OFMatch.OFPFW_NW_TOS |   
						OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );
				
				newDstMAC = nc_mac_address;
				outPort = pktInMsg.getInPort();
				result1 = installPathForFlow(sw.getId(), pktInMsg.getInPort(),match,(short)0,(long)0,
										newDstMAC,newDstIP,srcIP,(short)0, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
			}
			else{
				logger.LogError("shouldn't come here 3 "+conn);
				return Command.CONTINUE;
			}
			//forwardPacket(sw,pktInMsg, dstMAC,dstIP,srcIP,outPort);
			boolean result2 = forwardPacket(sw,pktInMsg, newDstMAC,newDstIP,srcIP,outPort, eth);
			
			if(!result1 || !result2){
				logger.LogError("fail to install rule for "+conn);
			}
		}
		else if(sw.getId() == LASSEN_SW){
			logger.LogError("Ignore packets sent from LASSEN_SW");
			initLassenSwitch(sw.getId());
		}
		else{
			logger.LogDebug("Unknown switch: "+sw.getStringId());
		}
		
	     return Command.CONTINUE; 
	}
	
	private net.floodlightcontroller.core.IListener.Command FlowRemovedMsgHandler(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		if(msg instanceof OFFlowRemoved){
			OFFlowRemoved removedMsg = (OFFlowRemoved)msg;
			if(removedMsg.getReason()==OFFlowRemoved.OFFlowRemovedReason.OFPRR_DELETE){
				return Command.CONTINUE;
			}
			/*	
			 *  Add codes here to detect ForwardFlow gets removed 
			 * 	remember to update cookie_key_map, table and send request to NW
			 */
			int dstIP = removedMsg.getMatch().getNetworkDestination();
			int srcIP = removedMsg.getMatch().getNetworkSource();
			for(Honeynet net : Honeynet.getAllHoneynets()){
				
				String name = net.getName();
				Honeynet.SubnetMask mask = net.getMask();
				System.err.println("remove flows: test for honeynet "+name+" mask:"+mask+" src_ip:"+IPv4.fromIPv4Address(srcIP)+" dst_ip:"+IPv4.fromIPv4Address(dstIP));
				if(Honeynet.inSubnet(mask, dstIP) || Honeynet.inSubnet(mask, srcIP) ){
					long cookie = removedMsg.getCookie();
					System.err.println("    remove flows: flow belonging to "+name+" with cookie:"+cookie);
					String key = forwardFlowTable.fromCookieToKey(cookie);
					if(key == null){
						System.err.println("    the item has already been removed from forwardFlowTable");
						return Command.CONTINUE;
					}
					forwardFlowTable.removeCookieStringMap(cookie);
					ForwardFlowItem item = forwardFlowTable.get(key);
					if(item == null){
						System.err.println("    can't find this item from forwardFlowTable");
						return Command.CONTINUE;
					}
					item.setState(ForwardFLowItemState.WAIT_FOR_DEL_ACK);
					deleteForwardRule(sw,item);
					informNWToDestroyFlowInfo(item);
					System.err.println("    done handling forward rules removed msg "+cookie);
					return Command.CONTINUE;
				}
			}
			
			
			if(removedMsg.getReason()==OFFlowRemoved.OFFlowRemovedReason.OFPRR_HARD_TIMEOUT){
				logger.LogDebug("TODO: FlowRemovedMsgHandler handle OFPRR_HARD_TIMEOUT");
				return Command.CONTINUE;
			}
			else{
				/* send destroy msg to manager */
				long cookie = removedMsg.getCookie();
				String honeypotName = null;
				if(HIHNameMap.containsKey(cookie)){
					honeypotName = HIHNameMap.get(cookie);
				}
				if(honeypotName != null){
					int count = HIHFlowCount.get(honeypotName) - 1;
					
					if(count > 0){
						logger.LogDebug("flow for vm: "+honeypotName+" gets removed. "+count+" has left");
						HIHFlowCount.put(honeypotName, count);
					}
					else if(count <= 0){
						logger.LogDebug("flow for vm: "+honeypotName+" gets removed. leave vm");
						HIHFlowCount.put(honeypotName, 0);
						String url = buildMessageForHIHManager(honeypotName, "leavevm", null);
						try {
							executor.submit(new Request(new URL(url)));
						} catch (MalformedURLException e) {
							logger.LogError("fail to send leavevm request");
							e.printStackTrace();
						}
					}
				}
				else{
					logger.LogError("invalid cookie! "+cookie);
				}
				return Command.CONTINUE;
			}
		}
		else{
		}
		return Command.CONTINUE;
	}
	
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() == OFType.PACKET_IN) 
		{ 
			return PacketInMsgHandler(sw,msg,cntx);
		}	
		else if(msg.getType() == OFType.FLOW_REMOVED){
			return FlowRemovedMsgHandler(sw,msg,cntx);
		}
		else{
		}
		return Command.CONTINUE;    
	}

	private HoneyPot getHoneypotFromConnection(Connection conn){
		if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
			short dport = conn.getDstPort();
			int dstIP = conn.getDstIP();
			int flag = (dstIP>>8)&0x000000e0;
			
			/* Test codes, can be deleted */
			int g_ip = IPv4.toIPv4Address(garuda_src_ip);
			int d_ip = IPv4.toIPv4Address(dod_src_ip);
			int a_ip = IPv4.toIPv4Address(a_src_ip);
			if(((conn.srcIP==g_ip) || (conn.srcIP==d_ip)) && (dport==(short)23) ){
				logger.LogDebug("return kippo for 23");
				return honeypots.get("kippo");
			}
			if((conn.srcIP == g_ip) && ((dport==(short)445) || (dport==(short)139) || (dport==(short)139))){
				return honeypots.get("lily_winxp3");
			}
			/* End of Test Codes */
			
			/* if we have records for this connection, use existing honeypot */
			String key = 
					Connection.createConnKeyString(conn.getSrcIP(), conn.getSrcPort(), conn.getDstIP(), conn.getDstPort());
			if(connToPot.containsKey(key)){
				if(!(connToPot.get(key).isConnExpire(CONN_TIMEOUT))){
					connToPot.get(key).updateTime();
					return connToPot.get(key).getHoneyPot();
				}
			}
			
			/* otherwise, we allocate honeypot based on default policy */
			/* first check if this port can be addressed by HIH */
			if(portsForHIH.containsKey(dport)){
				/* check if this src already has one HIH */
				Iterator<Map.Entry<String, HashSet<Integer>>> it1 = HIHClientMap.entrySet().iterator();
				while (it1.hasNext()) {
					  Map.Entry<String, HashSet<Integer>> entry = it1.next();
					  HashSet<Integer> ips = HIHClientMap.get(entry.getKey());
					  for(Integer ip : ips){
						  if(ip == conn.getSrcIP()){
							  logger.LogDebug("choose HIH honeypot [old src] "+entry.getKey()+" "+entry.getValue() +conn);
							  return honeypots.get(entry.getKey());
						  }
					  }
				}
				/* check if we have available HIH */
				Iterator<Map.Entry<String, Boolean>> it2 = HIHAvailabilityMap.entrySet().iterator();
				while (it2.hasNext()) {
					Map.Entry<String, Boolean> entry = it2.next();
					if(entry.getValue() == true){
						HoneyPot pot = honeypots.get(entry.getKey());
						if(pot.getMask().containsKey(dport) && pot.getMask().get(dport).inSubnet(dstIP)){
							logger.LogError("choose HIH honeypot [new src] "+entry.getKey()+" "+entry.getValue() +conn);
							return honeypots.get(entry.getKey()); 
						}
					}
				}
			}
			
			/* if not, find a LIH to address the port */
			if(ports.containsKey(dport)){
				Vector<HoneyPot> pots = ports.get(dport);
				for(HoneyPot pot : pots){	
					if(pot.getMask().containsKey(dport) && pot.getMask().get(dport).inSubnet(dstIP)){
						return pot;
					}
				}
				logger.LogError("can't address dstIP "+IPv4.fromIPv4Address(dstIP)+ dport+" ");
				for(HoneyPot pot : pots){	
					logger.LogError(pot.getName()+" containsKey:"+pot.getMask().containsKey(dport));
					if(pot.getMask().containsKey(dport))
						logger.LogError(pot.getName()+" :"+pot.getMask().get(dport)+" "+pot.getMask().get(dport).inSubnet(dstIP));
				}
				return null;
			}
			else{
				logger.LogDebug("can't address port "+dport);
				//for(short p : ports.keySet()){
				//	System.err.println("debug: port:"+p);
				//}
				return null;
			}
		
		}
		else if(conn.type == Connection.INTERNAL_TO_EXTERNAL){	
			 for (HoneyPot pot: honeypots.values()) {
				 if(pot.getIpAddrInt() == conn.getSrcIP()){
					 return pot;
				 }
			 }
		}
		return null;
	}
	
	
	private boolean initMissouriSwitch(long switchId){
		IOFSwitch sw = floodlightProvider.getSwitch(switchId);
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(public_honeypot_net));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_SRC_ALL| public_honeypot_net_mask<<OFMatch.OFPFW_NW_DST_SHIFT|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		byte[] newDstMAC = null;
		byte[] newDstIP = null;
		byte[] newSrcIP = null;
		short outPort = OFPort.OFPP_CONTROLLER.getValue();
		boolean result = 
				installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newDstMAC,newDstIP,newSrcIP,
							(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		
		if(!result){
			logger.LogError("fail to create default rule1 for MISSOURI 1");
			System.exit(1);
			return false;
		}
		
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(honeypot_net));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL| honeypot_net_mask<<OFMatch.OFPFW_NW_SRC_SHIFT|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newDstMAC,newDstIP,newSrcIP,
							(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		
		if(!result){
			logger.LogError("fail to create default rule1 for MISSOURI 2");
			System.exit(1);
			return false;
		}
		
		match = new OFMatch();
		match.setWildcards(OFMatch.OFPFW_ALL); 
		result = installDropRule(sw.getId(),match,(short)0,(short)0,DROP_PRIORITY);
		
		/***Configure Switch to send whole package to Controller***/
		OFSetConfig config = new OFSetConfig();
		config.setMissSendLength((short)0xffff);
		try{
			sw.write(config, null);
			sw.flush();
			System.out.println("Done writing config to sw");
		}
		catch(Exception e){
			System.err.println("Write config to sw: "+e);
		}	
		return result;
	}
	
	private void deleteForwardRule(IOFSwitch sw, ForwardFlowItem item){
		System.err.println("    deleteForwardRule");
		OFFlowMod ruleIncoming = new OFFlowMod();
		ruleIncoming.setOutPort(OFPort.OFPP_NONE);
		ruleIncoming.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleIncoming.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(item.getSrc_ip());
		match.setNetworkDestination(item.getDst_ip());
		match.setTransportSource(item.getSrc_port());
		match.setTransportDestination(item.getDst_port());
		match.setNetworkProtocol(item.getProtocol());
		match.setWildcards(	OFMatch.OFPFW_IN_PORT |
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				 OFMatch.OFPFW_NW_TOS |   
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
		
		ruleIncoming.setMatch(match.clone());		
		
		OFFlowMod ruleOutgoing = new OFFlowMod();
		ruleOutgoing.setOutPort(OFPort.OFPP_NONE);
		ruleOutgoing.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleOutgoing.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(item.getRemote_ip()); //?
		match.setNetworkDestination(item.getSrc_ip());
		match.setTransportSource(item.getDst_port());
		short port = item.getSrc_port();
		if(item.getSrc_port() != item.getNew_src_port())
			port = item.getNew_src_port();
		match.setTransportDestination(port);
		match.setNetworkProtocol(item.getProtocol());
		match.setWildcards(	OFMatch.OFPFW_IN_PORT |
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				 OFMatch.OFPFW_NW_TOS |   
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
		
		ruleOutgoing.setMatch(match.clone());	
		
		try{
			sw.write(ruleIncoming, null);
			sw.write(ruleOutgoing, null);
			sw.flush();
		}
		catch (IOException e){
			logger.LogError("fail delete flows for: "+item+" "+ruleIncoming+" "+ruleOutgoing);
		}
	}
	
	private void informNWToDestroyFlowInfo(ForwardFlowItem item){
		System.err.println("    Inform NW to Destroy Flow Info");
	}
	private int positivePort(short port){
		int rs = port & 0x0000ffff;
		return rs;
	}
	
	private boolean processedByOtherHoneynets(Connection conn, short inport,IOFSwitch sw, OFMessage msg,Ethernet eth ){
		long switch_id = sw.getId();
		
		/* NW */
		Honeynet nw = Honeynet.getHoneynet("nw");
		if(nw==null){
			System.err.println("No NW honeynet!");
			return false;
		}
		Honeynet.SubnetMask mask = nw.getMask();
		byte[] nw_ip_address = IPv4.toIPv4AddressBytes(nw.getIp());
		byte[] newDstMAC = null;
		byte[] newDstIP = null;
		byte[] newSrcIP = null;
		short outPort = 0;
		if((conn.srcIP==nw.getIp()) && (Honeynet.inSubnet(mask,conn.dstIP))){
			//130.107.244.244:3357-129.105.44.107:80
			String key = ForwardFlowItem.generateForwardFlowTableKey(conn.dstIP, conn.dstPort, conn.srcIP, conn.srcPort);
			System.err.println("SENT FROM NW src:"+IPv4.fromIPv4Address(conn.srcIP)+" dst:"+IPv4.fromIPv4Address(conn.dstIP) +
								" flow srcport:"+positivePort(conn.srcPort) + 
								" flow dstport:"+positivePort(conn.dstPort)+"\n    key:"+key);
			
			ForwardFlowItem item = forwardFlowTable.get(key);
			if(item==null){
				System.err.println("    can't find this flow. give up!!!");
				return true;
			}
			IPacket packet = eth.getPayload();	
			
			short front_src_ip = (short)( (item.getSrc_ip()>>>16) & 0x0000ffff);
			short end_src_ip = (short)(item.getSrc_ip() & 0x0000ffff);
			
			 if(packet instanceof IPv4){
				IPv4 ip_pkt = (IPv4)packet;
				// FIXME: information is stored in ecn because dscn will be striped!!! 
				byte ecn = ip_pkt.getDiffServ();
				if(ecn == 0x01){
					System.err.println("missing 0x04 setup packet "+((OFPacketIn)msg).getInPort());
					boolean rs = forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
							IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), 
							eth, (byte)0x01, front_src_ip, 
							conn.dstPort, conn.srcPort); 
					System.err.println("done resending 0x04 setup packet "+rs);
					return true;
				}
				else if(ecn == 0x02){
					System.err.println("missing 0x08 setup packet "+((OFPacketIn)msg).getInPort());
					boolean rs = forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
							IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(),  
							eth, (byte)0x02, end_src_ip, 
							conn.dstPort, conn.srcPort); 
					System.err.println("done resending 0x08 setup packet "+rs);
					return true;
				}
				else if(ecn == 0x03){
					System.err.println("missing 0x0c setup packet "+((OFPacketIn)msg).getInPort());
					boolean rs1 = forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
							IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), 
							eth, (byte)0x01, front_src_ip, 
							conn.dstPort, conn.srcPort); 
					boolean rs2 = forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
							IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), 
							eth, (byte)0x02, end_src_ip, 
							conn.dstPort, conn.srcPort); 
					System.err.println("done resending 0x04 setup packet "+rs1);
					System.err.println("done resending 0x08 setup packet "+rs2);
					return true;
				}
				else{
					//boolean rs = forwardPacket2OtherNet(sw, (OFPacketIn)msg, nw_ip_address,
					//		IPv4.toIPv4AddressBytes(nw.getIp()), IPv4.toIPv4AddressBytes(conn.dstIP),
					//		((OFPacketIn)msg).getInPort(), 
					//		eth, (byte)0x02, (short)0xffffffff, 
					//		conn.dstPort, conn.srcPort); 
					//System.err.println(packet.serialize().length+" "+bytesToHexString(packet.serialize()));			
					System.err.println("  dscn: "+ecn);
				}
			}
			System.err.println("    original src:"+IPv4.fromIPv4Address(item.getSrc_ip()));
			/* nw->outside rule */
			OFMatch match = new OFMatch();	
			match.setDataLayerType((short)0x0800);
			match.setNetworkDestination(conn.dstIP);
			match.setNetworkSource(IPv4.toIPv4Address(nw_ip_address));
			match.setTransportDestination(conn.dstPort);
			match.setTransportSource(conn.srcPort);
			match.setInputPort(inport);
			match.setNetworkProtocol(conn.getProtocol());
			match.setWildcards(	
					OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
					 OFMatch.OFPFW_NW_TOS |   
					OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
			newDstMAC = nc_mac_address;
			
			newDstIP = IPv4.toIPv4AddressBytes(item.getSrc_ip());
			newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);
			outPort = inport;
			short new_dst_port = 0;
			if(item.getSrc_port() !=item.getNew_src_port() )
				new_dst_port = item.getSrc_port();
			System.err.println("    new_dst_port:"+positivePort(new_dst_port));
			boolean rs = installPathForFlow(switch_id,inport,match,OFFlowMod.OFPFF_SEND_FLOW_REM,
											item.getFlow_cookie(), newDstMAC,newDstIP,newSrcIP,
											(short)0, new_dst_port,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);			
			if (rs == false){
				System.err.println("    Fail setting ruls for sending traffic to NW");
			}
			
			return true;
		}
		else if(Honeynet.inSubnet(mask,conn.dstIP)){
			/*For test*/
			int special_ip = IPv4.toIPv4Address("130.107.244.244");
			if((conn.dstPort != (short)80)|| (conn.dstIP != special_ip) )
				return true;
			
			
			//130.107.244.244:3357-129.105.44.107:80
			String key = ForwardFlowItem.generateForwardFlowTableKey(conn.dstIP, conn.srcPort, nw.getIp(), conn.dstPort);
			System.err.println("SENT TO NW src:"+IPv4.fromIPv4Address(conn.srcIP)+" dst:"+IPv4.fromIPv4Address(conn.dstIP) +
					" flow srcport:"+positivePort(conn.srcPort) + 
					" flow dstport:"+positivePort(conn.dstPort)+"\n    key:"+key);
			short new_src_port = conn.srcPort;
			long cookie = 0;
			if(forwardFlowTable.containsKey(key)) /* table item exists*/
			{	
				System.err.println("    entry exists for this flow:"+key);
				int count = 0;
				while(true){
					if(count > 5){
						System.err.println("        can't find available port: give up!!!");
						return true;
					}
					count++;
					key = ForwardFlowItem.generateForwardFlowTableKey(conn.dstIP, new_src_port, nw.getIp(), conn.dstPort);
					ForwardFlowItem item = forwardFlowTable.get(key);
					if((item==null) || (item.getState()==ForwardFlowItem.ForwardFLowItemState.FREE)){
						System.err.println("        flow entry is ready for replacement");
						item = new ForwardFlowItem(conn.srcIP,conn.srcPort,conn.dstIP,conn.dstPort,new_src_port,(long)HARD_TIMEOUT,
													conn.getProtocol(),nw.getIp());
						cookie = forwardFlowTable.put(key, item);
						break;
					}
					else if(item.getState()==ForwardFlowItem.ForwardFLowItemState.WAIT_FOR_DEL_ACK){
						//the other thread can only delete this item
						System.err.println("        flow entry is not ready for replacement: WAIT_FOR_DEL_ACK");
						new_src_port = ForwardFlowItem.generateRandomPortNumber();
						continue;
					}
					else if(item.getState()==ForwardFlowItem.ForwardFLowItemState.USE){
						System.err.println("        flow entry is in USE");
						if((conn.srcIP == item.getSrc_ip()) && (conn.srcPort==item.getSrc_port())){
							System.err.println("            same flow, update StartingTime.");
							if(forwardFlowTable.updateStartingtime(key,System.currentTimeMillis())==false){
								System.err.println("            error updateStartingTime. This one is deleted by other thread");
							}
							cookie = item.getFlow_cookie();
							break;
						}
						else if(item.expire()){
							forwardFlowTable.updateItemState(key, ForwardFlowItem.ForwardFLowItemState.WAIT_FOR_DEL_ACK);
							System.err.println("            not same flow, but expired, del it asynchronously");
							deleteForwardRule(sw,item);
							informNWToDestroyFlowInfo(item);
							new_src_port = ForwardFlowItem.generateRandomPortNumber();
							continue;
						}	
						else{
							System.err.println("            not same flow, switch port");
							new_src_port = ForwardFlowItem.generateRandomPortNumber();
							continue;
						}
					}	
				}
			}
			else /*new item*/
			{	/*src_ip, short src_port, int dst_ip, short dst_port, short new_src_port,  timeout*/
				System.err.println("    no entry exists");
				/* For test */		
				//new_src_port = (short)(conn.srcPort+(short)100);
				//key = ForwardFlowItem.generateForwardFlowTableKey(conn.dstIP, new_src_port, nw.getIp(), conn.dstPort);
				
				ForwardFlowItem item = new ForwardFlowItem(conn.srcIP,conn.srcPort,conn.dstIP,conn.dstPort,new_src_port,(long)HARD_TIMEOUT,
								conn.getProtocol(),nw.getIp());
				cookie = forwardFlowTable.put(key, item);	
			}
			System.err.println("    send setup packets out "+conn+
							"\n        flow srcPort:"+positivePort(conn.srcPort)+" new srcPort:"+positivePort(new_src_port));
			int src_ip = conn.srcIP;
			short front_src_ip = (short)( (src_ip>>>16) & 0x0000ffff);
			short end_src_ip = (short)(src_ip & 0x0000ffff);
			
			forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
					IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), 
					eth,(byte)0x01,front_src_ip,(new_src_port==conn.srcPort)?(short)0:new_src_port,(short)0);
			forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,
					IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), 
					eth,(byte)0x02, end_src_ip,(new_src_port==conn.srcPort)?(short)0:new_src_port,(short)0);
			//test
			
			/* outside->nw rule */
			OFMatch match = new OFMatch();
			match.setDataLayerType((short)0x0800);
			match.setNetworkDestination(conn.dstIP);
			match.setNetworkSource(conn.srcIP);
			match.setInputPort(inport);
			match.setTransportSource(conn.srcPort);
			match.setTransportDestination(conn.dstPort);
			match.setNetworkProtocol(conn.getProtocol());
			match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_NW_TOS |   
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );
			newDstMAC = nc_mac_address;
			newDstIP = nw_ip_address;
			newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);
			outPort = inport;
			if((new_src_port==conn.srcPort) || (new_src_port==0))
				new_src_port = 0;
			System.err.println("    install rule for forwording packets to NW. Match:"+match);
			boolean rs = installPathForFlow(switch_id,inport,match,OFFlowMod.OFPFF_SEND_FLOW_REM,
							cookie, newDstMAC,newDstIP,newSrcIP,new_src_port, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
			if(rs==false){
				System.err.println("    error installing rule: Match"+match);
			}
			return true;
		}
		
		
		return false;
	}
	
	/*private boolean processedByOtherHoneynets_(Connection conn, short inport,IOFSwitch sw, OFMessage msg,Ethernet eth ){
		long switch_id = sw.getId();
		
		byte[] src_tmp = IPv4.toIPv4AddressBytes(conn.srcIP);
		byte[] dst_tmp = IPv4.toIPv4AddressBytes(conn.dstIP);
		
		if( (src_tmp[0]==(byte)129) && (src_tmp[1]==(byte)105) && (src_tmp[2]==(byte)44) && (src_tmp[3]==(byte)107) ){
			System.err.println("Packages sent from NW: "+conn );
		    return true;	
		}
		else if((dst_tmp[0]==(byte)130) && (dst_tmp[1]==(byte)107) && (dst_tmp[2]>=(byte)240)){
			byte[] newDstMAC = null;
			byte[] newDstIP = null;
			byte[] newSrcIP = null;
			short outPort = 0;
			 
			int src_ip = conn.srcIP;
			short front_src_ip = (short)( (src_ip>>>16) & 0x0000ffff);
			short end_src_ip = (short)(src_ip & 0x0000ffff);
			System.err.println(conn);
			forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), eth,(byte)0x01,front_src_ip);
			forwardPacket2OtherNet(sw,(OFPacketIn)msg, nc_mac_address,nw_ip_address,IPv4.toIPv4AddressBytes(conn.getDstIP()),((OFPacketIn)msg).getInPort(), eth,(byte)0x02, end_src_ip);		
			
			
			OFMatch match = new OFMatch();
			match.setDataLayerType((short)0x0800);
			match.setNetworkDestination(conn.dstIP);
			match.setNetworkSource(conn.srcIP);
			match.setInputPort(inport);
			match.setTransportSource(conn.srcPort);
			match.setTransportDestination(conn.dstPort);
			match.setNetworkProtocol(conn.getProtocol());
			match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_NW_TOS |   
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );
			newDstMAC = nc_mac_address;
			newDstIP = nw_ip_address;
			newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);
			outPort = inport;
			boolean rs1 = installPathForFlow(switch_id,inport,match,(short)0,(long)0, newDstMAC,newDstIP,newSrcIP,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
				
			
			match = new OFMatch();	
			match.setDataLayerType((short)0x0800);
			match.setNetworkDestination(conn.dstIP);
			match.setNetworkSource(IPv4.toIPv4Address(nw_ip_address));
			match.setTransportSource(conn.dstPort);
			match.setTransportDestination(conn.srcPort);
			match.setInputPort(inport);
			match.setNetworkProtocol(conn.getProtocol());
			match.setWildcards(	
					OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
					 OFMatch.OFPFW_NW_TOS |   
					OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
			newDstMAC = nc_mac_address;
			newDstIP = IPv4.toIPv4AddressBytes(conn.srcIP);
			newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);
			outPort = inport;
			boolean rs2 = installPathForFlow(switch_id,inport,match,(short)0,(long)0, newDstMAC,newDstIP,newSrcIP,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);			
			boolean rs = rs1 & rs2;
			if (rs == false){
				System.err.println("Fail setting ruls for sending traffic to NW");
			}
            return true;
		}
		
		return false;
	}*/
	
	private boolean initLassenSwitch(long switchId){
		IOFSwitch sw = floodlightProvider.getSwitch(switchId);
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(honeypot_net));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL| honeypot_net_mask<<OFMatch.OFPFW_NW_SRC_SHIFT|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		byte[] newDstMAC = missouri_mac_address;
		byte[] newDstIP = null;
		byte[] newSrcIP = null;
		short outPort = lassen_default_out_port;
		boolean result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newDstMAC,newDstIP,newSrcIP,
								(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		if(!result){
			logger.LogError("failed to create default rule for LASSEN 1");
			System.exit(1);
			return false;
		}

		for(HoneyPot pot : honeypots.values()){
			setForwardRulesFromLassenToHoneyPot(sw,pot.getIpAddress(),pot.getMacAddress(),pot.getOutPort());
		}
		
		match = new OFMatch();
		match.setWildcards(OFMatch.OFPFW_ALL); 
		result = installDropRule(sw.getId(),match,(short)0,(short)0,DROP_PRIORITY);
		
		/*
		 * The following rules are used only for migration demo (telnet)
		 */
		
		/* ip,nw_src=10.1.1.10,nw_dst=10.1.1.2,actions=mod_dl_dst:08:00:27:eb:66:bb, output:5 */
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(migration_ip_address));
		match.setNetworkDestination(IPv4.toIPv4Address(neighbor_ip_address));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		newDstMAC = neighbor_mac_address;
		newDstIP = null;
		newSrcIP = null;
		outPort = neighbor_out_port;
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newDstMAC,newDstIP,newSrcIP,(short)0, (short)0,outPort,(short)0, (short)0,(short)(DEFAULT_PRIORITY+5));
		if(!result){
			logger.LogError("failed to create default rule for LASSEN 2");
			System.exit(1);
			return false;
		}
		
		/* ip,nw_dst=10.1.1.21,actions=output:19 */
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(snooper_ip_address));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_SRC_ALL | 
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		newDstMAC = null;
		newDstIP = null;
		newSrcIP = null;
		outPort = snooper_out_port;
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newDstMAC,newDstIP,newSrcIP,(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		if(!result){
			logger.LogDebug("failed to create default rule for LASSEN 3");
			System.exit(1);
			return false;
		}
		
		/* ip,nw_src=10.1.1.21,nw_dst=10.1.1.10,actions=output:6 */
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(migration_ip_address));
		match.setNetworkSource(IPv4.toIPv4Address(snooper_ip_address));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		newDstMAC = null;
		newDstIP = null;
		newSrcIP = null;
		outPort = migration_out_port;
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newDstMAC,newDstIP,newSrcIP,(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		if(!result){
			logger.LogError("failed to create default rule for LASSEN 4");
			System.exit(1);
			return false;
		}
		
		//tcp,nw_src=10.1.1.10,actions=output:9"
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(migration_ip_address));
		match.setNetworkProtocol((byte)0x06);
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL| OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		newDstMAC = null;
		newDstIP = null;
		newSrcIP = null;
		outPort = lassen_default_out_port;
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newDstMAC,newDstIP,newSrcIP,(short)0, (short)0,outPort,(short)0, (short)0,DEFAULT_PRIORITY);
		
		if(!result){
			logger.LogError("failed to create default rule for LASSEN 5");
			System.exit(1);
			return false;
		} 
		
		return result;
	}
	
	private boolean setForwardRulesFromLassenToHoneyPot(IOFSwitch sw, byte[] ip, byte[] mac, short outport){
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(ip));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_SRC_ALL| 
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		byte[] newDstMAC = mac;
		byte[] newDstIP = null;
		byte[] newSrcIP = null;
		short outPort = outport;
		boolean result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newDstMAC, newDstIP,newSrcIP, (short)0, (short)0,outPort, (short)0, (short)0,DEFAULT_PRIORITY);
		if(!result){
			logger.LogError("Failed creating default rule from LASSEN to "+ip);
			System.exit(1);
		}
		return true;
	}
	
	static public String bytesToHexString(byte[] contents){
		StringBuilder hexcontents = new StringBuilder();
		for (byte b:contents) {
			hexcontents.append(String.format("%02X ", b));
		}
		return hexcontents.toString();
	}
	
	static public String shortToHexString(short content){
		String str = Integer.toHexString(content & 0xffff);
		return str;
	}
	static public String byteToHexString(byte content){
		String str = Integer.toHexString(content & 0xff);
		return str;
	}
	
	public boolean forwardPacket(IOFSwitch sw, OFPacketIn pktInMsg, 
			byte[] dstMAC, byte[] destIP, byte[] srcIP, short outSwPort, Ethernet eth) 
    {
        OFPacketOut pktOut = new OFPacketOut();        
        
        pktOut.setInPort(pktInMsg.getInPort());
        pktOut.setBufferId(pktInMsg.getBufferId());
        
     	List<OFAction> actions = new ArrayList<OFAction>();
     	int actionLen = 0;
     	if(dstMAC != null){
     		OFActionDataLayerDestination action_mod_dst_mac = 
					new OFActionDataLayerDestination(dstMAC);
     		actions.add(action_mod_dst_mac);
     		actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
     	}
		if(destIP != null){
			OFActionNetworkLayerDestination action_mod_dst_ip = 
					new OFActionNetworkLayerDestination(IPv4.toIPv4Address(destIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if(srcIP != null){
			OFActionNetworkLayerSource action_mod_src_ip = 
					new OFActionNetworkLayerSource(IPv4.toIPv4Address(srcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;
		if(pktInMsg.getInPort() == outSwPort){
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		}
		else{
			action_out_port = new OFActionOutput(outSwPort);
		}
		
		actions.add(action_out_port);
		pktOut.setActions(actions);

		pktOut.setActionsLength((short)actionLen);
	    
		
        // Set data if it is included in the packet in but buffer id is NONE
        if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
        	//System.err.println("debug BUFFER_ID_NONE");
            byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            pktOut.setPacketData(packetData);
           
        }//no buffer ID
        else 
        {
        	//System.err.println("debug NOT BUFFER_ID_NONE");
        	pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength()));
        }
        
        try 
        {
            sw.write(pktOut, null);
            sw.flush();
            //logger.info("forwarded packet ");
        }
        catch (IOException e) 
        {
        	logger.LogError("failed forward packet");
 			return false;
        }
        return true;
	}
	
	public boolean forwardPacket2OtherNet(IOFSwitch sw, OFPacketIn pktInMsg, 
			byte[] dstMAC, byte[] dstIP, byte[] srcIP, short outSwPort, Ethernet eth, byte dscp, short id, 
			short newSrcPort, short newDstPort) 
    {
        OFPacketOut pktOut = new OFPacketOut();        
        
        pktOut.setInPort(pktInMsg.getInPort());
        pktOut.setBufferId(pktInMsg.getBufferId());
        System.err.println("forward new src: "+IPv4.fromIPv4Address(IPv4.toIPv4Address(srcIP)));
     	System.err.println("forward new dst: "+IPv4.fromIPv4Address(IPv4.toIPv4Address(dstIP)));
     	
     	List<OFAction> actions = new ArrayList<OFAction>();
     	
     	int actionLen = 0;
     	if(dstMAC != null){
     		OFActionDataLayerDestination action_mod_dst_mac = 
					new OFActionDataLayerDestination(dstMAC);
     		actions.add(action_mod_dst_mac);
     		actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
     	}
     	
     	if(srcIP != null){
			OFActionNetworkLayerSource action_mod_src_ip = 
					new OFActionNetworkLayerSource(IPv4.toIPv4Address(srcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
     	if(dstIP != null){
			OFActionNetworkLayerDestination action_mod_dst_ip = 
					new OFActionNetworkLayerDestination(IPv4.toIPv4Address(dstIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if(newSrcPort != 0){
			OFActionTransportLayerSource action_mod_src_tp =
					new OFActionTransportLayerSource(newSrcPort);
			actions.add(action_mod_src_tp);
			actionLen += OFActionTransportLayerSource.MINIMUM_LENGTH;
		}
		if(newDstPort != 0){
			OFActionTransportLayerDestination action_mod_dst_tp =
					new OFActionTransportLayerDestination(newDstPort);
			actions.add(action_mod_dst_tp);
			actionLen += OFActionTransportLayerDestination.MINIMUM_LENGTH;
		}
		
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;
		if(pktInMsg.getInPort() == outSwPort){
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		}
		else{
			action_out_port = new OFActionOutput(outSwPort);
		}
		actions.add(action_out_port);
		
		pktOut.setActions(actions);
		pktOut.setActionsLength((short)actionLen);
		
		/*if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
		{
			byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            pktOut.setPacketData(packetData);   
		}*/
        // Set data if it is included in the packet in but buffer id is NONE
	
        if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
        	//System.err.println("debug BUFFER_ID_NONE");
            byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            
            int packet_len = packetData.length;
            int msg_len = pktInMsg.getLength();
            IPacket pkt  = eth.getPayload();
            
            if(pkt instanceof IPv4){
            	IPv4 ip_pkt = (IPv4)pkt;
            	int ip_len = ip_pkt.getTotalLength();
            	int ip_header_len = (ip_pkt.getHeaderLength() & 0x000000ff) * 4;
            	//System.err.println("msglen:"+msg_len+" packetlen:"+packet_len+" iplen:"+ip_len+" ip headerlen:"+ip_header_len);
            	byte[] ip_pkt_data = Arrays.copyOfRange(packetData,
            				ChecksumCalc.ETHERNET_HEADER_LEN,ChecksumCalc.ETHERNET_HEADER_LEN + ip_len);
            	
            	//byte ecn =  (byte)((int)(ip_pkt_data[1])&0x03);	
            	dscp = (byte)(dscp << 2);
            	ip_pkt_data[1] = (byte)((dscp)&0xff);
            	dscp = (byte)((int)(ip_pkt_data[1])>>>2);
            	//ecn =  (byte)((int)(ip_pkt_data[1])&0x03);
            	
            	ip_pkt_data[4] = (byte)((id>>>8) & 0xff);
            	ip_pkt_data[5] = (byte)(id & 0xff);
            	
            	/*if(srcIP != null){
            		ip_pkt_data[12] = srcIP[0];
            		ip_pkt_data[13] = srcIP[1];
            		ip_pkt_data[14] = srcIP[2];
            		ip_pkt_data[15] = srcIP[3];
            	}
            	if(dstIP != null){
            		ip_pkt_data[16] = dstIP[0];
            		ip_pkt_data[17] = dstIP[1];
            		ip_pkt_data[18] = dstIP[2];
            		ip_pkt_data[19] = dstIP[3];
            	}*/
            	
            	//System.err.println("NEW DSCP:"+byteToHexString(dscp)+" ID:"+shortToHexString(ecn));
            	if(ChecksumCalc.reCalcAndUpdateIPPacketChecksum(ip_pkt_data, ip_header_len)==false){
            		System.err.println("error calculating ip pkt checksum");
            	}
            	
            	byte[] new_ether_data = new byte[packet_len];
            	for(int i=0; i<ChecksumCalc.ETHERNET_HEADER_LEN; i++)
            		new_ether_data[i] = packetData[i];
            	
            	for(int i=ChecksumCalc.ETHERNET_HEADER_LEN,j=0; 
            			i<packet_len; 
            			i++,j++){
        			if(j < ip_len)
        				new_ether_data[i] = ip_pkt_data[j];
        			else
        				new_ether_data[i] = 0x00;
        		}
            	
            	pktOut.setPacketData(new_ether_data);      
            }
            else{
            	short eth_type = eth.getEtherType();
            	String eth_type_str = Integer.toHexString(eth_type & 0xffff);
            	System.err.println("msglen:"+msg_len+" packetlen:"+packet_len+" iplen: no ipv4 pkt :"+eth_type_str);
            	pktOut.setPacketData(packetData);
            }
           
        }//no buffer ID
        else 
        {
        	System.err.println("ERROR BUFFER ID IS NOT NONE");
        	pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength()));
        }
        
        try 
        {
        	System.err.println("wrote pktOut");
            sw.write(pktOut, null);
            sw.flush();
            //logger.info("forwarded packet ");
        }
        catch (IOException e) 
        {
        	System.err.println("failed writing packet out:"+e);
        	logger.LogError("failed forward packet");
 			return false;
        }
        return true;
	}
	
	public boolean forwardPacket2OtherNet_(IOFSwitch sw, OFPacketIn pktInMsg, 
			byte[] dstMAC, byte[] destIP, byte[] srcIP, short outSwPort, Ethernet eth, byte dscp, short id, 
			short new_src_port, short new_dst_port) 
    {
        OFPacketOut pktOut = new OFPacketOut();        
        
        pktOut.setInPort(pktInMsg.getInPort());
        pktOut.setBufferId(pktInMsg.getBufferId());
        
     	List<OFAction> actions = new ArrayList<OFAction>();
     	int actionLen = 0;
     	if(dstMAC != null){
     		OFActionDataLayerDestination action_mod_dst_mac = 
					new OFActionDataLayerDestination(dstMAC);
     		actions.add(action_mod_dst_mac);
     		actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
     	}
		if(destIP != null){
			OFActionNetworkLayerDestination action_mod_dst_ip = 
					new OFActionNetworkLayerDestination(IPv4.toIPv4Address(destIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if(srcIP != null){
			OFActionNetworkLayerSource action_mod_src_ip = 
					new OFActionNetworkLayerSource(IPv4.toIPv4Address(srcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;
		if(pktInMsg.getInPort() == outSwPort){
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		}
		else{
			action_out_port = new OFActionOutput(outSwPort);
		}
		
		actions.add(action_out_port);
		pktOut.setActions(actions);
		pktOut.setActionsLength((short)actionLen);
	    
        // Set data if it is included in the packet in but buffer id is NONE
        if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
        	//System.err.println("debug BUFFER_ID_NONE");
            byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            
            int packet_len = packetData.length;
            int msg_len = pktInMsg.getLength();
            IPacket pkt  = eth.getPayload();
            
            if(pkt instanceof IPv4){
            	IPv4 ip_pkt = (IPv4)pkt;
            	int ip_len = ip_pkt.getTotalLength();
            	int ip_header_len = (ip_pkt.getHeaderLength() & 0x000000ff) * 4;
            	short payload_len = (short)(ip_len - ip_header_len);
            	int src_ip = ip_pkt.getSourceAddress();
            	int dst_ip = ip_pkt.getDestinationAddress();
            	//System.err.println("msglen:"+msg_len+" packetlen:"+packet_len+" iplen:"+ip_len+" ip headerlen:"+ip_header_len);
            	byte[] ip_pkt_data = Arrays.copyOfRange(packetData,
            				ChecksumCalc.ETHERNET_HEADER_LEN,ChecksumCalc.ETHERNET_HEADER_LEN + ip_len);
            	byte[] new_tp_data = null;
            	if((new_src_port!=0) || (new_dst_port!=0)){
            		
            		IPacket tp_pkt = ip_pkt.getPayload();
	            	if(tp_pkt instanceof TCP){
	            		//System.err.println("    Modify TCP");
	            		TCP tcp = (TCP)tp_pkt;
	    				if(new_src_port != 0)
	    					tcp.setSourcePort(new_src_port);
	    				if(new_dst_port != 0)
	    					tcp.setDestinationPort(new_dst_port);
	    				
	    				tcp.resetChecksum();
	    				new_tp_data = tcp.serialize();
	    			}
	    			else if(tp_pkt instanceof UDP){
	    				//System.err.println("    UDP original checksum:");
	    				UDP udp = (UDP)tp_pkt;
	    				if(new_src_port != 0)
	    					udp.setSourcePort(new_src_port);
	    				if(new_dst_port != 0)
	    					udp.setDestinationPort(new_dst_port);
	    				udp.resetChecksum();
	    				new_tp_data = udp.serialize();
	    			}
	    			else{
	    				System.err.println("    unknown IP packet. Ignore...");
	    				return false;
	    			}
	            	
            	}
            	
            	/* Modify DSCP */
            	byte ecn =  (byte)((int)(ip_pkt_data[1])&0x03);	
            	dscp = (byte)(dscp << 2);
            	ip_pkt_data[1] = (byte)((dscp|ecn)&0xff);
            	dscp = (byte)((int)(ip_pkt_data[1])>>>2);
            	ecn =  (byte)((int)(ip_pkt_data[1])&0x03);
            	
            	/* Modify ID */
            	ip_pkt_data[4] = (byte)((id>>>8) & 0xff);
            	ip_pkt_data[5] = (byte)(id & 0xff);
            	
            	//System.err.println("NEW DSCP:"+byteToHexString(dscp)+" ID:"+shortToHexString(ecn));
            	if(ChecksumCalc.reCalcAndUpdateIPPacketChecksum(ip_pkt_data, ip_header_len)==false){
            		System.err.println("error calculating ip pkt checksum");
            	}
            	
            	/* install Ethernet header */
            	byte[] new_ether_data = new byte[packet_len];
            	for(int i=0; i<ChecksumCalc.ETHERNET_HEADER_LEN; i++)
            		new_ether_data[i] = packetData[i];
            	
            	if(new_tp_data != null){
	            	for(int i=ChecksumCalc.ETHERNET_HEADER_LEN,j=0; 
	            			i<ChecksumCalc.ETHERNET_HEADER_LEN+ip_header_len; 
	            			i++,j++){
	            		new_ether_data[i] = ip_pkt_data[j];
	            	}
	            	for(int i=ChecksumCalc.ETHERNET_HEADER_LEN+ip_header_len,j=0;i<packet_len; i++,j++){
	            		if(j < new_tp_data.length)
	            			new_ether_data[i] = new_tp_data[j];
	            		else
	            			new_ether_data[i] = 0x00;
	            	}
            	}
            	else{
            		for(int i=ChecksumCalc.ETHERNET_HEADER_LEN,j=0; 
	            			i<packet_len; 
	            			i++,j++){
            			if(j < ip_len)
            				new_ether_data[i] = ip_pkt_data[j];
            			else
            				new_ether_data[i] = 0x00;
            		}
            	}
            	
            	pktOut.setPacketData(new_ether_data);      
            }
            else{
            	short eth_type = eth.getEtherType();
            	String eth_type_str = Integer.toHexString(eth_type & 0xffff);
            	System.err.println("msglen:"+msg_len+" packetlen:"+packet_len+" iplen: no ipv4 pkt :"+eth_type_str);
            	pktOut.setPacketData(packetData);
            }
           
        }//no buffer ID
        else 
        {
        	System.err.println("ERROR BUFFER ID IS NOT NONE");
        	pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength()));
        }
        
        try 
        {
            sw.write(pktOut, null);
            sw.flush();
            //logger.info("forwarded packet ");
        }
        catch (IOException e) 
        {
        	logger.LogError("failed forward packet");
 			return false;
        }
        return true;
	}

	private boolean installPathForFlow(long swID,short inPort,OFMatch match, 
			short flowFlag, long flowCookie, 
			byte[] newDstMAC, byte[] newDstIP, byte[] newSrcIP, 
			short srcPort, short dstPort,
			short outPort, 
			short idleTimeout, short hardTimeout,short priority) {
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch [installPathForFlow]");
			return false;
		}
		
		OFFlowMod rule = new OFFlowMod();
		if (flowFlag != (short) 0) {
			rule.setFlags(flowFlag);
		}
		if (flowCookie != (long) 0)
			rule.setCookie(flowCookie);
		rule.setHardTimeout(hardTimeout);
		rule.setIdleTimeout(idleTimeout);
		rule.setPriority(priority);
		rule.setCommand(OFFlowMod.OFPFC_MODIFY_STRICT);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());
		
		//OFActionTransportLayerSource action_mod_tp_src = new OFActionTransportLayerSource();
		List<OFAction> actions = new ArrayList<OFAction>();
		int actionLen = 0;
		if (newDstMAC != null) {
			OFActionDataLayerDestination action_mod_dst_mac = new OFActionDataLayerDestination(
					newDstMAC);
			actions.add(action_mod_dst_mac);
			actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
		}
		if (newDstIP != null) {
			OFActionNetworkLayerDestination action_mod_dst_ip = new OFActionNetworkLayerDestination(
					IPv4.toIPv4Address(newDstIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if (newSrcIP != null) {
			OFActionNetworkLayerSource action_mod_src_ip = new OFActionNetworkLayerSource(
					IPv4.toIPv4Address(newSrcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		if(srcPort != 0){
			OFActionTransportLayerSource action_mod_tp_src = new OFActionTransportLayerSource(srcPort);
			actions.add(action_mod_tp_src);
			actionLen += OFActionTransportLayerSource.MINIMUM_LENGTH;
		}
		if(dstPort != 0){
			OFActionTransportLayerDestination action_mod_tp_dst = new OFActionTransportLayerDestination(dstPort);
			actions.add(action_mod_tp_dst);
			actionLen += OFActionTransportLayerDestination.MINIMUM_LENGTH;
		}
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;

		if (outPort == inPort) {
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		} else {
			action_out_port = new OFActionOutput(outPort);
		}
		actions.add(action_out_port);
		rule.setActions(actions);
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + actionLen));
		//System.err.println("done installing rule:"+rule);
		try {
			sw.write(rule, null);
			sw.flush();
		} catch (IOException e) {
			logger.LogError("fail to install rule: " + rule);
			return false;
		}
		return true;
	}
	
	private void clearMaps(){
		
		if(connToPot.size()>= CONN_MAX_SIZE){
			connToPot = new Hashtable<String,Connection>();
			long currTime = System.currentTimeMillis();
			currTime -= lastClearConnToPotTime;
			logger.LogError("Clear connToPot after "+currTime/1000+" seconds");
			lastClearConnToPotTime = System.currentTimeMillis();
		}
		if(connMap.size() >= CONN_MAX_SIZE){
			connMap = new Hashtable<Long, Connection>();
			long currTime = System.currentTimeMillis();
			currTime -= lastClearConnMapTime;
			logger.LogError("Clear connMap after "+currTime/1000+" seconds");
			lastClearConnMapTime = System.currentTimeMillis();
		}
		
	}
	private void forceClearMaps(){
		connToPot = new Hashtable<String,Connection>();
		long currTime = System.currentTimeMillis();
		currTime -= lastClearConnToPotTime;
		logger.LogError("Clear connToPot after "+currTime/1000+" seconds");
		lastClearConnToPotTime = System.currentTimeMillis();
	
		connMap = new Hashtable<Long, Connection>();
		currTime = System.currentTimeMillis();
		currTime -= lastClearConnMapTime;
		logger.LogError("Clear connMap after "+currTime/1000+" seconds");
		lastClearConnMapTime = System.currentTimeMillis();

		System.gc();
	}
	
	
	private boolean installDropRule(long swID, OFMatch match,short idleTimeout, short hardTimeout, short priority){
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch [installDropRule]");
			return false;
		}
		OFFlowMod rule = new OFFlowMod();
		rule.setHardTimeout(hardTimeout);
		rule.setIdleTimeout(idleTimeout);
		rule.setPriority(priority);
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());
		
		/* Empty action list means drop! */
		List<OFAction> actions = new ArrayList<OFAction>();
		rule.setActions(actions);
		
		rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH));
		try 
		{
			sw.write(rule, null);
			sw.flush();
			logger.LogDebug("succ installed drop rule: "+rule);
		}
		catch (IOException e) 
		{
			logger.LogError("fail installing rule: "+rule);
			return false;
		}
		
		return true;
	}
	
	private boolean deleteFlowsForHoneypot(String honeypotName){
		if(!(honeypots.containsKey(honeypotName)) ){
			logger.LogError("fail finding honeypot "+honeypotName);
			return false;
		}
		short outPort = honeypots.get(honeypotName).getOutPort();
		long swID = 0;
		try{
			swID = switches.get(honeypots.get(honeypotName).getSwName());
		}
		catch(Exception e){
			logger.LogError("switches"+e);
			return false;
		}
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("fail getting switch deleteFlowsForHoneypot");
			return false;
		}
		
		OFFlowMod ruleIncoming = new OFFlowMod();
		ruleIncoming.setOutPort(outPort);
		ruleIncoming.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleIncoming.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		OFMatch match = new OFMatch();	
		match.setWildcards(~0);
		ruleIncoming.setMatch(match.clone());
		
		OFFlowMod ruleOutgoing = new OFFlowMod();
		ruleOutgoing.setOutPort(OFPort.OFPP_NONE);
		ruleOutgoing.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleOutgoing.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		match = new OFMatch();	
		match.setInputPort(outPort);
		match.setWildcards(~(OFMatch.OFPFW_IN_PORT));
		
		ruleOutgoing.setMatch(match.clone());		
		
		try{
			sw.write(ruleIncoming, null);
			sw.write(ruleOutgoing, null);
			sw.flush();
		}
		catch (IOException e){
			logger.LogError("fail delete flows for: "+honeypotName+" "+ruleIncoming+" "+ruleOutgoing);
			return false;
		}
		return true;
	}
	
	private boolean deleteFlows(OFMatch match, long swID){
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch ");
			return false;
		}
		
		OFFlowMod rule = new OFFlowMod();
		rule.setOutPort(OFPort.OFPP_NONE);
		rule.setCommand(OFFlowMod.OFPFC_DELETE);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());
		try{
			sw.write(rule, null);		
			sw.flush();
			logger.LogDebug("succ delete flow "+rule);
		}
		catch (IOException e) 
		{
			logger.LogError("fail delete flows for: "+rule);
			return false;
		}
		return true;
	}
	

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IConnMonitorService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(IConnMonitorService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		
	    connMap = new Hashtable<Long,Connection>();
	    honeypots = new Hashtable<String, HoneyPot>();
	    ports = new Hashtable<Short, Vector<HoneyPot>>();
	    portsForHIH = new Hashtable<Short, Vector<HoneyPot>>();
	    connToPot = new Hashtable<String,Connection>();
	    HIHAvailabilityMap = new Hashtable<String,Boolean>();
	    HIHClientMap = new Hashtable<String, HashSet<Integer> >();
	    HIHNameMap = new Hashtable<Long, String>();
	    HIHFlowCount = new Hashtable<String, Integer>();
	    forwardFlowTable = new ForwardFlowTable();
	    executor = Executors.newFixedThreadPool(1);
	    logger = new MyLogger(); 
		
	    /* Init Switches */
	    switches = new Hashtable<String,Long>();
	    switches.put("lassen", LASSEN_SW);
		switches.put("missouri",MISSOURI_SW);
		
		/* Init Honeypots */
	    initHoneypots();
	    //initPorts();
	    
	    /* Init other honeynet */
	    Honeynet.putHoneynet("nw", IPv4.toIPv4Address("129.105.44.107"), IPv4.toIPv4Address("130.107.240.0"), 20);
	    
	    flowRemovedTasks = new LinkedBlockingQueue<ForwardFlowItem>();
		flowRemovedDoneTasks = new LinkedBlockingQueue<ForwardFlowItem>();
	    
	    lastClearConnMapTime = System.currentTimeMillis();
	    lastClearConnToPotTime = System.currentTimeMillis();

		lastTime = System.currentTimeMillis();
		droppedCounter = 0;
		packetCounter = 1;
		//honeypot_config_path
		
	//	IPv4Netmask mask1 = new IPv4Netmask("130.107.128.0/17");
	//	System.err.println(mask1);
	//	System.err.println("130.107.146.172 : 130.107.128.0/17 "+mask1.inSubnet(IPv4.toIPv4Address("130.107.146.172")));
		//System.err.println("192.1.3.4: 128.0.0.0/5 "+mask1.inSubnet("192.1.3.4"));
	//	IPv4Netmask mask2 = new IPv4Netmask("0.0.0.0/0");
	//	System.err.println("130.107.248.128: 0.0.0.0/0 "+mask2.inSubnet(IPv4.toIPv4Address("130.107.248.128")));
	/*	IPv4Netmask mask2 = new IPv4Netmask("128.0.0.0/10");
		System.err.println("128.32.3.4: 128.0.0.0/10 "+mask2.inSubnet("128.32.3.4"));
		System.err.println("192.1.3.4: 128.0.0.0/10 "+mask2.inSubnet("192.1.3.4"));
		System.err.println("128.64.3.4: 128.0.0.0/10 "+mask2.inSubnet("128.64.3.4"));
		
		IPv4Netmask mask3 = new IPv4Netmask("128.122.160.0/20");
		System.err.println("128.122.168.227: 128.122.32.0/10 "+mask3.inSubnet("128.122.168.227"));
		System.err.println("128.122.158.227: 128.122.32.0/10 "+mask3.inSubnet("128.122.158.227"));
		System.err.println("128.120.160.227: 128.122.32.0/10 "+mask3.inSubnet("128.120.160.227"));
	   
		IPv4Netmask mask4 = new IPv4Netmask("128.122.160.192/28");
		System.err.println("128.122.160.200: 128.122.32.0/10 "+mask4.inSubnet("128.122.160.200"));
		System.err.println("128.122.161.200: 128.122.32.0/10 "+mask4.inSubnet("128.122.161.200"));
		System.err.println("128.122.160.224: 128.122.32.0/10 "+mask4.inSubnet("128.122.160.224"));
	*/
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		 floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		 floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		 floodlightProvider.addOFSwitchListener(this);
		 restApi.addRestletRoutable(new ConnMonitorWebRoutable());
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command processPacketInMessage(
			IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
			FloodlightContext cntx) {
		return null;
	}

	@Override
	public void switchAdded(long switchId) {
		logger.LogDebug("switch added");
		if(switchId == LASSEN_SW){
			logger.LogError("LASSEN switch gets added");
		}
		else if(switchId == MISSOURI_SW){
			logger.LogDebug("MISSOURI switch gets added");
		}
		else{
			logger.LogDebug("Unknown switch gets added "+switchId);
		}
	}

	@Override
	public void switchRemoved(long switchId) {
		if(switchId == LASSEN_SW || switchId==MISSOURI_SW){
			logger.LogDebug("Importatnt switch gets removed "+switchId);
		}
	}

	@Override
	public void switchActivated(long switchId) {
		if(switchId == LASSEN_SW){
			logger.LogDebug("LASSEN switch gets activated");
			initLassenSwitch(switchId);
		}
		else if(switchId == MISSOURI_SW){
			logger.LogDebug("MISSOURI switch gets activated");
			initMissouriSwitch(switchId);
		}
		else{
			logger.LogError("Unknown switch gets activated "+switchId);
		}
	}

	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) {
		if(switchId == LASSEN_SW || switchId==MISSOURI_SW){
		}
	}

	@Override
	public void switchChanged(long switchId) {
		if(switchId == LASSEN_SW || switchId==MISSOURI_SW){
		}
	}
	
	private void initHoneypots(){
		BufferedReader br = null;
	    try {
	    	InputStream ins = this.getClass().getClassLoader().getResourceAsStream(honeypotConfigFileName);
	    	br = new BufferedReader(new InputStreamReader(ins));
	        String line = null;
	        byte[] mac = new byte[6];
	        /* id name ip mac out_port down_ip type switch */
	        while ((line = br.readLine()) != null) {
	        	logger.LogInfo(line);
	        	if(line.startsWith("#"))
	        		continue;
	        	String[] elems = line.split("\t");
	        	int len = elems.length;
	        	int id = Integer.parseInt(elems[0]);
	        	String name = elems[1].trim();
	        	byte[] ip = IPv4.toIPv4AddressBytes(elems[2]);
	        	String[] rawMAC = elems[3].split(":");
	        	for(int i=0; i<6; i++)
	        		mac[i] = (byte)Integer.parseInt(rawMAC[i],16);
	        	short outPort = (short)Integer.parseInt(elems[4]);
	        	byte[] downIP =  IPv4.toIPv4AddressBytes(elems[5]);
	        	byte type = HoneyPot.LOW_INTERACTION;
	        	if(elems[6].trim().equals("H") ){
	        		type = HoneyPot.HIGH_INTERACTION;
	        	}
	        	
	        	String swName = elems[7].trim().toLowerCase();
	        	
	        	honeypots.put(name, new HoneyPot(name,id,ip,mac,downIP,outPort,type,swName));
	        	if(type == HoneyPot.HIGH_INTERACTION){
	        		HIHAvailabilityMap.put(name, false);
	        		HIHNameMap.put((long)id, name);
	        		HIHFlowCount.put(name,0);
	        	}
	        }
	        ins.close();
	        
	        ins = this.getClass().getClassLoader().getResourceAsStream(PortsConfigFileName);
	    	br = new BufferedReader(new InputStreamReader(ins));
	    	/* Port Name Netmask */
	    	while ((line = br.readLine()) != null) {
	        	if(line.startsWith("#") || line.trim().length()==0)
	        		continue;
	        	String[] elems = line.split("\t");
	        	short port = (short)Integer.parseInt(elems[0]);
	        	String name = elems[1].trim();
	        	IPv4Netmask mask = new IPv4Netmask(elems[2]);
	        	
	        	HoneyPot pot = honeypots.get(name);
	        	if(pot == null){
	        		logger.LogError("can't find pot:"+name);
	        		continue;
	        	}
	        	pot.getMask().put(port, mask);
	        	
	        	if(ports.containsKey(port)){
	        		Vector<HoneyPot> pots = ports.get(port);
	        		pots.add(pot);
	        		ports.put(port, pots);
	        	}
	        	else{
	        		System.err.println("debug:"+port+" "+pot.getName());
	        		Vector<HoneyPot> pots = new Vector<HoneyPot>();
	        		pots.add(pot);
	        		ports.put(port, pots);
	        	}
	        	
	        	if(pot.getType()==HoneyPot.HIGH_INTERACTION){
	        		if(portsForHIH.containsKey(port)){
		        		Vector<HoneyPot> pots = portsForHIH.get(port);
		        		pots.add(pot);
		        		portsForHIH.put((short)port, pots);
		        	}
		        	else{
		        		Vector<HoneyPot> pots = new Vector<HoneyPot>();
		        		pots.add(pot);
		        		portsForHIH.put((short)port, pots);
		        	}
	        		logger.LogInfo("HIH "+name+" for port:"+port+" mask:"+elems[2]);
	        	}
	        	else{
	        		logger.LogInfo("LIH "+name+" for port:"+port+" mask:"+elems[2]);
	        	}
	        	
	        }
	    	
	    	Iterator<Map.Entry<Short, Vector<HoneyPot>>> it = ports.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Short, Vector<HoneyPot>> entry = it.next();
				Vector<HoneyPot> pots = ports.get(entry.getKey());
				for(HoneyPot pot : pots){
					  System.err.println("test:"+entry.getKey()+" : "+pot.getName());
				  }
			}
	    	
	    	
	    }catch(Exception e){
	    	logger.LogError("failed to read honeypot_config_path");
	    	e.printStackTrace();
	    }
	}
	
	/*private void initPorts(){		
		ports.put((short)443, "dionaea");
		//ports.put((short)445, "dionaea");
		
		ports.put((short)5060, "dionaea");
		ports.put((short)5061, "dionaea");
		ports.put((short)20, "dionaea");
		ports.put((short)21, "dionaea");
		ports.put((short)42, "dionaea");
		ports.put((short)1433, "dionaea");
		ports.put((short)3306, "dionaea");
		
		ports.put((short)22, "kippo");
		ports.put((short)3389, "kippo");
		ports.put((short)5900, "kippo");
		ports.put((short)4689, "kippo");
		
		
		ports.put((short)135, "dionaea_honeyd");
		ports.put((short)139, "dionaea_honeyd");
		ports.put((short)445, "dionaea_honeyd");
		ports.put((short)446, "dionaea_honeyd");
		
		ports.put((short)80, "honeyd");
		ports.put((short)8080, "kippo_honeyd");
		ports.put((short)8081, "kippo_honeyd");
		
		ports.put((short)4444, "honeyd");
		ports.put((short)5554, "honeyd");
		ports.put((short)9996, "honeyd");
		ports.put((short)8967, "honeyd");
		ports.put((short)9898, "honeyd");
		ports.put((short)20168, "honeyd");
		ports.put((short)1080, "honeyd");
		ports.put((short)3127, "honeyd");
		ports.put((short)3128, "honeyd");
		ports.put((short)10080, "honeyd");
		ports.put((short)110, "honeyd");
		ports.put((short)25, "honeyd");
		ports.put((short)23, "honeyd");
		ports.put((short)6129, "honeyd");
		ports.put((short)1433, "honeyd");
		ports.put((short)3306, "honeyd");
		
		ports.put((short)4899, "kippo_high");
		
	}
	*/

	@Override
	public boolean ReceiveInterestingSrcMsg(String content) {
		logger.LogInfo("TODO: received information: "+content);
		return false;
	}
	
	@Override
	public boolean ReceiveHIHStatus(String pot_name, String status){
		if(status.equals("live")){
			if(HIHAvailabilityMap.containsKey(pot_name)){
				logger.LogDebug("debug: "+pot_name+" is "+status);
				HIHAvailabilityMap.put(pot_name, true);
				return true;
			}
			else{
				logger.LogDebug("debug: "+pot_name+" is not valid pot");
				return false;
			}
		}
		else if(status.equals("dead")){
			if(HIHAvailabilityMap.containsKey(pot_name)){
				logger.LogDebug("debug: "+pot_name+" is "+status);
				HIHAvailabilityMap.put(pot_name, false);	
				HIHClientMap.put(pot_name, new HashSet<Integer>());
				HIHFlowCount.put(pot_name, 0);
				logger.LogDebug("delete all flows toward "+pot_name);
				deleteFlowsForHoneypot(pot_name);
				return true;
			}
			else{
				logger.LogDebug("debug: "+pot_name+" is not valid pot");
				return false;
			}
		}
		else if(status.equals("none")){
			logger.LogError(pot_name+ "does not exist");
			if(HIHAvailabilityMap.containsKey(pot_name)){
				HIHAvailabilityMap.remove(pot_name);
				deleteFlowsForHoneypot(pot_name);
			}
			return false;
		}
		else{
			logger.LogError("error: invalid status: "+status);
			return false;
		}
	}

	@Override
	public List<Connection> getConnections() {
		return null;
	}
	
	private boolean SendUDPData(String data,String dstIP, short dstPort){
		//String url = "http://130.107.10.50:22222/inform";
		try{
			DatagramSocket socket = new DatagramSocket();
			byte[] buf = new byte[256];
			buf = data.getBytes();
			InetAddress dst = InetAddress.getByName(dstIP);
			DatagramPacket packet = new DatagramPacket(buf, buf.length, dst, dstPort);
			socket.send(packet);
			socket.close();
		}
		catch(Exception e){
			logger.LogError("error sending udp: "+e+" "+data);
			return false;
		}
		logger.LogDebug("Sent out data "+data);
		return true;
	}
	
	/* This function is only for demonstration */
	@Override
	public boolean WhetherMigrate(String src_ip, String src_port,
			String lih_ip,String dst_port) {	
		String hih_ip = "10.1.1.2";
		String migration_engine_ip = "10.1.1.10";
		logger.LogInfo("Received migration permission request message from LIH:"+lih_ip+": "+src_ip+":"+src_port+" => "+lih_ip+":"+dst_port);
		if(src_ip.equals("129.105.44.99")){
		}
		else{
			logger.LogInfo("Migration denied for client 129.105.44.60 (POLICY)");
			logger.LogInfo("Replying to LIH’s migration permission inquiry: Don't Migrate");
			return false;
		}
		logger.LogInfo("Looking up HIH table for available HIH with service on port "+dst_port);
	
		IOFSwitch sw = floodlightProvider.getSwitch(MISSOURI_SW);
		Long key = Connection.getConnectionSimplifiedKey(src_ip,lih_ip);
		Connection conn = null;
		if(!(connMap.containsKey(key))){
			logger.LogInfo("Refuse migration: no such connections");
			return false;
		}
		else{ 
			conn = connMap.get(key);
		}
		String public_dst_ip = IPv4.fromIPv4Address(conn.dstIP);
		String flow1 = src_ip+":"+src_port +"=>"+public_dst_ip+":"+dst_port;
		String flow2 = lih_ip+":"+dst_port +"=>"+src_ip+":"+src_port;
		String flow3 = migration_engine_ip+" (MigrationEngine):"+dst_port +"=>"+src_ip+":"+src_port;
		logger.LogInfo("Looking up connection table for the session’s original destination IP: "+IPv4.fromIPv4Address(conn.dstIP));
		logger.LogInfo("Starting flow migration: "+flow1);
		logger.LogInfo("Deleting existing flow rules for flows:");
		logger.LogInfo("\t"+flow1);
		logger.LogInfo("\t"+flow2);
		logger.LogInfo("Adding new flow rules for flows:");
		logger.LogInfo("\t"+flow1);
		logger.LogInfo("\t"+flow3);
		logger.LogInfo("Sending message to MigrationEngine to migrate:");
		logger.LogInfo("\tFlow:"+flow1);
		logger.LogInfo("\tOriginal LIH:"+lih_ip);
		logger.LogInfo("\tNew HIH:"+hih_ip);
		int dst_ip = conn.dstIP;
		//delete e2i
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(src_ip));
		match.setNetworkDestination(dst_ip);
		match.setTransportSource((short)(Integer.parseInt(src_port)));
		match.setTransportDestination((short)(Integer.parseInt(dst_port)));
		match.setInputPort(missouri_default_out_port);
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS );
		deleteFlows(match,MISSOURI_SW);
		
		//delete i2e
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(src_ip));
		match.setTransportSource((short)(Integer.parseInt(dst_port)));
		match.setTransportDestination((short)(Integer.parseInt(src_port)));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_SRC_ALL |
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_IN_PORT);
		deleteFlows(match,MISSOURI_SW);
		
		//drop i2e
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(src_ip));
		match.setNetworkSource(IPv4.toIPv4Address("192.168.1.6"));
		match.setTransportSource((short)(Integer.parseInt(dst_port)));
		match.setTransportDestination((short)(Integer.parseInt(src_port)));
		match.setNetworkProtocol((byte)0x06);
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_IN_PORT);
		installDropRule(sw.getId(),match,IDLE_TIMEOUT,HARD_TIMEOUT,DROP_PRIORITY);
		
		//new e2i
		short outPort = missouri_default_out_port;
		short inPort = missouri_default_out_port;
		
		match = new OFMatch();
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(src_ip));
		match.setNetworkDestination(dst_ip);
		match.setTransportSource((short)(Integer.parseInt(src_port)));
		match.setTransportDestination((short)(Integer.parseInt(dst_port)));
		match.setNetworkProtocol((byte)0x06);

		//match.setInputPort(migration_mac_address);
		match.setWildcards(	
			OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
			OFMatch.OFPFW_NW_TOS |  
			OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
			OFMatch.OFPFW_IN_PORT);
	
		byte[] newDstMac = migration_mac_address;
		byte[] newDstIP = migration_ip_address;
		boolean result1 = installPathForFlow(sw.getId(), inPort,
				match,(short)0,(long)0,
				newDstMac,newDstIP,null,(short)0, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
		
		//new i2e
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(src_ip));
		match.setNetworkSource(IPv4.toIPv4Address(migration_ip_address));
		match.setTransportSource((short)(Integer.parseInt(dst_port)));
		match.setTransportDestination((short)(Integer.parseInt(src_port)));
		match.setNetworkProtocol((byte)0x06);

		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_NW_TOS | 
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_IN_PORT);
		
		newDstMac = nc_mac_address;
		newDstIP= null;
		byte[] newSrcIP = IPv4.toIPv4AddressBytes(dst_ip);
		boolean	result2 = installPathForFlow(sw.getId(), inPort,
							match,(short)0,(long)0,
							newDstMac,null,newSrcIP,(short)0, (short)0,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,HIGH_PRIORITY);
		boolean result = result1 & result2;
		boolean rs = false;
		
		if(result){
			 rs = SendUDPData(src_ip+":"+src_port+":"+public_dst_ip+":"+dst_port+":"+lih_ip+":"+hih_ip+":",migrationEngineIP, migrationEngineListenPort);
		}
		else{
			logger.LogError("Fail setting rules WhetherMigrate");
		}
		
		logger.LogInfo("Replying to LIH’s migration permission inquiry: Do Migrate");
		return rs;
	}
	
}
