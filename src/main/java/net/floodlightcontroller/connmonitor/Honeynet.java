package net.floodlightcontroller.connmonitor;

import java.util.Collection;
import java.util.Hashtable;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

public class Honeynet {
	static private Hashtable<String, Honeynet> honeynets = new Hashtable<String, Honeynet>();
	static public Honeynet getHoneynetFromPacket(Ethernet eth){
		return null;
	}
	/* create one if it doesn't exist */
	static public boolean putHoneynet(String name, int ip, int mask, int mask_width, FlowRemoveMsgSender sender){
		if(honeynets.get(name)==null){
			Honeynet h = new Honeynet(name,ip,mask,mask_width,sender);
			int id = honeynets.size()+1;
			h.setId(id);
			honeynets.put(name, h);
			return true;
		}
		return false;
	}
	static public Collection<Honeynet> getAllHoneynets(){
		return honeynets.values();
	}
	static public boolean inSubnet(SubnetMask mask, int ip){
		int right = 32 - mask.mask_width;
		int x = 0xffffffff;
		x <<= right;
		int new_ip = ip & x;
		
		if(new_ip == mask.subnet)
			return true;
		return false;
	}
	
	class SubnetMask{
		public int subnet;
		public int mask_width;
		SubnetMask(int s, int m){
			subnet = s;
			mask_width = m;
		}
		public String toString(){
			String ip_tmp = IPv4.fromIPv4Address(subnet);
			return ip_tmp+"/"+String.valueOf(mask_width);
		}
	}
	
	public SubnetMask getMask() {
		return mask;
	}
	public void setMask(SubnetMask mask) {
		this.mask = mask;
	}
	/* only returns what we have */
	static public Honeynet getHoneynet(String name){
		return honeynets.get(name);
	}
	
	private String name;
	private FlowRemoveMsgSender sender;
	private int id;
	private int ip;
	private SubnetMask mask; /*SRI IP range*/
	private Honeynet(String n, int addr, int m, int mask_len, FlowRemoveMsgSender sender){
		name = n;
		ip = addr;
		mask = new SubnetMask(m,mask_len);
		this.setSender(sender);
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public int getIp() {
		return ip;
	}
	public void setIp(int ip) {
		this.ip = ip;
	}
	public FlowRemoveMsgSender getSender() {
		return sender;
	}
	public void setSender(FlowRemoveMsgSender sender) {
		this.sender = sender;
	}
	
}
