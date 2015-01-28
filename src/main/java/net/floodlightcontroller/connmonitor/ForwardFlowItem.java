package net.floodlightcontroller.connmonitor;

import java.util.Random;

public class ForwardFlowItem {
	private long starting_time;
	private long timeout;
	private int src_ip;
	private short src_port;
	private int dst_ip;
	private short dst_port;
	private int new_src_port;
	
	static public String generateForwardFlowTableKey(int src_ip, short src_port, int dst_ip, short dst_port){
		StringBuilder sb = new StringBuilder();
		sb.append(src_ip);
		sb.append(':');
		sb.append(src_port);
		sb.append('_');
		sb.append(dst_ip);
		sb.append(':');
		sb.append(dst_port);
		return sb.toString();
	} 
	static public short generateRandomPortNumber(){
		Random rnd = new Random();
		return (short)(rnd.nextInt()&0x0000ffff );
		
	}
	
	/* new_src_port == 0 => src_port not getting changed */
	public ForwardFlowItem(int src_ip, short src_port, int dst_ip, short dst_port, short new_src_port, long timeout){
		this.src_ip = src_ip;
		this.src_port = src_port;
		this.dst_ip = dst_ip;
		this.dst_port = dst_port;
		if(new_src_port==0)
			this.new_src_port = src_port;
		else
			this.new_src_port = new_src_port;
		
		this.timeout = timeout;	
		this.starting_time = System.currentTimeMillis();
	}
	
	public boolean expire(){
		long current_time = System.currentTimeMillis();
		if(current_time > timeout+starting_time)
			return true;
		return false;
	}
	public void update(){
		starting_time = System.currentTimeMillis();
	}
	
	
	public long getStarting_time() {
		return starting_time;
	}
	public void setStarting_time(long starting_time) {
		this.starting_time = starting_time;
	}
	public long getTimeout() {
		return timeout;
	}
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	public int getSrc_ip() {
		return src_ip;
	}
	public void setSrc_ip(int src_ip) {
		this.src_ip = src_ip;
	}
	public short getSrc_port() {
		return src_port;
	}
	public void setSrc_port(short src_port) {
		this.src_port = src_port;
	}
	public int getDst_ip() {
		return dst_ip;
	}
	public void setDst_ip(int dst_ip) {
		this.dst_ip = dst_ip;
	}
	public short getDst_port() {
		return dst_port;
	}
	public void setDst_port(short dst_port) {
		this.dst_port = dst_port;
	}
	public int getNew_src_port() {
		return new_src_port;
	}
	public void setNew_src_port(int new_src_port) {
		this.new_src_port = new_src_port;
	}
	
}
