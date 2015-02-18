package net.floodlightcontroller.connmonitor;

import java.util.Hashtable;

import net.floodlightcontroller.connmonitor.ForwardFlowItem.ForwardFLowItemState;

public class ForwardFlowTable {
	/* since we only have two threads, it's not necessary to use concurrentHashtable */
	private Hashtable<String, ForwardFlowItem> table;
	private Hashtable<Long,String> cookie_key_map;
	private long cookie_count;
	private static int MAX_SIZE = 50000;
	
	
	public ForwardFlowTable(){
		table = new Hashtable<String, ForwardFlowItem>();
		cookie_key_map = new Hashtable<Long,String>();
		cookie_count = 0;
	}
	public String fromCookieToKey(long cookie){
		return cookie_key_map.get(cookie);
	}
	private long getNextCookie(){
		cookie_count = (cookie_count + 1) & 0x8fffffffffffffffL;
		while(true){
			if(cookie_key_map.containsKey(cookie_count))
				cookie_count = (cookie_count + 1) & 0x8fffffffffffffffL;
			else
				return cookie_count;
		}
	}
	
	public void putCookieStringMap(long cookie, String key){
		cookie_key_map.put(cookie, key);
		if(cookie_key_map.size()>MAX_SIZE){
			System.err.println("ALERT!!! cookie_key_map size too large, something is not right...");
			cookie_key_map.clear();
		}
	}
	public void removeCookieStringMap(long cookie){
		cookie_key_map.remove(cookie);
	}
	
	public synchronized void clear(){
		System.err.println("hard clear ForwardFlowTable: FIXME can't guarantee two switches are consistent");
		table.clear();
		cookie_key_map.clear();
	}
	
	public synchronized long put(String key, ForwardFlowItem item){
		
		if(table.size() > 20){
			System.err.println("change this part ForwardFlowTable:51");
			for(String k : table.keySet()){
				
				ForwardFlowItem value = table.get(k);
				if(value.getState()==ForwardFLowItemState.FREE){
					System.err.println(" debug: "+k);
					table.remove(k);
				}
			}
			System.err.println("light clear ForwardFlowTable size:"+table.size());
			if(table.size() > MAX_SIZE/2){
				clear();
			}
		}
		long cookie = getNextCookie();
		putCookieStringMap(cookie,key);
		item.setFlow_cookie(cookie);
		table.put(key, item);
		
		return cookie;
	}
	
	public synchronized boolean updateItemState(String key, ForwardFlowItem.ForwardFLowItemState state){
		if(table.containsKey(key)){
			table.get(key).setState(state);
			return true;
		}
		return false;
	}
	public synchronized boolean updateStartingtime(String key, long time){
		if(table.containsKey(key)){
			table.get(key).setStarting_time(time);
			return true;
		}
		return false;
	}
	public synchronized void remove(String key){
		if(table.contains(key))
			cookie_key_map.remove(table.get(key).getFlow_cookie());
		table.remove(key);
	}
	
	public boolean containsKey(String key){
		return table.containsKey(key);
	}
	public int size(){
		return table.size();
	}
	public ForwardFlowItem get(String key){
		return table.get(key);
	}
}
