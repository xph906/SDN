package net.floodlightcontroller.connmonitor;

import java.util.ArrayList;
import java.util.List;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.json.JSONObject;;

public class ConnMonitorResource extends ServerResource {
	 
	@Get("json")
	 public List<Connection> retrieve() {
		 return null;
	 }
	
	 @Post
	 public String store(String info){
		JSONObject obj = null;
		String name = null;
		String status = null;
		 
		 try{
			 obj = new JSONObject(info);
			 name = obj.getString("name").toLowerCase().trim();
			 status = obj.getString("status").toLowerCase().trim();
		 }
		 catch(Exception e){
			 System.err.println("parsing json object fail: "+info);
			 return "false";
		 }
		 IConnMonitorService service = (IConnMonitorService)getContext().getAttributes().get(IConnMonitorService.class.getCanonicalName());
		 
		 if(status.equals("migrate")) {
			String ip = null;
			String src_port = null;
			String dst_port = null;
		    String dst_ip = null;
			try{
				obj = new JSONObject(info);
			    ip = obj.getString("src_ip").toLowerCase().trim();
				 //dst_ip = obj.getString("dst_ip").toLowerCase().trim();
				dst_ip = "192.168.1.6";
				System.err.println("change dst_ip in store function!!!");
			    src_port = obj.getString("src_port").toLowerCase().trim();
				 dst_port = obj.getString("dst_port").toLowerCase().trim();
			 }
			 catch(Exception e){
				 System.err.println("parsing json object fail: "+e+" "+info);
				 return "false";
			 } 
			 boolean rs = service.WhetherMigrate(ip, src_port, dst_ip,dst_port);
			 return String.valueOf(rs);
        }
        else if(status.equals("test")){
		    String data = null;
			try{
			    obj = new JSONObject(info);
				data = obj.getString("data").toLowerCase().trim();
			 }
			 catch(Exception e){
				 System.err.println("parsing json object fail: "+e+" "+info);
				 return "false";
			 } 
            String rs_str = "SERVER RS:"+name+" "+data;
            return rs_str;
        }
		 else{
			 boolean rs = service.ReceiveHIHStatus(name, status);
			 return String.valueOf(rs); 
		 }

	 }
	 
	 
	 
}
