package net.floodlightcontroller.connmonitor;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;


public class FlowRemoveMsgSender extends Thread {
	protected ConcurrentLinkedQueue<ForwardFlowItem> undoneTask;
	protected ConcurrentLinkedQueue<ForwardFlowItem> doneTask;
	protected HttpClient httpclient;
	protected String targetURL;
	
	public FlowRemoveMsgSender(ConcurrentLinkedQueue<ForwardFlowItem> undoneTask, ConcurrentLinkedQueue<ForwardFlowItem> doneTask, String url){
		this.undoneTask = undoneTask;
		this.doneTask = doneTask;
		this.httpclient = HttpClients.createDefault();
		this.targetURL = url;
	}
	
	public void run() {
		HttpPost httppost = null;
		while(true){
			try{
				ForwardFlowItem item = undoneTask.poll();
				if(item == null){
					 Thread.sleep(5000);
					 continue;
				}
				httppost = new HttpPost(targetURL);
				List<NameValuePair> params = new ArrayList<NameValuePair>(2);
				short srcPort = item.getNew_src_port()==0?item.getSrc_port():item.getNew_src_port();
				params.add(new BasicNameValuePair("srcIP", String.valueOf(item.getSrc_ip())));
				params.add(new BasicNameValuePair("srcPort", String.valueOf(srcPort)));
				params.add(new BasicNameValuePair("dstIP", String.valueOf(item.getDst_ip())));
				params.add(new BasicNameValuePair("dstPort", String.valueOf(item.getDst_port())));
				httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
				System.err.println("FlowRemoveMsgSender DEBUG request has been prepared");
				
				HttpResponse response = httpclient.execute(httppost);
				HttpEntity entity = response.getEntity();
				System.err.println("FlowRemoveMsgSender DEBUG response has been received");
				
				if (entity != null) {
				    InputStream instream = entity.getContent();
				    String rs = null;
				    try{
				    	rs = FlowRemoveMsgSender.readString(instream);
				    }
				    catch(IOException e){
				    	System.err.println("FlowRemoveMsgSender IOException read response:"+e);
				    }
				    System.err.println("FlowRemoveMsgSender DEBUG response: "+rs);
				}
				else{
					System.err.println("FlowRemoveMsgSender Exception doesn't get response");
				}
				doneTask.add(item);
				System.err.println("FlowRemoveMsgSender DEBUG undoneTask:"+undoneTask.size()+" doneTask:"+doneTask.size());
			}
			catch(Exception e){
				System.err.println("FlowRemoveMsgSender Exception "+e);
			}
			
		}
    }
	
	static private String readString(InputStream is) throws IOException {
		  char[] buf = new char[2048];
		  Reader r = new InputStreamReader(is, "UTF-8");
		  StringBuilder s = new StringBuilder();
		  while (true) {
		    int n = r.read(buf);
		    if (n < 0)
		      break;
		    s.append(buf, 0, n);
		  }
		  return s.toString();
		}
	
}
