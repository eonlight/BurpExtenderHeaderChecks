package versionchecker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;

public class BurpIO {

	public static BurpIO burpIO = null;
	
	public PrintWriter stdout, stderr;
	private HashMap<Integer, VersionConfig> config;
	private ArrayList<String> configs;

	private IBurpExtenderCallbacks callbacks;
	
	private static final String NAME = "BurpIO";
	private static final String VERSION = "0.1.0";
	
	public static void createInstance(IBurpExtenderCallbacks callbacks) {
		if(burpIO == null)
			burpIO = new BurpIO(callbacks);
	}
	
	public static BurpIO getInstance(){
		return burpIO;
	}
	
	public BurpIO(IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);
		this.configs = new ArrayList<String>();
		
		String configsCountSetting = callbacks.loadExtensionSetting("versionCheckerConfigCount");
		if(configsCountSetting != null && !configsCountSetting.equals("0"))
			this.config = this.loadVersionCheckerConfigs(Integer.parseInt(configsCountSetting));
		else
			this.config  = this.generateConfig("config.xml");
		
		this.write("[*] Created " + NAME + " v" + VERSION);
	}
	
	public void write(String output){
		this.stdout.write(output + "\n");
		this.stdout.flush();
	}
	
	public void error(String output){
		this.stderr.write(output + "\n");
		this.stderr.flush();
	}
	
	private HashMap<Integer, VersionConfig> loadVersionCheckerConfigs(int count){
		HashMap<Integer, VersionConfig> map = new HashMap<Integer, VersionConfig>();
		
		for(int i = 0; i < count; i++){
			String name = callbacks.loadExtensionSetting("software" + i);
			String url = callbacks.loadExtensionSetting(name + "URL");
			String regex = callbacks.loadExtensionSetting(name + "Regex");
			VersionConfig vc = new VersionConfig(name, url, regex);
			this.configs.add(vc.software);
			map.put(vc.id, vc);
		}
		
		return map;
	}
	
	public void saveCurrentVersionCheckerConfigs() {
		callbacks.saveExtensionSetting("versionCheckerConfigCount", "" + configs.size());
		
		for(int i = 0; i < configs.size(); i++){
			String name = configs.get(i);
			callbacks.saveExtensionSetting("software" + i, name);
			VersionConfig vc = config.get(name.toLowerCase().hashCode());
			callbacks.saveExtensionSetting(name + "URL", vc.url);
			callbacks.saveExtensionSetting(name + "Regex", vc.regex);
		}
	}
	
	public VersionConfig addVersionConfig(String software, String url, String regex){
		VersionConfig versionConfig = new VersionConfig(software, url, regex);
		if(this.config.containsKey(versionConfig.id))
			return null;
		this.config.put(versionConfig.id, versionConfig);
		this.configs.add(versionConfig.software);
		return versionConfig;
	}
	
	public void resetConfig(){
		this.configs = new ArrayList<String>();
		this.config = this.generateConfig("config.xml");
	}
	
	public VersionConfig removeConfig(int id){
		VersionConfig c = this.config.remove(id);
		if(c != null)
			this.configs.remove(c.software);
		return c;
	}
	
	public VersionConfig getVersionConfig(int id){
		return this.config.get(id);
	}
	
	public String[][] getVersionConfigs(){
		String [][] vcs = new String[this.config.size()][4];
		for(int i = 0; i< this.configs.size(); i++){
			VersionConfig c = this.config.get(this.configs.get(i).toLowerCase().hashCode());
			if(c != null){
				vcs[i][0] = "" + c.id;
				vcs[i][1] = c.software;
				vcs[i][2] = c.url;
				vcs[i][3] = c.regex;
			} else {
				vcs[i][0] = "null";
				vcs[i][1] = "null";
				vcs[i][2] = "null";
				vcs[i][3] = "null";
			}
		}
		return vcs;
	}
	
	public String getLastestVersion(int id){
		String version = null;
		
		VersionConfig vc = this.config.get(id);
				
		if(vc != null){			
			String response = makeGetRequest(vc.url);
			
			if(response == null)
				return "0.0.0";
			
			Pattern pattern = Pattern.compile(vc.regex);
			Matcher matcher = pattern.matcher(response);
			if(matcher.find())
				version = matcher.group(0);
			
			if(version != null){
				Matcher versionMatcher = VersionFinding.versionRegex.matcher(version);
				if(versionMatcher.find())
					version = versionMatcher.group(0);
			}
		}
		
		return version;
	}
	
	public static String makeGetRequest(String url){
		StringBuffer response = new StringBuffer();
		try {
			URLConnection connection = new URL(url).openConnection();				
			BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			while ((url = in.readLine()) != null)
				response.append(url);
			in.close();
			return response.toString();
		} catch(ConnectException e){
			// Connection timeout - do nothing
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		} catch (MalformedURLException e) {
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		} catch (IOException e) {
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		} catch(Exception e){
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		}
		
		return null;
	}
	
	private HashMap<Integer, VersionConfig> generateConfig(String filename){
		HashMap<Integer, VersionConfig> map = new HashMap<Integer, VersionConfig>();
		
		try {
			DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();

			Document dom = documentBuilder.parse(this.getClass().getResourceAsStream(filename));
			Element root = dom.getDocumentElement();

			NodeList configs = root.getElementsByTagName("config");
			for(int i = 0; i < configs.getLength(); i++){
				Element xmlConfig = (Element) configs.item(i);
				String name = ((Element) xmlConfig.getElementsByTagName("name").item(0)).getFirstChild().getNodeValue();
				String url = ((Element) xmlConfig.getElementsByTagName("url").item(0)).getFirstChild().getNodeValue();
				String regex = ((Element) xmlConfig.getElementsByTagName("regex").item(0)).getFirstChild().getNodeValue();
				VersionConfig vc = new VersionConfig(name, url, regex);
				this.configs.add(vc.software);
				map.put(vc.id, vc);
			}
			
		}catch(ParserConfigurationException e) {
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		}catch(SAXException e) {
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		}catch(IOException e) {
			if(BurpExtender.DEBUG)
				e.printStackTrace(BurpIO.getInstance().stderr);
		}
		
		return map;
	}
}
