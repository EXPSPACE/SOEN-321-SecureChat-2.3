package codebase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import infrastructure.ChatClient;

/**
 * ChatClient implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * 
 * Here MyChatClient (of your choice) extends it and implements the actual
 * client-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 *
 * Note that A and B are distinguished by the boolean value with the
 * constructor.
 */
class MyChatClient extends ChatClient {

	MyChatClient(boolean IsA) { // This is the minimum constructor you must
								// preserve
		super(IsA); // IsA indicates whether it's client A or B
		startComm(); // starts the communication
		clientCrypto = new ChatCrypto();	
	}

	/** The current user that is logged in on this client **/
	public String curUser = "";
	
	//object containing cryptographic info needed for secure connection from client to server
	private ChatCrypto clientCrypto;
	private File privKeyFile;

	/** The Json array storing the internal history state */
	JsonArray chatlog;

	/**
	 * Actions received from UI
	 */

	/**
	 * Someone clicks on the "Login" button
	 */
	public void LoginRequestReceived(String uid, String pwd) {
		
		ChatPacket cp = new ChatPacket();
		
		//load keys
		clientCrypto.loadRSAPublicKey(new File("certificate/server.crt")); //server public key
		clientCrypto.loadRSAPrivateKey(privKeyFile); //alice or bob private key
		
		clientCrypto.genClientDHKeyPair();
		
		cp.request = ChatRequest.DH_REQ;
		cp.dhPublicKey = clientCrypto.getDHPublicKey();
		cp.signature = clientCrypto.getSignature(cp.dhPublicKey.getEncoded());
		cp.uid = clientCrypto.getCertificateName(); 

		SerializeNSend(cp);
	}
	
	/**
	 * Callback invoked when the certificate file is selected
	 * @param certFile Selected certificate file's path
	 */
	public void FileLocationReceivedCert(File certFile) {
		clientCrypto.loadCertificateName(certFile);
	}
	
	/**
	 * Callback invoked when the private key file is selected
	 * @param keyFile Selected private key file's path
	 */
	public void FileLocationReceivedPriv(File keyFile) {
		privKeyFile = keyFile;		
	}
	
	/**
	 * Callback invoked when an authentication mode is selected. 
	 * @param IsPWD True if password-based (false if certificate-based).
	 */
	public void ReceivedMode(boolean IsPWD) {
		//application only functions for certificate based mode selecting the checkbox does nothing
	}


	/**
	 * Someone clicks on the "Logout" button
	 */
	public void LogoutRequestReceived() {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.LOGOUT;

		SerializeNSend(p);
	}

	/**
	 * Someone clicks on the "Send" button
	 * @param message Message to be sent (user's level)
	 */
	public void ChatRequestReceived(byte[] message) {
	
		if(clientCrypto.isAuthenticated()) {
			ChatPacket p = new ChatPacket();
			p.request = ChatRequest.CHAT;
			p.uid = curUser;
			
			//encrypt data to be sent
			byte[] iv = ChatCrypto.genRandomIV();
			
			
			p.data = clientCrypto.getEncryptedMsg(message,iv);
			p.iv = iv;
			
			SerializeNSend(p);
		}

	}

	/**
	 * Methods for updating UI
	 */

	/**
	 * This will refresh the messages on the UI with the Json array chatlog
	 */
	void RefreshList() {
		String[] list = new String[chatlog.size()];
		for (int i = 0; i < chatlog.size(); i++) {
			String from = chatlog.getJsonObject(i).getString("from");
			String to = chatlog.getJsonObject(i).getString("to");
			String message = chatlog.getJsonObject(i).getString("message");
			list[i] = (from + "->" + to + ": " + message);
		}
		UpdateMessages(list);
	}

	/**
	 * Methods invoked by the network stack
	 */

	/**
	 * Callback invoked when a packet has been received from the server
	 * (as the client only talks with the server, but not the other client)
	 * @param buf Incoming message
	 */
	public void PacketfromServer(byte[] buf) {
		ByteArrayInputStream is = new ByteArrayInputStream(buf);
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(is);
			Object o = in.readObject();
			ChatPacket sp = (ChatPacket) o;
			
			if (sp.request == ChatRequest.DH_ACK) {
				
				//make sure dh public key was sent from server
				boolean verifiedClientSide = clientCrypto.verifySignature(sp.signature, sp.dhPublicKey.getEncoded());
				
				if(verifiedClientSide) {
					
					//create shared aes key
					clientCrypto.genSharedSecretAESKey(sp.dhPublicKey);
					curUser = sp.uid; 
					
					System.out.println("Client: " + curUser + " verification of server signed dh public param passed.");
					
					//create auth request packet client -> server
					ChatPacket cp = new ChatPacket();
					cp.request = ChatRequest.AUTH_REQ;
					cp.uid = curUser;
					byte[] iv = ChatCrypto.genRandomIV();
					cp.data = clientCrypto.getEncryptedMsg(ChatCrypto.AUTH_CODE,iv);
					cp.iv = iv;
					SerializeNSend(cp);
					

				} else {
					System.out.println("Client: " + curUser + " verification of server signed dh public param failed.");
					System.out.println("WARNING: man-in-the-middle attack server -> client.");
				}
				
			} else if (sp.request == ChatRequest.AUTH_REQ) {
	
				//confirm authentication of client
				clientCrypto.authenticateConnection(sp.data, sp.iv);
				
				//create auth request packet server -> client
				if(clientCrypto.isAuthenticated()) {
					System.out.println("Client: authentication of server complete, secure connection established.");
				} else {
					System.out.println("Client: authentication of server failed, secure connection not established.");
					System.out.println("WARNING: replay attack server -> client.");
				}
			
				// Time to load the chatlog
				InputStream ins = null;
				JsonReader jsonReader;
				File f = new File(this.getChatLogPath());
				if (f.exists() && !f.isDirectory()) {
					try {
						ins = new FileInputStream(this.getChatLogPath());
						jsonReader = Json.createReader(ins);
						chatlog = jsonReader.readArray();
					} catch (FileNotFoundException e) {
						System.err.println("Chatlog file could not be opened.");
					}
				} else {
					try {
						f.createNewFile();
						ins = new FileInputStream(this.getChatLogPath());
						chatlog = Json.createArrayBuilder().build();
					} catch (IOException e) {
						System.err.println("Chatlog file could not be created or opened.");
					}
				}
				
				RefreshList();
				
			}else if (sp.request == ChatRequest.RESPONSE && sp.success.equals("LOGOUT")) {
				// Logged out, save chat log and clear messages on the UI
				SaveChatHistory();
				curUser = "";
				UpdateMessages(null);
				
			} else if (sp.request == ChatRequest.CHAT && !curUser.equals("")) {			
				
				byte[] decryptedMessage = clientCrypto.getDecryptedMsg(sp.data, sp.iv);
				Add1Message(sp.uid, curUser, decryptedMessage);
			} else if (sp.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
				
				// This was sent by us and now it's confirmed by the server				
				byte[] decryptedMessage = clientCrypto.getDecryptedMsg(sp.data, sp.iv);
				Add1Message(curUser, sp.uid, decryptedMessage);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}
	
	
	/**
	 * Gives the path of the local chat history file (user-based)
	 */
	private String getChatLogPath() {
		return "log/chatlog-" + curUser + ".json";
	}

	/**
	 * Methods dealing with local processing
	 */

	/**
	 * This method saves the Json array storing the chat log back to file
	 */
	public void SaveChatHistory() {
		if (curUser.equals(""))
			return;
		try {
			// The chatlog file is named after both the client and the user
			// logged in

			OutputStream out = new FileOutputStream(this.getChatLogPath());
			JsonWriter writer = Json.createWriter(out);
			writer.writeArray(chatlog);
			writer.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Similar to the one in MyChatServer, serializes and send the Java object
	 * @param p ChatPacket to serialize and send
	 */
	private void SerializeNSend(ChatPacket p) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
			out = new ObjectOutputStream(os);
			out.writeObject(p);
			byte[] packet = os.toByteArray();
			SendtoServer(packet);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	/**
	 * Adds a message to the internal's client state 
	 * @param from From whom the message comes from
	 * @param to To whom the messaged is addressed
	 * @param buf Message
	 */
	private void Add1Message(String from, String to, byte[] buf) {
		JsonArrayBuilder builder = Json.createArrayBuilder();
		for (int i = 0; i < chatlog.size(); i++) {
			builder.add(chatlog.getJsonObject(i));
		}
		try {
			builder.add(Json.createObjectBuilder().add("from", from).add("to", to).add("time", "").add("message",
					new String(buf, "UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		JsonArray newl = builder.build();
		chatlog = newl;
		RefreshList();

	}
}
