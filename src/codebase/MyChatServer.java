package codebase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import infrastructure.ChatServer;

/**
 * ChatServer implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * 
 * Here MyChatServer (of your choice) extends it and implements the actual
 * server-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 *
 */
class MyChatServer extends ChatServer {

	/** A Json array loaded from disk file storing plaintext uids and pwds. */
	JsonArray database;

	/**
	 * Client login status; "" indicates not logged in or otherwise is set to
	 * uid.
	 **/
	String statA = "";
	String statB = "";

	// objects containing cryptographic info needed for secure connections to
	// alice and bob
	ChatCrypto serverCryptoAlice;
	ChatCrypto serverCryptoBob;

	// In Constructor, the user database is loaded.
	MyChatServer() {
		try {
			InputStream in = new FileInputStream("database.json");
			JsonReader jsonReader = Json.createReader(in);
			database = jsonReader.readArray();

		} catch (FileNotFoundException e) {
			System.err.println("Database file not found!");
			System.exit(-1);
		}
		
		//assumption is that server already has valid certificates for alice and bob (and hence public keys)
		serverCryptoAlice = new ChatCrypto();
		serverCryptoAlice.loadRSAPrivateKey(new File("privatekey/server.key.pem"));
		serverCryptoAlice.loadRSAPublicKey(new File("certificate/alice.crt"));
		
		serverCryptoBob = new ChatCrypto();
		serverCryptoBob.loadRSAPrivateKey(new File("privatekey/server.key.pem"));
		serverCryptoBob.loadRSAPublicKey(new File("certificate/bob.crt"));
	}

	/**
	 * Methods invoked by the network stack
	 */

	/**
	 * Overrides the function in ChatServer Whenever a packet is received this
	 * method is called and IsA indicates whether it is from A (or B) with the
	 * byte array of the raw packet
	 */
	public void PacketReceived(boolean IsA, byte[] buf) {
		ByteArrayInputStream is = new ByteArrayInputStream(buf);
		ObjectInput in = null;
		ChatCrypto connectedCrypto; 
		
		//establish which cryptographic connection information to use
		if(IsA) { 
			connectedCrypto = serverCryptoAlice;
		} else {
			connectedCrypto = serverCryptoBob;
		}
		
		try {
			in = new ObjectInputStream(is);
			Object o = in.readObject();
			ChatPacket cp = (ChatPacket) o;

			if (cp.request == ChatRequest.DH_REQ) {
				
				// We want to go through all records
				for (int i = 0; i < database.size(); i++) {

					JsonObject l = database.getJsonObject(i);

					// user is registered
					if (l.getString("uid").equals(cp.uid)) {
						
						// We do not allow one user to be logged in on multiple
						// clients
						if (cp.uid.equals(IsA ? statB : statA))
							continue;

						boolean verifiedServerSide = connectedCrypto.verifySignature(cp.signature, cp.dhPublicKey.getEncoded());		
						
						if(verifiedServerSide) { 
							connectedCrypto.genServerDHKeyPair(cp.dhPublicKey);
							connectedCrypto.genSharedSecretAESKey(cp.dhPublicKey);
							
							System.out.println("Server: verification of client " + cp.uid + " signed dh public param passed.");
							
							//return acknowledgement packet of verified dh public parameter
							ChatPacket sp = new ChatPacket();
					
							sp.request = ChatRequest.DH_ACK;
							sp.dhPublicKey = connectedCrypto.getDHPublicKey();
							sp.signature = connectedCrypto.getSignature(sp.dhPublicKey.getEncoded());
							sp.uid = cp.uid; 
		
							SerializeNSend(IsA, sp);		
						} else {
							System.out.println("Server: verification of client " + cp.uid + " signed dh public param failed.");	
							System.out.println("WARNING: man-in-the-middle attack client -> server.");
						}
						
						break;
					}

				}

				if ((IsA ? statA : statB).equals("")) {
					// Oops, this means a failure, we tell the client so
					RespondtoClient(IsA, "");
				}
			} else if (cp.request == ChatRequest.AUTH_REQ) {
				
				//confirm authentication of client
				connectedCrypto.authenticateConnection(cp.data, cp.iv);
				
				//create auth request packet server -> client
				if(connectedCrypto.isAuthenticated()) {
					
					System.out.println("Server: authentication of client " + cp.uid + " complete.");
					
					ChatPacket sp = new ChatPacket();
					sp.request = ChatRequest.AUTH_REQ;
					sp.uid = cp.uid;
					byte[] iv = new byte[16]; //TODO: set to generate new random iv
					sp.data = connectedCrypto.getEncryptedMsg(ChatCrypto.AUTH_CODE,iv);
					sp.iv = iv;
					SerializeNSend(IsA, sp);
					
					// Update the corresponding login status
					if(IsA) {
						statA = cp.uid;
					} else {
						statB = cp.uid;
					}
					
					// Update the UI to indicate this
					UpdateLogin(IsA, (IsA ? statA : statB)); 					
				} else {
					System.out.println("Server: authentication of client " + cp.uid + " failed.");
					System.out.println("WARNING: replay attack client -> server.");
				}
								
			}
			
			else if (cp.request == ChatRequest.LOGOUT) {
				if (IsA) {
					statA = "";
				} else {
					statB = "";
				}
				UpdateLogin(IsA, "");
				RespondtoClient(IsA, "LOGOUT");

			} else if (cp.request == ChatRequest.CHAT) {
		
				// Whenever sending both clients must be authenticated for message to pass
				if(serverCryptoAlice.isAuthenticated() && serverCryptoBob.isAuthenticated()) {
					
					// Flip the uid and send it back to the sender for updating
					// chat history
					cp.request = ChatRequest.CHAT_ACK;
					cp.uid = (IsA ? statB : statA);
					SerializeNSend(IsA, cp);
					
					//establish sender and reciever
					ChatCrypto senderConnection;
					ChatCrypto recieverConnection;
					
					if(IsA) {
						senderConnection = serverCryptoAlice;
						recieverConnection = serverCryptoBob;
					} else {
						senderConnection = serverCryptoBob;
						recieverConnection = serverCryptoAlice;
					}
					
					//forward original packet after server translation
					
					//recieving packet data gets decrypted using sender shared AES key, this is then re-encrypted using
					//shared AES key of sender and sent to reciever
					
					cp.request = ChatRequest.CHAT;
					cp.uid = (IsA ? statA : statB);
					ChatCrypto.decryptReEncryptPacket(cp, senderConnection, recieverConnection);
					SerializeNSend(!IsA, cp);
				
				} else {
					System.out.println("Secure communications failed, both parties not authenticated.");
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}


	/**
	 * Methods for updating UI
	 */

	// You can use this.UpdateServerLog("anything") to update the TextField on
	// the server portion of the UI
	// when needed

	/**
	 * Methods invoked locally
	 */

	/**
	 * This method serializes (into byte[] representation) a Java object
	 * (ChatPacket) and sends it to the corresponding recipient (A or B)
	 */
	private void SerializeNSend(boolean IsA, ChatPacket p) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
			out = new ObjectOutputStream(os);
			out.writeObject(p);
			byte[] packet = os.toByteArray();
			SendtoClient(IsA, packet);
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
	 * This method composes the packet needed to respond to a client (indicated
	 * by IsA) regarding whether the login/logout request was successful
	 * p.success would be "" if failed or "LOGIN"/"LOGOUT" respectively if
	 * successful
	 */
	void RespondtoClient(boolean IsA, String Success) {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.RESPONSE;
		p.uid = IsA ? statA : statB;
		p.success = Success;

		SerializeNSend(IsA, p);
	}

}
