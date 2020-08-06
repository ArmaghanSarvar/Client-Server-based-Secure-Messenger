import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class ClientHandler extends Thread {
    private static final Object lock = new Object();
    private Socket socket;
    private Server server;
    private String sessionKey;
    private int clientNumber;
    private long startTime;
    private DataOutputStream os = null;
    private DataInputStream is = null;
    private byte[] inputBuffer;
    private String serverPrivateKey;
    private boolean errorInMac = false;

    private static final int delay = 0;
    private String physicalKey;
    private String publicKey;

    private int messageByteSize;
    private int dataSize;
    private int messageEncryptedSize;
    private byte[] messageMessage;
    private int client2;
    private boolean isFile;

    private String filePath;
    private int filePacketIndex;
    private int fileNumberOfPackets;
    private int fileContentLength;
    private ArrayList<Integer> packetLengths = new ArrayList<>();

    private ArrayList<Integer> packetEncryptedLengths = new ArrayList<>();
    private ArrayList<byte[]> packets = new ArrayList<>();

    private HashMap<Integer, Boolean> errorPacketsMap = new HashMap<>();

    private ArrayList<String> keyHistory = new ArrayList<>();
    private BigInteger Rc;
    private BigInteger Rs;
    private Vector<Integer> authenticatedClients;

    public ClientHandler(Socket socket, String physicalKey, int clientNumber, Server server) throws Exception {
        this.socket = socket;
        this.clientNumber = clientNumber;
        Rs = new BigInteger(16, new Random());
        this.server = server;
        this.physicalKey = physicalKey;
        startTime = System.currentTimeMillis();
        InputStream input = this.socket.getInputStream();
        OutputStream output = this.socket.getOutputStream();
        os = new DataOutputStream(output);
        is = new DataInputStream(input);
        inputBuffer = new byte[1024 * 16];
        sendClientNumber();
        if (!server.isSymmetric) {
            serverPrivateKey = Base64.getEncoder().encodeToString(server.getPrivateKey().getEncoded());
        }
        else{
            try {
                updateSessionKey();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    private void sendClientNumber(){
        sendData(os, "clientNumber#" + clientNumber);
    }


    private void initKeys(){
        String clientPub = publicKey;
        String serverPublicKey = Base64.getEncoder().encodeToString(server.getPublicKey().getEncoded());
        // send server pubic key to client
        sendData(os, "initServerStuff#" + serverPublicKey + ' ' + server.getServerID());
        updateAsymmetricTables(clientPub);
        if (!server.isSymmetric) {
            try {
                updateSessionKey();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    private void updateAsymmetricTables(String clientPublicKey){
        Vector<AsymmetricTable> asymmetricTables = server.getAsymmetricTables();
//        System.out.println("PrivateKey IN SERVER!" + serverPrivateKey);
//        System.out.println("clientPublicKey IN SERVER!" + clientPublicKey);
        AsymmetricTable asymmetricTable = new AsymmetricTable(server.getServerID(), serverPrivateKey, clientNumber, clientPublicKey);
        if (asymmetricTables.size() == Server.clients){
            asymmetricTables.set(clientNumber, asymmetricTable);
        }
        // new client
        else {
            asymmetricTables.add(asymmetricTable);
        }
        server.setAsymmetricTables(asymmetricTables);
    }


    @Override
    public void run() {

        long passedTime;
        Runnable task1 = this::listen;

        Thread thread1 = new Thread(task1);
        thread1.start();

        while (true) {
            passedTime = System.currentTimeMillis();
            if (passedTime - startTime == 10000) {
                startTime = passedTime;
                try {
                    synchronized(lock) {
                        updateSessionKey();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return;
                }
            }
        }
    }

    private byte[] digest(byte[] text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(text);
    }

    private void sendMessage(Socket socket, String sessionKey) throws Exception {
        byte[] decryptedText;
        int byteSize = messageByteSize;
        int encryptedSize = messageEncryptedSize;
        OutputStream output = socket.getOutputStream();
        DataOutputStream os = new DataOutputStream(output);

        byte[] message = messageMessage;
        byte[] encryptedText = new byte[encryptedSize];
        byte[] digest = new byte[byteSize - encryptedSize];

        for(int i = 0; i < byteSize; i++){
            if (i < encryptedSize)
                encryptedText[i] = message[i];
            else
                digest[i - encryptedSize] = message[i];
        }
        // digital signature and data together
        decryptedText = SymmetricEncryption.decryptByte(encryptedText, this.sessionKey);

        if(!server.isSymmetric){
            int pureDataSize = dataSize;
            byte[] pureData = new byte[pureDataSize];
            byte[] encryptedSignature = new byte[encryptedSize - pureDataSize];

            for(int i = 0; i < decryptedText.length ; i++){
                if (i < pureDataSize)
                    pureData[i] = decryptedText[i];
                else
                    encryptedSignature[i - pureDataSize] = decryptedText[i];
            }

            if(!Arrays.equals(digest(pureData), digest))
                errorInMac = true;

            String decryptedSig = RSA.decryptSig(new String(encryptedSignature), getClientPubKey());

            byte[] encryptedDigSig2 = RSA.encryptSig(decryptedSig, server.getPrivateKey()).getBytes(StandardCharsets.UTF_8);

            byte[] dataAndSig = new byte[encryptedDigSig2.length + pureData.length];
            System.arraycopy(pureData, 0, dataAndSig, 0, pureData.length);
            System.arraycopy(encryptedDigSig2, 0, dataAndSig, pureData.length, encryptedDigSig2.length);

            encryptedText = SymmetricEncryption.encryptByte(dataAndSig, sessionKey);

            int newLen = encryptedText.length + digest.length;
            byte[] toSend = new byte[newLen];
            for (int i = 0; i < newLen; i++){
                if(i < encryptedText.length)
                    toSend[i] = encryptedText[i];
                else
                    toSend[i] = digest[i - encryptedText.length];
            }
            sendData(os, "messageByteSize#" + String.valueOf(toSend.length));
            sendData(os, "messageEncryptedSize#" + String.valueOf(encryptedText.length));
            sendData(os, "dataSize#" + pureData.length);
            sendData(os, toSend, "messageMessage");
        }
        else {
            if(!Arrays.equals(digest(decryptedText), digest))
                errorInMac = true;
            encryptedText = SymmetricEncryption.encryptByte(decryptedText, sessionKey);
            int newLen = encryptedText.length + digest.length;
            byte[] toSend = new byte[newLen];
            for (int i = 0; i < newLen; i++){
                if(i < encryptedText.length)
                    toSend[i] = encryptedText[i];
                else
                    toSend[i] = digest[i - encryptedText.length];
            }
            sendData(os, "messageByteSize#" + String.valueOf(toSend.length));
            sendData(os, "messageEncryptedSize#" + String.valueOf(encryptedText.length));
            sendData(os, toSend, "messageMessage");
        }

    }

    private void sendData(DataOutputStream os, String data){
        synchronized(lock){
            try{
                os.writeBytes(data);
                os.writeByte(0);
                os.writeByte(1);
                os.writeByte(2);
                os.writeByte(3);
                os.writeByte(4);
                os.flush();
                os.writeBytes("rest#ended");
                os.writeByte(0);
                os.writeByte(1);
                os.writeByte(2);
                os.writeByte(3);
                os.writeByte(4);
                os.flush();
                Thread.sleep(delay);
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }


    private void sendData(DataOutputStream os, byte[] data, String type){
        synchronized(lock){
            try{
                os.writeBytes(type + "#");
                os.write(data);
                os.writeByte(0);
                os.writeByte(1);
                os.writeByte(2);
                os.writeByte(3);
                os.writeByte(4);
                os.flush();
                os.writeBytes("rest#ended");
                os.writeByte(0);
                os.writeByte(1);
                os.writeByte(2);
                os.writeByte(3);
                os.writeByte(4);
                os.flush();
                Thread.sleep(delay);
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }

    private void sendFile(Socket socket, String sessionKey) throws IOException, NoSuchAlgorithmException {
        OutputStream output = socket.getOutputStream();
        DataOutputStream os = new DataOutputStream(output);
        int numOfPackets = fileNumberOfPackets;
        sendData(os, "filePath#" + filePath);
        sendData(os, "fileNumberOfPackets#" + fileNumberOfPackets);
        sendData(os, "fileContentLength#" + fileContentLength);
        sendData(os, "theSender#" + clientNumber);

        errorInMac = false;

        for (int i = 0; i < numOfPackets - 1; i++) {
            try{
                int byteSize = packetLengths.get(i);
                int encryptedSize = packetEncryptedLengths.get(i);
                byte[] message = packets.get(i);
                byte[] encryptedText = new byte[encryptedSize];
                byte[] digest = new byte[byteSize - encryptedSize];

                for(int j = 0; j < byteSize; j++){
                    if (j < encryptedSize)
                        encryptedText[j] = message[j];
                    else
                        digest[j - encryptedSize] = message[j];
                }

                byte[] mypkt = null;
                boolean errorFlag = true;
                for(String key: keyHistory){
                    mypkt = SymmetricEncryption.decryptByte(encryptedText, key);
                    if(Arrays.equals(digest(mypkt), digest)){
                        errorFlag = false;
                        break;
                    }
                }
                if(errorFlag){
                    errorInMac = true;
                    sendData(this.os, "filePacketError#" + i);
                    errorPacketsMap.put(i, true);
                }
                mypkt = SymmetricEncryption.encryptByte(mypkt, sessionKey);
                sendData(os, mypkt, "fileData");
            }catch(Exception e){
                errorInMac = true;
                sendData(this.os, "filePacketError#" + i);
                errorPacketsMap.put(i, true);
                System.out.println("Packet Exception: " + i);
            }
        }

        if(!server.isSymmetric){
            try{
//            System.out.println("Sending the Last");
                int lastIndex = packets.size() - 1;
                int byteSize = packetLengths.get(lastIndex);
                int encryptedSize = packetEncryptedLengths.get(lastIndex);
                byte[] message = packets.get(lastIndex);
                byte[] encryptedText = new byte[encryptedSize];
                byte[] digest = new byte[byteSize - encryptedSize];
                int pureDataSize = dataSize;
                byte[] pureData = new byte[pureDataSize];
                byte[] encryptedSignature = new byte[encryptedSize - pureDataSize];

                for(int j = 0; j < byteSize; j++){
                    if (j <encryptedSize)
                        encryptedText[j] = message[j];
                    else
                        digest[j - encryptedSize] = message[j];
                }

                byte[] mypkt = null;
                boolean errorFlag = true;
                for(String key: keyHistory){
                    mypkt = SymmetricEncryption.decryptByte(encryptedText, key);
                    for(int k = 0; k < mypkt.length ; k++){
                        if (k < pureDataSize)
                            pureData[k] = mypkt[k];
                        else
                            encryptedSignature[k - pureDataSize] = mypkt[k];
                    }
                    if(Arrays.equals(digest(pureData), digest)){
                        errorFlag = false;
                        break;
                    }
                }

                if(errorFlag){
                    errorInMac = true;
                    sendData(this.os, "filePacketError#" + (numOfPackets - 1));
                    errorPacketsMap.put(numOfPackets - 1, true);
                }
//            System.out.println("Pure Size: " + pureDataSize);

                String decryptedSig = RSA.decryptSig(new String(encryptedSignature), getClientPubKey());

                byte[] encryptedDigSig2 = RSA.encryptSig(decryptedSig, server.getPrivateKey()).getBytes(StandardCharsets.UTF_8);

                byte[] dataAndSig = new byte[encryptedDigSig2.length + pureData.length];
                System.arraycopy(pureData, 0, dataAndSig, 0, pureData.length);
                System.arraycopy(encryptedDigSig2, 0, dataAndSig, pureData.length, encryptedDigSig2.length);

                mypkt = SymmetricEncryption.encryptByte(dataAndSig, sessionKey);
                sendData(os, "dataSize#" + pureData.length);
                sendData(os, "encryptionSize#" + encryptedDigSig2.length);
                sendData(os, mypkt, "fileData");

            }catch(Exception e){
                errorInMac = true;
                sendData(this.os, "filePacketError#" + (numOfPackets - 1));
                errorPacketsMap.put(numOfPackets - 1, true);
                System.out.println("Packet Exception: " + (numOfPackets - 1));
            }
        }

        else {
            try{
                int lastIndex = packets.size() - 1;
                int byteSize = packetLengths.get(lastIndex);
                int encryptedSize = packetEncryptedLengths.get(lastIndex);
                byte[] message = packets.get(lastIndex);
                byte[] encryptedText = new byte[encryptedSize];
                byte[] digest = new byte[byteSize - encryptedSize];

                for(int j = 0; j < byteSize; j++){
                    if (j <encryptedSize)
                        encryptedText[j] = message[j];
                    else
                        digest[j - encryptedSize] = message[j];
                }

                byte[] mypkt = null;
                boolean errorFlag = true;
                for(String key: keyHistory){
                    mypkt = SymmetricEncryption.decryptByte(encryptedText, key);
                    if(Arrays.equals(digest(mypkt), digest)){
                        errorFlag = false;
                        break;
                    }
                }
                if(errorFlag){
                    errorInMac = true;
                    sendData(this.os, "filePacketError#" + (numOfPackets - 1));
                    errorPacketsMap.put(numOfPackets - 1, true);
                }

                mypkt = SymmetricEncryption.encryptByte(mypkt, sessionKey);
                sendData(os, mypkt, "fileData");
            }catch(Exception e){
                errorInMac = true;
                sendData(this.os, "filePacketError#" + (numOfPackets - 1));
                errorPacketsMap.put(numOfPackets - 1, true);
                System.out.println("Packet Exception: " + (numOfPackets - 1));
            }
        }

        if(!errorInMac)
            sendData(os, "fileEnd#Hooloo");
    }

    private void sendFromC1ToC2() throws Exception {
        Vector<ClientMap> clientMaps = server.getClientMaps();

        System.out.println("Client 2 is: " + client2);
        String client2SessionKey = server.getSessionKeys().get(client2);

        for (ClientMap clientMap : clientMaps) {
            if (clientMap.clientNumber == client2) {
                System.out.println("Found!");
                Socket socket = clientMap.socket;
                // receiver socket
                if (isFile) {
                    sendFile(socket, client2SessionKey);
                }
                else
                    sendMessage(socket, client2SessionKey);
            }
        }
    }


    private void setSessionStuff(String digSig){
        client2 =  Integer.parseInt(digSig.split(" ")[1]);
        isFile = digSig.split(" ")[2].equals("file");
    }


    private PublicKey getClientPubKey(){
        Vector<AsymmetricTable> asymmetricTables = server.getAsymmetricTables();
        return RSA.StringToPubKey(asymmetricTables.get(clientNumber).publicKey);
    }


    private void authenticateServer() throws Exception {
        PublicKey clientKey = getClientPubKey();
        String mesToAuthenticate = Rc.toString().concat(" ").concat(Rs.toString());
        String encryptedRandom = RSA.encrypt(mesToAuthenticate, clientKey);
        sendData(this.os, "Rs#" + encryptedRandom);
    }

    private void showAuthenticatedClients(Vector<Integer> authenticatedClients) throws IOException {
        String theListOfClients = "";
        Enumeration enu = authenticatedClients.elements();

        // Displaying the Enumeration
        while (enu.hasMoreElements()) {
            theListOfClients = theListOfClients.concat(enu.nextElement().toString()).concat(" ");
        }
        System.out.println(theListOfClients);
//        sendData(this.os, "listOfClients#" + theListOfClients);
        Vector<ClientMap> clientMaps = server.getClientMaps();

        for (ClientMap clientMap : clientMaps) {
            Socket socket = clientMap.socket;
            OutputStream output = socket.getOutputStream();
            DataOutputStream os = new DataOutputStream(output);
            System.out.println("HERE");
            System.out.println(theListOfClients);
            sendData(os, "listOfClients#" + theListOfClients);
        }
    }


    private void listen(){
        String receivedMessage = "";
        try{
            while(true){
                receivedMessage = "";
                int size = 0;
                while(true){
                    int nextByte = is.read();
                    if(nextByte != 0)
                        inputBuffer[size++] = (byte) nextByte;
                    else{
                        int nexterByte = is.read();
                        if(nexterByte != 1) {
                            inputBuffer[size++] = (byte) nextByte;
                            inputBuffer[size++] = (byte) nexterByte;
                        }else{
                            int moreNexterByte = is.read();
                            if(moreNexterByte != 2){
                                inputBuffer[size++] = (byte) nextByte;
                                inputBuffer[size++] = (byte) nexterByte;
                                inputBuffer[size++] = (byte) moreNexterByte;
                            }else{
                                int theNextestByte = is.read();
                                if(theNextestByte != 3){
                                    inputBuffer[size++] = (byte) nextByte;
                                    inputBuffer[size++] = (byte) nexterByte;
                                    inputBuffer[size++] = (byte) moreNexterByte;
                                    inputBuffer[size++] = (byte) theNextestByte;
                                }else{
                                    int beyond = is.read();
                                    if(beyond != 4){
                                        inputBuffer[size++] = (byte) nextByte;
                                        inputBuffer[size++] = (byte) nexterByte;
                                        inputBuffer[size++] = (byte) moreNexterByte;
                                        inputBuffer[size++] = (byte) theNextestByte;
                                        inputBuffer[size++] = (byte) beyond;
                                    }else
                                        break;
                                }
                            }
                        }
                    }
                }

                receivedMessage = new String(inputBuffer).substring(0, size);

                String[] splits = receivedMessage.split("#");
                String type = splits[0];
                receivedMessage = receivedMessage.substring(type.length() + 1);

                switch(type){
                    case "rest":
                        continue;

                    case "initKey":
                        publicKey = receivedMessage;
                        initKeys();
                        break;

                    case "stuff":
                        String digitalSignature = RSA.decryptSig(receivedMessage, getClientPubKey());
                        setSessionStuff(digitalSignature);
//                        System.out.println(digitalSignature);
                        break;

                    case "stuff2":
                        if(receivedMessage.toLowerCase().startsWith("client")){
                            client2 = Character.getNumericValue(receivedMessage.charAt(receivedMessage.length() - 1));
                            isFile = receivedMessage.toLowerCase().substring(8, 12).equals("file");
                        }
                        break;

                    case "Rc":
                        Rc = new BigInteger(RSA.decrypt(receivedMessage, server.getPrivateKey()));
                        authenticateServer();
                        break;

                    case "lastAuth":
                        String toAuthClient = receivedMessage;
                        if (toAuthClient.equals(Rs.toString())){
                            System.out.println("CLIENT IS AUTHENTICATED!");
                        }
                        authenticatedClients = server.getAuthenticatedClients();
                        authenticatedClients.add(clientNumber);
                        server.setAuthenticatedClients(authenticatedClients);
                        showAuthenticatedClients(authenticatedClients);
                        break;

                    case "messageByteSize":
                        messageByteSize = Integer.parseInt(receivedMessage);
                        break;

                    case "dataSize":
                        dataSize = Integer.parseInt(receivedMessage);
                        break;

                    case "messageEncryptedSize":
                        messageEncryptedSize = Integer.parseInt(receivedMessage);
                        break;

                    case "messageMessage":
                        messageMessage = new byte[messageByteSize];
                        System.arraycopy(inputBuffer, type.length() + 1, messageMessage, 0, messageByteSize);
                        sendFromC1ToC2();
                        break;

                    case "filePath":
                        filePath = receivedMessage;
                        packetLengths.clear();
                        packetEncryptedLengths.clear();
                        packets.clear();
                        errorPacketsMap.clear();
                        break;

                    case "filePacketIndex":
                        filePacketIndex = Integer.parseInt(receivedMessage);
                        break;

                    case "fileNumberOfPackets":
                        fileNumberOfPackets = Integer.parseInt(receivedMessage);
                        break;

                    case "fileContentLength":
                        fileContentLength = Integer.parseInt(receivedMessage);
                        break;

                    case "fileBytesLength":
                        packetLengths.add(Integer.parseInt(receivedMessage));
                        break;

                    case "fileEncryptedBytesLength":
                        packetEncryptedLengths.add(Integer.parseInt(receivedMessage));
                        break;

                    case "fileData":
                        int packetSize = packetLengths.get(packetLengths.size() - 1);
                        byte[] packet = new byte[packetSize];
                        for(int i = 0; i < packetSize; i++)
                            packet[i] = inputBuffer[type.length() + 1 + i];
                        packets.add(packet);
                        break;

                    case "fileRecoveryPacketIndex":
                        filePacketIndex = Integer.parseInt(receivedMessage);
                        break;

                    case "fileRecoveryBytesLength":
                        packetLengths.set(filePacketIndex, Integer.parseInt(receivedMessage));
                        break;

                    case "fileRecoveryEncryptedBytesLength":
                        packetEncryptedLengths.set(filePacketIndex, Integer.parseInt(receivedMessage));
                        break;

                    case "fileRecoverPacket":
                        packetSize = packetLengths.get(filePacketIndex);
                        packet = new byte[packetSize];
                        for(int i = 0; i < packetSize; i++)
                            packet[i] = inputBuffer[type.length() + 1 + i];
                        packets.set(filePacketIndex, packet);
                        errorPacketsMap.remove(filePacketIndex);
                        System.out.println("Packet recovered: " + filePacketIndex + " Errors left: " + errorPacketsMap.size());
                        if(errorPacketsMap.isEmpty())
                            sendFromC1ToC2();
                        break;

                    case "fileEnd":
                        sendFromC1ToC2();
                        break;

                    default:
                        System.out.println("Unrecognized message type: " + type);
                }
            }
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("Error on: " + receivedMessage);
        }
    }

    private void updateSessionKey() throws Exception {
        sessionKey = server.generateNewPlain();

        keyHistory.add(sessionKey);
        int historySize = 20;
        if(keyHistory.size() > historySize)
            for(int i = 0; i < historySize; i++)
                keyHistory.set(i, keyHistory.get(i + 1));

        String encryptedSessionKey = "";
        if(server.isSymmetric)
            encryptedSessionKey = SymmetricEncryption.encrypt(sessionKey, physicalKey);
        else {
            Vector<AsymmetricTable> asymmetricTables = server.getAsymmetricTables();
            PublicKey clientPublicKey = RSA.StringToPubKey(asymmetricTables.get(clientNumber).publicKey);
            encryptedSessionKey = RSA.encrypt(sessionKey, clientPublicKey);
        }
        sendData(os, "key#" + encryptedSessionKey);
        HashMap<Integer, String> sessionKeys = server.getSessionKeys();
        sessionKeys.put(clientNumber, sessionKey);
        server.setSessionKeys(sessionKeys);
//        System.out.println("The Server Session Keys");
//        System.out.println(server.getSessionKeys());
    }


}