import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class ClientNew extends Thread{
    private boolean isSymmetric = true;
    private InetAddress host;
    private Socket socket;
    private String sessionKey;
    private InputStream input;
    private OutputStream output;
    private DataOutputStream os = null;
    private DataInputStream is = null;
    private int packetSize = 6000;
    private byte[] inputBuffer;
    private Scanner scanner;
    private PrivateKey privateKey;
    private AsymmetricTable asymmetricTable;
    private String physicalKey;
    private int clientNumber;
    private boolean errorInMac = false;

    private float packetErrorChance = 0.01f;

    private static final Object lock = new Object();
    private static final int delay = 0;

    private String serverStuff;

    private int messageByteSize;
    private int messageEncryptedSize;
    private byte[] messageMessage;

    private String filePath;
    private int fileNumberOfPackets;
    private int fileContentLength;
    private ArrayList<byte[]> packets = new ArrayList<>();

    private ArrayList<Integer> bytesSizeOfCurrentFile = new ArrayList<>();
    private ArrayList<Integer> encryptedBytesOfCurrentFile = new ArrayList<>();
    private ArrayList<byte[]> packetsOfCurrentFile = new ArrayList<>();

    public ClientNew(){
        scanner = new Scanner(System.in);
        try {
            host = InetAddress.getLocalHost();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            socket = new Socket(host.getHostName(), 6869);
            output = socket.getOutputStream();
            input = socket.getInputStream();
            os = new DataOutputStream(output);
            is = new DataInputStream(input);
            inputBuffer = new byte[1024 * 16];
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.start();
    }

    private void receivedClientNumber(){
        readPhysicalKey();
        if (!isSymmetric){
            initKeys();
        }
        new Thread(this::sendStuff).start();
    }

    private void readPhysicalKey(){
       physicalKey = PhysicalKey.getPhysicalKey(Integer.toString(clientNumber));
    }

    private void makeAsymmetricTable(String serverPublicKey, int serverID){
        String myPrivateKey = Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
//        System.out.println("PrivateKey IN CLIENT!" + myPrivateKey);
//        System.out.println("serverPublicKey IN CLIENT!" + serverPublicKey);
        asymmetricTable = new AsymmetricTable(clientNumber, myPrivateKey, serverID, serverPublicKey);
    }

    private PublicKey generateKeys(){
        KeyPair keyPair = null;
        try {
            keyPair = RSA.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        privateKey = keyPair.getPrivate();
        return keyPair.getPublic();
    }


    private void initKeys(){
        String STR_KEY = Base64.getEncoder().encodeToString(generateKeys().getEncoded());
        // send my public key to the server
        sendData("initKey#" + STR_KEY);
    }

    private void handleServerStuffFromInit(){
        String[] stuffSplit = serverStuff.split(" ");
        String serverPublicKey = stuffSplit[0];
        int serverID = Integer.parseInt(stuffSplit[1]);
        makeAsymmetricTable(serverPublicKey, serverID);
    }

    @Override
    public void run() {
        try{
            while(true){
                String receivedMessage = "";
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
                                if(theNextestByte != 3) {
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

                    case "initServerStuff":
                        serverStuff = receivedMessage;
                        handleServerStuffFromInit();
                        break;

                    case "clientNumber":
                        clientNumber = Integer.parseInt(receivedMessage);
                        receivedClientNumber();
                        break;

                    case "key":
                        if(isSymmetric)
                            sessionKey = SymmetricEncryption.decrypt(receivedMessage, physicalKey);
                        else
                            sessionKey = RSA.decrypt(receivedMessage, privateKey);
//                        System.out.println("Received session key: " + sessionKey);
                        break;

                    case "messageByteSize":
                        messageByteSize = Integer.parseInt(receivedMessage);
                        break;

                    case "messageEncryptedSize":
                        messageEncryptedSize = Integer.parseInt(receivedMessage);
                        break;

                    case "messageMessage":
                        messageMessage = new byte[messageByteSize];
                        System.arraycopy(inputBuffer, type.length() + 1, messageMessage, 0, messageByteSize);
                        receiveMessage();
                        break;

                    case "filePath":
                        filePath = receivedMessage;
                        packets.clear();
                        break;

                    case "fileNumberOfPackets":
                        fileNumberOfPackets = Integer.parseInt(receivedMessage);
                        break;

                    case "fileContentLength":
                        fileContentLength = Integer.parseInt(receivedMessage);
                        break;

                    case "fileData":
                        byte[] packet = new byte[packetSize];
                        for(int i = 0; i < packetSize; i++)
                            packet[i] = inputBuffer[type.length() + 1 + i];
                        packets.add(packet);
                        break;

                    case "filePacketError":
                        int packetIndex = Integer.parseInt(receivedMessage);
                        System.out.println("Resending packet: " + packetIndex);
                        sendData("fileRecoveryPacketIndex#" + packetIndex);
                        sendData("fileRecoveryBytesLength#" + bytesSizeOfCurrentFile.get(packetIndex));
                        sendData("fileRecoveryEncryptedBytesLength#" + encryptedBytesOfCurrentFile.get(packetIndex));
                        sendData(packetsOfCurrentFile.get(packetIndex), "fileRecoverPacket");
                        break;

                    case "fileEnd":
                        receiveFile();
                        System.out.println("File received.");
                        break;

                    default:
                        System.out.println("Unrecognized message type: " + type);
                }
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    private void receiveMessage() throws Exception {
        byte[] decryptedText;

        int bytesize = messageByteSize;
        int encryptedSize = messageEncryptedSize;
        byte[] message = messageMessage;
        byte[] encryptedText = new byte[encryptedSize];
        byte[] digest = new byte[bytesize - encryptedSize];

        for(int i = 0; i < bytesize; i++){
            if (i < encryptedSize)
                encryptedText[i] = message[i];
            else
                digest[i - encryptedSize] = message[i];
        }
        decryptedText = SymmetricEncryption.decryptByte(encryptedText, this.sessionKey);
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        if(!Arrays.equals(md.digest(decryptedText), digest))
            errorInMac = true;
        if(errorInMac)
            System.out.println("Send the Message Again!");
        else
            System.out.println("Received message: " + new String(decryptedText, StandardCharsets.UTF_8));
    }


    private void receiveFile() throws IOException {
        String path = filePath;
        int numOfPackets = fileNumberOfPackets;
        int fileSize = fileContentLength;
        int packetSize = this.packetSize;
        if(packetSize > fileSize)
            packetSize = fileSize;
        int offSet = fileSize - packetSize * (numOfPackets - 1);
        byte[] fileContents = new byte[fileSize];

        for (int i = 0; i < numOfPackets - 1; i++) {
            byte[] pkt = packets.get(i);

//            System.out.println(Arrays.toString(pkt));
            byte[] mypkt = SymmetricEncryption.decryptByte(pkt, sessionKey);
//            System.out.println(Arrays.toString(mypkt));

            int startPoint = i * packetSize;
            int finishPoint = startPoint + packetSize - 1;
            for (int j = startPoint; j <= finishPoint; j++) {
                fileContents[j] = mypkt[j - startPoint];
            }
        }
        byte[] pkt = packets.get(packets.size() - 1);

        byte[] mypkt = SymmetricEncryption.decryptByte(pkt, sessionKey);

        System.arraycopy(mypkt, 0, fileContents, packetSize * (numOfPackets - 1), offSet);
//        System.out.println(Arrays.toString(pkt));
        String receiverPath = "Receiver.";
        String format = "";
        for (int i =  path.length() - 1; i >= 0 ; i--){
            if (path.charAt(i) == '.'){
                break;
            }
            format = format.concat(String.valueOf(path.charAt(i)));
        }
        format = new StringBuilder(format).reverse().toString();
        receiverPath = receiverPath.concat(format);
        File file = new File(receiverPath);
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(fileContents);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void handleFile(byte[] fileContent) throws IOException, NoSuchAlgorithmException {
        bytesSizeOfCurrentFile.clear();
        encryptedBytesOfCurrentFile.clear();
        packetsOfCurrentFile.clear();
        System.out.println("Sending File...");

        int numOfPackets = fileContent.length / packetSize + 1;
        int threshold = fileContent.length;
        int offSet = fileContent.length - packetSize * (numOfPackets - 1);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        sendData("fileNumberOfPackets#" + numOfPackets);
        sendData("fileContentLength#" + fileContent.length);

        for (int i = 0; i < numOfPackets - 1; i++) {
            byte[] encryptedBytes;
            byte[] pkt = new byte[packetSize];
            int startPoint = i * packetSize;
            int finishPoint = startPoint + packetSize - 1;
            for (int j = startPoint; j <= finishPoint; j++) {
                if (j < threshold) {
                    pkt[j - startPoint] = fileContent[j];
                }
            }
            byte[] digest = md.digest(pkt);
            encryptedBytes = SymmetricEncryption.encryptByte(pkt, sessionKey);
            int newLen = encryptedBytes.length + digest.length;

            byte[] toSend = new byte[newLen];
            for (int j = 0; j < newLen; j++){
                if(j < encryptedBytes.length)
                    toSend[j] = encryptedBytes[j];
                else
                    toSend[j] = digest[j - encryptedBytes.length];
            }

            bytesSizeOfCurrentFile.add(toSend.length);
            encryptedBytesOfCurrentFile.add(encryptedBytes.length);
            packetsOfCurrentFile.add(toSend);

            sendData("fileBytesLength#" + toSend.length);
            sendData("fileEncryptedBytesLength#" + encryptedBytes.length);

            if(Math.random() < packetErrorChance){
                byte[] errorPacket = new byte[toSend.length];
                System.arraycopy(toSend, 0, errorPacket, 0, toSend.length);
                errorPacket[0]++;
                sendData(errorPacket, "fileData");
            }else{
                sendData(toSend, "fileData");
            }

            if(i % 100 == 0)
                System.out.println((i + 1) + " packets sent so far.");
        }
        byte[] pkt = new byte[offSet];
        System.arraycopy(fileContent, packetSize * (numOfPackets - 1), pkt, 0, offSet);
        byte[] digest = md.digest(pkt);
        byte[] encryptedBytes;
        encryptedBytes = SymmetricEncryption.encryptByte(pkt, sessionKey);
        int newLen = encryptedBytes.length + digest.length;
        byte[] toSend = new byte[newLen];
        for (int j = 0; j < newLen; j++){
            if(j < encryptedBytes.length)
                toSend[j] = encryptedBytes[j];
            else
                toSend[j] = digest[j - encryptedBytes.length];
        }

        bytesSizeOfCurrentFile.add(toSend.length);
        encryptedBytesOfCurrentFile.add(encryptedBytes.length);
        packetsOfCurrentFile.add(toSend);

        sendData("fileBytesLength#" + toSend.length);
        sendData("fileEncryptedBytesLength#" + encryptedBytes.length);

        if(Math.random() < packetErrorChance){
            byte[] errorPacket = new byte[toSend.length];
            System.arraycopy(toSend, 0, errorPacket, 0, toSend.length);
            errorPacket[0]++;
            sendData(errorPacket, "fileData");
        }else{
            sendData(toSend, "fileData");
        }

        sendData("fileEnd#ending");
    }

    private void sendFile(){
        String path;
        byte[] mybytearray;
        // get the path
        try {
            System.out.println("Enter the File Path:");
            path = scanner.nextLine();
            sendData("filePath#" + path);
            System.out.println("Loading file...");
            File clientFile = new File(path);
            mybytearray = new byte[(int) clientFile.length()];
            FileInputStream fis = new FileInputStream(clientFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);
            dis.readFully(mybytearray, 0, mybytearray.length);
            handleFile(mybytearray);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void sendMessage() throws Exception {
        String text;
        byte[] encryptedText;
        // get the message
        System.out.println("Enter the Message:");
        text = scanner.nextLine();
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);

        encryptedText = SymmetricEncryption.encryptByte(data, sessionKey);

        int newLen = encryptedText.length + digest.length;
        byte[] toSend = new byte[newLen];
        for (int i = 0; i < newLen; i++){
            if(i < encryptedText.length)
                toSend[i] = encryptedText[i];
            else
                toSend[i] = digest[i - encryptedText.length];
        }
        sendData("messageByteSize#" + toSend.length);
        sendData("messageEncryptedSize#" + encryptedText.length);
        sendData(toSend, "messageMessage");
    }

    private void sendStuff(){
        try {
            String text;
            do {
                text = scanner.nextLine();
                // client0 message client1 - client0 file client1
                if (text.toLowerCase().startsWith("client")){
                    sendData("stuff#" + text);
                    if (text.toLowerCase().substring(8, 12).equals("file"))
                        sendFile();
                    else
                        sendMessage();
                }

            } while (!text.equals("bye"));
            socket.close();
        } catch (Exception ex) {
            System.out.println("I/O error: " + ex.getMessage());
        }
    }

    private void sendData(String data){
        synchronized(lock){
            try{
                os.writeBytes(data);
                os.writeByte(0);
                os.writeByte(1);
                os.writeByte(2);
                os.writeByte(3);
                os.writeByte(4);
                os.flush();
                os.writeBytes("rest#ending");
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

    private void sendData(byte[] data, String type){
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
                os.writeBytes("rest#ending");
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

    public static void main(String[] args) {
        new ClientNew();
    }
}
