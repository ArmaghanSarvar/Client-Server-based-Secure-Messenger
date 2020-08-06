import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;


public class ClientNew extends JFrame implements ActionListener, Runnable {
    private boolean isSymmetric = false;
    private InetAddress host;
    private Socket socket;
    private String sessionKey;
    private InputStream input;
    private OutputStream output;
    private DataOutputStream os = null;
    private DataInputStream is = null;
    private int packetSize = 12000;
    private byte[] inputBuffer;
    private Scanner scanner;
    private PrivateKey privateKey;
    private AsymmetricTable asymmetricTable;
    private String physicalKey;
    private int clientNumber;
    private boolean errorInMac = false;
    private int mySender;

    private float packetErrorChance = 0.0f;

    private static final Object lock = new Object();
    private static final int delay = 0;

    private String serverStuff;

    private int messageByteSize;
    private int messageEncryptedSize;
    private byte[] messageMessage;
    private int dataSize;
    private int encryptionSize;

    private String filePath;
    private int fileNumberOfPackets;
    private int fileContentLength;
    private ArrayList<byte[]> packets = new ArrayList<>();

    private ArrayList<Integer> bytesSizeOfCurrentFile = new ArrayList<>();
    private ArrayList<Integer> encryptedBytesOfCurrentFile = new ArrayList<>();
    private ArrayList<byte[]> packetsOfCurrentFile = new ArrayList<>();
    private BigInteger Rc;
    private String digitalSignature;

    private int w, h ;
    private JButton button1;
    private JTextField t1, destCLient, authClients;
    private JRadioButton r1, r2;
    private JLabel label1, label2, introduction, destClientLabel, clientsList;
    private JTextArea t2;

    public ClientNew(){
        Rc = new BigInteger(16, new Random());

        setTitle("Safe Messenger");
        w = 600;
        h = 600;
        setSize(w, h);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        t1 = new JTextField();
        t2 = new JTextArea();
        authClients = new JTextField();
        destCLient = new JTextField();
        t1.setName("t1");
        t2.setName("t2");
        authClients.setName("authc");
        introduction = new JLabel("Hello , Welcome to the Messenger");
        introduction.setLocation(140, 1);
        introduction.setFont(new Font("Bold", Font.BOLD, 20));
        introduction.setSize(600, 60);
        clientsList = new JLabel("The Authenticated Clients:");
        clientsList.setLocation(2, 40);
        clientsList.setFont(new Font("Serif", Font.BOLD, 20));
        clientsList.setSize(250, 150);

        label1 = new JLabel("The File Path:");
        label2 = new JLabel("The Message:");
        destClientLabel = new JLabel("To Client:");
        button1 = new JButton("Send!");
        button1.setSize(100, 70);
        destCLient.setSize(100, 40);
        t1.setSize(100, 40);
        authClients.setSize(200, 40);
        t2.setSize(300, 100);
        button1.setLocation(250, 460);

        label1.setLocation(50, 70);
        label1.setSize(200, 300);
        label1.setFont(new Font("Serif", Font.BOLD, 20));
        destClientLabel.setLocation(50, 22);
        destClientLabel.setSize(200, 300);
        destClientLabel.setFont(new Font("Serif", Font.BOLD, 20));

        label2.setLocation(50, 110);
        label2.setSize(200, 300);
        label2.setFont(new Font("Serif", Font.BOLD, 20));

        destCLient.setLocation(240, 150);
        t1.setLocation(240, 200);
        authClients.setLocation(240, 100);
        t2.setLocation(240, 250);
        r1 = new JRadioButton("File");
        r2 = new JRadioButton("Message");

        r1.setSize(90, 60);
        r2.setSize(90, 60);
        r1.setLocation(50, 340);
        r2.setLocation(50, 380);

        ButtonGroup br = new ButtonGroup();
        br.add(r1);
        br.add(r2);

        //r1.setSelected(true);

        button1.setName("b1");
        button1.setBackground(new Color(130, 210, 193));
        button1.addActionListener(this);

        getContentPane().add(r1);
        getContentPane().add(r2);
        getContentPane().add(button1);
        getContentPane().add(t1);
        getContentPane().add(t2);
        getContentPane().add(destCLient);
        getContentPane().add(label1);
        getContentPane().add(label2);
        getContentPane().add(destClientLabel);
        getContentPane().add(introduction);
        getContentPane().add(clientsList);
        getContentPane().add(authClients);
        setResizable(false);
        setLayout(null);
        setVisible(true);

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
        this.run();
    }

    private void receivedClientNumber(){
        readPhysicalKey();
        if (!isSymmetric){
            initKeys();
        }
//        new Thread(this::sendStuff).start();
    }

    private void readPhysicalKey(){
       physicalKey = PhysicalKey.getPhysicalKey(Integer.toString(clientNumber));
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

    private void handleServerStuffFromInit() throws Exception {
        String[] stuffSplit = serverStuff.split(" ");
        String serverPublicKey = stuffSplit[0];
        int serverID = Integer.parseInt(stuffSplit[1]);
        makeAsymmetricTable(serverPublicKey, serverID);
    }

    private void makeAsymmetricTable(String serverPublicKey, int serverID) throws Exception {
        String myPrivateKey = Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
//        System.out.println("PrivateKey IN CLIENT!" + myPrivateKey);
//        System.out.println("serverPublicKey IN CLIENT!" + serverPublicKey);
        asymmetricTable = new AsymmetricTable(clientNumber, myPrivateKey, serverID, serverPublicKey);
        System.out.println("Asymmetric Table:");
        System.out.println(asymmetricTable.publicKey);
        System.out.println(asymmetricTable.privateKey);
        System.out.println(asymmetricTable.destID);
        System.out.println(asymmetricTable.sourceID);
        authenticate();
    }

    private void authenticate() throws Exception {
        PublicKey serverPublicKey = RSA.StringToPubKey(asymmetricTable.publicKey);
        String encryptedRandom = RSA.encrypt(Rc.toString(), serverPublicKey);
        sendData("Rc#" + encryptedRandom);
    }

    private void checkServer(String toAuthenticateServer){
        String[] RcAndRs = toAuthenticateServer.split(" ");
        if(RcAndRs[0].equals(Rc.toString())){
            System.out.println("SERVER IS AUTHENTICATED!");
        }
        sendData("lastAuth#" + RcAndRs[1]);
    }

    private void showAuthenticatedClients(String listOfClients){
        String[] clients = listOfClients.split(" ");
        System.out.println("********************************");
        System.out.println("The Authenticated Client IDs are:");
        String ccc = "";
        for (String client : clients) {
            System.out.println("Client with ID: " + client);
            ccc = ccc.concat(client).concat(" ");
        }
        authClients.setText(ccc);
        System.out.println("********************************");

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
                        System.out.println("Received session key: " + sessionKey);
                        break;

                    case "Rs":
                        String toAuthenticateServer = RSA.decrypt(receivedMessage, privateKey);
                        checkServer(toAuthenticateServer);
                        break;

                    case "listOfClients":
                        String listOfClients = receivedMessage;
                        showAuthenticatedClients(listOfClients);
                        break;

                    case "messageByteSize":
                        messageByteSize = Integer.parseInt(receivedMessage);
                        break;

                    case "messageEncryptedSize":
                        messageEncryptedSize = Integer.parseInt(receivedMessage);
                        break;

                    case "dataSize":
                        dataSize = Integer.parseInt(receivedMessage);
                        break;

                    case "encryptionSize":
                        encryptionSize = Integer.parseInt(receivedMessage);
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

                    case "theSender":
                        mySender = Integer.parseInt(receivedMessage);
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
                        System.out.println("File received!");
                        break;

                    default:
                        System.out.println("Unrecognized message type: " + type);
                }
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    private PublicKey getServerPubKey(){
        return RSA.StringToPubKey(asymmetricTable.publicKey);
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

        if (!isSymmetric){
            int pureDataSize = dataSize;
            byte[] pureData = new byte[pureDataSize];
            byte[] encryptedSignature = new byte[encryptedSize - pureDataSize];

            for(int i = 0; i < decryptedText.length ; i++){
                if (i < pureDataSize)
                    pureData[i] = decryptedText[i];
                else
                    encryptedSignature[i - pureDataSize] = decryptedText[i];
            }
            System.out.println("The Mac:" + digest);
            if(!Arrays.equals(md.digest(pureData), digest))
                errorInMac = true;

            // TODO
            String decryptedSig = RSA.decryptSig(new String(encryptedSignature), getServerPubKey());
            if(Integer.parseInt(decryptedSig.split(" ")[0]) == mySender){
                System.out.println("Authorized Message Received!");
            }
            if (errorInMac)
                System.out.println("Send the Message Again!");
            else {
                t2.append(new String(pureData, StandardCharsets.UTF_8));
                System.out.println("Received message: " + new String(pureData, StandardCharsets.UTF_8));
            }
        }
        else {
            if (!Arrays.equals(md.digest(decryptedText), digest)) {
                System.out.println("Send the Message Again!");
            }
            else {
                t2.append(new String(decryptedText, StandardCharsets.UTF_8) + '\n');
                System.out.println("Received message: " + new String(decryptedText, StandardCharsets.UTF_8));
            }
        }
    }

    private void receiveFile() throws Exception {
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

            byte[] mypkt = SymmetricEncryption.decryptByte(pkt, sessionKey);

            int startPoint = i * packetSize;
            int finishPoint = startPoint + packetSize - 1;
            for (int j = startPoint; j <= finishPoint; j++) {
                fileContents[j] = mypkt[j - startPoint];
            }
        }
        if (!isSymmetric){
            int pureDataSize = dataSize;
            byte[] pureData = new byte[pureDataSize];

            byte[] pkt = packets.get(packets.size() - 1);
            byte[] mypkt = SymmetricEncryption.decryptByte(pkt, sessionKey);
            byte[] encryptedSignature = new byte[encryptionSize];


            for(int i = 0; i < pureDataSize + encryptionSize; i++){
                if (i < pureDataSize)
                    pureData[i] = mypkt[i];
                else
                    encryptedSignature[i - pureDataSize] = mypkt[i];
            }
            // TODO
            String decryptedSig = RSA.decryptSig(new String(encryptedSignature), getServerPubKey());
            if(Integer.parseInt(decryptedSig.split(" ")[0]) == mySender){
                System.out.println("Authorized File Received!");
            }
            System.arraycopy(pureData, 0, fileContents, packetSize * (numOfPackets - 1), offSet);
        }
        else {
            byte[] pkt = packets.get(packets.size() - 1);

            byte[] mypkt = SymmetricEncryption.decryptByte(pkt, sessionKey);

            System.arraycopy(mypkt, 0, fileContents, packetSize * (numOfPackets - 1), offSet);
        }

        String receiverPath = "Receiver".concat(String.valueOf(clientNumber)).concat(".");
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

    private void handleFile(byte[] fileContent, int client2) throws Exception {
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
            }else {
                sendData(toSend, "fileData");
            }

            if(i % 100 == 0)
                System.out.println((i + 1) + " packets sent so far.");
        }

        byte[] pkt = new byte[offSet];
        System.arraycopy(fileContent, packetSize * (numOfPackets - 1), pkt, 0, offSet);

        if (!isSymmetric){
            // the last packet
            byte[] digest = md.digest(pkt);
            byte[] encryptedBytes;

            digitalSignature = getSignatureContent(true, client2);
            System.out.println("The digital signature: " + digitalSignature);
            byte[] encryptedDigitalSig = RSA.encryptSig(digitalSignature, this.privateKey).getBytes(StandardCharsets.UTF_8);
            byte[] dataAndSig = new byte[encryptedDigitalSig.length + pkt.length];
            System.arraycopy(pkt, 0, dataAndSig, 0, pkt.length);
            System.arraycopy(encryptedDigitalSig, 0, dataAndSig, pkt.length, encryptedDigitalSig.length);

            encryptedBytes = SymmetricEncryption.encryptByte(dataAndSig, sessionKey);

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
            sendData("dataSize#" + pkt.length);

            if(Math.random() < packetErrorChance){
                byte[] errorPacket = new byte[toSend.length];
                System.arraycopy(toSend, 0, errorPacket, 0, toSend.length);
                errorPacket[0]++;
                sendData(errorPacket, "fileData");
            }else{
                sendData(toSend, "fileData");
            }
            sendData("fileEnd#ending");
            System.out.println("File Sent!");
        }
        else{
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
    }


    private void sendFile(String path, int client2){
        byte[] mybytearray;
        // get the path
        try {
            System.out.println("Enter the File Path:");
            sendData("filePath#" + path);
            System.out.println("Loading file...");
            File clientFile = new File(path);
            mybytearray = new byte[(int) clientFile.length()];
            FileInputStream fis = new FileInputStream(clientFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);
            dis.readFully(mybytearray, 0, mybytearray.length);
            handleFile(mybytearray, client2);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private void sendMessage(String text, int client2) throws Exception {
//        String text;
        byte[] encryptedText;
        // get the message

        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        // data + encrypted signature => sym encryption => + digest of data
        digitalSignature = getSignatureContent(false, client2);
        System.out.println("The digital signature: " + digitalSignature);

        byte[] encryptedDigitalSig = RSA.encryptSig(digitalSignature, this.privateKey).getBytes(StandardCharsets.UTF_8);
        byte[] dataAndSig = new byte[encryptedDigitalSig.length + data.length];
        System.arraycopy(data, 0, dataAndSig, 0, data.length);
        System.arraycopy(encryptedDigitalSig, 0, dataAndSig, data.length, encryptedDigitalSig.length);

        encryptedText = SymmetricEncryption.encryptByte(dataAndSig, sessionKey);

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
        sendData("dataSize#" + data.length);
        sendData(toSend, "messageMessage");
    }

    private void sendMessage(String text) throws Exception {
//        String text;
        byte[] encryptedText;
        // get the message
//        System.out.println("Enter the Message:");
        //text = scanner.nextLine();
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

    private String getSignatureContent(boolean isFile, int client2){
        // source + dest + type + time
        String source = Integer.toString(asymmetricTable.sourceID);
        String dest = Integer.toString(client2);
        String comb = source.concat(" ").concat(dest).concat(" ");
        String type;
        if(isFile)
            type =  "file ";
        else
            type = "message ";
        return comb.concat(type).concat(String.valueOf(System.currentTimeMillis() / 1000));
    }

    private String initialSignature(boolean isFile, int client2) throws Exception {
        String initSig = getSignatureContent(isFile, client2);
        return RSA.encryptSig(initSig, this.privateKey);
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

    @Override
    public void actionPerformed(ActionEvent e) {
        String text = "client".concat(Integer.toString(this.clientNumber));
        if ("b1".equals(((JButton) e.getSource()).getName())) {
            if (r1.isSelected()) {  // file
//                System.out.println(t1.getText());
                try {
                    if (!isSymmetric)
                        sendData("stuff#" + initialSignature(true, Integer.parseInt(destCLient.getText())));
                    else
                        sendData("stuff2#" + text.concat(" file client").concat(destCLient.getText()));

                    sendFile(t1.getText(), Integer.parseInt(destCLient.getText()));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
            else if (r2.isSelected()) // message
            {
                try {
                    if (!isSymmetric) {
                    sendData("stuff#" + initialSignature(false, Integer.parseInt(destCLient.getText())));
//                    System.out.println(t2.getText());
                    sendMessage(t2.getText(), Integer.parseInt(destCLient.getText()));
                    }else{
                        sendData("stuff2#" + text.concat(" message client").concat(destCLient.getText()));
                        sendMessage(t2.getText());
                    }
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Override
    public void addNotify() {
        super.addNotify();
    }
}
