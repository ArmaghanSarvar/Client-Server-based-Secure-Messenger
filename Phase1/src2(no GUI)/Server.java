import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Random;
import java.util.Vector;

public class Server {
    public boolean isSymmetric = true;
    private String chosenKey = "comeLetsEncrypt";
    private HashMap<Integer, String> sessionKeys;
    private Vector<AsymmetricTable> asymmetricTables;
    private Vector<ClientMap> clientMaps;
    private int serverID;
    public static int clients;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public Server() {
        System.out.println("Server is Listening to the port");
        Random random = new Random();
        serverID = random.nextInt(10);
        sessionKeys = new HashMap<>();
        asymmetricTables = new Vector<>();
        clientMaps = new Vector<>();
        if(!isSymmetric){
            generateKeys();
        }
        serverListen();
    }


    private void generateKeys() {
        KeyPair keyPair = null;
        try {
            keyPair = RSA.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }


    private void serverListen(){
        int port = 6869;
        int clientNumber = 0;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client Connected");
                clients += 1;
                String physicalKey = setAndGetPhysicalKey(generateNewPlain(), clientNumber);
                ClientHandler ch= new ClientHandler(socket, physicalKey, clientNumber, this);
                clientMaps.add(new ClientMap(clientNumber, socket));
                ch.start();
                clientNumber ++;
            }
        }catch (Exception e) {
            System.out.println("Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private String setAndGetPhysicalKey(String plainText, int clientNumber){
        new PhysicalKey(chosenKey, plainText, Integer.toString(clientNumber));
        return PhysicalKey.getPhysicalKey(Integer.toString(clientNumber));
    }


    public String generateNewPlain(){
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 16;
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    public Vector<ClientMap> getClientMaps() {
        return clientMaps;
    }

    public HashMap<Integer, String> getSessionKeys() {
        return sessionKeys;
    }

    public void setSessionKeys(HashMap<Integer, String> sessionKeys) {
        this.sessionKeys = sessionKeys;
    }

    public Vector<AsymmetricTable> getAsymmetricTables() {
        return asymmetricTables;
    }

    public void setAsymmetricTables(Vector<AsymmetricTable> asymmetricTables) {
        this.asymmetricTables = asymmetricTables;
    }

    public int getServerID() {
        return serverID;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static void main(String[] args) {
        new Server();
    }

}
