import java.net.Socket;

public class ClientMap {
    public int clientNumber;
    public Socket socket;

    public ClientMap(int clientNumber, Socket socket) {
        this.clientNumber = clientNumber;
        this.socket = socket;
    }

}
