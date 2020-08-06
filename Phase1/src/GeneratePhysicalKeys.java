import java.util.Random;

public class GeneratePhysicalKeys {
    private int numOfClients = 2;
    private String chosenKey = "comeLetsEncrypt";

    public GeneratePhysicalKeys() {
        for (int i = 0; i < numOfClients; i++)
            new PhysicalKey(chosenKey, generateNewPlain(), Integer.toString(i));
    }


    private String generateNewPlain(){
        Random random = new Random();
        int leftLimit = 97;
        int rightLimit = 122;
        int targetStringLength = 16;
        return random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    public static void main(String[] args) {
        new GeneratePhysicalKeys();
    }

}
