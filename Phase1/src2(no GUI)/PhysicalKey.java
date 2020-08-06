import java.io.*;

public class PhysicalKey {

    public PhysicalKey(String chosenKey, String plainText, String clientNumber){
        SymmetricEncryption se = new SymmetricEncryption();
        createPhysicalKey(chosenKey, plainText, clientNumber);
    }

    private void createPhysicalKey(String chosenKey, String plainText, String clientNumber){
        String physical_key = SymmetricEncryption.encrypt(plainText, chosenKey);
        writeToFile(physical_key, clientNumber);
    }

    private void writeToFile(String physicalKey, String clientNumber){
        try (PrintWriter p = new PrintWriter(new FileOutputStream("physicalKey" + clientNumber + ".txt", true))) {
            p.println(physicalKey);
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        }
    }

    public static String getPhysicalKey(String clientNumber){
        String path = "physicalKey" + clientNumber + ".txt";
        File file = new File(path);
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
            byte fileContent[] = new byte[(int) file.length()];
            inputStream.read(fileContent);
//            System.out.println(new String(fileContent));
            return new String(fileContent);
        }
        catch (FileNotFoundException e) {
            System.out.println("File not found" + e);
        }
        catch (IOException ioe) {
            System.out.println("Exception while reading file " + ioe);
        }
        finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            }
            catch (IOException ioe) {
                System.out.println("Error while closing stream: " + ioe);
            }
        }
        return null;
    }

}
