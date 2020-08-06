public class AsymmetricTable {
    public int sourceID;
    public int destID;
    public String publicKey;
    public String privateKey;

    public AsymmetricTable(int sourceID, String privateKey, int destID, String publicKey) {
        this.sourceID = sourceID;
        this.destID = destID;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}
