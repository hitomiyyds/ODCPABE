package userKey;



public class UserSplitKeys {
    private static final long serialVersionUID = 1L;
    String userId;
    private byte[] z;
    private Userkeys edgeKeys;



    public UserSplitKeys(String UserId) {
        this.userId=UserId;
        edgeKeys=new Userkeys(UserId);
    }

    public byte[] getZ() {
        return z;
    }

    public void setZ(byte[] z) {
        this.z = z;
    }
    public Userkeys getEdgeKeys() {
        return edgeKeys;
    }

    public void setEdgeKeys(Userkeys edgeKeys) {
        this.edgeKeys = edgeKeys;
    }
}
