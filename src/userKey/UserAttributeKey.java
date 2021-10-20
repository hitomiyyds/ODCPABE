package userKey;

public class UserAttributeKey {
    private static final long serialVersionUID = 1L;
    private final String attribute;
    private byte[] kj_xk;



    public byte[] getKj_xk() {
        return kj_xk;
    }
    public void setKj_xk(byte[]kjk) {
        this.kj_xk=kjk;
    }



    public UserAttributeKey(String attribute) {
        this.attribute = attribute;
    }

    public String getAttribute() {
        return attribute;
    }

}
