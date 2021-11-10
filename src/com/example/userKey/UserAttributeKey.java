package com.example.userKey;

public class UserAttributeKey {
    private static final long serialVersionUID = 1L;
    private final String attribute;
    private byte[] kj_xk;


    public UserAttributeKey(String attribute) {
        this.attribute = attribute;
    }

    public byte[] getKj_xk() {
        return kj_xk;
    }

    public void setKj_xk(byte[] kjk) {
        this.kj_xk = kjk;
    }

    public String getAttribute() {
        return attribute;
    }

}
