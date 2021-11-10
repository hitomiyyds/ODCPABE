package com.example.ciphertext;

public class LocaleCiphertext {
    private String fID;
    private byte[] c0;
    private byte[] c1;

    public LocaleCiphertext(String fID) {
        this.fID = fID;
    }

    public byte[] getC0() {
        return c0;
    }

    public void setC0(byte[] c0) {
        this.c0 = c0;
    }

    public byte[] getC1() {
        return c1;
    }

    public void setC1(byte[] c1) {
        this.c1 = c1;
    }
}
