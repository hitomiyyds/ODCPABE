package com.example.authority;

import java.util.Arrays;

public class AuthPublicKey {
    private static final long serialVersionUID = 1L;
    private final byte[] eg1g1ai;
    private final byte[] g1yi;

    public AuthPublicKey(byte[] eg1g1ai, byte[] g1yi) {
        this.eg1g1ai = eg1g1ai;
        this.g1yi = g1yi;
    }

    public byte[] getEg1g1ai() {
        return eg1g1ai;
    }

    public byte[] getG1yi() {
        return g1yi;
    }

    @Override
    public String toString() {
        return "AuthPublicKey{" +
                "eg1g1ai=" + Arrays.toString(eg1g1ai) +
                ", g1yi=" + Arrays.toString(g1yi) +
                '}';
    }
}
