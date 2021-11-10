package com.example.ciphertext;

import java.util.*;

/**
 * 密文
 * @author user01
 */
public class Ciphertext {
    private static final long serialVersionUID = 1L;
    private String fID;
    private byte[] c0;
    private byte[] c1;
    private Map<String,byte[]> c2;
    private List<byte[]> c3;
    private List<byte[]> c4;
    private List<byte[]> c5;
    private AccessStructure accessStructure;

    public Ciphertext() {
        c2 = new HashMap<>();
        c3 = new ArrayList<byte[]>();
        c4 = new ArrayList<byte[]>();
        c5 = new ArrayList<byte[]>();
        fID=generateRandomFid();
    }

    /**
     * 根据当前时间戳 对 100000000 取余
     * @return
     */
    public String generateRandomFid(){
        Random random=new Random();
        long time=System.currentTimeMillis();
        long randomNum =time % 100000000;
        String fID=String.valueOf(randomNum);
        return fID;
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


    public void setC1(byte[] c1x) {
        this.c1=c1x ;
    }

    public byte[] getC2(String authority) {
        return c2.get(authority);
    }

    public Map<String,byte[]> getC2Map(){
        return c2;
    }
    public void setC2(String authorityID,byte[] c2x) {
        this.c2.put(authorityID,c2x) ;
    }
    public byte[] getC3(int x) {
        return c3.get(x);
    }

    public void setC3(byte[] c3x) {
        this.c3.add(c3x) ;
    }
    public byte[] getC4(int x) {
        return c4.get(x);
    }

    public void setC4(byte[] c4x) {
        this.c4.add(c4x) ;
    }

    public byte[] getC5(int x) {
        return c5.get(x);
    }

    public void setC5(byte[] c5x) {
        this.c5.add(c5x);
    }

    public AccessStructure getAccessStructure() {
        return accessStructure;
    }

    public void setAccessStructure(AccessStructure accessStructure) {
        this.accessStructure = accessStructure;
    }

    public String getfID() {
        return fID;
    }


}
