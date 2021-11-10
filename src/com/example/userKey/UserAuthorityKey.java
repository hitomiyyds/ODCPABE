package com.example.userKey;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author user01
 */
public class UserAuthorityKey {
    private static final long serialVersionUID = 1L;
    private Map<String, UserAttributeKey> userAttKeys;
    private final String authority;
    private byte[] kjk;
    private byte[] ljk;


    public UserAuthorityKey(String authority) {
        this.authority = authority;
        userAttKeys=new HashMap<>();
    }

    public Map<String, UserAttributeKey> getUserAttKeys() {
        return userAttKeys;
    }
    public void addKey(UserAttributeKey ak){
        userAttKeys.put(ak.getAttribute(),ak);
    }
    public Set<String> getAttributes(){
        return userAttKeys.keySet();
    }
    public byte[] getKjk() {
        return kjk;
    }

    public void setKjk(byte[] kjk) {
        this.kjk = kjk;
    }
    public String getAuthority() {
        return authority;
    }

    public byte[] getLjk() {
        return ljk;
    }

    public void setLjk(byte[] ljk) {
        this.ljk = ljk;
    }

}
