package com.example.authority;

import java.util.HashMap;
import java.util.Map;

public class AuthoritySecretKeys {
    private static final long serialVersionUID = 123241145L;

//    private Map<String,String> tMap ;
    /**
     * tMapASK 映射属性机构私钥
     */
    private Map<String ,AuthSecretKey> tMapASK;

    public AuthoritySecretKeys() {
//        this.tMap = new HashMap<>();
        this.tMapASK = new HashMap<>();
    }

//    public Map<String, String> gettMap() {
//        return tMap;
//    }

    public Map<String, AuthSecretKey> gettMapASK() {
        return tMapASK;
    }

//    public AuthSecretKey getASKByAttr(String attribute){
//        if(!tMap.containsKey(attribute))
//            throw new IllegalArgumentException("属性不存在于属性机构中");
//        String authorityID=tMap.get(attribute);
//        AuthSecretKey aSK=tMapASK.get(authorityID);
//        return aSK;
//    }
}
