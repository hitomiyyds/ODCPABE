package com.example.hashFunc;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

public class HashFunction {

    private static HashFunction instance=new HashFunction();
    private HashFunction(){
        tMap=new HashMap<>();

    }

    public static Map<String, String> gettMap() {
        return tMap;
    }

    public static HashFunction getInstance(){
        return instance;
    }
    private static Map<String,String> tMap;

    //F函数，映射属性到G的元素
    public static Element hashToG1(Pairing pairing, byte[] m){
        Element result =pairing.getG1().newElementFromHash(m, 0, m.length);
        return result;
    }

    //T函数，映射属性到属性机构
    public static String hashToAuthority(String attribute){
        if(!tMap.containsKey(attribute))
            throw new IllegalArgumentException("attribute not exist");
        return tMap.get(attribute);

    }

}
