package com.example.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;

import org.bitcoinj.params.MainNetParams;

/**
 * @author user01
 * 主要用于生成比特币地址
 * 在这里用于生成节点和用户的地址
 */
public class Wallet {


    public static void main(String[] args) throws Exception {
        // 属性机构数量
        int AAs = 3;

        String[] authorities = new String[AAs];

        for (int i = 0; i < AAs; i++) {
            authorities[i] = getAddress();
            System.out.println(authorities[i]);
        }
//        getAddress();
    }
    public static void getWholeAddressAndKey(){
        //生成正式链地址用这个
        NetworkParameters params = MainNetParams.get();

        //生成地址
        ECKey key = new ECKey();
        System.out.println("地址："+key.toAddress(params).toString());
        System.out.println("公钥："+key.getPublicKeyAsHex());
        System.out.println("私钥（但是这个私钥导入不了IMtoken）："+key.getPrivateKeyAsHex());
        System.out.println("私钥（可以导进IMtoken）："+key.getPrivateKeyAsWiF(params));

        //根据上面不能导进IMtoken的私钥获得可以导进IMtoken的私钥：
        BigInteger priKey = new BigInteger("61c6f70faa8b046232be99b73f8a5cdf21917bdaf56b38dd7e37bc318dc10cf7",16);
        key = ECKey.fromPrivate(priKey);
        System.out.println("私钥："+key.getPrivateKeyAsWiF(params));
        System.out.println("地址："+key.toAddress(params));
    }

    public static String getAddress() {
        //生成正式链地址用这个
        NetworkParameters params = MainNetParams.get();

        //生成地址
        ECKey key = new ECKey();
        // System.out.println("地址："+key.toAddress(params).toString());
        return key.toAddress(params).toString();
    }
}