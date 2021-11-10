package com.example.test;

import com.example.authority.AuthorityKey;
import com.example.authority.AuthoritySecretKeys;
import com.example.ciphertext.AccessStructure;
import com.example.ciphertext.Ciphertext;
import com.example.ciphertext.Message;
import com.example.globalAuthority.GlobalParam;
import org.apache.log4j.Logger;
import com.example.userKey.UserAuthorityKey;
import com.example.userKey.Userkeys;
import com.example.util.EdgeCPAbe;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MyTestEdgeCPAbe {
    private  static Logger log =Logger.getLogger(MyTestEdgeCPAbe.class);

    public static void main(String[] args) {
        int lambda=512;
        //Global Setup
        GlobalParam GP= EdgeCPAbe.globalSetup(lambda);
        //Authorities Setup
        AuthoritySecretKeys ASKS=new AuthoritySecretKeys();
        String authority1ID="authority1";
        String authority2ID="authority2";
        String authority3ID="authority3";


        AuthorityKey authorityKey1=EdgeCPAbe.authoritySetup(authority1ID,GP,ASKS,"a","b");
        AuthorityKey authorityKey2=EdgeCPAbe.authoritySetup(authority2ID,GP,ASKS,"c");
        AuthorityKey authorityKey3=EdgeCPAbe.authoritySetup(authority3ID,GP,ASKS,"d","e");
        //Ciphertext generated
        Message m =EdgeCPAbe.generateRandomMessage(GP);
        System.out.println("原来的内容是："+Arrays.toString(m.m)+"\n长度为："+m.m.length);
        String policy="and and a b  or c and d e";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);
        Ciphertext ct=EdgeCPAbe.encrypt(m,arho,GP);
        //Generate UserKey
        String user1ID="user1";
        Userkeys userkeys=EdgeCPAbe.userRegistry(user1ID,GP);
        UserAuthorityKey uAK1 =EdgeCPAbe.keyGen(user1ID,GP,authorityKey1,userkeys,"a","b");
        UserAuthorityKey uAK2 =EdgeCPAbe.keyGen(user1ID,GP,authorityKey2,userkeys,"c");
        UserAuthorityKey uAK3 =EdgeCPAbe.keyGen(user1ID,GP,authorityKey3,userkeys);
        log.info("UAK3:="+uAK3.getAuthority());

        List<UserAuthorityKey>uAKS=new ArrayList<>();
        uAKS.add(uAK1);
        uAKS.add(uAK2);
        uAKS.add(uAK3);
        userkeys=EdgeCPAbe.keysGen(uAKS,userkeys,GP);
        log.info("authorities:="+userkeys.getUserAuthKeys().keySet());



        //decrypt CT
        Message decM=EdgeCPAbe.decrypt(ct,userkeys,GP);
        System.out.println("解密后明文为："+Arrays.toString(decM.m)+"\n长度为："+decM.m.length);


    }

    public GlobalParam genGlobalParam(int lambda){
        GlobalParam GP= EdgeCPAbe.globalSetup(lambda);
        return GP;
    }

}
