package test;

import authority.AuthorityKey;
import authority.AuthoritySecretKeys;
import ciphertext.AccessStructure;
import ciphertext.Ciphertext;
import ciphertext.LocaleCiphertext;
import ciphertext.Message;
import globalAuthority.GlobalParam;
import org.apache.log4j.Logger;
import timeParam.EncParam;
import userKey.UserAuthorityKey;
import userKey.UserSplitKeys;
import userKey.Userkeys;
import util.EdgeCPAbe;
import util.EdgeTimeCPAbe;

import java.lang.reflect.Proxy;
import java.util.*;

public class MyTestEdgeTimeCPAbe implements TimeEdgeCPABE {
    private static Logger log = Logger.getLogger(MyTestEdgeTimeCPAbe.class);


    public static void main(String[] args) {

        //Global Setup
        int lambda = 512;
        //        使用的是质数阶对称双线性群
        GlobalParam GP = EdgeTimeCPAbe.globalSetup(lambda);

    //Authorities Setup
        // 还有一个AuthorityPublicKeys 机构公钥集
        // 机构私钥集
        // AuthoritySecretKeys() =  new HashMap<>()
        AuthoritySecretKeys ASKS = new AuthoritySecretKeys();

        String authority1ID = "authority1";
        String authority2ID = "authority2";
        String authority3ID = "authority3";
        //  生成属性机构的密钥
        AuthorityKey authorityKey1 = EdgeTimeCPAbe.authoritySetup(authority1ID, GP, ASKS, "a", "b");
        AuthorityKey authorityKey2 = EdgeTimeCPAbe.authoritySetup(authority2ID, GP, ASKS, "c", "d", "e");
        AuthorityKey authorityKey3 = EdgeTimeCPAbe.authoritySetup(authority3ID, GP, ASKS, "f", "g", "h");

    //Generate UserKey
        String user1ID = "user1";
        Userkeys userkeys = EdgeTimeCPAbe.userRegistry(user1ID, GP);

        Date t1 = new Date();
    //Ciphertext generated
        Message m = EdgeCPAbe.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);

        String policy = "and and and and a b  or c d and e f or g h";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);

        Map<String, byte[]> encParams = new HashMap<>();

        Ciphertext ct = new Ciphertext();
        String fID = ct.getfID();
        log.info("fID+attribute in Main()="+fID+"  c");

        Date begin = new Date(System.currentTimeMillis() - 100000);
        Date end = new Date(System.currentTimeMillis() + 100000);
        Date now = new Date();
        String attribute = "c";
        // 加密参数
        EncParam encParam = EdgeTimeCPAbe.genEncParam(GP, fID, begin, end, attribute);
        encParams.put(fID + attribute, encParam.getEncParam());

        ct = EdgeTimeCPAbe.encrypt(m, ct, arho, GP, encParams);
    //Userkey generate
        UserAuthorityKey uAK1 = EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKey1, userkeys, "a", "b");
        UserAuthorityKey uAK2 = EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKey2, userkeys, "c", "e");
        UserAuthorityKey uAK3 = EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKey3, userkeys, "f", "g");

        List<UserAuthorityKey> uAKS = new ArrayList<>();
        uAKS.add(uAK1);
        uAKS.add(uAK2);
        uAKS.add(uAK3);
        EdgeTimeCPAbe.keysGen(uAKS, userkeys, GP);
        byte[] userSK = userkeys.getuUid();
        byte[] timeKeyC = EdgeTimeCPAbe.timeKeysGen(fID, attribute, userSK, encParam, GP);
        Map<String, byte[]> timeKeyMap = new HashMap<>();
        timeKeyMap.put(attribute, timeKeyC);
        EdgeTimeCPAbe.timeKeyCombine(userkeys, timeKeyMap, GP);

        UserSplitKeys usks = EdgeTimeCPAbe.edgeKeysGen(userkeys, GP);

    //OutsourceDecrypt CT
        LocaleCiphertext LC = EdgeTimeCPAbe.outsourceDecrypt(ct, usks.getEdgeKeys(), GP);
    //LocaleDecrypt
        Message decM = EdgeTimeCPAbe.localDecrypt(LC, usks.getZ(), GP);
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
        Date t2 = new Date();
        System.out.println("dec Time =" + (t2.getTime() - t1.getTime()));
    }

    public void EdgeTimeCPAbeTest() {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbe.globalSetup(lambda);
        //Authorities Setup
        AuthoritySecretKeys ASKS = new AuthoritySecretKeys();
        String authority1ID = "authority1";
        String authority2ID = "authority2";
//        String authority3ID="authority3";


        AuthorityKey authorityKey1 = EdgeTimeCPAbe.authoritySetup(authority1ID, GP, ASKS, "a", "b");
        AuthorityKey authorityKey2 = EdgeTimeCPAbe.authoritySetup(authority2ID, GP, ASKS, "c", "d", "e");
//        AuthorityKey authorityKey3=EdgeCPAbe.authoritySetup(authority3ID,GP,ASKS,"d","e");
        //Generate UserKey
        String user1ID = "user1";
        Userkeys userkeys = EdgeTimeCPAbe.userRegistry(user1ID, GP);

        Date t1 = new Date();
        //Ciphertext generated
        Message m = EdgeCPAbe.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        String policy = "and and a b  or c and d e";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);
        Map<String, byte[]> encParams = new HashMap<>();

        Ciphertext ct = new Ciphertext();
        String fID = ct.getfID();
        log.info("fID+attribute in Main()=" + fID + "c");
        Date begin = new Date(System.currentTimeMillis() - 100000);
        Date end = new Date(System.currentTimeMillis() + 100000);
        Date now = new Date();
        String attribute = "c";
        EncParam encParam = EdgeTimeCPAbe.genEncParam(GP, fID, begin, end, attribute);
        encParams.put(fID + attribute, encParam.getEncParam());
        ct = EdgeTimeCPAbe.encrypt(m, ct, arho, GP, encParams);

        //Userkey generate
        UserAuthorityKey uAK1 = EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKey1, userkeys, "a", "b");
        UserAuthorityKey uAK2 = EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKey2, userkeys, "c");
//        UserAuthorityKey uAK3 =EdgeCPAbe.keyGen(user1ID,GP,authorityKey3,userkeys);

        List<UserAuthorityKey> uAKS = new ArrayList<>();
        uAKS.add(uAK1);
        uAKS.add(uAK2);
//        uAKS.add(uAK3);
        EdgeTimeCPAbe.keysGen(uAKS, userkeys, GP);
        byte[] userSK = userkeys.getuUid();
        byte[] timeKeyC = EdgeTimeCPAbe.timeKeysGen(fID, attribute, userSK, encParam, GP);
        Map<String, byte[]> timeKeyMap = new HashMap<>();
        timeKeyMap.put(attribute, timeKeyC);
        EdgeTimeCPAbe.timeKeyCombine(userkeys, timeKeyMap, GP);

        //decrypt CT
        Message decM = EdgeTimeCPAbe.decrypt(ct, userkeys, GP);
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
        Date t2 = new Date();
        System.out.println("dec Time =" + (t2.getTime() - t1.getTime()));
    }

    public void methodProxyTime(){
        MyTestEdgeTimeCPAbe myTestEdgeTimeCPAbe = new MyTestEdgeTimeCPAbe();

        // 动态代理，统计各个方法耗时
        TimeEdgeCPABE edgeCPABEProxy = (TimeEdgeCPABE) Proxy.newProxyInstance(
                MyTestEdgeTimeCPAbe.class.getClassLoader(),
                new Class[] { TimeEdgeCPABE.class }, new TimeCountProxyHandle(myTestEdgeTimeCPAbe));

        edgeCPABEProxy.globalSetup();
        edgeCPABEProxy.authoritiesSetup();
        edgeCPABEProxy.generateUserKey();
        edgeCPABEProxy.ciphertextGenerated();
        edgeCPABEProxy.userkeyGenerate();
        edgeCPABEProxy.outsourceDecryptCT();
        edgeCPABEProxy.localeDecrypt();
    }

    @Override
    public void globalSetup() {

    }

    @Override
    public void authoritiesSetup() {

    }

    @Override
    public void generateUserKey() {

    }

    @Override
    public void ciphertextGenerated() {

    }

    @Override
    public void userkeyGenerate() {

    }

    @Override
    public void outsourceDecryptCT() {

    }

    @Override
    public void localeDecrypt() {

    }
}
