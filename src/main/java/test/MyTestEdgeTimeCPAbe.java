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
import util.*;

import java.lang.reflect.Proxy;
import java.util.*;

public class MyTestEdgeTimeCPAbe implements TimeEdgeCPABE {
    private static Logger log = Logger.getLogger(MyTestEdgeTimeCPAbe.class);


    public static void main(String[] args) {
        // 所有属性集
        // String[] attributes = {"a", "b", "c", "d", "e", "f", "g", "h"};
        // System.out.println("属性总数：" + attributes.length);
        // // 属性机构数量
        // int AAs = 3;
        // System.out.println("为AA分配地址，为属性分配AA");
        // for (int i = 0; i < 20; i++) {
        //     attrManagementUnrepeatable(AAs, attributes);
        // }
        testODCPABE();
        // Set<String> attrs = new HashSet<>();
        // String[] attributes = {"a", "b", "c"};
        // Collections.addAll(attrs, attributes);
        // getUserAttr(attrs);
    }

    public static void testODCPABE() {
        //Global Setup
        int lambda = 512;
        //        使用的是质数阶对称双线性群
        GlobalParam GP = EdgeTimeCPAbe.globalSetup(lambda);

        //Authorities Setup
        // 还有一个AuthorityPublicKeys 机构公钥集
        // 机构私钥集
        // AuthoritySecretKeys() =  new HashMap<>()
        AuthoritySecretKeys ASKS = new AuthoritySecretKeys();

        // 所有属性集
        String[] attributes = {"a", "b", "c", "d", "e", "f", "g", "h"};
        System.out.println("属性：" + java.util.Arrays.toString(attributes));
        // 属性机构数量
        int AAs = 3;
        System.out.println("为AA分配地址，为属性分配AA");

        Map<String, Set<String>> aidWithAttr = attrManagementUnrepeatable(AAs, attributes);

        // 属性机构密钥集合
        ArrayList<AuthorityKey> authorityKeys = new ArrayList<>();
        //  生成属性机构的密钥
        System.out.println("生成AA密钥");
        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            authorityKeys.add(EdgeTimeCPAbe.authoritySetup(entry.getKey(), GP, ASKS, entry.getValue()));
        }
        for (AuthorityKey authorityKey : authorityKeys) {
            System.out.println(authorityKey);
        }
        //Generate UserKey
        String user1ID = Wallet.getAddress();
        // 设置了用户密钥的用户id和uuid
        Userkeys userkeys = EdgeTimeCPAbe.userRegistry(user1ID, GP);

        Date t1 = new Date();
        //Ciphertext generated
        Message m = EdgeCPAbe.generateRandomMessage(GP);
        System.out.println("初始明文：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);

        // 访问结构生成
        // String policy = "and and and and a b  or c d and e f or g h";
        String policy = "and or or or a b  or c d or e f or g h";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);

        // 加密参数
        Map<String, byte[]> encParams = new HashMap<>();
        Ciphertext ct = new Ciphertext();
        String fID = ct.getfID();
        log.info("fID+attribute in Main()=" + fID + "  c");

        Date begin = new Date(System.currentTimeMillis() - 100000);
        Date end = new Date(System.currentTimeMillis() + 100000);
        // Date now = new Date();
        String attribute = "c";

        EncParam encParam = EdgeTimeCPAbe.genEncParam(GP, fID, begin, end, attribute);
        encParams.put(fID + attribute, encParam.getEncParam());

        ct = EdgeTimeCPAbe.encrypt(m, ct, arho, GP, encParams);

        //Userkey generate
        List<UserAuthorityKey> uAKS = new ArrayList<>();
        int count = 0;
        // EdgeTimeCPAbe.keyGen 的返回值类型 UserAuthorityKey
        // 添加的属性必须有 c
        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            uAKS.add(EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKeys.get(count++), userkeys, getUserAttr(entry.getValue())));
        }

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

    /**
     * 获取用户的属性
     *
     * @param attrs
     * @return
     */
    public static Set<String> getUserAttr(Set<String> attrs) {
        Random random = new Random(System.currentTimeMillis());
        Set<String> userAttr = new HashSet<>();
        while (userAttr.isEmpty()) {
            for (String attr : attrs) {
                if (random.nextBoolean()) {
                    userAttr.add(attr);
                }
            }
        }
        System.out.println("用户属性 " + userAttr);
        return userAttr;
    }

    /**
     * 不可重复的
     * 为属性机构分配地址
     * 为属性集分配属性，
     * 属性机构与属性对应
     * 一个属性可以被多个属性机构管理
     *
     * @param AAs        属性机构的数量
     * @param attributes 所有的属性
     * @return
     */
    public static Map<String, Set<String>> attrManagementUnrepeatable(int AAs, String[] attributes) {
        // 设置属性机构aid,并为每个机构的分配属性
        Map<String, Set<String>> aidWithAttr = new HashMap<>();
        // 属性机构与aid 一一对应
        Map<Integer, String> aids = new HashMap<>();

        Set<Integer> isEmpty = new HashSet<>();
        for (int i = 0; i < AAs; i++) {
            String aid = Wallet.getAddress();
            aidWithAttr.put(aid, new HashSet<>());
            aids.put(i + 1, aid);
            isEmpty.add(i + 1);
        }
        int unit = 50;
        int maxNum = AAs * unit;
        Random random = new Random(System.currentTimeMillis());
        int count = 1;
        do {
            // aidWithAttr.clear();
            for (String attribute : attributes) {
                int number = random.nextInt(maxNum) + 1;
                while (number % unit == 0 || number == 1 || number == maxNum) {
                    number = random.nextInt(maxNum) + 1;
                }
                int i = (number / unit) + 1;
                aidWithAttr.get(aids.get(i)).add(attribute);
                isEmpty.remove(i);
            }
            if (isEmpty.size() != 0) {
                count++;
                for (int i = 0; i < AAs; i++) {
                    aidWithAttr.get(aids.get(i+1)).clear();
                }
                if (count >= AAs) {
                    unit = 10;
                } else {
                    unit = unit - count * 10;
                }
                maxNum = AAs * unit;
                System.out.println("循环次数：" + count);
            } else {
                break;
            }
        } while (true);

        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            System.out.println("key值：" + entry.getKey() + " ---Value值：" + entry.getValue());
        }
        System.out.println("===========");
        return aidWithAttr;
    }

    /**
     * 可重复的
     * 为属性机构分配地址
     * 为属性集分配属性，
     * 属性机构与属性对应
     * 一个属性可以被多个属性机构管理
     *
     * @param AAs        属性机构的数量
     * @param attributes 所有的属性
     * @return
     */
    public static Map<String, Set<String>> attrManagementRepeatable(int AAs, String[] attributes) {
        // 设置属性机构aid,并为每个机构的分配属性
        Map<String, Set<String>> aidWithAttr = new HashMap<>();
        // 属性机构与aid 一一对应
        Map<Integer, String> aids = new HashMap<>();
        for (int i = 0; i < AAs; i++) {
            String aid = Wallet.getAddress();
            aidWithAttr.put(aid, new HashSet<>());
            aids.put(i + 1, aid);
        }
        Set<String> attrset = new HashSet<>(Arrays.asList(attributes));

        // 用于随机的分配，切割的数
        List<Integer> separates = new ArrayList<Integer>();
        List<Integer> percents = new ArrayList<Integer>();
        while (true) {
            // System.out.println(attrset.size());
            if (attrset.size() == 0) {
                break;
            } else {
                for (int i = 1; i <= AAs; i++) {
                    int count = 0;
                    int turePercent = 50;
                    separates.clear();
                    percents.clear();
                    separates.add(turePercent);
                    percents.add(turePercent);
                    percents.add(turePercent);
                    // System.out.println("==========================");
                    do {
                        if (count >= attributes.length && count % attributes.length == 0 && aidWithAttr.get(aids.get(i)).size() == 0) {
                            // int n = count / (attributes.length);
                            separates.clear();
                            percents.clear();
                            // turePercent = 50;
                            turePercent = turePercent + 10;
                            separates.add(turePercent);
                            percents.add(turePercent);
                            percents.add(100 - turePercent);
                            // System.out.println("count = " + count + " turePercent = " + turePercent);
                        }
                        for (String attribute : attributes) {
                            int number = RateRandomNumber.produceRateRandomNumber(1, 100, separates, percents);
                            if (number <= turePercent) {
                                // System.out.println("属性被添加");
                                aidWithAttr.get(aids.get(i)).add(attribute);
                                if (attrset.contains(attribute)) {
                                    attrset.remove(attribute);
                                }
                            }
                            count++;
                            // System.out.println("第" + count + "次，此时随机数为：" + number + " True的概率是：" + turePercent);
                        }
                    } while (aidWithAttr.get(aids.get(i)).size() == 0);
                }
            }


        }
        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            System.out.println("key值：" + entry.getKey() + " ---Value值：" + entry.getValue());
        }
        System.out.println("===========");
        return aidWithAttr;
    }

    public void EdgeTimeCPAbeTest() {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbe.globalSetup(lambda);
        //Authorities Setup
        AuthoritySecretKeys ASKS = new AuthoritySecretKeys();

        // 所有属性集
        String[] attributes = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"};
        System.out.println("属性总数：" + attributes.length);
        // 属性机构数量
        int AAs = 5;
        Map<String, Set<String>> aidWithAttr = attrManagementUnrepeatable(AAs, attributes);
        // 属性机构密钥集合
        ArrayList<AuthorityKey> authorityKeys = new ArrayList<>();
        //  生成属性机构的密钥
        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            authorityKeys.add(EdgeTimeCPAbe.authoritySetup(entry.getKey(), GP, ASKS, entry.getValue()));
        }
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
        List<UserAuthorityKey> uAKS = new ArrayList<>();
        int count = 0;
        for (Map.Entry<String, Set<String>> entry : aidWithAttr.entrySet()) {
            uAKS.add(EdgeTimeCPAbe.keyGen(user1ID, GP, authorityKeys.get(count++), userkeys, getUserAttr(entry.getValue())));
        }
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

    public void methodProxyTime() {
        MyTestEdgeTimeCPAbe myTestEdgeTimeCPAbe = new MyTestEdgeTimeCPAbe();

        // 动态代理，统计各个方法耗时
        TimeEdgeCPABE edgeCPABEProxy = (TimeEdgeCPABE) Proxy.newProxyInstance(
                MyTestEdgeTimeCPAbe.class.getClassLoader(),
                new Class[]{TimeEdgeCPABE.class}, new TimeCountProxyHandle(myTestEdgeTimeCPAbe));

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
