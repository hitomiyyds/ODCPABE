package util;

import authority.*;
import ciphertext.AccessStructure;
import ciphertext.Ciphertext;
import ciphertext.LocaleCiphertext;
import ciphertext.Message;
import globalAuthority.GlobalParam;
import hashFunc.HashFunction;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.apache.log4j.Logger;
import timeParam.EncParam;
import userKey.UserAttributeKey;
import userKey.UserAuthorityKey;
import userKey.UserSplitKeys;
import userKey.Userkeys;

import java.text.SimpleDateFormat;
import java.util.*;

public class EdgeTimeCPAbe {
    private static Logger log = Logger.getLogger(EdgeTimeCPAbe.class);

    //first counstructed base CPABE

    /**
     * 这里使用的是Type A 曲线
     *
     * @param lambda 安全系数⋋
     * @return 全局参数GP
     */
    public static GlobalParam globalSetup(int lambda) {
        //官方文档中rbits=160,lambda=512
        GlobalParam params = new GlobalParam();
        /*
         * 动态产生的方法非常简单，大概有如下步骤:指定椭圆曲线的种类、产生椭圆曲线参数、初始化Pairing。
         * Type A曲线需要两个参数: rBit是Zp中阶数p 的比特长度; qBit是G中阶数的比特长度。代码为:
         * TypeACurveGenerator pg = newTypeACurveGenerator(rBit, qBit);
         * PairingParameters typeAParams = pg.generateo ;
         * Pairing pairing = PairingFactory.getPairing(typeAParams) ;
         *
         * Type A1 曲线需要二个参数: rumPrime是阶数N中有几个质数因子; qBit是每个质数因子的比特长度。
         * 注意，Type Al涉及到的阶数很大，其参数产生的时间也比较长。代码为:
         * TypeA1CurveGenerator pg = newTypeA1CurveGenerator(numPrime,qBit) ;
         * PairingParameters typeA1Params = pg.generate( ;
         * Pairing pairing = PairingFactory.getPairing(typeAlParams) ;
         * */
        params.setPairingParameters(new TypeACurveGenerator(160, lambda).generate());

        Pairing pairing = PairingFactory.getPairing(params.getPairingParameters());

        params.setG(pairing.getG1().newRandomElement().getImmutable());

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element ga = params.getG().powZn(a).getImmutable();
        params.setGa(ga.toBytes());
        params.setA(a);

        return params;
    }

    /**
     * 用户注册算法
     *
     * @param userID 用户ID
     * @param GP     　全局参数
     * @return　　返回用户密钥集
     */
    public static Userkeys userRegistry(String userID, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element uJ = pairing.getZr().newRandomElement().getImmutable();
        Userkeys userkeys = new Userkeys(userID);
        userkeys.setuUid(uJ.toBytes());
        return userkeys;
    }

    /**
     * 属性机构设立算法
     *
     * @param ASKS 属性机构私钥集
     * @return 输出具体属性机构的密钥
     */
    public static AuthorityKey authoritySetup(String authorityID, GlobalParam GP, AuthoritySecretKeys ASKS, Set<String> attributes) {
        // 初始化Pairing
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        // GP.getAPKS() = new AuthorityPublicKeys()
        AuthorityPublicKeys APKS = GP.getAPKS();

        Element egg = pairing.pairing(GP.getG(), GP.getG()).getImmutable();
        Element ad = pairing.getZr().newRandomElement().getImmutable();
        Element yd = pairing.getZr().newRandomElement().getImmutable();

        Element egg_ad = egg.powZn(ad);
        Element g_yd = GP.getG().powZn(yd);

        // 设置具体机构公钥
        AuthPublicKey authPublicKey = new AuthPublicKey(egg_ad.toBytes(), g_yd.toBytes());
        // 设置具体机构私钥
        AuthSecretKey authSecretKey = new AuthSecretKey(ad.toBytes(), yd.toBytes());
        /* 设置具体机构密钥 */
        AuthorityKey authorityKeys = new AuthorityKey(authorityID, authPublicKey, authSecretKey);

        /* 属性映射到属性机构 tMap */
        for (String attribute : attributes) {
            APKS.getTMap().put(attribute, authorityID);
        }
        /* 属性机构映射机构公钥 tMapAPK */
        APKS.gettMapAPK().put(authorityID, authPublicKey);
        /* tMapASK 映射属性机构私钥 */
        ASKS.gettMapASK().put(authorityID, authSecretKey);

        return authorityKeys;
    }

    /**
     * 生成加密参数
     *
     * @param GP        全局参数
     * @param fID       文件ID
     * @param begin     系统当前时间 减 10万
     * @param end       系统当前时间 加 10万
     * @param attribute 文件属性
     * @return 加密参数
     */
    public static EncParam genEncParam(GlobalParam GP, String fID, Date begin, Date end, String attribute) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        EncParam encParam = new EncParam(fID);

        Element r = pairing.getZr().newRandomElement().getImmutable();

        String fileInfo = fID + begin.toString() + end.toString() + attribute + r.toBytes().toString();

        Element tx = pairing.getZr().newElement();
        tx.setFromBytes(fileInfo.getBytes());

        Element attG1 = HashFunction.hashToG1(pairing, attribute.getBytes()).getImmutable();
        Element encP = attG1.powZn(tx);
        encParam.setAttribute(attribute);
        encParam.setBegin(begin);
        encParam.setEnd(end);
        encParam.setEncParam(encP.toBytes());
        return encParam;
    }

    /**
     * 加密
     *
     * @param message
     * @param ct
     * @param arho
     * @param GP
     * @param encParam
     * @return
     */
    public static Ciphertext encrypt(Message message, Ciphertext ct, AccessStructure arho, GlobalParam GP, Map<String, byte[]> encParam) {
//        Ciphertext ct=new Ciphertext();

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        AuthorityPublicKeys AKS = GP.getAPKS();

        Element M = pairing.getGT().newOneElement();
        M.setFromBytes(message.m);
        M = M.getImmutable();


        Element s = pairing.getZr().newRandomElement().getImmutable();

        List<Element> v = new ArrayList<>(arho.getL());
        v.add(s);

        List<Element> w = new ArrayList<>(arho.getL());
        w.add(pairing.getZr().newZeroElement().getImmutable());

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
            w.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        Element c0 = pairing.getGT().newOneElement();

        Element c1 = GP.getG().powZn(s);
        ct.setC1(c1.toBytes());


        for (int i = 0; i < arho.getN(); i++) {
            Element lambdaX = dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();
            Element wx = dotProduct(arho.getRow(i), w, pairing.getZr().newZeroElement(), pairing).getImmutable();

            Element rx = pairing.getZr().newRandomElement().getImmutable();

            Element eggAi = pairing.getGT().newElement();
            Element gYi = pairing.getG1().newElement();
            String attribute = arho.rho(i);
            eggAi.setFromBytes(AKS.getAPKByAttr(attribute).getEg1g1ai());
            eggAi = eggAi.getImmutable();
            gYi.setFromBytes(AKS.getAPKByAttr(attribute).getG1yi());
            gYi = gYi.getImmutable();

            String authorityID = AKS.getTMap().get(attribute);
            if (!ct.getC2Map().containsKey(authorityID)) {
                Element c2x = gYi.powZn(s);
                ct.setC2(authorityID, c2x.toBytes());

                c0.mul(eggAi);
            }

            Element gA = pairing.getG1().newElement();
            gA.setFromBytes(GP.getGa());
            Element attG1 = HashFunction.hashToG1(pairing, attribute.getBytes()).getImmutable();
            String key = ct.getfID() + attribute;
            log.info("encParam in CT:=" + key);
            //加入时间参数
            if (encParam.containsKey(key)) {
                Element timeParam = pairing.getG1().newElement();
                timeParam.setFromBytes(encParam.get(key));
                ct.setC3(gA.powZn(lambdaX).mul(timeParam.powZn(rx)).toBytes());
            } else {
                ct.setC3(gA.powZn(lambdaX).mul(attG1.powZn(rx)).toBytes());
            }

            Element c4x = gYi.powZn(rx).mul(GP.getG().powZn(wx));
            ct.setC4(c4x.toBytes());

            Element c5x = GP.getG().powZn(rx.negate());
            ct.setC5(c5x.toBytes());

        }
        ct.setC0(M.mul(c0.powZn(s)).toBytes());
        return ct;

    }

    public static UserAuthorityKey keyGen(String userID, GlobalParam GP, AuthorityKey AK, Userkeys userkeys, Set<String> attributes) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
//        AuthorityPublicKeys AKS=GP.getAPKS();
        UserAuthorityKey uAKey = new UserAuthorityKey(AK.getAuthorityID());

        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element u = pairing.getZr().newElement();
        u.setFromBytes(userkeys.getuUid());
        u = u.getImmutable();

//        Userkeys userkeys =new Userkeys(userID);

        Element ljk = pairing.getG1().newElement();
        ljk.setFromBytes(GP.getGa());
        uAKey.setLjk(ljk.powZn(t).toBytes());

//        Element rjk=GP.getG().powZn(u);
//        uAKey.setRj(rjk.toBytes());

        Element hGID = HashFunction.hashToG1(pairing, userID.getBytes()).getImmutable();

        AuthSecretKey sk = AK.getSecretKey();
        Element ai = pairing.getZr().newElement();
        ai.setFromBytes(sk.getAi());
        ai = ai.getImmutable();
        Element yi = pairing.getZr().newElement();
        yi.setFromBytes(sk.getYi());
        yi = yi.getImmutable();

        Element ga = pairing.getG1().newElement();
        ga.setFromBytes(GP.getGa());
        ga = ga.getImmutable();

        Element kjk = GP.getG().powZn(ai).mul(ga.powZn(u)).mul(ga.powZn(yi.mul(t)));
        uAKey.setKjk(kjk.toBytes());
        //未考虑重复属性的情况
        for (String attribute : attributes) {
            UserAttributeKey attKey = new UserAttributeKey(attribute);

            Element attG1 = HashFunction.hashToG1(pairing, attribute.getBytes()).getImmutable();


            Element kj_xk = attG1.powZn(u).mul(hGID.powZn(yi));
            attKey.setKj_xk(kj_xk.toBytes());
            uAKey.getUserAttKeys().put(attribute, attKey);

        }
        return uAKey;
    }

    public static Userkeys keysGen(List<UserAuthorityKey> userAKeys, Userkeys userkeys, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element uUid = pairing.getZr().newElement();
        uUid.setFromBytes(userkeys.getuUid());
        userkeys.setRj(GP.getG().powZn(uUid).toBytes());
        for (UserAuthorityKey uAK : userAKeys) {
            userkeys.getUserAuthKeys().put(uAK.getAuthority(), uAK);
            userkeys.addAttributes(uAK.getAttributes());
        }
        return userkeys;
    }

    public static UserSplitKeys edgeKeysGen(Userkeys userkeys, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        UserSplitKeys usk = new UserSplitKeys(userkeys.getUserID());
        Userkeys edgeKeys = usk.getEdgeKeys();
//        Userkeys edgeKeys=new Userkeys(userkeys.getUserID());

        Element z = pairing.getZr().newRandomElement().getImmutable();

        for (UserAuthorityKey uAK : userkeys.getUserAuthKeys().values()) {
            UserAuthorityKey edgeUAK = new UserAuthorityKey(uAK.getAuthority());
            Element kjk = pairing.getG1().newElement();
            kjk.setFromBytes(uAK.getKjk());
            kjk.powZn(z.invert());
            edgeUAK.setKjk(kjk.toBytes());

            Element ljk = pairing.getG1().newElement();
            ljk.setFromBytes(uAK.getLjk());
            ljk.powZn(z.invert());
            edgeUAK.setLjk(ljk.toBytes());

            for (UserAttributeKey uAttKey : uAK.getUserAttKeys().values()) {
                String attribute = uAttKey.getAttribute();
//                log.info("attribute in split Key:="+attribute);
                UserAttributeKey edgeUAttKey = new UserAttributeKey(attribute);
                Element kj_xk = pairing.getG1().newElement();
                kj_xk.setFromBytes(uAttKey.getKj_xk());
                kj_xk.powZn(z.invert());
                edgeUAttKey.setKj_xk(kj_xk.toBytes());
                edgeUAK.getUserAttKeys().put(attribute, edgeUAttKey);
            }
            edgeKeys.getUserAuthKeys().put(uAK.getAuthority(), edgeUAK);
            log.info("authority in split Key:" + edgeKeys.getUserAuthKeys().keySet());
        }
        Element rJ = pairing.getG1().newElement();
        rJ.setFromBytes(userkeys.getRj());
        rJ.powZn(z.invert());
        edgeKeys.setRj(rJ.toBytes());

        Element hGIDZ = HashFunction.hashToG1(pairing, userkeys.getUserID().getBytes());
        hGIDZ.powZn(z.invert());
        edgeKeys.setPj(hGIDZ.toBytes());
        edgeKeys.setuUid(userkeys.getuUid());
        edgeKeys.setAttributes(userkeys.getAttributes());

        usk.setZ(z.toBytes());
//        usk.setEdgeKeys(edgeKeys);
        return usk;
    }

    public static byte[] timeKeysGen(String fID, String attribute, byte[] userSK, EncParam encParam, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Date now = new Date();
        Element fUAttTx = pairing.getG1().newElement();
        SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        if ((now.compareTo(encParam.getBegin())) >= 0 && (now.compareTo(encParam.getEnd())) <= 0) {
            log.info("begin Date:=" + ft.format(encParam.getBegin()));
            log.info("current Date:=" + ft.format(now));
            log.info("end Date:=" + ft.format(encParam.getEnd()));
            fUAttTx.setFromBytes(encParam.getEncParam());
        } else {
            throw new IllegalArgumentException("illegality time");
        }

        Element fUAtt = HashFunction.hashToG1(pairing, attribute.getBytes()).getImmutable();
        Element uJ = pairing.getZr().newElement();
        uJ.setFromBytes(userSK);
        uJ = uJ.getImmutable();

        Element Tk = fUAttTx.powZn(uJ).mul(fUAtt.powZn(uJ.negate()));
        return Tk.toBytes();
    }

    public static void timeKeyCombine(Userkeys userkeys, Map<String, byte[]> timeKeyMap, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Map<String, String> authorityMap = GP.getAPKS().getTMap();
        for (String attribute : timeKeyMap.keySet()) {
            String authority = authorityMap.get(attribute);
            Element kj_xk = pairing.getG1().newElement();
            kj_xk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getUserAttKeys().get(attribute).getKj_xk());

            Element timeKey = pairing.getG1().newElement();
            timeKey.setFromBytes(timeKeyMap.get(attribute));
            userkeys.getUserAuthKeys().get(authority).getUserAttKeys().get(attribute).setKj_xk(kj_xk.mul(timeKey).toBytes());
        }
    }

    public static Message decrypt(Ciphertext CT, Userkeys userkeys, GlobalParam GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(userkeys.getAttributes());

        if (null == toUse || toUse.isEmpty()) {
            throw new IllegalArgumentException("not satisfied");
        }

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element HGID = HashFunction.hashToG1(pairing, userkeys.getUserID().getBytes()).getImmutable();

        Element t = pairing.getGT().newOneElement();

        for (Integer x : toUse) {
//            Element temp=pairing.getGT().newOneElement().getImmutable();

            String attribute = CT.getAccessStructure().rho(x);
            log.info("attributes in dec:=" + attribute);
            String authorityID = GP.getAPKS().getTMap().get(attribute);
            Element rjk = pairing.getG1().newElement();
            rjk.setFromBytes(userkeys.getRj());
            Element c3x = pairing.getG1().newElement();
            c3x.setFromBytes(CT.getC3(x));
            Element p3 = pairing.pairing(c3x, rjk);

            Element kj_xk = pairing.getG1().newElement();
            kj_xk.setFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserAttKeys().get(attribute).getKj_xk());
            Element c5x = pairing.getG1().newElement();
            c5x.setFromBytes(CT.getC5(x));
            Element p4 = pairing.pairing(kj_xk, c5x);

            Element c4x = pairing.getG1().newElement();
            c4x.setFromBytes(CT.getC4(x));
            Element p5 = pairing.pairing(HGID, c4x);


//            log.info("temp;="+temp.mul(p3.mul(p4).mul(p5)));
//            Element gALambdai=pairing.getG1().newElement();
//            gALambdai.setFromBytes(CT.getgALambda(x));
//            Element test=pairing.pairing(gALambdai,rjk);
//            log.info("temp2:="+test);

            t.mul(p3.mul(p4).mul(p5));
//            System.out.println("t in for:="+t);
        }
        int nA = CT.getC2Map().keySet().size();
        log.info("NA in dec:=" + nA);
        Element NA = pairing.getZr().newElement(nA);

        log.info("t=" + t);

        t.powZn(NA);
        t.invert();
        log.info("t after NA:=" + t);
        for (String authority : CT.getC2Map().keySet()) {
            Element c1x = pairing.getG1().newElement();
            c1x.setFromBytes(CT.getC1());
            Element kjk = pairing.getG1().newElement();
            kjk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getKjk());
            Element p1 = pairing.pairing(c1x, kjk);

            Element c2x = pairing.getG1().newElement();
            c2x.setFromBytes(CT.getC2(authority));
            Element ljk = pairing.getG1().newElement();
            ljk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getLjk());
            Element p2 = pairing.pairing(c2x, ljk).invert();
            t.mul(p1.mul(p2));
        }
        Element c0 = pairing.getGT().newElement();
        c0.setFromBytes(CT.getC0());
        c0.mul(t.invert());
        return new Message(c0.toBytes());

    }

    /**
     * 外包解密
     * @param CT
     * @param userkeys
     * @param GP
     * @return
     */
    public static LocaleCiphertext outsourceDecrypt(Ciphertext CT, Userkeys userkeys, GlobalParam GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(userkeys.getAttributes());

        if (null == toUse || toUse.isEmpty()) {
            throw new IllegalArgumentException("not satisfied");
        }

        LocaleCiphertext LC = new LocaleCiphertext(CT.getfID());

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element t = pairing.getGT().newOneElement();

        Element rj = pairing.getG1().newElement();
        rj.setFromBytes(userkeys.getRj());
        rj = rj.getImmutable();

        Element hGIDZ = pairing.getG1().newElement();
        hGIDZ.setFromBytes(userkeys.getPj());
        hGIDZ = hGIDZ.getImmutable();

        for (Integer x : toUse) {

            String attribute = CT.getAccessStructure().rho(x);
            String authorityID = GP.getAPKS().getTMap().get(attribute);

            Element c3x = pairing.getG1().newElement();
            c3x.setFromBytes(CT.getC3(x));
            Element p3 = pairing.pairing(c3x, rj);

            Element kj_xk = pairing.getG1().newElement();
            kj_xk.setFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserAttKeys().get(attribute).getKj_xk());
            log.info("kj_xk" + kj_xk);
            Element c5x = pairing.getG1().newElement();
            c5x.setFromBytes(CT.getC5(x));
            Element p4 = pairing.pairing(kj_xk, c5x);

            Element c4x = pairing.getG1().newElement();
            c4x.setFromBytes(CT.getC4(x));

            Element p5 = pairing.pairing(hGIDZ, c4x);

            t.mul(p3.mul(p4).mul(p5));
        }
        int nA = CT.getC2Map().keySet().size();
        Element NA = pairing.getZr().newElement(nA);
        t.powZn(NA);
        t.invert();

        for (String authority : CT.getC2Map().keySet()) {
            Element c1x = pairing.getG1().newElement();
            c1x.setFromBytes(CT.getC1());
            Element kjk = pairing.getG1().newElement();
            kjk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getKjk());
            Element p1 = pairing.pairing(c1x, kjk);

            Element c2x = pairing.getG1().newElement();
            c2x.setFromBytes(CT.getC2(authority));
            Element ljk = pairing.getG1().newElement();
            ljk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getLjk());
            Element p2 = pairing.pairing(c2x, ljk).invert();
            t.mul(p1.mul(p2));
        }
        LC.setC0(CT.getC0());
        LC.setC1(t.toBytes());
        return LC;
    }

    public static Message localDecrypt(LocaleCiphertext LC, byte[] usk, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element z = pairing.getZr().newElement();
        z.setFromBytes(usk);
        z = z.getImmutable();

        Element c0 = pairing.getGT().newElement();
        c0.setFromBytes(LC.getC0());

        Element c1 = pairing.getGT().newElement();
        c1.setFromBytes(LC.getC1());
        c1.powZn(z);
        c0.mul(c1.invert());
        return new Message(c0.toBytes());
    }

    private static Element dotProduct(List<AccessStructure.MatrixElement> v1, List<Element> v2, Element element, Pairing pairing) {
        if (v1.size() != v2.size()) throw new IllegalArgumentException("different length in acess policy");
        if (element.isImmutable()) {
            throw new IllegalArgumentException("result is immutable");
        }

        if (!element.isZero()) {
            element.setToZero();
        }

        for (int i = 0; i < v1.size(); i++) {
            Element e = pairing.getZr().newElement();
            switch (v1.get(i)) {
                case MINUS_ONE:
                    e.setToOne().negate();
                    break;
                case ONE:
                    e.setToOne();
                    break;
                case ZERO:
                    e.setToZero();
                    break;
            }
            element.add(e.mul(v2.get(i).getImmutable()));
        }
        return element;
    }

}
