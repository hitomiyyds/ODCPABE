package com.example.util;

import com.example.authority.*;
import com.example.ciphertext.AccessStructure;
import com.example.ciphertext.Ciphertext;
import com.example.ciphertext.Message;
import com.example.globalAuthority.GlobalParam;
import com.example.hashFunc.HashFunction;
import com.example.userKey.UserAttributeKey;
import com.example.userKey.UserAuthorityKey;
import com.example.userKey.Userkeys;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class EdgeCPAbe {
    private  static Logger log =Logger.getLogger(EdgeCPAbe.class);
    //first counstructed base CPABE
    public static GlobalParam globalSetup(int lambda) {
        //官方文档中rbits=160,lambda=512
        GlobalParam params = new GlobalParam();

        params.setPairingParameters(new TypeACurveGenerator(160, lambda).generate());//rbits 是Zp中阶数p的位数  ，qbits G中阶数的位数
        Pairing pairing = PairingFactory.getPairing(params.getPairingParameters());

        params.setG(pairing.getG1().newRandomElement().getImmutable());
        Element a=pairing.getZr().newRandomElement().getImmutable();
        Element ga=params.getG().powZn(a).getImmutable();
        params.setGa(ga.toBytes());
        params.setA(a);

        return params;
    }
    public static Userkeys userRegistry(String userID, GlobalParam GP){
        Pairing pairing=PairingFactory.getPairing(GP.getPairingParameters());
        Element uJ=pairing.getZr().newRandomElement().getImmutable();
        Userkeys userkeys=new Userkeys(userID);
        userkeys.setuUid(uJ.toBytes());
        return userkeys;
    }
    public static AuthorityKey authoritySetup(String authorityID, GlobalParam GP, AuthoritySecretKeys ASKS, String... attributes) {

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        AuthorityPublicKeys APKS=GP.getAPKS();

        Element egg=pairing.pairing(GP.getG(),GP.getG()).getImmutable();
        Element ad= pairing.getZr().newRandomElement().getImmutable();
        Element yd= pairing.getZr().newRandomElement().getImmutable();

        Element egg_ad=egg.powZn(ad);
        Element g_yd=GP.getG().powZn(yd);


        AuthPublicKey authPublicKey=new AuthPublicKey(egg_ad.toBytes(),g_yd.toBytes());
        AuthSecretKey authSecretKey=new AuthSecretKey(ad.toBytes(),yd.toBytes());
        AuthorityKey authorityKeys = new AuthorityKey(authorityID,authPublicKey,authSecretKey);

        for (String attribute:attributes) {
            APKS.getTMap().put(attribute,authorityID);
        }
        APKS.gettMapAPK().put(authorityID,authPublicKey);
        ASKS.gettMapASK().put(authorityID,authSecretKey);

        return authorityKeys;
    }
    public static Ciphertext encrypt(Message message, AccessStructure arho, GlobalParam GP) {
        Ciphertext ct=new Ciphertext();

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        AuthorityPublicKeys AKS=GP.getAPKS();

        Element M =pairing.getGT().newOneElement();
        M.setFromBytes(message.m);
        M=M.getImmutable();



        Element s= pairing.getZr().newRandomElement().getImmutable();

        List<Element>  v =new ArrayList<>(arho.getL());
        v.add(s);

        List<Element> w= new ArrayList<>(arho.getL());
        w.add(pairing.getZr().newZeroElement().getImmutable());

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
            w.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        Element c0=pairing.getGT().newOneElement();

        Element c1=GP.getG().powZn(s);
        ct.setC1(c1.toBytes());

//        Element cTest=pairing.getG1().newElement();
//        cTest.setFromBytes(GP.getGa());
//        ct.setcTest(cTest.powZn(s).toBytes());


        for (int i = 0; i <arho.getN() ; i++) {
            Element lambdaX = dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();
            Element wx = dotProduct(arho.getRow(i), w, pairing.getZr().newZeroElement(), pairing).getImmutable();

            Element rx = pairing.getZr().newRandomElement().getImmutable();

            Element eggAi = pairing.getGT().newElement();
            Element gYi=pairing.getG1().newElement();
            String attribute =arho.rho(i);
            eggAi.setFromBytes(AKS.getAPKByAttr(attribute).getEg1g1ai());
            eggAi=eggAi.getImmutable();
            gYi.setFromBytes(AKS.getAPKByAttr(attribute).getG1yi());
            gYi=gYi.getImmutable();

            String authorityID=AKS.getTMap().get(attribute);
            if(!ct.getC2Map().containsKey(authorityID)){
                Element c2x=gYi.powZn(s);
                ct.setC2(authorityID,c2x.toBytes());

                c0.mul(eggAi);
            }

            Element c3x1=pairing.getG1().newElement();
            c3x1.setFromBytes(GP.getGa());
            Element c3x2= HashFunction.hashToG1(pairing,attribute.getBytes()).getImmutable();
            ct.setC3(c3x1.powZn(lambdaX).mul(c3x2.powZn(rx)).toBytes());

            Element c4x=gYi.powZn(rx).mul(GP.getG().powZn(wx));
//            Element c4x=gYi.powZn(rx);
            ct.setC4(c4x.toBytes());

            Element c5x=GP.getG().powZn(rx.negate());
            ct.setC5(c5x.toBytes());

        }
        ct.setC0(M.mul(c0.powZn(s)).toBytes());
        return ct;

    }
    public static UserAuthorityKey keyGen(String userID, GlobalParam GP, AuthorityKey AK, Userkeys userkeys, String ...attributes){
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
//        AuthorityPublicKeys AKS=GP.getAPKS();
        UserAuthorityKey uAKey= new UserAuthorityKey(AK.getAuthorityID());

        Element t=pairing.getZr().newRandomElement().getImmutable();
        Element u=pairing.getZr().newElement();
        u.setFromBytes(userkeys.getuUid());
        u=u.getImmutable();

//        Userkeys userkeys =new Userkeys(userID);

        Element ljk=pairing.getG1().newElement();
        ljk.setFromBytes(GP.getGa());
        uAKey.setLjk(ljk.powZn(t).toBytes());

//        Element rjk=GP.getG().powZn(u);
//        uAKey.setRjk(rjk.toBytes());

        Element hGID= HashFunction.hashToG1(pairing,userID.getBytes()).getImmutable();

        AuthSecretKey sk=AK.getSecretKey();
        Element ai= pairing.getZr().newElement();
        ai.setFromBytes(sk.getAi());
        ai=ai.getImmutable();
        Element yi= pairing.getZr().newElement();
        yi.setFromBytes(sk.getYi());
        yi=yi.getImmutable();

        Element ga=pairing.getG1().newElement();
        ga.setFromBytes(GP.getGa());
        ga=ga.getImmutable();

        Element kjk=GP.getG().powZn(ai).mul(ga.powZn(u)).mul(ga.powZn(yi.mul(t)));
        uAKey.setKjk(kjk.toBytes());
        //未考虑重复属性的情况
        for(String attribute:attributes){
            UserAttributeKey attKey =new UserAttributeKey(attribute);

            Element attG1= HashFunction.hashToG1(pairing,attribute.getBytes()).getImmutable();


            Element kj_xk=attG1.powZn(u).mul(hGID.powZn(yi));
            attKey.setKj_xk(kj_xk.toBytes());
            uAKey.getUserAttKeys().put(attribute,attKey);

        }
        return uAKey;
    }
    public static  Userkeys keysGen(List<UserAuthorityKey> userAKeys,Userkeys userkeys,GlobalParam GP){
        Pairing pairing=PairingFactory.getPairing(GP.getPairingParameters());
        Element uUid=pairing.getZr().newElement();
        uUid.setFromBytes(userkeys.getuUid());
        userkeys.setRj(GP.getG().powZn(uUid).toBytes());
        for(UserAuthorityKey uAK: userAKeys){
            userkeys.getUserAuthKeys().put(uAK.getAuthority(),uAK);
            userkeys.addAttributes(uAK.getAttributes());
        }
        return userkeys;
    }
    public static Message decrypt(Ciphertext CT, Userkeys userkeys, GlobalParam GP ){
        List<Integer> toUse=CT.getAccessStructure().getIndexesList(userkeys.getAttributes());



        if(null == toUse || toUse .isEmpty()) throw new IllegalArgumentException("not satisfied");

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element HGID= HashFunction.hashToG1(pairing,userkeys.getUserID().getBytes()).getImmutable();

        Element t=pairing.getGT().newOneElement();

        for(Integer x :toUse){
//            Element temp=pairing.getGT().newOneElement().getImmutable();

            String attribute=CT.getAccessStructure().rho(x);
            log.info("attributes in dec:="+attribute);
            String authorityID=GP.getAPKS().getTMap().get(attribute);
            Element rjk=pairing.getG1().newElement();
            rjk.setFromBytes(userkeys.getRj());
            Element c3x=pairing.getG1().newElement();
            c3x.setFromBytes(CT.getC3(x));
            Element p3=pairing.pairing(c3x,rjk);

            Element kj_xk =pairing.getG1().newElement();
            kj_xk.setFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserAttKeys().get(attribute).getKj_xk());
            Element c5x=pairing.getG1().newElement();
            c5x.setFromBytes(CT.getC5(x));
            Element p4=pairing.pairing(kj_xk,c5x);

            Element c4x=pairing.getG1().newElement();
            c4x.setFromBytes(CT.getC4(x));
            Element p5=pairing.pairing(HGID,c4x);


//            log.info("temp;="+temp.mul(p3.mul(p4).mul(p5)));
//            Element gALambdai=pairing.getG1().newElement();
//            gALambdai.setFromBytes(CT.getgALambda(x));
//            Element test=pairing.pairing(gALambdai,rjk);
//            log.info("temp2:="+test);

            t.mul(p3.mul(p4).mul(p5));
//            System.out.println("t in for:="+t);
        }
        int nA=CT.getC2Map().keySet().size();
        log.info("NA in dec:="+nA);
        Element NA=pairing.getZr().newElement(nA);

//        Element uJ=pairing.getZr().newElement();
//        uJ.setFromBytes(userkeys.getuUid());
//        Element rjk1=GP.getG().powZn(uJ);
//        Element test=pairing.getG1().newElement();
//        test.setFromBytes(CT.getcTest());
//        Element eggASU=pairing.pairing(test,rjk1);
//        log.info("eggASU="+eggASU);
        log.info("t="+t);

        t.powZn(NA);
        t.invert();
        log.info("t after NA:="+t);
        for(String authority:CT.getC2Map().keySet()){
            Element c1x= pairing.getG1().newElement();
            c1x.setFromBytes(CT.getC1());
            Element kjk =pairing.getG1().newElement();
            kjk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getKjk());
            Element p1=pairing.pairing(c1x,kjk);

            Element c2x=pairing.getG1().newElement();
            c2x.setFromBytes(CT.getC2(authority));
            Element ljk=pairing.getG1().newElement();
            ljk.setFromBytes(userkeys.getUserAuthKeys().get(authority).getLjk());
            Element p2 =pairing.pairing(c2x,ljk).invert();
            t.mul(p1.mul(p2));
        }
        Element c0=pairing.getGT().newElement();
        c0.setFromBytes(CT.getC0());
        c0.mul(t.invert());
        return new Message(c0.toBytes());

    }

    private static Element dotProduct(List<AccessStructure.MatrixElement> v1 , List<Element> v2 , Element element , Pairing pairing){
        if(v1.size()!=v2.size()) throw new IllegalArgumentException("different length in acess policy");
        if(element.isImmutable()) throw new IllegalArgumentException("result is immutable");

        if(!element.isZero()){
            element.setToZero();
        }

        for (int i = 0; i <v1.size() ; i++) {
            Element e = pairing.getZr().newElement();
            switch (v1.get(i)){
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

    /**
     * 明文生成
     * @param GP　全局参数
     * @return　
     */
    public static Message generateRandomMessage(GlobalParam GP){
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element M =pairing.getGT().newRandomElement().getImmutable();
        return new Message(M.toBytes());
    }
}
