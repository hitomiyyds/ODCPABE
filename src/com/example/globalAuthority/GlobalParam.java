package com.example.globalAuthority;

import com.example.authority.AuthorityPublicKeys;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @author user01
 * 全局参数GP
 */
public class GlobalParam {
    private static final long serialVersionUID = 1L;
    /*在jPBC中，双线性群的使用都是通过叫做Pairing的对象来实现的。
    双线性群的初始化在jPBC中就是对Pairing对象的初始化。*/
    private PairingParameters pairingParameters;
    private AuthorityPublicKeys APKS;
    /**
        可以使用Element接口访问组、环和字段的元素。
        您可以从field接口表示的代数结构(例如特定的有限域或椭圆曲线组)开始获得Element的实例。
     */
    private Element g;
    private Element a;

    private byte[] ga;

    public GlobalParam() {
        this.APKS =new AuthorityPublicKeys();
    }

    public PairingParameters getPairingParameters(){return  pairingParameters;}

    public void setPairingParameters(PairingParameters pairingParameters) {
        this.pairingParameters = pairingParameters;
    }

    public Element getG() {
        return g;
    }

    public void setG(Element g) {
        this.g = g;
    }

    public byte[] getGa() {
        return ga;
    }

    public void setGa(byte[] ga) {
        this.ga = ga;
    }
    public Element getA() {
        return a;
    }

    public void setA(Element a) {
        this.a = a;
    }

    public AuthorityPublicKeys getAPKS() {
        return APKS;
    }

}
