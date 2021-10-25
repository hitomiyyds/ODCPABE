package timeParam;

import java.util.Date;

/**
 * 加密参数
 * 包含加密参数类型字节数组
 * 属性
 * 开始时间及结束时间
 * @author user01
 */
public class EncParam {
    private byte[] encParam;
    private String fID;
    private String attribute;
    private Date begin;
    private Date end;

    public EncParam(String fID) {
        this.fID = fID;
    }

    public byte[] getEncParam() {
        return encParam;
    }

    public void setEncParam(byte[] encParam) {
        this.encParam = encParam;
    }

    public String getAttribute() {
        return attribute;
    }

    public void setAttribute(String attribute) {
        this.attribute = attribute;
    }

    public Date getBegin() {
        return begin;
    }

    public void setBegin(Date begin) {
        this.begin = begin;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }
}
