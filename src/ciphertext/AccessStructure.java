package ciphertext;

import java.io.Serializable;
import java.util.*;

public class AccessStructure implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<Integer, String> rho;
    private Vector<Vector<MatrixElement>> A;//A=N*L
    private TreeNode policyTree;
    private int partsIndex;

    private AccessStructure() {
        A = new Vector<Vector<MatrixElement>>();
        rho = new HashMap<Integer, String>();
    }

    public static AccessStructure buildFromPolicy(String policy) {
        //AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c");
        AccessStructure aRho = new AccessStructure();

        aRho.generateTree(policy);

        aRho.generateMatrix();

        return aRho;
    }

    public Vector<MatrixElement> getRow(int row) {
        return A.get(row);
    }

    /**
     * 属性矩阵的列数
     * @return
     */
    public int getL() {
        return A.get(0).size();
    }

    /**
     * 属性矩阵的行数
     * @return
     */
    public int getN() {
        return A.size();
    }

    public String rho(int i) {
        return rho.get(i);
    }

    private boolean findIfSAT(TreeNode node) {
        if (node instanceof Attribute) {
            return 1 == node.getSat();
        } else {
            boolean b;
            if (node instanceof AndGate) {
                b = findIfSAT(((AndGate) node).getLeft());
                b &= findIfSAT(((AndGate) node).getRight());
            } else if (node instanceof OrGate) {
                b = findIfSAT(((OrGate) node).getLeft());
                b |= findIfSAT(((OrGate) node).getRight());
            } else
                throw new IllegalArgumentException("Unknown node type");
            node.setSat(b ? 1 : -1);
            return b;
        }
    }

    public List<Integer> getIndexesList(Collection<String> pKeys) {
        // initialize
        Queue<TreeNode> queue = new LinkedList<TreeNode>();
        queue.add(policyTree);

        while (!queue.isEmpty()) {
            TreeNode t = queue.poll();

            if (t instanceof Attribute) {
                t.setSat(pKeys.contains(t.getName()) ? 1 : -1);
            } else if (t instanceof InternalNode) {
                t.setSat(0);
                queue.add(((InternalNode) t).getLeft());
                queue.add(((InternalNode) t).getRight());
            }
        }

        // find if satisfiable
        if (!findIfSAT(policyTree))
            return null;

        // populate the list
        List<Integer> list = new LinkedList<Integer>();
        queue.add(policyTree);
        while (!queue.isEmpty()) {
            TreeNode t = queue.poll();

            if (1 == t.getSat()) {
                if (t instanceof AndGate) {
                    queue.add(((AndGate) t).getLeft());
                    queue.add(((AndGate) t).getRight());
                } else if (t instanceof OrGate) {
                    if (1 == ((OrGate) t).getLeft().getSat()) {
                        queue.add(((OrGate) t).getLeft());
                    } else if (1 == ((OrGate) t).getRight().getSat()) {
                        queue.add(((OrGate) t).getRight());
                    }
                } else if (t instanceof Attribute) {
                    list.add(((Attribute) t).getX());
                }
            }
        }

        // return
        return list;
    }

    /**
     * 生成矩阵
     */
    private void generateMatrix() {
        int c = computeLabels(policyTree);

        Queue<TreeNode> queue = new LinkedList<TreeNode>();
        queue.add(policyTree);

        while (!queue.isEmpty()) {
            TreeNode node = queue.poll();

            if (node instanceof InternalNode) {
                queue.add(((InternalNode) node).getLeft());
                queue.add(((InternalNode) node).getRight());
            } else {
                rho.put(A.size(), node.getName());
                ((Attribute) node).setX(A.size());
                Vector<MatrixElement> Ax = new Vector<MatrixElement>(c);

                for (int i = 0; i < node.getLabel().length(); i++) {
                    switch (node.getLabel().charAt(i)) {
                        case '0':
                            Ax.add(MatrixElement.ZERO);
                            break;
                        case '1':
                            Ax.add(MatrixElement.ONE);
                            break;
                        case '*':
                            Ax.add(MatrixElement.MINUS_ONE);
                            break;
                    }
                }

                while (c > Ax.size()) {
                    Ax.add(MatrixElement.ZERO);
                }
                A.add(Ax);
            }
        }
    }

    private int computeLabels(TreeNode root) {
        Queue<TreeNode> queue = new LinkedList<TreeNode>();
        StringBuffer sb = new StringBuffer();
        int c = 1;

        root.setLabel("1");
        queue.add(root);

        while (!queue.isEmpty()) {
//            queue.poll();
//            功能：检索并删除该队列的头部，如果该队列为空则返回null
//            返回：这个队列的头，如果这个队列是空的，则为空
            TreeNode node = queue.poll();

            if (node instanceof Attribute) {
                continue;
            }

            if (node instanceof OrGate) {
                ((OrGate) node).getLeft().setLabel(node.getLabel());
                queue.add(((OrGate) node).getLeft());
                ((OrGate) node).getRight().setLabel(node.getLabel());
                queue.add(((OrGate) node).getRight());
            } else if (node instanceof AndGate) {
                sb.delete(0, sb.length());

                sb.append(node.getLabel());

                while (c > sb.length()) {
                    sb.append('0');
                }
                sb.append('1');
                ((AndGate) node).getLeft().setLabel(sb.toString());
                queue.add(((AndGate) node).getLeft());

                sb.delete(0, sb.length());

                while (c > sb.length()) {
                    sb.append('0');
                }
                sb.append('*');

                ((AndGate) node).getRight().setLabel(sb.toString());
                queue.add(((AndGate) node).getRight());

                c++;
            }
        }

        return c;
    }

    /**
     * 生成访问结构树
     *
     * @param policyParts
     * @return
     */
    private TreeNode generateTree(String[] policyParts) {
        partsIndex++;
        String policyAtIndex = policyParts[partsIndex];
        TreeNode node = generateNodeAtIndex(policyAtIndex);
//instanceof 严格来说是Java中的一个双目运算符，用来测试一个对象是否为一个类的实例，
        if (node instanceof InternalNode) {
            ((InternalNode) node).setLeft(generateTree(policyParts));
            ((InternalNode) node).setRight(generateTree(policyParts));
        }

        return node;
    }

    /***
     * 根据索引生成节点
     * @param policyAtIndex
     * @return
     */
    private TreeNode generateNodeAtIndex(String policyAtIndex) {
        switch (policyAtIndex) {
            case "and":
                return new AndGate();
            case "or":
                return new OrGate();
            default:
                return new Attribute(policyAtIndex);
        }
    }

    /**
     * 生成访问结构树
     *
     * @return
     */
    private void generateTree(String policy) {
        partsIndex = -1;
        //按空格切分
        String[] policyParts = policy.split("\\s+");

        policyTree = generateTree(policyParts);
    }

    public void printMatrix() {
        System.out.println("\n");
        for (int x = 0; x < A.size(); x++) {
            Vector<MatrixElement> Ax = A.get(x);
            System.out.printf("%s: [", rho.get(x));
            for (MatrixElement aAx : Ax) {
                switch (aAx) {
                    case ONE:
                        System.out.print("  1");
                        break;
                    case MINUS_ONE:
                        System.out.print(" -1");
                        break;
                    case ZERO:
                        System.out.print("  0");
                        break;
                }
            }
            System.out.println("]");
        }
    }

    private void printPolicy(TreeNode node) {
        System.out.print(" " + node.getName());
        if (node instanceof InternalNode) {
            System.out.println(" \nleft: ");
            printPolicy(((InternalNode) node).getLeft());
            System.out.println(" \nright: ");
            printPolicy(((InternalNode) node).getRight());
        }
    }

    public void printPolicy() {
        printPolicy(policyTree);
        System.out.println();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((A == null) ? 0 : A.hashCode());
        result = prime * result + partsIndex;
        result = prime * result
                + ((policyTree == null) ? 0 : policyTree.hashCode());
        result = prime * result + ((rho == null) ? 0 : rho.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof AccessStructure))
            return false;
        AccessStructure other = (AccessStructure) obj;
        if (A == null) {
            if (other.A != null)
                return false;
        } else if (!A.equals(other.A))
            return false;
        if (partsIndex != other.partsIndex)
            return false;
        if (policyTree == null) {
            if (other.policyTree != null)
                return false;
        } else if (!policyTree.equals(other.policyTree))
            return false;
        if (rho == null) {
            if (other.rho != null)
                return false;
        } else if (!rho.equals(other.rho))
            return false;
        return true;
    }

    public enum MatrixElement {
        MINUS_ONE,
        ZERO,
        ONE
    }

    public static void main(String[] args) {
//        String policy = "and and and and a b  or c d and e f or g h";
        String policy = "and and and and a b  or c d and e f or g a";
        AccessStructure as = AccessStructure.buildFromPolicy(policy);

        TreeNode tn = as.policyTree;
        as.printPolicy(tn);
        as.printMatrix();

    }
}
