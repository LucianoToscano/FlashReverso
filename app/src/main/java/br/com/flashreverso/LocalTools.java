package br.com.flashreverso;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/** Bounded, read-only file inspection and selected ZIP entry export. */
public final class LocalTools {
    private LocalTools() {}
    public static final int MAX_ITEMS=1000;
    public static final long MAX_ENTRY=128L*1024*1024;
    private static final int MAX_TABLE=500000;
    static long u32(RandomAccessFile f, long p, boolean le) throws IOException {
        f.seek(p); int v=f.readInt(); return Integer.toUnsignedLong(le?Integer.reverseBytes(v):v);
    }
    static int u16(RandomAccessFile f,long p,boolean le)throws IOException {
        f.seek(p); short v=f.readShort();return Short.toUnsignedInt(le?Short.reverseBytes(v):v);
    }
    static long u64(RandomAccessFile f,long p,boolean le)throws IOException {
        f.seek(p); long v=f.readLong();return le?Long.reverseBytes(v):v;
    }
    static void range(long pos,long size,long length)throws IOException {
        if(pos<0||size<0||pos>length||size>length-pos)throw new IOException("Intervalo fora do arquivo");
    }
    static void table(long p,long n,int stride,long len)throws IOException{
        if(n>MAX_TABLE)throw new IOException("Tabela excede limite");
        range(p,n*stride,len);
    }
    public static String details(File file)throws IOException{
        try(RandomAccessFile f=new RandomAccessFile(file,"r")){
            if(f.length()<8)return "";
            int magic=f.readInt();
            if(magic==0x7f454c46)return elf(f);
            if(magic==0x6465780a)return dex(f);
            if(magic==0xaf1bb1fa)return metadata(f);
            if((magic>>>16)==0x504b)return archiveDetails(file);
            return "";
        }
    }
    private static String asciiZ(RandomAccessFile f,long p,long end,int limit)throws IOException{
        if(p<0||p>=end||end>f.length())return "?";
        f.seek(p);StringBuilder s=new StringBuilder();
        for(int i=0;i<limit&&f.getFilePointer()<end;i++){int v=f.readUnsignedByte();if(v==0)return s.toString();s.append(v>=32&&v<=126?(char)v:'?');}
        return s+"…";
    }
    private static String dexString(RandomAccessFile f,long ids,long n,long i)throws IOException{
        if(i<0||i>=n)return "?";
        long p=u32(f,ids+i*4,true);range(p,1,f.length());f.seek(p);
        boolean done=false;for(int a=0;a<5;a++){if((f.readUnsignedByte()&128)==0){done=true;break;}}if(!done)throw new IOException("ULEB128 inválido");
        return asciiZ(f,f.getFilePointer(),f.length(),256);
    }
    private static String dex(RandomAccessFile f)throws IOException{
        long len=f.length();range(0,112,len);if(u32(f,40,true)!=0x12345678)throw new IOException("DEX endian não suportado");
        long sn=u32(f,56,true),sp=u32(f,60,true),tn=u32(f,64,true),tp=u32(f,68,true),mn=u32(f,88,true),mp=u32(f,92,true),cn=u32(f,96,true),cp=u32(f,100,true);
        table(sp,sn,4,len);table(tp,tn,4,len);table(mp,mn,8,len);table(cp,cn,32,len);
        StringBuilder s=new StringBuilder("\nDEX — inventário de identificadores (não é código Java/Smali)\nClasses:\n");
        for(long i=0;i<Math.min(cn,MAX_ITEMS);i++){long t=u32(f,cp+32*i,true);s.append(type(f,tp,tn,sp,sn,t)).append('\n');}
        s.append("Métodos referenciados (até ").append(MAX_ITEMS).append("):\n");
        for(long i=0;i<Math.min(mn,MAX_ITEMS);i++){long at=mp+8*i;int t=u16(f,at,true);long name=u32(f,at+4,true);s.append(type(f,tp,tn,sp,sn,t)).append(" -> ").append(dexString(f,sp,sn,name)).append('\n');}
        return s.toString();
    }
    private static String type(RandomAccessFile f,long tp,long tn,long sp,long sn,long t)throws IOException{
        return t>=0&&t<tn?dexString(f,sp,sn,u32(f,tp+t*4,true)):"?";
    }
    private static String elf(RandomAccessFile f)throws IOException{
        f.seek(4);int cls=f.readUnsignedByte(),enc=f.readUnsignedByte();if((cls!=1&&cls!=2)||(enc!=1&&enc!=2))throw new IOException("ELF inválido");
        boolean x=cls==2,le=enc==1;long len=f.length();range(0,x?64:52,len);
        long sh=x?u64(f,40,le):u32(f,32,le);
        int stride=u16(f,x?58:46,le),count=u16(f,x?60:48,le),stridx=u16(f,x?62:50,le);
        StringBuilder s=new StringBuilder("\nELF — seções\n");
        if(count==0||stridx>=count||stride<(x?64:40))return s.append("Tabela ausente ou formato estendido não suportado.\n").toString();
        table(sh,count,stride,len);
        long st=sh+(long)stridx*stride;long names=x?u64(f,st+24,le):u32(f,st+16,le);long size=x?u64(f,st+32,le):u32(f,st+20,le);range(names,size,len);
        for(int i=0;i<Math.min(count,MAX_ITEMS);i++){
            long p=sh+(long)i*stride,n=u32(f,p,le),kind=u32(f,p+4,le),sz=x?u64(f,p+32,le):u32(f,p+20,le);
            s.append(i).append("  ").append(n<size?asciiZ(f,names+n,names+size,128):"?").append("  tipo=").append(kind).append("  tamanho=").append(Long.toUnsignedString(sz)).append('\n');
        }
        return s.toString();
    }
    private static String metadata(RandomAccessFile f)throws IOException{
        return "\nIL2CPP — versão declarada: "+u32(f,4,true)+"\nApenas identificação; não reconstrói classes ou funções Unity.\n";
    }
    public static String archiveDetails(File file)throws IOException{
        StringBuilder s=new StringBuilder("\nZIP — detalhes de componentes\n");
        int n=0;try(ZipFile z=new ZipFile(file)){
            Enumeration<? extends ZipEntry> it=z.entries();
            while(it.hasMoreElements()&&n<MAX_ITEMS){ZipEntry e=it.nextElement();n++;String name=e.getName();if(name.endsWith(".dex")||name.endsWith(".so")||name.endsWith("global-metadata.dat")||name.endsWith(".assets")||name.endsWith(".unity3d")||name.endsWith("resources.arsc"))s.append(clean(name)).append(" CRC=").append(Long.toHexString(e.getCrc())).append('\n');}
        }return s.toString();
    }
    private static String clean(String s){return s.replaceAll("[\\p{Cntrl}]","?");}
    public static List<String> entries(File file)throws IOException{
        List<String> names=new ArrayList<>();Set<String> seen=new HashSet<>();
        try(ZipFile z=new ZipFile(file)){Enumeration<? extends ZipEntry> it=z.entries();int scanned=0;while(it.hasMoreElements()&&scanned++<50000){ZipEntry e=it.nextElement();if(!seen.add(e.getName()))throw new IOException("ZIP com nomes duplicados");if(!e.isDirectory()&&names.size()<MAX_ITEMS)names.add(e.getName());}if(it.hasMoreElements())throw new IOException("ZIP excede limite de entradas");}
        return names;
    }
    public static void exportEntry(File file,String name,OutputStream dest)throws IOException{
        if(!entries(file).contains(name))throw new IOException("Entrada indisponível");
        try(ZipFile z=new ZipFile(file)){ZipEntry e=z.getEntry(name);if(e==null||e.isDirectory()||e.getSize()<0||e.getSize()>MAX_ENTRY)throw new IOException("Entrada inválida ou maior que 128 MiB");
            CRC32 crc=new CRC32();long total=0;
            try(InputStream in=z.getInputStream(e)){byte[] buf=new byte[65536];int n;while((n=in.read(buf))!=-1){total+=n;if(total>MAX_ENTRY||total>e.getSize())throw new IOException("Limite de extração excedido");crc.update(buf,0,n);dest.write(buf,0,n);}}
            if(total!=e.getSize()||crc.getValue()!=e.getCrc())throw new IOException("Integridade da entrada inválida");
        }
    }
    public static String compare(File a,File b)throws IOException{
        Map<String,String> x=index(a),y=index(b);StringBuilder s=new StringBuilder("Comparação ZIP — tamanho e CRC (não prova igualdade criptográfica)\n");int n=0,add=0,del=0,mod=0;
        for(String k:y.keySet()){String op=null;if(!x.containsKey(k)){add++;op="+ ";}else if(!Objects.equals(x.get(k),y.get(k))){mod++;op="~ ";}if(op!=null&&n++<MAX_ITEMS)s.append(op).append(clean(k)).append('\n');}
        for(String k:x.keySet())if(!y.containsKey(k)){del++;if(n++<MAX_ITEMS)s.append("- ").append(clean(k)).append('\n');}
        return s.append("Adicionados: ").append(add).append(" | Removidos: ").append(del).append(" | Alterados: ").append(mod).toString();
    }
    private static Map<String,String> index(File file)throws IOException{
        Map<String,String> result=new TreeMap<>();try(ZipFile z=new ZipFile(file)){Enumeration<? extends ZipEntry> it=z.entries();int count=0;while(it.hasMoreElements()){if(++count>50000)throw new IOException("Limite de entradas");ZipEntry e=it.nextElement();if(e.isDirectory())continue;if(result.put(e.getName(),e.getSize()+":"+e.getCrc())!=null)throw new IOException("ZIP com nomes duplicados");}}return result;
    }
}
