package br.com.flashreverso;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.zip.*;

/** Read-only inspection. Never executes or loads the selected binary. */
public final class Inspector {
    private static final int MAX_ENTRIES = 50000;
    private static final int MAX_LIST = 1500;
    private static final int MAX_HEADER = 112;
    private Inspector() {}
    public static String inspect(File file) throws IOException {
        byte[] h; try (InputStream in = new FileInputStream(file)) { byte[] buf=new byte[MAX_HEADER]; int pos=0,n; while(pos<buf.length && (n=in.read(buf,pos,buf.length-pos))!=-1) { if(n==0) break; pos+=n; } h=Arrays.copyOf(buf,pos); }
        StringBuilder out = new StringBuilder();
        out.append("Tamanho: ").append(file.length()).append(" bytes\nSHA-256: ").append(sha256(file)).append('\n');
        out.append(describe(h));
        if (h.length >= 4 && h[0] == 'P' && h[1] == 'K') archive(file, out);
        out.append("\nCabeçalho hexadecimal:\n");
        for (int i=0;i<h.length;i++) { if(i%16==0) out.append(String.format(Locale.ROOT,"%04x  ",i)); out.append(String.format(Locale.ROOT,"%02x ",h[i]&255)); if(i%16==15) out.append('\n'); }
        return out.toString();
    }
    static String describe(byte[] h) {
        if (h.length>=20 && h[0]==0x7f && h[1]=='E' && h[2]=='L' && h[3]=='F') {
            if ((h[4]!=1 && h[4]!=2)||(h[5]!=1 && h[5]!=2)) return "ELF: cabeçalho inválido\n";
            ByteBuffer b=ByteBuffer.wrap(h).order(h[5]==1?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
            int m=Short.toUnsignedInt(b.getShort(18));
            String arch=switch(m){case 3->"x86";case 40->"ARM";case 62->"x86-64";case 183->"AArch64";case 243->"RISC-V";default->"ID "+m;};
            return "Formato: ELF\nArquitetura: "+arch+"\nBits: "+(h[4]==1?32:64)+"\nOrdem: "+(h[5]==1?"little endian":"big endian")+"\n";
        }
        if (h.length>=8 && h[0]=='d' && h[1]=='e' && h[2]=='x' && h[3]=='\n' && h[7]==0) {
            String s="Formato: DEX\nVersão: "+new String(h,4,3,StandardCharsets.US_ASCII)+"\n";
            if(h.length>=112) { ByteBuffer b=ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN); if(b.getInt(40)==0x12345678) s+="Strings: "+Integer.toUnsignedLong(b.getInt(56))+"\nTipos: "+Integer.toUnsignedLong(b.getInt(64))+"\nMétodos: "+Integer.toUnsignedLong(b.getInt(88))+"\nClasses: "+Integer.toUnsignedLong(b.getInt(96))+"\n"; }
            return s;
        }
        if (h.length>=8 && ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt()==0xFAB11BAF) return "Formato: metadados IL2CPP (assinatura detectada)\nVersão declarada: "+ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt(4)+"\n";
        if(h.length>=4 && h[0]=='P' && h[1]=='K') return "Formato: contêiner ZIP (APK/AAB/JAR ou semelhante)\n";
        if(h.length>=2 && h[0]=='M' && h[1]=='Z') return "Formato provável: PE/DLL\n";
        return "Formato não reconhecido pelo módulo inicial\n";
    }
    private static String sha256(File file) throws IOException {
        try { MessageDigest d=MessageDigest.getInstance("SHA-256"); byte[] b=new byte[65536]; try(InputStream in=new FileInputStream(file)){int n;while((n=in.read(b))!=-1)d.update(b,0,n);} StringBuilder s=new StringBuilder();for(byte v:d.digest())s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString(); } catch(NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    private static void archive(File file, StringBuilder out) throws IOException {
        try(ZipFile z=new ZipFile(file)) {
            int count=0,dex=0,elf=0,images=0; boolean manifest=false,meta=false,il2cpp=false; StringBuilder list=new StringBuilder(); Set<String> abis=new TreeSet<>(); Enumeration<? extends ZipEntry> it=z.entries();
            while(it.hasMoreElements() && count<MAX_ENTRIES){ZipEntry e=it.nextElement();count++;String n=e.getName();if(n.endsWith(".dex"))dex++;if(n.endsWith(".so")){elf++;String[] p=n.split("/");if(p.length>2&&p[0].equals("lib"))abis.add(p[1]);}if(n.matches("(?i).*\\.(png|jpg|jpeg|webp|svg)$"))images++;manifest|=n.endsWith("AndroidManifest.xml");meta|=n.endsWith("global-metadata.dat");il2cpp|=n.endsWith("libil2cpp.so");if(count<=MAX_LIST)list.append(n.replaceAll("[\\p{Cntrl}]","?")).append("  [").append(e.getSize()).append(" B]\n");}
            out.append("Entradas examinadas: ").append(count).append(it.hasMoreElements()?" (limite atingido)":"").append("\nDEX: ").append(dex).append("\nBibliotecas SO: ").append(elf).append("\nImagens: ").append(images).append("\nABIs: ").append(abis).append("\nManifesto presente: ").append(manifest).append("\nMetadados IL2CPP: ").append(meta).append("\nBiblioteca IL2CPP: ").append(il2cpp).append("\n\nInventário (até ").append(MAX_LIST).append("):\n").append(list);
        } catch(ZipException e){out.append("ZIP inválido ou não suportado: ").append(e.getMessage()).append('\n');}
    }
}
