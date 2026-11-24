package br.com.flashreverso;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.zip.*;
public final class LocalToolsTest {
    static void check(boolean b){if(!b)throw new AssertionError();}
    static File zip(Path d,String name,String... pairs)throws IOException{
        File f=d.resolve(name).toFile();try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(f))){
            for(int i=0;i<pairs.length;i+=2){z.putNextEntry(new ZipEntry(pairs[i]));z.write(pairs[i+1].getBytes(java.nio.charset.StandardCharsets.UTF_8));z.closeEntry();}
        }return f;
    }
    public static void main(String[] args)throws Exception{
        Path d=Files.createTempDirectory("flash-local");
        try {
            File a=zip(d,"a.zip","classes.dex","a","res/a.png","old","gone","x"),b=zip(d,"b.zip","classes.dex","a","res/a.png","new","new","z");
            check(LocalTools.entries(a).size()==3);check(LocalTools.details(a).contains("classes.dex"));
            String diff=LocalTools.compare(a,b);check(diff.contains("Adicionados: 1 | Removidos: 1 | Alterados: 1"));
            ByteArrayOutputStream out=new ByteArrayOutputStream();LocalTools.exportEntry(a,"res/a.png",out);check(out.toString("UTF-8").equals("old"));
            boolean rejected=false;try{LocalTools.exportEntry(a,"missing",out);}catch(IOException e){rejected=true;}check(rejected);
            ByteBuffer dex=ByteBuffer.allocate(160).order(ByteOrder.LITTLE_ENDIAN);dex.put(new byte[]{'d','e','x','\n','0','3','9',0});dex.putInt(40,0x12345678);dex.putInt(56,2);dex.putInt(60,112);dex.putInt(64,1);dex.putInt(68,120);dex.putInt(88,1);dex.putInt(92,124);dex.putInt(112,132);dex.putInt(116,140);dex.putInt(120,0);dex.putShort(124,(short)0);dex.putInt(128,1);dex.position(132);dex.put(new byte[]{3,'L','A',';',0});dex.position(140);dex.put(new byte[]{3,'r','u','n',0});Path dx=d.resolve("sample.dex");Files.write(dx,dex.array());check(LocalTools.details(dx.toFile()).contains("LA; -> run"));
            dex.putInt(60,Integer.MAX_VALUE);Files.write(dx,dex.array());rejected=false;try{LocalTools.details(dx.toFile());}catch(IOException e){rejected=true;}check(rejected);
            ByteBuffer elf=ByteBuffer.allocate(140).order(ByteOrder.LITTLE_ENDIAN);elf.put(new byte[]{0x7f,'E','L','F',2,1});elf.putLong(40,64);elf.putShort(58,(short)64);elf.putShort(60,(short)1);elf.putShort(62,(short)0);elf.putInt(64,1);elf.putLong(88,128);elf.putLong(96,12);elf.position(129);elf.put(new byte[]{'.','t','e','x','t',0});Path ep=d.resolve("sample.so");Files.write(ep,elf.array());check(LocalTools.details(ep.toFile()).contains(".text"));
            Path md=d.resolve("metadata.dat");Files.write(md,ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFAB11BAF).putInt(31).array());check(LocalTools.details(md.toFile()).contains("31"));
        }finally{try(java.util.stream.Stream<Path> paths=Files.walk(d)){for(Path p:paths.sorted(java.util.Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}}
        System.out.println("PASS: ZIP diff/export, DEX identifiers and bounds, ELF sections, IL2CPP detection");
    }
}
