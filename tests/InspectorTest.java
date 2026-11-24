package br.com.flashreverso;
import java.io.*;import java.nio.*;import java.nio.file.*;import java.util.zip.*;
public class InspectorTest {
 static void check(boolean b){if(!b)throw new AssertionError();}
 public static void main(String[] args)throws Exception{
 byte[] h=new byte[112];h[0]=0x7f;h[1]='E';h[2]='L';h[3]='F';h[4]=2;h[5]=1;h[18]=(byte)183;check(Inspector.describe(h).contains("AArch64"));
 byte[] d=new byte[112];System.arraycopy(new byte[]{'d','e','x','\n','0','3','9',0},0,d,0,8);ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN).putInt(40,0x12345678).putInt(96,42);check(Inspector.describe(d).contains("Classes: 42"));
 byte[] m=ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFAB11BAF).putInt(31).array();check(Inspector.describe(m).contains("31"));
 Path p=Files.createTempFile("fixture",".zip");try{try(ZipOutputStream z=new ZipOutputStream(Files.newOutputStream(p))){for(String n:new String[]{"AndroidManifest.xml","classes.dex","lib/arm64-v8a/libil2cpp.so","assets/global-metadata.dat"}){z.putNextEntry(new ZipEntry(n));z.write(1);z.closeEntry();}}String r=Inspector.inspect(p.toFile());check(r.contains("DEX: 1"));check(r.contains("Metadados IL2CPP: true"));check(r.contains("SHA-256:"));check(r.contains("arm64-v8a"));}finally{Files.deleteIfExists(p);}System.out.println("PASS: ELF, DEX, IL2CPP signature, ZIP inventory and SHA-256 report");
 }
}
