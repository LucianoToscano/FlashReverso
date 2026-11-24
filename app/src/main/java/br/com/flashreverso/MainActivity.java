package br.com.flashreverso;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.graphics.Color;
import android.widget.*;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class MainActivity extends Activity {
    private TextView output,status;
    private Button open,apps,save,project,history,tools;
    private Uri archiveUri;
    private String selectedEntry;
    private String report="", source="", notes="";
    private File currentProject;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private static final long LIMIT=1024L*1024*1024;
    private Button button(LinearLayout root,String label,Runnable action){Button b=new Button(this);b.setText(label);root.addView(b);b.setOnClickListener(v->action.run());return b;}
    @Override public void onCreate(Bundle state){super.onCreate(state);
        LinearLayout root=new LinearLayout(this);root.setOrientation(1);root.setPadding(24,32,24,24);root.setBackgroundColor(Color.rgb(21,27,35));
        TextView title=new TextView(this);title.setText("FlashReverso");title.setTextSize(28);title.setTextColor(Color.WHITE);root.addView(title);
        status=new TextView(this);status.setText("Laboratório Android • análise local • 0.1.3");root.addView(status);
        open=button(root,"Arquivo APK / outros formatos",()->{Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("*/*");i.addCategory(Intent.CATEGORY_OPENABLE);i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(i,1);});
        apps=button(root,"Aplicativos instalados",this::pickApp);
        history=button(root,"Projetos salvos",this::showProjects);
        project=button(root,"Salvar projeto / notas",this::saveProject);project.setEnabled(false);
        save=button(root,"Exportar relatório TXT",()->{Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.setType("text/plain");i.addCategory(Intent.CATEGORY_OPENABLE);i.putExtra(Intent.EXTRA_TITLE,"flashreverso-relatorio.txt");startActivityForResult(i,2);});save.setEnabled(false);
        tools=button(root,"Ferramentas locais",this::showTools);
        button(root,"Outros módulos — estado",()->new AlertDialog.Builder(this).setTitle("Motores ainda não integrados").setMessage("Assinar APK / APKS\nDesofuscador de recursos\nDesofuscador DEX\nOfuscador de fluxo de controle\nCriptografia de strings\nEdição de APK, Java/Smali, IL2CPP, IA e conectores externos.\n\nOs módulos estão documentados; não executam operações nesta versão.").setPositiveButton("OK",null).show());
        output=new TextView(this);output.setText("Importe APK, AAB, ZIP, DEX, SO ou metadados.\n\nInventário, SHA-256, cabeçalhos ELF/DEX, detecção IL2CPP e hexadecimal.");output.setTextIsSelectable(true);output.setTextSize(14);output.setPadding(8,12,8,12);ScrollView scroll=new ScrollView(this);scroll.addView(output);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));setContentView(root);
    }
    private void busy(boolean b){open.setEnabled(!b);apps.setEnabled(!b);history.setEnabled(!b);tools.setEnabled(!b);save.setEnabled(!b&&!report.isEmpty());project.setEnabled(!b&&!report.isEmpty());}
    private void analyze(Callable<String> task,String uri,boolean reset){if(reset){currentProject=null;notes="";} source=uri;report="";busy(true);status.setText("Analisando localmente…");worker.execute(()->{String value;boolean success=false;try{value=task.call();success=true;}catch(Exception e){value="Falha: "+e.getMessage();}final String text=value;final boolean ok=success;runOnUiThread(()->{if(isDestroyed())return;report=ok?text:"";output.setText(text);status.setText(ok?"Análise concluída":"Análise interrompida");busy(false);});});}
    private void analyzeUri(Uri uri,boolean reset){analyze(()->{File tmp=File.createTempFile("input-",".apk",getCacheDir());try{try(InputStream in=getContentResolver().openInputStream(uri);OutputStream out=new FileOutputStream(tmp)){if(in==null)throw new IOException("Arquivo inacessível");byte[] b=new byte[65536];long total=0;int n;while((n=in.read(b))!=-1){total+=n;if(total>LIMIT)throw new IOException("Limite de 1 GiB excedido");out.write(b,0,n);}}return inspectExtended(tmp);}finally{tmp.delete();}},uri.toString(),reset);}
    private void pickApp(){Intent launcher=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);TreeMap<String,ApplicationInfo> items=new TreeMap<>();for(ResolveInfo r:getPackageManager().queryIntentActivities(launcher,0)){if(r.activityInfo!=null){ApplicationInfo a=r.activityInfo.applicationInfo;items.put(a.loadLabel(getPackageManager())+" — "+a.packageName,a);}}String[] labels=items.keySet().toArray(new String[0]);if(labels.length==0){new AlertDialog.Builder(this).setMessage("Nenhum aplicativo visível ao Android.").setPositiveButton("OK",null).show();return;}new AlertDialog.Builder(this).setTitle("Aplicativos com launcher").setItems(labels,(d,w)->{ApplicationInfo a=items.get(labels[w]);analyze(()->{StringBuilder s=new StringBuilder("Pacote: "+a.packageName+"\n");ArrayList<String> paths=new ArrayList<>();if(a.sourceDir!=null)paths.add(a.sourceDir);if(a.splitSourceDirs!=null)Collections.addAll(paths,a.splitSourceDirs);boolean any=false;for(String path:paths){File f=new File(path);s.append("\n=== ").append(f.getName()).append(" ===\n");try{if(f.length()>LIMIT)throw new IOException("Limite de 1 GiB excedido");s.append(inspectExtended(f));any=true;}catch(Exception e){s.append("Inacessível: ").append(e.getMessage());}}if(!any)throw new IOException("Nenhum APK acessível");return s.toString();},"",true);}).setNegativeButton("Cancelar",null).show();}
    private File projectsDir(){File dir=new File(getFilesDir(),"projects");dir.mkdirs();return dir;}
    private void saveProject(){if(report.isEmpty())return;EditText editor=new EditText(this);editor.setHint("Notas do projeto");editor.setText(notes);new AlertDialog.Builder(this).setTitle("Salvar projeto local").setView(editor).setPositiveButton("Salvar",(d,w)->{try{notes=editor.getText().toString();JSONObject obj=new JSONObject();obj.put("report",report);obj.put("source",source);obj.put("notes",notes);obj.put("updated",System.currentTimeMillis());File dest=currentProject==null?new File(projectsDir(),UUID.randomUUID()+".json"):currentProject;android.util.AtomicFile atomic=new android.util.AtomicFile(dest);FileOutputStream out=atomic.startWrite();try{out.write(obj.toString().getBytes(StandardCharsets.UTF_8));atomic.finishWrite(out);}catch(Exception e){atomic.failWrite(out);throw e;}currentProject=dest;Toast.makeText(this,"Projeto salvo localmente",Toast.LENGTH_SHORT).show();}catch(Exception e){Toast.makeText(this,"Falha ao salvar projeto: "+e.getMessage(),Toast.LENGTH_LONG).show();}}).setNegativeButton("Cancelar",null).show();}
    private void showProjects(){File[] files=projectsDir().listFiles((dir,name)->name.endsWith(".json"));if(files==null||files.length==0){new AlertDialog.Builder(this).setMessage("Nenhum projeto salvo.").setPositiveButton("OK",null).show();return;}Arrays.sort(files,(a,b)->Long.compare(b.lastModified(),a.lastModified()));String[] labels=new String[files.length];for(int i=0;i<files.length;i++)labels[i]=android.text.format.DateFormat.format("dd/MM/yyyy HH:mm:ss",files[i].lastModified()).toString()+" • "+files[i].getName().substring(0,8);new AlertDialog.Builder(this).setTitle("Projetos salvos").setItems(labels,(d,w)->loadProject(files[w])).setNegativeButton("Cancelar",null).show();}
    private void loadProject(File f){try{JSONObject obj=new JSONObject(new String(new android.util.AtomicFile(f).readFully(),StandardCharsets.UTF_8));currentProject=f;report=obj.getString("report");notes=obj.optString("notes");source=obj.optString("source");output.setText(report);status.setText("Projeto local reaberto");busy(false);AlertDialog.Builder dialog=new AlertDialog.Builder(this).setTitle("Projeto reaberto").setMessage(notes.isEmpty()?"Sem notas.":notes).setPositiveButton("OK",null);if(!source.isEmpty())dialog.setNeutralButton("Reanalisar arquivo",(d,w)->analyzeUri(Uri.parse(source),false));dialog.show();}catch(Exception e){Toast.makeText(this,"Falha ao abrir projeto",Toast.LENGTH_LONG).show();}}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();if(req==1){try{getContentResolver().takePersistableUriPermission(uri,data.getFlags()&Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(SecurityException ignored){}analyzeUri(uri,true);}else if(req==3){compareWith(uri);}else if(req==4){chooseEntry(uri);}else if(req==5){exportSelected(uri);}else if(req==2){final String snapshot=report;worker.execute(()->{try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Destino inacessível");out.write(snapshot.getBytes(StandardCharsets.UTF_8));runOnUiThread(()->Toast.makeText(this,"Relatório salvo",Toast.LENGTH_SHORT).show());}catch(Exception e){runOnUiThread(()->Toast.makeText(this,"Falha ao salvar",Toast.LENGTH_LONG).show());}});}}

    private String inspectExtended(File f)throws IOException {
        String original=Inspector.inspect(f);
        try{return original+"\n"+LocalTools.details(f)+apkInfo(f);}
        catch(IOException e){return original+"\nAnálise complementar limitada: "+e.getMessage();}
    }
    private String apkInfo(File f){
        try {
            android.content.pm.PackageInfo p=getPackageManager().getPackageArchiveInfo(f.getAbsolutePath(),android.content.pm.PackageManager.GET_PERMISSIONS | (android.os.Build.VERSION.SDK_INT>=28?android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES:android.content.pm.PackageManager.GET_SIGNATURES));
            if(p==null)return "";
            StringBuilder s=new StringBuilder("\nAPK — manifesto pelo Android\nPacote: "+p.packageName+"\nVersão: "+p.versionName+"\nPermissões declaradas:\n");
            if(p.requestedPermissions!=null)for(String perm:p.requestedPermissions)s.append(perm).append('\n');
            android.content.pm.Signature[] signatures=android.os.Build.VERSION.SDK_INT>=28?(p.signingInfo==null?null:p.signingInfo.getApkContentsSigners()):p.signatures;
            if(signatures!=null)for(android.content.pm.Signature sig:signatures){
                byte[] hash=java.security.MessageDigest.getInstance("SHA-256").digest(sig.toByteArray());s.append("Certificado SHA-256: ");for(byte v:hash)s.append(String.format(Locale.ROOT,"%02x",v&255));s.append('\n');
            }
            return s.toString();
        }catch(Exception e){return "\nManifesto/certificado não acessível pelo Android.\n";}
    }
    private File copyInput(Uri u)throws IOException{
        File t=File.createTempFile("tools-",".apk",getCacheDir());boolean ok=false;
        try{try(InputStream in=getContentResolver().openInputStream(u);OutputStream out=new FileOutputStream(t)){
            if(in==null)throw new IOException("Arquivo inacessível");byte[] buf=new byte[65536];long total=0;int n;
            while((n=in.read(buf))!=-1){total+=n;if(total>LIMIT)throw new IOException("Limite de 1 GiB");out.write(buf,0,n);}
        }ok=true;return t;}finally{if(!ok)t.delete();}
    }
    private void pickFile(int request){
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(i,request);
    }
    private void showTools(){
        String[] options={"Buscar no relatório","Comparar arquivo ZIP/APK com o atual","Extrair arquivo interno de ZIP/APK"};
        new AlertDialog.Builder(this).setTitle("Ferramentas locais").setItems(options,(d,w)->{
            if(w==0){EditText q=new EditText(this);q.setSingleLine(true);new AlertDialog.Builder(this).setTitle("Buscar texto").setView(q).setPositiveButton("Buscar",(a,c)->{
                String key=q.getText().toString().toLowerCase(Locale.ROOT);if(key.isEmpty())return;StringBuilder result=new StringBuilder();int total=0;for(String line:report.split("\n"))if(line.toLowerCase(Locale.ROOT).contains(key)){if(total++<200)result.append(line).append('\n');}new AlertDialog.Builder(this).setTitle("Ocorrências: "+total).setMessage(total==0?"Nenhuma ocorrência":result.toString()).setPositiveButton("OK",null).show();
            }).setNegativeButton("Cancelar",null).show();}
            else if(w==1){if(source.isEmpty()){Toast.makeText(this,"Importe primeiro um arquivo ZIP/APK pelo seletor.",Toast.LENGTH_LONG).show();return;}pickFile(3);}
            else pickFile(4);
        }).setNegativeButton("Cancelar",null).show();
    }
    private void compareWith(Uri second){
        if(source.isEmpty())return;Uri first=Uri.parse(source);busy(true);status.setText("Comparando arquivos…");
        worker.execute(()->{File a=null,b=null;String msg;boolean success=false;
            try{a=copyInput(first);b=copyInput(second);msg=LocalTools.compare(a,b);success=true;}
            catch(Exception e){msg="Falha na comparação: "+e.getMessage();}finally{if(a!=null)a.delete();if(b!=null)b.delete();}
            final String result=msg;final boolean ok=success;runOnUiThread(()->{if(isDestroyed())return;busy(false);status.setText(ok?"Comparação concluída":"Comparação interrompida");new AlertDialog.Builder(this).setTitle("Comparação ZIP/APK").setMessage(result).setPositiveButton("OK",null).setNeutralButton("Copiar",(d,w)->{android.content.ClipboardManager c=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);c.setPrimaryClip(android.content.ClipData.newPlainText("Comparação",result));}).show();});
        });
    }
    private void chooseEntry(Uri u){
        busy(true);status.setText("Lendo inventário…");worker.execute(()->{File t=null;try{t=copyInput(u);String[] names=LocalTools.entries(t).toArray(new String[0]);runOnUiThread(()->{if(isDestroyed())return;busy(false);status.setText("Selecione a entrada");new AlertDialog.Builder(this).setTitle("Arquivos internos (até 1000)").setItems(names,(d,w)->{
            archiveUri=u;selectedEntry=names[w];String name=selectedEntry.replace('\\','/');name=name.substring(name.lastIndexOf('/')+1).replaceAll("[\\p{Cntrl}]","_");if(name.isEmpty()||name.equals(".")||name.equals(".."))name="arquivo.bin";
            Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,name);startActivityForResult(i,5);
        }).setNegativeButton("Cancelar",null).show();});}catch(Exception e){runOnUiThread(()->{if(isDestroyed())return;busy(false);status.setText("Falha: "+e.getMessage());});}finally{if(t!=null)t.delete();}});
    }
    private void exportSelected(Uri dest){
        Uri input=archiveUri;String name=selectedEntry;archiveUri=null;selectedEntry=null;if(input==null||name==null)return;busy(true);status.setText("Extraindo arquivo…");
        worker.execute(()->{File t=null,stage=null;String msg;
            try{t=copyInput(input);stage=File.createTempFile("verified-",".bin",getCacheDir());try(OutputStream out=new FileOutputStream(stage)){LocalTools.exportEntry(t,name,out);}
                try(InputStream in=new FileInputStream(stage);OutputStream out=getContentResolver().openOutputStream(dest,"wt")){if(out==null)throw new IOException("Destino inacessível");byte[] buf=new byte[65536];int n;while((n=in.read(buf))!=-1)out.write(buf,0,n);}msg="Extração concluída; CRC e tamanho conferidos.";
            }catch(Exception e){msg="Falha na extração: "+e.getMessage();}finally{if(t!=null)t.delete();if(stage!=null)stage.delete();}
            final String result=msg;runOnUiThread(()->{if(isDestroyed())return;busy(false);status.setText(result);});
        });
    }

    @Override protected void onDestroy(){worker.shutdown();super.onDestroy();}
}
