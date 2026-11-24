# Escopo mestre — FlashReverso
Metas, não integrações concluídas. Android independente, PT-BR, ARM64, local por padrão, sem root obrigatório.

| Referência | URL | Módulo previsto |
|---|---|---|
| REA Reverse | https://rea-reverse.com/ | APK/AAB, certificados, binários, diagnóstico |
| OpenAPK AI | https://openapk.ai/ | IA para análise de APK (detalhes não verificados) |
| APKTool Studio | https://apktool.zoomnearby.com/ | Recursos, Smali, edição e assinatura autorizadas |
| DecompileAndroid | https://www.decompileandroid.com/ | Java/Kotlin, extração |
| APK Extractor | https://apkextractor.net/ | APK/XAPK, recursos |
| APKLint | https://apklint.com/dex-smali-analyzer/ | DEX/Smali (página não verificada) |
| Convert Guru | https://convert.guru/so-converter | SO e representação textual |
| Toolster | https://toolster.net/so_viewer | ELF, símbolos, dependências |
| Ghidra | https://github.com/NationalSecurityAgency/ghidra | Análise nativa profunda |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF | Auditoria isolada |
| Il2CppInspector | https://github.com/djkaty/Il2CppInspector | Tipos Unity |
| JEB | https://www.pnfsoftware.com/jeb/ | Referência comercial, não redistribuir |
| Il2CppDumper | https://github.com/Perfare/Il2CppDumper | Estruturas IL2CPP |
| Cpp2IL | https://github.com/SamboyCoding/Cpp2IL | IL2CPP |
| JADX | https://github.com/skylot/jadx | Java/DEX |
| Apktool | https://github.com/iBotPeaches/Apktool | XML binário, recursos e Smali |
| ILSpy | https://github.com/icsharpcode/ILSpy | .NET/C# |
| AssetRipper | https://github.com/AssetRipper/AssetRipper | Recursos Unity |
| 7-Zip | https://www.7-zip.org/ | Arquivos compactados |
| androidReverse | https://github.com/UltraSina/androidReverse | Referência mobile; URL a confirmar |
| Android Native Il2CppDumper | https://github.com/springmusk026/Android-Native-Il2cppDumper | Referência mobile; URL a confirmar |
| Il2CppDumpDroidGUI | https://github.com/Poko-Apps/Il2cppDumpDroidGUI | Referência mobile; URL a confirmar |
| Manifesto | https://getmanifesto.app/ | Referência mobile; URL a confirmar |
| IA local/API | — | Modelo local/API própria; consentimento por arquivo |
| GitHub | https://github.com/ | Exportação e versionamento autorizado |
| Google Drive | https://drive.google.com/ | Seletor/OAuth restrito |

## Critérios
1. SAF, SHA-256, formatos, limites e logs: núcleo inicial implementado.
2. APK/DEX: manifesto, componentes, permissões, certificados, Java/Smali, busca e comparação; fixtures próprias.
3. ELF: seções, símbolos, dependências, strings, desmontagem e pseudocódigo; fixtures sintéticas.
4. Unity/.NET: metadados, assemblies, tipos, assets e exportação autorizada; fixtures por versão.
5. ZIP/XAPK/APKS/AAB: extração seletiva segura, limites, previews, edição e assinatura de cópias próprias.
6. Auditoria, diff e relatórios, testes isolados.
7. IA local/API opcional com consentimento, segredos protegidos.
8. GitHub/Drive: escopo mínimo, exportação explícita.
9. Adaptadores AVAILABLE/UNAVAILABLE/FAILED, SBOM, versões fixadas, licenças revisadas.
10. Motores desktop/servidor: avaliar adaptação ou backend opcional controlado pelo usuário; não declarar já portados.
Ver MODULOS-EDICAO.md. Somente marcar disponível após teste executável.
