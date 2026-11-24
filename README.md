# FlashReverso
Laboratório Android em PT-BR para análise local de arquivos próprios ou autorizados. Independente do PGBR.

## 0.1.2
Importação do código 0.1.1, configuração de compilação de release e assinatura externa no CI. Sem novos motores nesta versão.

## Funcionalidades implementadas em código
- Seletor Android de arquivos; sem root, rede ou acesso amplo.
- SHA-256, inventário ZIP/APK/AAB, contagem DEX/SO/imagens, ABIs, manifesto, IL2CPP.
- Cabeçalhos ELF/DEX, metadados IL2CPP e prévia hex.
- Exportação TXT; projetos, relatórios e notas salvos localmente; reabertura e reanálise por URI.
- Seleção de apps com launcher visível e inventário APK base/splits acessíveis.
- Limite de 1 GiB por entrada e 50 mil entradas examinadas; sem execução de binários de entrada.

## Compilação
Android Studio, SDK 35, JDK 17, Gradle 8.9, AGP 8.7.3. Não há wrapper. CI: testes Java, assembleRelease, zipalign, apksigner verify, SHA-256, artifact e pré-release.
Segredos: KEYSTORE_BASE64, KEYSTORE_PASSWORD, KEY_ALIAS, KEY_PASSWORD. Nunca comitar chaves. Em PRs, somente testes/compilação sem assinatura de distribuição.

## Escopo e validação
Ver docs/ESCOPO.md e docs/MODULOS-EDICAO.md. Motores externos ainda não integrados. Teste local do núcleo Java 0.1.1 aprovado; build Android, assinatura com secrets e teste no dispositivo ainda não confirmados. Não afirmar disponibilidade sem evidência. Apenas arquivos próprios ou autorizados. Não contornar licenças ou controles de acesso.
