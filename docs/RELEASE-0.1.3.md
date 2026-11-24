# FlashReverso 0.1.3 — análise local
Base preservada: 09af184bb7bffcfce29930713b7bb51652e34bf0 (release 0.1.2 assinada).
Branch: feat/flashreverso-013-local-analysis.

## Alterações implementadas em código
- DEX individual: identificadores de classes e métodos referenciados, com validação de intervalos e limites. Prévia ASCII; não recupera MUTF-8 completo nem corpos de métodos.
- ELF individual: lista de seções para formatos de 32/64 bits, little/big endian; não é descompilação.
- APK: leitura do pacote, versão, permissões declaradas e impressão SHA-256 dos certificados quando PackageManager disponibiliza. Não equivale a verificação independente de assinatura.
- ZIP/APK: inventário complementar, comparação por CRC e tamanho, extração de entrada individual para destino escolhido no SAF, com verificação CRC e limite 128 MiB. Não extrai automaticamente para caminhos controlados pelo arquivo.
- Busca textual no relatório local; preservados projetos e importação.
- Testes sintéticos novos e pipeline ajustado para versão 0.1.3.
- IL2CPP: identificação de cabeçalho apenas; Unity assets apenas identificação por nome de arquivo.
- Sem rede ou root obrigatório.

## Validação
CI do PR e teste em aparelho a confirmar; sem novo APK publicado até merge e pipeline de release.
Limites: 1 GiB por arquivo importado, 1000 entradas listadas nos novos módulos, 50000 entradas examinadas, 500000 registros por tabela DEX/ELF. Comparação CRC+tamanho não prova igualdade criptográfica.

## Fila restante
JADX/Apktool e Smali completo; análise nativa profunda (Ghidra/radare2); reconstrução IL2CPP e assets Unity (Il2CppDumper/Cpp2IL/AssetRipper); .NET; edição HEX/APK e recompilação de cópias próprias; assinatura dentro do app; desofuscação por mapeamentos autorizados; proteção de código próprio; IA opcional com consentimento; GitHub e Drive; interface PT-BR completa. Conferir licenças e compatibilidade ARM64/Android antes de redistribuir motores. Preservar todos os requisitos de ESCOPO.md e MODULOS-EDICAO.md.
