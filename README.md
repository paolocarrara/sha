sha
===

Implementação em C das funções de hash descritas na FIPS 180-4.

Há dois branchs:

1º branch: implementação simples em C de acordo com o padrão ISO/IEC 9899:1990.

2º branch: implementação utilizando várias extensões fornecidas pelo GCC (GNU Compiler Colection) com o intuito de otimizar o tempo de execução das funções.


Funções hash já implementadas: SHA-1

Nota: Todos as funções de hash foram implementadas para tamanhos arbitrariamente pequenos de mensagens.
Tamanho máximo de uma mensagem: 2^64 bytes = 1.8446744e+19 bytes (por isso do 'arbitrariamente pequenos')
