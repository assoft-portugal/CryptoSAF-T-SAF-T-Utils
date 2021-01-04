# CryptoSAF-T: SAF-T Utils

## FastSaftEncrypt

Implementação em JAVA do algoritmo de encriptação `AES` em modo `Counter`.

O FastSaftEncrypt consiste num utiliário para processar a descaracterização (cifra) e a reversão (decifra) do ficheiro SAF-T nos termos do [**Decreto Lei n.º 48/2020 de 3 de agosto**](https://data.dre.pt/eli/dec-lei/48/2020/08/03/p/dre).

### Woodstox

O FastSaftEncrypt usa uma implementação STAX da biblioteca [Woodstox](https://github.com/FasterXML/woodstox).

Inicializado a partir da opção `configureForConvenience()` que, entre outras possibilidades, ativa a flag `P_PRESERVE_LOCATION`. Esta biblioteca permite processar o ficheiro XML em stream, lançando eventos que podem ser trabalhados pela aplicação.

Apesar de o Woodstox permitir obter os valores dos elementos a cifrar, não podemos usar essa função porque ela também converte os carateres escapados para carateres normais impedindo a sua reversão no formato original. Para contornar este problema estamos a usar o Woodstox para identificar o inicio e o fim das tags a cifrar e dos respectivos valores, e com essa informação, lêr diretamente do ficheiro os dados a copiar ou cifrar para o ficheiro de saída.

### AES-128-CTR (know issue)

Está a ser usada a cifra `AES/CTR/NoPadding` com uma chave de `128 bits` e um vetor de inicialização também de `128 bits`.
Com o decorrer do tempo e após inúmeros testes realizados pela comunidade usando diferentes bibliotecas e linguagens de programação, foram detetados alguns problemas nas implementações deste algoritmo de cifra.

O AES-CTR consiste num algoritmo de cifra em “stream” que, apesar de ser baseado num algoritmo de cifra de [**blocos**](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_%28CTR%29) de `16 bytes`, possibilita a cifra de listas de bytes de dimensão variável.

![AES-CTR](https://user-images.githubusercontent.com/32396185/103531320-ffd71c00-4e80-11eb-8d0b-06cba6a95617.png)

A implementação original do FastSaftEncrypt (commit [7c49657](https://github.com/assoft-portugal/CryptoSAF-T-SAF-T-Utils/commit/7c4965715e0d8c041ad07bad2e77db82fd5cd9da)) usava a API nativa do Java para executar a cifra o que permitia a sua utilização em "stream". O Java implementou o algoritmo do `AES/CTR/NoPadding` como um cifra de "stream" em que usa listas de bytes de tamanho variável como entrada e cujo resultado à saída consiste numa lista de bytes crifrados de tamanho igual à da entrada, permitindo assim cifras consecutivas de tamanho variável e mantendo o estado do contador coerente.

Sucede, porém, que noutras bibliotecas a forma de abordagem em relação ao AES-CTR é diferente daquela que é usada por omissão no JAVA. Por exemplo, no caso de [Bouncy Castle](https://www.bouncycastle.org/), o CTR é aplicado sob a forma de blocos de tamanho fixo. Permite saídas de listas de bytes cifrados com dimensões múltiplas de 16 bytes (tamanho do bloco), fazendo o acerto dos restantes bytes na última invocação. Esta abordagem, apesar de no final produzir um resultado igual, impede que a mesma seja usada de forma eficiente na descaracterização do ficheiro SAF-T, onde é **requisito essencial que todos os participantes usem o mesmo método e os mesmos parâmetros**.

A solução passa por implementar o algoritmo `AES/CTR/NoPadding` recorrendo a outra cifra, a `AES-ECB`. **A implementação através de AES-ECB permite obter os mesmos resultados independemente da biblioteca usada.**
Esta abordagem facilita a conversão FastSaftEncrypt para outras linguagens de programação.

### Solução: AES-CTR com base no AES-ECB

- cifrar o `IV` com a chave simétrica usando `AES-ECB` criando uma lista de bytes denominado de máscara. Para obter uma máscara maior, basta incrementar o IV e cifrá-lo com a chave, concatenando a máscara anterior. Este processo pode ser repetido indefinidamente, incrementando o IV.
- obtenção dos dados cifrados através de uma operação de XOR dos bytes originais com o mesmo número de bytes da máscara.
- descartar os bytes da máscara já usados e usar os restantes para a nova iteração. Se o tamanho da máscara não for suficiente para cobrir a nova lista de bytes a cifrar deve incrementar-se o IV, cifrar e concatenar à máscara.

    ![Processo AES-ECB](https://user-images.githubusercontent.com/32396185/103531377-1d0bea80-4e81-11eb-94db-8cca88fd3df2.png)

Notas:

- O IV normalmente é referido como Counter, após ter sido incrementado
- O processo de decifra é rigorosamente igual, sendo que em vez dos dados em claro são passados cifrados, obtendo assim o dados iniciais.

### Instalação

`mvn clean install`

### Execução

`java pt.cryptosaft.demo.FastSaftEncrypt <operation: E or D> <input xml file> <output xml file> <key in B64> <iv in B64>`

| Argumento | Descrição | Valores|
| --- | --- | --- |
| modo | Modo de operação | E - Descaracterização (Encrypt);<br />D - Reversão (Decrypt);|
| inputXml | Ficheiro SAF-T de entrada | Ex: saft.xml|
| outputXml | Ficheiro SAF-T de saída | Ex: saft_desc.xml|
| chave | Chave simétrica em formato Base64 | Ex: 8/K97v8vQqbD/ShX5yx+3g==|
| iv | Vetor de inicialização em formato Base64 | Ex: +KSjwLJcoMXl7W+U1y5VtQ==|

### JAR

`java -jar jar/FastSaftEncrypt.jar-jar-with-dependencies.jar E src/main/resources/Exemplo_Facturacao.xml /src/main/resources/CryptoSAFT-Exemplo_Facturacao.xml 8/K97v8vQqbD/ShX5yx+3g== +KSjwLJcoMXl7W+U1y5VtQ==`

### MAVEN

`mvn compile exec:java -Dexec.mainClass="pt.cryptosaft.demo.FastSaftEncrypt" -Dexec.args="E src/main/resources/Exemplo_Facturacao.xml /src/main/resources/CryptoSAFT-Exemplo_Facturacao.xml 8/K97v8vQqbD/ShX5yx+3g== +KSjwLJcoMXl7W+U1y5VtQ=="`

## FastHashCannon

Implementação em JAVA de canonização e cálculo de checksum de um ficheiro XML. 

O FastHashCannon usa uma implementação STAXX da biblioteca [Apache Santuario](https://santuario.apache.org/). Esta biblioteca vai processando o ficheiro XML em stream e lançando eventos que são usados para gerar o formato canonizado do xml. Este ficheiro canonizado é depois usado para calcular a hash usando SHA-256.

### Execução

`java pt.cryptosaft.demo.FastHashCannon <input xml file>`

| Argumento | Descrição | Valores|
| --- | --- | --- |
| inputXml | Ficheiro SAF-T de entrada | Ex: saft.xml|
| outputXml | Ficheiro SAF-T canonizado | Ex: saft_can.xml|

### JAR

`java -jar jar/FastHashCannon.jar-jar-with-dependencies.jar src/main/resources/Exemplo_Facturacao.xml`

### MAVEN

`mvn compile exec:java -Dexec.mainClass="pt.cryptosaft.demo.FastHashCannon" -Dexec.args="/src/main/resources/CryptoSAFT-Exemplo_Facturacao.xml"`

## Ajuda

Use a secção de [**issues**](https://github.com/assoft-portugal/CryptoSAF-T-SAF-T-Utils/issues) para consultar, colocar questões ou sugestões que gostaria de ver neste repositório.

## Contributos

Temos muito gosto em contar com a sua colaboração neste projeto. Faça Fork deste repositório e envie o seus [**pull requests**](https://github.com/assoft-portugal/CryptoSAF-T-SAF-T-Utils/pulls)!

## Licença

Este projeto está licenciado nos termos [MIT License](https://github.com/assoft-portugal/CryptoSAF-T-SAF-T-Utils/blob/main/LICENSE).
