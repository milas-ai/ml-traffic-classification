# Monitoramento e Classificação de Tráfego de Rede
Ferramenta de classificação de tráfego de rede com aprendizado de máquina para o projeto de iniciação científica de [análise de desempenho de técnicas de aprendizado de máquina na classificação online de tráfego malicioso](https://bv.fapesp.br/pt/bolsas/213080/analise-de-desempenho-de-tecnicas-de-aprendizado-de-maquina-na-classificacao-online-de-trafego-malic/).

A ferramenta desenvolvida é voltada para o monitoramento de tráfego de rede, utilizando um modelo de aprendizado de máquina treinado com capturas prévias de tráfego real para poder classificar em tempo real os pacotes passando em uma rede. O tráfego é capturado e posteriormente convertido para um arquivo CSV a ser usado como entrada para o modelo de classificação. São utilizados três programas principais (`monitor`, `trainer` e `tester`), e dois módulos auxiliares (`pcap_processor` e `csv_preprocessor`).

<p align="center">
  <img src="https://imgur.com/WOvZje9.png" width="750">
</p>

## Monitor
O programa principal, faz a captura do tráfego e a classificação dos pacotes utilizando o modelo recebido como parâmetro.

```bash
python monitor.py <model_file> [features_file]
```
*O [arquivo de features](#features-personalizadas) é opcional, caso não especificado, serão utilizadas as [features padrão](#features-padrão).

O modelo utilizado deve ser um objeto exportado pelo pickle (`.plk`) com uma função `predict(dataframe)` que classifica o dataframe dos pacotes capturados.

Um exemplo simples de modelo pode ser treinado utilizando os programas [`trainer.py`](#treinador) e [`tester.py`](#testes-de-classificação).

### Captura de pacotes

A captura do fluxo de rede é feita utilizando a ferramenta `tshark`, parte do pacote do analisador de protocolos de rede [wireshark](https://www.wireshark.org/).

O tempo de captura pode ser modificado pela constante `CAPTURE_TIME`, em segundos.

Caso o número de pacotes exceda a quantia especificada pela constante `SAMPLE_SIZE`, uma amostra desse mesmo tamanho será utilizada para a classificação, ao invés da captura completa (o tamanho máximo de `SAMPLE_SIZE` testado foi 5000, acima disso o filtro do tshark para amostragem pode falhar).

### Log de monitoramento

Um arquivo de log (`monitor.log`) é gerado conforme as mensagens são mostradas no console, indicando o início e fim das capturas, o total de pacotes capturados em cada medição e a porcentagem de pacotes classificados como ataque.

## Treinador

```bash
python trainer.py <data_path> <model_output_file>
```

## Testes de classificação

```bash
python tester.py <model_file> <data_path>
```

## Dependências

```bash
pip install pandas pyshark scikit-learn [numpy]
```
*`numpy` só é necessário para utilizar o `trainer.py`

O programa `wireshark` também é uma dependência do `monitor.py` para capturar o tráfego na rede.

## Processador de PCAP's

Módulo que cuida...

```bash
python pcap_processor.py <pcap_file> <output_file> [features_file] [attack category subcategory]
```

### Features padrão

São as features que podem ser extraídas das capturas do tshark pelo programa, sendo elas: `pkSeqID`, `stime`, `flgs`,  `proto`,  `saddr`,  `sport`,  `daddr`,  `dport`,  `pkts`,  `bytes`,  `ltime`,  `seq`,  `dur`,  `mean`,  `stddev`,  `sum`, `min`,  `max`,  `spkts`,  `dpkts`,  `sbytes`,  `dbytes`,  `rate`,  `srate`, `drate`.

Elas são sempre processadas para cada medição, porém podem ser ocultas do dataframe classificado através de um [arquivo de features personalizadas](#features-personalizadas).

### Features personalizadas

Um arquivo de features pode ser construído em formato de um CSV sem header, com cada linha contêndo quatro informações na seguinte ordem: `key` (feature), `value` (valor padrão), `name` (nome no cabeçalho do arquivo de saída), `locked` (booleana que indica se ela está fixada).

A coluna `locked` faz com que uma feature específica seja fixa, dessa forma, seu valor no dataframe processado será sempre igual ao valor padrão (`value`) especificado.

Ele é utilizado para que as colunas do dataframe a ser classificado estejam de acordo com as que o modelo espera, sendo assim, features não capturáveis (não estão entre as [features padrão](#features-padrão)) podem ser adicionadas, porém seu valor no dataframe passado ao modelo será sempre igual ao especificado na coluna value (sem se importar com a coluna `locked`)

```
saddr,-1,Endereço IP do remetente,False
daddr,-1,Endereço IP do destinatário,True
is_green,0,Cor,False
...
```

## Pré-processador de CSV's

Módulo responsável por transformar os CSV's produzidos pelo (processador de captura)[#processador-de-pcap's] em um dataframe classificável pelo modelo de aprendizado de máquina.

```bash
python csv_preprocessor.py <data_path> <output_file>
```
