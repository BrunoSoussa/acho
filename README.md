# Modelo de Detecção de Intenção de Compra

Este projeto implementa um modelo baseado no **BERT** para detecção de intenções de compra. O modelo foi ajustado para a língua portuguesa utilizando o checkpoint `neuralmind/bert-large-portuguese-cased`, com foco em tarefas de análise de similaridade entre textos.

## Sumário
- [Descrição do Modelo](#descrição-do-modelo)
- [Estrutura do Dataset](#estrutura-do-dataset)
- [Pipeline de Treinamento](#pipeline-de-treinamento)
- [Parâmetros de Treinamento](#parâmetros-de-treinamento)
- [Como Reproduzir o Treinamento](#como-reproduzir-o-treinamento)
- [Resultados](#resultados)
- [Requisitos](#requisitos)

## Descrição do Modelo
O modelo foi projetado para prever a similaridade entre dois textos (“Text1” e “Text2”) com o objetivo de identificar intenções de compra. Ele utiliza:
- Embeddings gerados pelo BERT (versão ajustada para o português);
- Perda baseada em **CosineSimilarityLoss** para medir a semelhança entre embeddings.

## Estrutura do Dataset
O dataset deve ser fornecido em formato CSV e conter as seguintes colunas:
- **Text1**: Texto que descreve o contexto do usuário ou do produto.
- **Text2**: Texto que representa uma categoria ou intenção de compra.
- **Label**: Valor numérico (0 ou 1), indicando a similaridade ou intenção de compra.

Exemplo:
| Text1                                | Text2                          | Label |
|-------------------------------------|--------------------------------|-------|
| "Estou procurando um celular novo" | "dispositivos eletrônicos"    | 1     |
| "Quero comprar uma bicicleta"      | "produtos de beleza"          | 0     |

## Pipeline de Treinamento
1. **Carregamento do Dataset**: O CSV é lido e convertido para um dataset compatível com a biblioteca `datasets` do Hugging Face.
2. **Divisão dos Dados**: O dataset é dividido em treino (90%) e validação (10%).
3. **Cálculo de Pesos de Amostragem**: Pesos balanceados são calculados para lidar com desbalanceamento nas classes.
4. **Criação de Exemplos de Treinamento**: Exemplos são estruturados usando a classe `InputExample`.
5. **Configuração do Treinador**: O treinador (“Trainer”) é configurado com hiperparâmetros otimizados e métricas de avaliação baseadas em similaridade.
6. **Treinamento e Avaliação**: O modelo é treinado e avaliado periodicamente em um conjunto de validação.
7. **Salvar Modelo**: Após o treinamento, o modelo ajustado é salvo.

## Parâmetros de Treinamento
- **Modelo Base**: `neuralmind/bert-large-portuguese-cased`
- **Épocas**: 5
- **Tamanho do Batch**: 32
- **Taxa de Aprendizado**: 1e-5
- **Warmup Ratio**: 10%
- **Decaimento de Peso**: 0.1
- **Estratégia de Salvamento**: Checkpoints a cada 500 steps (máximo de 2 checkpoints salvos).
- **Semente Aleatória**: 42


## Resultados
O desempenho do modelo é avaliado com base em **similaridade de embeddings**. Durante o treinamento, o modelo utiliza o `EmbeddingSimilarityEvaluator` para medir a perda de validação.

- **Métrica de Avaliação**: `eval_loss`
- **Checkpoint com Melhor Modelo**: O modelo com a menor perda no conjunto de validação é automaticamente salvo.

## Requisitos
- **Bibliotecas Necessárias**:
  - `torch`
  - `sentence-transformers`
  - `datasets`
  - `scikit-learn`
  - `pandas`
- **Hardware**:
  - GPU recomendada para aceleração do treinamento.

---
Para dúvidas ou melhorias, contribua no repositório ou entre em contato com o responsável pelo projeto.

# acho
