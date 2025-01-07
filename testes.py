from flask import Flask, request, jsonify,render_template
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import pandas as pd
from data.pipeline import TextPipeline
import json
from data.maping_classes import CategoryMapper
from transformers import BertForSequenceClassification, BertTokenizer
import torch

# Carregar o modelo e o tokenizer
model = BertForSequenceClassification.from_pretrained('SenhorDasMoscas/acho-classification-06-01-2025-update')
tokenizer = BertTokenizer.from_pretrained('SenhorDasMoscas/acho-classification-06-01-2025-update')

# Obter mapeamento label -> id
id2label = model.config.id2label

# Frase para teste
test_phrases = [
    "bolo de goma"
]

# Tokenizar as frases de teste
inputs = tokenizer(test_phrases, return_tensors="pt", truncation=True, padding=True, max_length=128)

# Fazer a predição
model.eval()  # Colocar o modelo em modo de avaliação
with torch.no_grad():
    outputs = model(**inputs)
    logits = outputs.logits
    predictions = torch.argmax(logits, dim=1).numpy()

# Decodificar as classes previstas
predicted_classes = [id2label[pred] for pred in predictions]

# Exibir as frases e suas respectivas previsões
for phrase, pred_class in zip(test_phrases, predicted_classes):
    print(f"Frase: '{phrase}' -> Classe prevista: '{pred_class}'")
probabilities = torch.softmax(logits, dim=1)

# Obter as 10 maiores probabilidades e seus índices
values, indices = torch.topk(probabilities, 10, dim=1)
rounded_values = [round(value.item(), 2) for value in values[0]]

# Usar o id2label para mapear índices para rótulos
id2label = model.config.id2label
top_labels = [id2label[idx.item()] for idx in indices[0]]

print("Probabilidades dos 10 maiores:", rounded_values)  
print("Índices dos 10 maiores:", top_labels)

app = Flask(__name__)
