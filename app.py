from flask import Flask, request, jsonify, render_template
from transformers import BertForSequenceClassification, BertTokenizer
import torch
from data.pipeline import TextPipeline
import google.generativeai as genai
import json
import os
from dotenv import load_dotenv
load_dotenv()

GEMINI_KEY = os.getenv("GEMINI_KEY")
MODEL_NAME = os.getenv("MODEL_NAME")

print(MODEL_NAME)


app = Flask(__name__)

model = BertForSequenceClassification.from_pretrained(MODEL_NAME)
tokenizer = BertTokenizer.from_pretrained(MODEL_NAME)
text_processor = TextPipeline()


id2label = model.config.id2label
with open(r"data\maping_classes.json", "r", encoding="utf-8") as f:
    mapping_classes = json.load(f)


genai.configure(api_key=GEMINI_KEY)
gemini_model = genai.GenerativeModel("gemini-1.5-flash")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search_text", methods=["POST"])
def api_search_text():
    try:
        data = request.get_json()
        query = data["query"]
        query_text = text_processor.preprocess(query)
        print(query_text)

        # Tokenizar e predizer
        inputs = tokenizer(
            [query_text],
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=128,
        )
        model.eval()
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            #predictions = torch.argmax(logits, dim=1).numpy()
            probabilities = torch.softmax(logits, dim=1)
            values, indices = torch.topk(probabilities, 10, dim=1)
       
        print(indices)
        print(probabilities)

           

        rounded_values = [round(value.item(), 2) for value in values[0]]
        print(rounded_values)
        top_labels = [id2label[idx.item()] for idx in indices[0]]
       
        top_results = [
            {
                "document": (
                    list(mapping_classes.get(top_labels[i], {}).keys())[0]
                    if mapping_classes.get(top_labels[i], {})
                    else ""
                ),
                "id": (
                    list(mapping_classes.get(top_labels[i], {}).values())[0]
                    if mapping_classes.get(top_labels[i], {})
                    else ""
                ),
                "degree_of_certainty": rounded_values[i],
            }
            for i in range(len(top_labels))
        ]

    

        if top_results[0]["degree_of_certainty"] >= 0.79:
            return jsonify(top_results[0]), 200

        filtered_results = [
            {"document": item["document"], "id": item["id"]}
            for item in top_results
            if item["degree_of_certainty"] > 0
        ]
        print(f"filtered results: {filtered_results}")

        prompt = f"""
        Você é um modelo especializado em detecção de intenção de compra.
        A intenção do usuário é: "{query}".
        As categorias disponíveis são: {filtered_results}.
        Retorne o ID da categoria mais adequada em formato JSON, com uma única chave 'ID' e o valor correspondente à categoria.
        Se nenhuma categoria for apropriada, retorne "None".
        Não adicione formatação ou metadados extras.
        """
        try:
            response = gemini_model.generate_content(prompt)
            response_text = response.text.strip().replace("```json", "").replace("```", "")

            if response_text == "None":
                return (
                    jsonify(
                        {
                            "message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"
                        }
                    ),
                    404,
                )

            try:
                category_data = json.loads(response_text)
                category_id = category_data.get("ID")
                matching_document = next(
                    (result for result in top_results if result["id"] == str(category_id)),
                    None,
                )

                if matching_document:
                    return jsonify(matching_document), 200
                else:
                    return (
                        jsonify(
                            {
                                "message": "ID retornado pelo modelo não encontrado nos resultados."
                            }
                        ),
                        404,
                    )

            except json.JSONDecodeError:
                return (
                    jsonify({"error": "Erro ao interpretar a resposta do modelo."}),
                    500,
                )
        except Exception as e:
            return jsonify(top_results[0]), 202

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_all_texts", methods=["GET"])
def api_get_all_texts():
    category_mapping = [
        {"document": list(value.keys())[0], "id": list(value.values())[0]}
        for value in mapping_classes.values()
    ]
    try:

        return jsonify(category_mapping), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
