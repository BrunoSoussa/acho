from flask import Flask, request, jsonify,render_template
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import pandas as pd
from data.pipeline import TextPipeline
import json

class TextSimilarityAPI:
    def __init__(self, db_path):
        # Configurações do ChromaDB
        self.chroma_settings = Settings(persist_directory=db_path, anonymized_telemetry=False)

        # Inicialização do cliente do ChromaDB e modelo de embeddings
        self.embedding_model =  SentenceTransformer('SenhorDasMoscas/bert-ptbr-teste')
        self.client = chromadb.PersistentClient(path=self.chroma_settings.persist_directory, settings=self.chroma_settings)
        self.collection = self.client.get_or_create_collection(name="text_similarity", metadata={"hnsw:space": "cosine"})

        # Inicialização do processador de texto
        self.text_processor = TextPipeline()

    def add_text(self, text_id, text):
        text_clean = self.text_processor.preprocess_text(text)
        embedding = self.embedding_model.encode([text_clean])[0]
        
        self.collection.add(
            documents=[text],
            ids=[text_id],
            embeddings=[embedding.tolist()]
        )
        return text_clean

    def search_text(self, query, top_k):
        query_embedding = self.embedding_model.encode([self.text_processor.preprocess(query)],convert_to_tensor=True)[0]
        results = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=top_k
        )
        return results

    def bulk_add_texts(self, csv_path):
        data = pd.read_csv(csv_path)
        unique_texts = data['Text2'].unique()

        for idx, text in enumerate(unique_texts):
            text_clean = self.text_processor.preprocess(text)
            embedding = self.embedding_model.encode([text_clean],convert_to_tensor=True)[0]

            self.collection.add(
                documents=[text],
                ids=[str(idx)],
                embeddings=[embedding.tolist()]
            )



text_similarity_api = TextSimilarityAPI(db_path="db_dir")
#text_similarity_api.bulk_add_texts(r"analises\dataset_binario_short_category.csv")
app = Flask(__name__)
@app.route('/add_text', methods=['POST'])
def api_add_text():
    try:
        data = request.get_json()
        text_id = data['id']
        text = data['text']

        text_clean = text_similarity_api.add_text(text_id, text)
        return jsonify({"message": f"Texto '{text_clean}' com ID '{text_id}' adicionado com sucesso."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/search_text', methods=['POST'])
def api_search_text():
    try:
        data = request.get_json()
        query = data['query']
        top_k = data.get('top_k', 10)

        results = text_similarity_api.search_text(query, top_k)

        if results["documents"]:
            top_results = [
                {
                    "document": results["documents"][0][i],
                    "id": results["ids"][0][i],
                    "degree_of_certainty": 1 - results["distances"][0][i]
                }
                for i in range(len(results["documents"][0]))
            ]  
            print(top_results)

            # Verificar se o item de maior similaridade excede 0.93
            if top_results[0]['degree_of_certainty'] > 0.93:
                return jsonify(top_results[0]), 200

            # Filtrar os campos `document` e `id` para o prompt do Gemini
            filtered_results = [
                {"document": item["document"], "id": item["id"]}
                for item in top_results
            ]
            
            # Código adicional para chamar o modelo Gemini
            import google.generativeai as genai

            genai.configure(api_key="AIzaSyAgr6SVtn1tfrD_ynYO0eZKXaHQP8ONI28")
            model = genai.GenerativeModel("gemini-1.5-flash")
            
            prompt = f"""
            você é um modelo de detecção de intenção de compra, para essa intenção "{query}"
            você recebeu as seguintes possibilidades {filtered_results}. 
            Retorne um ID da categoria adequada em formato JSON, com uma única chave 'ID' e um valor sendo a categoria. 
            Caso não encontre, retorne "None". Não inclua identificadores como ```json ```ou metadados extras.

            """
            response = model.generate_content(prompt)
            response_text = response.text.strip().replace("```json","").replace("```","")
            print(response_text)
            
            # Interpretação da resposta
            if response_text == "None":
                return jsonify({"message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"}), 404
            
            # Parse da categoria retornada
            try:
                category_data = json.loads(response_text)
                category_id = category_data.get("ID")
                
                # Localizar o documento correspondente ao ID
                matching_document = next(
                    (result for result in top_results if result["id"] == str(category_id)), 
                    None
                )
                
                if matching_document:
                    return jsonify(matching_document), 200
                else:
                    return jsonify({"message": "ID retornado pelo modelo não encontrado nos resultados."}), 404
            
            except json.JSONDecodeError:
                return jsonify({"error": "Erro ao interpretar a resposta do modelo Gemini."}), 500
        
        else:
            return jsonify({"message": "Nenhum texto encontrado similar."}), 404
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/bulk_add_texts', methods=['POST'])
def api_bulk_add_texts():
    try:
        text_similarity_api.bulk_add_texts(csv_path='base_de_dados_corrigida.csv')
        return jsonify({"message": "Textos adicionados com sucesso."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/hi', methods=['GET'])

@app.route('/get_all_texts', methods=['GET'])
def api_get_all_texts():
    try:
        # Obter todos os documentos e IDs da coleção
        results = text_similarity_api.collection.get()
        
        # Construir uma lista de documentos e seus IDs
        all_texts = [
            {
                "id": results["ids"][i],
                "document": results["documents"][i]
            }
            for i in range(len(results["documents"]))
        ]

        return jsonify(all_texts), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
