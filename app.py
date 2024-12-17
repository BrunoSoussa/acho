from flask import Flask, request, jsonify
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import pandas as pd
from data.pipeline import TextPipeline

class TextSimilarityAPI:
    def __init__(self, db_path):
        # Configurações do ChromaDB
        self.chroma_settings = Settings(persist_directory=db_path, anonymized_telemetry=False)

        # Inicialização do cliente do ChromaDB e modelo de embeddings
        self.embedding_model =  SentenceTransformer('SenhorDasMoscas/acho2-ptbr-e4-lr3e-05')
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
        query_embedding = self.embedding_model.encode([self.text_processor.preprocess(query)])[0]
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
            embedding = self.embedding_model.encode([text_clean])[0]

            self.collection.add(
                documents=[text],
                ids=[str(idx)],
                embeddings=[embedding.tolist()]
            )



text_similarity_api = TextSimilarityAPI(db_path="db_dir")
#text_similarity_api.bulk_add_texts(r"C:\Users\bruno\OneDrive\Documentos\tut_projects\recomendator\data\dataset_binario_novos_nomes.csv")
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
                    "similarity": 1 - results["distances"][0][i]
                }
                for i in range(len(results["documents"][0]))
            ]

            return jsonify({
                "total_results": len(top_results),
                "top_results": top_results
            }), 200
        else:
            return jsonify({"message": "Nenhum texto encontrado similar."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/bulk_add_texts', methods=['POST'])
def api_bulk_add_texts():
    try:
        text_similarity_api.bulk_add_texts(csv_path='base_de_dados_corrigida.csv')
        return jsonify({"message": "Textos adicionados com sucesso."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
